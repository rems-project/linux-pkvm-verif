// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

/* PS: relevant files:
arch/arm64/kvm/hyp/nvhe/page_alloc.c  - this file

arch/arm64/kvm/hyp/include/nvhe/gfp.h - defines struct hyp_pool, containing a lock and the per-order free lists of the buddy allocator, and the API of this file

arch/arm64/kvm/hyp/include/nvhe/memory.h - defines struct hyp_page , global `struct hyp_page *hyp_vmemmap`, and the macros to convert between pointers to pages and virtual and physical addresses

arch/arm64/kvm/hyp/nvhe/setup.c - initialises the allocator with

	nr_pages = hyp_s1_pgtable_size() >> PAGE_SHIFT;
	used_pages = hyp_early_alloc_nr_pages();
	ret = hyp_pool_init(&hpool, __hyp_pa(hyp_pgt_base), nr_pages, used_pages);

include/linux/list.h - doubly linked list macros

notes24-2020-08-20-pkvm-alloc-walkthrough.txt
*/

#include <asm/kvm_hyp.h>
#include <nvhe/gfp.h>

u64 __hyp_vmemmap;

/*
 * Example buddy-tree for a 4-pages physically contiguous pool:
 *
 *                 o : Page 3
 *                /
 *               o-o : Page 2
 *              /
 *             /   o : Page 1
 *            /   /
 *           o---o-o : Page 0
 *    Order  2   1 0
 *
 * Example of requests on this zon:
 *   __find_buddy(pool, page 0, order 0) => page 1
 *   __find_buddy(pool, page 0, order 1) => page 2
 *   __find_buddy(pool, page 1, order 0) => page 0
 *   __find_buddy(pool, page 2, order 0) => page 3
 */
static struct hyp_page *__find_buddy(struct hyp_pool *pool, struct hyp_page *p,
				     unsigned int order)
{
	phys_addr_t addr = hyp_page_to_phys(p);

	addr ^= (PAGE_SIZE << order);
	if (addr < pool->range_start || addr >= pool->range_end)
		return NULL;

	return hyp_phys_to_page(addr);
}

static void __hyp_attach_page(struct hyp_pool *pool,
			      struct hyp_page *p)
{
	unsigned int order = p->order;
	struct hyp_page *buddy;

	p->order = HYP_NO_ORDER;
	for (; order < HYP_MAX_ORDER; order++) {
		/* Nothing to do if the buddy isn't in a free-list */
		buddy = __find_buddy(pool, p, order);
		if (!buddy || list_empty(&buddy->node) || buddy->order != order)
			break;

		/* Otherwise, coalesce the buddies and go one level up */
		list_del_init(&buddy->node);
		buddy->order = HYP_NO_ORDER;
		p = (p < buddy) ? p : buddy;
	}

	p->order = order;
	list_add_tail(&p->node, &pool->free_area[order]);
}

void hyp_put_page(void *addr)
{
	struct hyp_page *p = hyp_virt_to_page(addr);
	struct hyp_pool *pool = hyp_page_to_pool(p);

	hyp_spin_lock(&pool->lock);
	if (!p->refcount)
		hyp_panic();
	p->refcount--;
	if (!p->refcount)
		__hyp_attach_page(pool, p);
	hyp_spin_unlock(&pool->lock);
}

void hyp_get_page(void *addr)
{
	struct hyp_page *p = hyp_virt_to_page(addr);
	struct hyp_pool *pool = hyp_page_to_pool(p);

	hyp_spin_lock(&pool->lock);
	p->refcount++;
	hyp_spin_unlock(&pool->lock);
}

/* Extract a page from the buddy tree, at a specific order */
static struct hyp_page *__hyp_extract_page(struct hyp_pool *pool,
					   struct hyp_page *p,
					   unsigned int order)
{
	struct hyp_page *buddy;

	if (p->order == HYP_NO_ORDER || p->order < order)
		return NULL;

	list_del_init(&p->node);

	/* Split the page in two until reaching the requested order */
	while (p->order > order) {
		p->order--;
		buddy = __find_buddy(pool, p, p->order);
		buddy->order = p->order;
		list_add_tail(&buddy->node, &pool->free_area[buddy->order]);
	}

	p->refcount = 1;

	return p;
}

static void clear_hyp_page(struct hyp_page *p)
{
	unsigned long i;

	for (i = 0; i < (1 << p->order); i++)
		clear_page(hyp_page_to_virt(p) + (i << PAGE_SHIFT));
}

static void *__hyp_alloc_pages(struct hyp_pool *pool, gfp_t mask,
			       unsigned int order)
{
	unsigned int i = order;
	struct hyp_page *p;

	/* Look for a high-enough-order page */
	while (i <= HYP_MAX_ORDER && list_empty(&pool->free_area[i]))
		i++;
	if (i > HYP_MAX_ORDER)
		return NULL;

	/* Extract it from the tree at the right order */
	p = list_first_entry(&pool->free_area[i], struct hyp_page, node);
	p = __hyp_extract_page(pool, p, order);

	if (mask & HYP_GFP_ZERO)
		clear_hyp_page(p);

	return p;
}

void *hyp_alloc_pages(struct hyp_pool *pool, gfp_t mask, unsigned int order)
{
	struct hyp_page *p;

	hyp_spin_lock(&pool->lock);
	p = __hyp_alloc_pages(pool, mask, order);
	hyp_spin_unlock(&pool->lock);

	return p ? hyp_page_to_virt(p) : NULL;
}


// PS: initialise the buddy allocator into `pool`, giving it memory phys..phys+ntr_pages<<PAGE_SHIFT, initialise all the corresponding vmemmap `struct hyp_page`s, and attach all of that after phys+used_pages<<PAGE_SHIFT to the free lists (which will presumably combine them as much as it can - is __hyp_attach_page commutative?)
// PS: precondition: phys is page-aligned (NB not highest-order aligned)
// PS: precondition: at the C semantics level, the "vmemmap is mapped" precondition is just ownership of the vmemmap array - but at a specific address that makes the arithmetic work

/* hyp_vmemmap must be backed beforehand */
int hyp_pool_init(struct hyp_pool *pool, phys_addr_t phys,
		  unsigned int nr_pages, unsigned int used_pages)
{
	struct hyp_page *p;
	int i;

	if (phys % PAGE_SIZE)
		return -EINVAL;

	// PS: initialise `pool`: the spinlock, the start and end to `phys` (surprising that this is a physical address?), and the per-order free lists to empty lists (pointing to themselves, see include/linux/list.h)
	hyp_spin_lock_init(&pool->lock);
	for (i = 0; i <= HYP_MAX_ORDER; i++)
		INIT_LIST_HEAD(&pool->free_area[i]);
	pool->range_start = phys;
	pool->range_end = phys + (nr_pages << PAGE_SHIFT);

	/* Init the vmemmap portion */
	// PS: zero all the `struct hyp_page`s in the vmemmap that correspond to the pages given to the allocator
	p = hyp_phys_to_page(phys);
	memset(p, 0, sizeof(*p) * nr_pages);
	// PS: and for each of them, record that it belongs to this pool, and initialise its `struct list_head node` to an empty list (pointing to itself)
	for (i = 0; i < nr_pages; i++, p++) {
		p->pool = pool;
		INIT_LIST_HEAD(&p->node);
	}

	/* Attach the unused pages to the buddy tree */
	p = hyp_phys_to_page(phys + (used_pages << PAGE_SHIFT));
	for (i = used_pages; i < nr_pages; i++, p++)
		__hyp_attach_page(pool, p);

	return 0;
}
