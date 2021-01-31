// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */




// PS: I'll add comments labelled like this
// PS: just in this file, rather than scatter them about

#include <asm/kvm_hyp.h>
#include <nvhe/gfp.h>

u64 __hyp_vmemmap;


/* PS: casual googling reveals a paper with an Isabelle proof. I've not read it.
A Formally Verified Buddy Memory Allocation Model
Ke Jiang; David Sanan; Yongwang Zhao; Shuanglong Kan; Yang Liu
2019 24th International Conference on Engineering of Complex Computer Systems (ICECCS) https://ieeexplore.ieee.org/abstract/document/8882772
*/

/* PS: relevant files:

- arch/arm64/kvm/hyp/nvhe/page_alloc.c  - this file, the buddy allocator implementation

- arch/arm64/kvm/hyp/include/nvhe/gfp.h - defines struct hyp_pool, containing a lock and the per-order free lists of the buddy allocator, and the API of this file

- arch/arm64/kvm/hyp/include/nvhe/memory.h - defines struct hyp_page , global `struct hyp_page *hyp_vmemmap`, and the macros to convert between pointers to pages and virtual and physical addresses

- arch/arm64/kvm/hyp/nvhe/setup.c - initialises the allocator with

	nr_pages = hyp_s1_pgtable_size() >> PAGE_SHIFT;
	used_pages = hyp_early_alloc_nr_pages();
	ret = hyp_pool_init(&hpool, __hyp_pa(hyp_pgt_base), nr_pages, used_pages);

  and the vmemmap, using the following two

- arch/arm64/kvm/hyp/nvhe/memory.c - includes hyp_back_vmemmap()

- arch/arm64/kvm/hyp/include/nvhe/mm.h - includes hyp_vmemmap_range()

- include/linux/list.h - doubly linked list macros

- include/linux/types.h - the type "struct list_head"

- notes24-2020-08-20-pkvm-alloc-walkthrough.txt - our previous chat about this with the pKVM devs
*/


/* PS: recalling the key types from those. In gfp.h:

struct hyp_pool {
	hyp_spinlock_t lock;
	struct list_head free_area[HYP_MAX_ORDER + 1];
	phys_addr_t range_start;
	phys_addr_t range_end;
};

and in memory.h:

struct hyp_page {
	unsigned int refcount;
	unsigned int order;
	struct hyp_pool *pool;
	struct list_head node;
};

#define hyp_vmemmap ((struct hyp_page *)__hyp_vmemmap)
*/


/* PS: morally, for any hyp_pool, when its lock is not taken:
     say a "page group" is a subset of the page-aligned physical addresses from its range_start..range_end, that is contiguous and for which there exists an order in 0..HYP_MAX_ORDER such that it is 2^order pages in size and 2^order pages aligned (wrt absolute physical addresses).  (Maybe there's a better name than "page group"? Do people use "area" for this??)
     there's a set of page groups that are currently handed out, each with a refcount >= 1. It's not clear whether there's not enough info in the concrete state to completely reconstruct this, as it doesn't say whether adjacent aligned pages were handed out together or separately. Do we need to record it for testing?
__hyp_attach_page uses the order of its hyp_page argument - but what do we know about the orders of the other pages in that group?  Must all be HYP_NO_ORDER??
     there's a set of page groups that are currently owned by the allocator, each with a refcount == 0.
     together, those are all disjoint and partition the range_start..range_end
     the set of elements of each free_area list of the hyp_pool is the subset of the page addresses (check which kind?) of the set of page groups currently owned by the allocator
     these are consistent (not sure exactly how) with the the vmemmap hyp_page's with refcount == 0, which each contain their order
     for each vmemmap hyp_page, the node member is its free-list node, if it's in one
     the free_area lists have no repeated elements
     the free_area's are maximally coalesced, i.e. for each non-maximal order, there don't exist any adjacent-in-memory suitably aligned pairs in the free set for that order
     it owns all the vmemmap entries
     all the vmemmap entries have this pool
*/

/*PS: maybe we want to macroise with this kind of thing to make the math abstraction a bit more obvious, but I won't for now
#define FORALL_HYP_PAGE(pool,phys,stmt) for (phys=pool->range_start; phys < pool->range_end; phys+= PAGE_SIZE) { stmt }
*/

// PS: smoke test: check some trivial parts of the invariant
#include <asm/kvm_mmu.h>
#include <../debug-pl011.h>
//#include <../check-debug-pl011.h>
bool check_alloc_invariant(struct hyp_pool *pool) {
	phys_addr_t phys;
	struct hyp_page *p;
	bool ret;
	ret = true;
	for (phys=pool->range_start; phys < pool->range_end; phys+= PAGE_SIZE) {
		p = hyp_phys_to_page(phys);
		ret = ret
			&& (p->pool == pool)
			&& (p->order == HYP_NO_ORDER || p->order <= HYP_MAX_ORDER);
			}
	if (!ret)
		hyp_puts("check_alloc_invariant failed");
	else
		hyp_puts("check_alloc_invariant succeed");

	return ret;
}


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


/* PS: given the address p of a hyp_page in the vmemmap, and an order,
   return the address of the hyp_page of its buddy (the adjacent page
   group, either before or after) if it exists within the pool range,
   otherwise return NULL */
/* PS: this is a pure-ish function: no non-local writes */
/* PS: I'm suspicious of the range_end check: it only checks the base
   address of the buddy page group, not the end address. This will
   only be sound if the range that the pool is initialised with is
   very aligned - I don't know whether that's enforced by the context*/
static struct hyp_page *__find_buddy(struct hyp_pool *pool, struct hyp_page *p,
				     unsigned int order)
{
	phys_addr_t addr = hyp_page_to_phys(p);

	addr ^= (PAGE_SIZE << order);
	if (addr < pool->range_start || addr >= pool->range_end)
		return NULL;

	return hyp_phys_to_page(addr);
}


/* PS: given a hyp_page p in the vmemmap, transfer that page group (at the order in that hyp_page) back to the allocator, coalescing buddy's as much as possible */
/* PS: the list_empty(&buddy->node) check suggests a non-NULL buddy->node member is valid only if it doesn't satisfy this list_empty property?? how can that arise? */
/* PS: coalescing the buddies doesn't zap the buddy->node */
/* PS: not sure what the buddy->order != order check is doing */
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


// PS: hand a reference-count of a page-group back to the allocator
// PS: ...actually transferring ownership it it's the last reference-count
// PS: precondition: the refcount for the page at hyp_virt addr is non-zero
// PS: decrement it 
// PS: if the recount becomes zero, __hyp_attach_page the page group
// PS: all protected by the pool lock
// PS: presumably there's already some standard seplogic idiom for ref-counted ownership?
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

// PS: bump the refcount for the page at hyp_virt addr
// PS: protected by the pool lock
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

// PS: zero all the bytes of a page-group p
static void clear_hyp_page(struct hyp_page *p)
{
	unsigned long i;

	for (i = 0; i < (1 << p->order); i++)
		clear_page(hyp_page_to_virt(p) + (i << PAGE_SHIFT));
}

// PS: ask for a page-group at some order, either zero'd or not depending on gfp_t mask; return the address of the vmemmap hyp_page (cast to void*) or NULL if it failed. 
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

// PS: ask for a page-group at some order, either zero'd or not depending on gfp_t mask; return the address of the vmemmap hyp_page (cast to void*) or NULL if it failed.  Protected by the pool lock
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

	// PS: add check
	check_alloc_invariant(pool);

	return 0;
}
