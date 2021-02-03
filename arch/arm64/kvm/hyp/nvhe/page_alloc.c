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


/* PS: related work: casual googling reveals a paper with an Isabelle proof of some kind of buddy allocator. I've not read it.
A Formally Verified Buddy Memory Allocation Model
Ke Jiang; David Sanan; Yongwang Zhao; Shuanglong Kan; Yang Liu
2019 24th International Conference on Engineering of Complex Computer Systems (ICECCS) https://ieeexplore.ieee.org/abstract/document/8882772
*/


/* ****************************************************************** */
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


Recalling the key types from those, we have in gfp.h:

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


/* ****************************************************************** */
/* PS: some abstration and invariant, informally

   for any hyp_pool, when its lock is not taken:

   say a "page group" is a subset of the page-aligned physical
   addresses from its range_start..range_end, that is contiguous, and
   for which there exists an order in 0..HYP_MAX_ORDER such that it is
   2^order pages in size and 2^order pages aligned (wrt absolute
   physical addresses).  (Maybe there's a better name than "page
   group"?)

   the hyp_page "order" members partition all the pages of a pool into
   a set of page groups, starting at each page that isn't HYP_NO_ORDER

   these page groups are partitioned into those that are currently
   handed out, which either are in the used_pages or have a refcount
   (in their first page) >= 1, and which do not appear in any free
   list, and those that are not in the used_pages and have a refcount
   (in their first page) == 0, which appear in the free list of their
   order

   the allocator owns the latter

   refcounts in non-first-pages of these page groups are presumably == 0 (?)

   in the external spec, it's unclear whether or not we want to retain
   the page-group structure over the set of free pages.  But we
   certainly need it for the internal invariant, either explicitly or
   implicitly

   the free list for each order contains exactly the set of
   non-used_page page groups of that order with refcount == 0

   free lists are represented as circular doubly linked lists, with
   `struct list_head` nodes that are either elements of the hyp_pool
   free_area array or hyp_page node members.  An empty list is one for
   which the free_area node has next and prev pointing to itself, and
   a hyp_page node member is "empty" in that sense iff it belongs to
   no free list.

   the free page groups are maximally coalesced, i.e. for each
   non-maximal order, there don't exist any adjacent-in-memory
   suitably aligned pairs in the free page groups for that order

   the allocator owns all the vmemmap entries

   all the vmemmap entries have this pool
*/


// PS: the following are to get debug printing via the uart
#include <asm/kvm_mmu.h>
#include <../debug-pl011.h>
#include <../check-debug-pl011.h>


/* ****************************************************************** */
/* PS: start encoding some of that into C. There's a lot of choice
   here, and we have to pay unfortunately much attention to making it
   feasible to compute; the following is a bit arbitrary, and not
   terribly nice - it avoids painful computation of the "partitions
   the pages" part, but is probably more algorithmic than we'd like,
   esp. in the check_page_groups_and_interpret loop
   structure. Although for refinement-type proof, we may want the
   invariants to be as far as possible about the concrete data, rather
   than about abstractions thereof.  So far the checking code below is
   computing but not using the abstraction.  Is the abstraction what
   we want to use for the external spec of this module?  (This seems a
   bit different to the pgtable case, where some elaboration of the
   abstraction is probably useful in specs of the recursive functions
   of the implementation) */


/* types of abstraction */

struct page_group {
	phys_addr_t start;
	unsigned int order;
	bool free;
};


#define MAX_PAGE_GROUPS 0x1000   /* horrible hack */

struct page_groups {
	struct page_group page_group[MAX_PAGE_GROUPS];
	u64 count;
};

struct page_groups page_groups_a;


bool in_used_pages(phys_addr_t phys, struct hyp_pool *pool)
{
	return phys < pool->range_start + PAGE_SIZE*pool->used_pages;
}


/* pretty-printing */

void put_page_group(struct page_group *pg, struct hyp_pool *pool)
{
	hyp_putsxn("page group start",pg->start,64);
	hyp_putsxn("end",pg->start + PAGE_SIZE*(1ul << pg->order),64);
	hyp_putsxn("order",pg->order,32);
	hyp_putsp("used_pages:"); hyp_putbool(in_used_pages(pg->start,pool));
	hyp_putsp(" free:"); hyp_putbool(pg->free);
	hyp_putsp("\n");
}

void put_free_list(struct list_head *head)
{
	struct list_head *pos;
	list_for_each(pos,head) {
		hyp_putsxn("",(u64)hyp_page_to_phys(list_entry(pos, struct hyp_page, node)),64);
	}
}

void put_free_lists(struct hyp_pool *pool)
{
	u64 i;
	for (i=0; i<HYP_MAX_ORDER+1; i++) {
		hyp_putsxn("order",i,64);
		put_free_list(&pool->free_area[i]);
		hyp_putc('\n');
	}
}

/* well-formed free list at specific order */
bool check_free_list(struct list_head *head, unsigned int order, struct hyp_pool *pool)
{
	bool ret;
	struct list_head *pos;
	struct hyp_page *p;
	phys_addr_t phys;
	ret = true;
	list_for_each(pos, head) { //for (pos = head->next; pos != (head); pos = pos->next) {
		p = list_entry(pos, struct hyp_page, node);
		phys = hyp_page_to_phys(p);
		if (phys < pool->range_start + PAGE_SIZE*pool->used_pages || phys >= pool->range_end) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("free list entry not in pool unused_page range"); } // maybe this should check p is the address of a hyp_page node member, not just go straight to hyp_page_to_phys's notion of phys 
		if (p->order != order) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("free list entry has wrong order"); }
	}
	return ret;
}

/* well-formed free lists of pool */
bool check_free_lists(struct hyp_pool *pool)
{
	u64 i;
	bool ret;
	ret = true;
	for (i=0; i<HYP_MAX_ORDER+1; i++) {
		ret = ret && check_free_list(&pool->free_area[i], i, pool);
	}
	return ret;
}


/* list auxiliary: check whether @node is an element of @head (curiously not already in linux/include/list.h) */
bool list_contains(struct list_head *node, struct list_head *head)
{
	struct list_head *pos;
	list_for_each(pos, head) { //for (pos = head->next; pos != (head); pos = pos->next) {
		if (pos==node)
			return true;
	}
	return false;
}


struct hyp_page *find_free_buddy(struct hyp_page *p, unsigned int order, struct hyp_pool *pool)
{
        struct hyp_page *buddy;
	// this duplicates __find_buddy :
	phys_addr_t addr = hyp_page_to_phys(p);
	addr ^= (PAGE_SIZE << order);
	if (addr < pool->range_start || addr >= pool->range_end)
		return NULL;
	buddy = hyp_phys_to_page(addr);
        // and this duplicates the check in __hyp_attach_page
	if (list_empty(&buddy->node) || buddy->order != order)
		return NULL;
	return buddy;
}

/* well-formed page_group start page */
bool check_page_group_start(phys_addr_t phys, struct hyp_page *p, struct hyp_pool *pool)
{
	bool ret;
	ret = true;
	if (p->pool != pool) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("found wrong pool at next start page"); }
	if (p->order == HYP_NO_ORDER) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("found HYP_NO_ORDER at next start page"); }
	if (p->order > HYP_MAX_ORDER) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("found over-large order in start page"); }
	if ((phys & GENMASK(p->order + PAGE_SHIFT - 1, 0)) != 0) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("found unaligned page group in start page"); }
	if (phys + PAGE_SIZE*(1ul << p->order) > pool->range_end) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("body runs over range_end"); }
	if (p->refcount != 0 || in_used_pages(phys,pool)) {
		if (!list_empty(&p->node)) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("found non-empty list in refcount!=0 or used_pages start page"); } }
	else {
		if (!list_contains(&p->node, &pool->free_area[p->order])) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("refcount==0 non-used_pages start page not in free list of its order"); }

		if (find_free_buddy(p, p->order, pool) != NULL) { ret=false; hyp_putsxn("phys",(u64)phys,64); check_assert_fail("found free buddy"); }
	}

	return ret;
}

/* well-formed page_group body page */
bool check_page_group_body(struct hyp_page *pbody, struct hyp_pool *pool)
{
	bool ret;
	ret= true;
	if (pbody->pool != pool) { ret=false; check_assert_fail("found wrong pool in body"); }
	if (pbody->order != HYP_NO_ORDER) { ret=false; check_assert_fail("found non-HYP_NO_ORDER in body"); }
	if (pbody->refcount !=0) { ret=false; check_assert_fail("found non-zero refcount in body"); }
	if (!list_empty(&pbody->node)) { ret=false; check_assert_fail("found non-empty list in body"); }
	return ret;
}

/* well-formed page_group */
bool check_page_group(phys_addr_t phys, struct hyp_page *p, struct hyp_pool *pool)
{
	bool ret;
	struct hyp_page *pbody;
	ret = check_page_group_start(phys, p, pool);
	for (pbody=p+1; pbody < p+(1ul << (p->order)); pbody++) {
		ret = ret && check_page_group_body(pbody, pool);
	}
	return ret;
}

/* add page_group to abstraction */
void add_page_group(struct page_groups *pgs, phys_addr_t phys, unsigned int order, bool free, struct hyp_pool *pool)
{
	struct page_group *pg;

	pg = &pgs->page_group[pgs->count];
	if (pgs->count >= MAX_PAGE_GROUPS) {check_assert_fail("overran MAX_PAGE_GROUPS"); return; }

	pg->start = phys;
	pg->order = order;
	pg->free = free;

	put_page_group(pg, pool);

	pgs->count++;
}

/* check all page groups and compute abstraction */

bool check_page_groups_and_interpret(struct page_groups* pgs, struct hyp_pool *pool)
{
	phys_addr_t phys;
	struct hyp_page *p;

	bool ret;
	ret = true;
	pgs->count = 0;
	phys = pool->range_start;
	while (phys < pool->range_end) {
		p = hyp_phys_to_page(phys);
		ret = ret && check_page_group(phys, p, pool);
		add_page_group(pgs, phys, p->order, (p->refcount == 0), pool);
		phys += PAGE_SIZE*(1ul << p->order);
	}
	return ret;
}


// running this, we see multiple initialisations of the allocator - why?



/* ****************************************************************** */
// PS: smoke test: check the above invariant

bool check_alloc_invariant(struct hyp_pool *pool) {
	bool ret;
	ret = true;
	ret = ret && check_page_groups_and_interpret(&page_groups_a, pool);
	ret = ret && check_free_lists(pool);
	put_free_lists(pool);

	if (!ret)
		hyp_putsp("check_alloc_invariant failed\n");
	else
		hyp_putsp("check_alloc_invariant succeed\n");

	return ret;
}


/* ****************************************************************** */
/* sample output
hyp_pool_init phys:0x000000013e02f000 phys':0x000000013eab0000 nr_pages:0x00000a81 used_pages:0x00000020 
page group start:0x000000013e02f000 end:0x000000013e030000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e030000 end:0x000000013e031000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e031000 end:0x000000013e032000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e032000 end:0x000000013e033000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e033000 end:0x000000013e034000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e034000 end:0x000000013e035000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e035000 end:0x000000013e036000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e036000 end:0x000000013e037000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e037000 end:0x000000013e038000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e038000 end:0x000000013e039000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e039000 end:0x000000013e03a000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e03a000 end:0x000000013e03b000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e03b000 end:0x000000013e03c000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e03c000 end:0x000000013e03d000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e03d000 end:0x000000013e03e000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e03e000 end:0x000000013e03f000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e03f000 end:0x000000013e040000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e040000 end:0x000000013e041000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e041000 end:0x000000013e042000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e042000 end:0x000000013e043000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e043000 end:0x000000013e044000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e044000 end:0x000000013e045000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e045000 end:0x000000013e046000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e046000 end:0x000000013e047000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e047000 end:0x000000013e048000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e048000 end:0x000000013e049000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e049000 end:0x000000013e04a000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e04a000 end:0x000000013e04b000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e04b000 end:0x000000013e04c000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e04c000 end:0x000000013e04d000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e04d000 end:0x000000013e04e000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e04e000 end:0x000000013e04f000 order:0x00000000 used_pages:true free:true
page group start:0x000000013e04f000 end:0x000000013e050000 order:0x00000000 used_pages:false free:true
page group start:0x000000013e050000 end:0x000000013e060000 order:0x00000004 used_pages:false free:true
page group start:0x000000013e060000 end:0x000000013e080000 order:0x00000005 used_pages:false free:true
page group start:0x000000013e080000 end:0x000000013e100000 order:0x00000007 used_pages:false free:true
page group start:0x000000013e100000 end:0x000000013e200000 order:0x00000008 used_pages:false free:true
page group start:0x000000013e200000 end:0x000000013e400000 order:0x00000009 used_pages:false free:true
page group start:0x000000013e400000 end:0x000000013e800000 order:0x0000000a used_pages:false free:true
page group start:0x000000013e800000 end:0x000000013ea00000 order:0x00000009 used_pages:false free:true
page group start:0x000000013ea00000 end:0x000000013ea80000 order:0x00000007 used_pages:false free:true
page group start:0x000000013ea80000 end:0x000000013eaa0000 order:0x00000005 used_pages:false free:true
page group start:0x000000013eaa0000 end:0x000000013eab0000 order:0x00000004 used_pages:false free:true
order:0x0000000000000000 :0x000000013e04f000
order:0x0000000000000001
order:0x0000000000000002
order:0x0000000000000003
order:0x0000000000000004 :0x000000013e050000 :0x000000013eaa0000
order:0x0000000000000005 :0x000000013e060000 :0x000000013ea80000
order:0x0000000000000006
order:0x0000000000000007 :0x000000013e080000 :0x000000013ea00000
order:0x0000000000000008 :0x000000013e100000
order:0x0000000000000009 :0x000000013e200000 :0x000000013e800000
order:0x000000000000000a :0x000000013e400000
order:0x000000000000000b
check_alloc_invariant succeed
*/


/* ****************************************************************** */
// PS: the following is the original code plus my comments plus a
// smoke-test check of the check_alloc_invariant

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
   group, either before or after) if its start page is within the pool range,
   otherwise return NULL */
/* PS: this is a pure-ish function: no non-local writes */
/* PS: looking at this range_end check: it only checks the base
   address of the buddy page group, not the end address. The range
   that the pool is initialised with is a nice power of two and
   suitably aligned, which is not the case in general. But the
   __hyp_attach_page also checks that the order of the buddy is the
   same as the order of the page its considering, which implies that
   all of the buddy must have been allocated sometime*/
/* PS: for the range_start check, should that really be range_start+PAGE_SIZE*used_pages?
   why is it ok as-is?  Because __hyp_attach_page also checks the buddy is in a free list, 
   and the used_pages never are */
static struct hyp_page *__find_buddy(struct hyp_pool *pool, struct hyp_page *p,
				     unsigned int order)
{
	phys_addr_t addr = hyp_page_to_phys(p);

	addr ^= (PAGE_SIZE << order);
	if (addr < pool->range_start || addr >= pool->range_end)
		return NULL;

	return hyp_phys_to_page(addr);
}


/* PS: given a hyp_page p in the vmemmap, transfer that page group (at the order in that hyp_page) back to the allocator, coalescing buddys as much as possible */
/* PS: note that the buddy->order != order check ensures that the buddy page-group is the same order as the one we're trying to coalesce with it, and also ensures, if buddy->order==order, that all of the buddy must have been allocated sometime, and so be inside range_start..range_end */
/* PS: can __hyp_attach_page mistakenly coalesce with the last unused_page?  No, because the used_pages have empty free lists */
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
// PS: ...actually transferring ownership if it's the last reference-count
// PS: precondition: the refcount for the page at hyp_virt addr is non-zero
// PS: decrement it
// PS: if the recount becomes zero, __hyp_attach_page the page group
// PS: all protected by the pool lock
// PS: some standard seplogic idiom for ref-counted ownership?
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

// PS: just bump the refcount for the page at hyp_virt addr
// PS: protected by the pool lock
void hyp_get_page(void *addr)
{
	struct hyp_page *p = hyp_virt_to_page(addr);
	struct hyp_pool *pool = hyp_page_to_pool(p);

	hyp_spin_lock(&pool->lock);
	p->refcount++;
	hyp_spin_unlock(&pool->lock);
}


// PS: precondition: p is a free (probably non-used_page) page-group of order at least order 
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

	// PS: add check.  later we may need to make these sample, not be re-run on every call
	hyp_putsxn("__hyp_alloc_pages order",order,32);
	hyp_putsxn(" returned p",(u64)p,64);
	check_alloc_invariant(pool);

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

	// PS: add:
	hyp_putsxn("hyp_pool_init phys",phys,64);
	hyp_putsxn("phys'",phys+PAGE_SIZE*nr_pages,64);
	hyp_putsxn("nr_pages",nr_pages,32);
	hyp_putsxn("used_pages",used_pages,32);
	hyp_putsp("\n");


	if (phys % PAGE_SIZE)
		return -EINVAL;

	// PS: initialise `pool`: the spinlock, the start and end to `phys` (surprising that this is a physical address?), and the per-order free lists to empty lists (pointing to themselves, see include/linux/list.h)
	hyp_spin_lock_init(&pool->lock);
	for (i = 0; i <= HYP_MAX_ORDER; i++)
		INIT_LIST_HEAD(&pool->free_area[i]);
	pool->range_start = phys;
	pool->range_end = phys + (nr_pages << PAGE_SHIFT);

	// PS: add this to help state the invariant:
	pool->used_pages = used_pages;

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
