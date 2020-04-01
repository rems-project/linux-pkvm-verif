// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_HYP_GFP_H
#define __KVM_HYP_GFP_H

#include <linux/list.h> /* XXX - use hyp version instead */

#include <nvhe/memory.h>
#include <nvhe/spinlock.h>

#define HYP_MAX_ORDER	11U
#define HYP_NO_ORDER	UINT_MAX

struct hyp_pool {
	nvhe_spinlock_t lock;
	struct list_head free_area[HYP_MAX_ORDER + 1];
};

/* GFP flags */
#define HYP_GFP_NONE	0
#define HYP_GFP_ZERO	1

/* Allocation */
void *hyp_alloc_pages(struct hyp_pool *pool, gfp_t mask, unsigned int order);
void hyp_get_page(void *addr);
void hyp_put_page(void *addr);

/* Used pages cannot be freed */
int hyp_pool_extend_used(struct hyp_pool *pool, phys_addr_t phys,
			 unsigned int nr_pages, unsigned int used_pages);
void hyp_pool_init(struct hyp_pool *pool);
#endif /* __KVM_HYP_GFP_H */
