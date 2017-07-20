/* Copyright 2008-2012 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file	bman.c
 * @brief	bman driver
 */

#include "bman.h"

#include "mtrace.h"

struct bman_portal {
	struct bm_portal p;
	/* When the cpu-affine portal is activated, this is non-NULL */
	const struct bm_portal_config *config;
	/* This is needed for power management */
	struct platform_device *pdev;
	/* Track if the portal was alloced by the driver */
	u8 alloced;
};

#define PORTAL_IRQ_LOCK(p, irqflags)	do { ; } while (0)
#define PORTAL_IRQ_UNLOCK(p, irqflags)	do { ; } while (0)

static DEFINE_PER_CPU(struct bman_portal, bman_affine_portal);
static inline struct bman_portal *get_raw_affine_portal(void)
{
	return this_cpu_ptr(&bman_affine_portal);
}
#define get_affine_portal() get_raw_affine_portal()
#define put_affine_portal()
static inline struct bman_portal *get_poll_portal(void)
{
	return this_cpu_ptr(&bman_affine_portal);
}
#define put_poll_portal()

/* GOTCHA: this object type refers to a pool, it isn't *the* pool. There may be
 * more than one such object per Bman buffer pool, eg. if different users of the
 * pool are operating via different portals. */
struct bman_pool {
	struct bman_pool_params params;
	/* Used for hash-table admin when using depletion notifications. */
	struct bman_portal *portal;
};

struct bman_portal *bman_create_portal(
				       struct bman_portal *portal,
				       const struct bm_portal_config *config)
{
	struct bm_portal *__p;
	int ret;
	u8 bpid = 0;
	char buf[16];

	if (!portal) {
		portal = kmalloc(sizeof(*portal), GFP_KERNEL);
		if (!portal)
			return portal;
		portal->alloced = 1;
	} else
		portal->alloced = 0;

	__p = &portal->p;

	/* prep the low-level portal struct with the mapped addresses from the
	 * config, everything that follows depends on it and "config" is more
	 * for (de)reference... */
	__p->addr.addr_ce = config->addr_virt[DPA_PORTAL_CE];
	__p->addr.addr_ci = config->addr_virt[DPA_PORTAL_CI];
	if (bm_rcr_init(__p, bm_rcr_pvb, bm_rcr_cce)) {
		pr_err("Bman RCR initialisation failed\n");
		goto fail_rcr;
	}
	if (bm_mc_init(__p)) {
		pr_err("Bman MC initialisation failed\n");
		goto fail_mc;
	}
	if (bm_isr_init(__p)) {
		pr_err("Bman ISR initialisation failed\n");
		goto fail_isr;
	}
	while (bpid < bman_pool_max) {
		/* Default to all BPIDs disabled, we enable as required at
		 * run-time. */
		bm_isr_bscn_mask(__p, bpid, 0);
		bpid++;
	}
	sprintf(buf, "bportal-%u", config->public_cfg.index);
	portal->pdev = platform_device_alloc(buf, -1);
	if (!portal->pdev) {
		pr_err("bman_portal - platform_device_alloc() failed\n");
		goto fail_devalloc;
	}
	portal->pdev->dev.platform_data = portal;
	ret = platform_device_add(portal->pdev);
	if (ret)
		goto fail_devadd;
	/* Write-to-clear any stale interrupt status bits */
	bm_isr_disable_write(__p, 0xffffffff);
	bm_isr_enable_write(__p, 0);
	bm_isr_status_clear(__p, 0xffffffff);

	/* Need RCR to be empty before continuing */
	ret = bm_rcr_get_fill(__p);
	if (ret) {
		pr_err("Bman RCR unclean\n");
		goto fail_rcr_empty;
	}
	/* Success */
	portal->config = config;

	bm_isr_disable_write(__p, 0);
	bm_isr_uninhibit(__p);
	return portal;
fail_rcr_empty:
	platform_device_del(portal->pdev);
fail_devadd:
	portal->pdev->dev.platform_data = NULL;
	platform_device_put(portal->pdev);
fail_devalloc:
	bm_isr_finish(__p);
fail_isr:
	bm_mc_finish(__p);
fail_mc:
	bm_rcr_finish(__p);
fail_rcr:
	if (portal->alloced)
		kfree(portal);
	return NULL;
}

struct bman_portal *bman_create_affine_portal(
			const struct bm_portal_config *config)
{
	struct bman_portal *portal;

	portal = per_cpu_ptr(&bman_affine_portal, config->public_cfg.cpu);
	portal = bman_create_portal(portal, config);
	return portal;
}

void bman_destroy_portal(struct bman_portal *bm)
{
	const struct bm_portal_config *pcfg;
	pcfg = bm->config;
	bm_rcr_cce_update(&bm->p);
	bm_rcr_cce_update(&bm->p);

	bm_isr_finish(&bm->p);
	bm_mc_finish(&bm->p);
	bm_rcr_finish(&bm->p);

	platform_device_del(bm->pdev);
	bm->pdev->dev.platform_data = NULL;
	platform_device_put(bm->pdev);

	bm->config = NULL;
	if (bm->alloced)
		kfree(bm);
}

const struct bm_portal_config *bman_destroy_affine_portal(void)
{
	struct bman_portal *p;
	const struct bm_portal_config *pcfg;

	p = get_raw_affine_portal();
	pcfg = p->config;
	bman_destroy_portal(p);
	put_affine_portal();

	return pcfg;
}

struct bman_pool *bman_new_pool(const struct bman_pool_params *params)
{
	struct bman_pool *pool = NULL;
	u32 bpid, thresholds[4] = {};

	if (params->flags & BMAN_POOL_FLAG_DYNAMIC_BPID) {
		int ret = bman_alloc_bpid(&bpid);
		if (ret)
			return NULL;
	} else {
		if (params->bpid >= bman_pool_max)
			return NULL;
		bpid = params->bpid;
	}
	bm_pool_set(bpid, thresholds);
	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		goto err;
	pool->params = *params;
	if (params->flags & BMAN_POOL_FLAG_DYNAMIC_BPID)
		pool->params.bpid = bpid;
	return pool;
err:
	if (params->flags & BMAN_POOL_FLAG_DYNAMIC_BPID)
		bman_release_bpid(bpid);
	if (pool) {
		kfree(pool);
	}
	return NULL;
}

void bman_free_pool(struct bman_pool *pool)
{
	if (pool->params.flags & BMAN_POOL_FLAG_DYNAMIC_BPID)
		bman_release_bpid(pool->params.bpid);
	kfree(pool);
}

static noinline void update_rcr_ci(struct bman_portal *p, u8 avail)
{
	if (avail)
		bm_rcr_cce_prefetch(&p->p);
	else
		bm_rcr_cce_update(&p->p);
}

static inline struct bm_rcr_entry *try_rel_start(struct bman_portal **p,
					__maybe_unused unsigned long *irqflags,
					__maybe_unused u32 flags)
{
	struct bm_rcr_entry *r;
	u8 avail;

	*p = get_affine_portal();
	PORTAL_IRQ_LOCK(*p, (*irqflags));
	avail = bm_rcr_get_avail(&(*p)->p);
	if (avail < 2)
		update_rcr_ci(*p, avail);
	r = bm_rcr_start(&(*p)->p);
	if (unlikely(!r)) {
		PORTAL_IRQ_UNLOCK(*p, (*irqflags));
		put_affine_portal();
	}
	return r;
}

union __bm_buffer {
	struct bm_buffer buf;
	u64 opaque;
};

static inline int ___bman_release(struct bman_pool *pool,
			const struct bm_buffer *bufs, u8 num, u32 flags)
{
	struct bman_portal *p;
	struct bm_rcr_entry *r;
	union __bm_buffer *o_dst;
	union __bm_buffer *o_src = (union __bm_buffer *)bufs;
	__maybe_unused unsigned long irqflags;
	u32 i = num - 1;

	r = try_rel_start(&p, &irqflags, flags);
	if (!r)
		return -EBUSY;
	/* We can copy all but the first entry, as this can trigger badness
	 * with the valid-bit. Use the overlay to mask the verb byte. */
	o_dst = (union __bm_buffer *)r->bufs;
	o_dst[0].opaque =
		((cpu_to_be64((o_src[0].opaque |
			      ((u64)pool->params.bpid<<48))
			      & 0x00ffffffffffffff)));
	if (i) {
		for (i = 1; i < num; i++)
			o_dst[i].opaque =
				cpu_to_be64(o_src[i].opaque);
	}

	bm_rcr_pvb_commit(&p->p, BM_RCR_VERB_CMD_BPID_SINGLE |
			(num & BM_RCR_VERB_BUFCOUNT_MASK));
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	return 0;
}

int bman_release(struct bman_pool *pool, const struct bm_buffer *bufs, u8 num,
			u32 flags)
{
#ifdef CONFIG_FSL_DPA_CHECKING
	if (!num || (num > 8))
		return -EINVAL;
	if (pool->params.flags & BMAN_POOL_FLAG_NO_RELEASE)
		return -EINVAL;
#endif
	return ___bman_release(pool, bufs, num, flags);
}

static inline int ___bman_acquire(struct bman_pool *pool, struct bm_buffer *bufs,
					u8 num)
{
	struct bman_portal *p = get_affine_portal();
	struct bm_mc_command *mcc;
	struct bm_mc_result *mcr;
	union __bm_buffer *o_dst = (union __bm_buffer *)bufs;
	union __bm_buffer *o_src;
	__maybe_unused unsigned long irqflags;
	int ret, i;

	PORTAL_IRQ_LOCK(p, irqflags);
	mcc = bm_mc_start(&p->p);
	mcc->acquire.bpid = pool->params.bpid;
	bm_mc_commit(&p->p, BM_MCC_VERB_CMD_ACQUIRE |
			(num & BM_MCC_VERB_ACQUIRE_BUFCOUNT));
	while (!(mcr = bm_mc_result(&p->p)))
		cpu_relax();
	ret = mcr->verb & BM_MCR_VERB_ACQUIRE_BUFCOUNT;
	if (bufs) {
		o_src = (union __bm_buffer *)mcr->acquire.bufs;
		for (i = 0; i < num; i++)
			o_dst[i].opaque =
				be64_to_cpu(o_src[i].opaque);
	}
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	if (ret != num)
		ret = -ENOMEM;
	return ret;
}

int bman_acquire(struct bman_pool *pool, struct bm_buffer *bufs, u8 num,
			u32 flags)
{
#ifdef CONFIG_FSL_DPA_CHECKING
	if (!num || (num > 8))
		return -EINVAL;
	if (pool->params.flags & BMAN_POOL_FLAG_ONLY_RELEASE)
		return -EINVAL;
#endif
	return ___bman_acquire(pool, bufs, num);
}

int bman_shutdown_pool(u32 bpid)
{
	struct bman_portal *p = get_affine_portal();
	__maybe_unused unsigned long irqflags;
	int ret;

	PORTAL_IRQ_LOCK(p, irqflags);
	ret = bm_shutdown_pool(&p->p, bpid);
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	return ret;
}
