/*
 * Copyright (C) 2016
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	qman.c
 * @brief	qman driver
 */

#include "qman.h"

#include "mtrace.h"

/* Compilation constants */
#define DQRR_MAXFILL	15

/* Lock/unlock frame queues, subject to the "LOCKED" flag. This is about
 * inter-processor locking only. Note, FQLOCK() is always called either under a
 * local_irq_save() or from interrupt context - hence there's no need for irq
 * protection (and indeed, attempting to nest irq-protection doesn't work, as
 * the "irq en/disable" machinery isn't recursive...). */
#define FQLOCK(fq) \
	do { \
		struct qman_fq *__fq478 = (fq); \
		if (fq_isset(__fq478, QMAN_FQ_FLAG_LOCKED)) \
			spin_lock(&__fq478->fqlock); \
	} while (0)
#define FQUNLOCK(fq) \
	do { \
		struct qman_fq *__fq478 = (fq); \
		if (fq_isset(__fq478, QMAN_FQ_FLAG_LOCKED)) \
			spin_unlock(&__fq478->fqlock); \
	} while (0)

static inline void fq_set(struct qman_fq *fq, u32 mask)
{
	set_bits(mask, &fq->flags);
}
static inline void fq_clear(struct qman_fq *fq, u32 mask)
{
	clear_bits(mask, &fq->flags);
}
static inline int fq_isset(struct qman_fq *fq, u32 mask)
{
	return fq->flags & mask;
}
static inline int fq_isclear(struct qman_fq *fq, u32 mask)
{
	return !(fq->flags & mask);
}

struct qman_portal {
	struct qm_portal p;
	u32 use_eqcr_ci_stashing;
	struct qman_fq *vdqcr_owned; /* only 1 volatile dequeue at a time */
	u32 sdqcr;
	/* When the cpu-affine portal is activated, this is non-NULL */
	const struct qm_portal_config *config;
	/* This is needed for providing a non-NULL device to dma_map_***() */
	struct platform_device *pdev;
	struct dpa_rbtree retire_table;
	/* track if memory was allocated by the driver */
	u8 alloced;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	/* Keep a shadow copy of the DQRR on LE systems as the SW needs to
	 * do byte swaps of DQRR read only memory.  First entry must be aligned
	 * to 2 ** 10 to ensure DQRR index calculations based shadow copy
	 * address (6 bits for address shift + 4 bits for the DQRR size).
	 */
	struct qm_dqrr_entry shadow_dqrr[QM_DQRR_SIZE] __aligned(1024);
#endif
};

#define PORTAL_IRQ_LOCK(p, irqflags)	do { ; } while (0)
#define PORTAL_IRQ_UNLOCK(p, irqflags)	do { ; } while (0)

static DEFINE_PER_CPU(struct qman_portal, qman_affine_portal);

/* "raw" gets the cpu-local struct whether it's a redirect or not. */
static inline struct qman_portal *get_raw_affine_portal(void)
{
	return &get_cpu_var(qman_affine_portal);
}
/* For ops that can redirect, this obtains the portal to use */
#define get_affine_portal() get_raw_affine_portal()
/* For every "get", there must be a "put" */
static inline void put_affine_portal(void)
{
	put_cpu_var(qman_affine_portal);
}
/* Exception: poll functions assume the caller is cpu-affine and in no risk of
 * re-entrance, which are the two reasons we usually use the get/put_cpu_var()
 * semantic - ie. to disable pre-emption. Some use-cases expect the execution
 * context to remain as non-atomic during poll-triggered callbacks as it was
 * when the poll API was first called (eg. NAPI), so we go out of our way in
 * this case to not disable pre-emption. */
static inline struct qman_portal *get_poll_portal(void)
{
	return &get_cpu_var(qman_affine_portal);
}
#define put_poll_portal()

/* This gives a FQID->FQ lookup to cover the fact that we can't directly demux
 * retirement notifications (the fact they are sometimes h/w-consumed means that
 * contextB isn't always a s/w demux - and as we can't know which case it is
 * when looking at the notification, we have to use the slow lookup for all of
 * them). NB, it's possible to have multiple FQ objects refer to the same FQID
 * (though at most one of them should be the consumer), so this table isn't for
 * all FQs - FQs are added when retirement commands are issued, and removed when
 * they complete, which also massively reduces the size of this table. */
IMPLEMENT_DPA_RBTREE(fqtree, struct qman_fq, node, fqid);

static inline int table_push_fq(struct qman_portal *p, struct qman_fq *fq)
{
	int ret = fqtree_push(&p->retire_table, fq);
	if (ret)
		pr_err("ERROR: double FQ-retirement %d\n", fq->fqid);
	return ret;
}

static inline void table_del_fq(struct qman_portal *p, struct qman_fq *fq)
{
	fqtree_del(&p->retire_table, fq);
}

static inline struct qman_fq *table_find_fq(struct qman_portal *p, u32 fqid)
{
	return fqtree_find(&p->retire_table, fqid);
}

#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
static void **qman_fq_lookup_table;
static size_t qman_fq_lookup_table_size;

int qman_setup_fq_lookup_table(size_t num_entries)
{
	num_entries++;
	/* Allocate 1 more entry since the first entry is not used */
	qman_fq_lookup_table = vzalloc((num_entries * sizeof(void *)));
	if (!qman_fq_lookup_table) {
		pr_err("QMan: Could not allocate fq lookup table\n");
		return -ENOMEM;
	}
	qman_fq_lookup_table_size = num_entries;
	pr_debug("QMan: Allocated lookup table at %p, entry count %lu\n",
			qman_fq_lookup_table,
			(unsigned long)qman_fq_lookup_table_size);
	return 0;
}

void qman_clean_fq_lookup_table(void) {
	vfree(qman_fq_lookup_table);
}

/* global structure that maintains fq object mapping */
static DEFINE_SPINLOCK(fq_hash_table_lock);

static int find_empty_fq_table_entry(u32 *entry, struct qman_fq *fq)
{
	u32 i;

	spin_lock(&fq_hash_table_lock);
	/* Can't use index zero because this has special meaning
	 * in context_b field. */
	for (i = 1; i < qman_fq_lookup_table_size; i++) {
		if (qman_fq_lookup_table[i] == NULL) {
			*entry = i;
			qman_fq_lookup_table[i] = fq;
			spin_unlock(&fq_hash_table_lock);
			return 0;
		}
	}
	spin_unlock(&fq_hash_table_lock);
	return -ENOMEM;
}

static void clear_fq_table_entry(u32 entry)
{
	spin_lock(&fq_hash_table_lock);
	BUG_ON(entry >= qman_fq_lookup_table_size);
	qman_fq_lookup_table[entry] = NULL;
	spin_unlock(&fq_hash_table_lock);
}

static inline struct qman_fq *get_fq_table_entry(u32 entry)
{
	BUG_ON(entry >= qman_fq_lookup_table_size);
	return qman_fq_lookup_table[entry];
}
#endif

static inline void cpu_to_hw_fqd(struct qm_fqd *fqd)
{
	/* Byteswap the FQD to HW format */
	fqd->fq_ctrl = cpu_to_be16(fqd->fq_ctrl);
	fqd->dest_wq = cpu_to_be16(fqd->dest_wq);
	fqd->ics_cred = cpu_to_be16(fqd->ics_cred);
	fqd->context_b = cpu_to_be32(fqd->context_b);
	fqd->context_a.opaque = cpu_to_be64(fqd->context_a.opaque);
}

static inline void hw_fqd_to_cpu(struct qm_fqd *fqd)
{
	/* Byteswap the FQD to CPU format */
	fqd->fq_ctrl = be16_to_cpu(fqd->fq_ctrl);
	fqd->dest_wq = be16_to_cpu(fqd->dest_wq);
	fqd->ics_cred = be16_to_cpu(fqd->ics_cred);
	fqd->context_b = be32_to_cpu(fqd->context_b);
	fqd->context_a.opaque = be64_to_cpu(fqd->context_a.opaque);
}

static inline void cpu_to_hw_fd(struct qm_fd *fd)
{
	fd->opaque_addr = cpu_to_be64(fd->opaque_addr);
	fd->status = cpu_to_be32(fd->status);
	fd->opaque = cpu_to_be32(fd->opaque);
}

static inline void hw_fd_to_cpu(struct qm_fd *fd)
{
	fd->opaque_addr = be64_to_cpu(fd->opaque_addr);
	fd->status = be32_to_cpu(fd->status);
	fd->opaque = be32_to_cpu(fd->opaque);
}

static int drain_mr_fqrni(struct qm_portal *p)
{
	const struct qm_mr_entry *msg;
loop:
	msg = qm_mr_current(p);
	if (!msg) {
		/* if MR was full and h/w had other FQRNI entries to produce, we
		 * need to allow it time to produce those entries once the
		 * existing entries are consumed. A worst-case situation
		 * (fully-loaded system) means h/w sequencers may have to do 3-4
		 * other things before servicing the portal's MR pump, each of
		 * which (if slow) may take ~50 qman cycles (which is ~200
		 * processor cycles). So rounding up and then multiplying this
		 * worst-case estimate by a factor of 10, just to be
		 * ultra-paranoid, goes as high as 10,000 cycles. NB, we consume
		 * one entry at a time, so h/w has an opportunity to produce new
		 * entries well before the ring has been fully consumed, so
		 * we're being *really* paranoid here. */
		u64 now, then = mfatb();
		do {
			now = mfatb();
		} while ((then + 10000) > now);
		msg = qm_mr_current(p);
		if (!msg)
			return 0;
	}
	if ((msg->verb & QM_MR_VERB_TYPE_MASK) != QM_MR_VERB_FQRNI) {
		/* We aren't draining anything but FQRNIs */
		pr_err("QMan found verb 0x%x in MR\n", msg->verb);
		return -1;
	}
	qm_mr_next(p);
	qm_mr_cci_consume(p, 1);
	goto loop;
}

struct qman_portal *qman_create_portal(
			struct qman_portal *portal,
			const struct qm_portal_config *config)
{
	struct qm_portal *__p;
	char buf[16];
	int ret;
	u32 isdr;

	if (!portal) {
		portal = kmalloc(sizeof(*portal), GFP_KERNEL);
		if (!portal)
			return portal;
		portal->alloced = 1;
	} else
		portal->alloced = 0;

	__p = &portal->p;

#if (defined CONFIG_PPC || defined CONFIG_PPC64) && defined CONFIG_FSL_PAMU
        /* PAMU is required for stashing */
        portal->use_eqcr_ci_stashing = ((qman_ip_rev >= QMAN_REV30) ?
					1 : 0);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	portal->use_eqcr_ci_stashing = 1;
#else
        portal->use_eqcr_ci_stashing = 0;
#endif

	/* prep the low-level portal struct with the mapped addresses from the
	 * config, everything that follows depends on it and "config" is more
	 * for (de)reference... */
	__p->addr.addr_ce = config->addr_virt[DPA_PORTAL_CE];
	__p->addr.addr_ci = config->addr_virt[DPA_PORTAL_CI];
	/*
	 * If CI-stashing is used, the current defaults use a threshold of 3,
	 * and stash with high-than-DQRR priority.
	 */
	if (qm_eqcr_init(__p, qm_eqcr_pvb,
			portal->use_eqcr_ci_stashing ? 3 : 0, 1)) {
		pr_err("Qman EQCR initialisation failed\n");
		goto fail_eqcr;
	}
	if (qm_dqrr_init(__p, config, qm_dqrr_dpush, qm_dqrr_pvb,
			qm_dqrr_cdc, DQRR_MAXFILL)) {
		pr_err("Qman DQRR initialisation failed\n");
		goto fail_dqrr;
	}
	if (qm_mr_init(__p, qm_mr_pvb, qm_mr_cci)) {
		pr_err("Qman MR initialisation failed\n");
		goto fail_mr;
	}
	if (qm_mc_init(__p)) {
		pr_err("Qman MC initialisation failed\n");
		goto fail_mc;
	}
	if (qm_isr_init(__p)) {
		pr_err("Qman ISR initialisation failed\n");
		goto fail_isr;
	}
	/* static interrupt-gating controls */
	qm_dqrr_set_ithresh(__p, CONFIG_FSL_QMAN_PIRQ_DQRR_ITHRESH);
	qm_mr_set_ithresh(__p, CONFIG_FSL_QMAN_PIRQ_MR_ITHRESH);
	qm_isr_set_iperiod(__p, CONFIG_FSL_QMAN_PIRQ_IPERIOD);
	portal->sdqcr = QM_SDQCR_SOURCE_CHANNELS | QM_SDQCR_COUNT_UPTO3 |
			QM_SDQCR_DEDICATED_PRECEDENCE | QM_SDQCR_TYPE_PRIO_QOS |
			QM_SDQCR_TOKEN_SET(0xab) | QM_SDQCR_CHANNELS_DEDICATED;
	sprintf(buf, "qportal-%d", config->public_cfg.channel);
	portal->pdev = platform_device_alloc(buf, -1);
	if (!portal->pdev) {
		pr_err("qman_portal - platform_device_alloc() failed\n");
		goto fail_devalloc;
	}
#ifdef CONFIG_ARM
	portal->pdev->dev.coherent_dma_mask = DMA_BIT_MASK(40);
	portal->pdev->dev.dma_mask = &portal->pdev->dev.coherent_dma_mask;
#else
	if (dma_set_mask(&portal->pdev->dev, DMA_BIT_MASK(40))) {
		pr_err("qman_portal - dma_set_mask() failed\n");
		goto fail_devadd;
	}
#endif
	portal->pdev->dev.platform_data = portal;
	ret = platform_device_add(portal->pdev);
	if (ret) {
		pr_err("qman_portal - platform_device_add() failed\n");
		goto fail_devadd;
	}
	dpa_rbtree_init(&portal->retire_table);
	isdr = 0xffffffff;
	qm_isr_disable_write(__p, isdr);
	qm_isr_enable_write(__p, 0);
	qm_isr_status_clear(__p, 0xffffffff);

	/* Need EQCR to be empty before continuing */
	isdr ^= QM_PIRQ_EQCI;
	qm_isr_disable_write(__p, isdr);
	ret = qm_eqcr_get_fill(__p);
	if (ret) {
		pr_err("Qman EQCR unclean\n");
		goto fail_eqcr_empty;
	}
	isdr ^= (QM_PIRQ_DQRI | QM_PIRQ_MRI);
	qm_isr_disable_write(__p, isdr);
	if (qm_dqrr_current(__p) != NULL) {
		pr_err("Qman DQRR unclean\n");
		qm_dqrr_cdc_consume_n(__p, 0xffff);
	}
	if (qm_mr_current(__p) != NULL) {
		/* special handling, drain just in case it's a few FQRNIs */
		if (drain_mr_fqrni(__p)) {
			const struct qm_mr_entry *e = qm_mr_current(__p);
			/*
			 * Message ring cannot be empty no need to check
			 * qm_mr_current returned successfully
			 */
			pr_err("Qman MR unclean, MR VERB 0x%x, rc 0x%x\n, addr 0x%x",
				e->verb, e->ern.rc, e->ern.fd.addr_lo);
			goto fail_dqrr_mr_empty;
		}
	}
	/* Success */
	portal->config = config;
	qm_isr_disable_write(__p, 0);
	qm_isr_uninhibit(__p);
	/* Write a sane SDQCR */
	qm_dqrr_sdqcr_set(__p, portal->sdqcr);
	return portal;
fail_dqrr_mr_empty:
fail_eqcr_empty:
	platform_device_del(portal->pdev);
fail_devadd:
	portal->pdev->dev.platform_data = NULL;
	platform_device_put(portal->pdev);
fail_devalloc:
	qm_isr_finish(__p);
fail_isr:
	qm_mc_finish(__p);
fail_mc:
	qm_mr_finish(__p);
fail_mr:
	qm_dqrr_finish(__p);
fail_dqrr:
	qm_eqcr_finish(__p);
fail_eqcr:
	if (portal->alloced)
		kfree(portal);
	return NULL;
}

struct qman_portal *qman_create_affine_portal(
			const struct qm_portal_config *config)
{
	struct qman_portal *res;
	struct qman_portal *portal;

	portal = &per_cpu(qman_affine_portal, config->public_cfg.cpu);
	res = qman_create_portal(portal, config);
	return res;
}

void qman_destroy_portal(struct qman_portal *qm)
{
	const struct qm_portal_config *pcfg;

	/* Stop dequeues on the portal */
	qm_dqrr_sdqcr_set(&qm->p, 0);

	/* NB we do this to "quiesce" EQCR. If we add enqueue-completions or
	 * something related to QM_PIRQ_EQCI, this may need fixing.
	 * Also, due to the prefetching model used for CI updates in the enqueue
	 * path, this update will only invalidate the CI cacheline *after*
	 * working on it, so we need to call this twice to ensure a full update
	 * irrespective of where the enqueue processing was at when the teardown
	 * began. */
	qm_eqcr_cce_update(&qm->p);
	qm_eqcr_cce_update(&qm->p);
	pcfg = qm->config;

	qm_isr_finish(&qm->p);
	qm_mc_finish(&qm->p);
	qm_mr_finish(&qm->p);
	qm_dqrr_finish(&qm->p);
	qm_eqcr_finish(&qm->p);

	platform_device_del(qm->pdev);
	qm->pdev->dev.platform_data = NULL;
	platform_device_put(qm->pdev);

	qm->config = NULL;
	if (qm->alloced)
		kfree(qm);
}

void qman_destroy_affine_portal(const struct qm_portal_config *config)
{
	struct qman_portal *portal;

	portal = &per_cpu(qman_affine_portal, config->public_cfg.cpu);

	qman_destroy_portal(portal);
}

/* remove some slowish-path stuff from the "fast path" and make sure it isn't
 * inlined. */
static noinline void clear_vdqcr(struct qman_portal *p, struct qman_fq *fq)
{
	p->vdqcr_owned = NULL;
	FQLOCK(fq);
	fq_clear(fq, QMAN_FQ_STATE_VDQCR);
	FQUNLOCK(fq);
}

/* Copy a DQRR entry ensuring reads reach QBMan in order */
static inline void safe_copy_dqrr(struct qm_dqrr_entry *dst,
				  const struct qm_dqrr_entry *src)
{
	int i = 0;
	const u64 *s64 = (u64*)src;
	u64 *d64 = (u64*)dst;

	/* DQRR only has 32 bytes of valid data so only need to
	 * copy 4 - 64 bit values */
	*d64 = *s64;
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	{
		u32 res, zero = 0;
		/* Create a dependancy after copying first bytes ensures no wrap
		   transaction generated to QBMan */
		/* Logical AND the value pointed to by s64 with 0x0 and
		   store the result in res */
		asm volatile("and %[result], %[in1], %[in2]"
			     : [result] "=r" (res)
			     : [in1] "r" (zero), [in2] "r" (*s64)
			     : "memory");
		/* Add res to s64 - this creates a dependancy on the result of
		   reading the value of s64 before the next read. The side
		   effect of this is that the core must stall until the first
		   aligned read is complete therefore preventing a WRAP
		   transaction to be seen by the QBMan */
		asm volatile("add %[result], %[in1], %[in2]"
			     : [result] "=r" (s64)
			     : [in1] "r" (res), [in2] "r" (s64)
			     : "memory");
	}
#endif
	/* Copy the last 3 64 bit parts */
	d64++; s64++;
	for (;i<3; i++)
		*d64++ = *s64++;
}

/* Look: no locks, no irq_save()s, no preempt_disable()s! :-) The only states
 * that would conflict with other things if they ran at the same time on the
 * same cpu are;
 *
 *   (i) setting/clearing vdqcr_owned, and
 *  (ii) clearing the NE (Not Empty) flag.
 *
 * Both are safe. Because;
 *
 *   (i) this clearing can only occur after qman_volatile_dequeue() has set the
 *       vdqcr_owned field (which it does before setting VDQCR), and
 *       qman_volatile_dequeue() blocks interrupts and preemption while this is
 *       done so that we can't interfere.
 *  (ii) the NE flag is only cleared after qman_retire_fq() has set it, and as
 *       with (i) that API prevents us from interfering until it's safe.
 *
 * The good thing is that qman_volatile_dequeue() and qman_retire_fq() run far
 * less frequently (ie. per-FQ) than __poll_portal_fast() does, so the nett
 * advantage comes from this function not having to "lock" anything at all.
 *
 * Note also that the callbacks are invoked at points which are safe against the
 * above potential conflicts, but that this function itself is not re-entrant
 * (this is because the function tracks one end of each FIFO in the portal and
 * we do *not* want to lock that). So the consequence is that it is safe for
 * user callbacks to call into any Qman API *except* qman_poll() (as that's the
 * sole API that could be invoking the callback through this function).
 */
static inline unsigned int __poll_portal_fast(struct qman_portal *p,
					unsigned int poll_limit)
{
	const struct qm_dqrr_entry *dq;
	struct qman_fq *fq;
	enum qman_cb_dqrr_result res;
	unsigned int limit = 0;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	struct qm_dqrr_entry *shadow;
	const struct qm_dqrr_entry *orig_dq;
#endif
loop:
	qm_dqrr_pvb_update(&p->p);
	dq = qm_dqrr_current(&p->p);
	if (!dq)
		goto done;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	/* If running on an LE system the fields of the
	   dequeue entry must be swapped.  Because the
	   QMan HW will ignore writes the DQRR entry is
	   copied and the index stored within the copy */
	shadow = &p->shadow_dqrr[DQRR_PTR2IDX(dq)];
	/* Use safe copy here to avoid WRAP transaction */
	safe_copy_dqrr(shadow, dq);
	orig_dq = dq;
	dq = shadow;
	shadow->fqid = be32_to_cpu(shadow->fqid);
	shadow->contextB = be32_to_cpu(shadow->contextB);
	shadow->seqnum = be16_to_cpu(shadow->seqnum);
	hw_fd_to_cpu(&shadow->fd);
#endif
	if (dq->stat & QM_DQRR_STAT_UNSCHEDULED) {
		/* VDQCR: don't trust contextB as the FQ may have been
		 * configured for h/w consumption and we're draining it
		 * post-retirement. */
		fq = p->vdqcr_owned;
		/* We only set QMAN_FQ_STATE_NE when retiring, so we only need
		 * to check for clearing it when doing volatile dequeues. It's
		 * one less thing to check in the critical path (SDQCR). */
		if (dq->stat & QM_DQRR_STAT_FQ_EMPTY)
			fq_clear(fq, QMAN_FQ_STATE_NE);
		/* this is duplicated from the SDQCR code, but we have stuff to
		 * do before *and* after this callback, and we don't want
		 * multiple if()s in the critical path (SDQCR). */
		res = fq->cb.dqrr(p, fq, dq);
		if (res == qman_cb_dqrr_stop)
			goto done;
		/* Check for VDQCR completion */
		if (dq->stat & QM_DQRR_STAT_DQCR_EXPIRED)
			clear_vdqcr(p, fq);
	} else {
		/* SDQCR: contextB points to the FQ */
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
		fq = get_fq_table_entry(dq->contextB);
#else
		fq = (void *)(uintptr_t)dq->contextB;
#endif
		/* Now let the callback do its stuff */
		res = fq->cb.dqrr(p, fq, dq);

		/* The callback can request that we exit without consuming this
		 * entry nor advancing; */
		if (res == qman_cb_dqrr_stop)
			goto done;
	}
	/* Interpret 'dq' from a driver perspective. */
	/* Parking isn't possible unless HELDACTIVE was set. NB,
	 * FORCEELIGIBLE implies HELDACTIVE, so we only need to
	 * check for HELDACTIVE to cover both. */
	DPA_ASSERT((dq->stat & QM_DQRR_STAT_FQ_HELDACTIVE) ||
		(res != qman_cb_dqrr_park));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (res != qman_cb_dqrr_defer)
		qm_dqrr_cdc_consume_1ptr(&p->p, orig_dq,
					 (res == qman_cb_dqrr_park));
#else
	/* Defer just means "skip it, I'll consume it myself later on" */
	if (res != qman_cb_dqrr_defer)
		qm_dqrr_cdc_consume_1ptr(&p->p, dq, (res == qman_cb_dqrr_park));
#endif
	/* Move forward */
	qm_dqrr_next(&p->p);
	/* Entry processed and consumed, increment our counter. The callback can
	 * request that we exit after consuming the entry, and we also exit if
	 * we reach our processing limit, so loop back only if neither of these
	 * conditions is met. */
	if ((++limit < poll_limit) && (res != qman_cb_dqrr_consume_stop))
		goto loop;
done:
	return limit;
}

int qman_p_poll_dqrr(struct qman_portal *p, unsigned int limit)
{
	int ret;

	ret = __poll_portal_fast(p, limit);

	return ret;
}

int qman_poll_dqrr(unsigned int limit)
{
	struct qman_portal *p = get_poll_portal();
	int ret;
	ret = qman_p_poll_dqrr(p, limit);
	put_poll_portal();
	return ret;
}

void qman_p_static_dequeue_add(struct qman_portal *p, u32 pools)
{
	unsigned long irqflags __maybe_unused;
	PORTAL_IRQ_LOCK(p, irqflags);
	pools &= p->config->public_cfg.pools;
	p->sdqcr |= pools;
	qm_dqrr_sdqcr_set(&p->p, p->sdqcr);
	PORTAL_IRQ_UNLOCK(p, irqflags);
}

void qman_static_dequeue_add(u32 pools)
{
	struct qman_portal *p = get_affine_portal();
	qman_p_static_dequeue_add(p, pools);
	put_affine_portal();
}

void qman_p_static_dequeue_del(struct qman_portal *p, u32 pools)
{
	unsigned long irqflags __maybe_unused;
	PORTAL_IRQ_LOCK(p, irqflags);
	pools &= p->config->public_cfg.pools;
	p->sdqcr &= ~pools;
	qm_dqrr_sdqcr_set(&p->p, p->sdqcr);
	PORTAL_IRQ_UNLOCK(p, irqflags);
}

void qman_static_dequeue_del(u32 pools)
{
	struct qman_portal *p = get_affine_portal();
	qman_p_static_dequeue_del(p, pools);
	put_affine_portal();
}

/*******************/
/* Frame queue API */
/*******************/

static const char *mcr_result_str(u8 result)
{
	switch (result) {
	case QM_MCR_RESULT_NULL:
		return "QM_MCR_RESULT_NULL";
	case QM_MCR_RESULT_OK:
		return "QM_MCR_RESULT_OK";
	case QM_MCR_RESULT_ERR_FQID:
		return "QM_MCR_RESULT_ERR_FQID";
	case QM_MCR_RESULT_ERR_FQSTATE:
		return "QM_MCR_RESULT_ERR_FQSTATE";
	case QM_MCR_RESULT_ERR_NOTEMPTY:
		return "QM_MCR_RESULT_ERR_NOTEMPTY";
	case QM_MCR_RESULT_PENDING:
		return "QM_MCR_RESULT_PENDING";
	case QM_MCR_RESULT_ERR_BADCOMMAND:
		return "QM_MCR_RESULT_ERR_BADCOMMAND";
	}
	return "<unknown MCR result>";
}

int qman_create_fq(u32 fqid, u32 flags, struct qman_fq *fq)
{
	struct qm_fqd fqd;
	struct qm_mcr_queryfq_np np;
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	unsigned long irqflags __maybe_unused;

	if (flags & QMAN_FQ_FLAG_DYNAMIC_FQID) {
		int ret = qman_alloc_fqid(&fqid);
		if (ret)
			return ret;
	}
	spin_lock_init(&fq->fqlock);
	fq->fqid = fqid;
	fq->flags = flags;
	fq->state = qman_fq_state_oos;
	fq->cgr_groupid = 0;
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
	if (unlikely(find_empty_fq_table_entry(&fq->key, fq)))
		return -ENOMEM;
#endif
	if (!(flags & QMAN_FQ_FLAG_AS_IS) || (flags & QMAN_FQ_FLAG_NO_MODIFY))
		return 0;
	/* Everything else is AS_IS support */
	p = get_affine_portal();
	PORTAL_IRQ_LOCK(p, irqflags);
	mcc = qm_mc_start(&p->p);
	mcc->queryfq.fqid = cpu_to_be32(fqid);
	qm_mc_commit(&p->p, QM_MCC_VERB_QUERYFQ);
	while (!(mcr = qm_mc_result(&p->p)))
		cpu_relax();
	DPA_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCC_VERB_QUERYFQ);
	if (mcr->result != QM_MCR_RESULT_OK) {
		pr_err("QUERYFQ failed: %s\n", mcr_result_str(mcr->result));
		goto err;
	}
	fqd = mcr->queryfq.fqd;
	hw_fqd_to_cpu(&fqd);
	mcc = qm_mc_start(&p->p);
	mcc->queryfq_np.fqid = cpu_to_be32(fqid);
	qm_mc_commit(&p->p, QM_MCC_VERB_QUERYFQ_NP);
	while (!(mcr = qm_mc_result(&p->p)))
		cpu_relax();
	DPA_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCC_VERB_QUERYFQ_NP);
	if (mcr->result != QM_MCR_RESULT_OK) {
		pr_err("QUERYFQ_NP failed: %s\n", mcr_result_str(mcr->result));
		goto err;
	}
	np = mcr->queryfq_np;
	/* Phew, have queryfq and queryfq_np results, stitch together
	 * the FQ object from those. */
	fq->cgr_groupid = fqd.cgid;
	switch (np.state & QM_MCR_NP_STATE_MASK) {
	case QM_MCR_NP_STATE_OOS:
		break;
	case QM_MCR_NP_STATE_RETIRED:
		fq->state = qman_fq_state_retired;
		if (np.frm_cnt)
			fq_set(fq, QMAN_FQ_STATE_NE);
		break;
	case QM_MCR_NP_STATE_TEN_SCHED:
	case QM_MCR_NP_STATE_TRU_SCHED:
	case QM_MCR_NP_STATE_ACTIVE:
		fq->state = qman_fq_state_sched;
		if (np.state & QM_MCR_NP_STATE_R)
			fq_set(fq, QMAN_FQ_STATE_CHANGING);
		break;
	case QM_MCR_NP_STATE_PARKED:
		fq->state = qman_fq_state_parked;
		break;
	default:
		DPA_ASSERT(NULL == "invalid FQ state");
	}
	if (fqd.fq_ctrl & QM_FQCTRL_CGE)
		fq->state |= QMAN_FQ_STATE_CGR_EN;
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	return 0;
err:
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	if (flags & QMAN_FQ_FLAG_DYNAMIC_FQID)
		qman_release_fqid(fqid);
	return -EIO;
}

void qman_destroy_fq(struct qman_fq *fq, u32 flags __maybe_unused)
{

	/* We don't need to lock the FQ as it is a pre-condition that the FQ be
	 * quiesced. Instead, run some checks. */
	switch (fq->state) {
	case qman_fq_state_parked:
		DPA_ASSERT(flags & QMAN_FQ_DESTROY_PARKED);
	case qman_fq_state_oos:
		if (fq_isset(fq, QMAN_FQ_FLAG_DYNAMIC_FQID))
			qman_release_fqid(fq->fqid);
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
		clear_fq_table_entry(fq->key);
#endif
		return;
	default:
		break;
	}
	DPA_ASSERT(NULL == "qman_free_fq() on unquiesced FQ!");
}

int qman_init_fq(struct qman_fq *fq, u32 flags, struct qm_mcc_initfq *opts)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	unsigned long irqflags __maybe_unused;
	u8 res, myverb = (flags & QMAN_INITFQ_FLAG_SCHED) ?
		QM_MCC_VERB_INITFQ_SCHED : QM_MCC_VERB_INITFQ_PARKED;

	if ((fq->state != qman_fq_state_oos) &&
			(fq->state != qman_fq_state_parked))
		return -EINVAL;
#ifdef CONFIG_FSL_DPA_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_MODIFY)))
		return -EINVAL;
#endif
	if (opts && (opts->we_mask & QM_INITFQ_WE_OAC)) {
		/* And can't be set at the same time as TDTHRESH */
		if (opts->we_mask & QM_INITFQ_WE_TDTHRESH)
			return -EINVAL;
	}
	/* Issue an INITFQ_[PARKED|SCHED] management command */
	p = get_affine_portal();
	PORTAL_IRQ_LOCK(p, irqflags);
	FQLOCK(fq);
	if (unlikely((fq_isset(fq, QMAN_FQ_STATE_CHANGING)) ||
			((fq->state != qman_fq_state_oos) &&
				(fq->state != qman_fq_state_parked)))) {
		FQUNLOCK(fq);
		PORTAL_IRQ_UNLOCK(p, irqflags);
		put_affine_portal();
		return -EBUSY;
	}
	mcc = qm_mc_start(&p->p);
	if (opts)
		mcc->initfq = *opts;
	mcc->initfq.fqid = cpu_to_be32(fq->fqid);
	mcc->initfq.count = 0;

	/* If the FQ does *not* have the TO_DCPORTAL flag, contextB is set as a
	 * demux pointer. Otherwise, the caller-provided value is allowed to
	 * stand, don't overwrite it. */
	if (fq_isclear(fq, QMAN_FQ_FLAG_TO_DCPORTAL)) {
		dma_addr_t phys_fq;
		mcc->initfq.we_mask |= QM_INITFQ_WE_CONTEXTB;
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
		mcc->initfq.fqd.context_b = fq->key;
#else
		mcc->initfq.fqd.context_b = (u32)(uintptr_t)fq;
#endif
		/* and the physical address - NB, if the user wasn't trying to
		 * set CONTEXTA, clear the stashing settings. */
		if (!(mcc->initfq.we_mask & QM_INITFQ_WE_CONTEXTA)) {
			mcc->initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;
			memset(&mcc->initfq.fqd.context_a, 0,
				sizeof(mcc->initfq.fqd.context_a));
		} else {
			phys_fq = dma_map_single(&p->pdev->dev, fq, sizeof(*fq),
						DMA_TO_DEVICE);
			qm_fqd_stashing_set64(&mcc->initfq.fqd, phys_fq);
		}
	}
	if (flags & QMAN_INITFQ_FLAG_LOCAL) {
		mcc->initfq.fqd.dest.channel = p->config->public_cfg.channel;
		if (!(mcc->initfq.we_mask & QM_INITFQ_WE_DESTWQ)) {
			mcc->initfq.we_mask |= QM_INITFQ_WE_DESTWQ;
			mcc->initfq.fqd.dest.wq = 4;
		}
	}
	mcc->initfq.we_mask = cpu_to_be16(mcc->initfq.we_mask);
	cpu_to_hw_fqd(&mcc->initfq.fqd);
	qm_mc_commit(&p->p, myverb);
	while (!(mcr = qm_mc_result(&p->p)))
		cpu_relax();
	DPA_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == myverb);
	res = mcr->result;
	if (res != QM_MCR_RESULT_OK) {
		FQUNLOCK(fq);
		PORTAL_IRQ_UNLOCK(p, irqflags);
		put_affine_portal();
		return -EIO;
	}
	if (opts) {
		if (opts->we_mask & QM_INITFQ_WE_FQCTRL) {
			if (opts->fqd.fq_ctrl & QM_FQCTRL_CGE)
				fq_set(fq, QMAN_FQ_STATE_CGR_EN);
			else
				fq_clear(fq, QMAN_FQ_STATE_CGR_EN);
		}
		if (opts->we_mask & QM_INITFQ_WE_CGID)
			fq->cgr_groupid = opts->fqd.cgid;
	}
	fq->state = (flags & QMAN_INITFQ_FLAG_SCHED) ?
			qman_fq_state_sched : qman_fq_state_parked;
	FQUNLOCK(fq);
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	return 0;
}

int qman_retire_fq(struct qman_fq *fq, u32 *flags)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	unsigned long irqflags __maybe_unused;
	int rval;
	u8 res;

	if ((fq->state != qman_fq_state_parked) &&
			(fq->state != qman_fq_state_sched))
		return -EINVAL;
#ifdef CONFIG_FSL_DPA_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_MODIFY)))
		return -EINVAL;
#endif
	p = get_affine_portal();
	PORTAL_IRQ_LOCK(p, irqflags);
	FQLOCK(fq);
	if (unlikely((fq_isset(fq, QMAN_FQ_STATE_CHANGING)) ||
			(fq->state == qman_fq_state_retired) ||
				(fq->state == qman_fq_state_oos))) {
		rval = -EBUSY;
		goto out;
	}
	rval = table_push_fq(p, fq);
	if (rval)
		goto out;
	mcc = qm_mc_start(&p->p);
	mcc->alterfq.fqid = cpu_to_be32(fq->fqid);
	qm_mc_commit(&p->p, QM_MCC_VERB_ALTER_RETIRE);
	while (!(mcr = qm_mc_result(&p->p)))
		cpu_relax();
	DPA_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCR_VERB_ALTER_RETIRE);
	res = mcr->result;
	/* "Elegant" would be to treat OK/PENDING the same way; set CHANGING,
	 * and defer the flags until FQRNI or FQRN (respectively) show up. But
	 * "Friendly" is to process OK immediately, and not set CHANGING. We do
	 * friendly, otherwise the caller doesn't necessarily have a fully
	 * "retired" FQ on return even if the retirement was immediate. However
	 * this does mean some code duplication between here and
	 * fq_state_change(). */
	if (likely(res == QM_MCR_RESULT_OK)) {
		rval = 0;
		/* Process 'fq' right away, we'll ignore FQRNI */
		if (mcr->alterfq.fqs & QM_MCR_FQS_NOTEMPTY)
			fq_set(fq, QMAN_FQ_STATE_NE);
		if (mcr->alterfq.fqs & QM_MCR_FQS_ORLPRESENT)
			fq_set(fq, QMAN_FQ_STATE_ORL);
		else
			table_del_fq(p, fq);
		if (flags)
			*flags = fq->flags;
		fq->state = qman_fq_state_retired;
		if (fq->cb.fqs) {
			/* Another issue with supporting "immediate" retirement
			 * is that we're forced to drop FQRNIs, because by the
			 * time they're seen it may already be "too late" (the
			 * fq may have been OOS'd and free()'d already). But if
			 * the upper layer wants a callback whether it's
			 * immediate or not, we have to fake a "MR" entry to
			 * look like an FQRNI... */
			struct qm_mr_entry msg;
			msg.verb = QM_MR_VERB_FQRNI;
			msg.fq.fqs = mcr->alterfq.fqs;
			msg.fq.fqid = fq->fqid;
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
			msg.fq.contextB = fq->key;
#else
			msg.fq.contextB = (u32)(uintptr_t)fq;
#endif
			fq->cb.fqs(p, fq, &msg);
		}
	} else if (res == QM_MCR_RESULT_PENDING) {
		rval = 1;
		fq_set(fq, QMAN_FQ_STATE_CHANGING);
	} else {
		rval = -EIO;
		table_del_fq(p, fq);
	}
out:
	FQUNLOCK(fq);
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	return rval;
}

int qman_oos_fq(struct qman_fq *fq)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	unsigned long irqflags __maybe_unused;
	int ret = 0;
	u8 res;

	if (fq->state != qman_fq_state_retired)
		return -EINVAL;
#ifdef CONFIG_FSL_DPA_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_MODIFY)))
		return -EINVAL;
#endif
	p = get_affine_portal();
	PORTAL_IRQ_LOCK(p, irqflags);
	FQLOCK(fq);
	if (unlikely((fq_isset(fq, QMAN_FQ_STATE_BLOCKOOS)) ||
			(fq->state != qman_fq_state_retired))) {
		ret = -EBUSY;
		goto out;
	}
	mcc = qm_mc_start(&p->p);
	mcc->alterfq.fqid = cpu_to_be32(fq->fqid);
	qm_mc_commit(&p->p, QM_MCC_VERB_ALTER_OOS);
	while (!(mcr = qm_mc_result(&p->p)))
		cpu_relax();
	DPA_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCR_VERB_ALTER_OOS);
	res = mcr->result;
	if (res != QM_MCR_RESULT_OK) {
		ret = -EIO;
		goto out;
	}
	fq->state = qman_fq_state_oos;
out:
	FQUNLOCK(fq);
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();
	return ret;
}

/* internal function used as a wait_event() expression */
static int set_p_vdqcr(struct qman_portal *p, struct qman_fq *fq, u32 vdqcr)
{
	unsigned long irqflags __maybe_unused;
	int ret = -EBUSY;
	PORTAL_IRQ_LOCK(p, irqflags);
	if (!p->vdqcr_owned) {
		FQLOCK(fq);
		if (fq_isset(fq, QMAN_FQ_STATE_VDQCR))
			goto escape;
		fq_set(fq, QMAN_FQ_STATE_VDQCR);
		FQUNLOCK(fq);
		p->vdqcr_owned = fq;
		ret = 0;
	}
escape:
	PORTAL_IRQ_UNLOCK(p, irqflags);
	if (!ret)
		qm_dqrr_vdqcr_set(&p->p, vdqcr);
	return ret;
}

static int set_vdqcr(struct qman_portal **p, struct qman_fq *fq, u32 vdqcr)
{
	int ret;
	*p = get_affine_portal();
	ret = set_p_vdqcr(*p, fq, vdqcr);
	put_affine_portal();
	return ret;
}

int qman_p_volatile_dequeue(struct qman_portal *p, struct qman_fq *fq,
					u32 flags __maybe_unused, u32 vdqcr)
{
	int ret;

	if ((fq->state != qman_fq_state_parked) &&
			(fq->state != qman_fq_state_retired))
		return -EINVAL;
	if (vdqcr & QM_VDQCR_FQID_MASK)
		return -EINVAL;
	if (fq_isset(fq, QMAN_FQ_STATE_VDQCR))
		return -EBUSY;
	vdqcr = (vdqcr & ~QM_VDQCR_FQID_MASK) | fq->fqid;
	ret = set_p_vdqcr(p, fq, vdqcr);

	return ret;
}

int qman_volatile_dequeue(struct qman_fq *fq, u32 flags __maybe_unused,
				u32 vdqcr)
{
	struct qman_portal *p;
	int ret;

	if ((fq->state != qman_fq_state_parked) &&
			(fq->state != qman_fq_state_retired))
		return -EINVAL;
	if (vdqcr & QM_VDQCR_FQID_MASK)
		return -EINVAL;
	if (fq_isset(fq, QMAN_FQ_STATE_VDQCR))
		return -EBUSY;
	vdqcr = (vdqcr & ~QM_VDQCR_FQID_MASK) | fq->fqid;
		ret = set_vdqcr(&p, fq, vdqcr);

	return ret;
}

static noinline void update_eqcr_ci(struct qman_portal *p, u8 avail)
{
	if (avail)
		qm_eqcr_cce_prefetch(&p->p);
	else
		qm_eqcr_cce_update(&p->p);
}

static inline struct qm_eqcr_entry *try_p_eq_start(struct qman_portal *p,
					unsigned long *irqflags __maybe_unused,
					struct qman_fq *fq,
					const struct qm_fd *fd,
					u32 flags)
{
	struct qm_eqcr_entry *eq;
	u8 avail;
	PORTAL_IRQ_LOCK(p, (*irqflags));

	if (p->use_eqcr_ci_stashing) {
		/*
		 * The stashing case is easy, only update if we need to in
		 * order to try and liberate ring entries.
		 */
		eq = qm_eqcr_start_stash(&p->p);
	} else {
		/*
		 * The non-stashing case is harder, need to prefetch ahead of
		 * time.
		 */
		avail = qm_eqcr_get_avail(&p->p);
		if (avail < 2)
			update_eqcr_ci(p, avail);
		eq = qm_eqcr_start_no_stash(&p->p);
	}

	if (unlikely(!eq)) {
		PORTAL_IRQ_UNLOCK(p, (*irqflags));
		return NULL;
	}
	if (flags & QMAN_ENQUEUE_FLAG_DCA)
		eq->dca = QM_EQCR_DCA_ENABLE |
			((flags & QMAN_ENQUEUE_FLAG_DCA_PARK) ?
					QM_EQCR_DCA_PARK : 0) |
			((flags >> 8) & QM_EQCR_DCA_IDXMASK);
	eq->fqid = cpu_to_be32(fq->fqid);
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
	eq->tag = cpu_to_be32(fq->key);
#else
	eq->tag = cpu_to_be32((u32)(uintptr_t)fq);
#endif
	eq->fd = *fd;
	cpu_to_hw_fd(&eq->fd);
	return eq;
}

static inline struct qm_eqcr_entry *try_eq_start(struct qman_portal **p,
					unsigned long *irqflags __maybe_unused,
					struct qman_fq *fq,
					const struct qm_fd *fd,
					u32 flags)
{
	struct qm_eqcr_entry *eq;
	*p = get_affine_portal();
	eq = try_p_eq_start(*p, irqflags, fq, fd, flags);
	if (!eq)
		put_affine_portal();
	return eq;
}

int qman_p_enqueue(struct qman_portal *p, struct qman_fq *fq,
				const struct qm_fd *fd, u32 flags)
{
	struct qm_eqcr_entry *eq;
	unsigned long irqflags __maybe_unused;

	eq = try_p_eq_start(p, &irqflags, fq, fd, flags);
	if (!eq)
		return -EBUSY;
	/* Note: QM_EQCR_VERB_INTERRUPT == QMAN_ENQUEUE_FLAG_WAIT_SYNC */
	qm_eqcr_pvb_commit(&p->p, QM_EQCR_VERB_CMD_ENQUEUE |
		(flags & (QM_EQCR_VERB_COLOUR_MASK | QM_EQCR_VERB_INTERRUPT)));
	/* Factor the below out, it's used from qman_enqueue_orp() too */
	PORTAL_IRQ_UNLOCK(p, irqflags);

	return 0;
}

int qman_enqueue(struct qman_fq *fq, const struct qm_fd *fd, u32 flags)
{
	struct qman_portal *p;
	struct qm_eqcr_entry *eq;
	unsigned long irqflags __maybe_unused;

	eq = try_eq_start(&p, &irqflags, fq, fd, flags);
	if (!eq)
		return -EBUSY;
	/* Note: QM_EQCR_VERB_INTERRUPT == QMAN_ENQUEUE_FLAG_WAIT_SYNC */
	qm_eqcr_pvb_commit(&p->p, QM_EQCR_VERB_CMD_ENQUEUE |
		(flags & (QM_EQCR_VERB_COLOUR_MASK | QM_EQCR_VERB_INTERRUPT)));
	/* Factor the below out, it's used from qman_enqueue_orp() too */
	PORTAL_IRQ_UNLOCK(p, irqflags);
	put_affine_portal();

	return 0;
}
