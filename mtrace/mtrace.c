/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	mtrace.c
 * @brief	Memory alloc/free trace tool
 */

#ifdef MTRACE

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <linux/device.h>
#include <linux/rbtree.h>
#include <linux/vmalloc.h>
#else	/* __KERNEL__ */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "sys_api.h"
#include "rbtree.h"
#endif	/* __KERNEL__ */

#ifdef _MTRACE_H_
#error "mtrace.h only used for hook memory APIs, don't include int this file"
#endif

enum {
#ifdef __KERNEL__
	MTRACE_KMEM = 0,
	MTRACE_VMEM,
	MTRACE_DEVM,
	MTRACE_SKB,
	MTRACE_COHERENT,
	MTRACE_PERCPU,
#else
	MTRACE_MEM = 0,
#endif
	MTRACE_TYPE_MAX
};

const char *mtrace_type[] = {
#ifdef __KERNEL__
	"kmem",
	"vmem",
	"devm",
	"skb",
	"coherent",
	"percpu",
#else
	"mem",
#endif
};

typedef struct mtrace_node {
	const void *ptr;
	const char *name;
	int line, refs;
	struct rb_node node;
} mtrace_node_t;

typedef struct mtrace_root {
	struct rb_root root;
	spinlock_t lock;
} mtrace_root_t;

static struct kmem_cache *mtrace_cache;
static mtrace_root_t mtrace_root[MTRACE_TYPE_MAX];

static mtrace_node_t *mtrace_find(const void *find, int type)
{
	mtrace_node_t *n;
	mtrace_root_t *r = &mtrace_root[type];
	struct rb_node *node;

	node = r->root.rb_node;
	while (node) {
		n = rb_entry(node, mtrace_node_t, node);
		if (find < n->ptr) {
			node = node->rb_left;
		} else if (find > n->ptr) {
			node = node->rb_right;
		} else {
			return n;
		}
	}

	return NULL;
}

static void mtrace_set(mtrace_node_t *n, const void *ptr, const char *name, int line)
{
	n->ptr = ptr;
	n->name = name;
	n->line = line;
	n->refs = 0;
}

static int mtrace_add(const void *ptr, int type, const char *name, int line)
{
	int rc;
	mtrace_node_t *n, *t;
	mtrace_root_t *r = &mtrace_root[type];
	struct rb_node **node, *parent = NULL;

	spin_lock_bh(&r->lock);

	rc = 0;
	node = &r->root.rb_node;
	while (*node) {
		parent = *node;
		t = rb_entry(parent, mtrace_node_t, node);
		if (ptr < t->ptr) {
			node = &(*node)->rb_left;
		} else if (ptr > t->ptr) {
			node = &(*node)->rb_right;
		} else {
			n = t;
			if (n->refs == INT_MAX) {
				rc = -ENOMEM;
				goto err;
			} else {
				goto ok;
			}
		}
	}

	if (!(n = kmem_cache_alloc(mtrace_cache, GFP_ATOMIC))) {
		rc = -ENOMEM;
		spin_unlock_bh(&r->lock);
		goto err;
	}
	mtrace_set(n, ptr, name, line);
	rb_link_node(&n->node, parent, node);
	rb_insert_color(&n->node, &r->root);
ok:
	n->refs++;
	spin_unlock_bh(&r->lock);
	return 0;
err:
	return rc;
}

static void mtrace_del(const void *ptr, int type, const char *name, int line)
{
	mtrace_node_t *n;
	mtrace_root_t *r = &mtrace_root[type];

	spin_lock_bh(&r->lock);

	if ((n = mtrace_find(ptr, type))) {
		BUG_ON(!(n->refs));
		n->refs--;
		if (!n->refs) {
			rb_erase(&n->node, &r->root);
			kmem_cache_free(mtrace_cache, n);
		}
	} else {
		pr_err("%s: failed to find %p at %s(), line %d\n",
		       mtrace_type[type], ptr, name, line);
	}

	spin_unlock_bh(&r->lock);
}

static void mtrace_print_leak(int type)
{
	mtrace_node_t *n;
	mtrace_root_t *r = &mtrace_root[type];
	struct rb_node *node;

	for (node = rb_first(&r->root); node; node = rb_next(node)) {
		n = rb_entry(node, mtrace_node_t, node);
		pr_warn("%s leak: %p at %s(), line %d\n",
			mtrace_type[type], n->ptr, n->name, n->line);
	}
}

int mtrace_init(void)
{
	int i;
	mtrace_root_t *r;

	for (i = 0; i < MTRACE_TYPE_MAX; i++) {
		r = &mtrace_root[i];
		r->root = RB_ROOT;
		spin_lock_init(&r->lock);
	}

	mtrace_cache = kmem_cache_create("mtrace", sizeof(struct mtrace_node),
					 0, 0, NULL);
	if (mtrace_cache) {
		return 0;
	} else {
		return -1;
	}
}

void mtrace_finish(void)
{
	int i;
	mtrace_node_t *n;
	mtrace_root_t *r;
	struct rb_node *node;

	for (i = 0; i < MTRACE_TYPE_MAX; i++) {
		r = &mtrace_root[i];
		spin_lock_bh(&r->lock);
		mtrace_print_leak(i);
		node = rb_first(&r->root);
		while (node) {
			n = rb_entry(node, mtrace_node_t, node);
			node = rb_next(node);
			rb_erase(&n->node, &r->root);
			kmem_cache_free(mtrace_cache, n);
		}
		spin_unlock_bh(&r->lock);
#ifndef __KERNEL__
		spin_lock_deinit(&r->lock);
#endif
	}

	if (mtrace_cache) {
		kmem_cache_destroy(mtrace_cache);
	}
}

#ifdef __KERNEL__

int _mtrace_kmem_add(const void *p, const char *name, int line)
{
	return mtrace_add(p, MTRACE_KMEM, name, line);
}

void _mtrace_kmem_del(const void *p, const char *name, int line)
{
	mtrace_del(p, MTRACE_KMEM, name, line);
}

int _mtrace_vmem_add(const void *p, const char *name, int line)
{
	return mtrace_add(p, MTRACE_VMEM, name, line);
}

void _mtrace_vmem_del(const void *p, const char *name, int line)
{
	mtrace_del(p, MTRACE_VMEM, name, line);
}

int _mtrace_devm_add(const void *p, const char *name, int line)
{
	return mtrace_add(p, MTRACE_DEVM, name, line);
}

void _mtrace_devm_del(const void *p, const char *name, int line)
{
	mtrace_del(p, MTRACE_DEVM, name, line);
}

int _mtrace_coherent_add(const void *p, const char *name, int line)
{
	return mtrace_add(p, MTRACE_COHERENT, name, line);
}

void _mtrace_coherent_del(const void *p, const char *name, int line)
{
	mtrace_del(p, MTRACE_COHERENT, name, line);
}

int _mtrace_skb_add(const struct sk_buff *skb, const char *name, int line)
{
	return mtrace_add(skb, MTRACE_SKB, name, line);
}

void _mtrace_skb_del(const struct sk_buff *skb, const char *name, int line)
{
	mtrace_del(skb, MTRACE_SKB, name, line);
}

int _mtrace_percpu_add(const void __percpu *p, const char *name, int line)
{
	return mtrace_add(p, MTRACE_PERCPU, name, line);
}

void _mtrace_percpu_del(const void __percpu *p, const char *name, int line)
{
	mtrace_del(p, MTRACE_PERCPU, name, line);
}

void *mtrace_kmalloc(size_t size, gfp_t flags,
		     const char *name, int line)
{
	void *p;

	if (!ZERO_OR_NULL_PTR(p = kmalloc(size, flags))
	&&  (_mtrace_kmem_add(p, name, line))) {
		goto err;
	}

	return p;
err:
	kfree(p);
	return NULL;
}

void *mtrace_kzalloc(size_t size, gfp_t flags,
		     const char *name, int line)
{
	void *p;

	if (!ZERO_OR_NULL_PTR(p = kzalloc(size, flags))
	&&  _mtrace_kmem_add(p, name, line)) {
		goto err;
	}

	return p;
err:
	kfree(p);
	return NULL;
}

void *mtrace_krealloc(const void *p, size_t new_size, gfp_t flags,
		      const char *name, int line)
{
	void *new;

	new = krealloc(p, new_size, flags);

	if (new != p) {
		if (!ZERO_OR_NULL_PTR(p)) {
			_mtrace_kmem_del(p, name, line);
		}
		if (!ZERO_OR_NULL_PTR(new)
		&&  _mtrace_kmem_add(new, name, line)) {
			goto err;
		}
	}

	return new;
err:
	kfree(new);
	return NULL;
}

void mtrace_kfree(const void *p, const char *name, int line)
{
	if (!ZERO_OR_NULL_PTR(p)) {
		_mtrace_kmem_del(p, name, line);
	}
	kfree(p);
}

void *mtrace_vmalloc(size_t size, const char *name, int line)
{
	void *p;

	if (!ZERO_OR_NULL_PTR(p = vmalloc(size))
	&&  (_mtrace_vmem_add(p, name, line))) {
		goto err;
	}

	return p;
err:
	vfree(p);
	return NULL;
}

void *mtrace_vzalloc(size_t size, const char *name, int line)
{
	void *p;

	if (!ZERO_OR_NULL_PTR(p = vzalloc(size))
	&&  _mtrace_vmem_add(p, name, line)) {
		goto err;
	}

	return p;
err:
	vfree(p);
	return NULL;
}

void mtrace_vfree(const void *p, const char *name, int line)
{
	if (!ZERO_OR_NULL_PTR(p)) {
		_mtrace_vmem_del(p, name, line);
	}
	vfree(p);
}

void *mtrace_devm_kmalloc(struct device *dev, size_t size, gfp_t flags,
			  const char *name, int line)
{
	void *p;

	if (!ZERO_OR_NULL_PTR(p = devm_kmalloc(dev, size, flags))
	&&  (_mtrace_devm_add(p, name, line))) {
		goto err;
	}

	return p;
err:
	kfree(p);
	return NULL;
}

void *mtrace_devm_kzalloc(struct device *dev, size_t size, gfp_t flags,
			  const char *name, int line)
{
	void *p;

	if (!ZERO_OR_NULL_PTR(p = devm_kzalloc(dev, size, flags))
	&&  _mtrace_devm_add(p, name, line)) {
		goto err;
	}

	return p;
err:
	kfree(p);
	return NULL;
}

void mtrace_devm_kfree(struct device *dev, void *p, const char *name, int line)
{
	_mtrace_devm_del(p, name, line);

	devm_kfree(dev, p);
}

void *mtrace_dma_alloc_coherent(struct device *dev, size_t size,
				dma_addr_t *dma_handle, gfp_t flag,
				const char *name, int line)
{
	void *vaddr;

	if (!(vaddr = dma_alloc_coherent(dev, size, dma_handle, flag))
	||  _mtrace_coherent_add(vaddr, name, line)) {
		goto err;
	}

	return vaddr;
err:
	if (vaddr) {
		dma_free_coherent(dev, size, vaddr, *dma_handle);
	}
	return NULL;
}

void mtrace_dma_free_coherent(struct device *dev, size_t size,
			      void *cpu_addr, dma_addr_t dma_handle,
			      const char *name, int line)
{
	_mtrace_coherent_del(cpu_addr, name, line);

	dma_free_coherent(dev, size, cpu_addr, dma_handle);
}

struct sk_buff *mtrace_alloc_skb(unsigned int size, gfp_t priority,
				 const char *name, int line)
{
	struct sk_buff *skb;

	if (!(skb = alloc_skb(size, priority))
	||  _mtrace_skb_add(skb, name, line)) {
		goto err;
	}

	return skb;
err:
	kfree_skb(skb);
	return NULL;
}

struct sk_buff *mtrace_netdev_alloc_skb(struct net_device *dev,
					unsigned int length,
					const char *name, int line)
{
	struct sk_buff *skb;

	if (!(skb = netdev_alloc_skb(dev, length))
	||  _mtrace_skb_add(skb, name, line)) {
		goto err;
	}

	return skb;
err:
	dev_kfree_skb(skb);
	return NULL;
}

struct sk_buff *mtrace___netdev_alloc_skb(struct net_device *dev,
					  unsigned int length, gfp_t gfp_mask,
					  const char *name, int line)
{
	struct sk_buff *skb;

	if (!(skb = __netdev_alloc_skb(dev, length, gfp_mask))
	||  _mtrace_skb_add(skb, name, line)) {
		goto err;
	}

	return skb;
err:
	dev_kfree_skb(skb);
	return NULL;
}

struct sk_buff *mtrace_skb_copy(const struct sk_buff *skb, gfp_t gfp_mask,
				const char *name, int line)
{
	struct sk_buff *new;

	if (!(new = skb_copy(skb, gfp_mask))
	||  _mtrace_skb_add(new, name, line)) {
		goto err;
	}

	return new;
err:
	kfree_skb(new);
	return NULL;
}

void mtrace_kfree_skb(struct sk_buff *skb, const char *name, int line)
{
	if (skb) {
		_mtrace_skb_del(skb, name, line);
	}
	kfree_skb(skb);
}

void mtrace_consume_skb(struct sk_buff *skb, const char *name, int line)
{
	if (skb) {
		_mtrace_skb_del(skb, name, line);
	}
	consume_skb(skb);
}

void mtrace_dev_kfree_skb(struct sk_buff *skb, const char *name, int line)
{
	if (skb) {
		_mtrace_skb_del(skb, name, line);
	}
	dev_kfree_skb(skb);
}

void __percpu *__mtrace_alloc_percpu(size_t size, size_t align,
				     const char *name, int line)
{
	void __percpu *p;

	if (!(p = __alloc_percpu(size, align))
	||  _mtrace_percpu_add(p, name, line)) {
		goto err;
	}

	return p;
err:
	free_percpu(p);
	return NULL;
}

void mtrace_free_percpu(void __percpu *p, const char *name, int line)
{
	if (p) {
		_mtrace_percpu_del(p, name, line);
	}
	free_percpu(p);
}

void *notrace_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags);
}

void *notrace_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}

void *notrace_krealloc(const void *p, size_t new_size, gfp_t flags)
{
	return krealloc(p, new_size, flags);
}

void notrace_kfree(const void *p)
{
	kfree(p);
}

void *notrace_vmalloc(size_t size)
{
	return vmalloc(size);
}

void *notrace_vzalloc(size_t size)
{
	return vzalloc(size);
}

void notrace_vfree(const void *p)
{
	vfree(p);
}

void *notrace_devm_kmalloc(struct device *dev, size_t size, gfp_t flags)
{
	return devm_kmalloc(dev, size, flags);
}

void *notrace_devm_kzalloc(struct device *dev, size_t size, gfp_t flags)
{
	return devm_kzalloc(dev, size, flags);
}

void notrace_devm_kfree(struct device *dev, void *p)
{
	devm_kfree(dev, p);
}

struct sk_buff *notrace_alloc_skb(unsigned int size, gfp_t priority)
{
	return alloc_skb(size, priority);
}

struct sk_buff *notrace_netdev_alloc_skb(struct net_device *dev, unsigned int length)
{
	return netdev_alloc_skb(dev, length);
}

struct sk_buff *notrace___netdev_alloc_skb(struct net_device *dev, unsigned int length, gfp_t gfp_mask)
{
	return __netdev_alloc_skb(dev, length, gfp_mask);
}

struct sk_buff *notrace_skb_copy(const struct sk_buff *skb, gfp_t gfp_mask)
{
	return skb_copy(skb, gfp_mask);
}

void notrace_kfree_skb(struct sk_buff *skb)
{
	kfree_skb(skb);
}

void notrace_consume_skb(struct sk_buff *skb)
{
	consume_skb(skb);
}

void notrace_dev_kfree_skb(struct sk_buff *skb)
{
	dev_kfree_skb(skb);
}

void *notrace_dma_alloc_coherent(struct device *dev, size_t size,
				 dma_addr_t *dma_handle, gfp_t flag)
{
	return dma_alloc_coherent(dev, size, dma_handle, flag);
}

void notrace_dma_free_coherent(struct device *dev, size_t size,
			       void *cpu_addr, dma_addr_t dma_handle)
{
	dma_free_coherent(dev, size, cpu_addr, dma_handle);
}

void __percpu *notrace___alloc_percpu(size_t size, size_t align)
{
	return __alloc_percpu(size, align);
}

void notrace_free_percpu(void __percpu *p)
{
	free_percpu(p);
}

#else	/* __KERNEL__ */

int _mtrace_mem_add(const void *p, const char *name, int line)
{
	return mtrace_add(p, MTRACE_MEM, name, line);
}

void _mtrace_mem_del(const void *p, const char *name, int line)
{
	mtrace_del(p, MTRACE_MEM, name, line);
}

void *mtrace_malloc(size_t size, const char *name, int line)
{
	void *p;

	if ((p = malloc(size)) && (_mtrace_mem_add(p, name, line))) {
		goto err;
	}

	return p;
err:
	free(p);
	return NULL;
}

char *mtrace_strdup(const char *s, const char *name, int line)
{
	char *p;

	if ((p = strdup(s)) && (_mtrace_mem_add(p, name, line))) {
		goto err;
	}

	return p;
err:
	free(p);
	return NULL;
}

void mtrace_free(void *p, const char *name, int line)
{
	if (p) {
		_mtrace_mem_del(p, name, line);
	}
	free(p);
}

void *notrace_malloc(size_t size)
{
	return malloc(size);
}

char *notrace_strdup(const char *s)
{
	return strdup(s);
}

void notrace_free(void *p)
{
	free(p);
}

#endif	/* __KERNEL__ */

#endif	/* _MTRACE_H_ */
