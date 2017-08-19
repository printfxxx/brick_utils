/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	mtrace.h
 * @brief	Header file for mtrace
 */

#ifndef _MTRACE_H_
#define _MTRACE_H_

#ifdef MTRACE

int mtrace_init(void);
void mtrace_finish(void);

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/percpu.h>

#define mtrace_kmem_add(p)		_mtrace_kmem_add(p, __func__, __LINE__)
#define mtrace_kmem_del(p)		_mtrace_kmem_del(p, __func__, __LINE__)
#define mtrace_vmem_add(p)		_mtrace_vmem_add(p, __func__, __LINE__)
#define mtrace_vmem_del(p)		_mtrace_vmem_del(p, __func__, __LINE__)
#define mtrace_devm_add(p)		_mtrace_devm_add(p, __func__, __LINE__)
#define mtrace_devm_del(p)		_mtrace_devm_del(p, __func__, __LINE__)
#define mtrace_coherent_add(p)		_mtrace_coherent_add(p, __func__, __LINE__)
#define mtrace_coherent_del(p)		_mtrace_coherent_del(p, __func__, __LINE__)
#define mtrace_skb_add(skb)		_mtrace_skb_add(skb, __func__, __LINE__)
#define mtrace_skb_del(skb)		_mtrace_skb_del(skb, __func__, __LINE__)
#define mtrace_percpu_add(p)		_mtrace_percpu_add(p, __func__, __LINE__)
#define mtrace_percpu_del(p)		_mtrace_percpu_del(p, __func__, __LINE__)

#undef kmalloc
#undef kzalloc
#undef krealloc
#undef kfree
#undef vmalloc
#undef vzalloc
#undef vfree
#undef devm_kmalloc
#undef devm_kzalloc
#undef devm_kfree
#undef dma_alloc_coherent
#undef dma_free_coherent
#undef alloc_skb
#undef netdev_alloc_skb
#undef __netdev_alloc_skb
#undef skb_copy
#undef kfree_skb
#undef consume_skb
#undef dev_kfree_skb
#undef alloc_percpu
#undef __alloc_percpu
#undef free_percpu

#define kmalloc(size, flags)		mtrace_kmalloc(size, flags, __func__, __LINE__)
#define kzalloc(size, flags)		mtrace_kzalloc(size, flags, __func__, __LINE__)
#define krealloc(p, new_size, flags)	mtrace_krealloc(p, new_size, flags, __func__, __LINE__)
#define kfree(p)			mtrace_kfree(p, __func__, __LINE__)

#define vmalloc(size)			mtrace_vmalloc(size, __func__, __LINE__)
#define vzalloc(size)			mtrace_vzalloc(size, __func__, __LINE__)
#define vfree(p)			mtrace_vfree(p, __func__, __LINE__)

#define devm_kmalloc(dev, size, flags)	mtrace_devm_kmalloc(dev, size, flags, __func__, __LINE__)
#define devm_kzalloc(dev, size, flags)	mtrace_devm_kzalloc(dev, size, flags, __func__, __LINE__)
#define devm_kfree(dev, p)		mtrace_devm_kfree(dev, p, __func__, __LINE__)

#define dma_alloc_coherent(dev, size, dma_handle, flag)		\
	mtrace_dma_alloc_coherent(dev, size, dma_handle, flag, __func__, __LINE__)
#define dma_free_coherent(dev, size, cpu_addr, dma_handle)	\
	mtrace_dma_free_coherent(dev, size, cpu_addr, dma_handle, __func__, __LINE__)

#define alloc_skb(size, priority)		mtrace_alloc_skb(size, priority, __func__, __LINE__)
#define netdev_alloc_skb(dev, length)		mtrace_netdev_alloc_skb(dev, length, __func__, __LINE__)
#define __netdev_alloc_skb(dev, length, gfp)	mtrace___netdev_alloc_skb(dev, length, gfp, __func__, __LINE__)
#define skb_copy(skb, gfp)			mtrace_skb_copy(skb, gfp, __func__, __LINE__)
#define kfree_skb(skb)				mtrace_kfree_skb(skb, __func__, __LINE__)
#define consume_skb(skb)			mtrace_consume_skb(skb, __func__, __LINE__)
#define dev_kfree_skb(skb)			mtrace_dev_kfree_skb(skb, __func__, __LINE__)

#define alloc_percpu(type)			(typeof(type) __percpu *)__alloc_percpu(sizeof(type), __alignof__(type))
#define __alloc_percpu(size, align)		__mtrace_alloc_percpu(size, align, __func__, __LINE__)
#define free_percpu(p)				mtrace_free_percpu(p, __func__, __LINE__)

int _mtrace_kmem_add(const void *p, const char *name, int line);
void _mtrace_kmem_del(const void *p, const char *name, int line);
int _mtrace_vmem_add(const void *p, const char *name, int line);
void _mtrace_vmem_del(const void *p, const char *name, int line);
int _mtrace_devm_add(const void *p, const char *name, int line);
void _mtrace_devm_del(const void *p, const char *name, int line);
int _mtrace_coherent_add(const void *p, const char *name, int line);
void _mtrace_coherent_del(const void *p, const char *name, int line);
int _mtrace_skb_add(const struct sk_buff *skb, const char *name, int line);
void _mtrace_skb_del(const struct sk_buff *skb, const char *name, int line);
int _mtrace_percpu_add(const void __percpu *p, const char *name, int line);
void _mtrace_percpu_del(const void __percpu *p, const char *name, int line);

void *mtrace_kmalloc(size_t size, gfp_t flags,
		     const char *name, int line);
void *mtrace_kzalloc(size_t size, gfp_t flags,
		     const char *name, int line);
void *mtrace_krealloc(const void *p, size_t new_size, gfp_t flags,
		      const char *name, int line);
void mtrace_kfree(const void *p, const char *name, int line);

void *mtrace_vmalloc(size_t size, const char *name, int line);
void *mtrace_vzalloc(size_t size, const char *name, int line);
void mtrace_vfree(const void *p, const char *name, int line);

void *mtrace_devm_kmalloc(struct device *dev, size_t size, gfp_t flags,
			  const char *name, int line);
void *mtrace_devm_kzalloc(struct device *dev, size_t size, gfp_t flags,
			  const char *name, int line);
void mtrace_devm_kfree(struct device *dev, void *p, const char *name, int line);

struct sk_buff *mtrace_alloc_skb(unsigned int size, gfp_t priority,
				 const char *name, int line);
struct sk_buff *mtrace_netdev_alloc_skb(struct net_device *dev,
					unsigned int length, gfp_t gfp_mask,
					const char *name, int line);
struct sk_buff *mtrace___netdev_alloc_skb(struct net_device *dev,
					  unsigned int length, gfp_t gfp_mask,
					  const char *name, int line);
struct sk_buff *mtrace_skb_copy(const struct sk_buff *skb, gfp_t gfp_mask,
				const char *name, int line);
void mtrace_kfree_skb(struct sk_buff *skb, const char *name, int line);
void mtrace_consume_skb(struct sk_buff *skb, const char *name, int line);
void mtrace_dev_kfree_skb(struct sk_buff *skb, const char *name, int line);

void *mtrace_dma_alloc_coherent(struct device *dev, size_t size,
				dma_addr_t *dma_handle, gfp_t flag,
				const char *name, int line);
void mtrace_dma_free_coherent(struct device *dev, size_t size,
			      void *cpu_addr, dma_addr_t dma_handle,
			      const char *name, int line);

void __percpu *__mtrace_alloc_percpu(size_t size, size_t align,
				     const char *name, int line);
void mtrace_free_percpu(void __percpu *p, const char *name, int line);

void *notrace_kmalloc(size_t size, gfp_t flags);
void *notrace_kzalloc(size_t size, gfp_t flags);
void *notrace_krealloc(const void *p, size_t new_size, gfp_t flags);
void notrace_kfree(const void *p);

void *notrace_vmalloc(size_t size);
void *notrace_vzalloc(size_t size);
void notrace_vfree(const void *p);

void *notrace_devm_kmalloc(struct device *dev, size_t size, gfp_t flags);
void *notrace_devm_kzalloc(struct device *dev, size_t size, gfp_t flags);
void notrace_devm_kfree(struct device *dev, void *p);

struct sk_buff *notrace_alloc_skb(unsigned int size, gfp_t priority);
struct sk_buff *notrace_netdev_alloc_skb(struct net_device *dev, unsigned int length);
struct sk_buff *notrace___netdev_alloc_skb(struct net_device *dev, unsigned int length, gfp_t gfp_mask);
struct sk_buff *notrace_skb_copy(const struct sk_buff *skb, gfp_t gfp_mask);
void notrace_kfree_skb(struct sk_buff *skb);
void notrace_consume_skb(struct sk_buff *skb);
void notrace_dev_kfree_skb(struct sk_buff *skb);

void *notrace_dma_alloc_coherent(struct device *dev, size_t size,
				 dma_addr_t *dma_handle, gfp_t flag);
void notrace_dma_free_coherent(struct device *dev, size_t size,
			       void *cpu_addr, dma_addr_t dma_handle);

#define notrace_alloc_percpu(type)	(typeof(type) __percpu *)notrace___alloc_percpu(sizeof(type), __alignof__(type))
void __percpu *notrace___alloc_percpu(size_t size, size_t align);
void notrace_free_percpu(void __percpu *p);

#else	/* __KERNEL__ */

#define mtrace_mem_add(p)	_mtrace_mem_add(p, __func__, __LINE__)
#define mtrace_mem_del(p)	_mtrace_mem_del(p, __func__, __LINE__)

#undef malloc
#undef free
#undef strdup

#define malloc(size)		mtrace_malloc(size, __func__, __LINE__)
#define free(p)			mtrace_free(p, __func__, __LINE__)
#define strdup(s)		mtrace_strdup(s, __func__, __LINE__)

int _mtrace_mem_add(const void *p, const char *name, int line);
void _mtrace_mem_del(const void *p, const char *name, int line);

void *mtrace_malloc(size_t size, const char *name, int line);
void mtrace_free(void *p, const char *name, int line);
char *mtrace_strdup(const char *s, const char *name, int line);

void *notrace_malloc(size_t size);
char *notrace_strdup(const char *s);
void notrace_free(void *p);

#endif	/* __KERNEL__ */

#else	/* MTRACE */

static inline int mtrace_init(void)
{
	return 0;
}

static inline void mtrace_finish(void)
{
}

#ifdef __KERNEL__

#define mtrace_kmem_add(p)		({ 0; })
#define mtrace_kmem_del(p)		do { ; } while (0)
#define mtrace_devm_add(p)		({ 0; })
#define mtrace_devm_del(p)		do { ; } while (0)
#define mtrace_coherent_add(p)		({ 0; })
#define mtrace_coherent_del(p)		do { ; } while (0)
#define mtrace_skb_add(skb)		({ 0; })
#define mtrace_skb_del(skb)		do { ; } while (0)
#define mtrace_percpu_add(p)		({ 0; })
#define mtrace_percpu_del(p)		do { ; } while (0)

#define notrace_kmalloc(size, flags)		kmalloc(size, flags)
#define notrace_kzalloc(size, flags)		kzalloc(size, flags)
#define notrace_krealloc(p, new_size, flags)	krealloc(p, new_size, flags)
#define notrace_kfree(p)			kfree(p)

#define notrace_vmalloc(size)			vmalloc(size)
#define notrace_vzalloc(size)			vzalloc(size)
#define notrace_vfree(p)			vfree(p)

#define notrace_devm_kmalloc(dev, size, flags)	devm_kmalloc(dev, size, flags)
#define notrace_devm_kzalloc(dev, size, flags)	devm_kzalloc(dev, size, flags)
#define notrace_devm_kfree(dev, p)		devm_kfree(dev, p)

#define notrace_alloc_skb(size, priority)		alloc_skb(size, priority)
#define notrace_netdev_alloc_skb(dev, length)		netdev_alloc_skb(dev, length)
#define notrace___netdev_alloc_skb(dev, length, gfp)	__netdev_alloc_skb(dev, length, gfp)
#define notrace_skb_copy(skb, gfp_mask)			skb_copy(skb, gfp_mask)
#define notrace_kfree_skb(skb)				kfree_skb(skb)
#define notrace_consume_skb(skb)			consume_skb(skb)
#define notrace_dev_kfree_skb(skb)			kfree_skb(skb)

#define notrace_dma_alloc_coherent(dev, size, dma_handle, flag)	\
	dma_alloc_coherent(dev, size, dma_handle, flag)
#define notrace_dma_free_coherent(dev, size, dma_handle, flag)	\
	dma_free_coherent(dev, size, cpu_addr, dma_handle)

#define notrace_alloc_percpu(type)		alloc_percpu(type)
#define notrace___alloc_percpu(size, align)	__alloc_percpu(size, align)
#define notrace_free_percpu(p)			free_percpu(p)

#else	/* __KERNEL__ */

#define mtrace_mem_add(p)		({ 0; })
#define mtrace_mem_del(p)		do { ; } while (0)

#define notrace_malloc(size)		malloc(size)
#define notrace_strdup(s)		strdup(s)
#define notrace_free(p)			kfree(p)

#endif	/* __KERNEL__ */

#endif	/* MTRACE */

#endif	/* _MTRACE_H_ */
