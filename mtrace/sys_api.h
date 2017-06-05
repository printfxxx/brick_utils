/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	sys_api.h
 * @brief	Header file for linux kernel compatible APIs in user space
 */

#ifndef _SYS_API_H_
#define _SYS_API_H_

#ifndef __KERNEL__

#include <stdio.h>
#include <pthread.h>

#define GFP_ATOMIC	0

#ifndef __always_inline
#define __always_inline	inline
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define EXPORT_SYMBOL(sym)

#define pr_in(fmt, ...)		fprintf(stdin, fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)

struct kmem_cache {
	size_t size;
};

typedef unsigned int gfp_t;
typedef pthread_spinlock_t spinlock_t;

struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *));
void kmem_cache_destroy(struct kmem_cache *s);
void *kmem_cache_alloc(struct kmem_cache *s, gfp_t flags);
void kmem_cache_free(struct kmem_cache *s, void *p);

void spin_lock_init(spinlock_t *lock);
void spin_lock_deinit(spinlock_t *lock);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);

#define spin_lock_bh(lock)	spin_lock(lock)
#define spin_unlock_bh(lock)	spin_unlock(lock)

#endif	/* __KERNEL__ */

#endif	/* _SYS_API_H_ */
