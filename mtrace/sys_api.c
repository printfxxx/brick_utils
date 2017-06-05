/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	sys_api.c
 * @brief	Linux kernel compatible APIs implementation in user space
 */

#include <stdlib.h>
#include <assert.h>

#include "sys_api.h"

struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *))
{
	struct kmem_cache *s;

	if (!(s = malloc(sizeof(s)))) {
		return NULL;
	}

	s->size = size;

	return s;
}

void kmem_cache_destroy(struct kmem_cache *s)
{
	free(s);
}

void *kmem_cache_alloc(struct kmem_cache *s, gfp_t flags)
{
	return malloc(s->size);
}

void kmem_cache_free(struct kmem_cache *s, void *p)
{
	free(p);
}

void spin_lock_init(spinlock_t *lock)
{
	int rc;

	rc = pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);

	assert(!rc);
}

void spin_lock_deinit(spinlock_t *lock)
{
	int rc;

	rc = pthread_spin_destroy(lock);

	assert(!rc);
}

void spin_lock(spinlock_t *lock)
{
	int rc;

	rc = pthread_spin_lock(lock);

	assert(!rc);
}

void spin_unlock(spinlock_t *lock)
{
	int rc;

	rc = pthread_spin_unlock(lock);

	assert(!rc);
}
