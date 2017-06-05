/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	ring.h
 * @brief	Ring op APIs
 */

#ifndef _RING_H_
#define _RING_H_

#ifdef RING_SANITY_CHECK
#include <linux/kernel.h>
#define RING_ASSERT(x)		BUG_ON(!likely(x))
#else
#define RING_ASSERT(x)
#endif

#define RING_SZ_MAX	(UINT_MAX / 2)

typedef struct ring {
	unsigned int head;
	unsigned int used;
	unsigned int size;
} ring_t;

static inline unsigned int _ring_used_nr(unsigned int head,
					 unsigned int tail,
					 unsigned int size)
{
	RING_ASSERT(size <= RING_SZ_MAX);
	RING_ASSERT(head < size);
	RING_ASSERT(tail < size);

	if (tail > head) {
		return size - tail + head;
	} else {
		return head - tail;
	}
}

static inline unsigned int _ring_free_nr(unsigned int head,
					 unsigned int tail,
					 unsigned int size)
{
	RING_ASSERT(size <= RING_SZ_MAX);
	RING_ASSERT(head < size);
	RING_ASSERT(tail < size);

	if (tail > head) {
		return tail - head;
	} else {
		return size - head + tail;
	}
}

static inline unsigned int _ring_add(unsigned int idx,
				     unsigned int add,
				     unsigned int size)
{
	unsigned int sum = idx + add;

	RING_ASSERT(size <= RING_SZ_MAX);
	RING_ASSERT(add <= size);
	RING_ASSERT(idx < size);

	return likely(sum < size) ? sum : sum - size;
}

static inline unsigned int _ring_sub(unsigned int idx,
				     unsigned int sub,
				     unsigned int size)
{
	RING_ASSERT(size <= RING_SZ_MAX);
	RING_ASSERT(sub <= size);
	RING_ASSERT(idx < size);

	return likely(idx < sub) ? idx + size - sub : idx - sub;
}

static inline void ring_init(ring_t *r, unsigned int size)
{
	RING_ASSERT(size <= RING_SZ_MAX);

	r->head = r->used = 0;
	r->size = size;
}

static inline unsigned int ring_head(const ring_t *r)
{
	return r->head;
}

static inline unsigned int ring_head_prev(const ring_t *r, unsigned int n)
{
	return _ring_sub(r->head, n, r->size);
}

static inline unsigned int ring_head_next(const ring_t *r, unsigned int n)
{
	return _ring_add(r->head, n, r->size);
}

static inline unsigned int ring_tail(const ring_t *r)
{
	return ring_head_prev(r, r->used);
}

static inline unsigned int ring_tail_prev(const ring_t *r, unsigned int n)
{
	return _ring_sub(ring_tail(r), n, r->size);
}

static inline unsigned int ring_tail_next(const ring_t *r, unsigned int n)
{
	return _ring_add(ring_tail(r), n, r->size);
}

static inline unsigned int ring_size(const ring_t *r)
{
	return r->size;
}

static inline unsigned int ring_used_nr(const ring_t *r)
{
	return r->used;
}

static inline unsigned int ring_free_nr(const ring_t *r)
{
	return r->size - r->used;
}

static inline void ring_set_head(ring_t *r, unsigned int head)
{
	RING_ASSERT(head < r->size);

	r->head = head;
}

static inline void ring_set_used(ring_t *r, unsigned int used)
{
	RING_ASSERT(used <= r->size);

	r->used = used;
}

static inline void ring_push(ring_t *r, unsigned int n)
{
	RING_ASSERT(n <= ring_free_nr(r));

	r->head = _ring_add(r->head, n, r->size);
	r->used += n;
}

static inline void ring_push_cancel(ring_t *r, unsigned int n)
{
	RING_ASSERT(n <= ring_used_nr(r));

	r->head = _ring_sub(r->head, n, r->size);
	r->used -= n;
}

static inline void ring_pull(ring_t *r, unsigned int n)
{
	RING_ASSERT(n <= ring_used_nr(r));

	r->used -= n;
}

static inline void ring_pull_cancel(ring_t *r, unsigned int n)
{
	RING_ASSERT(n <= ring_free_nr(r));

	r->used += n;
}

#endif	/* _RING_H_ */
