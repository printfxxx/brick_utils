/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	time.h
 * @brief	Time type definition and convert APIs
 */

#ifndef _TIME_H_
#define _TIME_H_

#include <linux/types.h>

typedef uint64_t plat_time_t;

#ifdef PLATFORM_TIME

int plat_time_init(void);
plat_time_t plat_time_get(void);
plat_time_t nsec_to_plat_time(uint64_t ns);
uint64_t plat_time_to_nsec(plat_time_t time);

#else	/* PLATFORM_TIME */

#include <linux/ktime.h>

#define plat_time_init()	(0)

static inline plat_time_t plat_time_get(void)
{
	int64_t ns = ktime_to_ns(ktime_get());

	return (plat_time_t)ns;
}

static inline plat_time_t nsec_to_plat_time(uint64_t ns)
{
	return (plat_time_t)ns;
}

static inline uint64_t plat_time_to_nsec(plat_time_t time)
{
	return (uint64_t)time;
}

#endif	/* PLATFORM_TIME */

#endif	/* _TIME_H_ */
