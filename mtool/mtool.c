/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	mtool.c
 * @brief	Tool for R/W physical memory from user space.
 */

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "mtrace.h"

#define DEV_MEM_DEFAULT		"/dev/mem"
#define LINE_BYTES		16

#define PAGE_ROUND_UP(x)	PAGE_ROUND_DOWN((x) + getpagesize() - 1)
#define PAGE_ROUND_DOWN(x)	((x) & ~(typeof(x))(getpagesize() - 1))

struct mem_op {
	const char *name;
	int (*handler)(int argc, const char *argv[]);
	const char *help;
};

static struct {
	int fd;
	off_t offset;
	size_t len;
	void *vaddr;
} dev_mem = { -1, 0, 0, NULL };

const char *dev_mem_file;

static void unmap_dev_mem(void)
{
	if (dev_mem.vaddr != NULL) {
		munmap(dev_mem.vaddr, dev_mem.len);
	}
	if (dev_mem.fd != -1) {
		close(dev_mem.fd);
	}
	dev_mem.fd = -1;
	dev_mem.offset = 0;
	dev_mem.len = 0;
	dev_mem.vaddr = NULL;
}

static int map_dev_mem(uint64_t addr, uint32_t size)
{
	int fd;
	void *vaddr;
	off_t offset;
	size_t len;

	offset = PAGE_ROUND_DOWN(addr);
	len = PAGE_ROUND_UP(size);

	if ((offset == dev_mem.offset) && (len == dev_mem.len)) {
		goto ok;
	}

	unmap_dev_mem();

	if ((fd = open(dev_mem_file, O_RDWR | O_SYNC)) < 0) {
		fprintf(stderr, "open '%s' failed\n", dev_mem_file);
		goto err;
	}
	dev_mem.fd = fd;

	vaddr = mmap64(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);

	if ((vaddr == NULL) || (vaddr == MAP_FAILED)) {
		fprintf(stderr, "mmap '%s' failed\n", dev_mem_file);
		goto err;
	}

	dev_mem.offset = offset;
	dev_mem.len = len;
	dev_mem.vaddr = vaddr;
ok:
	return 0;
err:
	unmap_dev_mem();
	return ENOMEM;
}

static int mem_read(int argc, const char *argv[])
{
	int rc;
	void *vaddr;
	uint64_t addr;
	unsigned int i, n, skip, count = 1, width = sizeof(uint32_t);
	union {
		uint8_t   u8[LINE_BYTES / sizeof(uint8_t)  + 1];
		uint16_t u16[LINE_BYTES / sizeof(uint16_t) + 1];
		uint32_t u32[LINE_BYTES / sizeof(uint32_t) + 1];
		uint64_t u64[LINE_BYTES / sizeof(uint64_t) + 1];
	} linebuf;

	switch (argc) {
	case 3:
		count = strtoul(argv[2], NULL, 16);
	case 2:
		addr = strtoull(argv[1], NULL, 16);
		break;
	default:
		fprintf(stderr, "ERROR: Bad format for command \"%s\"\n", argv[0]);
		rc = EINVAL;
		goto err;
	}

	if (strlen(argv[0]) == 3) {
		switch (argv[0][2]) {
		case 'b':
			width = sizeof(uint8_t);
			break;
		case 'w':
			width = sizeof(uint16_t);
			break;
		case 'd':
			width = sizeof(uint64_t);
			break;
		default:
			break;
		}
	}

	addr &= ~(uint64_t)(width - 1);
	if ((rc = map_dev_mem(addr, count * width))) {
		goto err;
	}
	vaddr = (uint8_t *)dev_mem.vaddr + (addr - dev_mem.offset);

	skip = (addr % LINE_BYTES) / width;
	addr -= skip * width;

	while (count) {
		n = (LINE_BYTES / width) - skip;
		n = n < count ? n : count;
		printf("%016" PRIx64 "%-*c", addr, skip * (1 + width * 2) + 1, ':');
		for (i = 0; i < n; i++) {
			switch (width) {
			case 1:
				linebuf.u8[i] = *(volatile uint8_t *)vaddr;
				printf(" %02" PRIx8, linebuf.u8[i]);
				break;
			case 2:
				linebuf.u16[i] = *(volatile uint16_t *)vaddr;
				printf(" %04" PRIx16, linebuf.u16[i]);
				break;
			case 8:
				linebuf.u64[i] = *(volatile uint64_t *)vaddr;
				printf(" %016" PRIx64, linebuf.u64[i]);
				break;
			case 4:
			default:
				linebuf.u32[i] = *(volatile uint32_t *)vaddr;
				printf(" %08" PRIx32, linebuf.u32[i]);
				break;
			}
			vaddr += width;
		}
		for (i = 0; i < n * width; i++) {
			if (!isprint(linebuf.u8[i])) {
				linebuf.u8[i] = '.';
			}
		}
		linebuf.u8[i] = '\0';
		addr += LINE_BYTES;
		count -= n;
		n = (LINE_BYTES / width) - n - skip;
		printf("%*c|%*c", n * (1 + width * 2) + 1, ' ', skip * width + 1, ' ');
		printf("%s%*c|\n", linebuf.u8, n * width + 1, ' ');
		skip = 0;
	}

	rc = 0;
	goto ok;
ok:
err:
	unmap_dev_mem();
	return rc;
}

static int mem_write(int argc, const char *argv[])
{
	int rc;
	void *vaddr;
	uint64_t addr, data;
	unsigned int count = 1, width = sizeof(uint32_t);

	switch (argc) {
	case 4:
		count = strtoul(argv[3], NULL, 16);
	case 3:
		addr = strtoull(argv[1], NULL, 16);
		data = strtoull(argv[2], NULL, 16);
		break;
	default:
		fprintf(stderr, "ERROR: Bad format for command \"%s\"\n", argv[0]);
		rc = EINVAL;
		goto err;
	}

	if (strlen(argv[0]) == 3) {
		switch (argv[0][2]) {
		case 'b':
			width = sizeof(uint8_t);
			break;
		case 'w':
			width = sizeof(uint16_t);
			break;
		case 'd':
			width = sizeof(uint64_t);
			break;
		default:
			break;
		}
	}

	addr &= ~(uint64_t)(width - 1);
	if ((rc = map_dev_mem(addr, count * width))) {
		goto err;
	}
	vaddr = (uint8_t *)dev_mem.vaddr + (addr - dev_mem.offset);

	while (count--) {
		switch (width) {
		case 1 :
			*(volatile uint8_t *)vaddr = (uint8_t)data;
			break;
		case 2 :
			*(volatile uint16_t *)vaddr = (uint16_t)data;
			break;
		case 8 :
			*(volatile uint64_t *)vaddr = (uint64_t)data;
			break;
		case 4 :
		default :
			*(volatile uint32_t *)vaddr = (uint32_t)data;
			break;
		}
		vaddr += width;
	}

	rc = 0;
	goto ok;
ok:
err:
	unmap_dev_mem();
	return rc;
}

static int mem_wstr(int argc, const char *argv[])
{
	int rc;
	void *vaddr;
	uint64_t addr;
	unsigned int count;

	switch (argc) {
	case 3:
		addr = strtoull(argv[1], NULL, 16);
		count = strlen(argv[2]);
		break;
	default:
		fprintf(stderr, "ERROR: Bad format for command \"%s\"\n", argv[0]);
		rc = EINVAL;
		goto err;
	}

	if ((rc = map_dev_mem(addr, count))) {
		goto err;
	}
	vaddr = (uint8_t *)dev_mem.vaddr + (addr - dev_mem.offset);

	memcpy(vaddr, argv[2], count);

	rc = 0;
	goto ok;
ok:
err:
	unmap_dev_mem();
	return rc;
}

const struct mem_op mem_op_handler[] = {
	{"r",   mem_read,  "r   [ addr ] [[ count ]]          - Read physical memory, width is 4-byte"},
	{"r.b", mem_read,  "r.b [ addr ] [[ count ]]          - Read physical memory, width is 1-byte"},
	{"r.w", mem_read,  "r.w [ addr ] [[ count ]]          - Read physical memory, width is 2-byte"},
	{"r.l", mem_read,  "r.l [ addr ] [[ count ]]          - Read physical memory, width is 4-byte"},
	{"r.d", mem_read,  "r.d [ addr ] [[ count ]]          - Read physical memory, width is 8-byte"},
	{"w",   mem_write, "w   [ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte"},
	{"w.b", mem_write, "w.b [ addr ] [ data ] [[ count ]] - Write physical memory, width is 1-byte"},
	{"w.w", mem_write, "w.w [ addr ] [ data ] [[ count ]] - Write physical memory, width is 2-byte"},
	{"w.l", mem_write, "w.l [ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte"},
	{"w.d", mem_write, "w.d [ addr ] [ data ] [[ count ]] - Write physical memory, width is 8-byte"},
	{"w.s", mem_wstr,  "w.s [ addr ] [ string ]           - Write string to physical memory"},
	{NULL, NULL, NULL}
};

static void print_help(void)
{
	const struct mem_op *op = mem_op_handler;

	printf("Usage:\n");
	while (op->name != NULL) {
		if (op->help != NULL) {
			printf("mtool %s\n", op->help);
		}
		op++;
	}
}

int main(int argc, const char *argv[])
{
	int rc;
	const struct mem_op *op = mem_op_handler;

	mtrace_init();

	if (argc < 2) {
		fprintf(stderr, "ERROR: too few argument!\n");
		rc = EINVAL;
		goto err;
	}

	if ((dev_mem_file = getenv("DEV_MEM")) == NULL)
		dev_mem_file = DEV_MEM_DEFAULT;

	if (strcmp("-h", argv[1]) == 0) {
		print_help();
		goto ok;
	}

	while (op->name != NULL) {
		if (strcmp(op->name, argv[1]) == 0) {
			if (!(rc = op->handler(argc - 1, argv + 1))) {
				goto ok;
			} else {
				goto err;
			}
		}
		op++;
	}

	fprintf(stderr, "ERROR: unknown command %s\n", argv[1]);
	rc = EINVAL;
err:
	if (rc == EINVAL) {
		print_help();
	}
	mtrace_finish();
	return rc;
ok:
	mtrace_finish();
	return 0;
}
