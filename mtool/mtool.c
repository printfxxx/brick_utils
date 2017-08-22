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
#include <stdbool.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <asm/byteorder.h>

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

static void parse_arg(const char *str, bool *be, bool *le, unsigned int *width)
{
	const char *dot;

	switch (str[1]) {
	case 'b':
		*be = true;
		*le = false;
		break;
	case 'l':
		*be = false;
		*le = true;
		break;
	default:
		*be = false;
		*le = false;
		break;
	}

	dot = strchr(str, '.');
	if (dot) {
		switch (dot[1]) {
		case 'b':
			*width = 1;
			break;
		case 'w':
			*width = 2;
			break;
		case 'q':
			*width = 8;
			break;
		case 'l':
		default:
			*width = 4;
			break;
		}
	} else {
		*width = 4;
	}
}

static int mem_read(int argc, const char *argv[])
{
	int rc;
	void *vaddr;
	bool be, le;
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64, addr;
	unsigned int i, n, skip, count = 1, width = sizeof(uint32_t);
	union {
		uint8_t   u8[LINE_BYTES / sizeof(uint8_t) + 1];
		uint16_t u16[LINE_BYTES / sizeof(uint16_t)];
		uint32_t u32[LINE_BYTES / sizeof(uint32_t)];
		uint64_t u64[LINE_BYTES / sizeof(uint64_t)];
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

	parse_arg(argv[0], &be, &le, &width);

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
				u8 = *(volatile uint8_t *)vaddr;
				linebuf.u8[i] = u8;
				printf(" %02" PRIx8, u8);
				break;
			case 2:
				u16 = *(volatile uint16_t *)vaddr;
				linebuf.u16[i] = u16;
				u16 = be ? __be16_to_cpu(u16) : u16;
				u16 = le ? __le16_to_cpu(u16) : u16;
				printf(" %04" PRIx16, u16);
				break;
			case 8:
				u64 = *(volatile uint64_t *)vaddr;
				linebuf.u64[i] = u64;
				u64 = be ? __be64_to_cpu(u64) : u64;
				u64 = le ? __le64_to_cpu(u64) : u64;
				printf(" %016" PRIx64, u64);
				break;
			case 4:
			default:
				u32 = *(volatile uint32_t *)vaddr;
				linebuf.u32[i] = u32;
				u32 = be ? __be32_to_cpu(u32) : u32;
				u32 = le ? __le32_to_cpu(u32) : u32;
				printf(" %08" PRIx32, u32);
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
	bool be, le;
	uint8_t u8 = 0;
	uint16_t u16 = 0;
	uint32_t u32 = 0;
	uint64_t addr, u64;
	unsigned int count = 1, width;

	switch (argc) {
	case 4:
		count = strtoul(argv[3], NULL, 16);
	case 3:
		addr = strtoull(argv[1], NULL, 16);
		u64 = strtoull(argv[2], NULL, 16);
		break;
	default:
		fprintf(stderr, "ERROR: Bad format for command \"%s\"\n", argv[0]);
		rc = EINVAL;
		goto err;
	}

	parse_arg(argv[0], &be, &le, &width);

	addr &= ~(uint64_t)(width - 1);
	if ((rc = map_dev_mem(addr, count * width))) {
		goto err;
	}
	vaddr = (uint8_t *)dev_mem.vaddr + (addr - dev_mem.offset);

	switch (width) {
	case 1:
		u8 = (uint8_t)u64;
		break;
	case 2:
		u16 = (uint16_t)u64;
		u16 = be ? __cpu_to_be16(u16) : u16;
		u16 = le ? __cpu_to_le16(u16) : u16;
		break;
	case 8:
		u64 = be ? __cpu_to_be64(u64) : u64;
		u64 = le ? __cpu_to_le64(u64) : u64;
		break;
	case 4:
	default:
		u32 = (uint32_t)u64;
		u32 = be ? __cpu_to_be32(u32) : u32;
		u32 = le ? __cpu_to_le32(u32) : u32;
		break;
	}

	while (count--) {
		switch (width) {
		case 1 :
			*(volatile uint8_t *)vaddr = u8;
			break;
		case 2 :
			*(volatile uint16_t *)vaddr = u16;
			break;
		case 8 :
			*(volatile uint64_t *)vaddr = u64;
			break;
		case 4 :
		default :
			*(volatile uint32_t *)vaddr = u32;
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
	{"r",    mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 4-byte"},
	{"rb",   mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 4-byte, big-endian"},
	{"rl",   mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 4-byte, little-endian"},
	{"r.b",  mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 1-byte"},
	{"r.w",  mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 2-byte"},
	{"rb.w", mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 2-byte, big-endian"},
	{"rl.w", mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 2-byte, little-endian"},
	{"r.l",  mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 4-byte"},
	{"rb.l", mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 4-byte, big-endian"},
	{"rl.l", mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 4-byte, little-endian"},
	{"r.q",  mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 8-byte"},
	{"rb.q", mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 8-byte, big-endian"},
	{"rl.q", mem_read,  "[ addr ] [[ count ]]          - Read physical memory, width is 8-byte, little-endian"},
	{"w",    mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte"},
	{"wb",   mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte, big-endian"},
	{"wl",   mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte, little-endian"},
	{"w.b",  mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 1-byte"},
	{"w.w",  mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 2-byte"},
	{"wb.w", mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 2-byte, big-endian"},
	{"wl.w", mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 2-byte, little-endian"},
	{"w.l",  mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte"},
	{"wb.l", mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte, big-endian"},
	{"wl.l", mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 4-byte, little-endian"},
	{"w.q",  mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 8-byte"},
	{"wb.q", mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 8-byte, big-endian"},
	{"wl.q", mem_write, "[ addr ] [ data ] [[ count ]] - Write physical memory, width is 8-byte, little-endian"},
	{"w.s",  mem_wstr,  "[ addr ] [ string ]           - Write string to physical memory"},
	{NULL,   NULL, NULL}
};

static void print_help(void)
{
	const struct mem_op *op = mem_op_handler;

	printf("Usage:\n");
	printf("mtool [r|w|rb|rl|wb|wl].[b|w|l|q]\n");
	printf("\n");
	printf("type:  r|w|rb|rl|wb|wl - read|write|read-be|read-le|write-be|write-le\n");
	printf("width: b|w|l|q         - byte|word|long|quad-word\n");
	printf("\n");
	while (op->name != NULL) {
		if (op->help != NULL) {
			printf("mtool %-4s %s\n", op->name, op->help);
		}
		op++;
	}
}

int main(int argc, const char *argv[])
{
	int rc;
	const struct mem_op *op = mem_op_handler;

	if ((rc = mtrace_init())) {
		rc = -rc;
		goto err_mtrace;
	}

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

	fprintf(stderr, "ERROR: unknown command \"%s\"\n", argv[1]);
	rc = EINVAL;
err:
	if (rc == EINVAL) {
		print_help();
	}
	mtrace_finish();
err_mtrace:
	return rc;
ok:
	mtrace_finish();
	return 0;
}
