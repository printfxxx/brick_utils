/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	proto.h
 * @brief	Header file for communication protocol
 */

#ifndef _PROTO_H_
#define _PROTO_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/socket.h>
#else
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#define PROTO_IDENTIFY_0	0xaa
#define PROTO_IDENTIFY_1	0x55

enum {
	MAGIC_WORKER	= 0,
	MAGIC_NETDEV	= 1,
	MAGIC_MAX,
	MAGIC_MSG	= 0xf0,
#define MSG_ID_STDOUT	0
#define MSG_ID_STDERR	1
	MAGIC_RESP,
	MAGIC_RET_CODE,
	MAGIC_PRIV
};

enum {
	WORKER_ID_WORKER	= 0,
	WORKER_ID_BYTE_MODE	= 1,
	WORKER_ID_QLEN		= 2,
	WORKER_ID_POOL_SZ	= 3,
	WORKER_ID_BURST_SZ	= 4,
	WORKER_ID_BUDGET	= 5,
	WORKER_ID_PS_LIMIT	= 6,
	WORKER_ID_PKT_CNT	= 7,
	WORKER_ID_ADD_SKB	= 8,
	WORKER_ID_DEL_SKB	= 9,
	WORKER_ID_SKB_TXQ	= 10,
	WORKER_ID_DUMP_SKB	= 11,
	WORKER_ID_MAX
};

enum {
	NETDEV_ID_NETDEV	= 0,
	NETDEV_ID_START		= 1,
	NETDEV_ID_STOP		= 2,
	NETDEV_ID_CLEAR		= 3,
	NETDEV_ID_STATS		= 4,
	NETDEV_ID_ATTACH	= 5,
	NETDEV_ID_DETACH	= 6,
	NETDEV_ID_MAX
};

#ifdef __KERNEL__
typedef struct socket *proto_sock_t;
typedef struct kvec proto_iovec_t;
#else
typedef int proto_sock_t;
typedef struct iovec proto_iovec_t;
#endif

typedef struct proto_hdr {
	uint8_t		magic;
	uint8_t		id;
	uint16_t	length;
} proto_hdr_t;

typedef struct proto_txd {
	proto_hdr_t	hdr;
	struct {
#define PROTO_IOVEC_MAX		8
		proto_iovec_t	head_iov[2];
		proto_iovec_t	iov[PROTO_IOVEC_MAX];
	};
	size_t		num;
} proto_txd_t;

typedef struct proto_rxd {
	proto_hdr_t	hdr;
#define PROTO_BUF_MAX	65536
	void		*buf;
	size_t		len;
} proto_rxd_t;

typedef struct proto_handle {
	bool		io_err;
	proto_sock_t	sock;
	ssize_t (*sendmsg)(proto_sock_t sock, proto_iovec_t *iov, size_t num, int flags);
	ssize_t (*recv)(proto_sock_t sock, void *buf, size_t len, int flags);
} proto_handle_t;

int proto_send(proto_handle_t *handle, proto_txd_t *txd);
int proto_recv(proto_handle_t *handle, proto_rxd_t *rxd);
int proto_send_ret_code(proto_handle_t *handle, int ret);
int proto_get_uint8(void **buf, size_t *len, uint8_t *out);
int proto_get_uint16(void **buf, size_t *len, uint16_t *out);
int proto_get_uint32(void **buf, size_t *len, uint32_t *out);
int proto_get_uint64(void **buf, size_t *len, uint64_t *out);
char *proto_get_str(void **buf, size_t *len);
void *proto_get_buf(void **buf, size_t *len, size_t sz);

#endif	/* _PROTO_H_ */
