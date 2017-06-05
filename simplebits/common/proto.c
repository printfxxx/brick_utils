/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	proto.c
 * @brief	protocol process code
 */

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <asm/byteorder.h>

#include "proto.h"

#include "mtrace.h"

enum {
	PROTO_STATE_START,
	PROTO_STATE_CMD_ID_0,
	PROTO_STATE_CMD_ID_1,
	PROTO_STATE_HDR,
	PROTO_STATE_DATA,
};

/*
 * Protocol format for data transfer between server and client:
 * [ 0xaa ] [ 0x55 ] [ magic ] [ id ] [ length ] ...
 */

int proto_send(proto_handle_t *handle, proto_txd_t *txd)
{
	int i;
	ssize_t ret;
	uint8_t identity[] = {PROTO_IDENTIFY_0, PROTO_IDENTIFY_1};

	txd->head_iov[0].iov_base = identity;
	txd->head_iov[0].iov_len = sizeof(identity);
	txd->head_iov[1].iov_base = &txd->hdr;
	txd->head_iov[1].iov_len = sizeof(txd->hdr);
	txd->hdr.length = 0;
	for (i = 0; i < txd->num; i++) {
		txd->hdr.length += txd->iov[i].iov_len;
	}
	txd->hdr.length = __cpu_to_be16(txd->hdr.length);
	ret = handle->sendmsg(handle->sock, txd->head_iov, txd->num + 2, 0);
	if (ret <= 0) {
		ret = -EIO;
		handle->io_err = true;
		goto err;
	}

	return 0;
err:
	return ret;
}

int proto_recv(proto_handle_t *handle, proto_rxd_t *rxd)
{
	int state, n, len;
	ssize_t ret;

	state = PROTO_STATE_START;

	while (state != PROTO_STATE_DATA) {
		switch (state) {
		case PROTO_STATE_START:
			state = PROTO_STATE_CMD_ID_0;
			len = 1;
			break;
		case PROTO_STATE_CMD_ID_0:
			if (((uint8_t *)rxd->buf)[0] == PROTO_IDENTIFY_0) {
				state = PROTO_STATE_CMD_ID_1;
				len = 1;
			} else {
				state = PROTO_STATE_CMD_ID_0;
				len = 1;
			}
			break;
		case PROTO_STATE_CMD_ID_1:
			if (((uint8_t *)rxd->buf)[0] == PROTO_IDENTIFY_1) {
				state = PROTO_STATE_HDR;
				len = sizeof(rxd->hdr);
			} else {
				state = PROTO_STATE_CMD_ID_0;
				len = 1;
			}
			break;
		case PROTO_STATE_HDR:
			memcpy(&rxd->hdr, rxd->buf, sizeof(rxd->hdr));
			rxd->hdr.length = __be16_to_cpu(rxd->hdr.length);
			len = rxd->hdr.length;
			if (len > rxd->len) {
				ret = -ENOMEM;
				goto err;
			}
			state = PROTO_STATE_DATA;
			break;
		default:
			ret = -EINVAL;
			goto err;
		}
		for (n = 0; n < len; n += ret) {
			ret = handle->recv(handle->sock, rxd->buf + n, len - n, 0);
			if (ret <= 0) {
				ret = -EIO;
				handle->io_err = true;
				goto err;
			}
		}
	}

	return 0;
err:
	return ret;
}

int proto_send_ret_code(proto_handle_t *handle, int ret)
{
	proto_txd_t txd;

	txd.num = 0;
	txd.hdr.magic = MAGIC_RET_CODE;
	txd.hdr.id = ret & 0xff;

	return proto_send(handle, &txd);
}

int proto_get_uint8(void **buf, size_t *len, uint8_t *out)
{
	if (*len < sizeof(*out)) {
		return -ENOMEM;
	}
	memcpy(out, *buf, sizeof(*out));
	*len -= sizeof(*out);
	*buf += sizeof(*out);

	return 0;
}

int proto_get_uint16(void **buf, size_t *len, uint16_t *out)
{
	if (*len < sizeof(*out)) {
		return -ENOMEM;
	}
	memcpy(out, *buf, sizeof(*out));
	*out = __be16_to_cpu(*out);
	*len -= sizeof(*out);
	*buf += sizeof(*out);

	return 0;
}

int proto_get_uint32(void **buf, size_t *len, uint32_t *out)
{
	if (*len < sizeof(*out)) {
		return -ENOMEM;
	}
	memcpy(out, *buf, sizeof(*out));
	*out = __be32_to_cpu(*out);
	*len -= sizeof(*out);
	*buf += sizeof(*out);

	return 0;
}

int proto_get_uint64(void **buf, size_t *len, uint64_t *out)
{
	if (*len < sizeof(*out)) {
		return -ENOMEM;
	}
	memcpy(out, *buf, sizeof(*out));
	*out = __be64_to_cpu(*out);
	*len -= sizeof(*out);
	*buf += sizeof(*out);

	return 0;
}

char *proto_get_str(void **buf, size_t *len)
{
	char *str;
	size_t n;

	n = strnlen(*buf, *len);
	if (n >= *len) {
		return NULL;
	}
	str = *buf;
	*len -= n + 1;
	*buf += n + 1;

	return str;
}

void *proto_get_buf(void **buf, size_t *len, size_t sz)
{
	void *p;

	if (sz > *len) {
		return NULL;
	}
	p = *buf;
	*len -= sz;
	*buf += sz;

	return p;
}
