/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2022
 *
 * Richard van Schagen <vschagen@icloud.com>
 */
#ifndef _EIP93_CIPHER_H_
#define _EIP93_CIPHER_H_

#include "eip93-main.h"

struct mtk_crypto_ctx {
	struct mtk_device		*mtk;
	struct saRecord_s		*sa_in;
	dma_addr_t			sa_base_in;
	struct saRecord_s		*sa_out;
	dma_addr_t			sa_base_out;
	uint32_t			saNonce;
	int				blksize;
	/* AEAD specific */
	unsigned int			authsize;
	bool				in_first;
	bool				out_first;
	struct crypto_shash		*shash;
};

struct mtk_cipher_reqctx {
	struct mtk_device		*mtk;
	uintptr_t			async;
	unsigned long			flags;
	unsigned int			blksize;
	unsigned int			ivsize;
	unsigned int			textsize;
	unsigned int			assoclen;
	unsigned int			authsize;
	dma_addr_t			saRecord_base;
	uint32_t			saNonce;
	struct saState_s		*saState;
	dma_addr_t			saState_base;
	uint32_t			saState_idx;
	struct eip93_descriptor_s	*cdesc;
	struct scatterlist		*sg_src;
	struct scatterlist		*sg_dst;
	int				src_nents;
	int				dst_nents;
	struct saState_s		*saState_ctr;
	dma_addr_t			saState_base_ctr;
	uint32_t			saState_ctr_idx;
};

void mtk_skcipher_handle_result(struct skcipher_request *req, int err);

#endif /* _EIP93_CIPHER_H_ */
