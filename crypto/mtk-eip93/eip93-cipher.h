/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _EIP93_CIPHER_H_
#define _EIP93_CIPHER_H_

#include "eip93-common.h"
#include "eip93-main.h"

struct mtk_crypto_ctx {
	struct mtk_device		*mtk;
	struct saRecord_s		*sa_in;
	dma_addr_t			sa_base_in;
	struct saRecord_s		*sa_out;
	dma_addr_t			sa_base_out;
	uint32_t			saNonce;
	int				blksize;
	struct crypto_skcipher		*fallback;
	/* AEAD specific */
	unsigned int			authsize;
	unsigned int			assoclen_in;
	unsigned int			assoclen_out;
	bool				in_first;
	bool				out_first;
	enum mtk_alg_type		type;
	struct crypto_shash		*shash;
};

struct mtk_cipher_reqctx {
	unsigned long			flags;
	unsigned int			blksize;
	unsigned int			ivsize;
	unsigned int			textsize;
	unsigned int			assoclen;
	unsigned int			authsize;
	dma_addr_t			saRecord_base;
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
#endif /* _EIP93_CIPHER_H_ */
