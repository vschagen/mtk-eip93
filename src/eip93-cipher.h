// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#ifndef _CIPHER_H_
#define _CIPHER_H_

struct mtk_cipher_ctx {
	struct mtk_context		base;
	struct mtk_device		*mtk;
	u8						key[AES_MAX_KEY_SIZE];
	u32						keylen;
	struct crypto_skcipher	*fallback;
	bool					aead;
	/* AEAD specific */
	struct crypto_shash 	*shash; // TODO change to ahash
	u8						ipad[SHA512_DIGEST_SIZE] __aligned(sizeof(u32));
	u8						opad[SHA512_DIGEST_SIZE] __aligned(sizeof(u32));
	unsigned int			*saState1;
	unsigned int			*saState2;
	unsigned int			*saRecord;
	dma_addr_t				src1_base;
	dma_addr_t				src2_base;
	int						authsize;
};

struct mtk_cipher_reqctx {
	unsigned long			flags;
	int						textsize;
	/* AEAD */
	u32						odigest[SHA512_DIGEST_SIZE] __aligned(sizeof(u32));
	int						assoclen;
	int						authsize;
	/* copy in case of mis-alignment or AEAD */
	struct scatterlist		*sg_src;
	int						src_nents;
	struct scatterlist		*sg_dst;
	int						dst_nents;
	/* AES-CTR in case of counter overflow */
	struct scatterlist		ctr_src[2];
	struct scatterlist		ctr_dst[2];
};

#endif /* _CIPHER_H_ */
