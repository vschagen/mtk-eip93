/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _CIPHER_H_
#define _CIPHER_H_

struct mtk_cipher_ctx {
	struct mtk_device		*mtk;
	struct saRecord_s		*sa;
	struct crypto_skcipher		*fallback;
	/* AEAD specific */
	unsigned int			authsize;
	struct crypto_shash		*shash;
	bool				aead;
};

struct mtk_cipher_reqctx {
	unsigned long			flags;
	u32				textsize;
	u32				ivsize;
	bool				iv_dma;
	struct saRecord_s		*saRecord;
	dma_addr_t			saRecord_base;
	struct saState_s		*saState;
	dma_addr_t			saState_base;
	/* copy in case of mis-alignment or AEAD if no-consecutive blocks */
	struct scatterlist		*sg_src;
	struct scatterlist		*sg_dst;
	/* AES-CTR in case of counter overflow */
	struct saState_s		*saState_ctr;
	dma_addr_t			saState_base_ctr;
	struct scatterlist		ctr_src[2];
	struct scatterlist		ctr_dst[2];
	/* AEAD */
	u32				assoclen;
	u32				authsize;
	/* request fallback, keep at the end */
	struct skcipher_request		fallback_req;
};
#endif /* _CIPHER_H_ */
