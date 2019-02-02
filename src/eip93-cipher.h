// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#ifndef _CIPHER_H_
#define _CIPHER_H_

struct mtk_cipher_ctx {
	struct mtk_context			base;
	struct mtk_device			*mtk;
	u8							key[AES_MAX_KEY_SIZE];
	u32							keylen;
	struct crypto_skcipher		*fallback;

};

struct mtk_cipher_reqctx {
	unsigned long			flags;
	int						blksize;
	/* copy in case of mis-alignment */
	struct scatterlist		*sg_src;
	struct scatterlist		*sg_dst;
	/* AES-CTR in case of counter overflow */
	struct scatterlist		ctr_src[2];
	struct scatterlist		ctr_dst[2];
};

static inline struct mtk_alg_template *to_cipher_tmpl(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	return container_of(alg, struct mtk_alg_template, alg.crypto);
}

extern const struct mtk_algo_ops ablkcipher_ops;

#endif /* _CIPHER_H_ */
