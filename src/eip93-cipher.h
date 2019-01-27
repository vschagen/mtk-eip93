/*
 * Copyright (c) 2018, Richard van Schagen. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _CIPHER_H_
#define _CIPHER_H_

#include <linux/timex.h>

struct mtk_cipher_ctx {
	struct mtk_device	*mtk;
	u8			key[AES_MAX_KEY_SIZE];
	u32			keylen;
	unsigned int		*saState;
	dma_addr_t		phy_sa;
	dma_addr_t		phy_state;
	bool			refresh;
	struct crypto_skcipher	*fallback;
};

struct mtk_cipher_reqctx {
	unsigned long		flags;
	struct scatterlist	*sg_src;
	struct scatterlist	*sg_dst;
};

static inline struct mtk_alg_template *to_cipher_tmpl(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	return container_of(alg, struct mtk_alg_template, alg.crypto);
}

extern const struct mtk_algo_ops ablkcipher_ops;

void mtk_cipher_req_done(struct mtk_device *mtk, int ctr);

#endif /* _CIPHER_H_ */
