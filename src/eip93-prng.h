// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

bool mtk_prng_activate (struct mtk_device *mtk, bool fLongSA);

int mtk_prng_seed(struct crypto_rng *tfm, const u8 *seed,
		       unsigned int slen);

int mtk_prng_generate(struct crypto_rng *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int dlen);

static inline struct mtk_alg_template *to_prng_tmpl(struct crypto_rng *tfm)
{
	struct rng_alg *alg = crypto_rng_alg(tfm);

	return container_of(alg, struct mtk_alg_template, alg.rng);
}

extern const struct mtk_algo_ops prng_ops;



