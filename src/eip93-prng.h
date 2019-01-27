/*
 * Copyright (c) 2018 Richard van Schagen. All rights reserved.
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



