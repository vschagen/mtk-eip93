

int mtk_prng_seed(struct crypto_rng *tfm, const u8 *seed,
		       unsigned int slen);

int mtk_prng_generate(struct crypto_rng *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int dlen);


