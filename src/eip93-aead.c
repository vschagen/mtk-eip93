/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#define DEBUG 1
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/authenc.h>
#include <crypto/ctr.h>
#include <crypto/hmac.h>
#include <crypto/internal/aead.h>
#include <crypto/md5.h>
#include <crypto/null.h>
#include <crypto/sha.h>

#ifdef CONFIG_EIP93_DES
#include <crypto/internal/des.h>
#endif

#include <linux/types.h>

#include "eip93-common.h"
#include "eip93-main.h"
#include "eip93-cipher.h"
#include "eip93-regs.h"
#include "eip93-ring.h"

void mtk_aead_handle_result(struct mtk_device *mtk,
				struct crypto_async_request *async,
				bool complete,  int err)
{
	struct aead_request *req = aead_request_cast(async);
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);

	mtk_handle_result(mtk, async, rctx, req->src, req->dst, req->iv,
				complete, err);
}

/* Crypto aead API functions */
static int mtk_aead_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.aead.base);
	unsigned long flags = tmpl->flags;
	char *alg_base;

	memset(ctx, 0, sizeof(*ctx));

	crypto_aead_set_reqsize(__crypto_aead_cast(tfm),
			sizeof(struct mtk_cipher_reqctx));

	ctx->mtk = tmpl->mtk;
	ctx->aead = true;
	ctx->fallback = NULL;

	ctx->sa = kzalloc(sizeof(struct saRecord_s), GFP_KERNEL);
	if (!ctx->sa)
		printk("!! no sa memory\n");

	/* software workaround for now */
	if (IS_HASH_MD5(flags))
		alg_base = "md5";
	if (IS_HASH_SHA1(flags))
		alg_base = "sha1";
	if (IS_HASH_SHA224(flags))
		alg_base = "sha224";
	if (IS_HASH_SHA256(flags))
		alg_base = "sha256";

	ctx->shash = crypto_alloc_shash(alg_base, 0, CRYPTO_ALG_NEED_FALLBACK);

	if (IS_ERR(ctx->shash)) {
		dev_err(ctx->mtk->dev, "base driver %s could not be loaded.\n",
				alg_base);
		return PTR_ERR(ctx->shash);
	}

	return 0;
}

static void mtk_aead_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	if (ctx->shash)
		crypto_free_shash(ctx->shash);

	kfree(ctx->sa);
}

static int mtk_aead_setkey(struct crypto_aead *ctfm, const u8 *key,
			unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);
	unsigned long flags = tmpl->flags;
	struct crypto_authenc_keys keys;
	struct crypto_aes_ctx aes;
	int bs = crypto_shash_blocksize(ctx->shash);
	int ds = crypto_shash_digestsize(ctx->shash);
	u8 *ipad, *opad;
	unsigned int i, err = -EINVAL;
	u32 nonce;

	SHASH_DESC_ON_STACK(shash, ctx->shash);

	if (crypto_authenc_extractkeys(&keys, key, len))
		goto badkey;

	if (IS_RFC3686(flags)) {
		if (keys.enckeylen < CTR_RFC3686_NONCE_SIZE)
			goto badkey;

		keys.enckeylen -= CTR_RFC3686_NONCE_SIZE;
		memcpy(&nonce, keys.enckey + keys.enckeylen,
						CTR_RFC3686_NONCE_SIZE);
	}

	switch ((flags & MTK_ALG_MASK)) {
#ifdef CONFIG_EIP93_DES
	case MTK_ALG_DES:
		err = verify_aead_des_key(ctfm, keys.enckey, keys.enckeylen);
		break;
	case MTK_ALG_3DES:
		if (keys.enckeylen != DES3_EDE_KEY_SIZE) {
			err = -EINVAL;
			break;
		}
		err = verify_aead_des3_key(ctfm, keys.enckey, keys.enckeylen);
		break;
#endif
	case MTK_ALG_AES:
		err = aes_expandkey(&aes, keys.enckey, keys.enckeylen);
	}
	if (err)
		goto badkey;

	/* auth key
	 *
	 * EIP93 can only authenticate with hash of the key
	 * do software shash until EIP93 hash function complete.
	 */
	ipad = kcalloc(2, SHA512_BLOCK_SIZE, GFP_KERNEL);
	if (!ipad)
		return -ENOMEM;

	opad = ipad + SHA512_BLOCK_SIZE;

	shash->tfm = ctx->shash;

	if (keys.authkeylen > bs) {
		err = crypto_shash_digest(shash, keys.authkey,
					keys.authkeylen, ipad);
		if (err)
			goto badkey;

		keys.authkeylen = ds;
	} else
		memcpy(ipad, keys.authkey, keys.authkeylen);

	memset(ipad + keys.authkeylen, 0, bs - keys.authkeylen);
	memcpy(opad, ipad, bs);

	for (i = 0; i < bs; i++) {
		ipad[i] ^= HMAC_IPAD_VALUE;
		opad[i] ^= HMAC_OPAD_VALUE;
	}

	err = crypto_shash_init(shash) ?:
				 crypto_shash_update(shash, ipad, bs) ?:
				 crypto_shash_export(shash, ipad) ?:
				 crypto_shash_init(shash) ?:
				 crypto_shash_update(shash, opad, bs) ?:
				 crypto_shash_export(shash, opad);

	if (err)
		goto badkey;

	/* Encryption key */
	mtk_ctx_saRecord(ctx, keys.enckey, nonce, keys.enckeylen, flags);
	/* add auth key */
	memcpy(&ctx->sa->saIDigest, ipad, SHA256_DIGEST_SIZE);
	memcpy(&ctx->sa->saODigest, opad, SHA256_DIGEST_SIZE);

	kfree(ipad);
	return err;

badkey:
	kfree(ipad);
	crypto_aead_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static int mtk_aead_setauthsize(struct crypto_aead *ctfm,
				unsigned int authsize)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	/* might be needed for IPSec SHA1 (3 Words vs 5 Words)
	u32 maxauth = crypto_aead_maxauthsize(ctfm);
	*/

	ctx->authsize = authsize;

	return 0;
}

static int mtk_aead_crypt(struct aead_request *req)
{
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct mtk_device *mtk = ctx->mtk;
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	u32 ivsize = crypto_aead_ivsize(aead);
	int ret;
	int DescriptorCountDone = MTK_RING_SIZE - 1;
	int DescriptorDoneTimeout = 3;
	int DescriptorPendingCount = 0;

	rctx->textsize = req->cryptlen;
	rctx->assoclen = req->assoclen;
	rctx->authsize = ctx->authsize;
	rctx->iv_dma = false;
	rctx->ivsize = ivsize;

	if IS_DECRYPT(rctx->flags)
		rctx->textsize -= rctx->authsize;

	if (!rctx->textsize)
		return 0;

	if (mtk->ring->requests > MTK_RING_BUSY)
		return -EAGAIN;

	ret = mtk_send_req(base, ctx, req->src, req->dst, req->iv,
				rctx);

	if (ret < 0) {
		base->complete(base, ret);
		return ret;
	}

	if (ret == 0)
		return 0;

	spin_lock_bh(&mtk->ring->lock);
	mtk->ring->requests += ret;

	if (!mtk->ring->busy) {
		DescriptorPendingCount = min_t(int, mtk->ring->requests, 32);
		writel(BIT(31) | (DescriptorCountDone & GENMASK(10, 0)) |
			(((DescriptorPendingCount - 1) & GENMASK(10, 0)) << 16) |
			((DescriptorDoneTimeout  & GENMASK(4, 0)) << 26),
			mtk->base + EIP93_REG_PE_RING_THRESH);
		mtk->ring->busy = true;
	}
	spin_unlock_bh(&mtk->ring->lock);

	/* Writing new descriptor count starts DMA action */
	writel(ret, mtk->base + EIP93_REG_PE_CD_COUNT);

	if (mtk->ring->requests > MTK_RING_BUSY) {
		rctx->flags |= MTK_BUSY;
		return -EBUSY;
	}

	return -EINPROGRESS;
}

static int mtk_aead_encrypt(struct aead_request *req)
{
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.aead.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_ENCRYPT;

	return mtk_aead_crypt(req);
}

static int mtk_aead_decrypt(struct aead_request *req)
{
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.aead.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_DECRYPT;

	return mtk_aead_crypt(req);
}

/* Available authenc algorithms in this module */
struct mtk_alg_template mtk_alg_authenc_hmac_md5_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_MD5 | MTK_MODE_CBC | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = MD5_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(md5),cbc(aes))",
			.cra_driver_name =
				"authenc(hmac(md5-eip93), cbc(aes-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha1_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1 | MTK_MODE_CBC | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(aes))",
			.cra_driver_name =
				"authenc(hmac(sha1-eip93),cbc(aes-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha224_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA224 | MTK_MODE_CBC | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),cbc(aes))",
			.cra_driver_name =
				"authenc(hmac(sha224-eip93),cbc(aes-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha256_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256 | MTK_MODE_CBC | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),cbc(aes))",
			.cra_driver_name =
				"authenc(hmac(sha256-eip93),cbc(aes-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_md5_rfc3686_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_MD5 |
			MTK_MODE_CTR | MTK_MODE_RFC3686 | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= CTR_RFC3686_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = MD5_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(md5),rfc3686(ctr(aes)))",
			.cra_driver_name =
			"authenc(hmac(md5-eip93),rfc3686(ctr(aes-eip93)))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha1_rfc3686_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1 |
			MTK_MODE_CTR | MTK_MODE_RFC3686 | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= CTR_RFC3686_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),rfc3686(ctr(aes)))",
			.cra_driver_name =
			"authenc(hmac(sha1-eip93),rfc3686(ctr(aes-eip93)))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha224_rfc3686_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA224 |
			MTK_MODE_CTR | MTK_MODE_RFC3686 | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= CTR_RFC3686_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),rfc3686(ctr(aes)))",
			.cra_driver_name =
			"authenc(hmac(sha224-eip93),rfc3686(ctr(aes-eip93)))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha256_rfc3686_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256 |
			MTK_MODE_CTR | MTK_MODE_RFC3686 | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= CTR_RFC3686_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),rfc3686(ctr(aes)))",
			.cra_driver_name =
			"authenc(hmac(sha256-eip93),rfc3686(ctr(aes-eip93)))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

#ifdef CONFIG_EIP93_PRNG
struct mtk_alg_template mtk_alg_echainiv_authenc_hmac_sha1_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1 | MTK_MODE_CBC |
			MTK_ALG_AES | MTK_GENIV,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "echainiv(authenc(hmac(sha1),cbc(aes)))",
			.cra_driver_name = "echainiv(authenc(hmac(sha1-eip93)"
					",cbc(aes-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_echainiv_authenc_hmac_sha256_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256 | MTK_MODE_CBC |
			MTK_ALG_AES | MTK_GENIV,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "echainiv(authenc(hmac(sha256),cbc(aes)))",
			.cra_driver_name = "echainiv(authenc(hmac(sha256-eip93)"
				",cbc(aes-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_seqiv_authenc_hmac_sha1_rfc3686_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1 | MTK_ALG_AES |
			MTK_MODE_CTR | MTK_MODE_RFC3686 | MTK_GENIV,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= CTR_RFC3686_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "seqiv(authenc(hmac(sha1),rfc3686(ctr(aes))))",
			.cra_driver_name = "seqiv(authenc(hmac(sha1-eip93),"
				"rfc3686(ctr(aes-eip93)))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_seqiv_authenc_hmac_sha256_rfc3686_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256 | MTK_ALG_AES |
			MTK_MODE_CTR | MTK_MODE_RFC3686 | MTK_GENIV,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= CTR_RFC3686_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "seqiv(authenc(hmac(sha256),rfc3686(ctr(aes))))",
			.cra_driver_name = "seqiv(authenc(hmac(sha256-eip93),"
				"rfc3686(ctr(aes-eip93)))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
#endif

#ifdef CONFIG_EIP93_DES
struct mtk_alg_template mtk_alg_authenc_hmac_md5_cbc_des = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_MD5 | MTK_MODE_CBC | MTK_ALG_DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = MD5_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(md5),cbc(des))",
			.cra_driver_name =
				"authenc(hmac(md5-eip93),cbc(des-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha1_cbc_des = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1 | MTK_MODE_CBC | MTK_ALG_DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(des))",
			.cra_driver_name =
				"authenc(hmac(sha1-eip93),cbc(des-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha224_cbc_des = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA224 | MTK_MODE_CBC | MTK_ALG_DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),cbc(des))",
			.cra_driver_name =
				"authenc(hmac(sha224-eip93),cbc(des-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha256_cbc_des = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256 | MTK_MODE_CBC | MTK_ALG_DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),cbc(des))",
			.cra_driver_name =
				"authenc(hmac(sha256-eip93),cbc(des-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_md5_cbc_des3_ede = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_MD5 | MTK_MODE_CBC | MTK_ALG_3DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES3_EDE_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = MD5_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(md5),cbc(des3_ede))",
			.cra_driver_name =
				"authenc(hmac(md5-eip93),cbc(des3_ede-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha1_cbc_des3_ede = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1 | MTK_MODE_CBC | MTK_ALG_3DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES3_EDE_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(des3_ede))",
			.cra_driver_name =
				"authenc(hmac(sha1-eip93),cbc(des3_ede-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha224_cbc_des3_ede = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA224 | MTK_MODE_CBC | MTK_ALG_3DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES3_EDE_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),cbc(des3_ede))",
			.cra_driver_name =
			"authenc(hmac(sha224-eip93),cbc(des3_ede-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha256_cbc_des3_ede = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256 | MTK_MODE_CBC | MTK_ALG_3DES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES3_EDE_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),cbc(des3_ede))",
			.cra_driver_name =
			"authenc(hmac(sha256-eip93),cbc(des3_ede-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
/* Single pass IPSEC ESP descriptor */
struct mtk_alg_template mtk_alg_authenc_hmac_md5_ecb_null = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_MD5,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= NULL_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = MD5_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(md5),ecb(cipher_null))",
			.cra_driver_name = "authenc(hmac(md5-eip93),"
						"ecb(cipher_null)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = NULL_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha1_ecb_null = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= NULL_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),ecb(cipher_null))",
			.cra_driver_name = "authenc(hmac(sha1-eip93),"
						"ecb(cipher_null)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = NULL_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha224_ecb_null = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA224,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= NULL_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),ecb(cipher_null))",
			.cra_driver_name = "authenc(hmac(sha224-eip93),"
						"ecb(cipher_null)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = NULL_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha256_ecb_null = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= NULL_IV_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),ecb(cipher_null))",
			.cra_driver_name = "authenc(hmac(sha256-eip93),"
						"ecb(cipher_null)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = NULL_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0x0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
#ifdef CONFIG_EIP93_PRNG
struct mtk_alg_template mtk_alg_echainiv_authenc_hmac_md5_cbc_des = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_MD5 | MTK_MODE_CBC |
			MTK_ALG_DES | MTK_GENIV,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= DES_BLOCK_SIZE,
		.setauthsize = mtk_aead_setauthsize,
		.maxauthsize = MD5_DIGEST_SIZE,
		.base = {
			.cra_name = "echainiv(authenc(hmac(md5),cbc(des)))",
			.cra_driver_name = "echainiv(authenc(hmac(md5-eip93)"
					",cbc(des-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
#endif
#endif
