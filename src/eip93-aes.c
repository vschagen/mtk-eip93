/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#define DEBUG 1
#include <crypto/aes.h>
#include <crypto/ctr.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#include "eip93-aes.h"
#include "eip93-common.h"
#include "eip93-main.h"
#include "eip93-cipher.h"
#ifdef CONFIG_EIP93_DES
#include "eip93-des.h"
#endif
#include "eip93-regs.h"
#include "eip93-ring.h"

static unsigned int aes_sw = NUM_AES_BYPASS;
module_param(aes_sw, uint, 0644);
MODULE_PARM_DESC(aes_sw,
		 "Only use hardware for AES requests larger than this "
		 "[0=always use hardware; default="
		 __stringify(NUM_AES_BYPASS)"]");



/* Crypto skcipher API functions */
static int mtk_skcipher_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	memset(ctx, 0, sizeof(*ctx));

	ctx->fallback = NULL;

	if (IS_AES(tmpl->flags)) {
		ctx->fallback = crypto_alloc_skcipher(crypto_tfm_alg_name(tfm),
				0, CRYPTO_ALG_NEED_FALLBACK);
		if (IS_ERR(ctx->fallback))
			ctx->fallback = NULL;
	}

	if (IS_AES(tmpl->flags) && (ctx->fallback))
		crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
					sizeof(struct mtk_cipher_reqctx) +
					crypto_skcipher_reqsize(ctx->fallback));
	else
		crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
			offsetof(struct mtk_cipher_reqctx, fallback_req));

	ctx->mtk = tmpl->mtk;
	ctx->aead = false;
	ctx->sa = kzalloc(sizeof(struct saRecord_s), GFP_KERNEL);
	if (!ctx->sa)
		printk("!! no sa memory\n");

	return 0;
}

static void mtk_skcipher_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	kfree(ctx->sa);

	if (ctx->fallback)
		crypto_free_skcipher(ctx->fallback);
}

static int mtk_skcipher_setkey(struct crypto_skcipher *ctfm, const u8 *key,
				 unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);
	unsigned long flags = tmpl->flags;
	struct crypto_aes_ctx aes;
	unsigned int keylen = len;
	u32 nonce = 0;
	int err = 0;

	if (IS_RFC3686(flags)) {
		if (len < CTR_RFC3686_NONCE_SIZE)
			return -EINVAL;

		keylen = len - CTR_RFC3686_NONCE_SIZE;
		memcpy(&nonce, key + keylen, CTR_RFC3686_NONCE_SIZE);
	}

	err = aes_expandkey(&aes, key, keylen);
	if (err) {
		crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return err;
	}

	mtk_set_saRecord(ctx->sa, key, nonce, keylen, flags);

	if (ctx->fallback)
		err = crypto_skcipher_setkey(ctx->fallback, key, len);

	return err;
}

static int mtk_skcipher_crypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct mtk_device *mtk = ctx->mtk;
	int ret;
	int DescriptorCountDone = MTK_RING_SIZE - 1;
	int DescriptorDoneTimeout = 3;
	int DescriptorPendingCount = 0;
	struct crypto_skcipher *skcipher = crypto_skcipher_reqtfm(req);
	u32 ivsize = crypto_skcipher_ivsize(skcipher);

	if (!req->cryptlen)
		return 0;

	if ((req->cryptlen <= aes_sw) && (ctx->fallback)) {
		skcipher_request_set_tfm(&rctx->fallback_req, ctx->fallback);
		skcipher_request_set_callback(&rctx->fallback_req,
					req->base.flags,
					req->base.complete,
					req->base.data);
		skcipher_request_set_crypt(&rctx->fallback_req, req->src,
					req->dst, req->cryptlen, req->iv);
		if (IS_ENCRYPT(rctx->flags))
			ret = crypto_skcipher_encrypt(&rctx->fallback_req);
		else
			ret = crypto_skcipher_decrypt(&rctx->fallback_req);

		return ret;
	}

	if (mtk->ring->requests > MTK_RING_BUSY)
		return -EAGAIN;

	rctx->textsize = req->cryptlen;
	rctx->authsize = 0;
	rctx->assoclen = 0;
	rctx->iv_dma = true;
	rctx->ivsize = ivsize;

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

static int mtk_skcipher_encrypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_ENCRYPT;

	return mtk_skcipher_crypt(req);
}

static int mtk_skcipher_decrypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_DECRYPT;

	return mtk_skcipher_crypt(req);
}

/* Available algorithms in this module */

struct mtk_alg_template mtk_alg_ecb_aes = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_AES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(aes)",
			.cra_driver_name = "ecb(aes-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_cbc_aes = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_AES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize	= AES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "cbc(aes-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_ctr_aes = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CTR | MTK_ALG_AES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize	= AES_BLOCK_SIZE,
		.base = {
			.cra_name = "ctr(aes)",
			.cra_driver_name = "ctr(aes-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_NEED_FALLBACK |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_rfc3686_aes = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CTR | MTK_MODE_RFC3686 | MTK_ALG_AES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.ivsize	= CTR_RFC3686_IV_SIZE,
		.base = {
			.cra_name = "rfc3686(ctr(aes))",
			.cra_driver_name = "rfc3686(ctr(aes-eip93))",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
