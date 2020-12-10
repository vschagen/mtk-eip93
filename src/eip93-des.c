/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#define DEBUG 1
#include <crypto/internal/des.h>

#include "eip93-common.h"
#include "eip93-main.h"
#include "eip93-cipher.h"
#include "eip93-regs.h"

/* Crypto skcipher API functions */
static int mtk_des_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	memset(ctx, 0, sizeof(*ctx));

	ctx->fallback = NULL;

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
			offsetof(struct mtk_cipher_reqctx, fallback_req));

	ctx->mtk = tmpl->mtk;
	ctx->aead = false;
	ctx->sa = kzalloc(sizeof(struct saRecord_s), GFP_KERNEL);
	if (!ctx->sa)
		printk("!! no sa memory\n");

	return 0;
}

static void mtk_des_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	kfree(ctx->sa);
}

static int mtk_des_setkey(struct crypto_skcipher *ctfm, const u8 *key,
				 unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);
	unsigned long flags = tmpl->flags;
	unsigned int keylen = len;
	u32 nonce = 0;
	int ret = 0;

	if (!key || !keylen)
		return -EINVAL;

	switch ((flags & MTK_ALG_MASK)) {
	case MTK_ALG_DES:
		ret = verify_skcipher_des_key(ctfm, key);
		break;
	case MTK_ALG_3DES:
		if (keylen != DES3_EDE_KEY_SIZE) {
			ret = -EINVAL;
			break;
		}
		ret = verify_skcipher_des3_key(ctfm, key);
	}

	if (ret) {
		crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return ret;
	}

	mtk_ctx_saRecord(ctx, key, nonce, keylen, flags);

	return ret;
}

static int mtk_des_crypt(struct skcipher_request *req)
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

static int mtk_des_encrypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_ENCRYPT;

	return mtk_des_crypt(req);
}

static int mtk_des_decrypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_DECRYPT;

	return mtk_des_crypt(req);
}


/* Available algorithms in this module */

struct mtk_alg_template mtk_alg_ecb_des = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(des)",
			.cra_driver_name = "ebc(des-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_cbc_des = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize	= DES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des)",
			.cra_driver_name = "cbc(des-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_ecb_des3_ede = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_3DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(des3_ede)",
			.cra_driver_name = "ecb(des3_ede-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_cbc_des3_ede = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_3DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize	= DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "cbc(des3_ede-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
