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
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>


#include "eip93-common.h"
#include "eip93-cipher.h"
#include "eip93-regs.h"

#define WORDSWAP(a)     	((((a)>>24)&0xff) | (((a)>>8)&0xff00) |	(((a)<<8)&0xff0000) | (((a)<<24)&0xff000000))

static LIST_HEAD(ablkcipher_algs);


static void mtk_free_sg_cpy(int nbytes, struct scatterlist **sg)
{
	int len;

	if (!*sg)
		return;

	len = ALIGN(nbytes, AES_BLOCK_SIZE);
	free_pages((unsigned long)sg_virt(*sg), get_order(len));

	kfree(*sg);
	*sg = NULL;
}

static void mtk_sg_copy_buf(void *buf, struct scatterlist *sg,
			    unsigned int nbytes, int out)
{
	struct scatter_walk walk;

	if (!nbytes)
		return;

	scatterwalk_start(&walk, sg);
	scatterwalk_copychunks(buf, &walk, nbytes, out);
	scatterwalk_done(&walk, out, 0);
}

static int mtk_make_sg_cpy(int nbytes, struct scatterlist *src,
			    struct scatterlist **dst)
{
	void *pages;
	int len;

	*dst = kmalloc(sizeof(**dst), GFP_ATOMIC);
	if (!*dst)
		return -ENOMEM;

	len = ALIGN(nbytes, AES_BLOCK_SIZE);
	pages = (void *)__get_free_pages(GFP_ATOMIC, get_order(len));
	if (!pages) {
		kfree(*dst);
		*dst = NULL;
		return -ENOMEM;
	}

	mtk_sg_copy_buf(pages, src, nbytes, 0);

	sg_init_table(*dst, 1);
	sg_set_buf(*dst, pages, len);

	return 0;
}

// get one request from finished queue
void mtk_cipher_req_done(struct mtk_device *mtk, int ctr)
{
	struct ablkcipher_request *req = NULL;
	struct mtk_cipher_reqctx *rctx = NULL;
	struct eip93DescpHandler_s *rd;
	struct mtk_dma_rec *rec;
	unsigned long flags;

	rd = &mtk->rd[ctr];
	rec = &mtk->rec[ctr];
	req = (struct ablkcipher_request *)rec->req;
	rctx = ablkcipher_request_ctx(req);

	if (rctx->sg_dst) {
		dev_dbg(mtk->dev,
			"Copying %d bytes of output data back to original place\n",
			req->nbytes);
		mtk_sg_copy_buf(sg_virt(rctx->sg_dst), req->dst,
				req->nbytes, 1);
		mtk_free_sg_cpy(req->nbytes, &rctx->sg_src);
		mtk_free_sg_cpy(req->nbytes, &rctx->sg_dst);
	}
		 
	rec->flags = 0;
	spin_lock_bh(&mtk->lock);
	req->base.complete(&req->base, 0);
	spin_unlock_bh(&mtk->lock);
}

int mtk_cipher_setkey(struct crypto_ablkcipher *ablk, const u8 *key,
				 unsigned int keylen)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(ablk);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned long flags = to_cipher_tmpl(tfm)->alg_flags;
	u32 tmp[DES_EXPKEY_WORDS];
	int ret, err;

	if (!key || !keylen)
		return -EINVAL;

	if (IS_AES(flags)) {
		switch (keylen) {
		case AES_KEYSIZE_128:
		case AES_KEYSIZE_192:
		case AES_KEYSIZE_256:
			break;
		default:
			goto fallback;
		}
	}

	if (IS_DES(flags)) {
		if (keylen != DES_KEY_SIZE)
			return -EINVAL;
	}

	if (IS_3DES(flags)) {
		if (keylen != DES3_EDE_KEY_SIZE)
			return -EINVAL;
	}
	ctx->keylen = keylen;
	memcpy(ctx->key, key, keylen);
	ctx->refresh = true;
	return 0;
fallback:
	ret = crypto_skcipher_setkey(ctx->fallback, key, keylen);
	if (!ret)
		ctx->keylen = keylen;
	return ret;
}

int mtk_scatter_combine(struct mtk_device *mtk, struct scatterlist *sgsrc,
		struct scatterlist *sgdst, int nbytes)
{
	struct mtk_dma_rec *rec;
	unsigned int remainin, remainout;
	int offsetin = 0;
	int offsetout = 0;
	unsigned int n, len;
	struct page *spage, *dpage;
	unsigned int soff, doff;
	unsigned int ssize, dsize;
	dma_addr_t saddr, daddr;
	bool nextin = false;
	bool nextout = false;
	int ctr;
	int count = 0;

	n = nbytes;
	spage = sg_page(sgsrc);
	soff = sgsrc->offset;
	remainin = min(sgsrc->length, n);
	ssize = remainin;
	saddr = dma_map_page(mtk->dev, spage, soff, remainin,
			DMA_BIDIRECTIONAL);


	dpage = sg_page(sgdst);
	doff = sgdst->offset;
	remainout = min(sgdst->length, n);
	dsize = remainout;
	daddr = dma_map_page(mtk->dev, dpage, doff, remainout,
			DMA_BIDIRECTIONAL);

	ctr = mtk->rec_rear_idx;

	while (n) {
		if (nextin) {
			sgsrc++;
			spage = sg_page(sgsrc);
			soff = sgsrc->offset;
			remainin = min(sgsrc->length, n);
			if (remainin == 0)
				continue;
			saddr = dma_map_page(mtk->dev, spage, soff, remainin,
				DMA_BIDIRECTIONAL);
			ssize = remainin;
			offsetin = 0;
			nextin = false;
		}

		if (nextout) {
			sgdst++;
			dpage = sg_page(sgdst);
			doff = sgdst->offset;
			remainout = min(sgdst->length, n);
			if (remainout == 0)
				continue;
			daddr = dma_map_page(mtk->dev, dpage, doff, remainout,
				DMA_BIDIRECTIONAL);
			dsize = remainout;
			offsetout = 0;
			nextout = false;
		}
		rec = &mtk->rec[ctr];
		rec->srcDma = (saddr + offsetin);
		rec->dstDma = (daddr + offsetout);
		rec->saddr = saddr;
		rec->daddr = daddr;
		rec->ssize = ssize;
		rec->dsize = dsize;
		if (remainin == remainout) {
			len = remainin;
			nextin = true;
			nextout = true;
		} else if (remainin < remainout) {
			len = remainin;
			offsetout += len;
			remainout -= len;
			nextin = true;
		} else {
			len = remainout;
			offsetin += len;
			remainin -= len;
			nextout = true;
		}
		n -= len;
		rec->dmaLen = len;
		count++;
		ctr = (ctr + 1) % MTK_RING_SIZE;
		dev_dbg(mtk->dev, "[%d]Src:%08x,Dst:%08x Len:%d\n", 
			ctr, rec->srcDma, rec->dstDma, rec->dmaLen);
	}
	return count;
}

void mtk_prepare_sa(struct mtk_device *mtk, struct mtk_cipher_ctx *ctx,
			unsigned long flags, int ctr)
{
	saRecord_t *saRecord;
	saState_t *saState;

	/* Part 1: prepare context */

	saRecord = &mtk->saRecord[ctr];
	memset(saRecord, 0x00, sizeof(saRecord_t));
	ctx->phy_sa = mtk->phy_record + (sizeof(saRecord_t) * ctr);

	saState = &mtk->saState[ctr];
	ctx->saState = (void *)saState;
	memset(saState, 0x00, sizeof(saState_t));
	ctx->phy_state = mtk->phy_state + (sizeof(saState_t) * ctr);

	/* Part 2: variable stuff */

	if IS_ENCRYPT(flags)
		saRecord->saCmd0.bits.direction = 0
	else
		saRecord->saCmd0.bits.direction = 1;
	if IS_ECB(flags)
		saRecord->saCmd1.bits.cipherMode = 0;
	if IS_CBC(flags)
		saRecord->saCmd1.bits.cipherMode = 1;
	if IS_CTR(flags)
		saRecord->saCmd1.bits.cipherMode = 2;
	if IS_DES(flags)
		saRecord->saCmd0.bits.cipher = 0;
	if IS_3DES(flags)
		saRecord->saCmd0.bits.cipher = 1;
	if IS_AES(flags) {
		saRecord->saCmd0.bits.cipher = 3;
		saRecord->saCmd1.bits.aesKeyLen = ctx->keylen >> 3;
	}

	memcpy(saRecord->saKey, ctx->key, ctx->keylen);

	/* Part 2: constant stuff */

	saRecord->saCmd0.bits.ivSource = 0x2;   	// 0x2;Load IV from SaRecord
	saRecord->saCmd0.bits.saveIv = 0x1;     	// 0x1;Save IV to SaRecord
	saRecord->saCmd0.bits.opGroup = 0x0;    	// basic operation
	saRecord->saCmd0.bits.opCode = 0x0;     	// protocol
	saRecord->saCmd0.bits.hash = 15;		// hashAlg 15 = NULL;
	saRecord->saCmd0.bits.hdrProc = 0x0;		// no header processing
	saRecord->saCmd0.bits.digestLength = 0x0;	// digestWord;
	saRecord->saCmd0.bits.padType = 3; 		// Zero padding
	saRecord->saCmd0.bits.extPad = 0;
	saRecord->saCmd0.bits.scPad = 0; 		// no padding
	saRecord->saCmd1.bits.hmac = 0; 		// enHmac no Hmac;
	saRecord->saCmd1.bits.seqNumCheck = 0;		// no Seq Num Check
	saRecord->saSpi = 0x0;				// WORDSWAP(spi); //esp spi
	saRecord->saSeqNumMask[0] = 0xFFFFFFFF;
	saRecord->saSeqNumMask[1] = 0x0;

	return;
}

int mtk_cipher_xmit(struct mtk_device *mtk, struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_cipher_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	struct eip93DescpHandler_s *cd;
	struct mtk_dma_rec *rec;
	struct scatterlist *src;
	struct scatterlist *dst;
	saState_t *saState;
	u32 ctr = 0, count, i;
	unsigned long flags = 0;
	int DescriptorCountDone = 0;
	int DescriptorPendingCount = 1;
	int DescriptorDoneTimeout = 10;

	if (!mtk)
		return -ENODEV;

	spin_lock_bh(&mtk->lock);

	ctr = mtk->rec_rear_idx;
	// refresh SA record
	if (unlikely(ctx->refresh = true)) {
		flags = rctx->flags;
		mtk_prepare_sa(mtk, ctx, flags, ctr);
		ctx->refresh = false;
	}
	saState = (saState_t *)ctx->saState;

	// update IV per request
	if (IS_CBC(rctx->flags) || IS_CTR(rctx->flags)) {
		if (!req->info)
			memset(saState->stateIv, 0xFF, 16);
		else
			memcpy(saState->stateIv, req->info, 16);
	}

	// Create combined scatterlist records
	if (rctx->sg_src == NULL) {
		src = req->src;
	} else {
		src = rctx->sg_src;
	}
	if (rctx->sg_dst == NULL) {
		dst = req->dst;
	} else {
		dst = rctx->sg_dst;
	}
	count = mtk_scatter_combine(mtk, src, dst, req->nbytes);
	// Create #count Cmd Descriptors
	for (i = 0; i < count; i++) {
		cd = &mtk->cd[ctr];
		memset(cd, 0x00, 32); // clear CDR??
		rec = &mtk->rec[ctr];
		rec->req = (void *)req;
		rec->flags = BIT(1); // (TODO indicate simple "crypto"
		cd->peCrtlStat.bits.hostReady = 1;
		cd->peCrtlStat.bits.hashFinal = 0;
		cd->peCrtlStat.bits.padCrtlStat = 0; //padCrtlStat; pad boundary
		cd->peCrtlStat.bits.peReady = 0;

		cd->srcAddr = rec->srcDma;
		cd->dstAddr = rec->dstDma;
		cd->saAddr = ctx->phy_sa;
		cd->stateAddr = ctx->phy_state;
		cd->arc4Addr = ctx->phy_state;
		cd->peLength.bits.length = (rec->dmaLen) & GENMASK(20, 0);
		cd->peLength.bits.hostReady = 1;
		ctr = (ctr + 1) % MTK_RING_SIZE;
	}
	rec->flags |= BIT(0); // Indicate last
	mtk->rec_rear_idx = ctr;

	/* Update RDR count to reduce IRQs */
	mtk->count = mtk->count + count;
	DescriptorPendingCount = min(mtk->count, 64) - 1;
	writel((DescriptorCountDone & GENMASK(10, 0)) |
		((DescriptorPendingCount & GENMASK(10, 0)) << 16) |
		((DescriptorDoneTimeout  & GENMASK(6, 0)) << 26) |
		BIT(31), mtk->base + EIP93_REG_PE_RING_THRESH);

	spin_unlock_bh(&mtk->lock);
	/*
	 * Make sure all data is updated before starting engine.
	 */
	wmb();
	/* Writing new descriptor count starts DMA action */
	writel(count, mtk->base + EIP93_REG_PE_CD_COUNT);

	return 0;
}

static bool mtk_is_sg_aligned(struct scatterlist *sg)
{
	while (sg) {
		if (!IS_ALIGNED(sg->length, AES_BLOCK_SIZE))
			return false;
		sg = sg_next(sg);
	}

	return true;
}

int mtk_handle_request(struct mtk_device *mtk, struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	int ret = 0;

	ret = mtk_is_sg_aligned(req->dst);
	if (!ret) {
		rctx->sg_dst = req->dst;
		mtk_make_sg_cpy(req->nbytes, rctx->sg_dst,
			&rctx->sg_dst);
	} else {
		rctx->sg_dst = NULL;
	}

	ret = mtk_is_sg_aligned(req->src);
	if (!ret) {
		rctx->sg_src = req->src;
		mtk_make_sg_cpy(req->nbytes, rctx->sg_src,
			&rctx->sg_src);
	} else {
		rctx->sg_src = NULL;
	}

	ret = mtk_cipher_xmit(mtk, req);

	return ret;
}

int mtk_handle_queue(struct mtk_device *mtk, struct ablkcipher_request *req)
{
	int ret = 0, err;

	spin_lock_bh(&mtk->lock);

	if (mtk->count > MTK_QUEUE_LENGTH) {
		spin_unlock_bh(&mtk->lock);
		return -EBUSY;
	}
	ret = -EINPROGRESS;

	spin_unlock_bh(&mtk->lock);

	if (!req)
		return 0;

	err = mtk_handle_request(mtk, req);

	if (err)
		dev_err(mtk->dev, "Error: %d\n", err);

	return ret;
}

int mtk_cipher_crypt(struct ablkcipher_request *req, int encrypt)
{
	struct crypto_tfm *tfm =
			crypto_ablkcipher_tfm(crypto_ablkcipher_reqtfm(req));
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_alg_template *tmpl = to_cipher_tmpl(tfm);
	int ret;

	rctx->flags = tmpl->alg_flags;
	rctx->flags |= encrypt ? MTK_ENCRYPT : MTK_DECRYPT;

/*
	if (IS_AES(rctx->flags) &&
		ctx->keylen != AES_KEYSIZE_128 &&
		ctx->keylen != AES_KEYSIZE_192 &&
		ctx->keylen != AES_KEYSIZE_256) {

		SKCIPHER_REQUEST_ON_STACK(subreq, ctx->fallback);

		skcipher_request_set_tfm(subreq, ctx->fallback);
		skcipher_request_set_callback(subreq, req->base.flags,
					      NULL, NULL);
		skcipher_request_set_crypt(subreq, req->src, req->dst,
					   req->nbytes, req->info);
		if (IS_ENCRYPT(rctx->flags)) 
			ret = crypto_skcipher_encrypt(subreq);
		else
			ret = crypto_skcipher_decrypt(subreq);
		skcipher_request_zero(subreq);
		return ret;
	}
*/
	return mtk_handle_queue(tmpl->mtk, req);
}

int mtk_cipher_encrypt(struct ablkcipher_request *req)
{
	return mtk_cipher_crypt(req, 1);
}

int mtk_cipher_decrypt(struct ablkcipher_request *req)
{
	return mtk_cipher_crypt(req, 0);
}

int mtk_cipher_init(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	ctx->refresh = true;
	tfm->crt_ablkcipher.reqsize = sizeof(struct mtk_cipher_reqctx);

	ctx->fallback = crypto_alloc_skcipher(crypto_tfm_alg_name(tfm), 0,
					      CRYPTO_ALG_ASYNC |
					      CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);

	return 0;
}

void mtk_cipher_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_free_skcipher(ctx->fallback);
}

static int
mtk_ablkcipher_async_req_handle(struct crypto_async_request *async_req)
{
	return 0;
}

struct mtk_ablkcipher_def {
	unsigned long flags;
	const char *name;
	const char *drv_name;
	unsigned int blocksize;
	unsigned int ivsize;
	unsigned int min_keysize;
	unsigned int max_keysize;
};

static const struct mtk_ablkcipher_def ablkcipher_def[] = {
	{
		.flags		= MTK_ALG_AES | MTK_MODE_ECB,
		.name		= "ecb(aes)",
		.drv_name	= "eip93-ecb-aes",
		.blocksize	= AES_BLOCK_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_AES | MTK_MODE_CBC,
		.name		= "cbc(aes)",
		.drv_name	= "eip93-cbc-aes",
		.blocksize	= AES_BLOCK_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_AES | MTK_MODE_CTR,
		.name		= "ctr(aes)",
		.drv_name	= "eip93-ctr-aes",
		.blocksize	= AES_BLOCK_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_DES | MTK_MODE_ECB,
		.name		= "ecb(des)",
		.drv_name	= "eip93-ecb-des",
		.blocksize	= DES_BLOCK_SIZE,
		.ivsize		= 0,
		.min_keysize	= DES_KEY_SIZE,
		.max_keysize	= DES_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_DES | MTK_MODE_CBC,
		.name		= "cbc(des)",
		.drv_name	= "eip93-cbc-des",
		.blocksize	= DES_BLOCK_SIZE,
		.ivsize		= DES_BLOCK_SIZE,
		.min_keysize	= DES_KEY_SIZE,
		.max_keysize	= DES_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_3DES | MTK_MODE_ECB,
		.name		= "ecb(des3_ede)",
		.drv_name	= "eip93-ecb-3des",
		.blocksize	= DES3_EDE_BLOCK_SIZE,
		.ivsize		= 0,
		.min_keysize	= DES3_EDE_KEY_SIZE,
		.max_keysize	= DES3_EDE_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_3DES | MTK_MODE_CBC,
		.name		= "cbc(des3_ede)",
		.drv_name	= "eip93-cbc-3des",
		.blocksize	= DES3_EDE_BLOCK_SIZE,
		.ivsize		= DES3_EDE_BLOCK_SIZE,
		.min_keysize	= DES3_EDE_KEY_SIZE,
		.max_keysize	= DES3_EDE_KEY_SIZE,
	},
};
static int mtk_ablkcipher_register_one(const struct mtk_ablkcipher_def *def,
				       struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl;
	struct crypto_alg *alg;
	int ret;

	tmpl = kzalloc(sizeof(*tmpl), GFP_KERNEL);
	if (!tmpl)
		return -ENOMEM;

	alg = &tmpl->alg.crypto;

	snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s", def->name);
	snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 def->drv_name);

	alg->cra_blocksize = def->blocksize;
	alg->cra_ablkcipher.ivsize = def->ivsize;
	alg->cra_ablkcipher.min_keysize = def->min_keysize;
	alg->cra_ablkcipher.max_keysize = def->max_keysize;
	alg->cra_ablkcipher.setkey = mtk_cipher_setkey;
	alg->cra_ablkcipher.encrypt = mtk_cipher_encrypt;
	alg->cra_ablkcipher.decrypt = mtk_cipher_decrypt;

	alg->cra_priority = 300;
	alg->cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC |
			 CRYPTO_ALG_NEED_FALLBACK;
	alg->cra_ctxsize = sizeof(struct mtk_cipher_ctx);
	alg->cra_alignmask = 0xF;
	alg->cra_type = &crypto_ablkcipher_type;
	alg->cra_module = THIS_MODULE;
	alg->cra_init = mtk_cipher_init;
	alg->cra_exit = mtk_cipher_exit;
	INIT_LIST_HEAD(&alg->cra_list);

	INIT_LIST_HEAD(&tmpl->entry);
	tmpl->crypto_alg_type = CRYPTO_ALG_TYPE_ABLKCIPHER;
	tmpl->alg_flags = def->flags;
	tmpl->mtk = mtk;

	ret = crypto_register_alg(alg);
	if (ret) {
		kfree(tmpl);
		dev_err(mtk->dev, "%s registration failed\n", alg->cra_name);
		return ret;
	}

	list_add_tail(&tmpl->entry, &ablkcipher_algs);
	dev_info(mtk->dev, "%s is registered\n", alg->cra_name);
	return 0;
}

static void mtk_ablkcipher_unregister(struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl, *n;

	list_for_each_entry_safe(tmpl, n, &ablkcipher_algs, entry) {
		crypto_unregister_alg(&tmpl->alg.crypto);
		list_del(&tmpl->entry);
		kfree(tmpl);
	}
}

static int mtk_ablkcipher_register(struct mtk_device *mtk)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(ablkcipher_def); i++) {
		ret = mtk_ablkcipher_register_one(&ablkcipher_def[i], mtk);
		if (ret)
			goto err;
	}

	return 0;
err:
	mtk_ablkcipher_unregister(mtk);
	return ret;
}

const struct mtk_algo_ops ablkcipher_ops = {
	.type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	.register_algs = mtk_ablkcipher_register,
	.unregister_algs = mtk_ablkcipher_unregister,
	.async_req_handle = mtk_ablkcipher_async_req_handle,
};

