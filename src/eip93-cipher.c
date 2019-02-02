// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>

#include "eip93-common.h"
#include "eip93-core.h"
#include "eip93-cipher.h"
#include "eip93-regs.h"
#include "eip93-ring.h"

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

static inline int mtk_aes_padlen(int len)
{
	len &= AES_BLOCK_SIZE - 1;
	return len ? AES_BLOCK_SIZE - len : 0;
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

static int mtk_make_sg_cpy(struct scatterlist *src, struct scatterlist **dst,
			int nbytes)
{
	void *pages;

	*dst = kmalloc(sizeof(**dst), GFP_ATOMIC);
	if (!*dst)
		return -ENOMEM;

	pages = (void *)__get_free_pages(GFP_ATOMIC, get_order(nbytes));
	if (!pages) {
		kfree(*dst);
		*dst = NULL;
		return -ENOMEM;
	}

	mtk_sg_copy_buf(pages, src, nbytes, 0);

	sg_init_table(*dst, 1);
	sg_set_buf(*dst, pages, nbytes);

	return 0;
}

static bool mtk_is_sg_aligned(struct scatterlist *sg, int len, int blocksize)
{
	int nents;

	if (!IS_ALIGNED(len, blocksize))
		return false;

	for (nents = 0; sg; sg = sg_next(sg), ++nents) {
		if (!IS_ALIGNED(sg->offset, sizeof(u32)))
			return false;

		if (len <= sg->length) {
			if (!IS_ALIGNED(len, blocksize))
				return false;

			sg->length = len;
			return true;
		}

		if (!IS_ALIGNED(sg->length, blocksize))
			return false;

		len -= sg->length;
	}

	return false;
}

int mtk_cipher_setkey(struct crypto_ablkcipher *ablk, const u8 *key,
				 unsigned int keylen)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(ablk);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned long flags = to_cipher_tmpl(tfm)->alg_flags;
	//u32 tmp[DES_EXPKEY_WORDS];
	int ret;

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

	return 0;
fallback:
	ret = crypto_skcipher_setkey(ctx->fallback, key, keylen);
	if (!ret)
		ctx->keylen = keylen;
	return ret;
}

static dma_addr_t mtk_set_saRecord(struct mtk_device *mtk, struct mtk_cipher_ctx *ctx,
			unsigned long flags)
{
	dma_addr_t ptr;
	int wptr;
	struct saRecord_s *saRecord;

	wptr = mtk_ring_curr_wptr_index(mtk);

	/* prepare SA */
	saRecord = &mtk->saRecord[wptr];
	ptr = mtk->saRecord_base + wptr * sizeof(saRecord_t);

	memset(saRecord, 0x00, sizeof(saRecord_t));

	if IS_ENCRYPT(flags) {
		saRecord->saCmd0.bits.direction = 0x0; //outbound
	} else {
		saRecord->saCmd0.bits.direction = 0x1; //inbound
	}
	saRecord->saCmd0.bits.ivSource = 0x2;//0x2;Load IV from saState

	saRecord->saCmd0.bits.saveIv = 0x1;//0x1;Save IV to saState

	saRecord->saCmd0.bits.opGroup = 0x0; // basic operation
	saRecord->saCmd0.bits.opCode = 0x0; // protocol

	if IS_DES(flags)
		saRecord->saCmd0.bits.cipher = 0x0;

	if IS_3DES(flags)
		saRecord->saCmd0.bits.cipher = 0x1;

	if IS_AES(flags)
		saRecord->saCmd0.bits.cipher = 0x3;

	if IS_HASH(flags)
		saRecord->saCmd0.bits.saveHash = 1;

	saRecord->saCmd0.bits.hash = 15; // hash = NULL

	if IS_HASH_MD5(flags)
		saRecord->saCmd0.bits.hash = 0;

	if IS_HASH_SHA1(flags)
		saRecord->saCmd0.bits.hash = 1;

	if IS_HASH_SHA224(flags)
		saRecord->saCmd0.bits.hash = 2;

	if IS_HASH_SHA256(flags)
		saRecord->saCmd0.bits.hash = 3;

	saRecord->saCmd0.bits.hdrProc = 0x0; // no header processing

	saRecord->saCmd0.bits.digestLength = 0x0; // digestWord;
	saRecord->saCmd0.bits.padType = 3; // Zero padding
	saRecord->saCmd0.bits.extPad = 0;
	saRecord->saCmd0.bits.scPad = 0; //no padding

	if IS_ECB(flags)
		saRecord->saCmd1.bits.cipherMode = 0;

	if IS_CBC(flags)
		saRecord->saCmd1.bits.cipherMode = 1;

	if IS_CTR(flags)
		saRecord->saCmd1.bits.cipherMode = 2;

	if IS_HMAC(flags)
		saRecord->saCmd1.bits.hmac = 1;

	if IS_AES(flags) {
		if (ctx->keylen == AES_KEYSIZE_256)
			saRecord->saCmd1.bits.aesKeyLen = 4;
		else if (ctx->keylen == AES_KEYSIZE_192)
			saRecord->saCmd1.bits.aesKeyLen = 3;
		else
			saRecord->saCmd1.bits.aesKeyLen = 2;
	}

	saRecord->saCmd1.bits.seqNumCheck = 0; // no Seq Num Check

	memcpy(saRecord->saKey, ctx->key, ctx->keylen);

	saRecord->saSpi = 0x0; //WORDSWAP(spi); //esp spi

	saRecord->saSeqNumMask[0] = 0xFFFFFFFF;
	saRecord->saSeqNumMask[1] = 0x0;

	return ptr;
}

int mtk_scatter_combine(struct mtk_device *mtk, dma_addr_t saRecord_base,
			dma_addr_t saState_base, struct scatterlist *sgsrc,
			struct scatterlist *sgdst, int nbytes, bool complete,
			unsigned int *areq, int *commands, int *results)
{
	struct mtk_dma_rec *rec;
	struct saRecord_s *saRecord;
	unsigned int remainin, remainout;
	unsigned int lenin, lenout;
	unsigned int pgsize = PAGE_SIZE;
	int offsetin = 0, pgin = 0;
	int offsetout = 0, pgout = 0;
	unsigned int n, len;
	dma_addr_t saddr, daddr;
	bool nextin = false;
	bool nextout = false;
	bool first = true;
	struct eip93_descriptor_s *cdesc;
	struct eip93_descriptor_s *rdesc;
	int wptr, nptr, ndesc_cdr = 0, ndesc_rdr = 0;

	n = nbytes;
	remainin = min(sgsrc->length, n);
	lenin = min(remainin, pgsize);
	if (remainin > lenin)
		pgin++;
		
	remainout = min(sgdst->length, n);
	lenout = min(remainout, pgsize);
	if (remainin > lenin)
		pgout++;

	saddr = dma_map_single(mtk->dev, sg_virt(sgsrc), remainin,
				 DMA_TO_DEVICE);
	daddr = dma_map_single(mtk->dev, sg_virt(sgdst), remainout,
				DMA_FROM_DEVICE);

	do {
		wptr = mtk_ring_curr_wptr_index(mtk);
		if (nextin) {
			sgsrc++;
			remainin = min(sgsrc->length, n);
			if (remainin == 0)
				continue;

			lenin = min(remainin, pgsize);
			if (remainin > lenin)
			pgin++;

			saddr = dma_map_single(mtk->dev, sg_virt(sgsrc), lenin,
					DMA_TO_DEVICE);
			offsetin = 0;
			nextin = false;
		}

		if (nextout) {
			sgdst++;
			remainout = min(sgdst->length, n);
			if (remainout == 0)
				continue;
			lenout = min(remainout, pgsize);
			if (remainin > lenin)
				pgout++;

			daddr = dma_map_single(mtk->dev, sg_virt(sgdst), lenout,
					DMA_FROM_DEVICE);
			offsetout = 0;
			nextout = false;
		}
		rec = &mtk->ring[0].cdr_dma[wptr];
		rec->srcDma = saddr + (offsetin % pgsize);
		rec->dstDma = daddr + (offsetout % pgsize);
		if (remainin == remainout) {
			len = remainin;
			if (len <= pgsize) {
				nextin = true;
				nextout = true;
			} else {
				len = pgsize;
				remainin -= pgsize;
				remainout -= pgsize;
				pgin++;
				pgout++;
			}			
		} else if (remainin < remainout) {
			len = remainin;
			if (len <= pgsize) {
				offsetout += len;
				remainout -= len;
				nextin = true;
				pgin = 0;
			} else {
				len = pgsize;
				remainin -= pgsize;
				remainout -= pgsize;
				pgin++;
				pgout++;
			}			
		} else {
			len = remainout;
			if (len <= pgsize) {
				offsetin += len;
				remainin -= len;
				nextout = true;
				pgout = 0;
			} else {
				len = pgsize;
				remainin -= pgsize;
				remainout -= pgsize;
				pgin++;
				pgout++;
			}
		}
		if (pgin > 0) {
			saddr = dma_map_single(mtk->dev, sg_virt(sgsrc) + (pgsize * pgin),
							len, DMA_TO_DEVICE);
		}

		if (pgout > 0) {
			daddr = dma_map_single(mtk->dev, sg_virt(sgdst) + (pgsize * pgout),
							len, DMA_TO_DEVICE);
		}

		rec->req = areq;
		rec->flags = BIT(1); // (TODO indicate simple "crypto"
		rec->dmaLen = min(len, pgsize);

		cdesc = mtk_add_cdesc(mtk, rec, saRecord_base, saState_base);
		rdesc = mtk_add_rdesc(mtk);

		ndesc_cdr++;
		ndesc_rdr++;
		n -= len;
		first = false;
		if (!first) {
			nptr = mtk_ring_curr_wptr_index(mtk);
			saRecord = &mtk->saRecord[nptr];
			memcpy(&mtk->saRecord[nptr], &mtk->saRecord[wptr] , sizeof(saRecord_t));
			saRecord_base = mtk->saRecord_base + nptr * sizeof(saRecord_t);
			saRecord->saCmd0.bits.ivSource = 0x0;//0x0 use previous result IV
		}

		dev_dbg(mtk->dev, "[%d]Src:%08x,Len:%d wptr:%d\n", 
			ndesc_cdr, rec->srcDma, rec->dmaLen, wptr);
	} while (n);

	if (complete == true)
		rec->flags |= BIT(0); // Indicate last

	*commands = ndesc_cdr;
	*results = ndesc_rdr;

	return 0;
}

int mtk_skcipher_send(struct crypto_async_request *async,
			int *commands, int *results)
{
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(async->tfm);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_device *mtk = ctx->mtk;
	int ndesc_cdr = 0, ndesc_rdr = 0, ctr_cdr = 0, ctr_rdr = 0;
	int offset = 0, wptr, err;
	u32 datalen;
	struct scatterlist *src, *src_ctr;
	struct scatterlist *dst, *dst_ctr; 
	struct saState_s *saState;
	dma_addr_t saState_base, saRecord_base;
	u32 start, end, ctr, blocks;
	unsigned long flags;
	bool complete;
	u32 iv[AES_BLOCK_SIZE / sizeof(u32) ];

	datalen = req->nbytes;
	complete = true;
	flags = rctx->flags;
	wptr = mtk_ring_curr_wptr_index(mtk);

	/* prepare saState */
	saState = &mtk->saState[wptr];
	saState_base = mtk->saState_base + wptr * sizeof(saState_t);
	memset(saState, 0x00, sizeof(saState_t));

	// refresh SA record
	saRecord_base = mtk_set_saRecord(mtk, ctx, flags);

	// update IV per request
	if (IS_CBC(flags) || IS_CTR(flags)) {
		if (!req->info)
			memset(saState->stateIv, 0xFF, AES_BLOCK_SIZE);
		else
			memcpy(saState->stateIv, req->info, AES_BLOCK_SIZE);
			memcpy(iv, req->info, AES_BLOCK_SIZE);
	}

	err = mtk_is_sg_aligned(req->dst, datalen, AES_BLOCK_SIZE); //rctx->blksize);
	if (!err) {
		rctx->sg_dst = req->dst;
		mtk_make_sg_cpy(rctx->sg_dst, &rctx->sg_dst, datalen);
		dst = rctx->sg_dst;
	} else {
		rctx->sg_dst = NULL;
		dst = req->dst;
	}
	
	err = mtk_is_sg_aligned(req->src, datalen, AES_BLOCK_SIZE); //rctx->blksize);
	if (!err) {
		rctx->sg_src = req->src;
		mtk_make_sg_cpy(rctx->sg_src, &rctx->sg_src, datalen);
		src = rctx->sg_src;
	} else {
		rctx->sg_src = NULL;
		src = req->src;
	}

	if (IS_CTR(rctx->flags) && complete == true) {
		/* Compute data length. */
		blocks = DIV_ROUND_UP(datalen, AES_BLOCK_SIZE);
		ctr = be32_to_cpu(iv[3]);
		/* Check 32bit counter overflow. */
		start = ctr;
		end = start + blocks - 1;
		if (end < start) {
			offset = AES_BLOCK_SIZE * -start;
			/*
			 * Increment the counter manually to cope with the hardware
			 * counter overflow.
			 */
			if (offset < req->nbytes) {
				memcpy(iv, req->info, AES_BLOCK_SIZE);
				ctr |= 0xffffffff;
				iv[3] = cpu_to_be32(ctr);
				crypto_inc((u8 *)iv, AES_BLOCK_SIZE);
				complete = false;
			}
		}
	}

	if (unlikely(complete == false)) {
		src_ctr = src;
		dst_ctr = dst;
		err = mtk_scatter_combine(mtk, saRecord_base,
				saState_base, src, dst,
				offset, complete, (void *)async,
				&ctr_cdr, &ctr_rdr);
		/* Jump to offset. */
		src = scatterwalk_ffwd(rctx->ctr_src, src_ctr, offset);
		dst = ((src_ctr == dst_ctr) ? src :
		       scatterwalk_ffwd(rctx->ctr_dst, dst_ctr, offset));
		/* Set new State */
		wptr = mtk_ring_curr_wptr_index(mtk);
		saState = &mtk->saState[wptr];
		saState_base = mtk->saState_base +wptr * sizeof(saState_t);
		memcpy(saState->stateIv, iv, AES_BLOCK_SIZE);
		datalen -= offset;
		complete = true;
	}

	err = mtk_scatter_combine(mtk, saRecord_base, 
			saState_base, src, dst,
			datalen, complete, (void *)async,
			&ndesc_cdr, &ndesc_rdr);

	*commands = ndesc_cdr + ctr_cdr;
	*results = ndesc_rdr + ctr_rdr;

	return 0;
}

int mtk_skcipher_handle_result(struct mtk_device *mtk,
				struct crypto_async_request *async,
				bool *should_complete,  int *ret)
{
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	struct eip93_descriptor_s *cdesc;
	struct eip93_descriptor_s *rdesc;
	struct mtk_dma_rec *rec;
	int ndesc= 0, rptr, nreq;

	*ret = 0;
	nreq = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);
	*should_complete = false;

	while (ndesc < nreq) {
		rptr =  mtk_ring_curr_rptr_index(mtk);
		rdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].rdr);
		if (IS_ERR(rdesc)) {
			dev_err(mtk->dev, "cipher: result: error!\n");
			*ret = PTR_ERR(rdesc);
			break;
		}

//		if (likely(!*ret))
			//*ret = mtk_rdesc_check_errors(mtk, rdesc);

			if (rdesc->peCrtlStat.bits.errStatus) {
				dev_err(mtk->dev, "Err: %02x \n",
					rdesc->peCrtlStat.bits.errStatus);
				*ret = -EINVAL;
			}

		cdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].cdr);

		rec = &mtk->ring[0].cdr_dma[rptr];

		dma_unmap_single(mtk->dev, (dma_addr_t)rdesc->srcAddr, rec->dmaLen,
				DMA_TO_DEVICE);

		dma_unmap_single(mtk->dev, (dma_addr_t)rdesc->dstAddr, rec->dmaLen,
				DMA_FROM_DEVICE);

		ndesc++;

		if (rec->flags & BIT(0)) {
				*should_complete = true;
				break;
		}			
	}

	if (*should_complete) {
		if (rctx->sg_dst) {
			dev_dbg(mtk->dev,
				"Copying %d bytes of output data back to original place\n",
				req->nbytes);
			mtk_sg_copy_buf(sg_virt(rctx->sg_dst), req->dst,
					req->nbytes, 1);
			mtk_free_sg_cpy(req->nbytes, &rctx->sg_dst);
		}

		if (rctx->sg_src) {
			mtk_free_sg_cpy(req->nbytes, &rctx->sg_src);
		}
	}

	return ndesc;
}

int mtk_cipher_crypt(struct ablkcipher_request *req, int encrypt)
{
	struct crypto_tfm *tfm =
			crypto_ablkcipher_tfm(crypto_ablkcipher_reqtfm(req));
//	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_alg_template *tmpl = to_cipher_tmpl(tfm);
	struct mtk_device *mtk = tmpl->mtk;
	int ret;

	rctx->flags = tmpl->alg_flags;
	rctx->flags |= encrypt ? MTK_ENCRYPT : MTK_DECRYPT;
	rctx->blksize = tmpl->alg_blksize;
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
*/;

	spin_lock_bh(&mtk->ring[0].queue_lock);
	ret = crypto_enqueue_request(&mtk->ring[0].queue, &req->base);
	spin_unlock_bh(&mtk->ring[0].queue_lock);

	queue_work(mtk->ring[0].workqueue, &mtk->ring[0].work_data.work);

	return ret;
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
	struct mtk_alg_template *tmpl = to_cipher_tmpl(tfm);
	struct mtk_device *mtk = tmpl->mtk;

	memset(ctx, 0, sizeof(*ctx));
	tfm->crt_ablkcipher.reqsize = sizeof(struct mtk_cipher_reqctx);

	ctx->fallback = crypto_alloc_skcipher(crypto_tfm_alg_name(tfm), 0,
					      CRYPTO_ALG_ASYNC |
					      CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);

	ctx->mtk = mtk;
	ctx->base.send = mtk_skcipher_send;
	ctx->base.handle_result = mtk_skcipher_handle_result;

	return 0;
}

void mtk_cipher_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_device *mtk;

	mtk = ctx->mtk;

	crypto_free_skcipher(ctx->fallback);
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
	tmpl->alg_blksize = def->blocksize;
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
};

