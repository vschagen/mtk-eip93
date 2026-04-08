// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 * Christian Marangi <ansuelsmth@gmail.com
 */

#include <crypto/aes.h>
#include <crypto/ctr.h>
#include <crypto/hmac.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>

#include "eip93-cipher.h"
#include "eip93-hash.h"
#include "eip93-common.h"
#include "eip93-main.h"
#include "eip93-regs.h"

int eip93_parse_ctrl_stat_err(struct eip93_device *eip93, int err)
{
	u32 ext_err;

	if (!err)
		return 0;

	switch (err & ~EIP93_PE_CTRL_PE_EXT_ERR_CODE) {
	case EIP93_PE_CTRL_PE_AUTH_ERR:
	case EIP93_PE_CTRL_PE_PAD_ERR:
		return -EBADMSG;
	/* let software handle anti-replay errors */
	case EIP93_PE_CTRL_PE_SEQNUM_ERR:
		return 0;
	case EIP93_PE_CTRL_PE_EXT_ERR:
		break;
	default:
		dev_err(eip93->dev, "Unhandled error 0x%08x\n", err);
		return -EINVAL;
	}

	/* Parse additional ext errors */
	ext_err = FIELD_GET(EIP93_PE_CTRL_PE_EXT_ERR_CODE, err);
	switch (ext_err) {
	case EIP93_PE_CTRL_PE_EXT_ERR_BUS:
	case EIP93_PE_CTRL_PE_EXT_ERR_PROCESSING:
		return -EIO;
	case EIP93_PE_CTRL_PE_EXT_ERR_DESC_OWNER:
		return -EACCES;
	case EIP93_PE_CTRL_PE_EXT_ERR_INVALID_CRYPTO_OP:
	case EIP93_PE_CTRL_PE_EXT_ERR_INVALID_CRYPTO_ALGO:
	case EIP93_PE_CTRL_PE_EXT_ERR_SPI:
		return -EINVAL;
	case EIP93_PE_CTRL_PE_EXT_ERR_ZERO_LENGTH:
	case EIP93_PE_CTRL_PE_EXT_ERR_INVALID_PK_LENGTH:
	case EIP93_PE_CTRL_PE_EXT_ERR_BLOCK_SIZE_ERR:
		return -EBADMSG;
	default:
		dev_err(eip93->dev, "Unhandled ext error 0x%08x\n", ext_err);
		return -EINVAL;
	}
}

inline uint16_t eip93_desc_ring_free(struct eip93_desc_ring *ring) {
	return (ring->read - ring->write) & EIP93_RING_MASK;
}

inline bool eip93_desc_ring_empty(struct eip93_desc_ring *ring) {
	return ring->read == ring->write;
}

inline bool eip93_desc_ring_full(struct eip93_desc_ring *ring) {
	return ((ring->write + 1) & EIP93_RING_MASK) == ring->read;
}

inline uint16_t eip93_sa_alloc(struct eip93_device *eip93)
{
        struct eip93_sa_ring *sa_pool = &eip93->ring->sa_pool;
	uint16_t idr;

      idr = find_first_zero_bit(sa_pool->sa_bitmap, EIP93_SA_POOL);
      if (idr == EIP93_SA_POOL)
          idr = -ENOMEM;
      else
      	  __set_bit(idr, sa_pool->sa_bitmap);

	return idr;
}

inline void eip93_sa_free(struct eip93_device *eip93, uint16_t idr)
{
    struct eip93_sa_ring *sa_pool = &eip93->ring->sa_pool;

    __clear_bit(idr, sa_pool->sa_bitmap);
}

static inline uint16_t eip93_state_alloc(struct eip93_device *eip93, uint16_t cdr_idx)
{
        struct eip93_state_ring *state_pool = &eip93->ring->state_pool;
	uint16_t idr;

	if (!test_and_set_bit(cdr_idx, state_pool->state_bitmap))
	      return cdr_idx;

	idr = find_first_zero_bit(state_pool->state_bitmap, EIP93_STATE_POOL);
        if (idr == EIP93_STATE_POOL)
            idr = -ENOMEM;
        else
      	    __set_bit(idr, state_pool->state_bitmap);

        return idr;
}

static inline void eip93_state_free(struct eip93_device *eip93, uint16_t idr)
{
    struct eip93_state_ring *state_pool = &eip93->ring->state_pool;

    __clear_bit(idr, state_pool->state_bitmap);
}

static inline uint16_t eip93_callback_alloc(struct eip93_device *eip93, uint16_t cdr_idx)
{
        struct eip93_callback_ring *callback = &eip93->ring->callback;
	uint16_t idx;

	if (!test_and_set_bit(cdr_idx, callback->cb_bitmap))
	      return cdr_idx;

	idx = find_first_zero_bit(callback->cb_bitmap, EIP93_STATE_POOL);
        if (idx == EIP93_STATE_POOL)
            idx = -ENOMEM;
        else
      	    __set_bit(idx, callback->cb_bitmap);

        return idx;
}

inline void eip93_callback_free(struct eip93_device *eip93, uint16_t idx)
{
    struct eip93_callback_ring *callback = &eip93->ring->callback;

    __clear_bit(idx, callback->cb_bitmap);
}

static void eip93_free_sg_copy(const int len, struct scatterlist **sg)
{
	if (!*sg || !len)
		return;

	free_pages((unsigned long)sg_virt(*sg), get_order(len));
	kfree(*sg);
	*sg = NULL;
}

static int eip93_make_sg_copy(struct scatterlist *src, struct scatterlist **dst,
			      const u32 len, const bool copy)
{
	void *pages;

	*dst = kmalloc(sizeof(**dst), GFP_ATOMIC);
	if (!*dst)
		return -ENOMEM;

	pages = (void *)__get_free_pages(GFP_ATOMIC | GFP_DMA,
					 get_order(len));
	if (!pages) {
		kfree(*dst);
		*dst = NULL;
		return -ENOMEM;
	}

	sg_init_table(*dst, 1);
	sg_set_buf(*dst, pages, len);

	/* copy only as requested */
	if (copy)
		sg_copy_to_buffer(src, sg_nents(src), pages, len);

	return 0;
}

static int eip93_alloc_and_stage_bounce(struct eip93_device *eip93,
			struct eip93_cipher_reqctx *rctx,
			u32 src_total, u32 dst_total)
{
	struct scatterlist *src = rctx->sg_src;
	struct scatterlist *dst = rctx->sg_dst;
	int err;

	err = eip93_make_sg_copy(src, &rctx->sg_src, src_total, true);
	if (err)
		return err;

	err = eip93_make_sg_copy(dst, &rctx->sg_dst, dst_total, false);
	if (err)
		return err;

	rctx->src_nents = sg_nents_for_len(rctx->sg_src, src_total);
	rctx->dst_nents = sg_nents_for_len(rctx->sg_dst, dst_total);

	if (!dma_map_sg(eip93->dev, rctx->sg_dst, rctx->dst_nents, DMA_BIDIRECTIONAL))
		return -ENOMEM;

	if (!dma_map_sg(eip93->dev, rctx->sg_src, rctx->src_nents, DMA_TO_DEVICE)) {
		dma_unmap_sg(eip93->dev, dst, rctx->dst_nents, DMA_BIDIRECTIONAL);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Set sa_record function:
 * Even sa_record is set to "0", keep " = 0" for readability.
 */
void eip93_set_sa_record(struct sa_record *sa_record, const unsigned int keylen,
			 const u32 flags)
{
	/* Reset cmd word */
	sa_record->sa_cmd0_word = 0;
	sa_record->sa_cmd1_word = 0;

	sa_record->sa_cmd0_word |= EIP93_SA_CMD_IV_FROM_STATE;
	if (!IS_ECB(flags))
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_SAVE_IV;

	sa_record->sa_cmd0_word |= EIP93_SA_CMD_OP_BASIC;

	switch ((flags & EIP93_ALG_MASK)) {
	case EIP93_ALG_AES:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_CIPHER_AES;
		sa_record->sa_cmd1_word |= FIELD_PREP(EIP93_SA_CMD_AES_KEY_LENGTH,
						      keylen >> 3);
		break;
	case EIP93_ALG_3DES:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_CIPHER_3DES;
		break;
	case EIP93_ALG_DES:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_CIPHER_DES;
		break;
	default:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_CIPHER_NULL;
	}

	switch ((flags & EIP93_HASH_MASK)) {
	case EIP93_HASH_SHA256:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_HASH_SHA256;
		break;
	case EIP93_HASH_SHA224:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_HASH_SHA224;
		break;
	case EIP93_HASH_SHA1:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_HASH_SHA1;
		break;
	case EIP93_HASH_MD5:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_HASH_MD5;
		break;
	default:
		sa_record->sa_cmd0_word |= EIP93_SA_CMD_HASH_NULL;
	}

	sa_record->sa_cmd0_word |= EIP93_SA_CMD_PAD_ZERO;

	switch ((flags & EIP93_MODE_MASK)) {
	case EIP93_MODE_CBC:
		sa_record->sa_cmd1_word |= EIP93_SA_CMD_CHIPER_MODE_CBC;
		break;
	case EIP93_MODE_CTR:
		sa_record->sa_cmd1_word |= EIP93_SA_CMD_CHIPER_MODE_CTR;
		break;
	case EIP93_MODE_ECB:
		sa_record->sa_cmd1_word |= EIP93_SA_CMD_CHIPER_MODE_ECB;
		break;
	}

	sa_record->sa_cmd0_word |= EIP93_SA_CMD_DIGEST_3WORD;
	if (IS_HASH(flags)) {
		sa_record->sa_cmd1_word |= EIP93_SA_CMD_COPY_PAD;
		sa_record->sa_cmd1_word |= EIP93_SA_CMD_COPY_DIGEST;
	}

	if (IS_HMAC(flags)) {
		sa_record->sa_cmd1_word |= EIP93_SA_CMD_HMAC;
		sa_record->sa_cmd1_word |= EIP93_SA_CMD_COPY_HEADER;
	}

	sa_record->sa_spi = 0x0;
	sa_record->sa_seqmum_mask[0] = 0xFFFFFFFF;
	sa_record->sa_seqmum_mask[1] = 0x0;
}

/* Helper utilities ------------------------------------------------------- */

static inline struct scatterlist *sg_skip_zero_len(struct scatterlist *sg)
{
	while (sg && !sg->length)
		sg = sg_next(sg);
	return sg;
}

/*
 * Ensure we can consume 'total' bytes in block-size multiples except possibly
 * for the final chunk when allow_partial_last == true (CTR).
 */
static bool eip93_blk_ok_over_range(struct scatterlist *sg, u32 total,
				  u32 blksz, bool allow_partial_last)
{
	u32 seg;

	sg = sg_skip_zero_len(sg);
	while (sg && total) {
		seg = min_t(u32, sg_dma_len(sg), total);

		if (!seg) {
			sg = sg_next(sg);
			continue;
		}
		/* check address alignment */
		if (!IS_ALIGNED(sg_dma_address(sg), 4))
			return false;

		/* not last segment covering remaining bytes -> must be multiple */
		if (seg < total) {
			if (seg % blksz)
				return false;
		} else { /* last segment (covers remaining total) */
			if (!allow_partial_last && (seg % blksz))
				return false;
		}

		total -= seg;
		sg = sg_next(sg);
	}
	return total == 0;
}

/* ------------------------------------------------------------------------- */
/* Main validation / decision functions                                      */
/* ------------------------------------------------------------------------- */

/*
 * Validate AEAD requests: hardware requires single contiguous descriptor
 * for AEAD on EIP93-like devices. If not suitable, return bounce path error
 * (caller will allocate & stage a bounce).
 */
int eip93_validate_aead_request(struct eip93_device *eip93,
				struct eip93_cipher_reqctx *rctx)
{
	bool enc = IS_ENCRYPT(rctx->flags);
	u32 src_total = rctx->assoclen + rctx->textsize + (enc ? 0 : rctx->authsize);
	u32 dst_total = rctx->assoclen + rctx->textsize + (enc ? rctx->authsize : 0);
	struct scatterlist *src = rctx->sg_src;
	struct scatterlist *dst = rctx->sg_dst;
	int src_nents, dst_nents;
	int sn, dn;

	src_nents = sg_nents_for_len(src, src_total);
	dst_nents = sg_nents_for_len(dst, dst_total);

	/* Map: if in-place map once as BIDIRECTIONAL */
	dn = dma_map_sg(eip93->dev, dst, dst_nents, DMA_BIDIRECTIONAL);
	if (unlikely(!dn))
		return -ENOMEM;
	sn = dn;

	if (src != dst) {
		sn = dma_map_sg(eip93->dev, src, src_nents, DMA_TO_DEVICE);
		if (unlikely(!sn)) {
				dma_unmap_sg(eip93->dev, dst, dn, DMA_BIDIRECTIONAL);
			return -ENOMEM;
		}
	}

	/* Fast path: both sides must be single mapped segment and addresses aligned */
	if  ((src_nents == 1) && (dst_nents == 1) &&
	    /* check DMA address alignment */
	    !(sg_dma_address(src) & 3) &&
	    !(sg_dma_address(dst) & 3)) {
		rctx->src_nents = sn;
		rctx->dst_nents = dn;
		return 0;
	}

	/* Not suitable: unmap and request bounce staging */
	dma_unmap_sg(eip93->dev, dst, dn, DMA_BIDIRECTIONAL);
	if (src != dst)
		dma_unmap_sg(eip93->dev, src, sn, DMA_TO_DEVICE);

	/* Caller should allocate a bounce buffer (one contiguous descriptor). */
	return eip93_alloc_and_stage_bounce(eip93, rctx, src_total, dst_total);
}

/*
 * Validate skcipher requests (CBC/ECB/CTR). Prefer "poor-man SG" fast path:
 * - per-segment DMA addresses must be 4B aligned
 * - each consumed segment must be a multiple of blksz except the final chunk
 *   when CTR mode allows a final partial
 * Otherwise fallback to bounce (single contiguous buffer).
 */
int eip93_validate_skcipher_request(struct eip93_device *eip93,
					struct eip93_cipher_reqctx *rctx,
					const int blksize)
{
	u32 total = rctx->textsize;   /* skcipher covers text (assoc handled separately) */
	struct scatterlist *src = rctx->sg_src, *dst = rctx->sg_dst;
	bool ctr = IS_CTR(rctx->flags);
	int src_nents, dst_nents;
	int sn, dn;

	dst_nents = sg_nents_for_len(dst, total);
	src_nents = sg_nents_for_len(src, total);
	if (!src_nents || !dst_nents)
		return -EINVAL;

	/* Map once (bidirectional for in-place) */
	dn = dma_map_sg(eip93->dev, dst, dst_nents, DMA_BIDIRECTIONAL);
	if (unlikely(!dn))
		return -ENOMEM;

	if (src != dst) {
		sn = dma_map_sg(eip93->dev, src, src_nents, DMA_TO_DEVICE);
		if (unlikely(!sn)) {
			dma_unmap_sg(eip93->dev, dst, dn, DMA_BIDIRECTIONAL);
			return -ENOMEM;
		}
	} else {
		sn = dn;
	}

	/* Fast "poor-man SG" path: dma addrs aligned & block-ok over ranges */
	if (eip93_blk_ok_over_range(src, total, blksize, ctr) &&
	    eip93_blk_ok_over_range(dst, total, blksize, ctr)) {
		rctx->src_nents = sn;
		rctx->dst_nents = dn;
		return 0;
	}

	/* Not suitable -> unmap and bounce */
	if (src != dst)
		dma_unmap_sg(eip93->dev, src, sn, DMA_TO_DEVICE);

	dma_unmap_sg(eip93->dev, dst, dn, DMA_BIDIRECTIONAL);

	return eip93_alloc_and_stage_bounce(eip93, rctx, total, total);
}

/**
 * eip93_check_ctr_overflow - Check for AES-CTR 32-bit counter overflow
 * @rctx: Cipher request context
 *
 * Detects if the AES-CTR counter (the last 32 bits of the IV)
 * would overflow during this request. If so, it computes:
 *   - @rctx->split:  number of bytes that can be processed before overflow
 *   - @rctx->iv_ctr: IV to use for the second phase (after wraparound)
 *
 * This is a rare edge case (only for extremely large CTR requests,
 * >64 GiB per IV), but must be handled to maintain compliance.
 *
 * Note:
 *   RFC3686 AEAD (AES-CTR-HMAC) requests will never trigger this.
 */
void eip93_check_ctr_overflow(struct eip93_cipher_reqctx *rctx)
{
	u32 blocks, start, end, ctr;
	u32 iv[AES_BLOCK_SIZE / sizeof(u32)];

	/* Copy current IV to a local buffer for manipulation */
	memcpy(iv, rctx->iv, rctx->ivsize);

	/* Number of AES blocks this request will process */
	blocks = DIV_ROUND_UP(rctx->textsize, AES_BLOCK_SIZE);

	/* Extract the current 32-bit counter (last word of the IV) */
	ctr = be32_to_cpu(iv[3]);

	start = ctr;
	end = start + blocks - 1;

	/* Detect counter overflow (end < start under 32-bit wrap) */
	if (end < start) {
		u32 split_blocks = (0xFFFFFFFFu - start + 1u);

		/* Number of bytes before counter wraparound (×16) */
		rctx->split = split_blocks << 4;

		/* Prepare IV for second phase (after wrap) */
		iv[3] = cpu_to_be32(0xFFFFFFFF);
		crypto_inc((u8 *)iv, AES_BLOCK_SIZE);
		memcpy(rctx->iv_ctr, iv, rctx->ivsize);
	}
}

inline bool eip93_kick_engine(struct eip93_device *eip93, u16 queued, u16 handled)
{
	struct eip93_ring *ring = eip93->ring;
      	struct eip93_desc_ring *cdr_ring = &eip93->ring->cdr;
	unsigned long flags;
	u16 fill_level;
	u16 coal;
	u32 val = 0;
	bool need_kick = false;

	spin_lock_irqsave(&ring->kick_lock, flags);

        if (eip93_desc_ring_free(cdr_ring) < EIP93_BUDGET)
        	cdr_ring->read = FIELD_GET(GENMASK(9, 0),
			      readl_relaxed(eip93->base + EIP93_REG_PE_RING_RW_PNTR));

	ring->queued += queued;
	ring->pending += queued;
	ring->pending -= handled;

	if (unlikely(!ring->queued && !ring->pending)) {
		spin_unlock_irqrestore(&ring->kick_lock, flags);
		return false;
	}

	/* make sure we get IRQ based on pending RDR */
	coal = MIN(ring->pending, EIP93_BUDGET);
	if (coal) {
		coal--;
		if (ring->threshold != coal) {
			val |= FIELD_PREP(EIPR93_PE_RDR_THRESH, coal);
			val |= FIELD_PREP(EIPR93_PE_RD_TIMEOUT, 10) | EIPR93_PE_TIMEROUT_EN;
			writel_relaxed(val, eip93->base + EIP93_REG_PE_RING_THRESH);
			ring->threshold = coal;
		}
	}

	if (ring->queued > EIP93_RING_BUSY) {
        	cdr_ring->read = FIELD_GET(GENMASK(9, 0),
			      readl_relaxed(eip93->base + EIP93_REG_PE_RING_RW_PNTR));
		need_kick = true;
	} else {
		fill_level = FIELD_GET(GENMASK(10, 0), readl_relaxed(eip93->base + EIP93_REG_PE_CD_COUNT));
		if (fill_level < EIP93_RING_CDR_LOW_WATER)
			need_kick = true;
	}

	if (need_kick) {
		dma_wmb();
		writel_relaxed(ring->queued, eip93->base + EIP93_REG_PE_CD_COUNT) ;
		ring->queued = 0;
	}

	spin_unlock_irqrestore(&ring->kick_lock, flags);

	return true;
}

inline int eip93_set_callback(struct eip93_device *eip93,
                                      void *cb, void *context)
{
	struct eip93_callback_ring *callback = &eip93->ring->callback;
	struct eip93_desc_ring *cdr_ring = &eip93->ring->cdr;
        struct eip93_callback_ops *ops;
        uint16_t idx;

	idx = eip93_callback_alloc(eip93, cdr_ring->write);
	if (idx < 0)
	      return -ENOMEM;

	ops = &callback->ops[idx];
	ops->callback = cb;
	ops->context = context;

        return idx;
}

/* -------------------------------------------------------------------------- */
/* Inline helpers                                                             */
/* -------------------------------------------------------------------------- */

/**
 * eip93_prepare_state - Allocate and initialize state buffer(s)
 * @eip93:  EIP93 device handle
 * @rctx:   Request context
 * @ctr_overflow: True if CTR counter overflow requires a second IV state
 *
 * Allocates one or two state slots from the state pool and fills the
 * initial IV(s). Should be called inside the write_lock scope if it uses
 * cdr->write as allocation hint.
 */
static inline int eip93_prepare_state(struct eip93_device *eip93,
                                      struct eip93_cipher_reqctx *rctx,
                                      bool ctr_overflow)
{
	struct eip93_state_ring *state_pool = &eip93->ring->state_pool;
	struct eip93_desc_ring *cdr_ring = &eip93->ring->cdr;
        struct sa_state *sa_state;

	rctx->state_idx = eip93_state_alloc(eip93, cdr_ring->write);
	if (rctx->state_idx < 0)
	      return -ENOMEM;

	rctx->sa_state_base = state_pool->base_dma +
			      rctx->state_idx * sizeof(struct sa_state);
	sa_state = &state_pool->state[rctx->state_idx];
	memcpy(sa_state->state_iv, rctx->iv, rctx->ivsize);

	if (IS_RFC3686(rctx->flags)) {
		sa_state->state_iv[2] = sa_state->state_iv[1];
		sa_state->state_iv[1] = sa_state->state_iv[0];
		sa_state->state_iv[3] = cpu_to_be32(1);
		sa_state->state_iv[0] = rctx->sa_nonce;
	} else if (IS_CTR(rctx->flags)) {
	/* sync after read IV; this fixed issues with gcm_base */
              dma_sync_sg_for_device(eip93->dev, rctx->sg_dst, rctx->dst_nents,
			     DMA_BIDIRECTIONAL);
        }

	if (ctr_overflow) {
		rctx->state_ctr_idx = eip93_state_alloc(eip93, cdr_ring->write);
		if (rctx->state_ctr_idx < 0) {
		        eip93_state_free(eip93, rctx->state_idx);
			return -ENOMEM;
                }
		rctx->sa_state_ctr_base = state_pool->base_dma +
					  rctx->state_ctr_idx * sizeof(struct sa_state);
                sa_state = &state_pool->state[rctx->state_ctr_idx];
		memcpy(sa_state->state_iv, rctx->iv_ctr, rctx->ivsize);
	}

	return 0;
}

/**
 * eip93_put_descriptor - Write a prepared descriptor into CDR ring
 * @eip93:  EIP93 device
 * @cdesc:  Prepared descriptor template
 *
 * Caller must hold eip93->ring->write_lock and ensure ring has space.
 */
inline void eip93_put_descriptor(struct eip93_device *eip93,
                                 const struct eip93_descriptor *cdesc)
{
	struct eip93_desc_ring *cdr_ring = &eip93->ring->cdr;
	struct eip93_descriptor *desc = &cdr_ring->desc[cdr_ring->write];

	/* Copy descriptor contents */
	*desc = *cdesc;

	/* Mark both control words ready for engine */
	desc->pe_ctrl_stat_word |= FIELD_PREP(EIP93_PE_CTRL_PE_READY_DES_TRING_OWN,
					     EIP93_PE_CTRL_HOST_READY);
	desc->pe_length_word    |= FIELD_PREP(EIP93_PE_LENGTH_HOST_PE_READY,
					     EIP93_PE_LENGTH_HOST_READY);

	/* Ensure memory visible to DMA before advancing ring pointer */
	dma_wmb();

	cdr_ring->write = (cdr_ring->write + 1) & EIP93_RING_MASK;
}

/* -------------------------------------------------------------------------- */
/* Scatter / combine main path                                                */
/* -------------------------------------------------------------------------- */

/**
 * eip93_scatter_combine - Build and enqueue CDR descriptors from scatterlists
 */
int eip93_scatter_combine(struct eip93_device *eip93,
			  struct eip93_cipher_reqctx *rctx)
{
	struct scatterlist *sgsrc = rctx->sg_src;
	struct scatterlist *sgdst = rctx->sg_dst;
	u32 rin, rout, len;
	bool completes_phase, last_desc;
	struct eip93_descriptor cdesc = { 0 };
	u32 datalen       = rctx->assoclen + rctx->textsize;
	u32 split         = rctx->split;  /* 0 unless CTR overflow */
	bool ctr_overflow = split > 0;
	bool use_second_iv = false;
	bool first_iv      = !IS_ECB(rctx->flags);
	u32 phase_rem      = split ? split : datalen;
	u32 phase2_total   = split ? (datalen - split) : 0;
	u32 off_in = 0, off_out = 0;
	int queued = 0;
	uint16_t idx;

	cdesc.sa_addr = rctx->sa_record_base;
	cdesc.arc4_addr = 0;
	cdesc.user_id = FIELD_PREP(EIP93_PE_USER_ID_DESC_FLAGS, rctx->desc_flags);

	while (phase_rem) {
		rin  = min(sg_dma_len(sgsrc) - off_in,  phase_rem);
		rout = min(sg_dma_len(sgdst) - off_out, phase_rem);
		len  = min(rin, rout);

		cdesc.src_addr = sg_dma_address(sgsrc) + off_in;
		cdesc.dst_addr = sg_dma_address(sgdst) + off_out;
		cdesc.pe_length_word = FIELD_PREP(EIP93_PE_LENGTH_LENGTH, len);

		phase_rem -= len;
		off_in    += len;
		off_out   += len;
		if (off_in  == sg_dma_len(sgsrc)) {
		    sgsrc = sg_next(sgsrc);
		    off_in  = 0;
		}
		if (off_out == sg_dma_len(sgdst)) {
		    sgdst = sg_next(sgdst);
		    off_out = 0;
		}

		completes_phase = (phase_rem == 0);
		last_desc = completes_phase && (!split || use_second_iv);
again:
		scoped_guard(spinlock_irqsave, &eip93->ring->write_lock) {
  			struct eip93_desc_ring *cdr_ring = &eip93->ring->cdr;

			if (unlikely(eip93_desc_ring_full(cdr_ring))) {
				if (queued) {
					eip93_kick_engine(eip93, queued, 0);
					queued = 0;
				}
				goto again;
			}

			if (first_iv) {
				int err = eip93_prepare_state(eip93, rctx, ctr_overflow);
				if (err)
					return err;
			}
        	        cdesc.state_addr = use_second_iv ?
                	                rctx->sa_state_ctr_base :
                        	        rctx->sa_state_base;
			if (last_desc) {
			        idx = eip93_set_callback(eip93, rctx->callback, rctx->context);
                                cdesc.user_id |= FIELD_PREP(EIP93_PE_USER_ID_CRYPTO_IDR, idx) |
				                  FIELD_PREP(EIP93_PE_USER_ID_DESC_FLAGS, EIP93_DESC_LAST);
			}

			eip93_put_descriptor(eip93, &cdesc);
			queued++;
		}
		if (completes_phase && split && !use_second_iv) {
			use_second_iv = true;
			phase_rem     = phase2_total;
		}
		first_iv = false;
	}
	eip93_kick_engine(eip93, queued, 0);

	return -EINPROGRESS;
}

void eip93_unmap_dma(struct eip93_device *eip93,
		     struct eip93_cipher_reqctx *rctx,
		     struct scatterlist *reqsrc,
		     struct scatterlist *reqdst)
{
	u32 len      = rctx->assoclen + rctx->textsize;
	u32 authsize = rctx->authsize;
	u32 flags    = rctx->flags;

	if (likely(rctx->sg_src == rctx->sg_dst)) {
		dma_unmap_sg(eip93->dev, rctx->sg_dst, rctx->dst_nents,
			     DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_sg(eip93->dev, rctx->sg_src, rctx->src_nents,
			     DMA_TO_DEVICE);
		if (unlikely(rctx->sg_src != reqsrc))
			eip93_free_sg_copy(len + authsize, &rctx->sg_src);
		dma_unmap_sg(eip93->dev, rctx->sg_dst, rctx->dst_nents,
			     DMA_BIDIRECTIONAL);
	}
	if (unlikely(IS_DECRYPT(flags)))
		authsize = 0;
	/* Tag endian conversion — common for SHA1/SHA256 */
	if (likely(authsize)) {
		if (likely(!IS_HASH_MD5(flags))) {
			u32 *otag = sg_virt(rctx->sg_dst) + len;
			u32 words = authsize >> 2;
			for (u32 i = 0; i < words; i++)
				otag[i] = be32_to_cpu((__be32 __force)otag[i]);
		}
	}
	if (unlikely(rctx->sg_dst != reqdst)) {
		u32 len_total = len + authsize;
		sg_copy_from_buffer(reqdst, sg_nents(reqdst),
				    sg_virt(rctx->sg_dst), len_total);
		eip93_free_sg_copy(len_total, &rctx->sg_dst);
	}
}

void eip93_update_iv_from_state(struct eip93_device *eip93,
                          struct eip93_cipher_reqctx *rctx)
{
	struct eip93_state_ring *state_pool = &eip93->ring->state_pool;
        struct sa_state *sa_state;

        if (unlikely(rctx->split)) {
              sa_state = &state_pool->state[rctx->state_ctr_idx];
              memcpy(rctx->iv, sa_state->state_iv, rctx->ivsize);
              eip93_state_free(eip93, rctx->state_ctr_idx);
        } else {
	      sa_state = &state_pool->state[rctx->state_idx];
              memcpy(rctx->iv, sa_state->state_iv, rctx->ivsize);
	}
        eip93_state_free(eip93, rctx->state_idx);
}

int eip93_hmac_setkey(u32 ctx_flags, const u8 *key, unsigned int keylen,
		      unsigned int hashlen, u8 *dest_ipad, u8 *dest_opad,
		      bool skip_ipad)
{
	struct crypto_shash *cshash;
	int bs, ss;
	const char *alg_name;
	u8 *ipad, *opad;
	int i, ret;
	
	switch (ctx_flags & EIP93_HASH_MASK) {
	case EIP93_HASH_SHA256:
		alg_name = "sha256";
		break;
	case EIP93_HASH_SHA224:
		alg_name = "sha224";
		break;
	case EIP93_HASH_SHA1:
		alg_name = "sha1";
		break;
	case EIP93_HASH_MD5:
		alg_name = "md5";
		break;
	default: /* Impossible */
		return -EINVAL;
	}

	cshash = crypto_alloc_shash(alg_name, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(cshash))
		return PTR_ERR(cshash);

	SHASH_DESC_ON_STACK(shash, cshash);
	
	shash->tfm = cshash;
	bs = crypto_shash_blocksize(cshash);
	ss = crypto_shash_statesize(cshash);
	
	ipad = kcalloc(2, SHA256_BLOCK_SIZE + ss, GFP_ATOMIC);
	if (!ipad)
		return -ENOMEM;

	opad = ipad + SHA256_BLOCK_SIZE + ss;

	/* Hash the key if > BLOCK_SIZE */
	if (keylen > bs) {
		ret = crypto_shash_digest(shash, key, keylen, ipad);
		if (ret)
			goto err_free;

		keylen = hashlen;
	} else {
		memcpy(ipad, key, keylen);
	}

	/* Copy to opad */
	memset(ipad + keylen, 0, bs - keylen);
	memcpy(opad, ipad, bs);

	/* Pad with HMAC constants */
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ipad[i] ^= HMAC_IPAD_VALUE;
		opad[i] ^= HMAC_OPAD_VALUE;
	}

	/* Hash ipad */

	if (skip_ipad) {
		memcpy(dest_ipad, ipad, bs);
	} else {
		ret = crypto_shash_init(shash) ?:
			crypto_shash_update(shash, ipad, bs) ?:
			crypto_shash_export(shash, ipad);
	
		if (ret)
			goto err_free;

		memcpy(dest_ipad, ipad, bs);
	}			

	/* Hash opad */
	ret = crypto_shash_init(shash) ?:
		crypto_shash_update(shash, opad, bs) ?:
		crypto_shash_export(shash, opad);
		
	if (ret)
		goto err_free;

	memcpy(dest_opad, opad, bs);

err_free:
	kfree(ipad);
	
	return ret;
}
