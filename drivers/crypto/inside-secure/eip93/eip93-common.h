/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 * Christian Marangi <ansuelsmth@gmail.com
 */

#ifndef _EIP93_COMMON_H_
#define _EIP93_COMMON_H_

#include "eip93-cipher.h"

int eip93_parse_ctrl_stat_err(struct eip93_device *eip93, int err);

inline uint16_t eip93_desc_ring_free(struct eip93_desc_ring *ring);

inline bool eip93_desc_ring_empty(struct eip93_desc_ring *ring);

inline bool eip93_desc_ring_full(struct eip93_desc_ring *ring);

inline uint16_t eip93_sa_alloc(struct eip93_device *eip93);

inline void eip93_sa_free(struct eip93_device *eip93, uint16_t idr);

inline void eip93_callback_free(struct eip93_device *eip93, uint16_t idx);

inline int eip93_set_callback(struct eip93_device *eip93,
                                      void *cb, void *context);

void eip93_set_sa_record(struct sa_record *sa_record, const unsigned int keylen,
			 const u32 flags);

int eip93_validate_skcipher_request(struct eip93_device *eip93,
					struct eip93_cipher_reqctx *rctx,
					const int blksize);

int eip93_validate_aead_request(struct eip93_device *eip93,
				struct eip93_cipher_reqctx *rctx);

void eip93_check_ctr_overflow(struct eip93_cipher_reqctx *rctx);

inline bool eip93_kick_engine(struct eip93_device *eip93, u16 queued, u16 handled);

inline void eip93_put_descriptor(struct eip93_device *eip93,
                                 const struct eip93_descriptor *cdesc);

int eip93_scatter_combine(struct eip93_device *eip93,
			  struct eip93_cipher_reqctx *rctx);

void eip93_unmap_dma(struct eip93_device *eip93, struct eip93_cipher_reqctx *rctx,
		     struct scatterlist *reqsrc, struct scatterlist *reqdst);

void eip93_update_iv_from_state(struct eip93_device *eip93,
                          struct eip93_cipher_reqctx *rctx);

int eip93_hmac_setkey(u32 ctx_flags, const u8 *key, unsigned int keylen,
		      unsigned int hashlen, u8 *ipad, u8 *opad,
		      bool skip_ipad);

#endif /* _EIP93_COMMON_H_ */
