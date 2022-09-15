/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2022
 *
 * Richard van Schagen <vschagen@icloud.com>
 */

#ifndef _EIP93_COMMON_H_
#define _EIP93_COMMON_H_

#include "eip93-main.h"
#include "eip93-cipher.h"

int mtk_ring_free(struct mtk_desc_ring *ring);

int mtk_put_descriptor(struct mtk_device *mtk,
					struct eip93_descriptor_s *desc);

void *mtk_get_descriptor(struct mtk_device *mtk);

int mtk_get_free_saState(struct mtk_device *mtk);

void mtk_set_saRecord(struct saRecord_s *saRecord, const unsigned int keylen,
			const u32 flags);

int mtk_send_req(struct mtk_cipher_reqctx *rctx, const u8 *reqiv);

void mtk_handle_result(struct mtk_cipher_reqctx *rctx, u8 *reqiv);

int check_valid_request(struct mtk_cipher_reqctx *rctx);

void mtk_unmap_dma(struct mtk_cipher_reqctx *rctx, struct scatterlist *reqsrc,
			struct scatterlist *reqdst);

#if IS_ENABLED(CONFIG_CRYPTO_DEV_EIP93_HMAC)
int mtk_authenc_setkey(struct crypto_shash *cshash, struct saRecord_s *sa,
			const u8 *authkey, unsigned int authkeylen);
#endif

#endif /* _EIP93_COMMON_H_ */
