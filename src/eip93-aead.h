/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _CIPHER_AEAD_H_
#define _CIPHER_AEAD_H_

#include <crypto/internal/aead.h>

#include "eip93-cipher.h"

extern struct mtk_alg_template mtk_alg_authenc_hmac_md5_cbc_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha1_cbc_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha224_cbc_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha256_cbc_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_md5_ctr_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha1_ctr_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha224_ctr_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha256_ctr_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_md5_rfc3686_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha1_rfc3686_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha224_rfc3686_aes;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha256_rfc3686_aes;
#ifdef CONFIG_EIP93_PRNG
extern struct mtk_alg_template mtk_alg_echainiv_authenc_hmac_sha1_cbc_aes;
extern struct mtk_alg_template mtk_alg_echainiv_authenc_hmac_sha256_cbc_aes;
extern struct mtk_alg_template mtk_alg_seqiv_authenc_hmac_sha1_rfc3686_aes;
extern struct mtk_alg_template mtk_alg_seqiv_authenc_hmac_sha256_rfc3686_aes;
#endif
#ifdef CONFIG_EIP93_DES
extern struct mtk_alg_template mtk_alg_authenc_hmac_md5_cbc_des;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha1_cbc_des;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha224_cbc_des;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha256_cbc_des;
extern struct mtk_alg_template mtk_alg_authenc_hmac_md5_cbc_des3_ede;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha1_cbc_des3_ede;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha224_cbc_des3_ede;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha256_cbc_des3_ede;
extern struct mtk_alg_template mtk_alg_authenc_hmac_md5_ecb_null;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha1_ecb_null;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha224_ecb_null;
extern struct mtk_alg_template mtk_alg_authenc_hmac_sha256_ecb_null;
#ifdef CONFIG_EIP93_PRNG
extern struct mtk_alg_template mtk_alg_echainiv_authenc_hmac_md5_cbc_des;
#endif
#endif

void mtk_aead_handle_result(struct mtk_device *mtk,
				struct crypto_async_request *async,
				bool complete,  int err);

int mtk_authenc_setkey(struct crypto_shash *cshash, struct saRecord_s *sa,
			const u8 *authkey, unsigned int authkeylen);

#endif /* _CIPHER_AEAD_H_ */
