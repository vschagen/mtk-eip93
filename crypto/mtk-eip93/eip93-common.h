/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#ifndef _EIP93_COMMON_H_
#define _EIP93_COMMON_H_

void mtk_set_saRecord(struct saRecord_s *saRecord, const unsigned int keylen,
				const u32 flags);

#ifdef CONFIG_CRYPTO_DEV_EIP93_SKCIPHER
int mtk_skcipher_send_req(struct crypto_async_request *async);

void mtk_skcipher_handle_result(struct mtk_device *mtk,
				struct crypto_async_request *async,
				int err);
#endif

#ifdef CONFIG_CRYPTO_DEV_EIP93_HMAC
int mtk_authenc_setkey(struct crypto_shash *cshash, struct saRecord_s *sa,
			const u8 *authkey, unsigned int authkeylen);
#endif

#endif /* _EIP93_COMMON_H_ */
