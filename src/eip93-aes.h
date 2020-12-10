/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _CIPHER_AES_H_
#define _CIPHER_AES_H_

#include <crypto/aes.h>

extern struct mtk_alg_template mtk_alg_ecb_aes;
extern struct mtk_alg_template mtk_alg_cbc_aes;
extern struct mtk_alg_template mtk_alg_ctr_aes;
extern struct mtk_alg_template mtk_alg_rfc3686_aes;

#endif /* _CIPHER_AES_H_ */
