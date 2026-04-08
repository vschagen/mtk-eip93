/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 * Christian Marangi <ansuelsmth@gmail.com
 */
#ifndef _EIP93_CIPHER_H_
#define _EIP93_CIPHER_H_

#include "eip93-main.h"

struct eip93_crypto_ctx {
	struct eip93_device		*eip93;
	u32				flags;
	uint16_t                        sa_in_idx;
	uint16_t                        sa_out_idx;
	dma_addr_t			sa_record_base_in;
	dma_addr_t                      sa_record_base_out;
	u32				sa_nonce;
	int				blksize;
	/* AEAD specific */
	unsigned int			authsize;
	unsigned int			assoclen;
	bool				set_assoc;
	enum eip93_alg_type		type;
};

struct eip93_cipher_reqctx {
	u16				desc_flags;
	u16				flags;
	u16				crypto_async_idr;
	struct scatterlist		*sg_src;
	struct scatterlist		*sg_dst;
	u8                              *iv;
	uint16_t                        state_idx;
	dma_addr_t			sa_record_base;
	unsigned int			split;
	unsigned int			ivsize;
	unsigned int			textsize;
	unsigned int			assoclen;
	unsigned int			authsize;
	u32                             sa_nonce;
	int				src_nents;
	int				dst_nents;
	uint16_t                        state_ctr_idx;
	dma_addr_t			sa_state_base;
	u32                             iv_ctr[4];
	dma_addr_t			sa_state_ctr_base;
        void                            *callback;
        void                            *context;
};

#endif /* _EIP93_CIPHER_H_ */
