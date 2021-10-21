/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#ifndef _EIP93_COMMON_H_
#define _EIP93_COMMON_H_

#include "eip93-cipher.h"

#define MTK_RING_SIZE			512
#define MTK_RING_BUSY			32
#define MTK_CRA_PRIORITY		1500

/* cipher algorithms */
#define MTK_ALG_DES			BIT(0)
#define MTK_ALG_3DES			BIT(1)
#define MTK_ALG_AES			BIT(2)
#define MTK_ALG_MASK			GENMASK(2, 0)
/* hash and hmac algorithms */
#define MTK_HASH_MD5			BIT(3)
#define MTK_HASH_SHA1			BIT(4)
#define MTK_HASH_SHA224			BIT(5)
#define MTK_HASH_SHA256			BIT(6)
#define MTK_HASH_HMAC			BIT(7)
#define MTK_HASH_MASK			GENMASK(6, 3)
/* cipher modes */
#define MTK_MODE_CBC			BIT(8)
#define MTK_MODE_ECB			BIT(9)
#define MTK_MODE_CTR			BIT(10)
#define MTK_MODE_RFC3686		BIT(11)
#define MTK_MODE_MASK			GENMASK(10, 8)

/* cipher encryption/decryption operations */
#define MTK_ENCRYPT			BIT(12)
#define MTK_DECRYPT			BIT(13)

#define MTK_BUSY			BIT(14)

/* descriptor flags */
#define MTK_DESC_ASYNC			BIT(31)
#define MTK_DESC_SKCIPHER		BIT(30)
#define MTK_DESC_AEAD			BIT(29)
#define MTK_DESC_AHASH			BIT(28)
#define MTK_DESC_PRNG			BIT(27)
#define MTK_DESC_FAKE_HMAC		BIT(26)
#define MTK_DESC_LAST			BIT(25)
#define MTK_DESC_FINISH			BIT(24)
#define MTK_DESC_IPSEC			BIT(23)
#define MTK_DESC_DMA_IV			BIT(22)

#define IS_DES(flags)			(flags & MTK_ALG_DES)
#define IS_3DES(flags)			(flags & MTK_ALG_3DES)
#define IS_AES(flags)			(flags & MTK_ALG_AES)

#define IS_HASH_MD5(flags)		(flags & MTK_HASH_MD5)
#define IS_HASH_SHA1(flags)		(flags & MTK_HASH_SHA1)
#define IS_HASH_SHA224(flags)		(flags & MTK_HASH_SHA224)
#define IS_HASH_SHA256(flags)		(flags & MTK_HASH_SHA256)
#define IS_HMAC(flags)			(flags & MTK_HASH_HMAC)

#define IS_CBC(mode)			(mode & MTK_MODE_CBC)
#define IS_ECB(mode)			(mode & MTK_MODE_ECB)
#define IS_CTR(mode)			(mode & MTK_MODE_CTR)
#define IS_RFC3686(mode)		(mode & MTK_MODE_RFC3686)

#define IS_BUSY(flags)			(flags & MTK_BUSY)
#define IS_DMA_IV(flags)		(flags & MTK_DESC_DMA_IV)

#define IS_ENCRYPT(dir)			(dir & MTK_ENCRYPT)
#define IS_DECRYPT(dir)			(dir & MTK_DECRYPT)

#define IS_CIPHER(flags)		(flags & (MTK_ALG_DES || \
						MTK_ALG_3DES ||  \
						MTK_ALG_AES))

#define IS_HASH(flags)			(flags & (MTK_HASH_MD5 ||  \
						MTK_HASH_SHA1 ||   \
						MTK_HASH_SHA224 || \
						MTK_HASH_SHA256))

/*
 * Interrupts of EIP93
 */

enum EIP93_InterruptSource_t {
	EIP93_INT_PE_CDRTHRESH_REQ =	BIT(0),
	EIP93_INT_PE_RDRTHRESH_REQ =	BIT(1),
	EIP93_INT_PE_OPERATION_DONE =	BIT(9),
	EIP93_INT_PE_INBUFTHRESH_REQ =	BIT(10),
	EIP93_INT_PE_OUTBURTHRSH_REQ =	BIT(11),
	EIP93_INT_PE_PRNG_IRQ =		BIT(12),
	EIP93_INT_PE_ERR_REG =		BIT(13),
	EIP93_INT_PE_RD_DONE_IRQ =	BIT(16),
};

union saCmd0 {
	u32	word;
	struct {
		u32 opCode		:3;
		u32 direction		:1;
		u32 opGroup		:2;
		u32 padType		:2;
		u32 cipher		:4;
		u32 hash		:4;
		u32 reserved2		:1;
		u32 scPad		:1;
		u32 extPad		:1;
		u32 hdrProc		:1;
		u32 digestLength	:4;
		u32 ivSource		:2;
		u32 hashSource		:2;
		u32 saveIv		:1;
		u32 saveHash		:1;
		u32 reserved1		:2;
	} bits;
} __packed;

union saCmd1 {
	u32	word;
	struct {
		u32 copyDigest		:1;
		u32 copyHeader		:1;
		u32 copyPayload		:1;
		u32 copyPad		:1;
		u32 reserved4		:4;
		u32 cipherMode		:2;
		u32 reserved3		:1;
		u32 sslMac		:1;
		u32 hmac		:1;
		u32 byteOffset		:1;
		u32 reserved2		:2;
		u32 hashCryptOffset	:8;
		u32 aesKeyLen		:3;
		u32 reserved1		:1;
		u32 aesDecKey		:1;
		u32 seqNumCheck		:1;
		u32 reserved0		:2;
	} bits;
} __packed;

struct saRecord_s {
	union saCmd0	saCmd0;
	union saCmd1	saCmd1;
	u32		saKey[8];
	u32		saIDigest[8];
	u32		saODigest[8];
	u32		saSpi;
	u32		saSeqNum[2];
	u32		saSeqNumMask[2];
	u32		saNonce;
} __packed;

struct saState_s {
	u32	stateIv[4];
	u32	stateByteCnt[2];
	u32	stateIDigest[8];
} __packed;

union peCrtlStat_w {
	u32 word;
	struct {
		u32 hostReady		:1;
		u32 peReady		:1;
		u32 reserved		:1;
		u32 initArc4		:1;
		u32 hashFinal		:1;
		u32 haltMode		:1;
		u32 prngMode		:2;
		u32 padValue		:8;
		u32 errStatus		:8;
		u32 padCrtlStat		:8;
	} bits;
} __packed;

union  peLength_w {
	u32 word;
	struct {
		u32 length		:20;
		u32 reserved		:2;
		u32 hostReady		:1;
		u32 peReady		:1;
		u32 byPass		:8;
	} bits;
} __packed;

struct eip93_descriptor_s {
	union peCrtlStat_w	peCrtlStat;
	u32			srcAddr;
	u32			dstAddr;
	u32			saAddr;
	u32			stateAddr;
	u32			arc4Addr;
	u32			userId;
	union peLength_w	peLength;
} __packed;

void mtk_set_saRecord(struct saRecord_s *saRecord, const unsigned int keylen,
				const u32 flags);

int check_valid_request(struct mtk_cipher_reqctx *rctx);

void mtk_unmap_dma(struct mtk_device *mtk, struct mtk_cipher_reqctx *rctx,
			struct scatterlist *reqsrc, struct scatterlist *reqdst);

int mtk_send_req(struct crypto_async_request *async,
			const u8 *reqiv, struct mtk_cipher_reqctx *rctx);

void mtk_handle_result(struct mtk_device *mtk, struct mtk_cipher_reqctx *rctx,
			u8 *reqiv); //, unsigned int ctxassoclen);

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
