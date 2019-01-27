/*
 * Copyright (c) 2018 Richard van Schagen. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/rng.h>
#include <crypto/rng.h>
#include <crypto/sha.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/types.h>

#include "eip93-core.h"

/* key size in bytes */
#define MTK_SHA_HMAC_KEY_SIZE		64
#define MTK_MAX_CIPHER_KEY_SIZE		AES_KEYSIZE_256

/* IV length in bytes */
#define MTK_AES_IV_LENGTH			AES_BLOCK_SIZE
/* max of AES_BLOCK_SIZE, DES3_EDE_BLOCK_SIZE */
#define MTK_MAX_IV_SIZE				AES_BLOCK_SIZE

/* maximum nonce bytes  */
#define MTK_MAX_NONCE				16
#define MTK_MAX_NONCE_WORDS			(MTK_MAX_NONCE / sizeof(u32))

/* burst size alignment requirement */
#define MTK_MAX_ALIGN_SIZE			64

/* cipher algorithms */
#define MTK_ALG_DES				BIT(0)
#define MTK_ALG_3DES			BIT(1)
#define MTK_ALG_AES				BIT(2)

/* hash and hmac algorithms */
#define MTK_HASH_SHA1			BIT(3)
#define MTK_HASH_SHA256			BIT(4)
#define MTK_HASH_SHA1_HMAC		BIT(5)
#define MTK_HASH_SHA256_HMAC	BIT(6)
#define MTK_HASH_AES_CMAC		BIT(7)

/* cipher modes */
#define MTK_MODE_CBC			BIT(8)
#define MTK_MODE_ECB			BIT(9)
#define MTK_MODE_CTR			BIT(10)
//#define MTK_MODE_XTS			BIT(11)
//#define MTK_MODE_CCM			BIT(12)
#define MTK_MODE_MASK			GENMASK(12, 8)

/* cipher encryption/decryption operations */
#define MTK_ENCRYPT				BIT(13)
#define MTK_DECRYPT				BIT(14)

#define IS_DES(flags)			(flags & MTK_ALG_DES)
#define IS_3DES(flags)			(flags & MTK_ALG_3DES)
#define IS_AES(flags)			(flags & MTK_ALG_AES)

#define IS_SHA1(flags)			(flags & MTK_HASH_SHA1)
#define IS_SHA256(flags)		(flags & MTK_HASH_SHA256)
#define IS_SHA1_HMAC(flags)		(flags & MTK_HASH_SHA1_HMAC)
#define IS_SHA256_HMAC(flags)	(flags & MTK_HASH_SHA256_HMAC)
#define IS_CMAC(flags)			(flags & MTK_HASH_AES_CMAC)
#define IS_SHA(flags)			(IS_SHA1(flags) || IS_SHA256(flags))
#define IS_SHA_HMAC(flags)		\
		(IS_SHA1_HMAC(flags) || IS_SHA256_HMAC(flags))

#define IS_CBC(mode)			(mode & MTK_MODE_CBC)
#define IS_ECB(mode)			(mode & MTK_MODE_ECB)
#define IS_CTR(mode)			(mode & MTK_MODE_CTR)
//#define IS_XTS(mode)			(mode & MTK_MODE_XTS)
//#define IS_CCM(mode)			(mode & MTK_MODE_CCM)

#define IS_ENCRYPT(dir)			(dir & MTK_ENCRYPT)
#define IS_DECRYPT(dir)			(dir & MTK_DECRYPT)

#define HASH_DIGEST_OUT			0
#define HASH_DIGEST_IN			1
#define CRYPTO_ENCRYPTION		1
#define CRYPTO_DECRYPTION		2

#define MTK_RING_SIZE			256
#define NUM_AES_BYPASS			250
#define MTK_QUEUE_LENGTH		128
/*
 * Interrupts of EIP93
 */
typedef enum
{
    EIP93_INT_PE_CDRTHRESH_REQ =   BIT(0),
    EIP93_INT_PE_RDRTHRESH_REQ =   BIT(1),
    EIP93_INT_PE_OPERATION_DONE =  BIT(9),
    EIP93_INT_PE_INBUFTHRESH_REQ = BIT(10),
    EIP93_INT_PE_OUTBURTHRSH_REQ = BIT(11),
    EIP93_INT_PE_ERR_REG =         BIT(13),
    EIP93_INT_PE_RD_DONE_IRQ =     BIT(16)

} EIP93_InterruptSource_t;

typedef union
{
	struct
	{
		unsigned int opCode			: 3;
		unsigned int direction		: 1;
		unsigned int opGroup		: 2;
		unsigned int padType		: 2;
		unsigned int cipher			: 4;
		unsigned int hash			: 4;
		unsigned int reserved2		: 1;
		unsigned int scPad			: 1;
		unsigned int extPad			: 1;
		unsigned int hdrProc		: 1;
		unsigned int digestLength	: 4;
		unsigned int ivSource		: 2;
		unsigned int hashSource		: 2;
		unsigned int saveIv			: 1;
		unsigned int saveHash		: 1;
		unsigned int reserved1		: 2;
	} bits;
	unsigned int word;

} saCmd0_t;

typedef union
{
	struct
	{
		unsigned int copyDigest			: 1;
		unsigned int copyHeader			: 1;
		unsigned int copyPayload		: 1;
		unsigned int copyPad			: 1;
		unsigned int reserved4			: 4;
		unsigned int cipherMode			: 2;
		unsigned int reserved3			: 1;
		unsigned int sslMac				: 1;
		unsigned int hmac				: 1;
		unsigned int byteOffset			: 1;
		unsigned int reserved2			: 2;
		unsigned int hashCryptOffset	: 8;
		unsigned int aesKeyLen			: 3;
		unsigned int reserved1			: 1;
		unsigned int aesDecKey			: 1;
		unsigned int seqNumCheck		: 1;
		unsigned int reserved0			: 2;
	} bits;
	unsigned int word;

} saCmd1_t;

typedef struct saRecord_s
{
	saCmd0_t		saCmd0;
	saCmd1_t		saCmd1;
	unsigned int	saKey[8];
	unsigned int	saIDigest[8];
	unsigned int	saODigest[8];
	unsigned int	saSpi;
	unsigned int	saSeqNum[2];
	unsigned int	saSeqNumMask[2];
	unsigned int	saNonce;
} saRecord_t;

typedef struct saState_s
{
	unsigned int	stateIv[4];
	unsigned int	stateByteCnt[2];
	unsigned int	stateIDigest[8];
} saState_t;

typedef union
{
	struct
	{
		unsigned int hostReady		: 1;
		unsigned int peReady		: 1;
		unsigned int reserved		: 1;
		unsigned int initArc4		: 1;
		unsigned int hashFinal		: 1;
		unsigned int haltMode		: 1;
		unsigned int prngMode		: 2;
		unsigned int padValue		: 8;
		unsigned int errStatus		: 8;
		unsigned int padCrtlStat	: 8;
	} bits;
	unsigned int word;	
} peCrtlStat_t;

typedef union
{
	struct
	{
		unsigned int length			: 20;
		unsigned int reserved		: 2;
		unsigned int hostReady		: 1;
		unsigned int peReady		: 1;
		unsigned int byPass			: 8;
	} bits;	
	unsigned int word;		
} peLength_t;

typedef struct eip93DescpHandler_s
{
	peCrtlStat_t	peCrtlStat;
	unsigned int	srcAddr;
	unsigned int	dstAddr;
	unsigned int	saAddr;
	unsigned int	stateAddr;
	unsigned int	arc4Addr;
	unsigned int	userId;
	peLength_t		peLength;
} eip93DescpHandler_t;

struct mtk_alg_template {
	struct list_head entry;
	u32 crypto_alg_type;
	unsigned long alg_flags;
	const u32 *std_iv;
	union {
		struct crypto_alg crypto;
		struct ahash_alg ahash;
		struct rng_alg rng;
	} alg;
	struct mtk_device *mtk;
};

#endif /* _COMMON_H_ */
