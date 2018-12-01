/*
 * Copyright (c) 2010-2014, The Linux Foundation. All rights reserved.
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

#include "core-eip93.h"

/* ============ BIT_n ============ */

// using postfix "U" to be compatible with uint32
// ("UL" is not needed and gives lint warning)
#define BIT_0   0x00000001U
#define BIT_1   0x00000002U
#define BIT_2   0x00000004U
#define BIT_3   0x00000008U
#define BIT_4   0x00000010U
#define BIT_5   0x00000020U
#define BIT_6   0x00000040U
#define BIT_7   0x00000080U
#define BIT_8   0x00000100U
#define BIT_9   0x00000200U
#define BIT_10  0x00000400U
#define BIT_11  0x00000800U
#define BIT_12  0x00001000U
#define BIT_13  0x00002000U
#define BIT_14  0x00004000U
#define BIT_15  0x00008000U
#define BIT_16  0x00010000U
#define BIT_17  0x00020000U
#define BIT_18  0x00040000U
#define BIT_19  0x00080000U
#define BIT_20  0x00100000U
#define BIT_21  0x00200000U
#define BIT_22  0x00400000U
#define BIT_23  0x00800000U
#define BIT_24  0x01000000U
#define BIT_25  0x02000000U
#define BIT_26  0x04000000U
#define BIT_27  0x08000000U
#define BIT_28  0x10000000U
#define BIT_29  0x20000000U
#define BIT_30  0x40000000U
#define BIT_31  0x80000000U


/* ============ MASK_n_BITS ============ */

#define MASK_1_BIT      (BIT_1 - 1)
#define MASK_2_BITS     (BIT_2 - 1)
#define MASK_3_BITS     (BIT_3 - 1)
#define MASK_4_BITS     (BIT_4 - 1)
#define MASK_5_BITS     (BIT_5 - 1)
#define MASK_6_BITS     (BIT_6 - 1)
#define MASK_7_BITS     (BIT_7 - 1)
#define MASK_8_BITS     (BIT_8 - 1)
#define MASK_9_BITS     (BIT_9 - 1)
#define MASK_10_BITS    (BIT_10 - 1)
#define MASK_11_BITS    (BIT_11 - 1)
#define MASK_12_BITS    (BIT_12 - 1)
#define MASK_13_BITS    (BIT_13 - 1)
#define MASK_14_BITS    (BIT_14 - 1)
#define MASK_15_BITS    (BIT_15 - 1)
#define MASK_16_BITS    (BIT_16 - 1)
#define MASK_17_BITS    (BIT_17 - 1)
#define MASK_18_BITS    (BIT_18 - 1)
#define MASK_19_BITS    (BIT_19 - 1)
#define MASK_20_BITS    (BIT_20 - 1)
#define MASK_21_BITS    (BIT_21 - 1)
#define MASK_22_BITS    (BIT_22 - 1)
#define MASK_23_BITS    (BIT_23 - 1)
#define MASK_24_BITS    (BIT_24 - 1)
#define MASK_25_BITS    (BIT_25 - 1)
#define MASK_26_BITS    (BIT_26 - 1)
#define MASK_27_BITS    (BIT_27 - 1)
#define MASK_28_BITS    (BIT_28 - 1)
#define MASK_29_BITS    (BIT_29 - 1)
#define MASK_30_BITS    (BIT_30 - 1)
#define MASK_31_BITS    (BIT_31 - 1)


/* key size in bytes */
#define MTK_SHA_HMAC_KEY_SIZE		64
#define MTK_MAX_CIPHER_KEY_SIZE		AES_KEYSIZE_256

/* IV length in bytes */
#define MTK_AES_IV_LENGTH		AES_BLOCK_SIZE
/* max of AES_BLOCK_SIZE, DES3_EDE_BLOCK_SIZE */
#define MTK_MAX_IV_SIZE			AES_BLOCK_SIZE

/* maximum nonce bytes  */
#define MTK_MAX_NONCE			16
#define MTK_MAX_NONCE_WORDS		(MTK_MAX_NONCE / sizeof(u32))

/* burst size alignment requirement */
#define MTK_MAX_ALIGN_SIZE		64

/* cipher algorithms */
#define MTK_ALG_DES			BIT(0)
#define MTK_ALG_3DES			BIT(1)
#define MTK_ALG_AES			BIT(2)

/* hash and hmac algorithms */
#define MTK_HASH_SHA1			BIT(3)
#define MTK_HASH_SHA256			BIT(4)
#define MTK_HASH_SHA1_HMAC		BIT(5)
#define MTK_HASH_SHA256_HMAC		BIT(6)
#define MTK_HASH_AES_CMAC		BIT(7)

/* cipher modes */
#define MTK_MODE_CBC			BIT(8)
#define MTK_MODE_ECB			BIT(9)
#define MTK_MODE_CTR			BIT(10)
//#define MTK_MODE_XTS			BIT(11)
//#define MTK_MODE_CCM			BIT(12)
//#define MTK_MODE_MASK			GENMASK(12, 8)

/* cipher encryption/decryption operations */
#define MTK_ENCRYPT			BIT(13)
#define MTK_DECRYPT			BIT(14)

#define IS_DES(flags)			(flags & MTK_ALG_DES)
#define IS_3DES(flags)			(flags & MTK_ALG_3DES)
#define IS_AES(flags)			(flags & MTK_ALG_AES)

#define IS_SHA1(flags)			(flags & MTK_HASH_SHA1)
#define IS_SHA256(flags)		(flags & MTK_HASH_SHA256)
#define IS_SHA1_HMAC(flags)		(flags & MTK_HASH_SHA1_HMAC)
#define IS_SHA256_HMAC(flags)		(flags & MTK_HASH_SHA256_HMAC)
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

#define MTK_RING_SIZE			512
#define NUM_AES_BYPASS			250
#define MTK_QUEUE_LENGTH		64
/*
 * Interrupts of EIP93
 */
typedef enum
{
    EIP93_INT_PE_CDRTHRESH_REQ =   BIT_0,
    EIP93_INT_PE_RDRTHRESH_REQ =   BIT_1,
    EIP93_INT_PE_OPERATION_DONE =  BIT_9,
    EIP93_INT_PE_INBUFTHRESH_REQ = BIT_10,
    EIP93_INT_PE_OUTBURTHRSH_REQ = BIT_11,
    EIP93_INT_PE_ERR_REG =         BIT_13,
    EIP93_INT_PE_RD_DONE_IRQ =     BIT_16

} EIP93_InterruptSource_t;

typedef union
{
	struct
	{
		unsigned int opCode		: 3;
		unsigned int direction		: 1;
		unsigned int opGroup		: 2;
		unsigned int padType		: 2;
		unsigned int cipher		: 4;
		unsigned int hash		: 4;
		unsigned int reserved2		: 1;
		unsigned int scPad		: 1;
		unsigned int extPad		: 1;
		unsigned int hdrProc		: 1;
		unsigned int digestLength	: 4;
		unsigned int ivSource		: 2;
		unsigned int hashSource		: 2;
		unsigned int saveIv		: 1;
		unsigned int saveHash		: 1;
		unsigned int reserved1		: 2;
	} bits;
	unsigned int word;

} saCmd0_t;

typedef union
{
	struct
	{
		unsigned int copyDigest		: 1;
		unsigned int copyHeader		: 1;
		unsigned int copyPayload	: 1;
		unsigned int copyPad		: 1;
		unsigned int reserved4		: 4;
		unsigned int cipherMode		: 2;
		unsigned int reserved3		: 1;
		unsigned int sslMac		: 1;
		unsigned int hmac		: 1;
		unsigned int byteOffset		: 1;
		unsigned int reserved2		: 2;
		unsigned int hashCryptOffset	: 8;
		unsigned int aesKeyLen		: 3;
		unsigned int reserved1		: 1;
		unsigned int aesDecKey		: 1;
		unsigned int seqNumCheck	: 1;
		unsigned int reserved0		: 2;
	} bits;
	unsigned int word;

} saCmd1_t;

typedef struct saRecord_s
{
	saCmd0_t	saCmd0;
	saCmd1_t	saCmd1;
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
		unsigned int length		: 20;
		unsigned int reserved		: 2;
		unsigned int hostReady		: 1;
		unsigned int peReady		: 1;
		unsigned int byPass		: 8;	
	} bits;	
	unsigned int word;		
} peLength_t;

typedef struct addrHandler_s
{
	unsigned int	addr;
	dma_addr_t	phyAddr;
} addrHandler_t;

typedef struct eip93DescpHandler_s
{
	peCrtlStat_t	peCrtlStat;
	unsigned int	srcAddr;
	unsigned int	dstAddr;
	unsigned int	saAddr;
	unsigned int	stateAddr;
	unsigned int	arc4Addr;
	unsigned int	userId;
	peLength_t	peLength;
} eip93DescpHandler_t;

typedef struct addrsDigestPreCompute_s
{
	unsigned int		*hashKeyTank;
	addrHandler_t		ipadHandler;
	addrHandler_t		opadHandler;
	unsigned int		blkSize;
	eip93DescpHandler_t	*cmdHandler;
	addrHandler_t		saHandler;
	addrHandler_t		stateHandler;
	addrHandler_t		stateHandler2;
	unsigned int		digestWord;
	unsigned int		*pIDigest;
	unsigned int		*pODigest;
} addrsDigestPreCompute_t;

typedef struct ipsecEip93Adapter_s
{
	unsigned int 		spi; //every ipsec flow has a unique spi
	struct xfrm_state 	*x; //the SA
	unsigned int 		isHashPreCompute; //0:pre-compute init, 1:inner digest done, 2:inner digest done, 3:pre-compute done
	unsigned int 		isEncryptOrDecrypt; //1:encrypt, 2:decrypt
	struct sk_buff_head	skbQueue;
	addrsDigestPreCompute_t	*addrsPreCompute; //for hash pre-compute
	eip93DescpHandler_t	*cmdHandler; //for encrypt/decrypt
	spinlock_t		lock;
	unsigned int		addedLen; //refer to ssh_hwaccel_alloc_combined() in safenet_la.c
} ipsecEip93Adapter_t;


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
