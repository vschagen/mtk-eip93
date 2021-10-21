/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _EIP93_MAIN_H_
#define _EIP93_MAIN_H_

#include <crypto/internal/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/rng.h>
#include <crypto/internal/skcipher.h>
#include <linux/device.h>

/**
 * struct mtk_device - crypto engine device structure
 */
struct mtk_device {
	void __iomem		*base;
	struct device		*dev;
	struct clk		*clk;
	int			irq;
	struct mtk_ring		*ring;
	struct mtk_state_pool	*saState_pool;
};

struct mtk_desc_ring {
	void			*base;
	void			*base_end;
	dma_addr_t		base_dma;
	/* write and read pointers */
	void			*read;
	void			*write;
	/* descriptor element offset */
	u32			offset;
};

struct mtk_state_pool {
	void			*base;
	dma_addr_t		base_dma;
	bool			in_use;
};

struct mtk_ring {
	struct tasklet_struct		done_task;
	/* command/result rings */
	struct mtk_desc_ring		cdr;
	struct mtk_desc_ring		rdr;
	spinlock_t			write_lock;
	spinlock_t			read_lock;
	atomic_t			free;
	/* saState */
	struct mtk_state_pool		*saState_pool;
	void				*saState;
	dma_addr_t			saState_dma;
};

enum mtk_alg_type {
	MTK_ALG_TYPE_AEAD,
	MTK_ALG_TYPE_SKCIPHER,
};

struct mtk_alg_template {
	struct mtk_device	*mtk;
	enum mtk_alg_type	type;
	u32			flags;
	union {
		struct aead_alg		aead;
		struct skcipher_alg	skcipher;
	} alg;
};

inline void mtk_irq_disable(struct mtk_device *mtk, u32 mask);

inline void mtk_irq_enable(struct mtk_device *mtk, u32 mask);

inline void mtk_irq_clear(struct mtk_device *mtk, u32 mask);

#endif /* _EIP93_MAIN_H_ */
