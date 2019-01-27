/*
 * Copyright (c) 2018 Richard van Schagen. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _CORE_H_
#define _CORE_H_

#include <linux/timex.h>

/**
 * struct mtk_device - crypto engine device structure
 * @queue: crypto request queue
 * @lock: the lock protects queue and req
 * @done_tasklet: done tasklet object
 * @front_idx: dma-idx pointer (to be replaced)
 * @read_idx: dma-idx pointer (to be replaced)
 * @rec: DMA-record structure
 * @result: result of current transform
 * @base: virtual IO base
 * @dev: pointer to device structure number
 * @irq: allocated interrupt
 * @async_req_enqueue: invoked by every algorithm to enqueue a request
 * @async_req_done: invoked by every algorithm to finish its request
 */
struct mtk_device {
	void __iomem			*base;
	struct device			*dev;
	struct clk			*clk;
	int				irq;

	struct eip93DescpHandler_s	*cd;
	struct eip93DescpHandler_s	*rd;
	dma_addr_t			phy_cd;
	dma_addr_t			phy_rd;
	dma_addr_t			phy_rec;
	dma_addr_t			phy_state;
	dma_addr_t			phy_record;

	struct crypto_queue		queue;
//	struct tasklet_struct		done_tasklet;
//	struct tasklet_struct		queue_tasklet;
	unsigned int			rec_front_idx;
	unsigned int			rec_rear_idx;
	struct mtk_dma_rec		*rec;

	struct saState_s		*saState;
	struct saRecord_s		*saRecord;

	int				result;
	int				count;
	
	unsigned int			seed[8];

	int (*async_req_enqueue)(struct mtk_device *mtk,
				 struct crypto_async_request *req);
	void (*async_req_done)(struct mtk_device *mtk, int ret);
	spinlock_t			lock;
};

/**
 * struct mtk_dma_rec - holds the records associated with the ringbuffer
 * @src: Dma address of the source packet
 * @Dst: Dma address of the destination
 * @size: Size of the packet
 * @req: holds the async_request
 */
struct mtk_dma_rec {
	unsigned int			srcDma;
	unsigned int			dstDma;
	unsigned int			dmaLen;
	unsigned int			saddr;
	unsigned int			daddr;
	unsigned int			ssize;
	unsigned int			dsize;
	unsigned int			flags;
	unsigned int			*req;
	unsigned int			result;
};

struct mtk_cipher_drv {
	struct list_head	dev_list;
	spinlock_t		lock;
};

static struct mtk_cipher_drv mtk_cipher = {
	.dev_list = LIST_HEAD_INIT(mtk_cipher.dev_list),
	.lock = __SPIN_LOCK_UNLOCKED(mtk_cipher.lock),
};

/**
 * struct mtk_algo_ops - algorithm operations per crypto type
 * @type: should be CRYPTO_ALG_TYPE_XXX
 * @register_algs: invoked by core to register the algorithms
 * @unregister_algs: invoked by core to unregister the algorithms
 * @async_req_handle: invoked by core to handle enqueued request
 */
struct mtk_algo_ops {
	u32 type;
	int (*register_algs)(struct mtk_device *mtk);
	void (*unregister_algs)(struct mtk_device *mtk);
	int (*async_req_handle)(struct crypto_async_request *async_req);
};

#endif /* _CORE_H_ */
