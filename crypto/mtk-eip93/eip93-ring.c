// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include "eip93-common.h"
#include "eip93-main.h"

inline void *mtk_ring_next_wptr(struct mtk_device *mtk,
						struct mtk_desc_ring *ring)
{
	void *ptr = ring->write;

	if ((ring->write == ring->read - ring->offset) ||
		(ring->read == ring->base && ring->write == ring->base_end))
		return ERR_PTR(-ENOMEM);

	if (ring->write == ring->base_end)
		ring->write = ring->base;
	else
		ring->write += ring->offset;

	return ptr;
}

inline void *mtk_ring_next_rptr(struct mtk_device *mtk,
						struct mtk_desc_ring *ring)
{
	void *ptr = ring->read;

	if (ring->write == ring->read)
		return ERR_PTR(-ENOENT);

	if (ring->read == ring->base_end)
		ring->read = ring->base;
	else
		ring->read += ring->offset;

	return ptr;
}

inline int mtk_put_descriptor(struct mtk_device *mtk,
					struct eip93_descriptor_s *desc)
{
	struct eip93_descriptor_s *cdesc;
	struct eip93_descriptor_s *rdesc;
	unsigned long irqflags;

	spin_lock_irqsave(&mtk->ring->write_lock, irqflags);

	rdesc = mtk_ring_next_wptr(mtk, &mtk->ring->rdr);

	if (IS_ERR(rdesc)) {
		spin_unlock_irqrestore(&mtk->ring->write_lock, irqflags);
		return -ENOENT;
	}

	cdesc = mtk_ring_next_wptr(mtk, &mtk->ring->cdr);

	if (IS_ERR(cdesc)) {
		spin_unlock_irqrestore(&mtk->ring->write_lock, irqflags);
		return -ENOENT;
	}

	memset(rdesc, 0, sizeof(struct eip93_descriptor_s));

	memcpy(cdesc, desc, sizeof(struct eip93_descriptor_s));

	atomic_dec(&mtk->ring->free);
	spin_unlock_irqrestore(&mtk->ring->write_lock, irqflags);

	return 0;
}

inline void *mtk_get_descriptor(struct mtk_device *mtk)
{
	struct eip93_descriptor_s *cdesc;
	void *ptr;
	unsigned long irqflags;

	spin_lock_irqsave(&mtk->ring->read_lock, irqflags);

	cdesc = mtk_ring_next_rptr(mtk, &mtk->ring->cdr);

	if (IS_ERR(cdesc)) {
		spin_unlock_irqrestore(&mtk->ring->read_lock, irqflags);
		return ERR_PTR(-ENOENT);
	}

	memset(cdesc, 0, sizeof(struct eip93_descriptor_s));

	ptr = mtk_ring_next_rptr(mtk, &mtk->ring->rdr);
	if (IS_ERR(ptr)) {
		spin_unlock_irqrestore(&mtk->ring->read_lock, irqflags);
		return ERR_PTR(-ENOENT);
	}

	atomic_inc(&mtk->ring->free);
	spin_unlock_irqrestore(&mtk->ring->read_lock, irqflags);
	return ptr;
}

inline int mtk_get_free_saState(struct mtk_device *mtk)
{
	struct mtk_state_pool *saState_pool;
	int i;

	for (i = 0; i < MTK_RING_SIZE; i++) {
		saState_pool = &mtk->ring->saState_pool[i];
		if (saState_pool->in_use == false) {
			saState_pool->in_use = true;
			return i;
		}

	}

	return -ENOENT;
}
