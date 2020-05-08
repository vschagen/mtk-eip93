/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */

inline void *mtk_ring_next_wptr(struct mtk_device *mtk,
					struct mtk_desc_ring *ring);

inline void *mtk_ring_next_rptr(struct mtk_device *mtk,
					struct mtk_desc_ring *ring);

inline void mtk_ring_rollback_wptr(struct mtk_device *mtk,
					struct mtk_desc_ring *ring);

inline struct eip93_descriptor_s *mtk_add_cdesc(struct mtk_device *mtk);

inline struct eip93_descriptor_s *mtk_add_rdesc(struct mtk_device *mtk);
