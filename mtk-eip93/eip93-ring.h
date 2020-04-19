/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */

inline int mtk_ring_first_cdr_index(struct mtk_device *mtk);

inline int mtk_ring_curr_wptr_index(struct mtk_device *mtk);

inline int mtk_ring_curr_rptr_index(struct mtk_device *mtk);

inline int mtk_ring_cdr_index(struct mtk_device *mtk,
					struct eip93_descriptor_s *cdesc);

inline int mtk_ring_rdr_index(struct mtk_device *mtk,
					struct eip93_descriptor_s *rdesc);

inline void *mtk_ring_next_wptr(struct mtk_device *mtk,
					struct mtk_desc_ring *ring, u32 *idx);

inline void *mtk_ring_next_rptr(struct mtk_device *mtk,
					struct mtk_desc_ring *ring, u32 *idx);

inline void mtk_ring_rollback_wptr(struct mtk_device *mtk,
						struct mtk_desc_ring *ring);

inline void *mtk_ring_curr_wptr(struct mtk_device *mtk);

inline void *mtk_ring_curr_rptr(struct mtk_device *mtk);

inline struct eip93_descriptor_s *mtk_add_cdesc(struct mtk_device *mtk,
								u32 *idx);

inline struct eip93_descriptor_s *mtk_add_rdesc(struct mtk_device *mtk,
								u32 *idx);
