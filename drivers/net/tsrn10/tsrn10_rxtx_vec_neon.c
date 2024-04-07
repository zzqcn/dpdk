#include <stdint.h>
#include <stdlib.h>

#include <rte_malloc.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION
#include <rte_mbuf.h>
#include <rte_net.h>
#endif
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include "base/tsrn10_hw.h"
#include "tsrn10_ptp.h"
#include "tsrn10.h"
#include "tsrn10_logs.h"

#include <arm_neon.h>

#pragma GCC diagnostic ignored "-Wcast-qual"

static __rte_always_inline int
tsrn10_tx_free_bufs(struct tsrn10_tx_queue *txq)
{
	struct tsrn10_txsw_entry *txep;
	uint32_t n;
	uint32_t i;
	int nb_free = 0;
	struct rte_mbuf *m, *free[64];

	/* check DD bits on threshold descriptor */
	if (!(txq->tx_bdr[txq->tx_next_dd].d.cmd & TSRN10_DD))
		return 0;

	n = txq->tx_rs_thresh;

	/* first buffer to free from S/W ring is at index
	 * tx_next_dd - (tx_rs_thresh-1)
	 */
	txep = &txq->sw_ring[txq->tx_next_dd - (n - 1)];
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	if (txq->offloads & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
		for (i = 0; i < n; i++) {
			free[i] = txep[i].mbuf;
			txep[i].mbuf = NULL;
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, n);
		goto done;
	}
#endif
	m = rte_pktmbuf_prefree_seg(txep[0].mbuf);
	if (likely(m != NULL)) {
		free[0] = m;
		nb_free = 1;
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (likely(m != NULL)) {
				if (likely(m->pool == free[0]->pool)) {
					free[nb_free++] = m;
				} else {
					rte_mempool_put_bulk(free[0]->pool,
							(void *)free,
							nb_free);
					free[0] = m;
					nb_free = 1;
				}
			}
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, nb_free);
	} else {
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (m != NULL)
				rte_mempool_put(m->pool, m);
		}
	}
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
done:
#endif
	/* buffers were freed, update counters */
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + txq->tx_rs_thresh);
	txq->tx_next_dd = (uint16_t)(txq->tx_next_dd + txq->tx_rs_thresh);
	if (txq->tx_next_dd >= txq->attr.bd_count)
		txq->tx_next_dd = (uint16_t)(txq->tx_rs_thresh - 1);

	return txq->tx_rs_thresh;
}

static __rte_always_inline uint64_t
tx_backlog_entry(struct tsrn10_txsw_entry *txep,
		 struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint64_t tx_bytes = 0;
	int i;

	for (i = 0; i < (int)nb_pkts; ++i) {
		txep[i].mbuf = tx_pkts[i];
		/* Just For Avoid Hardware fault */
		if (unlikely(txep[i].mbuf->data_len > TSRN10_MAC_MAXFRM_SIZE))
			txep[i].mbuf->data_len = 0;
		tx_bytes += tx_pkts[i]->data_len;
	}

	return tx_bytes;
}

static inline void
vtx1(struct tsrn10_tx_queue *txq,
     volatile struct tsrn10_tx_desc *txdp,
     struct rte_mbuf *pkt, uint64_t flags)
{
	uint64_t mac_len = 14;
	uint64_t ip_len = 20;
	uint64_t mac_ip = ip_len | (mac_len << 9);

	uint64_t high_qw = ((uint64_t)flags << (64 - 16)) |
		((uint64_t)mac_ip << 16) |
		((uint64_t)pkt->data_len);
	uint64x2_t vf_addr = {txq->attr.sriov_st << 56, 0};

#if RTE_VERSION_NUM(17, 11, 0, 0) >  RTE_VERSION
	uint64x2_t descriptor = {pkt->buf_physaddr + pkt->data_off, high_qw};
#else
	uint64x2_t descriptor = {pkt->buf_iova + pkt->data_off, high_qw};
#endif
	descriptor = vorrq_u64(descriptor, vf_addr);
	vst1q_u64((uint64_t *)txdp, descriptor);
}

static inline void
vtx(struct tsrn10_tx_queue *txq,
    volatile struct tsrn10_tx_desc *txdp,
    struct rte_mbuf **pkt, uint16_t nb_pkts,  uint64_t flags)
{
	int i;

	for (i = 0; i < nb_pkts; ++i, ++txdp, ++pkt)
		vtx1(txq, txdp, *pkt, flags);
}

uint16_t
tsrn10_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
			    uint16_t nb_pkts)
{
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)tx_queue;
	volatile struct tsrn10_tx_desc *txdp;
	struct tsrn10_txsw_entry *txep;
	uint16_t n, nb_commit, tx_id, tx_record;
	uint64_t flags = TSRN10_EOP;
	uint64_t rs = TSRN10_RS | TSRN10_EOP;
	uint64_t tx_bytes_record = 0;
	int i;

	if (unlikely(!txq->txq_started || !txq->tx_link))
		return 0;

	/* cross rx_thresh boundary is not allowed */
	nb_pkts = RTE_MIN(nb_pkts, txq->tx_rs_thresh);

	if (txq->nb_tx_free < txq->tx_free_thresh)
		tsrn10_tx_free_bufs(txq);

	nb_commit = nb_pkts = (uint16_t)RTE_MIN(txq->nb_tx_free, nb_pkts);
	if (unlikely(nb_pkts == 0))
		return 0;

	tx_record = nb_commit;
	tx_id = txq->tx_tail;
	txdp = &txq->tx_bdr[tx_id];
	txep = &txq->sw_ring[tx_id];

	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free - nb_pkts);

	n = (uint16_t)(txq->attr.bd_count - tx_id);
	if (nb_commit >= n) {
		tx_bytes_record += tx_backlog_entry(txep, tx_pkts, n);

		for (i = 0; i < n - 1; ++i, ++tx_pkts, ++txdp)
			vtx1(txq, txdp, *tx_pkts, flags);

		vtx1(txq, txdp, *tx_pkts++, rs);

		nb_commit = (uint16_t)(nb_commit - n);

		tx_id = 0;
		txq->tx_next_rs = (uint16_t)(txq->tx_rs_thresh - 1);

		/* avoid reach the end of ring */
		txdp = &txq->tx_bdr[tx_id];
		txep = &txq->sw_ring[tx_id];
	}

	tx_bytes_record += tx_backlog_entry(txep, tx_pkts, nb_commit);

	vtx(txq, txdp, tx_pkts, nb_commit, flags);

	tx_id = (uint16_t)(tx_id + nb_commit);
	if (tx_id > txq->tx_next_rs) {
		txq->tx_bdr[txq->tx_next_rs].d.cmd |= TSRN10_RS;
		txq->tx_next_rs =
			(uint16_t)(txq->tx_next_rs + txq->tx_rs_thresh);
	}
	txq->stats.opackets += tx_record;
	txq->stats.obytes += tx_bytes_record;

	txq->tx_tail = tx_id;

	rte_wmb();
	tsrn10_wr_reg(txq->tx_tailreg, tx_id);

	return nb_pkts;
}

#define PKTLEN_SHIFT    0
#define TSRN10_UINT16_BIT (CHAR_BIT * sizeof(uint16_t))

static inline void
tsrn10_desc_to_ptype(struct tsrn10_rx_queue *rxq __rte_unused,
		     uint64x2_t descs[4],
		     struct rte_mbuf **rx_pkts, uint16_t var)
{
	uint32x4_t ptype_msk = {0x60F00000, 0x60F00000,
				0x60F00000, 0x60F00000};
	uint32x4_t hw_parse0, hw_parse1, hw_parses;
	uint32x4_t combine0, combine1, ptypes;
	uint16_t parse_en[4];
	uint16_t ptype[4];
	uint16_t idx;

	/* Get High Four Desc 64 Bit */
	combine0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
			vreinterpretq_u32_u64(descs[2])).val[1];
	combine1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
			vreinterpretq_u32_u64(descs[3])).val[1];
	hw_parse0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
			vreinterpretq_u32_u64(descs[2])).val[0];
	hw_parse1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
			vreinterpretq_u32_u64(descs[3])).val[0];
	/* Get High 32-Bit */
	hw_parses = vzipq_u32(hw_parse0, hw_parse1).val[1];
	/* Get High 32-Bit */
	ptypes = vzipq_u32(combine0, combine1).val[1];
	ptypes = vandq_u32(ptypes, ptype_msk);
	/* Ptype Bit Is Locate Begin 4 bit
	 * So Right Move To Locate Begin Zero Bit
	 */
	ptypes = vshrq_n_u32(ptypes, 4);
	hw_parse0 = vshrq_n_u32(hw_parses, 8);

	ptype[0] = vgetq_lane_u16(vreinterpretq_u16_u32(ptypes), 1);
	ptype[1] = vgetq_lane_u16(vreinterpretq_u16_u32(ptypes), 3);
	ptype[2] = vgetq_lane_u16(vreinterpretq_u16_u32(ptypes), 5);
	ptype[3] = vgetq_lane_u16(vreinterpretq_u16_u32(ptypes), 7);

	parse_en[0] = vgetq_lane_u16(vreinterpretq_u16_u32(hw_parse0), 1);
	parse_en[1] = vgetq_lane_u16(vreinterpretq_u16_u32(hw_parse0), 3);
	parse_en[2] = vgetq_lane_u16(vreinterpretq_u16_u32(hw_parse0), 5);
	parse_en[3] = vgetq_lane_u16(vreinterpretq_u16_u32(hw_parse0), 7);

	for (idx = 0; idx < var; idx++) {
#if 0
		tmp = vreinterpretq_u8_u64(vshrq_n_u64(descs[i], 20));
		tb = tmp;
		printf("vreinterretq_u8_u32 0x%.2x 0x%.2x 0x%.2x 0x%.2x \n"
				    "0x%.2x 0x%.2x 0x%.2x 0x%.2x \n"
				    "0x%.2x 0x%.2x 0x%.2x 0x%.2x\n"
				    "0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
				    tb[0], tb[1], tb[2], tb[3],
				    tb[4], tb[5], tb[6], tb[7],
				    tb[8], tb[9], tb[10], tb[11],
				    tb[12], tb[13], tb[14], tb[15]);

		ptype = vgetq_lane_u16(vreinterpretq_u16_u32(descs[i]), 0);
		printf("vget_laneu16 0 0x%.2x\n", ptype);
		ptype = vgetq_lane_u16(vreinterpretq_u16_u64(descs[i], 0), 1);
		printf("vget_laneu16 1 0x%.2x\n", ptype);
		ptype = vgetq_lane_u16(vshrq_n_u64(descs[i], 0), 2);
		printf("vget_laneu16 2 0x%.2x\n", ptype);
		ptype = vgetq_lane_u16(vshrq_n_u64(descs[i], 0), 3);
		printf("vget_laneu16 3 0x%.2x\n", ptype);
		ptype = vgetq_lane_u16(vshrq_n_u64(descs[i], 0), 4);
		printf("vget_laneu16 4 0x%.2x\n", ptype);
		ptype = vgetq_lane_u16(vshrq_n_u64(descs[i], 0), 5);
		printf("vget_laneu16 5 0x%.2x\n", ptype);
		ptype = vgetq_lane_u16(vshrq_n_u64(descs[i], 0), 6);
		printf("vget_laneu16 6 0x%.2x\n", ptype);
		ptype = vgetq_lane_u16(vshrq_n_u64(descs[i], 0), 7);
		printf("vget_laneu16 7 0x%.2x\n", ptype);
#endif
		if (parse_en[idx] & TSRN10_RX_L3_TYPE_MASK)
			rx_pkts[idx]->packet_type =
				tsrn10_get_rx_parse_ptype(ptype[idx],
						rx_pkts[idx]);
		else
			rx_pkts[idx]->packet_type = RTE_PTYPE_UNKNOWN;
		if (rx_pkts[idx]->vlan_tci) {
			rx_pkts[idx]->packet_type &= ~RTE_PTYPE_L2_MASK;
			rx_pkts[idx]->packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
		}
	}
}

static inline void
desc_to_olflags_v(struct tsrn10_rx_queue *rxq, uint64x2_t descs[4],
		  struct rte_mbuf **rx_pkts, uint16_t var)
{
	uint32x4_t vlan0, vlan1, l3_l4e;
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	union {
		uint16_t e[4];
		uint64_t dword;
	} vol;
#else
	const uint64x2_t mbuf_init = {rxq->mbuf_initializer, 0};
	uint64x2_t rearm[4];
#endif
	uint32x4_t combine0, combine1;
	uint32x4_t flags;
	uint16_t idx;

	/* mask everything except RSS, flow director and VLAN flags
	 * bit2 is for VLAN tag, bit11 for flow director indication
	 * bit13:12 for RSS indication.
	 */
	const uint32x4_t vlan_csum_msk = {
		0xFF000000, 0xFF000000, 0xFF000000, 0xFF000000};
	const uint32x4_t csum_msk = {
		0x7F000000, 0x7F000000, 0x7F000000, 0x7F000000};
	const uint32x4_t cksum_mask = {
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD};

	/* map rss and vlan type to rss hash and vlan flag */
	/* 8 Bit Vlan-Strip-Flag */
	const uint8x16_t vlan_flags = {
		0, 0, 0, 0,
		0, 0, 0, 0,
		RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED,
		0, 0, 0, 0,
		0, 0, 0};
	const uint8x16_t l3_l4e_flags = {
		 (RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		 (RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD) >> 1,
		 0,
		 0,
		 0,
		 0,
		 (RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD |
		  RTE_MBUF_F_RX_IP_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD |
		  RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD |
		  RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		 (RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
		  RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,

		 (RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
		  RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
	};
	/* aggregation desc */
	/* Get High Four Desc 64 Bit */
	combine0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
			vreinterpretq_u32_u64(descs[2])).val[1];
	combine1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
			vreinterpretq_u32_u64(descs[3])).val[1];
	vlan0 = vzipq_u32(combine0, combine1).val[1];
	/* Deal VLAN Flags Detect */
	vlan0 = vandq_u32(vlan0, vlan_csum_msk);
	l3_l4e = vandq_u32(vlan0, csum_msk);
	vlan1 = vshrq_n_u32(vlan0, 28);
	l3_l4e = vshrq_n_u32(l3_l4e, 24);
	/* Right Move 16 Bit Get Vlan Status */
	/* vqtbl1q_u8 vs _mm_shuffle_epi8
	 * vqtbl1q_u8 don't support 16bytes must shift the val to
	 * low 4 bit to find table 0-15
	 */
	vlan0 = vreinterpretq_u32_u8(vqtbl1q_u8(vlan_flags,
				vreinterpretq_u8_u32(vlan1)));
	/* If User Enable Rss Value Must Exist */
	if (rxq->rx_offload_capa & DEV_RX_OFFLOAD_RSS_HASH ||
		rxq->mark_enabled) {
		const uint32x4_t check_msk = {
			RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH,
			RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH};
		const uint32x4_t hash_msk = {
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		const uint8x16_t hash_flag = {
			RTE_MBUF_F_RX_RSS_HASH, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		uint32x4_t hash, hash_tmp;
		combine0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
				vreinterpretq_u32_u64(descs[2])).val[0];
		combine1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
				vreinterpretq_u32_u64(descs[3])).val[0];
		hash_tmp = vzipq_u32(combine0, combine1).val[0];
		hash_tmp = vceqq_u32(~hash_tmp, hash_msk);
		/* if hash_val is zero all 8bit will be 0xf
		 * so vqtbl1q_u8 will get zero
		 * otherwise 8 bit is zero we can get all 8bit is hash_flag r0
		 */
		hash = vreinterpretq_u32_u8(vqtbl1q_u8(hash_flag,
					vreinterpretq_u8_u32(hash_tmp)));
		/* mask the 8bit that we don't wished */
		hash = vandq_u32(hash, check_msk);
		flags = vorrq_u32(vlan0, hash);
		if (rxq->mark_enabled) {
			const uint32x4_t mark_msk = {
				0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF};
			const uint32x4_t mark_match = {
				0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
			const uint32x4_t mark_flow_check =
				vdupq_n_u32(RTE_MBUF_F_RX_FDIR |
						RTE_MBUF_F_RX_FDIR_ID);
			uint32x4_t mark, mark_flow, mark_tmp;
			uint16x8_t mark_turn;
			uint32_t val[4] = {0};

			RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR != (1 << 2));
			RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR_ID != (1 << 13));
			mark = vzipq_u32(combine0, combine1).val[1];
			mark = vandq_u32(mark, mark_msk);
			mark_tmp = vceqq_u32(~mark, mark_match);
			/* Get Mark flags */
			mark_flow = vshlq_n_u32(~mark_tmp, 13);
			mark_flow = vorrq_u32(mark_flow, vshlq_n_u32(~mark_tmp, 2));
			mark_flow = vandq_u32(mark_flow, mark_flow_check);
			mark_turn = vreinterpretq_u16_u32(mark);
			val[0] = vgetq_lane_u16(mark_turn, 0);
			val[1] = vgetq_lane_u16(mark_turn, 2);
			val[2] = vgetq_lane_u16(mark_turn, 4);
			val[3] = vgetq_lane_u16(mark_turn, 6);
			for (idx = 0; idx < var; idx++)
				rx_pkts[idx]->hash.fdir.hi = val[idx];
			flags = vorrq_u32(flags, mark_flow);
		}
	} else {
		flags = vlan0;
	}
	/* Rx-checksum Err Parse */
	if (rxq->rx_offload_capa & DEV_RX_OFFLOAD_CHECKSUM) {
#define TSRN10_CKSUM_IP_ERR	BIT(0)
#define TSRN10_CKSUM_L4_ERR	BIT(1)
#define TSRN10_CKSUM_IN_IP_ERR	BIT(2)
#define TSRN10_CKSUM_TUNNEL_ERR	BIT(3)
		const uint8x16_t cksum_turn = {
			0, TSRN10_CKSUM_IP_ERR,
			TSRN10_CKSUM_L4_ERR,
			TSRN10_CKSUM_L4_ERR | TSRN10_CKSUM_IP_ERR,
			TSRN10_CKSUM_L4_ERR,
			TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_L4_ERR,
			TSRN10_CKSUM_L4_ERR,
			TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_L4_ERR,
			TSRN10_CKSUM_IN_IP_ERR,
			TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_IN_IP_ERR,
			TSRN10_CKSUM_L4_ERR | TSRN10_CKSUM_IN_IP_ERR,
			0,
			TSRN10_CKSUM_IN_IP_ERR | TSRN10_CKSUM_L4_ERR,
			TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_IN_IP_ERR |
			TSRN10_CKSUM_L4_ERR,
			0, 0};
		const uint8x16_t out_cksum_mask = {
			0, 0, TSRN10_CKSUM_TUNNEL_ERR,
			TSRN10_CKSUM_TUNNEL_ERR | TSRN10_CKSUM_L4_ERR,
			TSRN10_CKSUM_TUNNEL_ERR,
			TSRN10_CKSUM_TUNNEL_ERR | TSRN10_CKSUM_L4_ERR,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		uint32x4_t outcksum_flag;
		uint32x4_t l3_l4_mask = {0x0000000F, 0x0000000F,
					 0x0000000F, 0x0000000F};

		outcksum_flag = vshrq_n_u32(l3_l4e, 4);
		/* when the packet is tunnel packent the cksum-err means
		 * will be overthrow the 0,1 bits 0 bit means out-ipcksum-err
		 * 1 bit will be not meaningless
		 * so change hw cksum bit sequenct to driver define */
		l3_l4e = vandq_u32(l3_l4e, l3_l4_mask);
		l3_l4e = vreinterpretq_u32_u8(vqtbl1q_u8(cksum_turn,
					vreinterpretq_u8_u32(l3_l4e)));
		l3_l4e = vorrq_u32(l3_l4e,
				vreinterpretq_u32_u8(vqtbl1q_u8(out_cksum_mask,
					vreinterpretq_u8_u32(outcksum_flag))));
		l3_l4e = vreinterpretq_u32_u8(vqtbl1q_u8(l3_l4e_flags,
					vreinterpretq_u8_u32(l3_l4e)));
		/* then we shift left 1 bit */
		l3_l4e = vshlq_n_u32(l3_l4e, 1);
		/* we need to mask out the reduntant bits */
		l3_l4e = vandq_u32(l3_l4e, cksum_mask);
		flags = vorrq_u32(flags, l3_l4e);
	}
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	vol.e[0] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 0);
	vol.e[1] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 2);
	vol.e[2] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 4);
	vol.e[3] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 6);
	for (idx = 0; idx < var; idx++)
		rx_pkts[idx]->ol_flags = vol.e[idx];
#else
	rearm[0] = vsetq_lane_u64(vgetq_lane_u32(flags, 0), mbuf_init, 1);
	rearm[1] = vsetq_lane_u64(vgetq_lane_u32(flags, 1), mbuf_init, 1);
	rearm[2] = vsetq_lane_u64(vgetq_lane_u32(flags, 2), mbuf_init, 1);
	rearm[3] = vsetq_lane_u64(vgetq_lane_u32(flags, 3), mbuf_init, 1);

	for (idx = 0; idx < var; idx++)
		vst1q_u64((uint64_t *)&rx_pkts[idx]->rearm_data, rearm[idx]);
#endif
}

#define RTE_TSRN10_DESCS_PER_LOOP	(4)
#define RTE_TSRN10_RXQ_REARM_THRESH	(32)

static inline void
tsrn10_rxq_rearm(struct tsrn10_rx_queue *rxq)
{
	int i;
	uint16_t rx_id;
	volatile struct tsrn10_rx_desc *rxdp;
	struct tsrn10_rxsw_entry *rxep = &rxq->sw_ring[rxq->rxrearm_start];
	uint64_t vf_addr = rxq->attr.sriov_st << 56;
	struct rte_mbuf *mb0, *mb1;
	uint64x2_t dma_addr0, dma_addr1;
	uint64x2_t zero = vdupq_n_u64(0);
	uint64_t paddr;
	uint8x8_t p;

	rxdp = rxq->rx_bdr + rxq->rxrearm_start;

	/* Pull 'n' more MBUFs into the software ring */
	if (unlikely(rte_mempool_get_bulk(rxq->mb_pool,
					(void *)rxep,
					RTE_TSRN10_RXQ_REARM_THRESH) < 0)) {
		if (rxq->rxrearm_nb + RTE_TSRN10_RXQ_REARM_THRESH >=
				rxq->attr.bd_count) {
			for (i = 0; i < RTE_TSRN10_DESCS_PER_LOOP; i++) {
				rxep[i].mbuf = NULL;
				vst1q_u64((uint64_t *)&rxdp[i].d, zero);
			}
		}
		rte_eth_devices[rxq->attr.rte_pid].data->rx_mbuf_alloc_failed +=
			RTE_TSRN10_RXQ_REARM_THRESH;
		return;
	}

	p = vld1_u8((uint8_t *)&rxq->mbuf_initializer);
	/* Initialize the mbufs in vector, process 2 mbufs in one loop */
	for (i = 0; i < RTE_TSRN10_RXQ_REARM_THRESH; i += 2, rxep += 2) {
		mb0 = rxep[0].mbuf;
		mb1 = rxep[1].mbuf;

		vst1_u8((uint8_t *)&mb0->rearm_data, p);
#if RTE_VERSION_NUM(17, 11, 0, 0) >  RTE_VERSION
		paddr = mb0->buf_physaddr + RTE_PKTMBUF_HEADROOM;
#else
		paddr = mb0->buf_iova + RTE_PKTMBUF_HEADROOM;
#endif
		paddr |= vf_addr;
		dma_addr0 = vdupq_n_u64(paddr);

		/* flush desc with pa dma_addr */
		vst1q_u64((uint64_t *)&rxdp++->d.pkt_addr, dma_addr0);

		vst1_u8((uint8_t *)&mb1->rearm_data, p);
#if RTE_VERSION_NUM(17, 11, 0, 0) >  RTE_VERSION
		paddr = mb1->buf_physaddr + RTE_PKTMBUF_HEADROOM;
#else
		paddr = mb1->buf_iova + RTE_PKTMBUF_HEADROOM;
#endif
		paddr |= vf_addr;
		dma_addr1 = vdupq_n_u64(paddr);
		vst1q_u64((uint64_t *)&rxdp++->d, dma_addr1);
	}

	rxq->rxrearm_start += RTE_TSRN10_RXQ_REARM_THRESH;
	if (rxq->rxrearm_start >= rxq->attr.bd_count)
		rxq->rxrearm_start = 0;

	rxq->rxrearm_nb -= RTE_TSRN10_RXQ_REARM_THRESH;
	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
			(rxq->attr.bd_count - 1) : (rxq->rxrearm_start - 1));

	/* Update the tail pointer on the NIC */
	rte_wmb();

	tsrn10_wr_reg(rxq->rx_tailreg, rx_id);
}

#if 0
static void  buf_dump(const char *msg, void *ptr, int len)
{
	unsigned char *buf = ptr;
	int i;

	printf("\n%s #%d\n", msg, len);
	for (i = 0; i < len; i++) {
		if (i != 0 && (i % 16) == 0)
			printf("\n");

		printf("%02x ", buf[i]);
	}
	printf("\n");
}
#endif

static inline uint16_t
_recv_raw_pkts_vec(struct tsrn10_rx_queue *rxq, struct rte_mbuf **rx_pkts,
		   uint16_t nb_pkts, uint8_t *split_packet __rte_unused)
{
	volatile struct tsrn10_rx_desc *rxdp;
	struct tsrn10_rxsw_entry *sw_ring;
	uint64_t nb_bytes_recd = 0;
	uint16_t nb_pkts_recd;
	int pos;

	/* mask to shuffle from desc. to mbuf */
	uint8x16_t shuf_msk = {
		0xFF, 0xFF,	/* pkt_type set as unknown */
		0xFF, 0xFF,	/*pkt_type set as unknown */
		8, 9,		/* octet 15~14, low 16 bits pkt_len */
		0xFF, 0xFF,	/* skip high 16 bits pkt_len, zero out */
		8, 9,		/* octet 15~14, 16 bits data_len */
		12, 13,		/* octet 2~3, low 16 bits vlan_macip */
		0, 1, 2, 3,	/* octet 0~3, 32bits rss */
		};

#ifdef PHYTIUM_SUPPORT
	uint8x16_t pad_msk = {
		0xFF, 0xFF,	/* pkt_type set as unknown */
		0xFF, 0xFF,	/*pkt_type set as unknown */
		10, 11,		/* octet 15~14, low 16 bits pkt_len */
		0xFF, 0xFF,	/* skip high 16 bits pkt_len, zero out */
		10, 11,		/* octet 15~14, 16 bits data_len */
		0xFF, 0xFF,	/* octet 2~3, low 16 bits vlan_macip */
		0xFF, 0xFF, 0xFF, 0xFF,	/* octet 0~3, 32bits rss */
	};
#endif
	uint8x16_t eop_check __rte_unused = {
		0x02, 0x00, 0x02, 0x00,
		0x02, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	if (unlikely(!rxq->rxq_started || !rxq->rx_link))
		return 0;
	/* nb_pkts has to be floor-aligned to RTE_TSRN10_DESCS_PER_LOOP */
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, RTE_TSRN10_DESCS_PER_LOOP);

	/* Just the act of getting into the function from the application is
	 * going to cost about 7 cycles
	 */
	rxdp = rxq->rx_bdr + rxq->rx_tail;

	rte_prefetch_non_temporal(rxdp);

	/* See if we need to rearm the RX queue - gives the prefetch a bit
	 * of time to act
	 */
	if (rxq->rxrearm_nb > RTE_TSRN10_RXQ_REARM_THRESH)
		tsrn10_rxq_rearm(rxq);

	/* Before we start moving massive data around, check to see if
	 * there is actually a packet available
	 */
	if (!(rxdp->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD)))
		return 0;
	/* Cache is empty -> need to scan the buffer rings, but first move
	 * the next 'n' mbufs into the cache
	 */
	sw_ring = &rxq->sw_ring[rxq->rx_tail];

	/* A. load 4 packet in one loop
	 * [A*. mask out 4 unused dirty field in desc]
	 * B. copy 4 mbuf point from swring to rx_pkts
	 * C. calc the number of DD bits among the 4 packets
	 * [C*. extract the end-of-packet bit, if requested]
	 * D. fill info. from desc to mbuf
	 */

	for (pos = 0, nb_pkts_recd = 0; pos < nb_pkts;
			pos += RTE_TSRN10_DESCS_PER_LOOP,
			rxdp += RTE_TSRN10_DESCS_PER_LOOP) {
		uint64x2_t descs[RTE_TSRN10_DESCS_PER_LOOP];
		uint8x16_t pkt_mb[4];
#ifdef PHYTIUM_SUPPORT
		uint8x16_t pad_len_tmp;
		uint16x8_t tmp;
#endif
		uint16x8x2_t sterr_tmp1, sterr_tmp2;
		uint64x2_t mbp1, mbp2;
		uint16x8_t staterr;
		uint32x4_t len[4];
		uint64_t stat;
		uint16_t idx;

		int32x4_t len_shl = {0, 0, 0, 0};

		/* B.1 load 1 mbuf point */
		mbp1 = vld1q_u64((uint64_t *)&sw_ring[pos]);
		/* Read desc statuses backwards to avoid race condition */
		/* A.1 load 4 pkts desc */
		descs[3] =  vld1q_u64((uint64_t *)(rxdp + 3));
		/* B.2 copy 2 mbuf point into rx_pkts  */
		vst1q_u64((uint64_t *)&rx_pkts[pos], mbp1);

		/* B.1 load 1 mbuf point */
		mbp2 = vld1q_u64((uint64_t *)&sw_ring[pos + 2]);

		descs[2] =  vld1q_u64((uint64_t *)(rxdp + 2));

		/* B.1 load 2 mbuf point */
		descs[1] =  vld1q_u64((uint64_t *)(rxdp + 1));
		descs[0] =  vld1q_u64((uint64_t *)(rxdp));

		/* B.2 copy 2 mbuf point into rx_pkts  */
		vst1q_u64((uint64_t *)&rx_pkts[pos + 2], mbp2);

		/* pkt 3,4 shift the pktlen field to be 16-bit aligned*/
		len[3] = vshlq_u32(vreinterpretq_u32_u64(descs[3]),
				len_shl);
		descs[3] = vreinterpretq_u64_u32(len[3]);
		len[2] = vshlq_u32(vreinterpretq_u32_u64(descs[2]),
				len_shl);
		descs[2] = vreinterpretq_u64_u32(len[2]);

		/* D.1 pkt 3,4 convert format from desc to pktmbuf */
		pkt_mb[3] = vqtbl1q_u8(vreinterpretq_u8_u64(descs[3]), shuf_msk);
#ifdef PHYTIUM_SUPPORT
		pad_len_tmp = vqtbl1q_u8(vreinterpretq_u8_u64(descs[3]), pad_msk);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb[3]), vreinterpretq_u16_u8(pad_len_tmp));
		pkt_mb[3] = vreinterpretq_u8_u16(tmp);
#endif
		pkt_mb[2] = vqtbl1q_u8(vreinterpretq_u8_u64(descs[2]), shuf_msk);
#ifdef PHYTIUM_SUPPORT
		pad_len_tmp = vqtbl1q_u8(vreinterpretq_u8_u64(descs[2]), pad_msk);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb[2]), vreinterpretq_u16_u8(pad_len_tmp));
		pkt_mb[2] = vreinterpretq_u8_u16(tmp);
#endif
		/* C.1 4=>2 filter staterr info only */
		sterr_tmp2 = vzipq_u16(vreinterpretq_u16_u64(descs[1]),
				vreinterpretq_u16_u64(descs[3]));
		/* C.1 4=>2 filter staterr info only */
		sterr_tmp1 = vzipq_u16(vreinterpretq_u16_u64(descs[0]),
				vreinterpretq_u16_u64(descs[2]));

		/* C.2 get 4 pkts staterr value  */
		staterr = vzipq_u16(sterr_tmp1.val[1],
				sterr_tmp2.val[1]).val[1];

		staterr = vzipq_u16(sterr_tmp1.val[1], sterr_tmp2.val[1]).val[1];

		/* pkt 1,2 shift the pktlen field to be 16-bit aligned*/
		len[1] = vshlq_u32(vreinterpretq_u32_u64(descs[1]),
				len_shl);
		descs[1] = vreinterpretq_u64_u32(len[1]);
		len[0] = vshlq_u32(vreinterpretq_u32_u64(descs[0]),
				len_shl);
		descs[0] = vreinterpretq_u64_u32(len[0]);

		/* D.1 pkt 1,2 convert format from desc to pktmbuf */
		pkt_mb[1] = vqtbl1q_u8(vreinterpretq_u8_u64(descs[1]), shuf_msk);
#ifdef PHYTIUM_SUPPORT
		pad_len_tmp = vqtbl1q_u8(vreinterpretq_u8_u64(descs[1]), pad_msk);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb[1]), vreinterpretq_u16_u8(pad_len_tmp));
		pkt_mb[1] = vreinterpretq_u8_u16(tmp);
#endif

		pkt_mb[0] = vqtbl1q_u8(vreinterpretq_u8_u64(descs[0]), shuf_msk);
#ifdef PHYTIUM_SUPPORT
		pad_len_tmp = vqtbl1q_u8(vreinterpretq_u8_u64(descs[0]), pad_msk);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb[0]), vreinterpretq_u16_u8(pad_len_tmp));
		pkt_mb[0] = vreinterpretq_u8_u16(tmp);
#endif

		staterr = vshlq_n_u16(staterr, TSRN10_UINT16_BIT - 1);
		stat = vgetq_lane_u64(vreinterpretq_u64_u16(staterr), 1);

		/* rte_prefetch_non_temporal(rxdp + RTE_TSRN10_DESCS_PER_LOOP); */
		stat = __builtin_popcountl(stat);
		if (stat) {
			for (idx = 0; idx < stat; idx++) {
				vst1q_u8((void *)&rx_pkts[pos + idx]->rx_descriptor_fields1,
						pkt_mb[idx]);
				if (unlikely(!rx_pkts[pos + idx]->data_len ||
				     !(len[idx][3] & BIT(17)))) {
					/* Just Workarbound For Side Effect*/
					/* TODO Analyze Side Effect Abourt
					 * Descs[2] not load But Fort Descs[0],
					 * Descs[1], Descs[3] Memory Had Been Loaded
					 */
#if 0
					printf("data_len %d\n", rx_pkts[pos + idx]->data_len);
					printf("descs0 0x%llx 0x%llx\n", descs_tmp[0][0], descs_tmp[0][1]);
					printf("descs1 0x%llx 0x%llx\n", descs_tmp[1][0], descs_tmp[1][1]);
					printf("descs2 0x%llx 0x%llx\n", descs_tmp[2][0], descs_tmp[2][1]);
					printf("descs3 0x%llx 0x%llx\n", descs_tmp[3][0], descs_tmp[3][1]);
					printf("len0 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", len0[0], len0[1], len0[2], len0[3]);
					printf("len1 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", len1[0], len1[1], len1[2], len1[3]);
					printf("len2 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", len2[0], len2[1], len2[2], len2[3]);
					printf("len3 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", len3[0], len3[1], len3[2], len3[3]);
					printf("idx[%d] data_len %d\n", idx, rx_pkts[pos + idx]->data_len);
					printf("idx[%d] pkt_len %d\n", idx, rx_pkts[pos + idx]->pkt_len);
					printf("idx %d stat %d\n", idx, stat);
#endif
					break;
				}
				nb_bytes_recd += rx_pkts[pos + idx]->data_len;
			}
			stat = idx;
			if (stat) {
				desc_to_olflags_v(rxq, descs,
						&rx_pkts[pos], stat);
				tsrn10_desc_to_ptype(rxq, descs,
						&rx_pkts[pos], stat);
			}
		}

		if (unlikely(stat == 4)) {
			nb_pkts_recd += RTE_TSRN10_DESCS_PER_LOOP;
			/* This the End of Packet the Large pkt has been recv finish */
			rxq->stats.ipackets += RTE_TSRN10_DESCS_PER_LOOP;
		} else {
			nb_pkts_recd += stat;
			rxq->stats.ipackets += stat;
			break;
		}
	}

	/* Update our internal tail pointer */
	rxq->rx_tail = (uint16_t)(rxq->rx_tail + nb_pkts_recd);
	rxq->rx_tail = (uint16_t)(rxq->rx_tail & (rxq->attr.bd_count - 1));
	rxq->rxrearm_nb = (uint16_t)(rxq->rxrearm_nb + nb_pkts_recd);

	rxq->stats.ibytes += nb_bytes_recd;

	return nb_pkts_recd;
}

uint16_t
tsrn10_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
		     uint16_t nb_pkts)
{
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)rx_queue;
	uint16_t nb_rx = 0, n, ret;

	if (unlikely(!rx_queue))
		return 0;
	if (unlikely(!rxq->rxq_started || nb_pkts == 0))
		return 0;

	if (likely(nb_pkts <= TSRN10_RX_MAX_BURST_SIZE))
		return _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts, NULL);

	while (nb_pkts) {
		n = RTE_MIN(nb_pkts, TSRN10_RX_MAX_BURST_SIZE);
		/* Avoid Cache-Miss Cause Tx HardFault
		 * TODO Analyze This Problem
		 */
		ret = _recv_raw_pkts_vec(rxq, &rx_pkts[nb_rx], n, NULL);
		nb_rx = (uint16_t)(nb_rx + ret);
		nb_pkts = (uint16_t)(nb_pkts - ret);
		if (ret < n)
			break;
	}

	return nb_rx;
}

uint16_t
tsrn10_scattered_burst_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts)
{
	return _recv_raw_pkts_vec(rx_queue, rx_pkts, nb_pkts, NULL);
}
