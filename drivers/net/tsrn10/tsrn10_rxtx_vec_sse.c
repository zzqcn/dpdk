#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <rte_version.h>
#include <rte_malloc.h>
#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION
#include <rte_mbuf.h>
#include <rte_net.h>
#endif
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_common.h>

#include "base/tsrn10_hw.h"
#include "tsrn10_ptp.h"
#include "tsrn10.h"
#include "tsrn10_logs.h"

#include <tmmintrin.h>
#include <emmintrin.h>

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

static inline void
tsrn10_rxq_rearm(struct tsrn10_rx_queue *rxq);

static inline void
vtx1(struct tsrn10_tx_queue *txq,
     volatile struct tsrn10_tx_desc *txdp,
     struct rte_mbuf *pkt, uint64_t flags)
{
	uint64_t mac_len = 14;
	uint64_t ip_len = 20;
	uint64_t mac_ip = ip_len | (mac_len << 9);
	__m128i vf_addr = _mm_set_epi64x(0,
					txq->attr.sriov_st << 56);

	uint64_t high_qw = ((uint64_t)flags << (64 - 16)) |
		((uint64_t)mac_ip << 16) |
		((uint64_t)pkt->data_len);

	__m128i descriptor = _mm_set_epi64x(high_qw,
#if RTE_VERSION_NUM(17, 11, 0, 0) >  RTE_VERSION
			pkt->buf_physaddr + pkt->data_off);
#else
			pkt->buf_iova + pkt->data_off);
#endif
	descriptor = _mm_or_si128(descriptor, vf_addr);
	_mm_store_si128((__m128i *)txdp, descriptor);
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
		if (unlikely(txep[i].mbuf->data_len  > TSRN10_MAC_MAXFRM_SIZE))
			txep[i].mbuf->data_len = 0;

		tx_bytes += tx_pkts[i]->data_len;
	}

	return tx_bytes;
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
	if (unlikely(nb_pkts == 0)) {
		txq->stats.tx_ring_full++;
		return 0;
	}

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

#define RTE_TSRN10_DESCS_PER_LOOP	(4)
#define PKTLEN_SHIFT			(0)
#define RTE_TSRN10_RXQ_REARM_THRESH	(32)

static inline void
tsrn10_rxq_rearm(struct tsrn10_rx_queue *rxq)
{
	int i;
	uint16_t rx_id;
	volatile struct tsrn10_rx_desc *rxdp;
	struct tsrn10_rxsw_entry *rxep = &rxq->sw_ring[rxq->rxrearm_start];
	struct rte_mbuf *mb0, *mb1;
	__m128i hdr_room = _mm_set_epi64x(RTE_PKTMBUF_HEADROOM,
			RTE_PKTMBUF_HEADROOM);
	__m128i dma_addr0, dma_addr1;
	__m128i vf_addr = _mm_set_epi64x(rxq->attr.sriov_st << 56,
					rxq->attr.sriov_st << 56);

	rxdp = rxq->rx_bdr + rxq->rxrearm_start;
	/* Pull 'n' more MBUFs into the software ring */
	if (rte_mempool_get_bulk(rxq->mb_pool,
				(void *)rxep,
				RTE_TSRN10_RXQ_REARM_THRESH) < 0) {
		if (rxq->rxrearm_nb + RTE_TSRN10_RXQ_REARM_THRESH >=
				rxq->attr.bd_count) {
			dma_addr0 = _mm_setzero_si128();
			for (i = 0; i < RTE_TSRN10_DESCS_PER_LOOP; i++) {
				rxep[i].mbuf = NULL;
				_mm_store_si128((__m128i *)&rxdp[i].d.pkt_addr,
						dma_addr0);
			}
		}
		rte_eth_devices[rxq->attr.rte_pid].data->rx_mbuf_alloc_failed +=
			RTE_TSRN10_RXQ_REARM_THRESH;
		return;
	}

	/* Initialize the mbufs in vector, process 2 mbufs in one loop */
	for (i = 0; i < RTE_TSRN10_RXQ_REARM_THRESH; i += 2, rxep += 2) {
		__m128i vaddr0, vaddr1;
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
		uintptr_t p0, p1;
#endif
		mb0 = rxep[0].mbuf;
		mb1 = rxep[1].mbuf;
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
		/*
		 * Flush mbuf with pkt template.
		 * Data to be rearmed is 6 bytes long.
		 * Though, RX will overwrite ol_flags that are coming next
		 * anyway. So overwrite whole 8 bytes with one load:
		 * 6 bytes of rearm_data plus first 2 bytes of ol_flags.
		 */
		p0 = (uintptr_t)&mb0->rearm_data;
		*(uint64_t *)p0 = rxq->mbuf_initializer;
		p1 = (uintptr_t)&mb1->rearm_data;
		*(uint64_t *)p1 = rxq->mbuf_initializer;
#endif
		/* load buf_addr(lo 64bit) and buf_iova(hi 64bit) */

#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
		RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, buf_iova) !=
				offsetof(struct rte_mbuf, buf_addr) + 8);
#else
		RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, buf_physaddr) !=
				offsetof(struct rte_mbuf, buf_addr) + 8);
#endif
		vaddr0 = _mm_loadu_si128((__m128i *)&mb0->buf_addr);
		vaddr1 = _mm_loadu_si128((__m128i *)&mb1->buf_addr);

		/* convert pa to dma_addr hdr/data */
		dma_addr0 = _mm_unpackhi_epi64(vaddr0, vaddr0);
		dma_addr1 = _mm_unpackhi_epi64(vaddr1, vaddr1);

		/* add headroom to pa values */
		dma_addr0 = _mm_add_epi64(dma_addr0, hdr_room);
		dma_addr1 = _mm_add_epi64(dma_addr1, hdr_room);

		dma_addr0 = _mm_or_si128(dma_addr0, vf_addr);

		dma_addr1 = _mm_or_si128(dma_addr1, vf_addr);
		/* flush desc with pa dma_addr */
		_mm_store_si128((__m128i *)&rxdp++->d.pkt_addr, dma_addr0);
		_mm_store_si128((__m128i *)&rxdp++->d.pkt_addr, dma_addr1);
		/* printf("dma0 %.16llx %.16llx\n", dma_addr0[1], dma_addr0[0]); */

		/* printf("dma1 %.16llx %.16llx\n", dma_addr1[1], dma_addr1[0]); */
	}

	rxq->rxrearm_start += RTE_TSRN10_RXQ_REARM_THRESH;

	if (rxq->rxrearm_start >= rxq->attr.bd_count)
		rxq->rxrearm_start = 0;

	rxq->rxrearm_nb -= RTE_TSRN10_RXQ_REARM_THRESH;

	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
			(rxq->attr.bd_count - 1) : (rxq->rxrearm_start - 1));

	rte_wmb();
	/* Update the tail pointer on the NIC */
	tsrn10_wr_reg(rxq->rx_tailreg, rx_id);
}

#ifdef DEBUG_VECTOR
static void print128_num(__m128i var)
{
	/* can also use uint32_t instead of 16_t */
	uint16_t *val = (uint16_t *)&var;
	printf("Numerical: %i %i %i %i %i %i %i %i \n",
			val[0], val[1], val[2], val[3], val[4], val[5],
			val[6], val[7]);
}

static void print128_u8_num(__m128i var)
{
	/* can also use uint32_t instead of 16_t */
	uint8_t *val = (uint8_t *)&var;
	printf("Numerical: %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i \n",
			val[0], val[1], val[2], val[3], val[4], val[5],
			val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
}

static void print128_u16_num(__m128i var)
{
	/* can also use uint32_t instead of 16_t */
	uint16_t *val = (uint16_t *)&var;
	printf("Numerical u 16: %i %i %i %i %i %i %i %i \n",
			val[0], val[1], val[2], val[3], val[4], val[5],
			val[6], val[7]);
}
#endif

static inline void
tsrn10_rx_desc_parse_field(struct tsrn10_rx_queue *rxq,
		  __m128i descs[4], struct rte_mbuf **rx_pkts, uint16_t var)
{
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	union {
		uint16_t e[4];
		uint64_t dword;
	} vol;
#else
	const __m128i mbuf_init = _mm_set_epi64x(0, rxq->mbuf_initializer);
	__m128i rearm[4];
#endif
	__m128i vlan0, vlan1 __rte_unused, l3_l4e, l3_l4_e, outcksum_flag;
	__m128i combine0, combine1;
	__m128i flags;
	uint8_t idx;
	/* mask everything except RSS, flow director and VLAN flags
	 * bit2 is for VLAN tag, bit11 for flow director indication
	 * bit13:12 for RSS indication.
	 */
	const __m128i vlan_csum_msk = _mm_set_epi32(
			0xFF000000, 0xFF000000, 0xFF000000, 0xFF000000);
	const __m128i csum_msk = _mm_set_epi32(
			0x7F000000, 0x7F000000, 0x7F000000, 0x7F000000);
	const __m128i vlan_flags = _mm_set_epi8(0,
			0, 0, 0, 0,
			0, 0,
			RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED,
			0, 0, 0, 0,
			0, 0, 0, 0);
	const __m128i cksum_mask = _mm_set_epi32(
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
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD);
	const __m128i l3_l4e_flags = _mm_set_epi8(
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			 RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			 RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD |
			 RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD |
			 RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD |
			 RTE_MBUF_F_RX_IP_CKSUM_GOOD) >> 1,
			0,
			0,
			0,
			0,
			(RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1);
	/* aggregation desc */
	combine0 = _mm_unpackhi_epi32(descs[0], descs[1]);
	combine1 = _mm_unpackhi_epi32(descs[2], descs[3]);
	vlan0 = _mm_unpackhi_epi64(combine0, combine1);
	/* Deal VLAN Flags Detect */
	vlan0 = _mm_and_si128(vlan0, vlan_csum_msk);
	l3_l4e = _mm_and_si128(vlan0, csum_msk);
	vlan1 =  _mm_srli_epi32(vlan0, 20);
	l3_l4e = _mm_srli_epi32(l3_l4e, 24);
	/* Right Move 16 Bit Get Vlan Status */
	vlan0 = _mm_shuffle_epi8(vlan_flags, vlan1);
	/* Move VLAN-vaild Bit To Less Than 0-15 bit */
	vlan0 = _mm_srli_epi32(vlan0, 8);
	/* If User Enable Rss Value Must Exist */
	if (rxq->rx_offload_capa & DEV_RX_OFFLOAD_RSS_HASH ||
		rxq->mark_enabled) {
		const __m128i hash_msk = _mm_set_epi32(
				0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);
		const __m128i hash_flag = _mm_set_epi8(
				0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				RTE_MBUF_F_RX_RSS_HASH);

		const __m128i check_msk = _mm_set_epi32(
				RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH,
				RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH);
		__m128i hash, hash_tmp;
		/* check if rss value is zero
		 * use this condition  to set HASH_FLAG
		 */
		combine0 = _mm_unpacklo_epi32(descs[0], descs[1]);
		combine1 = _mm_unpacklo_epi32(descs[2], descs[3]);
		hash_tmp = _mm_unpacklo_epi64(combine0, combine1);
		hash_tmp = _mm_cmpeq_epi32(~hash_tmp, hash_msk);
		hash = _mm_shuffle_epi8(hash_flag, hash_tmp);
		hash = _mm_and_si128(hash, check_msk);
		flags = _mm_or_si128(vlan0, hash);
		if (rxq->mark_enabled) {
			const __m128i mark_msk = _mm_set_epi32(
					0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF);
			const __m128i mark_match = _mm_set_epi32(
					0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);
			const __m128i mark_flow_check = _mm_set1_epi32(RTE_MBUF_F_RX_FDIR |
					RTE_MBUF_F_RX_FDIR_ID);
			__m128i mark, mark_flow, mark_tmp;
			uint32_t val[4] = {0};

			RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR != (1 << 2));
			RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR_ID != (1 << 13));
			mark = _mm_unpackhi_epi64(combine0, combine1);
			mark = _mm_and_si128(mark, mark_msk);
			mark_tmp = _mm_cmpeq_epi32(~mark, mark_match);
			/* Get Mark flags */
			mark_flow = _mm_slli_epi32(~mark_tmp, 13);
			mark_flow = _mm_or_si128(mark_flow, _mm_slli_epi32(~mark_tmp, 2));
			mark_flow = _mm_and_si128(mark_flow, mark_flow_check);
			val[0] = _mm_extract_epi16(mark, 0);
			val[1] = _mm_extract_epi16(mark, 2);
			val[2] = _mm_extract_epi16(mark, 4);
			val[3] = _mm_extract_epi16(mark, 6);
			for (idx = 0; idx < var; idx++)
				 rx_pkts[idx]->hash.fdir.hi = val[idx];
			flags = _mm_or_si128(flags, mark_flow);
		}
	} else {
		flags = vlan0;
	}
	/* L3-L4 Checksum Detect */
	if (rxq->rx_offload_capa & DEV_RX_OFFLOAD_CHECKSUM) {
#define TSRN10_CKSUM_IP_ERR	BIT(0)
#define TSRN10_CKSUM_L4_ERR	BIT(1)
#define TSRN10_CKSUM_IN_IP_ERR	BIT(2)
#define TSRN10_CKSUM_TUNNEL_ERR	BIT(3)
		const __m128i cksum_turn = _mm_set_epi8(
				0, 0,
				TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_IN_IP_ERR |
				TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_IN_IP_ERR | TSRN10_CKSUM_L4_ERR,
				0,
				TSRN10_CKSUM_L4_ERR | TSRN10_CKSUM_IN_IP_ERR,
				TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_IN_IP_ERR,
				TSRN10_CKSUM_IN_IP_ERR,
				TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_IP_ERR | TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_L4_ERR | TSRN10_CKSUM_IP_ERR,
				TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_IP_ERR,
				0);
		const __m128i out_cksum_mask = _mm_set_epi8(
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				TSRN10_CKSUM_TUNNEL_ERR | TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_TUNNEL_ERR,
				TSRN10_CKSUM_TUNNEL_ERR | TSRN10_CKSUM_L4_ERR,
				TSRN10_CKSUM_TUNNEL_ERR, 0, 0);

		outcksum_flag = _mm_srli_epi32(l3_l4e, 4);
		/* when the packet is tunnel packent the cksum-err means
		 * will be overthrow the 0,1 bits 0 bit means out-ipcksum-err
		 * 1 bit will be not meaningless
		 * so change hw cksum bit sequenct to driver define */
		l3_l4e = _mm_shuffle_epi8(cksum_turn, l3_l4e);
		l3_l4e = _mm_or_si128(l3_l4e,
				_mm_shuffle_epi8(out_cksum_mask, outcksum_flag));
		l3_l4_e = _mm_shuffle_epi8(l3_l4e_flags, l3_l4e);
		l3_l4_e = _mm_slli_epi32(l3_l4_e, 1);
		l3_l4_e = _mm_and_si128(l3_l4_e, cksum_mask);
		flags = _mm_or_si128(flags, l3_l4_e);
	}
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	vol.e[0] = _mm_extract_epi16(flags, 0);
	vol.e[1] = _mm_extract_epi16(flags, 2);
	vol.e[2] = _mm_extract_epi16(flags, 4);
	vol.e[3] = _mm_extract_epi16(flags, 6);
	for (idx = 0; idx < var; idx++)
		rx_pkts[idx]->ol_flags = vol.e[idx];
#else
	rearm[0] = _mm_blend_epi16(mbuf_init, _mm_slli_si128(flags, 8), 0x10);
	rearm[1] = _mm_blend_epi16(mbuf_init, _mm_slli_si128(flags, 4), 0x10);
	rearm[2] = _mm_blend_epi16(mbuf_init, flags, 0x10);
	rearm[3] = _mm_blend_epi16(mbuf_init, _mm_srli_si128(flags, 4), 0x10);

	/* write the rearm data and the olflags in one write */
	for (idx = 0; idx < var; idx++)
		_mm_store_si128((__m128i *)&rx_pkts[idx]->rearm_data, rearm[idx]);
#endif
}

static inline void
tsrn10_desc_to_ptype(struct tsrn10_rx_queue *rxq __rte_unused,
		     __m128i descs[4], struct rte_mbuf **rx_pkts, uint16_t var)
{
	__m128i hw_parse0 = _mm_unpacklo_epi32(descs[0], descs[1]);
	__m128i hw_parse1 = _mm_unpacklo_epi32(descs[2], descs[3]);
	__m128i hw_parses = _mm_unpackhi_epi64(hw_parse0, hw_parse1);
	__m128i ptype0 = _mm_unpackhi_epi32(descs[0], descs[1]);
	__m128i ptype1 = _mm_unpackhi_epi32(descs[2], descs[3]);
	__m128i ptypes = _mm_unpackhi_epi64(ptype0, ptype1);
	uint16_t ptype_id[4];
	uint16_t parse_en[4];
	uint16_t idx;
	const __m128i ptype_msk = _mm_set_epi16(
			0x60F0, 0, 0x60F0, 0, 0x60f0, 0, 0x60f0, 0);

	ptype0 = _mm_and_si128(ptypes, ptype_msk);
	ptype1 = _mm_srli_epi32(ptype0, 20);
	hw_parse0 = _mm_srli_epi32(hw_parses, 8);

	ptype_id[0] = _mm_extract_epi16(ptype1, 0);
	ptype_id[1] = _mm_extract_epi16(ptype1, 2);
	ptype_id[2] = _mm_extract_epi16(ptype1, 4);
	ptype_id[3] = _mm_extract_epi16(ptype1, 6);

	parse_en[0] = _mm_extract_epi16(hw_parse0, 1);
	parse_en[1] = _mm_extract_epi16(hw_parse0, 3);
	parse_en[2] = _mm_extract_epi16(hw_parse0, 5);
	parse_en[3] = _mm_extract_epi16(hw_parse0, 7);

	for (idx = 0; idx < var; idx++) {
		if (parse_en[idx] & TSRN10_RX_L3_TYPE_MASK)
			rx_pkts[idx]->packet_type =
				tsrn10_get_rx_parse_ptype(ptype_id[idx],
						rx_pkts[idx]);
		else
			rx_pkts[idx]->packet_type = RTE_PTYPE_UNKNOWN;
		if (rx_pkts[idx]->vlan_tci) {
			rx_pkts[idx]->packet_type &= ~RTE_PTYPE_L2_MASK;
			rx_pkts[idx]->packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
		}
	}
}

static inline uint16_t
_recv_raw_pkts_vec(struct tsrn10_rx_queue *rxq, struct rte_mbuf **rx_pkts,
		   uint16_t nb_pkts, uint8_t *split_packet __rte_unused)
{
	volatile struct tsrn10_rx_desc *rxdp;
	struct tsrn10_rxsw_entry *sw_ring;
	uint64_t nb_bytes_recd = 0;
	uint16_t nb_pkts_recd = 0;
	uint16_t idx = 0;
	uint8_t dd_review;
	int pos;
	uint64_t var;
	__m128i shuf_msk;
#if 0
	const __m128i zero_bytes = _mm_setzero_si128();
#endif
	/*
	 * compile-time check the above crc_adjust layout is correct.
	 * NOTE: the first field (lowest address) is given last in set_epi16
	 * call above.
	 */
	if (unlikely(!rxq->rxq_started || !rxq->rx_link))
		return 0;

	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	__m128i dd_check;
	/* eop_check; */

	/* nb_pkts has to be floor-aligned to RTE_TSRN10_DESCS_PER_LOOP */
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, RTE_TSRN10_DESCS_PER_LOOP);

	/* Just the act of getting into the function from the application is
	 * going to cost about 7 cycles
	 */
	rxdp = rxq->rx_bdr + rxq->rx_tail;

	rte_prefetch0(rxdp);

	/* HW Desc Write-Back May Slow Than Expect
	 * In Order To Avoid Just Recv 1 or 2 Pkts
	 * To Delay A Cycle
	 */
	if (rxq->rxrearm_nb > RTE_TSRN10_RXQ_REARM_THRESH)
		tsrn10_rxq_rearm(rxq);
	/* Before we start moving massive data around, check to see if
	 * there is actually a packet available
	 */
	if (!(rxdp->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD)))
		return 0;
	if (rxq->rx_tail & 0x3)
		rte_delay_us(1);

	/* 4 packets DD mask */
	dd_check = _mm_set_epi64x(0x0002000000020000LL, 0x0002000000020000LL);

	/* 4 packets EOP mask */
	/* eop_check = _mm_set_epi64x(0x0002000000020000LL, 0x0002000000020000LL); */

	/* mask to shuffle from desc. to mbuf */
	shuf_msk = _mm_set_epi8(
			3, 2, 1, 0,  /* octet 0~3, 32bits rss */
			13, 12,        /* octet 2~3, low 16 bits vlan_macip */
			9, 8,      /* octet 15~14, 16 bits data_len */
			0xFF, 0xFF,  /* skip high 16 bits pkt_len, zero out */
			9, 8,      /* octet 15~14, low 16 bits pkt_len */
			0xFF, 0xFF,  /* pkt_type set as unknown */
			0xFF, 0xFF  /*pkt_type set as unknown */
			);

	/*
	 * Compile-time verify the shuffle mask
	 * NOTE: some field positions already verified above, but duplicated
	 * here for completeness in case of future modifications.
	 */
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, vlan_tci) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 10);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, hash) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 12);

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
		__m128i descs[RTE_TSRN10_DESCS_PER_LOOP];
		__m128i pkt_mb[4];
		__m128i len[4];
		__m128i zero, staterr, sterr_tmp1, sterr_tmp2;
		/* 2 64 bit or 4 32 bit mbuf pointers in one XMM reg. */
		__m128i mbp1;
#if 0
		__m128i rx_byte1, rx_byte2, rx_bytes;
		__m128i byte_cnt;
#endif
#if defined(RTE_ARCH_X86_64)
		__m128i mbp2;
#endif
		/* B.1 load 2 (64 bit) or 4 (32 bit) mbuf points */
		mbp1 = _mm_loadu_si128((__m128i *)&sw_ring[pos]);
		/* Read desc statuses backwards to avoid race condition */
		/* A.1 load desc[3] */
		descs[3] = _mm_loadu_si128((__m128i *)(rxdp + 3));
		rte_compiler_barrier();

		/* B.2 copy 2 64 bit or 4 32 bit mbuf point into rx_pkts */
		_mm_storeu_si128((__m128i *)&rx_pkts[pos], mbp1);

#if defined(RTE_ARCH_X86_64)
		/* B.1 load 2 64 bit mbuf points */
		mbp2 = _mm_loadu_si128((__m128i *)&sw_ring[pos + 2]);
#endif

		/* A.1 load desc[2-0] */
		descs[2] = _mm_loadu_si128((__m128i *)(rxdp + 2));
		rte_compiler_barrier();
		descs[1] = _mm_loadu_si128((__m128i *)(rxdp + 1));
		rte_compiler_barrier();
		descs[0] = _mm_loadu_si128((__m128i *)(rxdp));

#if defined(RTE_ARCH_X86_64)
		/* B.2 copy 2 mbuf point into rx_pkts  */
		_mm_storeu_si128((__m128i *)&rx_pkts[pos + 2], mbp2);
#endif
		/* avoid compiler reorder optimization */
		rte_compiler_barrier();

		/* pkt 3,4 shift the pktlen field to be 16-bit aligned*/
		len[3] = _mm_slli_epi32(descs[3], PKTLEN_SHIFT);
		len[2] = _mm_slli_epi32(descs[2], PKTLEN_SHIFT);
		/* merge the now-aligned packet length fields back in */
		descs[3] = _mm_blend_epi16(descs[3], len[3], 0x80);
		descs[2] = _mm_blend_epi16(descs[2], len[2], 0x80);
#if 0
		rx_byte2 = _mm_unpackhi_epi32(len3, len2);
#endif

		/* C.1 4=>2 filter staterr info only */
		sterr_tmp2 = _mm_unpackhi_epi32(descs[3], descs[2]);
		/* C.1 4=>2 filter staterr info only */
		sterr_tmp1 = _mm_unpackhi_epi32(descs[1], descs[0]);

		/* D.1 pkt 3,4 convert format from desc to pktmbuf */
		pkt_mb[3] = _mm_shuffle_epi8(descs[3], shuf_msk);
		pkt_mb[2] = _mm_shuffle_epi8(descs[2], shuf_msk);

		/* pkt 1,2 shift the pktlen field to be 16-bit aligned*/
		len[1] = _mm_slli_epi32(descs[1], PKTLEN_SHIFT);
		len[0] = _mm_slli_epi32(descs[0], PKTLEN_SHIFT);

#if 0
		rx_byte1 = _mm_unpackhi_epi32(len1, len0);
		rx_bytes = _mm_unpacklo_epi32(rx_byte2, rx_byte1);
#endif

		/* merge the now-aligned packet length fields back in */
		descs[1] = _mm_blend_epi16(descs[1], len[1], 0x80);
		descs[0] = _mm_blend_epi16(descs[0], len[0], 0x80);

		/* D.1 pkt 1,2 convert format from desc to pktmbuf */
		pkt_mb[1] = _mm_shuffle_epi8(descs[1], shuf_msk);
		pkt_mb[0] = _mm_shuffle_epi8(descs[0], shuf_msk);

		/* C.2 get 4 pkts staterr value  */
		zero = _mm_xor_si128(dd_check, dd_check);
		staterr = _mm_unpackhi_epi32(sterr_tmp1, sterr_tmp2);
#if 0
		/* D.2 pkt 1,2 set in_port/nb_seg and remove crc */
		pkt_mb2 = _mm_add_epi16(pkt_mb2, crc_adjust);
		pkt_mb1 = _mm_add_epi16(pkt_mb1, crc_adjust);

		/* C* extract and record EOP bit */
		if (split_packet) {
			__m128i eop_shuf_mask = _mm_set_epi8(
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0x04, 0x0C, 0x00, 0x08
					);


			/* and with mask to extract bits, flipping 1-0 */
			__m128i eop_bits = _mm_andnot_si128(staterr, eop_check);
			/* the staterr values are not in order, as the count
			 * of dd bits doesn't care. However, for end of
			 * packet tracking, we do care, so shuffle. This also
			 * compresses the 32-bit values to 8-bit
			 */
			eop_bits = _mm_shuffle_epi8(eop_bits, eop_shuf_mask);
			/* store the resulting 32-bit value */
			*(int *)split_packet = _mm_cvtsi128_si32(eop_bits);
			split_packet += RTE_TSRN10_DESCS_PER_LOOP;
		}
#endif
		/* C.3 calc available number of desc */

		staterr = _mm_and_si128(staterr, dd_check);
		staterr = _mm_srai_epi32(staterr, 16);
		staterr = _mm_packs_epi32(staterr, zero);

		/* D.3 copy final 1,2 data to rx_pkts */
		/* desc_to_ptype_v(descs, &rx_pkts[pos], ptype_tbl); */
		/* C.4 calc available number of desc */
		/* how Many Bit Is Hi */


		var = __builtin_popcountll(_mm_cvtsi128_si64(staterr));

		if (var) {
			for (idx = 0; idx < var; idx++) {
				dd_review = _mm_extract_epi8(len[idx], 14);
				if (unlikely(!(dd_review & 0x2)))
					break;

				_mm_storeu_si128((void *)&rx_pkts[pos + idx]->rx_descriptor_fields1,
						pkt_mb[idx]);
				nb_bytes_recd += rx_pkts[pos + idx]->data_len;
			}
			var = idx;
			tsrn10_rx_desc_parse_field(rxq, descs, &rx_pkts[pos], var);
			tsrn10_desc_to_ptype(rxq, descs, &rx_pkts[pos], var);
#if 0
			byte_cnt = _mm_hadd_epi16(rx_bytes, zero_bytes);
			rx_bytes = _mm_hadd_epi16(byte_cnt, zero_bytes);

			nb_bytes_recd +=  _mm_cvtsi128_si64(_mm_hadd_epi16(rx_bytes, zero_bytes));
#endif
		}
		nb_pkts_recd += var;
		if (likely(var != RTE_TSRN10_DESCS_PER_LOOP))
			break;
	}

	/* Update our internal tail pointer */
	rxq->rx_tail = (uint16_t)(rxq->rx_tail + nb_pkts_recd);
	rxq->rx_tail = (uint16_t)(rxq->rx_tail & (rxq->attr.bd_count - 1));
	rxq->rxrearm_nb = (uint16_t)(rxq->rxrearm_nb + nb_pkts_recd);

	rxq->stats.ipackets += nb_pkts_recd;
	rxq->stats.ibytes += nb_bytes_recd;

	return nb_pkts_recd;
}

uint16_t
tsrn10_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
		     uint16_t nb_pkts)
{
	uint16_t nb_rx = 0, n, ret;
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)rx_queue;

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

#if 0
inline void
_tsrn10_rx_queue_release_mbufs_vec(struct tsrn10_rx_queue *rxq)
{
	const unsigned int mask = rxq->attr.bd_count - 1;
	unsigned int i;

	if (rxq->sw_ring == NULL || rxq->rxrearm_nb >= rxq->attr.bd_count)
		return;

	/* free all mbufs that are valid in the ring */
	if (rxq->rxrearm_nb == 0) {
		for (i = 0; i < rxq->attr.bd_count; i++) {
			if (rxq->sw_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	} else {
		for (i = rxq->rx_tail;
				i != rxq->rxrearm_start;
				i = (i + 1) & mask) {
			if (rxq->sw_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	}

	rxq->rxrearm_nb = rxq->attr.bd_count;

	/* set all entries to NULL */
	memset(rxq->sw_ring, 0, sizeof(rxq->sw_ring[0]) * rxq->attr.bd_count);
}
#endif
