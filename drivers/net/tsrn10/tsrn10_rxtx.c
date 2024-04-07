#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <rte_version.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
#include <rte_vxlan.h>
#endif
#if RTE_VERSION_NUM(19, 8, 0, 0) < RTE_VERSION
#include <rte_gre.h>
#endif
#ifdef RTE_ARCH_ARM64
#include <rte_cpuflags_64.h>
#elif defined(RTE_ARCH_ARM)
#include <rte_cpuflags_32.h>
#endif

#include "base/tsrn10_hw.h"
#include "tsrn10_ptp.h"
#include "tsrn10.h"
#include "tsrn10_logs.h"

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
#if defined(RTE_ARCH_ARM64)
#define TSRN10_USING_NEON
#endif
#if defined(RTE_ARCH_X86)
#define TSRN10_USING_SSE
#endif
#else
#ifdef RTE_MACHINE_CPUFLAG_NEON
#define TSRN10_USING_NEON
#endif

#ifdef RTE_MACHINE_CPUFLAG_SSE
#define TSRN10_USING_SSE
#endif
#endif

#define TSRN10_ETH_HDR_LEN	(14)
#define CACHE_FETCH_RX (4)
#define TSRN10_RX_BURST_SIZE	(32)

#define TSRN10_PKTLEN_MASK	 (0x00ff)

static inline bool
tsrn10_check_tx_vaild_offload(struct rte_mbuf *m);

int tsrn10_dev_rx_descriptor_done(void *rx_queue, uint16_t offset)
{
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)rx_queue;
	volatile struct tsrn10_rx_desc *rxbd;
	uint32_t rx_id;

	if (unlikely(offset >= rxq->attr.bd_count))
		return 0;

	rx_id = TSRN10_NEXT_CL_ID(rxq, offset);
	rxbd = &rxq->rx_bdr[rx_id];

	return !!(rxbd->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD));
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
uint32_t
tsrn10_dev_rx_queue_count(void *rx_queue)
{
	volatile struct tsrn10_rx_desc *rxbd;
	struct tsrn10_rx_queue *rxq;
	uint16_t rx_count = 0;
	uint16_t rx_id;

	rxq = (struct tsrn10_rx_queue *)rx_queue;
	rxbd = &rxq->rx_bdr[rxq->next_to_clean];

	while (rx_count < rxq->attr.bd_count &&
			(rxbd->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD))) {
		rx_count++;

		rx_id = TSRN10_NEXT_CL_ID(rxq, 1);

		rxbd = &rxq->rx_bdr[rx_id];
	}

	return rx_count;
}
#else
uint32_t
tsrn10_dev_rx_queue_count(struct rte_eth_dev *dev, uint16_t q_id)
{
	volatile struct tsrn10_rx_desc *rxbd;
	struct tsrn10_rx_queue *rxq;
	uint16_t rx_count = 0;
	uint16_t rx_id;

	rxq = dev->data->rx_queues[q_id];
	rxbd = &rxq->rx_bdr[rxq->next_to_clean];

	while (rx_count < rxq->attr.bd_count &&
		(rxbd->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD))) {
		rx_count++;

		rx_id = TSRN10_NEXT_CL_ID(rxq, 1);

		rxbd = &rxq->rx_bdr[rx_id];
	}

	return rx_count;
}
#endif

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
int
tsrn10_dev_rx_descriptor_status(void *rx_queue, uint16_t offset)
{
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)rx_queue;
	volatile struct tsrn10_rx_desc *rxbd;
	uint16_t rx_id;

	if (unlikely(offset >= rxq->attr.bd_count))
		return 0;

	if (offset >= rxq->next_to_clean)
		return RTE_ETH_RX_DESC_UNAVAIL;

	rx_id = TSRN10_NEXT_CL_ID(rxq, offset);
	rxbd = &rxq->rx_bdr[rx_id];
	if (rxbd->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD))
		return RTE_ETH_RX_DESC_DONE;

	return RTE_ETH_RX_DESC_AVAIL;
}

int
tsrn10_dev_tx_descriptor_status(void *tx_queue, uint16_t offset)
{
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)tx_queue;
	volatile struct tsrn10_tx_desc *txbd;
	uint16_t tx_id;

	if (unlikely(offset >= txq->attr.bd_count))
		return -EINVAL;

	if (offset >= txq->next_to_use)
		return RTE_ETH_TX_DESC_UNAVAIL;

	tx_id = TSRN10_NEXT_USE_ID(txq, offset);
	txbd = &txq->tx_bdr[tx_id];

	if (txbd->d.cmd & rte_cpu_to_le_32(TSRN10_CMD_DD))
		return RTE_ETH_TX_DESC_DONE;

	return RTE_ETH_TX_DESC_FULL;
}
#endif

static  __rte_always_inline int
tsrn10_clean_tx_ring(struct tsrn10_tx_queue *txq)
{
#define TSRN10_TX_BURST_FREE	(64)
	struct rte_mbuf *free[TSRN10_TX_BURST_FREE];
	struct tsrn10_txsw_entry *tx_swbd;
	volatile struct tsrn10_tx_desc *txbd;
	uint16_t nb_free = 0;
	struct rte_mbuf *m;
	uint16_t next_dd;
	uint16_t j;

	txbd = &txq->tx_bdr[txq->tx_next_dd];
	if (!(txbd->d.cmd & TSRN10_DD))
		return 0;
	txbd->d.blen = 0;
	txbd->d.addr = 0;
	txbd->d.cmd = 0;
	txbd->d.vlan = 0;
	next_dd = txq->tx_next_dd - (txq->tx_free_thresh - 1);
	tx_swbd = &txq->sw_ring[next_dd];

	for (j = 0; j < txq->tx_rs_thresh; ++j, ++tx_swbd) {
		m = rte_pktmbuf_prefree_seg(tx_swbd->mbuf);
		tx_swbd->mbuf = NULL;
		if (unlikely(m == NULL))
			continue;
		if (nb_free >= TSRN10_TX_BURST_FREE ||
				(nb_free > 0 && m->pool != free[0]->pool)) {
			rte_mempool_put_bulk(free[0]->pool,
					(void **)free, nb_free);
			nb_free = 0;
		}
		free[nb_free++] = m;
	}
	if (nb_free)
		rte_mempool_put_bulk(free[0]->pool, (void **)free, nb_free);
	txq->nb_tx_free = (txq->nb_tx_free + txq->tx_rs_thresh);
	txq->tx_next_dd = (txq->tx_next_dd + txq->tx_rs_thresh) &
		(txq->attr.bd_count - 1);

	return 0;
}

#ifdef RX_DEBUG
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

static void dump_rx_desc(volatile struct tsrn10_rx_desc *rx_desc)
{
	printf("\tRxDescription:\tRSS-Value\t 0x%.2x\n", rx_desc->wb.rss_hash);
	printf("\tMarkId:\tID\t 0x%.2x\n", rx_desc->wb.marks.mark);
	printf("\tPktLen:\t%d\tPaddingLen %d\n",
			rx_desc->wb.hdr.len, rx_desc->wb.hdr.pad_len);
	printf("\tDescription\tcmd:\t 0x%.2x\n", rx_desc->wb.st.cmd);
	printf("\tVLAN_STRIO_TCI:\t %d\n", rx_desc->wb.st.vlan_tci);
}
#endif

struct tsrn10_rx_cksum_parse {
	uint64_t offloads;
	uint64_t packet_type;
	uint16_t hw_offload;
	uint64_t good;
	uint64_t bad;
};

#define TSRN10_RX_OFFLOAD_L4_CKSUM (DEV_RX_OFFLOAD_TCP_CKSUM | \
				    DEV_RX_OFFLOAD_UDP_CKSUM | \
				    DEV_RX_OFFLOAD_SCTP_CKSUM)
static const struct tsrn10_rx_cksum_parse rx_cksum_tunnel_parse[] = {
	{DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM,
		RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_MASK,
		TSRN10_RX_L3_ERR,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD, RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD},
	{DEV_RX_OFFLOAD_IPV4_CKSUM,
		RTE_PTYPE_L3_IPV4,
		TSRN10_RX_IN_L3_ERR,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD, RTE_MBUF_F_RX_IP_CKSUM_BAD},
	{TSRN10_RX_OFFLOAD_L4_CKSUM,
		RTE_PTYPE_L4_MASK,
		TSRN10_RX_IN_L4_ERR | TSRN10_RX_SCTP_ERR,
		RTE_MBUF_F_RX_L4_CKSUM_GOOD, RTE_MBUF_F_RX_L4_CKSUM_BAD}
};

static const struct tsrn10_rx_cksum_parse rx_cksum_parse[] = {
	{DEV_RX_OFFLOAD_IPV4_CKSUM,
		RTE_PTYPE_L3_IPV4,
		TSRN10_RX_L3_ERR,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD, RTE_MBUF_F_RX_IP_CKSUM_BAD},
	{TSRN10_RX_OFFLOAD_L4_CKSUM,
		RTE_PTYPE_L4_MASK,
		TSRN10_RX_L4_ERR | TSRN10_RX_SCTP_ERR,
		RTE_MBUF_F_RX_L4_CKSUM_GOOD, RTE_MBUF_F_RX_L4_CKSUM_BAD}
};

static void
tsrn10_rx_parse_tunnel_cksum(struct tsrn10_rx_queue *rxq,
			     struct rte_mbuf *m, uint16_t cksum_cmd)
{
	uint16_t idx = 0;

	for (idx = 0; idx < RTE_DIM(rx_cksum_tunnel_parse); idx++) {
		if (rxq->rx_offload_capa & rx_cksum_tunnel_parse[idx].offloads &&
			m->packet_type & rx_cksum_tunnel_parse[idx].packet_type) {
			if (cksum_cmd & rx_cksum_tunnel_parse[idx].hw_offload)
				m->ol_flags |= rx_cksum_tunnel_parse[idx].bad;
			else
				m->ol_flags |= rx_cksum_tunnel_parse[idx].good;
			/* If Outer Or Inner Has one IP Cksum Bad
			 * pkt is IP_CKSUM_BAD
			 * TODO In DPDK-21.08 Add OUT_IP_CKSUM_BAD
			 */
			if (m->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_GOOD &&
					m->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_BAD)
				m->ol_flags &= ~RTE_MBUF_F_RX_IP_CKSUM_GOOD;
		}
	}
}

static void
tsrn10_rx_parse_cksum(struct tsrn10_rx_queue *rxq,
		      struct rte_mbuf *m, uint16_t cksum_cmd)
{
	uint16_t idx = 0;

	for (idx = 0; idx < RTE_DIM(rx_cksum_parse); idx++) {
		if (rxq->rx_offload_capa &
				rx_cksum_parse[idx].offloads &&
			m->packet_type & rx_cksum_parse[idx].packet_type) {
			if (cksum_cmd & rx_cksum_parse[idx].hw_offload)
				m->ol_flags |= rx_cksum_parse[idx].bad;
			else
				m->ol_flags |= rx_cksum_parse[idx].good;
		}
	}
}

static __rte_always_inline void
tsrn10_dev_rx_offload(struct tsrn10_rx_queue *rxq,
		      struct rte_mbuf *m,
		      ctrl_rx_desc_t wb)
{
	uint16_t cmd = wb.vlan_cmd >> TSRN10_DESC_STATE_OFFSET;
	uint16_t vlan_tci = wb.vlan_cmd & TSRN10_VLAN_TCI_MASK;

	if (rxq->rx_offload_capa & DEV_RX_OFFLOAD_CHECKSUM ||
	    rxq->rx_offload_capa & DEV_RX_OFFLOAD_SCTP_CKSUM ||
	    rxq->rx_offload_capa & DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM) {
		if (m->packet_type & RTE_PTYPE_TUNNEL_MASK) {
			tsrn10_rx_parse_tunnel_cksum(rxq, m, cmd);
		} else {
			if (m->packet_type & RTE_PTYPE_L3_MASK ||
			    m->packet_type & RTE_PTYPE_L4_MASK)
				tsrn10_rx_parse_cksum(rxq, m, cmd);
		}
	}
	if (rxq->mark_enabled) {
		m->hash.fdir.hi = wb.marks.mark;
		if (m->hash.fdir.hi)
			m->ol_flags |= RTE_MBUF_F_RX_FDIR |
				       RTE_MBUF_F_RX_FDIR_ID;
	}
	if (rxq->rx_offload_capa & DEV_RX_OFFLOAD_RSS_HASH) {
		m->hash.rss =
			rte_le_to_cpu_32(wb.rss_hash);
		m->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
	}
#ifdef RTE_LIBRTE_IEEE1588
	if (cmd & TSRN10_RX_PTP_OFFLOAD)
		tsrn10_rx_get_timestamp(m, rxq);
#endif
	if (rxq->rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
		if (vlan_tci && cmd & TSRN10_VLAN_OFFLOAD_EN) {
			m->ol_flags |= RTE_MBUF_F_RX_VLAN |
				RTE_MBUF_F_RX_VLAN_STRIPPED;
			m->vlan_tci = vlan_tci;
		}
	}
}

static __rte_always_inline void
tsrn10_dev_rx_parse(struct tsrn10_rx_queue *rxq,
		    struct rte_mbuf *m, ctrl_rx_desc_t wb)
{
	uint16_t cmd = wb.vlan_cmd >> TSRN10_DESC_STATE_OFFSET;
	uint16_t vlan_tci = wb.vlan_cmd & TSRN10_VLAN_TCI_MASK;

	if (unlikely(rxq->attr.vf_num != UINT16_MAX &&
			wb.marks.veb & TSRN10_TX_VEB)) {
		/* WorkArbound For Veb Tx-VLAN Pacp Tranmit Back To VF */
		if (cmd & TSRN10_VLAN_OFFLOAD_EN)
			cmd &= ~TSRN10_VLAN_OFFLOAD_EN;
	}
	/* clear mbuf packet_type and ol_flags */
	m->packet_type = 0;
	m->ol_flags = 0;
	if (wb.marks.ack & TSRN10_RX_L3_TYPE_MASK) {
		/* For Tunnel Packet We Just Recognize Outer IP Type And L4 Type */
		if (cmd & TSRN10_L3TYPE_IPV6)
			m->packet_type |= RTE_PTYPE_L3_IPV6;
		else
			m->packet_type |= RTE_PTYPE_L3_IPV4;
	}
	if (vlan_tci)
		m->packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
	switch (cmd & TSRN10_L4TYPE_MASK) {
	case TSRN10_L4TYPE_UDP:
		m->packet_type |= RTE_PTYPE_L4_UDP;
		break;
	case TSRN10_L4TYPE_TCP:
		m->packet_type |= RTE_PTYPE_L4_TCP;
		break;
	case TSRN10_L4TYPE_SCTP:
		m->packet_type |= RTE_PTYPE_L4_SCTP;
		break;
	}
	if ((cmd & TSRN10_RX_TUNNEL_MASK) == TSRN10_RX_TUNNEL_VXLAN)
		m->packet_type |= RTE_PTYPE_TUNNEL_VXLAN;

	if ((cmd & TSRN10_RX_TUNNEL_MASK) == TSRN10_RX_TUNNEL_NVGRE)
		m->packet_type |= RTE_PTYPE_TUNNEL_NVGRE;

	tsrn10_dev_rx_offload(rxq, m, wb);
	if (!(m->packet_type & RTE_PTYPE_L2_MASK))
		m->packet_type |= RTE_PTYPE_L2_ETHER;
}

static void
tsrn10_check_inner_eth_hdr(struct rte_mbuf *mbuf,
			   volatile struct tsrn10_tx_desc *tx_desc)
{
	struct rte_ether_hdr *eth_hdr;
	uint16_t inner_l2_offset = 0;
	struct rte_vlan_hdr *vlan_hdr;
	uint16_t l2_type;

	inner_l2_offset = mbuf->outer_l2_len + mbuf->outer_l3_len +
			  sizeof(struct rte_udp_hdr) +
			  sizeof(struct rte_vxlan_hdr);
	eth_hdr = rte_pktmbuf_mtod_offset(mbuf,
			struct rte_ether_hdr *, inner_l2_offset);
	l2_type = eth_hdr->ether_type;
	while (l2_type == _htons(RTE_ETHER_TYPE_VLAN) ||
		l2_type == _htons(RTE_ETHER_TYPE_QINQ)) {
		vlan_hdr = (struct rte_vlan_hdr *)
			((char *)eth_hdr + tx_desc->d.mac_len);
		tx_desc->d.mac_len += sizeof(struct rte_vlan_hdr);
		l2_type = vlan_hdr->eth_proto;
	}
}

__attribute__((hot))
static inline void
tsrn10_setup_csum_offload(struct rte_mbuf *mbuf,
			  volatile struct tsrn10_tx_desc *tx_desc)
{
	if (mbuf->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK) { /* app-offloading-setted */
		tx_desc->d.cmd |= (mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) ?
				  TSRN10_IP_CKSUM_OFFLOAD : 0;
		tx_desc->d.cmd |= (mbuf->ol_flags & RTE_MBUF_F_TX_IPV6) ?
				  TSRN10_L3TYPE_IPV6 : 0;
		tx_desc->d.cmd |= (mbuf->ol_flags & TSRN10_L4_OFFLOAD_ALL) ?
				  TSRN10_L4_CKSUM_OFFLOAD : 0;

		switch ((mbuf->ol_flags & RTE_MBUF_F_TX_L4_MASK)) {
		case RTE_MBUF_F_TX_TCP_CKSUM:
			tx_desc->d.cmd |= TSRN10_L4TYPE_TCP;
			break;
		case RTE_MBUF_F_TX_UDP_CKSUM:
			tx_desc->d.cmd |= TSRN10_L4TYPE_UDP;
			break;
		case RTE_MBUF_F_TX_SCTP_CKSUM:
			tx_desc->d.cmd |= TSRN10_L4TYPE_SCTP;
			break;
		}
		if (mbuf->ol_flags & RTE_MBUF_F_TX_TCP_SEG)
			tx_desc->d.cmd |= TSRN10_TX_TCP_TSO_EN;
		/* NON-TUNNEL TSO */
		tx_desc->d.mac_len = mbuf->l2_len;
		if (mbuf->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
			switch (mbuf->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
			case RTE_MBUF_F_TX_TUNNEL_VXLAN:
				/* For RTE_MBUF_F_TX_TUNNEL_VXLAN Maclen Is Inner Ether
				 * ETH + VXLAN + (ETH + VLAN(opt) + IP + TCP)
				 */
				tx_desc->d.mac_len = TSRN10_ETH_HDR_LEN;
				tsrn10_check_inner_eth_hdr(mbuf, tx_desc);
				tx_desc->d.cmd |= TSRN10_TX_TUNNEL_TYPE_VXLAN
					<< TSRN10_TX_TUNNEL_TYPE_SHIFT;
				break;
			case RTE_MBUF_F_TX_TUNNEL_GRE:
				tx_desc->d.mac_len = TSRN10_ETH_HDR_LEN;
				tx_desc->d.cmd |= TSRN10_TX_TUNNEL_TYPE_NVGRE
					<< TSRN10_TX_TUNNEL_TYPE_SHIFT;
				break;
			default:
				if (mbuf->ol_flags & RTE_MBUF_F_TX_TCP_SEG)
					tx_desc->d.cmd &= ~TSRN10_TX_TCP_TSO_EN;
				PMD_TX_LOG(ERR, "Tunnel type not supported");
				break;
			}
		}
		tx_desc->d.ip_len = mbuf->l3_len;
	}
}

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
static inline int
tsrn10_net_cksum_flags_prepare(struct rte_mbuf *m, uint64_t ol_flags)
{
	/* Initialise ipv4_hdr to avoid false positive compiler warnings. */
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_sctp_hdr *sctp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint64_t inner_l3_offset = m->l2_len;

	/*
	 * Does packet set any of available offloads?
	 * Mainly it is required to avoid fragmented headers check if
	 * no offloads are requested.
	 */
	if (!(ol_flags & (RTE_MBUF_F_TX_IP_CKSUM |
			 RTE_MBUF_F_TX_L4_MASK |
			 RTE_MBUF_F_TX_TCP_SEG)))
		return 0;

	if (ol_flags & (RTE_MBUF_F_TX_OUTER_IPV4 | RTE_MBUF_F_TX_OUTER_IPV6)) {
		if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) ==
				RTE_MBUF_F_TX_TCP_CKSUM ||
				(ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
			/* Hardware Must require Out-IP Cksum Is Zero
			 * When VXLAN-TSO Enable
			 */
			ipv4_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv4_hdr *, m->outer_l2_len);
			ipv4_hdr->hdr_checksum = 0;
		}

		inner_l3_offset += m->outer_l2_len + m->outer_l3_len;
	}

	/*
	 * Check if headers are fragmented.
	 * The check could be less strict depending on which offloads are
	 * requested and headers to be used, but let's keep it simple.
	 */
	if (unlikely(rte_pktmbuf_data_len(m) <
				inner_l3_offset + m->l3_len + m->l4_len))
		return -ENOTSUP;

	if (ol_flags & RTE_MBUF_F_TX_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
				inner_l3_offset);
		if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
			ipv4_hdr->hdr_checksum = 0;
	}
	if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) == RTE_MBUF_F_TX_UDP_CKSUM) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr +
					m->l3_len);
			udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr,
					ol_flags);

		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv6_hdr *, inner_l3_offset);
			/* non-TSO udp */
			udp_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_udp_hdr *,
					inner_l3_offset + m->l3_len);
			udp_hdr->dgram_cksum = rte_ipv6_phdr_cksum(ipv6_hdr,
					ol_flags);
		}
	} else if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) == RTE_MBUF_F_TX_TCP_CKSUM ||
			(ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			/* non-TSO tcp or TSO */
			tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr +
					m->l3_len);
			tcp_hdr->cksum = rte_ipv4_phdr_cksum(ipv4_hdr,
					ol_flags);
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv6_hdr *, inner_l3_offset);
			/* non-TSO tcp or TSO */
			tcp_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_tcp_hdr *,
					inner_l3_offset + m->l3_len);
			tcp_hdr->cksum = rte_ipv6_phdr_cksum(ipv6_hdr,
					ol_flags);
		}
	} else if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) == RTE_MBUF_F_TX_SCTP_CKSUM) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			sctp_hdr = (struct rte_sctp_hdr *)((char *)ipv4_hdr +
					m->l3_len);
			/* SCTP-cksm implement CRC32 */
			sctp_hdr->cksum = 0;
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv6_hdr *, inner_l3_offset);
			/* NON-TSO SCTP */
			sctp_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_sctp_hdr *,
					inner_l3_offset + m->l3_len);
			sctp_hdr->cksum = 0;
		}
	}

	if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM && !(ol_flags & RTE_MBUF_F_TX_L4_MASK)) {
		/* Workaround For Hardware Fault Of CKSUM OFFLOAD
		 * The Hardware L4 is follow on L3 CKSUM.
		 * When ol_flags set HW L3, SW L4 CKSUM Offload,
		 * We Must Prepare Pseudo Header To avoid
		 * The L4 CKSUM ERROR
		 */
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv4_hdr *, inner_l3_offset);
			switch (ipv4_hdr->next_proto_id) {
			case IPPROTO_UDP:
				udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr +
						m->l3_len);
				udp_hdr->dgram_cksum =
					rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
				break;
			case IPPROTO_TCP:
				tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr +
						m->l3_len);
				tcp_hdr->cksum = rte_ipv4_phdr_cksum(ipv4_hdr,
						ol_flags);
				break;
			default:
				break;
			}
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv6_hdr *, inner_l3_offset);
			switch (ipv6_hdr->proto) {
			case IPPROTO_UDP:
				udp_hdr = (struct rte_udp_hdr *)((char *)ipv6_hdr +
						m->l3_len);
				udp_hdr->dgram_cksum =
					rte_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
				break;
			case IPPROTO_TCP:
				tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv6_hdr +
						m->l3_len);
				tcp_hdr->cksum = rte_ipv6_phdr_cksum(ipv6_hdr,
						ol_flags);
				break;
			default:
				break;
			}
		}
	}

	return 0;
}

uint16_t tsrn10_prep_pkts(void *tx_queue,
			  struct rte_mbuf **tx_pkts,
			  uint16_t nb_pkts)
{
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)tx_queue;
	struct rte_mbuf *m;
	int i, ret;

	PMD_INIT_FUNC_TRACE();
	for (i = 0; i < nb_pkts; i++) {
		m = tx_pkts[i];
		if (unlikely(!tsrn10_check_tx_vaild_offload(m))) {
			txq->stats.errors++;
			rte_errno = EINVAL;
			return i;
		}
		if (m->nb_segs > 10) {
			rte_errno = EINVAL;
			return i;
		}

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
		ret = rte_validate_tx_offload(m);
		if (ret != 0) {
			rte_errno = -ret;
			return i;
		}
#endif
		ret = tsrn10_net_cksum_flags_prepare(m, m->ol_flags);

		if (ret != 0) {
			rte_errno = -ret;
			return i;
		}
	}

	return i;
}
#endif

static inline uint32_t
tsrn10_cal_tso_seg(struct rte_mbuf *mbuf)
{
	uint32_t hdr_len;

	hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;

	hdr_len += (mbuf->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) ?
		mbuf->outer_l2_len + mbuf->outer_l3_len : 0;

	return (mbuf->tso_segsz) ? mbuf->tso_segsz : hdr_len;
}

static inline bool
tsrn10_need_ctrl_desc(struct tsrn10_tx_queue *txq __rte_unused, uint64_t flags)
{
	static uint64_t mask = RTE_MBUF_F_TX_OUTER_IP_CKSUM |
			       RTE_MBUF_F_TX_TCP_SEG |
			       RTE_MBUF_F_TX_QINQ |
			       RTE_MBUF_F_TX_TUNNEL_VXLAN |
			       RTE_MBUF_F_TX_TUNNEL_GRE;
	/* Next Product Nor N10
	 * When A VF Want To Send Pcap Must To Mark
	 * The Pcap Belong VF Via Use Ctrl Desc
	 */

	return (flags & mask) ? 1 : 0;
}

static void tsrn10_build_tx_control_desc(struct tsrn10_tx_queue *txq,
					 volatile struct tsrn10_tx_desc *txbd,
					 struct rte_mbuf *mbuf)
{
	struct tsrn10_queue_attr *q_attr = &txq->attr;
	volatile ctrl_tx_desc_t *ctx = &txbd->c;
	uint64_t flags;
	struct rte_gre_hdr *gre_hdr;

	ctx->cmd = 0;
	ctx->mss = 0;
	ctx->vf_num = 0;
	ctx->l4_len = 0;
	ctx->tunnel_len = 0;
	ctx->vlan_tag = 0;
	ctx->veb_tran = 0;
	ctx->rev[0] = 0;
	ctx->rev[1] = 0;
	ctx->rev[2] = 0;
	ctx->rev[3] = 0;
	ctx->rev[4] = 0;
	ctx->rev[5] = 0;
	/*
	 * For Outer CKSUM OFFLOAD L2_len is
	 * L2 (MAC) Header Length for non-tunneling pkt.
	 * For Inner CKSUM OFFLOAD L2_LEN is
	 * Outer_L4_len + ... + Inner_L2_len(Inner L2 Header Len)
	 * for tunneling pkt.
	 */

	if (!mbuf)
		return;
	flags = mbuf->ol_flags;

	if (unlikely(q_attr->vf_num != UINT16_MAX)) {
		ctx->vf_num = txq->attr.vf_num | TSRN10_TX_VF_PKT;
		ctx->veb_tran = TSRN10_TX_VEB;
	}

	if (flags & RTE_MBUF_F_TX_TCP_SEG) {
		ctx->mss = tsrn10_cal_tso_seg(mbuf);
		ctx->l4_len = mbuf->l4_len;
	}
	if (flags & RTE_MBUF_F_TX_QINQ) {
		ctx->vlan_tag = mbuf->vlan_tci;
		ctx->cmd |= (TSRN10_TX_OFFLOAD_VLAN_INSERT
			     << TSRN10_TX_CTX_INVLAN_ACT_SHIFT);
	}
#define GRE_TUNNEL_KEY (4)
#define GRE_TUNNEL_SEQ (4)
	switch (flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
	case RTE_MBUF_F_TX_TUNNEL_VXLAN:
		ctx->tunnel_len = mbuf->outer_l2_len + mbuf->outer_l3_len +
			sizeof(struct rte_udp_hdr) +
			sizeof(struct rte_vxlan_hdr);
		break;
	case RTE_MBUF_F_TX_TUNNEL_GRE:
		gre_hdr = rte_pktmbuf_mtod_offset(mbuf,
			struct rte_gre_hdr *, mbuf->outer_l2_len + mbuf->outer_l3_len);
		ctx->tunnel_len = mbuf->outer_l2_len + mbuf->outer_l3_len +
				sizeof(struct rte_gre_hdr);
		if (gre_hdr->k)
			ctx->tunnel_len += GRE_TUNNEL_KEY;
		if (gre_hdr->s)
			ctx->tunnel_len += GRE_TUNNEL_SEQ;
#ifdef DEBUG_NVGRE_TSO
		TSRN10_PMD_LOG(INFO, "outer_l2_len %d outer_l3_len %d\n",
				mbuf->outer_l2_len, mbuf->outer_l3_len);
		TSRN10_PMD_LOG(INFO, "l2_len %d l3_len %d\n",
				mbuf->l2_len, mbuf->l3_len);
		TSRN10_PMD_LOG(INFO, "tunnel _len %d\n", ctx->tunnel_len);
#endif
		break;
	default:
		break;
	}

	ctx->cmd |= TSRN10_CTRL_DESC;
}

static void
tsrn10_padding_hdr_len(volatile struct tsrn10_tx_desc *txbd,
		       struct rte_mbuf *m)
{
	if (m->l2_len == 0) {
		int ethertype, l2_len;
		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m,
				struct rte_ether_hdr *);
		l2_len = sizeof(struct rte_ether_hdr);
		ethertype = rte_le_to_cpu_32(eth_hdr->ether_type);
		if (ethertype == RTE_ETHER_TYPE_VLAN) {
			struct rte_vlan_hdr *vlan_hdr =
				(struct rte_vlan_hdr *)(eth_hdr + 1);
			l2_len  += sizeof(struct rte_vlan_hdr);
			ethertype = vlan_hdr->eth_proto;
		}

		txbd->d.mac_len = l2_len;
		switch (ethertype) {
		case RTE_ETHER_TYPE_IPV4:
			txbd->d.ip_len = sizeof(struct rte_ipv4_hdr);
			break;
		case RTE_ETHER_TYPE_IPV6:
			txbd->d.ip_len = sizeof(struct rte_ipv6_hdr);
			break;
		default:
			txbd->d.ip_len = 0;
			break;
		}
	} else {
		txbd->d.mac_len = m->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK ?
				  m->outer_l2_len : m->l2_len;
		txbd->d.ip_len = m->l3_len;
	}
}

static void
tsrn10_setup_tx_offload(volatile struct tsrn10_tx_desc *txbd,
			uint64_t flags, struct rte_mbuf *tx_pkt)
{
	txbd->d.cmd = 0;

	if (flags & (RTE_MBUF_F_TX_VLAN |
		     RTE_MBUF_F_TX_QINQ)) {
		txbd->d.cmd |= TSRN10_VLAN_OFFLOAD_EN;
		txbd->d.vlan = (flags & RTE_MBUF_F_TX_QINQ) ?
			tx_pkt->vlan_tci_outer : tx_pkt->vlan_tci;
		txbd->d.cmd |= TSRN10_TX_OFFLOAD_VLAN_INSERT
			       << TSRN10_TX_OFFLOAD_VLAN_ACT_SHIFT;
	}

	if (flags & RTE_MBUF_F_TX_L4_MASK ||
	    flags & RTE_MBUF_F_TX_TCP_SEG ||
	    flags & RTE_MBUF_F_TX_IP_CKSUM)
		tsrn10_setup_csum_offload(tx_pkt, txbd);

	switch (flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
	case RTE_MBUF_F_TX_TUNNEL_VXLAN:
		txbd->d.cmd |= TSRN10_TX_TUNNEL_TYPE_VXLAN;
		break;
	case RTE_MBUF_F_TX_TUNNEL_GRE:
		txbd->d.cmd |= TSRN10_TX_TUNNEL_TYPE_NVGRE;
		break;
	default:
		txbd->d.cmd &= ~TSRN10_TX_TUNNEL_TYPE_MASK;
	}
#ifdef RTE_LIBRTE_IEEE1588
	if (flags & RTE_MBUF_F_TX_IEEE1588_TMST)
		txbd->d.cmd |= TSRN10_TX_PTP_OFFLOAD;
#endif
}

static __rte_always_inline uint16_t
tsrn10_clean_txq(struct tsrn10_tx_queue *txq)
{
	uint16_t last_desc_cleaned = txq->last_desc_cleaned;
	struct tsrn10_txsw_entry *sw_ring = txq->sw_ring;
	volatile struct tsrn10_tx_desc *txbd;
	uint16_t desc_to_clean_to;
	uint16_t nb_tx_to_clean;

	desc_to_clean_to = (uint16_t)(last_desc_cleaned + txq->tx_rs_thresh);
	desc_to_clean_to = desc_to_clean_to & (txq->attr.bd_count - 1);

	desc_to_clean_to = sw_ring[desc_to_clean_to].last_id;
	txbd = &txq->tx_bdr[desc_to_clean_to];
	if (!(txbd->d.cmd & TSRN10_DD))
		return txq->nb_tx_free;

	if (last_desc_cleaned > desc_to_clean_to)
		nb_tx_to_clean = (uint16_t)((txq->attr.bd_count -
					last_desc_cleaned) + desc_to_clean_to);
	else
		nb_tx_to_clean = (uint16_t)(desc_to_clean_to -
				last_desc_cleaned);

	txbd->d.cmd = 0;

	txq->last_desc_cleaned = desc_to_clean_to;
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + nb_tx_to_clean);

	return txq->nb_tx_free;
}

static void
tsrn10_around_tx_veb_vlan(volatile struct tsrn10_tx_desc *txbd, struct rte_mbuf *mbuf)
{
	struct rte_ether_hdr *eh =
		rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_vlan_hdr *vh;

	if (eh->ether_type == htons(RTE_ETHER_TYPE_VLAN)) {
		vh = (struct rte_vlan_hdr *)(eh + 1);
		txbd->d.vlan = vh->vlan_tci;
		txbd->d.cmd |= TSRN10_TX_OFFLOAD_VLAN_INSERT
			<< TSRN10_TX_OFFLOAD_VLAN_ACT_SHIFT;
	}
}

static inline bool
tsrn10_check_tx_vaild_offload(struct rte_mbuf *m)
{
	uint16_t max_seg = m->nb_segs;
	uint32_t remain_len = 0;
	struct rte_mbuf *m_seg;
	uint32_t total_len = 0;
	uint32_t limit_len = 0;
	uint32_t tso = 0;

	if (likely(!(m->ol_flags & RTE_MBUF_F_TX_TCP_SEG))) {
		/* non tso mode */
		if (unlikely(m->pkt_len > TSRN10_MAC_MAXFRM_SIZE)) {
			return false;
		} else if (max_seg <= TSRN10_TX_MAX_MTU_SEG) {
			m_seg = m;
			do {
				total_len += m_seg->data_len;
				m_seg = m_seg->next;
			} while (m_seg != NULL);
			if (total_len > TSRN10_MAC_MAXFRM_SIZE)
				return false;
			return true;
		}
	} else {
		if (max_seg > TSRN10_TX_MAX_MTU_SEG)
			return false;

		tso = tsrn10_cal_tso_seg(m);
		m_seg = m;
		do {
			remain_len = RTE_MAX(remain_len, m_seg->data_len % tso);
			m_seg = m_seg->next;
		} while (m_seg != NULL);
		/* TSO Will remain bytes because of tso
		 * in this situation must refer the worst condition
		 */

		limit_len = remain_len * max_seg + tso;

		if (limit_len > TSRN10_MAX_TSO_PKT)
			return false;
	}
	return true;
}

__rte_always_inline uint16_t
tsrn10_xmit_pkts(void *_txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)_txq;
	volatile struct tsrn10_tx_desc *txbd;
	struct tsrn10_txsw_entry *txe, *txn;
	struct rte_mbuf *tx_pkt, *m_seg;
	uint8_t first_seg;
	uint8_t ctx_desc_use;
	uint16_t nb_used_bd;
	uint16_t tx_last;
	uint16_t nb_tx;
	uint16_t tx_id;

	if (unlikely(!txq->txq_started || !txq->tx_link))
		return 0;

	if (txq->nb_tx_free < txq->tx_free_thresh)
		tsrn10_clean_txq(txq);

	tx_id = txq->next_to_use;
	txbd = &txq->tx_bdr[tx_id];
	txe = &txq->sw_ring[tx_id];

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		tx_pkt = tx_pkts[nb_tx];

		ctx_desc_use = tsrn10_need_ctrl_desc(txq, tx_pkt->ol_flags);
		nb_used_bd = tx_pkt->nb_segs + ctx_desc_use;
		tx_last = (uint16_t)(tx_id + nb_used_bd - 1);

		if (tx_last >= txq->attr.bd_count)
			tx_last = (uint16_t)(tx_last - txq->attr.bd_count);

		if (nb_used_bd > txq->nb_tx_free)
			if (nb_used_bd > tsrn10_clean_txq(txq)) {
				if (txq->nb_tx_free == 0)
					txq->stats.tx_ring_full++;
				break;
			}

		if (ctx_desc_use) {
			txbd = &txq->tx_bdr[tx_id];
			txn = &txq->sw_ring[txe->next_id];
			RTE_MBUF_PREFETCH_TO_FREE(txn->mbuf);
			if (txe->mbuf) {
				rte_pktmbuf_free_seg(txe->mbuf);
				txe->mbuf = NULL;
			}
			tsrn10_build_tx_control_desc(txq, txbd, tx_pkt);

			txe->last_id = tx_last;
			tx_id = txe->next_id;
			txe = txn;
		}
		m_seg = tx_pkt;
		first_seg = 1;
		do {
			txbd = &txq->tx_bdr[tx_id];
			txn = &txq->sw_ring[txe->next_id];
			txbd->d.cmd = 0;
			txbd->d.vlan = 0;
			if (first_seg && m_seg->ol_flags) {
				tsrn10_setup_tx_offload(txbd,
						m_seg->ol_flags, m_seg);
				/* Avoid Hardware fault */
				if (!txbd->d.mac_len && !txbd->d.ip_len)
					tsrn10_padding_hdr_len(txbd, m_seg);
				if (unlikely(txq->attr.vf_num != UINT16_MAX &&
					!(m_seg->ol_flags & RTE_MBUF_F_TX_VLAN)))
					tsrn10_around_tx_veb_vlan(txbd, m_seg);
				first_seg = 0;
			}
			if (txe->mbuf) {
				rte_pktmbuf_free_seg(txe->mbuf);
				txe->mbuf = NULL;
			}
			txe->mbuf = m_seg;
			txe->last_id = tx_last;
			txbd->d.addr = tsrn10_get_dma_addr(&txq->attr, m_seg);
			txbd->d.blen = rte_cpu_to_le_32(m_seg->data_len);
			txq->stats.obytes += txbd->d.blen;
			txbd->d.cmd &= ~TSRN10_EOP;
			txbd->d.cmd |= TSRN10_DATA_DESC;
			m_seg = m_seg->next;
			tx_id = txe->next_id;
			txe = txn;
		} while (m_seg != NULL);
		first_seg = 0;

		txbd->d.cmd |= TSRN10_EOP;
		txq->nb_tx_used = txq->nb_tx_used + nb_used_bd;
		txq->nb_tx_free = txq->nb_tx_free - nb_used_bd;

		if (txq->nb_tx_used  >= txq->tx_rs_thresh) {
			txq->nb_tx_used  = 0;
			txbd->d.cmd |= TSRN10_RS;
		}
	}

	if (!nb_tx)
		return 0;

	txq->stats.opackets += nb_tx;
	txq->next_to_use = tx_id;

	rte_wmb();
	tsrn10_wr_reg(txq->tx_tailreg, tx_id);

	return nb_tx;
}

static __rte_always_inline uint16_t
tsrn10_xmit_simple(void *_txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)_txq;
	volatile struct tsrn10_tx_desc *txbd;
	struct tsrn10_txsw_entry *tx_swbd;
	uint64_t phy;
	uint16_t start;
	uint16_t i;

#ifdef RX_PERFORMANCE_DEBUG
	rte_mempool_put_bulk(tx_pkts[0]->pool, (void **)tx_pkts, nb_pkts);

	return nb_pkts;
#endif
	if (unlikely(!txq->txq_started || !txq->tx_link))
		return 0;

	if (txq->nb_tx_free < txq->tx_free_thresh)
		tsrn10_clean_tx_ring(txq);

	nb_pkts = RTE_MIN(txq->nb_tx_free, nb_pkts);
	if (!nb_pkts) {
		txq->stats.tx_ring_full++;
		return 0;
	}

	start = nb_pkts;
	i = txq->next_to_use;

	while (nb_pkts--) {
		txbd = &txq->tx_bdr[i];
		tx_swbd = &txq->sw_ring[i];
		tx_swbd->mbuf = *tx_pkts++;
		phy = tsrn10_get_dma_addr(&txq->attr, tx_swbd->mbuf);
		txbd->d.addr = phy;
		/* Just For Avoid Hardware fault */
		if (unlikely(tx_swbd->mbuf->data_len > TSRN10_MAC_MAXFRM_SIZE))
			tx_swbd->mbuf->data_len = 0;
		txbd->d.blen = tx_swbd->mbuf->data_len;
		txbd->d.cmd = TSRN10_EOP;
		txq->stats.obytes += tx_swbd->mbuf->data_len;

		i = (i + 1) & (txq->attr.bd_count - 1);
	}

	txq->nb_tx_free -= start;

	txq->stats.opackets += start;

	if (txq->next_to_use + start > txq->tx_next_rs) {
		txbd = &txq->tx_bdr[txq->tx_next_rs];
		txbd->d.cmd |= TSRN10_RS;
		txq->tx_next_rs = (txq->tx_next_rs + txq->tx_rs_thresh);

		if (txq->tx_next_rs > txq->attr.bd_count)
			txq->tx_next_rs = txq->tx_rs_thresh - 1;
	}

	txq->next_to_use = i;

	rte_wmb();
	tsrn10_wr_reg(txq->tx_tailreg, i);

	return start;
}

#define TSRN10_MAX_TX_RETRY	(10000)
static __rte_always_inline uint16_t
tsrn10_burst_xmit_pkts(void *_txq,
		  struct rte_mbuf **tx_pkts,
		  uint16_t nb_pkts)
{
	uint16_t nb_tx = 0;
	uint32_t retry = 0;
	uint32_t tx_burst;
	uint32_t idx = 0;
#ifdef DEBUG_PERF
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(&rte_eth_devices[txq->attr.rte_pid]);
#endif
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)_txq;
	while (nb_tx < nb_pkts) {
		tx_burst = nb_pkts - nb_tx >= 32 ? 32 : nb_pkts - nb_tx;
		idx = tsrn10_xmit_pkts(_txq,
				&tx_pkts[nb_tx], tx_burst);
		nb_tx += idx;
		if (nb_tx != nb_pkts) {
			retry++;
			if (retry >= TSRN10_MAX_TX_RETRY) {
				txq->stats.tx_full_drop += nb_pkts - nb_tx;
				break;
			}
		}
	}

	return nb_tx;
}

static __rte_always_inline uint16_t
tsrn10_burst_xmit_simple(void *_txq,
		  struct rte_mbuf **tx_pkts,
		  uint16_t nb_pkts)
{
	uint16_t nb_tx = 0;
	uint32_t retry = 0;
	uint32_t tx_burst;
	uint32_t idx = 0;
#ifdef DEBUG_PERF
	struct tsrn10_eth_port *port =
		TSRN10_DEV_TO_PORT(&rte_eth_devices[txq->attr.rte_pid]);
#endif
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)_txq;

	while (nb_tx < nb_pkts) {
		tx_burst = nb_pkts - nb_tx >= 32 ? 32 : nb_pkts - nb_tx;
		idx = tsrn10_xmit_simple(_txq,
				&tx_pkts[nb_tx], tx_burst);
		nb_tx += idx;
		if (nb_tx != nb_pkts) {
			retry++;
			if (retry >= TSRN10_MAX_TX_RETRY) {
				txq->stats.tx_full_drop += nb_pkts - nb_tx;
				break;
			}
		}
	}

	return nb_tx;
}

#if defined(RTE_ARCH_PPC_64) || defined(RTE_ARCH_LOONGSON) || defined(RTE_ARCH_SW_64)
uint16_t
tsrn10_xmit_fixed_burst_vec(void __rte_unused *tx_queue,
			    struct rte_mbuf __rte_unused **tx_pkts,
			    uint16_t __rte_unused nb_pkts)
{
	return 0;
}
#endif

static __rte_always_inline uint16_t
tsrn10_xmit_pkts_vec(void *_txq,
		     struct rte_mbuf **tx_pkts,
		     uint16_t nb_pkts)
{
	uint16_t nb_tx = 0;
	uint32_t retry = 0;
	uint32_t tx_burst;
	uint32_t idx = 0;
#ifdef DEBUG_PERF
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(&rte_eth_devices[txq->attr.rte_pid]);
#endif
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)_txq;
	if (unlikely(!txq))
		return 0;

	while (nb_tx < nb_pkts) {
		tx_burst = (uint16_t)RTE_MIN(nb_pkts - nb_tx, txq->tx_rs_thresh);
		idx = tsrn10_xmit_fixed_burst_vec(_txq,
				&tx_pkts[nb_tx], tx_burst);
		nb_tx += idx;
		if (nb_tx != nb_pkts) {
			retry++;
			if (retry >= TSRN10_MAX_TX_RETRY) {
				txq->stats.tx_full_drop += nb_pkts - nb_tx;
				break;
			}
		}
	}

	return nb_tx;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static const struct {
	eth_tx_burst_t pkt_burst;
	const char *info;
} tsrn10_tx_burst_infos[] = {
	{ tsrn10_xmit_simple,		"Scalar Simple" },
	{ tsrn10_burst_xmit_simple,	"Scalar Simple Burst" },
	{ tsrn10_xmit_pkts,		"Scalar"},
	{ tsrn10_burst_xmit_pkts,	"Scalar Burst" },
#ifdef RTE_ARCH_X86
	{ tsrn10_xmit_pkts_vec,	"Vector SSE" },
#elif defined(RTE_ARCH_ARM64)
	{ tsrn10_xmit_pkts_vec,	"Vector Neon" },
#endif
};

int
tsrn10_tx_burst_mode_get(struct rte_eth_dev *dev,
			 __rte_unused uint16_t queue_id,
			 struct rte_eth_burst_mode *mode)
{
	eth_tx_burst_t pkt_burst = dev->tx_pkt_burst;
	int ret = -EINVAL;
	unsigned int i;

	for (i = 0; i < RTE_DIM(tsrn10_tx_burst_infos); ++i) {
		if (pkt_burst == tsrn10_tx_burst_infos[i].pkt_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
					tsrn10_tx_burst_infos[i].info);
			ret = 0;
			break;
		}
	}

	return ret;
}
#endif

static bool
tsrn10_get_vec_support_info(void)
{
#ifdef TSRN10_USING_NEON
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_NEON))
		return true;
#endif
#ifdef TSRN10_USING_SSE
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE))
		return true;
#endif

	return false;
}

static int
tsrn10_check_tx_vec_valid(struct rte_eth_dev *dev, struct tsrn10_tx_queue *txq)
{
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	uint64_t tx_offloads = dev->data->dev_conf.txmode.offloads;
	uint64_t rx_offloads = dev->data->dev_conf.rxmode.offloads;
#else
	uint64_t tx_offloads = 0;
	uint64_t rx_offloads = 0;
#endif
	/* 1588 ptp feature will be enabled
	 * The tx side may need timestamps of ptp event
	 */
	tx_offloads |= txq->offloads;
	if (rx_offloads & DEV_RX_OFFLOAD_TIMESTAMP)
		return -ENOTSUP;
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	/* vector mode must be int fast_free mbuf mode */
	if (tx_offloads != DEV_TX_OFFLOAD_MBUF_FAST_FREE)
#else
#define TSRN10_TX_SIMPLE_FLAGS ((uint32_t)ETH_TXQ_FLAGS_NOMULTSEGS | \
					  ETH_TXQ_FLAGS_NOOFFLOADS)
	/* no multsegs and no tx offload feature enabled */
	if (!tx_offloads || (tx_offloads & TSRN10_TX_SIMPLE_FLAGS) !=
		TSRN10_TX_SIMPLE_FLAGS)
#endif
		return -ENOTSUP;
	if (dev->data->scattered_rx)
		return -ENOTSUP;
#ifdef RTE_LIBRTE_IEEE1588
	bool timestamp_en = true;
#endif

#ifdef RTE_LIBRTE_IEEE1588
	if (timestamp_en)
		return -ENOTSUP;
#endif
	return 0;
}
void
tsrn10_setup_tx_function(struct rte_eth_dev *dev,
			 struct tsrn10_tx_queue *txq)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	bool vec_options;
	bool cpu_support;
	bool simple_xmit;

	dev->tx_pkt_burst = NULL;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	dev->tx_pkt_prepare = NULL;
#endif
	cpu_support = tsrn10_get_vec_support_info();
	simple_xmit = tsrn10_check_tx_vec_valid(dev, txq) == 0;
	vec_options = cpu_support && simple_xmit;

	if (port->tx_func_sec == TSRN10_IO_FUNC_USE_NONE) {
		if (vec_options) {
			dev->tx_pkt_burst = tsrn10_xmit_pkts_vec;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
			dev->tx_pkt_prepare = NULL;
#endif
		} else {
			if (simple_xmit) {
				dev->tx_pkt_burst = tsrn10_burst_xmit_simple;
			} else {
				dev->tx_pkt_burst = tsrn10_burst_xmit_pkts;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
				dev->tx_pkt_prepare = tsrn10_prep_pkts;
#endif
			}
		}
	} else {
		if (port->tx_func_sec == TSRN10_IO_FUNC_USE_VEC && vec_options)
			dev->tx_pkt_burst = tsrn10_xmit_pkts_vec;
		if (port->tx_func_sec == TSRN10_IO_FUNC_USE_SIMPLE &&
				simple_xmit)
			dev->tx_pkt_burst = tsrn10_burst_xmit_simple;
		if (port->tx_func_sec == TSRN10_IO_FUNC_USE_COMMON) {
			dev->tx_pkt_burst = tsrn10_burst_xmit_pkts;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
			dev->tx_pkt_prepare = tsrn10_prep_pkts;
#endif
		}
		if (dev->tx_pkt_burst == NULL) {
			dev->tx_pkt_burst = tsrn10_burst_xmit_pkts;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
			dev->tx_pkt_prepare = tsrn10_prep_pkts;
#endif
		}
	}
}

static inline int tsrn10_refill_rx_ring(struct tsrn10_rx_queue *rxq)
{
	struct tsrn10_rxsw_entry *rx_swbd;
	volatile struct tsrn10_rx_desc *rxbd;
	struct rte_mbuf *mb;
	int ret;
	uint16_t j, i;
	uint16_t rx_id;

	rxbd = rxq->rx_bdr + rxq->rxrearm_start;
	rx_swbd = &rxq->sw_ring[rxq->rxrearm_start];

	ret = rte_mempool_get_bulk(rxq->mb_pool, (void *)rx_swbd, rxq->rx_free_thresh);

	if (unlikely(ret != 0)) {
		if (rxq->rxrearm_nb + rxq->rx_free_thresh >= rxq->attr.bd_count) {
			for (i = 0; i < CACHE_FETCH_RX; i++) {
				rx_swbd[i].mbuf = NULL;
				rxbd[i].d.pkt_addr = 0;
				rxbd[i].d.cmd = 0;
			}
		}
		rte_eth_devices[rxq->attr.rte_pid].data->rx_mbuf_alloc_failed +=
			rxq->rx_free_thresh;
		return 0;
	}
	for (j = 0; j < rxq->rx_free_thresh; ++j) {
		mb = rx_swbd[j].mbuf;
		rte_mbuf_refcnt_set(mb, 1);
		mb->data_off = RTE_PKTMBUF_HEADROOM;
		mb->port = rxq->attr.rte_pid;

		rxbd[j].d.pkt_addr = tsrn10_get_dma_addr(&rxq->attr, mb);
		rxbd[j].d.cmd = 0;
	}
	rxq->rxrearm_start += rxq->rx_free_thresh;
	if (rxq->rxrearm_start >= rxq->attr.bd_count - 1)
		rxq->rxrearm_start = 0;
	rxq->rxrearm_nb -= rxq->rx_free_thresh;

	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
			(rxq->attr.bd_count - 1) : (rxq->rxrearm_start - 1));

	rte_wmb();
	tsrn10_wr_reg(rxq->rx_tailreg, rx_id);

	return j;
}

__rte_always_inline uint16_t
tsrn10_recv_pkts(void *_rxq,
		 struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct tsrn10_rxsw_entry *rx_swbd;
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)_rxq;
	uint32_t state_cmd[CACHE_FETCH_RX];
	uint32_t pkt_len[CACHE_FETCH_RX] = {0};
	volatile struct tsrn10_rx_desc *rxbd;
	struct rte_mbuf *nmb;
	int nb_dd, nb_rx = 0;
	int i, j;

	if (unlikely(!rxq->rxq_started || !rxq->rx_link))
		return 0;
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, CACHE_FETCH_RX);
	rxbd = &rxq->rx_bdr[rxq->next_to_clean];
	rte_prefetch0(rxbd);
	if (rxq->rxrearm_nb > rxq->rx_free_thresh)
		tsrn10_refill_rx_ring(rxq);

	if (!(rxbd->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD)))
		return 0;

	rx_swbd = &rxq->sw_ring[rxq->next_to_clean];
	for (i = 0; i < nb_pkts;
			i += CACHE_FETCH_RX, rxbd += CACHE_FETCH_RX,
			rx_swbd += CACHE_FETCH_RX) {
		for (j = 0; j < CACHE_FETCH_RX; j++)
			state_cmd[j] = rxbd[j].wb.vlan_cmd;
		rte_smp_rmb();

		for (nb_dd = 0; nb_dd < CACHE_FETCH_RX &&
			(state_cmd[nb_dd] & rte_cpu_to_le_32(TSRN10_CMD_DD));
			nb_dd++)
			;

		for (j = 0; j < nb_dd; j++)
			pkt_len[j] = rxbd[j].wb.hdr.len - rxbd[j].wb.hdr.pad_len;

		for (j = 0; j < nb_dd; ++j) {
			nmb = rx_swbd[j].mbuf;
			nmb->data_len = pkt_len[j];
			nmb->pkt_len = pkt_len[j];
			nmb->nb_segs = 1;
			nmb->packet_type = 0;
			nmb->ol_flags = 0;
			nmb->data_off = RTE_PKTMBUF_HEADROOM;
			nmb->port = rxq->attr.rte_pid;

			tsrn10_dev_rx_parse(rxq, nmb, rxbd[j].wb);
			rxq->stats.ibytes += pkt_len[j];
		}
		for (j = 0; j < nb_dd; ++j)
			rx_pkts[i + j] = rx_swbd[j].mbuf;

		nb_rx += nb_dd;
		rxq->nb_rx_free -= nb_dd;
		if (nb_dd != CACHE_FETCH_RX)
			break;
	}
	if (nb_rx)
		rxq->stats.ipackets += nb_rx;
	rxq->next_to_clean = (rxq->next_to_clean + nb_rx) & rxq->attr.bd_mask;
	rxq->rxrearm_nb = rxq->rxrearm_nb + nb_rx;

	return nb_rx;
}

__rte_always_inline uint16_t
tsrn10_scattered_rx(void *rx_queue, struct rte_mbuf **rx_pkts,
		    uint16_t nb_pkts)
{
	/* 1.Recv first pkts */
	/* 2.According the EOP flag to know segment pkts
	 * We dno't let segment pkts point to rx_pkts[n]
	 * We will store it into mbuf->next with multitle descriptor
	 * so we must manage the segment abort the descriptor
	 */
	/* 3.point the segment mbuf to rx_pkts[0], multitle segment pkt just regard
	 * as one pkt
	 * 4.clean the segment-descriptor manage entry
	 */
	/* 5* update rx-tail judge by the free-threshold */
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)rx_queue;
	volatile struct tsrn10_rx_desc *bd_ring = rxq->rx_bdr;
	struct tsrn10_rxsw_entry *sw_ring = rxq->sw_ring;
	struct rte_mbuf *first_seg = rxq->pkt_first_seg;
	struct rte_mbuf *last_seg = rxq->pkt_last_seg;
	volatile struct tsrn10_rx_desc *rxbd;
	volatile struct tsrn10_rx_desc rxd;
	struct tsrn10_rxsw_entry *rxe;
	struct rte_mbuf *rxm;
	uint16_t rx_id;
	uint16_t nb_rx = 0;
	uint16_t nb_hold = 0;
	uint16_t rx_pkt_len;
	uint32_t rx_status;

	if (unlikely(!rxq->rxq_started || !rxq->rx_link))
		return 0;

	rx_id = rxq->next_to_clean;
	if (rxq->rxrearm_nb > rxq->rx_free_thresh)
		tsrn10_refill_rx_ring(rxq);

	while (nb_rx < nb_pkts) {
		rxbd = &bd_ring[rx_id];
		rx_status = rxbd->wb.vlan_cmd;
		if (!(rx_status & rte_cpu_to_le_32(TSRN10_CMD_DD)))
			break;
		rxd = *rxbd;

		nb_hold++;
		rxe = &sw_ring[rx_id];

		rx_id = TSRN10_NEXT_ID(rxq, rx_id);
		rte_prefetch0(sw_ring[rx_id].mbuf);

		if ((rx_id & 0x3) == 0) {
			rte_prefetch0(&bd_ring[rx_id]);
			rte_prefetch0(&sw_ring[rx_id]);
		}
		rxm = rxe->mbuf;

		rxe->mbuf = NULL;
		rx_pkt_len = rxd.wb.hdr.len - rxd.wb.hdr.pad_len;
		rxm->data_len = rx_pkt_len;
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		if (!first_seg) {
			/* first segment pkt */
			first_seg = rxm;
			first_seg->nb_segs = 1;
			first_seg->pkt_len = rx_pkt_len;
		} else {
			/* follow-up segment pkt */
			first_seg->pkt_len =
				(uint16_t)(first_seg->pkt_len +
						rx_pkt_len);
			first_seg->nb_segs++;
			last_seg->next = rxm;
		}

		if (!(rx_status & rte_cpu_to_le_32(TSRN10_CMD_EOP))) {
			last_seg = rxm;
			continue;
		}

		rxm->next = NULL;
		first_seg->port = rxq->attr.rte_pid;
		tsrn10_dev_rx_parse(rxq, first_seg, rxd.wb);
		/* This the End of Packet the Large pkt has been recv finish */
		rxq->stats.ibytes += first_seg->pkt_len;
		rxq->stats.ipackets++;
		/* avoid Tx Hard fault about non EOP Seg-Pkt */
		rte_prefetch0(RTE_PTR_ADD(first_seg->buf_addr,
					first_seg->data_off));
		rx_pkts[nb_rx++] = first_seg;
		first_seg = NULL;
	}
	/* update sw record point */
	rxq->next_to_clean = rx_id;
	rxq->pkt_first_seg = first_seg;
	rxq->pkt_last_seg = last_seg;

	rxq->rxrearm_nb = rxq->rxrearm_nb + nb_hold;

	return nb_rx;
}

uint16_t
tsrn10_rx_burst_simple(void *_rxq,
		       struct rte_mbuf **rx_pkts,
		       uint16_t nb_pkts)
{
	uint16_t min_rx, burst_rx;
	uint16_t nb_rx = 0;

	if (nb_pkts < CACHE_FETCH_RX)
		return tsrn10_scattered_rx(_rxq, rx_pkts, nb_pkts);

	while (nb_pkts) {
		min_rx = RTE_MIN(nb_pkts, TSRN10_RX_BURST_SIZE);
		burst_rx = tsrn10_recv_pkts(_rxq, &rx_pkts[nb_rx], min_rx);
		nb_rx = (nb_rx + burst_rx);
		nb_pkts = (nb_pkts - burst_rx);
		if (burst_rx < min_rx)
			break;
	}

	return nb_rx;
}

static uint16_t
tsrn10_rx_burst_scatter(void *_rxq,
			struct rte_mbuf **rx_pkts,
			uint16_t nb_pkts)
{
	uint16_t min_rx, burst_rx;
	uint16_t nb_rx = 0;

	while (nb_pkts) {
		min_rx = RTE_MIN(nb_pkts, TSRN10_RX_BURST_SIZE);
		burst_rx = tsrn10_scattered_rx(_rxq, &rx_pkts[nb_rx], min_rx);
		nb_rx = (nb_rx + burst_rx);
		nb_pkts = (nb_pkts - burst_rx);
		if (burst_rx < min_rx)
			break;
	}

	return nb_rx;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static const struct {
	eth_rx_burst_t pkt_burst;
	const char *info;
} tsrn10_rx_burst_infos[] = {
	{ tsrn10_scattered_rx,		"Scalar Scattered" },
	{ tsrn10_rx_burst_scatter,	"Scalar Burst Scattered" },
	{ tsrn10_recv_pkts,		"Scalar" },
	{ tsrn10_rx_burst_simple,	"Scalar Burst" },
#ifdef RTE_ARCH_X86
	{ tsrn10_recv_pkts_vec,		"Vector SSE" },
	{ tsrn10_scattered_burst_vec,	"Vector SSE Scattered" },
#elif defined(RTE_ARCH_ARM64)
	{ tsrn10_recv_pkts_vec,		"Vector Neon" },
	{ tsrn10_scattered_burst_vec,	"Vector Neon Scattered" },
#endif
};

int
tsrn10_rx_burst_mode_get(struct rte_eth_dev *dev,
			 __rte_unused uint16_t queue_id,
			 struct rte_eth_burst_mode *mode)
{
	eth_rx_burst_t pkt_burst = dev->rx_pkt_burst;
	int ret = -EINVAL;
	unsigned int i;

	for (i = 0; i < RTE_DIM(tsrn10_rx_burst_infos); ++i) {
		if (pkt_burst == tsrn10_rx_burst_infos[i].pkt_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
					tsrn10_rx_burst_infos[i].info);
			ret = 0;
			break;
		}
	}

	return ret;
}
#endif

static int
tsrn10_check_rx_vec_valid(struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	uint64_t rx_offloads = dev->data->dev_conf.rxmode.offloads;
#else
	uint64_t rx_offloads = 0;
#endif
#ifdef RTE_LIBRTE_IEEE1588
	bool timestamp_en = true;
#endif
	if (dev->data->scattered_rx || rx_offloads & DEV_RX_OFFLOAD_SCATTER)
		return -ENOTSUP;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rx_offloads & DEV_RX_OFFLOAD_TIMESTAMP)
		return -ENOTSUP;
#endif
#ifdef RTE_LIBRTE_IEEE1588
	if (timestamp_en)
		return -ENOTSUP;
#endif
	return 0;
}

void tsrn10_setup_rx_function(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	bool vec_options, simple_allowed;
	bool cpu_support;

	cpu_support = tsrn10_get_vec_support_info();
	simple_allowed = tsrn10_check_rx_vec_valid(dev) == 0;
	vec_options = cpu_support && simple_allowed;
	dev->rx_pkt_burst = NULL;
	if (port->rx_func_sec == TSRN10_IO_FUNC_USE_NONE) {
		if (vec_options) {
#if defined(TSRN10_USING_NEON) || defined(TSRN10_USING_SSE)
			dev->rx_pkt_burst = tsrn10_recv_pkts_vec;
#else
			PMD_DRV_LOG(ERR, "RxFunction Setup Vector Mode Failed\n");
			dev->rx_pkt_burst = tsrn10_rx_burst_simple;
#endif
		} else {
			if (dev->data->scattered_rx)
				dev->rx_pkt_burst = tsrn10_rx_burst_scatter;
			else
				dev->rx_pkt_burst = tsrn10_rx_burst_simple;
		}
	} else {
		if (port->rx_func_sec == TSRN10_IO_FUNC_USE_VEC &&
			vec_options)
			dev->rx_pkt_burst = tsrn10_recv_pkts_vec;
		if (port->rx_func_sec == TSRN10_IO_FUNC_USE_SIMPLE &&
			simple_allowed)
			dev->rx_pkt_burst = tsrn10_rx_burst_simple;
		if (port->rx_func_sec == TSRN10_IO_FUNC_USE_COMMON)
			dev->rx_pkt_burst = tsrn10_rx_burst_scatter;
		if (dev->rx_pkt_burst == NULL)
			dev->rx_pkt_burst = tsrn10_rx_burst_scatter;
	}
}
