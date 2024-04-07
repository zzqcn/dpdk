#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_kvargs.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#include <rte_pci.h>
#else
#if RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
#include <rte_ethdev_pci.h>
#else
#include <ethdev_pci.h>
#endif
#endif
#include <rte_ethdev.h>
#include <rte_random.h>
#include <rte_malloc.h>
#include <rte_memory.h>

#include "tsrn10_logs.h"
#include "tsrn10.h"
#include "tsrn10_mbx.h"
#include "base/tsrn10_api.h"

#define TSRN10_MAX_MTU_SIZE (RTE_ETHER_MAX_LEN - \
		RTE_ETHER_HDR_LEN - \
		RTE_ETHER_CRC_LEN)

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = MAX_BD_COUNT,
	.nb_min = MIN_BD_COUNT,
	.nb_align = BD_ALIGN,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = MAX_BD_COUNT,
	.nb_min = MIN_BD_COUNT,
	.nb_align = BD_ALIGN,
};
#endif

extern struct tsrn10_mbx_api tsrn10_mbx_vf_ops;
static void tsrn10vf_rx_queue_release(void *rxq);
static void tsrn10vf_tx_queue_release(void *txq);
static int tsrn10vf_dev_link_update(struct rte_eth_dev *eth_dev,
				    int wait_to_complete __rte_unused);

static int tsrn10vf_rx_queue_start(struct rte_eth_dev *eth_dev, uint16_t qidx);

static int tsrn10vf_rx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t qidx);

static int tsrn10vf_tx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t qidx);
static int tsrn10vf_tx_queue_start(struct rte_eth_dev *eth_dev, uint16_t qidx);

static int tsrn10vf_dev_configure(struct rte_eth_dev *dev)
{
	PMD_FUNC_LOG(DEBUG, "Configured Physical Function port id: %d ",
			dev->data->port_id);
	if (dev->data->nb_rx_queues != 2 || dev->data->nb_tx_queues != 2) {
		TSRN10_PMD_LOG(ERR, "VF Queue Num Must Setup To 2\n");
		return -EINVAL;
	}

	return 0;
}

static int tsrn10vf_dev_start(struct rte_eth_dev *dev)
{
	/* 1.mark we have start */
	/* 2.enabled the vf mac engine */
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	uint32_t i = 0;
	uint16_t index;
	uint32_t ctrl;
	int ret = 0;


	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		ret = tsrn10vf_tx_queue_start(dev, i);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		ret = tsrn10vf_rx_queue_start(dev, i);
		if (ret < 0)
			return ret;
	}
	tsrn10vf_dev_link_update(dev, 0);

	if (dev->data->mtu > RTE_ETHER_MAX_LEN)
		dev->data->scattered_rx = 1;
	tsrn10_setup_rx_function(dev);

	index = TSRN10_MAX_VFTA_SIZE - 1 - hw->mbx.vf_num;
	ctrl = tsrn10_eth_rd(hw,
			TSRN10_RAH_BASE_ADDR(index));
	ctrl |= TSRN10_MAC_FILTER_EN;
	tsrn10_eth_wr(hw,
		TSRN10_RAH_BASE_ADDR(index), ctrl);
	port->port_stopped = 0;

	return 0;
}

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
static int tsrn10vf_dev_stop(struct rte_eth_dev *dev)
#else
static void tsrn10vf_dev_stop(struct rte_eth_dev *dev)
#endif
{
	/* 1. stop queue vf reg can disable the
	 * belong mac enging or queue
	 */
	/* 2. disable the vf belong interrupt */
	/* 3. remove the mac-address set */
	/* 4. mark we has stop ,don't stop multi-time */
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_rx_queue *rxq = NULL;
	struct tsrn10_tx_queue *txq = NULL;
	uint16_t timeout = 0;
	uint32_t ctrl;
	uint32_t i = 0;
	uint16_t index;

	if (port->port_stopped)
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
		return -EPERM;
#else
		return;
#endif
	index = TSRN10_MAX_VFTA_SIZE - 1 - hw->mbx.vf_num;
	ctrl = tsrn10_eth_rd(hw,
			TSRN10_RAH_BASE_ADDR(index));

	ctrl &= ~TSRN10_MAC_FILTER_EN;
	tsrn10_eth_wr(hw,
		TSRN10_RAH_BASE_ADDR(index), ctrl);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = (struct tsrn10_rx_queue *)dev->data->rx_queues[i];
		timeout = 0;
		do {
			if (tsrn10_dma_rd(hw, TSRN10_DMA_RXQ_READY(rxq->attr.index)))
				break;
			rte_delay_us(10);

			timeout++;
		} while (timeout < 2000);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = (struct tsrn10_rx_queue *)dev->data->rx_queues[i];
		if (!rxq)
			continue;
		if (rxq->rxq_started)
			tsrn10vf_rx_queue_stop(dev, i);
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = (struct tsrn10_tx_queue *)dev->data->tx_queues[i];
		if (!txq)
			continue;
		if (txq->txq_started)
			tsrn10vf_tx_queue_stop(dev, i);
	}

	dev->data->scattered_rx = 0;
	dev->data->dev_started = 0;
	port->port_stopped = 1;
#ifdef RTE_PCI_DRV_NEED_MAPPING
	rte_intr_efd_disable(intr_handle);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	rte_intr_vec_list_free(intr_handle);
#else
	if (intr_handle->intr_vec) {
		rte_free(intr_handle->intr_vec);
		intr_handle->intr_vec = NULL;
	}
#endif
#endif
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
static int tsrn10vf_dev_close(struct rte_eth_dev *dev)
#else
static void tsrn10vf_dev_close(struct rte_eth_dev *dev)
#endif
{
	uint16_t i;
	/* This function normally to call when the process is
	 * prepare to close.its target is to clean resource
	 */
	PMD_INIT_FUNC_TRACE();

	tsrn10vf_dev_stop(dev);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		tsrn10vf_rx_queue_release(dev->data->rx_queues[i]);
		dev->data->rx_queues[i] = NULL;
	}
	dev->data->nb_rx_queues = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		tsrn10vf_tx_queue_release(dev->data->tx_queues[i]);
		dev->data->tx_queues[i] = NULL;
	}
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	dev->data->dev_flags |= RTE_ETH_DEV_CLOSE_REMOVE;
#endif
	dev->data->nb_tx_queues = 0;
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static int tsrn10vf_dev_link_update(struct rte_eth_dev *eth_dev,
				    int wait_to_complete __rte_unused)
{
	struct tsrn10vf_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER_VF(eth_dev);
	struct tsrn10_eth_port *port = adapter->port;
	struct tsrn10_rx_queue *rxq;
	struct tsrn10_tx_queue *txq;
	struct rte_eth_link link;
	uint32_t status;
	uint16_t idx;

	PMD_INIT_LOG(DEBUG, "link port %d update working",
			eth_dev->data->port_id);
	/* For Vf we will let it work in what mode? */

	status = port->attr.link_ready;
	link.link_duplex = ETH_LINK_FULL_DUPLEX;
	link.link_status = status ? ETH_LINK_UP : ETH_LINK_DOWN;
	link.link_speed  = link.link_status ? adapter->max_link_speed :
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		ETH_SPEED_NUM_UNKNOWN;
#else
		ETH_SPEED_NUM_NONE;
#endif

#if RTE_VERSION_NUM(17, 8, 0, 0) < RTE_VERSION
	link.link_autoneg = ETH_LINK_FIXED;
#endif
	rte_eth_linkstatus_set(eth_dev, &link);

	for (idx = 0; idx < eth_dev->data->nb_tx_queues; idx++) {
		txq = eth_dev->data->tx_queues[idx];
		if (!txq)
			continue;
		txq->tx_link = link.link_status;
	}
	for (idx = 0; idx < eth_dev->data->nb_rx_queues; idx++) {
		rxq = eth_dev->data->rx_queues[idx];
		if (!rxq)
			continue;
		rxq->rx_link = link.link_status;
	}

	return 0;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10vf_dev_infos_get(struct rte_eth_dev *dev,
		       struct rte_eth_dev_info *dev_info __rte_unused)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	dev_info->max_rx_queues = port->attr.max_rx_queues;
	dev_info->max_tx_queues = port->attr.max_rx_queues;
	/* includes CRC, cf MAXFRS register */
	dev_info->max_rx_pktlen = TSRN10_MAC_MAXFRM_SIZE;
	dev_info->max_mac_addrs = port->attr.max_mac_addrs;

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	dev_info->rx_queue_offload_capa = DEV_RX_OFFLOAD_VLAN_STRIP;
#endif
	dev_info->rx_offload_capa = DEV_RX_OFFLOAD_CHECKSUM |
				    DEV_RX_OFFLOAD_SCTP_CKSUM |
#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
				    DEV_RX_OFFLOAD_JUMBO_FRAME |
#endif
				    DEV_RX_OFFLOAD_RSS_HASH |
				    DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
				    DEV_RX_OFFLOAD_SCATTER |
				    DEV_RX_OFFLOAD_VLAN |
				    DEV_RX_OFFLOAD_VLAN_STRIP;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	dev_info->tx_queue_offload_capa = DEV_TX_OFFLOAD_MBUF_FAST_FREE;
#endif
	dev_info->tx_offload_capa = DEV_TX_OFFLOAD_IPV4_CKSUM |
				    DEV_TX_OFFLOAD_UDP_CKSUM |
				    DEV_TX_OFFLOAD_TCP_CKSUM |
				    DEV_TX_OFFLOAD_SCTP_CKSUM |
				    DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
				    DEV_TX_OFFLOAD_TCP_TSO |
				    DEV_TX_OFFLOAD_VLAN_INSERT |
				    DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
				    DEV_TX_OFFLOAD_GRE_TNL_TSO |
				    DEV_TX_OFFLOAD_MULTI_SEGS;

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	 /* Default Ring configure */
	dev_info->default_rxportconf.burst_size = 32;
	dev_info->default_txportconf.burst_size = 32;
	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = 256;
	dev_info->default_txportconf.ring_size = 256;
#endif

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_free_thresh = 32,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_free_thresh = 32,
	};
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10vf_dev_promiscuous_enable(struct rte_eth_dev *dev __rte_unused)
{
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10vf_dev_promiscuous_disable(struct rte_eth_dev *dev __rte_unused)
{
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#ifdef USE
static s32 rnpvf_get_mac_addr_vf(struct tsrn10_hw *hw, u8 *mac_addr)
{
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val = 0;

	memset(msgbuf, 0, sizeof(msgbuf));
	/*
	 * If index is one then this is the start of a new list and needs
	 * indication to the PF so it can do it's own list management.
	 * If it is zero then that tells the PF to just clear all of
	 * this VF's macvlans and there is no new list.
	 */
	msgbuf[0] |= RNP_VF_SET_MACVLAN;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 1, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	if (!ret_val)
		if (msgbuf[0] == (RNP_VF_GET_MACVLAN | RNP_VT_MSGTYPE_NACK))
			ret_val = -ENOMEM;

	memcpy(mac_addr, msg_addr, 6);

	return 0;
}
#endif

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
static void
#else
static int
#endif
tsrn10vf_dev_set_mac(struct rte_eth_dev *dev,
		     struct rte_ether_addr *addr)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW_VF(port);

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
	tsrn10_set_mac_addr_vf(port, addr->addr_bytes,
			hw->mbx.vf_num, UINT8_MAX);
#else
	return tsrn10_set_mac_addr_vf(port, addr->addr_bytes,
				hw->mbx.vf_num, UINT8_MAX);
#endif
}

#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void
#else
static int
#endif
tsrn10vf_dev_mac_addr_add(struct rte_eth_dev *dev __rte_unused,
			  struct rte_ether_addr *mac_addr __rte_unused,
			  uint32_t index __rte_unused,
			  uint32_t pool __rte_unused)
{
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#else
	return 0;
#endif
}

static int
tsrn10vf_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	int ret = -EPERM;

	ret = rnpvf_set_mtu(dev, mtu);
	if (ret < 0) {
		TSRN10_PMD_ERR("PF Not Support VF Set MTU Bigger than PF %d\n",
				port->attr.max_mtu);
		return -EPERM;
	}

	return 0;
}

static void
tsrn10vf_vlan_strip_queue_set(struct rte_eth_dev *dev, uint16_t queue, int on)
{
	struct tsrn10_rx_queue *rxq = dev->data->rx_queues[queue];

	if (on)
		rxq->rx_offload_capa |= DEV_RX_OFFLOAD_VLAN_STRIP;
	else
		rxq->rx_offload_capa &= ~DEV_RX_OFFLOAD_VLAN_STRIP;

	rnpvf_set_vlan_q_strip(dev, rxq->attr.index, on);
}

static int
tsrn10vf_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct tsrn10vf_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER_VF(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	uint16_t port;

	if (!adapter->vlan_change_allow ||
			rte_atomic16_read(&hw->mbx.state) == TSRN10_STATE_MBX_POLLING) {
		PMD_DRV_LOG(ERR, "PF Has Set Vlan To VF,So Vf Don't "
				 "Support Set Vlan Filter\n");
		return -EPERM;
	}
	if (vlan_id != adapter->vlan_id && !on) {
		PMD_DRV_LOG(ERR, "Delete Vlan-Id Isn't Exist"
				 " Last Set-Id Is %d\n",
				adapter->vlan_id);
		return -EINVAL;
	}
	if (on && adapter->add_vlan_num >= 1) {
		PMD_DRV_LOG(ERR, "Vf Just Support Set One Vlan-Filter So "
				 "You Must Delete Last Set Vlan ID %d\n",
				 adapter->vlan_id);
		return -EINVAL;
	}
	rnpvf_set_vfta_vf(dev, vlan_id, on);
	if (on) {
		adapter->add_vlan_num++;
		adapter->vlan_id = vlan_id;
		for (port = 0; port < 4; port++) {
			tsrn10_dma_wr(hw, TSRN10_VEB_VID_CFG(port,
						VFNUM(hw->pfvfnum)), vlan_id);
		}
	} else {
		adapter->add_vlan_num--;
		adapter->vlan_id = 0;
		for (port = 0; port < 4; port++) {
			tsrn10_dma_wr(hw, TSRN10_VEB_VID_CFG(port,
						VFNUM(hw->pfvfnum)), 0);
		}
	}

	return 0;
}

static void
tsrn10vf_vlan_hw_strip_enable(struct rte_eth_dev *dev, bool en)
{
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		tsrn10vf_vlan_strip_queue_set(dev, i, en);
}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int
tsrn10vf_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct rte_eth_rxmode *rxmode;

	rxmode = &dev->data->dev_conf.rxmode;

	if (mask & ETH_VLAN_STRIP_MASK) {
		if (rxmode->offloads & DEV_RX_OFFLOAD_VLAN_STRIP)
			tsrn10vf_vlan_hw_strip_enable(dev, true);
		else
			tsrn10vf_vlan_hw_strip_enable(dev, false);
	}

	return 0;
}
#else
static void
tsrn10vf_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	if (mask & ETH_VLAN_STRIP_MASK) {
		if (dev->data->dev_conf.rxmode.hw_vlan_strip)
			tsrn10vf_vlan_hw_strip_enable(dev, true);
		else
			tsrn10vf_vlan_hw_strip_enable(dev, false);
	}
}
#endif

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10vf_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct rte_eth_dev_data *data = dev->data;
	int i = 0;

	PMD_INIT_FUNC_TRACE();

	memset(stats, 0, sizeof(*stats));

	for (i = 0; i < data->nb_rx_queues; i++) {
		stats->q_ipackets[i] = ((struct tsrn10_rx_queue **)
				(data->rx_queues))[i]->stats.ipackets;
		stats->q_ibytes[i] = ((struct tsrn10_rx_queue **)
				(data->rx_queues))[i]->stats.ibytes;
		stats->ipackets += stats->q_ipackets[i];
		stats->ibytes += stats->q_ibytes[i];
	}

	for (i = 0; i < data->nb_tx_queues; i++) {
		stats->q_opackets[i] = ((struct tsrn10_tx_queue **)
				(data->tx_queues))[i]->stats.opackets;
		stats->q_obytes[i] = ((struct tsrn10_tx_queue **)
				(data->tx_queues))[i]->stats.obytes;
		stats->opackets += stats->q_opackets[i];
		stats->obytes += stats->q_obytes[i];
	}
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10vf_stats_reset(struct rte_eth_dev *dev)
{
	struct tsrn10_rx_queue *rxq = NULL;
	struct tsrn10_tx_queue *txq = NULL;
	uint32_t i = 0;

	PMD_INIT_LOG(DEBUG, "statstic clear all port[%d]",
			dev->data->port_id);
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = (struct tsrn10_rx_queue *)dev->data->rx_queues[i];
		rxq->stats.ipackets = 0;
		rxq->stats.ibytes = 0;
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = (struct tsrn10_tx_queue *)dev->data->tx_queues[i];
		txq->stats.opackets = 0;
		txq->stats.obytes = 0;
	}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static int
tsrn10vf_rx_queue_setup(struct rte_eth_dev *dev,
			uint16_t qidx, uint16_t nb_desc,
			unsigned int socket_id,
			const struct rte_eth_rxconf *rx_conf __rte_unused,
			struct rte_mempool *mb_pool)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint16_t dma_ring_base = port->attr.queue_ring_base;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	const struct rte_memzone *rz = NULL;
	struct tsrn10_rx_queue *rxq = NULL;
	uint64_t offloads = 0;
	uint64_t size = 0;

	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(DEBUG, "config rx_queue");

	/* For don't support vf to offload */
	rxq = rte_zmalloc_socket("Tsrn10 ethdev RX queue",
			sizeof(struct tsrn10_rx_queue),
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (!rxq) {
		PMD_INIT_LOG(DEBUG, "alloc rx_queue failed");
		return -ENOMEM;
	}

	if (nb_desc > MAX_BD_COUNT) {
		PMD_INIT_LOG(DEBUG, "rx_ring_desc is %d bigger than max %d",
				nb_desc,
				MAX_BD_COUNT);
		nb_desc = MAX_BD_COUNT;
		rxq->attr.bd_count = nb_desc;
	} else {
		rxq->attr.bd_count = nb_desc;
	}
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	offloads = rx_conf->offloads | dev->data->dev_conf.rxmode.offloads;
#else
	if (dev->data->dev_conf.rxmode.hw_ip_checksum)
		offloads = DEV_RX_OFFLOAD_UDP_CKSUM |
			DEV_RX_OFFLOAD_TCP_CKSUM |
			DEV_RX_OFFLOAD_IPV4_CKSUM |
			DEV_RX_OFFLOAD_SCTP_CKSUM |
			DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM;
#endif
	/* TODO if we need to cal the pf and vf num to summary the index*/
	rxq->attr.sriov_st = hw->mbx.sriov_st;
	rxq->attr.index = (dma_ring_base) + qidx;
	rxq->attr.vf_num = hw->mbx.vf_num;
	rxq->attr.queue_id = qidx;
	rxq->attr.rte_pid = dev->data->port_id;
	/* Because Of Vf Must Use 2 Queue So RSS Default Enable */
	rxq->rx_offload_capa = offloads | DEV_RX_OFFLOAD_RSS_HASH;

	size = sizeof(struct tsrn10_rxsw_entry) * rxq->attr.bd_count;
	rxq->sw_ring = rte_zmalloc_socket("tsrn10vf_ethdev_rxsq",
			size, TSRN10_BD_RING_ALIGN, socket_id);
	if (!rxq->sw_ring)
		goto queue_failed;

	rxq->next_to_clean = 0;

	size = rxq->attr.bd_count * sizeof(struct tsrn10_rx_desc);
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", rxq->attr.queue_id,
			TSRN10_RX_MAX_RING_SZ, TSRN10_BD_RING_ALIGN,
			dev->data->numa_node);
#else
	rz = ring_dma_zone_reserve(dev, "rx_ring", rxq->attr.queue_id,
			TSRN10_RX_MAX_RING_SZ, socket_id);
#endif
	if (rz == NULL) {
		PMD_RX_LOG("ring_%d bd_mem alloc failed", queue_idx);
		goto bd_failed;
	}
	rxq->rx_bdr = rz->addr;
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#ifndef RTE_LIBRTE_XEN_DOM0
	rxq->ring_phys_addr = (uint64_t)rz->phys_addr;
#else
	rxq->ring_phys_addr = rte_mem_phy2mch((rz)->memseg_id, (rz)->phys_addr);
#endif
#else
	rxq->ring_phys_addr = rz->iova;
#endif
	tsrn10_setup_rxbdr(dev, hw, rxq, mb_pool);
	rxq->free_mbufs = rte_zmalloc_socket("rxq->free_mbufs",
			sizeof(struct rte_mbuf *) * 1024,
			RTE_CACHE_LINE_SIZE, socket_id);

	rxq->nb_rx_free = nb_desc - 1;
	rxq->rx_free_thresh = 32;
	rxq->rx_free_trigger = rxq->rx_free_thresh - 1;

	dev->data->rx_queues[qidx] = rxq;

	tsrn10_rxq_vec_setup_default(rxq);
	return 0;
bd_failed:
	rte_free(rxq->sw_ring);
	rxq->sw_ring = NULL;
queue_failed:

	return -ENOMEM;
}

static void tsrn10vf_rx_queue_release(void *_rxq)
{
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)_rxq;
	int32_t i = 0, size = 0;
	/* This Function will call when setup the queue and queue isn't null */
	PMD_INIT_FUNC_TRACE();

	if (!rxq)
		return;
	/* Clean the bd ring */
	/* Free all the Rx ring mbuf */
	if (rxq->sw_ring) {
		for (i = 0; i < rxq->attr.bd_count; i++) {
			if (rxq->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
				rxq->sw_ring[i].mbuf = NULL;
			}
		}
		size = sizeof(struct tsrn10_rxsw_entry) * rxq->attr.bd_count;
		memset(rxq->sw_ring, 0, size);
		rte_free(rxq->sw_ring);
	}
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static void tsrn10vf_dev_rxq_release(struct rte_eth_dev *dev, uint16_t qid)
{
	tsrn10vf_rx_queue_release(dev->data->rx_queues[qid]);
}
#endif

static int
tsrn10vf_tx_queue_setup(struct rte_eth_dev *dev,
			uint16_t qidx, uint16_t nb_desc,
			unsigned int socket_id,
			const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_txmode *txmode = &dev->data->dev_conf.txmode;
#endif
	uint16_t dma_ring_base = port->attr.queue_ring_base;
	struct tsrn10vf_eth_adapter *adapter = port->adapt;
	struct rte_eth_dev_data *data = dev->data;
	struct tsrn10_hw *hw = &adapter->hw;
	struct tsrn10_tx_queue *txq;
	int err = 0;

	PMD_INIT_FUNC_TRACE();

	if (nb_desc > MAX_BD_COUNT)
		return -1;

	/* Check Whether Queue Has Been Create If So Release it */
	if (dev->data->tx_queues[qidx]) {
		tsrn10vf_tx_queue_release(dev->data->tx_queues[qidx]);
		dev->data->tx_queues[qidx] = NULL;
	}

	txq = rte_zmalloc_socket("tsrn10_txq", sizeof(struct tsrn10_tx_queue),
			RTE_CACHE_LINE_SIZE, socket_id);

	if (!txq) {
		TSRN10_PMD_ERR("Failed to allocate TX ring memory");
		return -ENOMEM;
	}
	txq->attr.index = dma_ring_base + qidx;
	txq->attr.lane_id = port->attr.nr_port;
	txq->attr.queue_id = qidx;
	txq->attr.bd_count = nb_desc;
	txq->attr.rte_pid = dev->data->port_id;
	txq->attr.sriov_st = hw->mbx.sriov_st;
	txq->attr.vf_num = hw->mbx.vf_num;
	/* When PF and VF all used that the PF must regards
	 * it as a VF Just For dma-ring resource divide
	 */
	err = tsrn10_alloc_txbdr(dev, txq, nb_desc, socket_id);
	if (err)
		goto fail;

	PMD_DRV_LOG(INFO, "VF[%d] dev:[%d] txq queue_id[%d] "
			"dma_idx %d socket %d\n",
			hw->mbx.vf_num, txq->attr.rte_pid, qidx,
			txq->attr.index, socket_id);

	tsrn10_setup_txbdr(hw, txq);
	txq->nb_tx_free = nb_desc - 1;
	txq->tx_rs_thresh = 32;
	txq->tx_free_thresh = 32;
	txq->tx_free_trigger = txq->tx_free_thresh + 1;
	txq->tx_next_dd = txq->tx_rs_thresh - 1;
	txq->tx_next_rs = txq->tx_rs_thresh - 1;
	txq->last_desc_cleaned = (uint16_t)(txq->attr.bd_count - 1);
	txq->last_clean = 0;
	data->tx_queues[qidx] = txq;

	int i = 0, prev = 0;
	struct tsrn10_txsw_entry *sw_ring = txq->sw_ring;
	prev = (uint16_t)(txq->attr.bd_count - 1);

	for (i = 0; i < txq->attr.bd_count; i++) {
		volatile struct tsrn10_tx_desc *txbd = &txq->tx_bdr[i];
		txbd->d.cmd = 0;
		sw_ring[i].mbuf = NULL;
		sw_ring[i].last_id = i;
		sw_ring[i].rs_bit_set = false;
		sw_ring[i].cur_id = i;
		sw_ring[i].prev_id = prev;
		sw_ring[prev].next_id = i;
		prev = i;
	}
#if RTE_VERSION_NUM(16, 5, 0, 16) > RTE_VERSION
	txq->offloads |= tx_conf->txq_flags;
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	txq->offloads |= ((txmode->offloads & DEV_TX_OFFLOAD_VLAN_INSERT) ?
			DEV_TX_OFFLOAD_VLAN_INSERT : 0);
	txq->offloads |= ((txmode->offloads & DEV_TX_OFFLOAD_QINQ_INSERT) ?
			DEV_TX_OFFLOAD_QINQ_INSERT : 0);
#endif

	tsrn10_setup_tx_function(dev, txq);
	return 0;
fail:
	rte_free(txq);

	return err;
}

static int tsrn10vf_tx_queue_start(struct rte_eth_dev *eth_dev, uint16_t qidx)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(eth_dev);
	struct tsrn10_tx_queue *txq;
	uint32_t dma_index;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	txq = eth_dev->data->tx_queues[qidx];
	if (!txq) {
		PMD_INIT_LOG(ERR, "Can't start Tx Queue %d it's not Setup By "
			       "tx_queue_setup API\n",
				qidx);
		return -EINVAL;
	}
	if (eth_dev->data->tx_queue_state[qidx] ==
				RTE_ETH_QUEUE_STATE_STOPPED) {
		txq->txq_started = TSRN10_TX_QUEUE_START;
		eth_dev->data->tx_queue_state[qidx] =
				RTE_ETH_QUEUE_STATE_STARTED;
		dma_index = txq->attr.index;
		/* Enable Tx Queue */
		tsrn10_dma_wr(hw,
				TSRN10_DMA_TXQ_START(dma_index), 1);
	}
#else
	if (qidx < eth_dev->data->nb_tx_queues) {
		txq = eth_dev->data->tx_queues[qidx];
		if (!txq) {
			PMD_INIT_LOG(ERR, "Can't start Tx Queue %d "
				"it's not Setup By tx_queue_setup API\n", qidx);
			return -EINVAL;
		}
		txq->txq_started = TSRN10_TX_QUEUE_START;
		dma_index = txq->attr.index;
		/* Enable Tx Queue */
		tsrn10_dma_wr(hw,
				TSRN10_DMA_TXQ_START(dma_index), 1);
	} else {
		return -EINVAL;
	}
#endif

	return 0;
}

static int tsrn10vf_tx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t qidx)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(eth_dev);
	struct tsrn10_tx_queue *txq;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	txq = eth_dev->data->tx_queues[qidx];
	if (!txq)
		return 0;
	if (eth_dev->data->tx_queue_state[qidx] ==
				RTE_ETH_QUEUE_STATE_STARTED) {
		txq->txq_started = TSRN10_TX_QUEUE_STOP;
		tsrn10_tx_queue_reset(hw, txq);
		tsrn10_tx_queue_sw_reset(txq);
		tsrn10_tx_queue_release_mbuf(txq);
		eth_dev->data->tx_queue_state[qidx] =
				RTE_ETH_QUEUE_STATE_STOPPED;
	}
#else
	if (qidx < eth_dev->data->nb_tx_queues) {
		txq = eth_dev->data->tx_queues[qidx];
		if (!txq)
			return -1;
		txq->txq_started = TSRN10_TX_QUEUE_STOP;
		tsrn10_tx_queue_reset(hw, txq);
		tsrn10_tx_queue_sw_reset(txq);
		tsrn10_tx_queue_release_mbuf(txq);
	} else {
		return -1;
	}
#endif
	return 0;
}

static void tsrn10vf_tx_queue_release(void *_txq)
{
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)_txq;
	int32_t i = 0, size = 0;

	/* This Function will call when prepare to setup the queue
	 * but the queue isn't null clear queu most queue mem
	 */
	if (!txq)
		return;
	PMD_INIT_FUNC_TRACE();
	/* Clean the bd ring */
	/* Free all the Rx ring mbuf */
	if (txq->sw_ring) {
		for (i = 0; i < txq->attr.bd_count; i++) {
			if (txq->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
		}
		size = sizeof(struct tsrn10_txsw_entry) * txq->attr.bd_count;
		memset(txq->sw_ring, 0, size);
		rte_free(txq->sw_ring);
	}
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static void tsrn10vf_dev_txq_release(struct rte_eth_dev *dev,
				     uint16_t qid)
{
	tsrn10vf_tx_queue_release(dev->data->tx_queues[qid]);
}
#endif

static int tsrn10vf_rx_queue_stop(struct rte_eth_dev *dev, uint16_t qidx)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_rx_queue *rxq;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	rxq = dev->data->rx_queues[qidx];
	if (!rxq)
		return 0;
	if (dev->data->rx_queue_state[qidx] ==
			RTE_ETH_QUEUE_STATE_STARTED) {
		rxq->rxq_started = false;
		tsrn10_rx_queue_release_mbuf(rxq);
		tsrn10_rx_queue_reset(dev, hw, rxq);
		tsrn10_rx_queue_sw_reset(rxq);
		dev->data->rx_queue_state[qidx] = RTE_ETH_QUEUE_STATE_STOPPED;
		tsrn10_dma_wr(hw,
				TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
	}
#else
	if (qidx < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[qidx];
		if (!rxq)
			return -1;
		rxq->rxq_started = false;
		tsrn10_rx_queue_release_mbuf(rxq);
		tsrn10_rx_queue_reset(dev, hw, rxq);
		tsrn10_rx_queue_sw_reset(rxq);
		tsrn10_dma_wr(hw,
				TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
	} else {
		return -1;
	}
#endif
	return 0;
}

static int tsrn10vf_rx_queue_start(struct rte_eth_dev *dev, uint16_t qidx)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_rx_queue *rxq;
	uint32_t dma_idx;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	rxq = dev->data->rx_queues[qidx];
	if (dev->data->rx_queue_state[qidx] ==
			RTE_ETH_QUEUE_STATE_STOPPED) {
		/* enable ring */
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 0);

		if (tsrn10_alloc_rxq_mbuf(rxq) != 0) {
			PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
					qidx);
			return -1;
		}

		rxq->nb_rx_free = rxq->attr.bd_count - 1;
		rxq->rxq_started = true;
		if (rxq->next_to_clean)
			tsrn10_wr_reg(rxq->rx_tailreg, rxq->next_to_clean - 1);
		else
			tsrn10_wr_reg(rxq->rx_tailreg, rxq->attr.bd_count - 1);
		dma_idx = rxq->attr.index;

		tsrn10_dma_wr(hw,
				TSRN10_DMA_RXQ_START(dma_idx), 1);
		dev->data->rx_queue_state[qidx] = RTE_ETH_QUEUE_STATE_STARTED;
		tsrn10_dma_wr(hw,
			TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(dma_idx), 500000000);
	}
#else
	if (qidx < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[qidx];
		if (!rxq)
			return -1;
		/* enable ring */
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 0);

		if (tsrn10_alloc_rxq_mbuf(rxq) != 0) {
			PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
					qidx);
			return -1;
		}

		rxq->nb_rx_free = rxq->attr.bd_count - 1;
		rxq->rxq_started = true;
		if (rxq->next_to_clean)
			tsrn10_wr_reg(rxq->rx_tailreg, rxq->next_to_clean - 1);
		else
			tsrn10_wr_reg(rxq->rx_tailreg, rxq->attr.bd_count - 1);
		dma_idx = rxq->attr.index;
		tsrn10_dma_wr(hw,
				TSRN10_DMA_RXQ_START(dma_idx), 1);
		tsrn10_dma_wr(hw,
			TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(dma_idx), 500000000);
	} else {
		return -1;
	}
#endif
	return 0;
}

static int tsrn10vf_fw_version_get(struct rte_eth_dev *eth_dev,
				   char *fw_version, size_t fw_size)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(eth_dev);
	char *ver = (char *)&hw->fw_version;
	int ret = 0;

	ret = snprintf(fw_version, fw_size, "%d.%d.%d.%d",
			ver[3],
			ver[2],
			ver[1],
			ver[0]);
	ret += 1; /* add string null-terminator */

	if (fw_size < (size_t)ret)
		return ret;

	return 0;
}

static const struct eth_dev_ops tsrn10vf_eth_dev_ops = {
	.dev_configure		= tsrn10vf_dev_configure,
	.dev_start		= tsrn10vf_dev_start,
	.dev_stop		= tsrn10vf_dev_stop,
	.dev_close		= tsrn10vf_dev_close,
	.link_update		= tsrn10vf_dev_link_update,
	.dev_infos_get		= tsrn10vf_dev_infos_get,
	.promiscuous_enable	= tsrn10vf_dev_promiscuous_enable,
	.promiscuous_disable	= tsrn10vf_dev_promiscuous_disable,
	.mac_addr_set		= tsrn10vf_dev_set_mac,
	.mac_addr_add		= tsrn10vf_dev_mac_addr_add,
	.mtu_set		= tsrn10vf_dev_mtu_set,

	.vlan_strip_queue_set	= tsrn10vf_vlan_strip_queue_set,
	.vlan_filter_set        = tsrn10vf_vlan_filter_set,
	.vlan_offload_set       = tsrn10vf_vlan_offload_set,

	.stats_get		= tsrn10vf_dev_stats_get,
	.stats_reset		= tsrn10vf_stats_reset,

	.rx_queue_setup		= tsrn10vf_rx_queue_setup,
	.rx_queue_start		= tsrn10vf_rx_queue_start,
	.rx_queue_stop		= tsrn10vf_rx_queue_stop,
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	.rx_queue_release	= tsrn10vf_dev_rxq_release,
#else
	.rx_queue_release	= tsrn10vf_rx_queue_release,
#endif
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.rxq_info_get		= tsrn10_rx_queue_info_get,
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	.fw_version_get         = tsrn10vf_fw_version_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.rx_burst_mode_get      = tsrn10_rx_burst_mode_get,
#endif
	.tx_queue_setup		= tsrn10vf_tx_queue_setup,
	.tx_queue_start		= tsrn10_tx_queue_start,
	.tx_queue_stop		= tsrn10vf_tx_queue_stop,
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	.tx_queue_release	= tsrn10vf_dev_txq_release,
#else
	.tx_queue_release	= tsrn10vf_tx_queue_release,
#endif
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.txq_info_get		= tsrn10_tx_queue_info_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.tx_burst_mode_get      = tsrn10_tx_burst_mode_get,
#endif
};

static const struct eth_dev_ops tsrn10vf_secondary_ops = {
	.link_update            = tsrn10vf_dev_link_update,
	.dev_infos_get          = tsrn10vf_dev_infos_get,
	.promiscuous_enable     = tsrn10vf_dev_promiscuous_enable,
	.promiscuous_disable    = tsrn10vf_dev_promiscuous_disable,
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	.mac_addr_set		= tsrn10vf_dev_set_mac,
	.vlan_strip_queue_set	= tsrn10vf_vlan_strip_queue_set,
	.vlan_filter_set        = tsrn10vf_vlan_filter_set,
	.vlan_offload_set       = tsrn10vf_vlan_offload_set,
	.mtu_set		= tsrn10vf_dev_mtu_set,
#endif
	.mac_addr_add		= tsrn10vf_dev_mac_addr_add,


#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.rxq_info_get		= tsrn10_rx_queue_info_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.rx_burst_mode_get      = tsrn10_rx_burst_mode_get,
#endif
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.txq_info_get		= tsrn10_tx_queue_info_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.tx_burst_mode_get      = tsrn10_tx_burst_mode_get,
#endif
};

struct tsrn10_mac_api tsrn10vf_mac_ops = {
	.init_hw = tsrn10_init_hw_vf,
	.reset_hw = tsrn10_reset_hw_vf,
	.get_fw_ver = tsrn10_get_fw_version_vf,
	.get_mac_addr = tsrn10_get_mac_addr_vf,
	.set_rafb = tsrn10_set_mac_addr_vf,
};

static int tsrn10vf_ops_init(struct tsrn10vf_eth_adapter *adap,
			     struct tsrn10_hw *hw __rte_unused)
{
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	struct tsrn10_share_ops *share_priv;

	share_priv = calloc(1, sizeof(*share_priv));
	if (!share_priv) {
		PMD_DRV_LOG(ERR, "calloc share_priv failed");
		return -ENOMEM;
	}

	adap->ndev->process_private = share_priv;
	share_priv->mac_api = tsrn10vf_mac_ops;
	share_priv->mbx_api = tsrn10_mbx_vf_ops;
#else
	hw->mac.ops = tsrn10vf_mac_ops;
#endif
	return 0;
}

static void
tsrn10vf_intr_enable(struct rte_eth_dev *dev __rte_unused, bool en __rte_unused)
{
	/* write irq vector to MBX VF2PF according vf-id
	 * we decide all vf mbx interrut vector use 0
	 */
	/* Note mbx interrupt mask bit 1 == shield both vf and pf interrupt
	 * trigger
	 */
	struct tsrn10_hw *hw __rte_unused = TSRN10_DEV_TO_HW_VF(dev);
}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static void
tsrn10vf_pf_set_vlan_filter_on(struct rte_eth_dev *dev, uint32_t *msgbuf)
{
	struct tsrn10vf_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER_VF(dev);
	uint64_t orig_offloads = 0;
	uint32_t ctrl_code = 0;
	uint32_t on = 0;

	ctrl_code = msgbuf[TSRN10_ARRAY_CTRL_OFFSET];
	on = ctrl_code & RNP_VF_RNP_VF_FILTER_EN;

	if (on)
		orig_offloads |= ETH_VLAN_FILTER_OFFLOAD;
	else
		orig_offloads &= ~ETH_VLAN_FILTER_OFFLOAD;

	orig_offloads = dev->data->dev_conf.rxmode.offloads;
	adapter->vlan_change_allow = on;
}
#else
static void
tsrn10vf_pf_set_vlan_filter_on(struct rte_eth_dev *dev, uint32_t *msgbuf)
{
	struct tsrn10vf_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER_VF(dev);
	uint32_t ctrl_code = 0;
	uint32_t on = 0;

	ctrl_code = msgbuf[TSRN10_ARRAY_CTRL_OFFSET];
	on = ctrl_code & RNP_VF_RNP_VF_FILTER_EN;
	dev->data->dev_conf.rxmode.hw_vlan_filter = ctrl_code ? 1 : 0;
	adapter->vlan_change_allow = on;
}
#endif

static void
tsrn10vf_pf_set_link_update(struct rte_eth_dev *dev, uint32_t *msgbuf)
{
	struct tsrn10vf_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER_VF(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	bool link_changed = false;
	uint32_t ctrl_code = 0;
	uint32_t speed = 0;

	ctrl_code = msgbuf[TSRN10_ARRAY_CTRL_OFFSET];

	if (ctrl_code & RNP_PF_LINK_UP) {
		if (!port->attr.link_ready)
			link_changed = true;
		port->attr.link_ready = true;
		speed = tsrn10_get_real_speed(ctrl_code & RNP_PF_SPEED_MASK);
		adapter->max_link_speed = speed;
	} else {
		if (port->attr.link_ready)
			link_changed = true;
		port->attr.link_ready = false;
		adapter->max_link_speed = 0;
	}
	if (link_changed) {
		tsrn10vf_dev_link_update(dev, 0);
		/* Notice Event Process Link Status Change */
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		rte_eth_dev_callback_process(dev,
				RTE_ETH_EVENT_INTR_LSC, NULL);
#elif (RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION && \
       RTE_VERSION_NUM(17, 8, 0, 0) > RTE_VERSION) || \
      (RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION && \
       RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION)
		_rte_eth_dev_callback_process(dev,
				RTE_ETH_EVENT_INTR_LSC, NULL);
#elif RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION && \
      RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
		_rte_eth_dev_callback_process(dev,
				RTE_ETH_EVENT_INTR_LSC, NULL, NULL);
#else
		_rte_eth_dev_callback_process(dev,
				RTE_ETH_EVENT_INTR_LSC);
#endif
	}
}

static void
tsrn10vf_pf_set_mtu(struct rte_eth_dev *dev, uint32_t *msgbuf)
{
	uint32_t ctrl_code = 0;
	uint32_t mtu = 0;

	ctrl_code = msgbuf[TSRN10_ARRAY_CTRL_OFFSET];
	mtu = ctrl_code;

	if (mtu)
		dev->data->mtu = mtu;
}

#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void
tsrn10vf_dev_interrupt_handler(struct rte_intr_handle *handle __rte_unused,
			       void *param)
#else
static void
tsrn10vf_dev_interrupt_handler(void *param)
#endif
{
	/* 1.Disable This Vector interrupt trigger */
	/* 2.Check If This Is a MBX Interrupt */
	/* 3.Read message from PF and Do Event */
	/* 4.Enable This Vector interrupt trigger */
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	uint32_t msgbuf[RNP_VFMAILBOX_SIZE];
	int32_t ret = -EINVAL;
	int32_t op_code = 0;

	if (rte_atomic16_read(&hw->mbx.state) == TSRN10_STATE_MBX_POLLING)
		return;

	ret = ops->check_for_msg(hw, MBX_VF);
	if (ret < 0)
		return;
	if (ops->read(hw, msgbuf, RNP_VFMAILBOX_SIZE, MBX_VF))
		return;

	op_code = msgbuf[TSRN10_ARRAY_OPCODE_OFFSET];
	if (op_code & RNP_VT_MSGTYPE_CTS)
		return;
	TSRN10_PMD_LOG(INFO, "interrupt generate\n");

	switch (op_code) {
	case RNP_PF_SET_VLAN_FILTER:
		tsrn10vf_pf_set_vlan_filter_on(dev, msgbuf);
		break;
	case RNP_PF_SET_LINK:
		tsrn10vf_pf_set_link_update(dev, msgbuf);
		break;
	case RNP_PF_SET_MTU:
		tsrn10vf_pf_set_mtu(dev, msgbuf);
		break;
	case RNP_PF_SET_RESET:
		/* TODO Reset VF Operate */
		break;
	default:
		TSRN10_PMD_LOG(WARNING, "VF Isn't Operate code [%d]\n", op_code);
	}
}

static void
tsrn10vf_port_attr_init(struct tsrn10vf_eth_adapter *adapt __rte_unused,
			struct tsrn10_eth_port *port)
{
	port->attr.max_rx_queues = TSRN10_VF_MAX_RXQ_NUM;
	port->attr.max_tx_queues = TSRN10_VF_MAX_TXQ_NUM;
}

#ifdef USE
static void
tsrn10_mbx_irq_setup(struct tsrn10_hw *hw)
{
	uint16_t vf_id = hw->mbx.vf_num;

	mbx_wr32(hw, TSRN10_PF2VF_MBX_VEC_CTR(vf_id),
			  TSRN10_MBX_VECTOR_ID);
}
#endif

static int8_t
tsrn10vf_port_init_resource(struct tsrn10vf_eth_adapter *adapter,
			    struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = &adapter->hw;
	int8_t ret;

	tsrn10vf_port_attr_init(adapter, port);

	adapter->port = port;
	port->dev = dev;
	port->adapt = adapter;
	dev->data->mac_addrs = rte_zmalloc("tsrn10vf", RTE_ETHER_ADDR_LEN, 0);
	tsrn10_get_fw_version(dev, hw);
	/* reset VF */
	tsrn10_reset_hw(dev, hw);
	tsrn10_get_mac_addr(dev, port->mac_addr);
	/* Get the VF resource info */
	if (tsrn10_get_queue_info_vf(dev))
		return -EPERM;
	/* Setup port attr info  */
	port->attr.link_ready = adapter->link_up;
	ret = rnpvf_get_max_mtu(dev);
	if (ret < 0)
		return -EPERM;
	rte_intr_disable(intr_handle);
	tsrn10vf_intr_enable(dev, false);

	if (rte_is_zero_ether_addr((const struct rte_ether_addr *)hw->mac.assign_addr)) {
		ret = tsrn10_set_rafb(dev, hw->mac.set_addr, hw->mbx.vf_num,
					       TSRN10_VF_DEFAULT_PORT);
		if (ret) {
			rte_free(dev->data->mac_addrs);
			dev->data->mac_addrs = NULL;
			return -EINVAL;
		}
	}
#if RTE_VERSION_NUM(19, 8, 0, 0) < RTE_VERSION
	rte_ether_addr_copy((const struct rte_ether_addr *)hw->mac.assign_addr,
			dev->data->mac_addrs);
#else
	ether_addr_copy((struct ether_addr *)hw->mac.assign_addr,
			dev->data->mac_addrs);
#endif
	/* MTU */
	dev->data->mtu = port->attr.max_mtu;

	/* Set interrupt Deal Progress */
	rte_intr_callback_register(intr_handle,
			tsrn10vf_dev_interrupt_handler, dev);

	rte_intr_enable(intr_handle);
	tsrn10vf_intr_enable(dev, true);

#if RTE_VERSION_NUM(18, 2, 4, 16) <= RTE_VERSION
	rte_eth_dev_probing_finish(dev);
#endif

	return 0;
}

#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
static int
tsrn10vf_dev_secondary_init(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	char name[RTE_ETH_NAME_MAX_LEN] = "";
	struct rte_eth_dev *eth_dev;

	memcpy(name, pci_dev->device.name,
			strlen(pci_dev->device.name));
	eth_dev = rte_eth_dev_attach_secondary(name);

	if (!dev->data->tx_queues)
		/* Use default TX function if we get here */
		PMD_INIT_LOG(NOTICE,
				"No TX queues configured yet. Using default TX function.");
	if (eth_dev) {
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
		struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);
		struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(eth_dev);
		struct tsrn10vf_eth_adapter *adapter;

		adapter = port->adapt;
		tsrn10vf_ops_init(adapter, hw);
#endif
		eth_dev->dev_ops = &tsrn10vf_secondary_ops;

		eth_dev->rx_pkt_burst = &tsrn10_recv_pkts;
		eth_dev->tx_pkt_burst = &tsrn10_xmit_pkts;
		eth_dev->tx_pkt_prepare = &tsrn10_prep_pkts;
#if RTE_VERSION_NUM(18, 2, 4, 16) <= RTE_VERSION
		rte_eth_dev_probing_finish(eth_dev);
#endif
	}

	return 0;
}
#endif
/*
 * Virtual Function device init
 */
static int eth_tsrn10vf_dev_init(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	char name[RTE_ETH_NAME_MAX_LEN] = " ";
	struct tsrn10vf_eth_adapter *adapter;
	struct tsrn10_hw *hw;
	int ret = 0;

	dev->dev_ops = &tsrn10vf_eth_dev_ops;
	dev->rx_pkt_burst = tsrn10_scattered_rx;
	dev->tx_pkt_burst = tsrn10_xmit_pkts;

	/* for secondary processes, we don't initialise any further as primary
	 * has already done this work. Only check we don't need a different
	 * RX function
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		/* TX queue function in primary, set by last queue initialized
		 * Tx queue may not initialized by primary process
		 */
#if RTE_VERSION_NUM(17, 8, 0, 0) > RTE_VERSION
		return -EINVAL;
#else
		tsrn10vf_dev_secondary_init(dev);
		return 0;
#endif
	}

	snprintf(name, sizeof(name), "tsrn10vf_adapter_%d", dev->data->port_id);
	adapter = rte_zmalloc(name, sizeof(*adapter), 0);
	if (!adapter)
		return -ENOMEM;
	hw = &adapter->hw;

	rte_eth_copy_pci_info(dev, pci_dev);
	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->back = (void *)adapter;

	hw->nic_reg = (char *)pci_dev->mem_resource[TSRN10_CFG_BAR].addr;
	hw->iobar0 = (char *)pci_dev->mem_resource[0].addr;
	hw->iobar0_len = pci_dev->mem_resource[0].len;
	adapter->ndev = dev;
	tsrn10vf_ops_init(adapter, hw);
	/* init mailbox */
	tsrn10_init_mbx_ops_vf(hw);
	/* Prepare Reg Hw Offset */
	tsrn10_reg_offset_init(hw);
	/* VF just support one port */
	adapter->num_ports = 1;

	ret = tsrn10vf_port_init_resource(adapter, dev);
	if (ret)
		return ret;

	return 0;
}

/* Virtual Function device uninit */

static int
eth_tsrn10vf_dev_uninit(struct rte_eth_dev *eth_dev)
{
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	eth_dev->dev_ops = NULL;
	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	eth_dev->tx_pkt_prepare = NULL;
#endif

	tsrn10vf_dev_close(eth_dev);

	return 0;
}

static const struct rte_pci_id pci_id_tsrn10vf_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_VF_C) },
	/* only exist 2*1G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N400_VF) },
	{ .vendor_id = 0, /* */ },
};

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION

static int eth_tsrn10vf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
				  struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct tsrn10_eth_port), eth_tsrn10vf_dev_init);
}

static int eth_tsrn10vf_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev,
			eth_tsrn10vf_dev_uninit);
}

/*
 * virtual function driver struct
 */
static struct rte_pci_driver rte_tsrn10vf_pmd = {
	.id_table = pci_id_tsrn10vf_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_tsrn10vf_pci_probe,
	.remove = eth_tsrn10vf_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_tsrn10vf, rte_tsrn10vf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_tsrn10vf, pci_id_tsrn10vf_map);
RTE_PMD_REGISTER_KMOD_DEP(net_tsrn10vf, "* igb_uio | vfio-pci");

#else

static struct eth_driver rte_tsrn10vf_pmd = {
	.pci_drv = {
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
		.name = "rte_tsrn10vf_pmd",
#endif
		.id_table = pci_id_tsrn10vf_map,
#if RTE_VERSION_NUM(17, 2, 0, 16) <= RTE_VERSION
		.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
#else
		.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC |
			RTE_PCI_DRV_DETACHABLE,
#endif
#if RTE_VERSION_NUM(16, 11, 0, 16) <= RTE_VERSION
		.probe = rte_eth_dev_pci_probe,
		.remove = rte_eth_dev_pci_remove,
#endif
	},
	.eth_dev_init = eth_tsrn10vf_dev_init,
	.eth_dev_uninit = eth_tsrn10vf_dev_uninit,
	.dev_private_size = sizeof(struct tsrn10_eth_port),
};

#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
RTE_PMD_REGISTER_PCI(net_tsrn10vf, rte_tsrn10vf_pmd.pci_drv);
RTE_PMD_REGISTER_PCI_TABLE(net_tsrn10vf, pci_id_tsrn10vf_map);
#if RTE_VERSION_NUM(17, 2, 0, 16) == RTE_VERSION
RTE_PMD_REGISTER_KMOD_DEP(net_tsrn10vf, "* igb_uio | uio_pci_generic | vfio");
#endif
#else /* RTE_VERSION < 16.04 */
/*
 * Driver initialization routine.
 * Invoked once at EAL init time.
 * Register itself as the [Poll Mode] Driver of PCI TSRN10 devices.
 */
static int
rte_tsrn10vf_pmd_init(const char *name __rte_unused, const char *params __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	rte_eth_driver_register(&rte_tsrn10vf_pmd);

	return 0;
}

static struct rte_driver rte_tsrn10vf_driver = {
	.type = PMD_PDEV,
	.init = rte_tsrn10vf_pmd_init,
};
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
PMD_REGISTER_DRIVER(rte_tsrn10vf_driver);
#else
PMD_REGISTER_DRIVER(rte_tsrn10vf_driver, tsrn10vf);
DRIVER_REGISTER_PCI_TABLE(tsrn10vf, pci_id_tsrn10vf_map);
#endif
#endif /* <= 16.04 */

#endif
