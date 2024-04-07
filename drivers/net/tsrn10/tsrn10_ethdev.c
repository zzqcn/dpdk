#include <stdbool.h>
#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <linux/limits.h>
#include <inttypes.h>
#include <netinet/in.h>

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
#include <rte_random.h>
#include <rte_string_fns.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_alarm.h>

#include "tsrn10.h"
#include "tsrn10_flow.h"
#include "base/tsrn10_api.h"
#include "base/tsrn10_mac_regs.h"
#include "base/tsrn10_bitrev.h"
#include "base/tsrn10_tcam.h"
#include "base/tsrn10_pcs.h"
#include "tsrn10_mbx.h"
#include "tsrn10_mbx_fw.h"
#include "tsrn10_phy.h"

#define TSRN10_REG_DEBUG_VALUE		(0x1a2b3c4d)
#define TSRN10_HW_MAC_LOOPBACK_ARG	"hw_loopback"
#define TSRN10_FW_UPDATE		"fw_update"
#define TSRN10_RX_FUNC_SELECT		"rx_func_sec"
#define TSRN10_TX_FUNC_SELECT		"tx_func_sec"
#define TSRN10_FW_4X10G_10G_1G_DET	"fw_4x10g_10g_1g_auto_det"
#define TSRN10_FW_FORCE_SPEED_1G	"fw_force_1g_speed"

int signal_start;
/* Function Not Use Or Need To Achieve*/
extern uint8_t rss_default_key[40];

extern struct rte_flow_ops tsrn10_flow_ops;
extern struct tsrn10_pcs_operations pcs_ops_generic;
extern struct tsrn10_pma_operations pma_ops_generic;

int tsrn10_logtype_pmd;

uint64_t tsrn10_timestamp_dynflag;
int tsrn10_timestamp_dynfield_offset = -1;

static int tsrn10_mac_init(struct rte_eth_dev *dev);

static void tsrn10_mac_rx_disable(struct rte_eth_dev *dev);
static void tsrn10_mac_tx_disable(struct rte_eth_dev *dev);

static void tsrn10_rx_queue_release(void *_rxq);
static void tsrn10_tx_queue_release(void *_rxq);
static int tsrn10_link_update(struct rte_eth_dev *eth_dev,
			      int wait_to_complete __rte_unused);
static uint32_t tsrn10_dev_cal_xstats_num(void);

static void tsrn10_qinq_insert_offload_en(struct rte_eth_dev *dev, bool on);
static void tsrn10_vlan_insert_offload_en(struct rte_eth_dev *dev, bool on);

static bool system_no_interrupt;
struct tsrn10_mac_api tsrn10_mac_indep_ops;
struct tsrn10_mac_api tsrn10_mac_ops;
struct tsrn10_phy_api tsrn10_phy_ops;
struct tsrn10_phy_api tsrn10_fiber_ops;
extern struct tsrn10_mbx_api tsrn10_mbx_pf_ops;

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int
tsrn10_vlan_offload_set(struct rte_eth_dev *dev, int mask);
#else
static void
tsrn10_vlan_offload_set(struct rte_eth_dev *dev, int mask);
#endif
static void
tsrn10_vlan_strip_queue_set(struct rte_eth_dev *dev, uint16_t queue, int on);

#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void
tsrn10_dev_interrupt_handler(struct rte_intr_handle *handle __rte_unused,
			     void *parm);
#else
static void tsrn10_dev_interrupt_handler(void *parm);
#endif
static int
tsrn10_special_ops_init(struct tsrn10_eth_adapter *adap,
			struct rte_eth_dev *dev __rte_unused);

/*  Set device link up: enable tx. */
static int tsrn10_dev_set_link_up(struct rte_eth_dev *eth_dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(eth_dev);
	uint16_t nr_lane = port->attr.nr_port;
	struct tsrn10_rx_queue *rxq;
	uint16_t timeout;
	uint32_t state;
	uint32_t ctrl;
	uint16_t idx;

	PMD_INIT_FUNC_TRACE();

	if (rte_atomic64_read(&port->state) != TSRN10_PORT_STATE_FINISH) {
		TSRN10_PMD_LOG(WARNING, "port[%d] is not support link "
				"up change when dev_start is not finish\n",
				eth_dev->data->port_id);
		return -EINVAL;
	}
	/* Cur link-state Is Down Verity The Rx Dma Queue State Is Empty */
	if (!port->attr.link_ready) {
		for (idx = 0; idx < eth_dev->data->nb_rx_queues; idx++) {
			rxq = eth_dev->data->rx_queues[idx];
			if (!rxq)
				continue;
			timeout = 0;
			do {
				if (!tsrn10_dma_rd(hw,
					TSRN10_DMA_RXQ_READY(rxq->attr.index)))
					break;
				rte_delay_us(10);
				timeout++;
			} while (timeout < 1000);
		}
	}
	/* Tell Firmware Do Link Up Work */
	rnp_mbx_ifup_down(eth_dev, nr_lane, 1);
#ifdef RTE_LIBRTE_PMD_TSRN10_NO_IRQ
	rnp_mbx_link_event_enable(eth_dev, false);
#endif
	/* Verity The Link Up Event Has Been Generate But
	 * The Port May Be Never Up Because Of Remote Fault Or Unplugged
	 */
	timeout = 0;
	do {
		state = tsrn10_rd_reg(hw->dev_dummy);
		if (state & BIT(nr_lane))
			break;
		timeout++;
		rte_delay_us(10);
	} while (timeout < 100);
	ctrl = tsrn10_mac_rd(hw, nr_lane, TSRN10_MAC_TX_CFG);
	ctrl |= TSRN10_MAC_TE;
	tsrn10_mac_wr(hw, nr_lane, TSRN10_MAC_TX_CFG, ctrl);

	return 0;
}

/* Set device link down: disable tx. */
static int tsrn10_dev_set_link_down(struct rte_eth_dev *eth_dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(eth_dev);
	uint16_t nr_lane = port->attr.nr_port;
	struct tsrn10_tx_queue *txq;
	uint32_t idx, timeout;
	uint32_t ctrl = 0;

	PMD_INIT_FUNC_TRACE();

	if (rte_atomic64_read(&port->state) != TSRN10_PORT_STATE_FINISH) {
		TSRN10_PMD_LOG(WARNING, "port[%d] is not support link "
				"down change when dev_start is not finish\n",
				eth_dev->data->port_id);
		return -EINVAL;
	}
	/* 1 Disable ETH Engine RX Work To Prevent Mac Recv Err packe */
	tsrn10_eth_wr(hw, TSRN10_RX_FIFO_FULL_THRETH(nr_lane),
			TSRN10_RX_WORKAROUND_VAL);

	for (idx = 0; idx < eth_dev->data->nb_tx_queues; idx++) {
		txq = eth_dev->data->tx_queues[idx];
		if (!txq)
			continue;
		txq->tx_link = false;
	}
	/* 2 Check All Tx Queue Isn't Send Anymore Pkts */
	for (idx = 0; idx < eth_dev->data->nb_tx_queues; idx++) {
		txq = eth_dev->data->tx_queues[idx];
		if (!txq)
			continue;
		timeout = 0;
		do {
			if (tsrn10_dma_rd(hw, TSRN10_DMA_TXQ_READY(txq->attr.index)))
				break;
			rte_delay_us(10);
			timeout++;
		} while (timeout < 2000);
		if (timeout >= 2000)
			TSRN10_PMD_LOG(WARNING, "port[%d] Check "
				"Tx Queue[%d] Empty failed",
				eth_dev->data->port_id, idx);
	}

	/* 3 Disable Mac Tx Side */
	ctrl = tsrn10_mac_rd(hw, nr_lane, TSRN10_MAC_TX_CFG);
	ctrl &= ~TSRN10_MAC_TE;
	tsrn10_mac_wr(hw, nr_lane, TSRN10_MAC_TX_CFG, ctrl);
	/* 4 Tell Firmeware Do Link-down Event Work */
	rnp_mbx_ifup_down(eth_dev, nr_lane, 0);
	/* 5 Wait For Link-Down that Firmware Do done */
	timeout = 0;
	do {
		if (!port->attr.link_ready)
			break;
		rte_delay_ms(1);
		timeout++;
	} while (timeout < 2000);

	return 0;
}

int tsrn10_get_dma_ring_index(struct tsrn10_eth_port *port, uint16_t queue_idx)
{
	struct tsrn10_eth_adapter *adapter = port->adapt;
	uint16_t dmar_index = 0;

	switch (adapter->mode) {
	case TSRN10_DUAL_10G:
		dmar_index = 2 * (queue_idx + port->attr.nr_port) - queue_idx % 2;
		break;
	case TSRN10_QUAD_10G:
		dmar_index = 4 * (queue_idx) + port->attr.nr_port;
		break;
	default:
		dmar_index = (uint16_t)((RTE_ETH_DEV_SRIOV(adapter->eth_dev).active == 0) ?
			queue_idx : RTE_ETH_DEV_SRIOV(adapter->eth_dev).def_pool_q_idx + queue_idx);
	}

	return dmar_index;
}

static int tsrn10_dev_rss_configure(struct rte_eth_dev *dev)
{
	/* 1.disable/enable Rss Feature */
	/* 2.Setup Redirection Table */
	/* 3.Setup Rss Hash Cfg */
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	enum rte_eth_rx_mq_mode mq_mode = conf->rxmode.mq_mode;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t dma_offset = port->attr.port_offset;
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t *indirtbl = &port->indirtbl[0];
	struct rte_eth_rss_conf rss_conf;
	struct tsrn10_rx_queue *rxq;
	uint16_t dma_index;
	uint16_t queue_id;
	int i, j;

	rss_conf = dev->data->dev_conf.rx_adv_conf.rss_conf;
	if (!(rss_conf.rss_hf & TSRN10_SUPPORT_RSS_OFFLOAD_ALL) ||
		!(mq_mode & ETH_MQ_RX_RSS_FLAG)) {
		tsrn10_disable_rss(dev);
		for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
			rxq = dev->data->rx_queues[0];
			if (!rxq) {
				PMD_DRV_LOG(ERR, "This is A SW BUG Rss "
						"Operate Queue Is Null\n");
				return -ENOMEM;
			}
			indirtbl[i] = rxq->attr.queue_id;
			dma_index = rxq->attr.index - dma_offset;
			rxq->rx_offload_capa &= ~DEV_RX_OFFLOAD_RSS_HASH;
			tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i), dma_index);
		}
		port->hw_rss_en = false;

		return 0;
	}
	if (rss_conf.rss_key == NULL)
		rss_conf.rss_key = rss_default_key;

	if (port->rxq_num_changed || !port->reta_has_cfg) {
		for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
			j = i % dev->data->nb_rx_queues;
			rxq = dev->data->rx_queues[j];
			if (!rxq) {
				TSRN10_PMD_ERR("Rss Set reta-cfg rxq %d Is Null\n", i);
				return -EINVAL;
			}
			indirtbl[i] = rxq->attr.queue_id;
			dma_index = rxq->attr.index - dma_offset;
			rxq->rx_offload_capa |= DEV_RX_OFFLOAD_RSS_HASH;
			tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i), dma_index);
		}
	}
	if (!port->rxq_num_changed && port->reta_has_cfg) {
		for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
			queue_id = indirtbl[i];
			if (queue_id < dev->data->nb_rx_queues) {
				rxq = dev->data->rx_queues[queue_id];
				if (!rxq) {
					TSRN10_PMD_ERR("Rss Set rxq reta %d Is Null\n", queue_id);
					return -EINVAL;
				}
				dma_index = rxq->attr.index - dma_offset;
				tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i),
						dma_index);
				rxq->rx_offload_capa |= DEV_RX_OFFLOAD_RSS_HASH;
			} else {
				TSRN10_PMD_LOG(WARNING, "port[%d] reta[%d]-Queue"
				" %d Rx Queue Num Is Out Range Of Cur Settings\n",
						dev->data->port_id, i, queue_id);
			}
		}
	}
	port->hw_rss_en = true;
	port->rss_cfg = rss_conf;
	tsrn10_rss_hash_set(dev, &rss_conf);

	return 0;
}

#ifdef DEBUG_THREAD
static void *
tsrn10_poll_debug(void *arg)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)arg;
	uint16_t i = 0;
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	while (signal_start) {
		printf("---------Start-----------------\n");
		for (i = 0; i < RTE_DIM(port->stats.rx_burst_count); i++) {
			if (port->stats.rx_burst_count[i])
				printf("rx_burst[%d] count %lu\n", i,
						port->stats.rx_burst_count[i]);
		}
		for (i = 0; i < RTE_DIM(port->stats.rx_tail_update); i++) {
			if (port->stats.rx_tail_update[i])
				printf("rx_tail_diff [%d] count %lu\n", i,
						port->stats.rx_tail_update[i]);
		}
		for (i = 0; i < 32; i++) {
			if (port->stats.tx_burst_count[i])
				printf("tx_burst[%d] count %lu\n", i,
						port->stats.tx_burst_count[i]);
		}
		printf("---------End-----------------\n");
		sleep(2);
	}
	return NULL;
}
#endif

static void tsrn10_set_rx_cksum_offload(struct rte_eth_dev *dev)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint64_t offloads;
	uint32_t cksum_ctrl;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	offloads = dev->data->dev_conf.rxmode.offloads;
#else
	if (dev->data->dev_conf.rxmode.hw_ip_checksum)
		offloads = DEV_RX_OFFLOAD_UDP_CKSUM |
			   DEV_RX_OFFLOAD_TCP_CKSUM |
			   DEV_RX_OFFLOAD_IPV4_CKSUM |
			   DEV_RX_OFFLOAD_SCTP_CKSUM |
			   DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM;
#endif
	cksum_ctrl = TSRN10_HW_CHECK_ERR_MASK;
	/* Enable Cksum Feature */
	/* We Don't Support OUT_L4 CKSUM But We Support OUT_L3
	 * So We Need To Know Whether User Enable Tunnel Mode
	 */
	if (hw->device_id == TSRN10_DEV_ID_N10G) {
		if (offloads & DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM) {
			/* Tunnel Option Cksum L4_Option */
			cksum_ctrl &= ~TSRN10_HW_L4_CKSUM_ERR;
			if (offloads & (DEV_RX_OFFLOAD_UDP_CKSUM |
						DEV_RX_OFFLOAD_TCP_CKSUM))
				cksum_ctrl &= ~TSRN10_HW_INNER_L4_CKSUM_ERR;
			else
				cksum_ctrl |= TSRN10_HW_INNER_L4_CKSUM_ERR;
		} else {
			/* No Tunnel Option Cksum L4_Option */
			cksum_ctrl |= TSRN10_HW_INNER_L4_CKSUM_ERR;
			if (offloads & (DEV_RX_OFFLOAD_UDP_CKSUM |
						DEV_RX_OFFLOAD_TCP_CKSUM))
				cksum_ctrl &= ~TSRN10_HW_L4_CKSUM_ERR;
			else
				cksum_ctrl |= TSRN10_HW_L4_CKSUM_ERR;
		}
		if (offloads & DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM) {
			/* Tunnel Option Cksum L3_Option */
			cksum_ctrl &= ~TSRN10_HW_L3_CKSUM_ERR;
			if (offloads & DEV_RX_OFFLOAD_IPV4_CKSUM)
				cksum_ctrl &= ~TSRN10_HW_INNER_L3_CKSUM_ERR;
			else
				cksum_ctrl |= TSRN10_HW_INNER_L3_CKSUM_ERR;
		} else {
			/* No Tunnel Option Cksum L3_Option */
			cksum_ctrl |= TSRN10_HW_INNER_L3_CKSUM_ERR;
			if (offloads & DEV_RX_OFFLOAD_IPV4_CKSUM)
				cksum_ctrl &= ~TSRN10_HW_L3_CKSUM_ERR;
			else
				cksum_ctrl |= TSRN10_HW_L3_CKSUM_ERR;
		}
		/* Sctp Option */
		if (offloads & DEV_RX_OFFLOAD_SCTP_CKSUM) {
			cksum_ctrl &= ~TSRN10_HW_SCTP_CKSUM_ERR;
			tsrn10_eth_wr(hw, TSRN10_HW_SCTP_CKSUM_CTRL, true);
		} else {
			tsrn10_eth_wr(hw, TSRN10_HW_SCTP_CKSUM_CTRL, false);
		}

		tsrn10_eth_wr(hw, TSRN10_HW_CHECK_ERR_CTRL, cksum_ctrl);
	} else {
		/* Enabled All Type Checksum Feature Workaroun For N10
		 * Multiple Port Device
		 * Receive All Packet And Enabled All Support Checksum Feature
		 * Use Software Mode Support Per Port Rx Checksum
		 * Feature Enabled/Disabled
		 * For N10 Multiple Port Mode
		 */
		tsrn10_eth_wr(hw, TSRN10_HW_SCTP_CKSUM_CTRL, true);
		tsrn10_eth_wr(hw, TSRN10_HW_CHECK_ERR_CTRL,
				TSRN10_HW_ERR_RX_ALL_MASK);
	}
}

static int
tsrn10_rx_scattered_setup(struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	uint16_t max_pkt_size =
		dev->data->dev_conf.rxmode.mtu + TSRN10_ETH_OVERHEAD;
#else
	uint16_t max_pkt_size = dev->data->dev_conf.rxmode.max_rx_pkt_len;
#endif
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_rx_queue *rxq;
	uint16_t dma_buf_size;
	uint16_t queue_id;
	uint32_t dma_ctrl;

	if (dev->data->rx_queues == NULL)
		return -ENOMEM;;

	for (queue_id = 0; queue_id < dev->data->nb_rx_queues; queue_id++) {
		rxq = dev->data->rx_queues[queue_id];
		if (!rxq)
			continue;
		if (hw->min_dma_size == 0)
			hw->min_dma_size = rxq->rx_buf_len;
		else
			hw->min_dma_size = RTE_MIN(hw->min_dma_size,
					rxq->rx_buf_len);
	}
	if (hw->min_dma_size < TSRN10_MIN_DMA_BUF_SIZE)
		return -ENOTSUP;

	dma_buf_size = hw->min_dma_size;
	/* Setup Max Dma Scatter Engins Split Size */
	dma_ctrl = tsrn10_rd_reg(hw->nic_reg + TSRN10_DMA_CTRL);
	if (max_pkt_size == dma_buf_size)
		dma_buf_size += (dma_buf_size % 16);
#if RTE_VERSION_NUM(17, 11, 0, 16) < RTE_VERSION
	if (dev_conf->rxmode.offloads & DEV_RX_OFFLOAD_SCATTER ||
#else
	if (dev_conf->rxmode.enable_scatter ||
#endif
			max_pkt_size > dma_buf_size ||
			dev->data->mtu + TSRN10_ETH_OVERHEAD > dma_buf_size)
		dev->data->scattered_rx = 1;
	else
		dev->data->scattered_rx = 0;

	TSRN10_PMD_LOG(INFO, "PF[%d] MaxPktLen %d MbSize %d MbHeadRoom %d\n",
			hw->function, max_pkt_size,
			dma_buf_size, RTE_PKTMBUF_HEADROOM);

	dma_ctrl &= ~TSRN10_DMA_SCATTER_MEM_MASK;
	dma_ctrl |= ((dma_buf_size / 16) << TSRN10_DMA_SCATTER_MEM_SHIFT);
	tsrn10_wr_reg(hw->nic_reg + TSRN10_DMA_CTRL, dma_ctrl);

	return 0;
}

static void
tsrn10_dev_link_task(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t lane_bit = port->attr.nr_port;
	bool link_change = false;
	uint32_t link_state;
	uint32_t speed_code;
	uint32_t ctrl;

	link_state = tsrn10_nicx_rd(hw, TSRN10_NIC_DEVICE_LINK);

	if (link_state & TSRN10_LINK_STATE(lane_bit)) {
		/* Port Link Change To Up */
		port->attr.pre_link = port->attr.link_ready;
		port->attr.link_ready = true;
		speed_code = TSRN10_LINK_SPEED_STATE(link_state, lane_bit);
		switch (speed_code) {
		case TSRN10_LANE_SPEED_10M:
			port->attr.speed = ETH_SPEED_NUM_10M;
			break;
		case TSRN10_LANE_SPEED_100M:
			port->attr.speed = ETH_SPEED_NUM_100M;
			break;
		case TSRN10_LANE_SPEED_1G:
			port->attr.speed = ETH_SPEED_NUM_1G;
			break;
		case TSRN10_LANE_SPEED_10G:
			port->attr.speed = ETH_SPEED_NUM_10G;
			break;
		case TSRN10_LANE_SPEED_25G:
			port->attr.speed = ETH_SPEED_NUM_25G;
			break;
		case TSRN10_LANE_SPEED_40G:
			port->attr.speed = ETH_SPEED_NUM_40G;
			break;
		}
	} else {
		/* Port Link to Down */
		port->attr.pre_link = port->attr.link_ready;
		port->attr.link_ready = false;
		port->attr.speed = RNP_LINK_SPEED_UNKNOWN;
	}
	if (port->attr.pre_link != port->attr.link_ready)
		link_change = true;

	if (link_change) {
		tsrn10_link_report(dev, port->attr.link_ready);
		/* WorkAround For Hardware When Link Down
		 * Eth Module Tx-side Can't Drop In some condition
		 * So back The Packet To Rx Side To Drop Packet
		 */
		/* To Protect Conflict Hw Resource */
		rte_spinlock_lock(&port->rx_mac_lock);
		ctrl = tsrn10_mac_rd(hw, lane_bit, TSRN10_MAC_RX_CFG);
		if (port->attr.link_ready) {
			ctrl &= ~TSRN10_MAC_LM;
			tsrn10_eth_wr(hw, TSRN10_RX_FIFO_FULL_THRETH(lane_bit),
					TSRN10_RX_DEFAULT_VAL);
		} else {
			tsrn10_eth_wr(hw, TSRN10_RX_FIFO_FULL_THRETH(lane_bit),
					TSRN10_RX_WORKAROUND_VAL);
			ctrl |= TSRN10_MAC_LM;
		}
		tsrn10_mac_wr(hw, lane_bit, TSRN10_MAC_RX_CFG, ctrl);
		rte_spinlock_unlock(&port->rx_mac_lock);
	}
	rte_eal_alarm_set(TSRN10_ALARM_INTERVAL,
			tsrn10_dev_link_task,
			(void *)dev);
}

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
static int tsrn10_speed_link_setup(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_phy_cfg cfg;
	uint32_t speed_cfg;
	uint16_t conf_bit;
	uint16_t bit_hi;
	int i = 0;

	if (!port->attr.phy_meta.is_sgmii && !hw->force_10g_1g_speed_ablity) {
		TSRN10_PMD_LOG(INFO, "port[%d] isn't support configure"
				" speed ability\n",
				port->attr.rte_pid);
		return 0;
	}
	speed_cfg = conf->link_speeds;
	memset(&cfg, 0, sizeof(cfg));
	if (speed_cfg == ETH_LINK_SPEED_AUTONEG) {
		cfg.autoneg = 1;
	} else {
		if (speed_cfg & ETH_LINK_SPEED_FIXED) {
			cfg.autoneg = 0;
			speed_cfg &= ~ETH_LINK_SPEED_FIXED;
		} else {
			cfg.autoneg = 1;
		}
	}
	if (hw->force_10g_1g_speed_ablity) {
		switch (speed_cfg) {
		case ETH_LINK_SPEED_1G:
			cfg.speed = RNP_SPEED_CAP_1GB_FULL;
			cfg.duplex = 1;
			break;
		case ETH_LINK_SPEED_10G:
			cfg.speed = RNP_SPEED_CAP_10GB_FULL;
			cfg.duplex = 1;
			break;
		}
	} else {
		conf_bit = __builtin_popcountl(speed_cfg);
		for (i = 0; i < conf_bit; i++) {
			bit_hi = ffs(speed_cfg);
			if (!bit_hi)
				continue;
			bit_hi -= 1;
			switch (BIT(bit_hi)) {
			case ETH_LINK_SPEED_10M:
				cfg.speed |= RNP_SPEED_CAP_10M_FULL;
				cfg.duplex = 1;
				/* fall through */
			case ETH_LINK_SPEED_10M_HD:
				cfg.speed |= RNP_SPEED_CAP_10M_HALF;
				break;
			case ETH_LINK_SPEED_100M:
				cfg.speed |= RNP_SPEED_CAP_100M_FULL;
				cfg.duplex = 1;
				/* fall through */
			case ETH_LINK_SPEED_100M_HD:
				cfg.speed |= RNP_SPEED_CAP_100M_HALF;
				break;
			case ETH_LINK_SPEED_1G:
				cfg.speed |= RNP_SPEED_CAP_1GB_FULL;
				cfg.duplex = 1;
				break;
			}
			speed_cfg &= BIT(bit_hi);
		}
	}

	return tsrn10_set_port_link(dev, &cfg);
}
#else
static int tsrn10_speed_link_setup(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_phy_cfg cfg;
	uint32_t speed_cfg;

	if (!port->attr.phy_meta.is_sgmii && !hw->force_10g_1g_speed_ablity) {
		TSRN10_PMD_LOG(INFO, "port[%d] isn't support configure"
				" speed ability\n",
				port->attr.rte_pid);
		return 0;
	}
	speed_cfg = conf->link_speed;
	memset(&cfg, 0, sizeof(cfg));
	if (conf->link_duplex == ETH_LINK_AUTONEG_DUPLEX)
		cfg.autoneg = 1;
	else
		cfg.autoneg = 0;
	if (conf->link_duplex == ETH_LINK_HALF_DUPLEX) {
		cfg.duplex = 0;
		switch (speed_cfg) {
		case ETH_LINK_SPEED_10:
			cfg.speed = RNP_SPEED_CAP_10M_HALF;
			break;
		case ETH_LINK_SPEED_100:
			cfg.speed = RNP_SPEED_CAP_100M_HALF;
			break;
		default:
			cfg.speed = RNP_SPEED_CAP_UNKNOWN;
		}
	}
	if (conf->link_duplex == ETH_LINK_FULL_DUPLEX) {
		cfg.duplex = 1;
		switch (speed_cfg) {
		case ETH_LINK_SPEED_10:
			cfg.speed = RNP_SPEED_CAP_10M_FULL;
			break;
		case ETH_LINK_SPEED_100:
			cfg.speed = RNP_SPEED_CAP_100M_FULL;
			break;
		case ETH_LINK_SPEED_1000:
			cfg.speed = RNP_SPEED_CAP_1GB_FULL;
			break;
		case ETH_LINK_SPEED_10G:
			cfg.speed = RNP_SPEED_CAP_10GB_FULL;
			break;
		default:
			cfg.speed = RNP_SPEED_CAP_UNKNOWN;
		}
	}

	return tsrn10_set_port_link(dev, &cfg);
}
#endif

static int tsrn10_enable_all_rx_queue(struct rte_eth_dev *dev)
{
	struct tsrn10_rx_queue *rxq;
	uint16_t idx;
	int ret = 0;

	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = dev->data->rx_queues[idx];
		if (!rxq || rxq->rx_deferred_start)
			continue;
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		if (dev->data->rx_queue_state[idx] ==
				RTE_ETH_QUEUE_STATE_STOPPED) {
			ret = tsrn10_rx_queue_start(dev, idx);
			if (ret < 0)
				return ret;
		}
#else
		ret = tsrn10_rx_queue_start(dev, idx);
		if (ret < 0)
			return ret;
#endif
	}

	return ret;
}

static int tsrn10_enable_all_tx_queue(struct rte_eth_dev *dev)
{
	struct tsrn10_tx_queue *txq;
	uint16_t idx;
	int ret = 0;

	for (idx = 0; idx < dev->data->nb_tx_queues; idx++) {
		txq = dev->data->tx_queues[idx];
		if (!txq || txq->tx_deferred_start)
			continue;
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		if (dev->data->tx_queue_state[idx] ==
				RTE_ETH_QUEUE_STATE_STOPPED) {
			ret = tsrn10_tx_queue_start(dev, idx);
			if (ret < 0)
				return ret;
		}
#else
		ret = tsrn10_tx_queue_start(dev, idx);
		if (ret < 0)
			return ret;
#endif
	}

	return ret;
}

static int tsrn10_dev_start(struct rte_eth_dev *eth_dev)
{
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	uint16_t max_rx_pkt_len =
		eth_dev->data->dev_conf.rxmode.mtu + TSRN10_ETH_OVERHEAD;
#else
	uint16_t max_rx_pkt_len = eth_dev->data->dev_conf.rxmode.max_rx_pkt_len;
	struct rte_eth_rxmode *rxmode = &eth_dev->data->dev_conf.rxmode;
	bool jumbo_en;
#endif
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(eth_dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);
	struct rte_eth_dev_data *data = eth_dev->data;
	struct tsrn10_hw *hw = &adapter->hw;
	struct tsrn10_tx_queue *txq;
	uint16_t p_id;
	uint16_t idx;
	uint16_t timeout = 0;
	int mask = 0;
	int8_t ret;

#ifdef ENABLE_MSIX
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif

	PMD_INIT_FUNC_TRACE();

	p_id = port->attr.nr_port;
	/* Disable ETH Engine RX Work */
	tsrn10_eth_wr(hw, TSRN10_RX_FIFO_FULL_THRETH(p_id),
			TSRN10_RX_WORKAROUND_VAL);
#ifdef ENABLE_MSIX
	if ((rte_intr_cap_multiple(intr_handle) ||
				!RTE_ETH_DEV_SRIOV(dev).active) &&
			dev->data->dev_conf.intr_conf.rxq != 0) {
		intr_vector = dev->data->nb_rx_queues;
		if (intr_vector > ATL_MAX_INTR_QUEUE_NUM) {
			PMD_INIT_LOG(ERR, "At most %d intr queues supported",
					ATL_MAX_INTR_QUEUE_NUM);
			return -ENOTSUP;
		}
		if (rte_intr_efd_enable(intr_handle, intr_vector)) {
			PMD_INIT_LOG(ERR, "rte_intr_efd_enable failed");
			return -1;
		}
	}

	if (rte_intr_dp_is_en(intr_handle) && !intr_handle->intr_vec) {
		intr_handle->intr_vec = rte_zmalloc("intr_vec",
				dev->data->nb_rx_queues * sizeof(int), 0);
		if (intr_handle->intr_vec == NULL) {
			PMD_INIT_LOG(ERR, "Failed to allocate %d rx_queues"
					" intr_vec", dev->data->nb_rx_queues);
			return -ENOMEM;
		}
	}
#if 0
	/* TODO Rx Interrupt Function */
	rte_intr_callback_register(intr_handle,
			tsrn10_dev_interrupt_handler, eth_dev);
	rte_intr_enable(intr_handle);
	tsrn10_enable_intr(eth_dev);
#endif

#endif
	timeout = 0;
	do {
		tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(port->attr.nr_port, 0), 0x7f);
		rte_delay_ms(10);
		timeout++;
		if (timeout >= 1000)
			break;
	} while (tsrn10_eth_rd(hw, TSRN10_RSS_REDIR_TB(port->attr.nr_port, 0)) != 0x7f);

	if (timeout >= 1000) {
		PMD_INIT_LOG(ERR, "ethernet[%d]ETH REG can't be write\n",
				port->attr.nr_port);
		return -EPERM;
	}
	tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(port->attr.nr_port, 0), 0);
	/* Setup Default Rss configure */
	tsrn10_dev_rss_configure(eth_dev);
	ret = tsrn10_rx_scattered_setup(eth_dev);
	if (ret)
		return ret;
#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	/* Setp Jumbo Mtu Support Base On the DEV_RX_OFFLOAD_JUMBO_FRAME Flag*/
	jumbo_en = rxmode->offloads & DEV_RX_OFFLOAD_JUMBO_FRAME ? true : false;
#else
	jumbo_en = rxmode->jumbo_frame ? true : false;
#endif
	if (jumbo_en && (max_rx_pkt_len <= RTE_ETHER_MAX_LEN ||
			 max_rx_pkt_len > TSRN10_MAC_MAXFRM_SIZE)) {
		PMD_DRV_LOG(ERR, "maximux packet length must be "
				"range from %u to %u "
				"when Jumbo Frame Is Enable",
				(uint32_t)RTE_ETHER_MAX_LEN,
				(uint32_t)TSRN10_MAC_MAXFRM_SIZE);
		return -EINVAL;
	}

	if (!jumbo_en && (max_rx_pkt_len < RTE_ETHER_MIN_LEN ||
			  max_rx_pkt_len > RTE_ETHER_MAX_LEN)) {
		PMD_DRV_LOG(ERR, "maximux packet length must be "
				"range from %u to %u "
				"when Jumbo Frame Is Disable",
				(uint32_t)RTE_ETHER_MIN_LEN,
				(uint32_t)RTE_ETHER_MAX_LEN);
		if (max_rx_pkt_len > RTE_ETHER_MAX_LEN)
			jumbo_en = true;
		else
			return -EINVAL;
	}
	port->jumbo_en = jumbo_en;
#else
	if (max_rx_pkt_len > RTE_ETHER_MAX_LEN)
		port->jumbo_en = true;
#endif
	tsrn10_mtu_set(eth_dev, max_rx_pkt_len - TSRN10_ETH_OVERHEAD);
	tsrn10_setup_rx_function(eth_dev);
	for (idx = 0; idx < eth_dev->data->nb_tx_queues; idx++) {
		txq = eth_dev->data->tx_queues[idx];
		tsrn10_setup_tx_function(eth_dev, txq);
	}
#ifdef DEBUG_THREAD
	pthread_t thread;
	signal_start = true;
	pthread_create(&thread, NULL, tsrn10_poll_debug, (void *)eth_dev);
#endif
	ret = tsrn10_enable_all_tx_queue(eth_dev);
	if (ret)
		goto txq_start_failed;
	ret = tsrn10_enable_all_rx_queue(eth_dev);
	if (ret)
		goto rxq_start_failed;
	mask = ETH_VLAN_STRIP_MASK | ETH_VLAN_FILTER_MASK |
	       ETH_VLAN_EXTEND_MASK;
	tsrn10_vlan_offload_set(eth_dev, mask);
	/* when Hardware Is Link Down We Must Set Timeout
	 * For Tx Side To Xmit Frame
	 */
	tsrn10_mac_init(eth_dev);
	ret = tsrn10_speed_link_setup(eth_dev);
	if (ret)
		goto setup_link_failed;
	tsrn10_link_update(eth_dev, 0);

	port->port_stopped = 0;
	/* For Hardware Multitle Port Mode
	 * Link Interrupt Just Have Only One
	 * So Just Use Sw Resource Mark
	 */
	rte_atomic64_set(&port->state, TSRN10_PORT_STATE_FINISH);
	tsrn10_dev_set_link_up(eth_dev);
	if (system_no_interrupt)
		if (rte_eal_alarm_set(TSRN10_ALARM_INTERVAL,
					tsrn10_dev_link_task,
					(void *)eth_dev) < 0)
			PMD_DRV_LOG(ERR, "Error setting alarm");

	tsrn10_eth_wr(hw, TSRN10_RX_FIFO_FULL_THRETH(p_id),
			TSRN10_RX_DEFAULT_VAL);

	return 0;

setup_link_failed:
	PMD_DRV_LOG(ERR, "Setup_link failed ret %d", ret);
rxq_start_failed:
	for (idx = 0; idx < data->nb_rx_queues; idx++)
		tsrn10_rx_queue_stop(eth_dev, idx);
txq_start_failed:
	for (idx = 0; idx < data->nb_tx_queues; idx++)
		tsrn10_tx_queue_stop(eth_dev, idx);


	return -EINVAL;
}

#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
static int tsrn10_dev_stop(struct rte_eth_dev *dev)
#else
static void tsrn10_dev_stop(struct rte_eth_dev *dev)
#endif
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_rx_queue *rxq;
	struct rte_eth_link link;
	uint16_t idx;

	PMD_INIT_FUNC_TRACE();

	if (port->port_stopped)
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
		return -EPERM;
#else
		return;
#endif
	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = dev->data->rx_queues[idx];
		if (!rxq)
			continue;
		rxq->rxq_started = false;
	}


	/* disable interrupts */
#ifdef ENABLE_MSIX
	tsrn10_disable_intr(hw);
#endif
	/* clear the recorded link status */
	memset(&link, 0, sizeof(link));

	rte_eth_linkstatus_set(dev, &link);

	tsrn10_dev_set_link_down(dev);
	/* The Below Operate Must Can't Disburb
	 * Link Must Be Down. Can't Operate By API
	 */
	rte_atomic64_set(&port->state, TSRN10_PORT_STATE_SETTING);

	signal_start = false;

	dev->data->scattered_rx = 0;
	dev->data->dev_started = 0;

	tsrn10_mac_tx_disable(dev);
	tsrn10_mac_rx_disable(dev);

	rte_atomic64_set(&port->state, TSRN10_PORT_STATE_FINISH);
	port->port_stopped = 1;
	if (system_no_interrupt) {
		port->attr.link_ready = false;
		rte_eal_alarm_cancel(tsrn10_dev_link_task, dev);
	}
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
	return 0;
#endif
}

/* return 0 means link status changed, -1 means not changed */
static int tsrn10_link_update(struct rte_eth_dev *eth_dev,
			      int wait_to_complete __rte_unused)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(eth_dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);
	struct tsrn10_phy_meta *phy_meta = &port->attr.phy_meta;
#ifndef USING_MBX
	struct tsrn10_pcs_info *pcs = &hw->pcs;
	uint8_t p_id = port->attr.nr_port;
#endif
	uint8_t p_id = port->attr.nr_port;
	struct rte_eth_link link;
	uint32_t status;

	PMD_INIT_FUNC_TRACE();

	memset(&link, 0, sizeof(link));

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		rnp_mbx_get_lane_stat(eth_dev, p_id);
#ifdef USING_MBX
	/* nr_lane = port->attr.nr_port; */
	/*status = rnp_mbx_get_link_stat(hw, nr_lane); */

	status = port->attr.link_ready;
	link.link_duplex = phy_meta->link_duplex;
	link.link_status = status ? ETH_LINK_UP : ETH_LINK_DOWN;
	link.link_speed	 = link.link_status ? port->attr.speed :
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
			ETH_SPEED_NUM_UNKNOWN;
#else
			ETH_SPEED_NUM_NONE;
#endif
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	link.link_autoneg = phy_meta->link_autoneg ?
		ETH_LINK_SPEED_AUTONEG : ETH_LINK_SPEED_FIXED;
#else
	if (phy_meta->link_autoneg)
		link.link_duplex = ETH_LINK_AUTONEG_DUPLEX;
#endif
	tsrn10_link_stat_mark(&adapter->hw, port->attr.nr_port,
			link.link_status);
	rte_eth_linkstatus_set(eth_dev, &link);
#else
	status = pcs->ops.read(hw, p_id, TSRN10_PCS_LINK_STATUS);
	if (status & TSRN10_PCS_LINKUP)
		link.link_status = ETH_LINK_UP;
	else
		link.link_status = ETH_LINK_DOWN;

	link.link_duplex = ETH_LINK_FULL_DUPLEX;
	status = pcs->ops.read(hw, p_id, TSRN10_PCS_LINK_SPEED);
	if (status & TSRN10_PCS_1G_OR_10G) {
		switch (status & TSRN10_PCS_SPPEED_MASK) {
		case TSRN10_PCS_SPPEED_10G:
			link.link_speed = ETH_SPEED_NUM_10G;
			break;
		case TSRN10_PCS_SPPEED_40G:
			link.link_speed = ETH_SPEED_NUM_10G;
			break;
		}
	} else {
		link.link_speed = ETH_SPEED_NUM_1G;
	}
	status = pcs->ops.read(hw, p_id, TSRN10_PCS_LINK_SPEED);
	link.link_autoneg = ETH_LINK_FIXED;

	tsrn10_link_stat_mark(&adapter->hw, port->attr.nr_port, link.link_status);
	rte_eth_linkstatus_set(eth_dev, &link);
#endif
	return 0;
}

static int32_t tsrn10_reset_hw_pf(struct tsrn10_hw *hw)
{
#ifndef USING_MBX
	uint16_t trytime = 0;
	uint32_t reg = 0;
#endif
	struct tsrn10_eth_adapter *adapter = hw->back;

	tsrn10_wr_reg(hw->comm_reg_base + TSRN10_NIC_RESET, 0);
	rte_wmb();
	tsrn10_wr_reg(hw->comm_reg_base + TSRN10_NIC_RESET, 1);

#ifndef USING_MBX
	/* Debug For Register R/W Status */
	tsrn10_wr_reg(hw->dev_dummy, TSRN10_REG_DEBUG_VALUE);
#define TSRN10_RESET_TIMEOUT (200)
	while (!((reg = tsrn10_rd_reg(hw->dev_dummy)) ==
		TSRN10_REG_DEBUG_VALUE + 1) &&
		trytime < TSRN10_RESET_TIMEOUT) {
		rte_delay_ms(10);
		trytime++;
	}

	if (trytime == TSRN10_RESET_TIMEOUT) {
		PMD_DRV_LOG(ERR, "PF[%d] reset nic failed\n",
				hw->function);
		return -EPERM;
	}
	sleep(4);
#else
	rnp_mbx_fw_reset_phy(adapter->eth_dev);
#endif
	PMD_DRV_LOG(INFO, "PF[%d] reset nic finish\n",
			hw->function);

	return 0;
}

static int tsrn10_dev_get_regs(struct rte_eth_dev *eth_dev,
			       struct rte_dev_reg_info *regs)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(eth_dev);
	struct tsrn10_hw *hw = &adapter->hw;
	unsigned int i;

	if (!regs->data) {
		regs->length = 4096;
#if RTE_VERSION_NUM(16, 4, 0, 16) < RTE_VERSION
		regs->width = sizeof(uint32_t);
#endif
		return 0;
	}

	for (i = 0; i < regs->length; i++)
		*((uint32_t *)regs->data) =
			tsrn10_nicx_rd(hw, regs->offset + i * 4);

	regs->version = tsrn10_rd_reg(hw->dev_version);

	return 0;
}

static int tsrn10_fw_version_get(struct rte_eth_dev *eth_dev,
				 char *fw_version, size_t fw_size)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(eth_dev);
	char *ver = (char *)&hw->fw_version;
	int ret = 0;

	ret = snprintf(fw_version, fw_size, "%d.%d.%d.%d 0x%.2x",
			ver[3],
			ver[2],
			ver[1],
			ver[0],
			hw->fw_uid);
	ret += 1; /* add string null-terminator */

	if (fw_size < (size_t)ret)
		return ret;

	return 0;
}

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
static uint32_t
tsrn10_get_speed_caps(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint32_t speed_cap = 0;
	uint32_t i = 0, speed;
	uint32_t support_link;
	uint32_t link_types;

	support_link = port->attr.phy_meta.supported_link;
	link_types = __builtin_popcountl(support_link);

	if (!link_types)
		return 0;

	for (i = 0; i < link_types; i++) {
		speed = ffs(support_link) - 1;
		switch (BIT(speed)) {
		case RNP_SPEED_CAP_10M_FULL:
			speed_cap |= ETH_LINK_SPEED_10M;
			break;
		case RNP_SPEED_CAP_100M_FULL:
			speed_cap |= ETH_LINK_SPEED_100M;
			break;
		case RNP_SPEED_CAP_1GB_FULL:
			speed_cap |= ETH_LINK_SPEED_1G;
			break;
		case RNP_SPEED_CAP_10GB_FULL:
			speed_cap |= ETH_LINK_SPEED_10G;
			break;
		case RNP_SPEED_CAP_40GB_FULL:
			speed_cap |= ETH_LINK_SPEED_40G;
			break;
		case RNP_SPEED_CAP_25GB_FULL:
			speed_cap |= ETH_LINK_SPEED_25G;
			break;
		case RNP_SPEED_CAP_10M_HALF:
			speed_cap |= ETH_LINK_SPEED_10M_HD;
			break;
		case RNP_SPEED_CAP_100M_HALF:
			speed_cap |= ETH_LINK_SPEED_100M_HD;
			break;
		}
		support_link &= ~BIT(speed);
	}
	if (port->attr.phy_meta.media_type != TSRN10_MEDIA_TYPE_COPPER)
		speed_cap |= ETH_LINK_SPEED_FIXED;

	return speed_cap;
}
#endif

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int tsrn10_dev_infos_get(struct rte_eth_dev *eth_dev,
				struct rte_eth_dev_info *dev_info)
#else
static void tsrn10_dev_infos_get(struct rte_eth_dev *eth_dev,
				 struct rte_eth_dev_info *dev_info)
#endif
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	dev_info->rx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = MAX_BD_COUNT,
		.nb_min = MIN_BD_COUNT,
		.nb_align = BD_ALIGN,
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
		.nb_seg_max = TSRN10_RX_MAX_SEG,
		.nb_mtu_seg_max = TSRN10_RX_MAX_MTU_SEG,
#endif
	};
	dev_info->tx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = MAX_BD_COUNT,
		.nb_min = MIN_BD_COUNT,
		.nb_align = BD_ALIGN,
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
		.nb_seg_max = TSRN10_TX_MAX_SEG,
		.nb_mtu_seg_max = TSRN10_TX_MAX_MTU_SEG,
#endif
	};
#endif
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	dev_info->switch_info.domain_id = RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID;
#endif
	/* if (RTE_ETH_DEV_SRIOV(eth_dev).active == 0) */


#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	/*  per queue Rx offload capability */
	dev_info->rx_queue_offload_capa = DEV_RX_OFFLOAD_VLAN_STRIP;
#endif

	dev_info->rx_offload_capa = 0 |
		DEV_RX_OFFLOAD_CHECKSUM |
		DEV_RX_OFFLOAD_SCTP_CKSUM |
		DEV_RX_OFFLOAD_VLAN |
#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
		DEV_RX_OFFLOAD_JUMBO_FRAME |
#endif
		DEV_RX_OFFLOAD_RSS_HASH |
		DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		DEV_RX_OFFLOAD_SCATTER |
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		DEV_RX_OFFLOAD_TIMESTAMP |
		dev_info->rx_queue_offload_capa;
#else
		DEV_RX_OFFLOAD_TIMESTAMP;
#endif

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	dev_info->tx_queue_offload_capa = DEV_TX_OFFLOAD_MBUF_FAST_FREE;
#endif

	dev_info->tx_offload_capa = 0 |
		DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM |
		DEV_TX_OFFLOAD_SCTP_CKSUM |
		DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
		DEV_TX_OFFLOAD_TCP_TSO |
		DEV_TX_OFFLOAD_VLAN_INSERT |
		DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
		DEV_TX_OFFLOAD_GRE_TNL_TSO |
		DEV_TX_OFFLOAD_QINQ_INSERT |
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		DEV_TX_OFFLOAD_MULTI_SEGS |
		dev_info->tx_queue_offload_capa;
#else
		DEV_TX_OFFLOAD_MULTI_SEGS;
#endif

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	dev_info->speed_capa = tsrn10_get_speed_caps(eth_dev);
#endif
	dev_info->max_rx_pktlen = TSRN10_MAC_MAXFRM_SIZE;
#if RTE_VERSION_NUM(19, 5, 0, 0) <= RTE_VERSION
	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->max_mtu = dev_info->max_rx_pktlen - TSRN10_ETH_OVERHEAD;
#endif
	dev_info->min_rx_bufsize = TSRN10_MAC_MINFRM_SIZE;

	dev_info->max_rx_queues = port->attr.max_rx_queues;
	dev_info->max_tx_queues = port->attr.max_tx_queues;

	dev_info->max_mac_addrs = port->attr.max_mac_addrs;
	dev_info->max_hash_mac_addrs = port->attr.max_uc_mac_hash;

	/* For RSS Offload We Just Support Four tuple */
	dev_info->flow_type_rss_offloads = TSRN10_SUPPORT_RSS_OFFLOAD_ALL;
	dev_info->hash_key_size = TSRN10_MAX_HASH_KEY_SIZE * sizeof(uint32_t);
	dev_info->reta_size = TSRN10_MAX_RX_QUEUE_NUM;

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

int tsrn10_alloc_txbdr(struct rte_eth_dev *dev,
			      struct tsrn10_tx_queue *txr,
			      uint16_t nb_desc, int socket_id)
{
	const struct rte_memzone *rz = NULL;
	int size;

	size = nb_desc * sizeof(struct tsrn10_txsw_entry);
	txr->sw_ring = rte_zmalloc_socket("tx_swq", size,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (txr->sw_ring == NULL)
		return -ENOMEM;

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	rz = rte_eth_dma_zone_reserve(dev, "tx_ring", txr->attr.queue_id,
			TSRN10_TX_MAX_RING_SZ, TSRN10_BD_RING_ALIGN, socket_id);
#else
	rz = ring_dma_zone_reserve(dev, "tx_ring", txr->attr.queue_id,
			TSRN10_TX_MAX_RING_SZ, socket_id);
#endif
	if (rz == NULL) {
		rte_free(txr->sw_ring);
		txr->sw_ring = NULL;
		return -ENOMEM;
	}
	txr->rz = rz;
	memset(rz->addr, 0, TSRN10_TX_MAX_RING_SZ);
	txr->tx_bdr = rz->addr;
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#ifndef RTE_LIBRTE_XEN_DOM0
	txr->ring_phys_addr = (uint64_t)rz->phys_addr;
#else
	txr->ring_phys_addr = rte_mem_phy2mch((rz)->memseg_id, (rz)->phys_addr);
#endif
#else
	txr->ring_phys_addr = rz->iova;
#endif

	txr->next_to_use = 0;

	return 0;
}

void tsrn10_setup_txbdr(struct tsrn10_hw *hw, struct tsrn10_tx_queue *txq)
{
	uint16_t max_desc = txq->attr.bd_count;
	uint16_t idx = txq->attr.index;
	phys_addr_t bd_address;
	uint32_t dmah, dmal;
	int v;

	bd_address = (phys_addr_t)txq->ring_phys_addr;
	dmah = upper_32_bits((uint64_t)bd_address);
	dmal = lower_32_bits((uint64_t)bd_address);
	if (hw->mbx.sriov_st)
		dmah |= (hw->mbx.sriov_st << 24);

	/* We must set sriov_state to hi dma_address high 8bit for vf isolation
	 * |---8bit-----|----------24bit--------|
	 * |sriov_state-|-------high dma address|
	 * |---------------8bit-----------------|
	 * |7bit | 6bit |5-0bit-----------------|
	 * |vf_en|pf_num|-------vf_num----------|
	 */
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_BASE_ADDR_LO(idx), dmal);
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_BASE_ADDR_HI(idx), dmah);

	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_DESC_FETCH_CTRL(idx),
			  (TSRN10_TX_DEFAULT_BURST << 16) |
			   TSRN10_TX_DESC_HIGH_WATER_TH);
	tsrn10_dma_wr(hw, TSRN10_DMA_INT_MASK(idx),
			TSRN10_TX_INT_MASK | TSRN10_RX_INT_MASK);
	txq->tx_headreg = (void *)((char *)hw->dma_base +
			TSRN10_DMA_TXQ_HEAD(idx));
	txq->tx_tailreg = (void *)((char *)hw->dma_base +
			TSRN10_DMA_TXQ_TAIL(idx));

	v = tsrn10_dma_rd(hw, TSRN10_DMA_TXQ_HEAD(idx));
	if (v) {
		tsrn10_tx_queue_reset(hw, txq);
		v = txq->next_to_use;
	}
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_LEN(idx), max_desc);
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_TAIL(idx), v);

	txq->next_to_use = tsrn10_dma_rd(hw,
			TSRN10_DMA_TXQ_HEAD(idx));
}

static int tsrn10_tx_queue_setup(struct rte_eth_dev *dev,
				 uint16_t qidx, uint16_t nb_desc,
				 unsigned int socket_id,
				 const struct rte_eth_txconf *tx_conf)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_txmode *txmode = &dev->data->dev_conf.txmode;
#endif
	struct tsrn10_eth_adapter *adapter = port->adapt;
	struct rte_eth_dev_data *data = dev->data;
	struct tsrn10_hw *hw = &adapter->hw;
	struct tsrn10_tx_queue *txq;
	int err = 0;

	PMD_INIT_FUNC_TRACE();
	PMD_DRV_LOG(INFO, "TXQ[%d] setup nb-desc %d\n", qidx, nb_desc);
	if (!port->port_stopped) {
		TSRN10_PMD_ERR("Txq[%d] Don't Support Dynamic Setup "
				"Port Must Be stopped\n", qidx);

		return -EINVAL;
	}

	if (rte_is_power_of_2(nb_desc) == 0) {
		TSRN10_PMD_ERR("Txq Desc Num Must power of 2\n");
		return -EINVAL;
	}

	if (nb_desc > MAX_BD_COUNT)
		return -1;

	/* Check Whether Queue Has Been Create If So Release it */
	if (qidx < dev->data->nb_tx_queues && dev->data->tx_queues[qidx]) {
		tsrn10_tx_queue_release(dev->data->tx_queues[qidx]);
		dev->data->tx_queues[qidx] = NULL;
	}

	txq = rte_zmalloc_socket("tsrn10_txq", sizeof(struct tsrn10_tx_queue),
			RTE_CACHE_LINE_SIZE, socket_id);

	if (!txq) {
		TSRN10_PMD_ERR("Failed to allocate TX ring memory");
		return -ENOMEM;
	}
	txq->tx_rs_thresh = tx_conf->tx_rs_thresh ?
		tx_conf->tx_rs_thresh : TSRN10_DEFAULT_TX_RS_THRESH;
	if (tx_conf->tx_free_thresh == 0) {
		txq->tx_free_thresh = nb_desc - txq->tx_rs_thresh;
		if (txq->tx_free_thresh >= 64 + TSRN10_DEFAULT_TX_FREE_THRESH)
			txq->tx_free_thresh = txq->tx_free_thresh - 64;
	} else {
		txq->tx_free_thresh = tx_conf->tx_free_thresh;
	}
	txq->tx_free_thresh = RTE_MIN(txq->tx_free_thresh, nb_desc - 3);
	if (txq->tx_rs_thresh > txq->tx_free_thresh) {
		PMD_INIT_LOG(ERR, "tx_rs_thresh must be less than or "
				"equal to tx_free_thresh. (tx_free_thresh=%u"
				" tx_rs_thresh=%u port=%d queue=%d)",
				(unsigned int)tx_conf->tx_free_thresh,
				(unsigned int)tx_conf->tx_rs_thresh,
				(int)dev->data->port_id,
				(int)qidx);
		err = -EINVAL;
		goto fail;
	}
	/* We just Support Sriov One port per PF*/
	txq->attr.index = tsrn10_get_dma_ring_index(port, qidx);
	txq->attr.lane_id = port->attr.nr_port;
	txq->attr.vf_num = hw->mbx.vf_num;
	txq->attr.queue_id = qidx;
	txq->attr.bd_count = nb_desc;
	txq->attr.bd_mask = nb_desc - 1;
	txq->attr.rte_pid = dev->data->port_id;

	/* When PF and VF all used that the PF must regards
	 * it as a VF Just For dma-ring resource divide
	 */
	err = tsrn10_alloc_txbdr(dev, txq, nb_desc, socket_id);
	if (err)
		goto fail;

	PMD_DRV_LOG(INFO, "PF[%d] dev:[%d] hw-lane[%d] txq queue_id[%d] "
			"dma_idx %d socket %d\n",
			hw->function, txq->attr.rte_pid,
			txq->attr.lane_id, qidx,
			txq->attr.index, socket_id);

	tsrn10_setup_txbdr(hw, txq);
	txq->nb_tx_free = nb_desc - 1;
	txq->tx_free_trigger = txq->tx_free_thresh + 1;
	txq->tx_next_dd = txq->tx_rs_thresh - 1;
	txq->tx_next_rs = txq->tx_rs_thresh - 1;
	txq->last_desc_cleaned = (uint16_t)(txq->attr.bd_count - 1);
	txq->last_clean = 0;

	if (qidx < data->nb_tx_queues)
		data->tx_queues[qidx] = txq;
	port->tx_queues[qidx] = txq;
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
	txq->tx_deferred_start = tx_conf->tx_deferred_start;
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
	txq->offloads = tx_conf->txq_flags;
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	txq->offloads |= ((txmode->offloads & DEV_TX_OFFLOAD_MBUF_FAST_FREE) ?
			DEV_TX_OFFLOAD_MBUF_FAST_FREE : 0);
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

static enum tsrn10_fc_mode tsrn10_fc_mode_support[] = {
	TSRN10_FC_NONE,
	TSRN10_FC_RX_PAUSE,
	TSRN10_FC_TX_PAUSE,
	TSRN10_FC_FULL,
};

static int tsrn10_flow_ctrl_get(struct rte_eth_dev *dev,
				struct rte_eth_fc_conf *fc_conf)
{
	struct tsrn10_fc_info *fc_info = TSRN10_DEV_TO_FC_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t mfc_reg;

	fc_conf->pause_time = fc_info->pause_time;
	fc_conf->high_water = fc_info->hi_water[0];
	fc_conf->low_water = fc_info->lo_water[0];
	fc_conf->send_xon = fc_info->send_xon;

	mfc_reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
	fc_conf->mac_ctrl_frame_fwd = mfc_reg & TSRN10_MAC_PCF ? 1 : 0;

	switch (fc_info->mode) {
	case TSRN10_FC_RX_PAUSE:
		fc_conf->mode = RTE_FC_RX_PAUSE;
		break;
	case TSRN10_FC_TX_PAUSE:
		fc_conf->mode = RTE_FC_TX_PAUSE;
		break;
	case TSRN10_FC_FULL:
		fc_conf->mode = RTE_FC_FULL;
		break;
	case TSRN10_FC_NONE:
		fc_conf->mode = RTE_FC_FULL;
		/* fall through */
	default:
		fc_conf->mode = RTE_FC_NONE;
	}

	return 0;
}

static int
tsrn10_flow_ctrl_set(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	struct tsrn10_fc_info *fc_info = TSRN10_DEV_TO_FC_INFO(dev);
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t cfg_mode;
	bool en;

	if (fc_conf->mode > RTE_DIM(tsrn10_fc_mode_support)) {
		PMD_INIT_LOG(ERR, "Flow Ctrl Mode Is Not Support");
		return -EINVAL;
	}
	if (fc_conf->autoneg) {
		PMD_INIT_LOG(ERR, "Flow Ctrl Is Not Support Autoneg");
		return -EINVAL;
	}
	fc_info->ctrl_fwd_en = fc_conf->mac_ctrl_frame_fwd;
	cfg_mode = tsrn10_fc_mode_support[fc_conf->mode];
	en = cfg_mode ? true : false;
	if (!en || cfg_mode == TSRN10_FC_NONE)
		return tsrn10_flow_ctrl_en(dev, fc_info, p_id, false);

	fc_info->mode = cfg_mode;
	fc_info->pause_time = fc_conf->pause_time;
	fc_info->hi_water[0] = fc_conf->high_water;
	fc_info->lo_water[0] = fc_conf->low_water;
	fc_info->send_xon = fc_conf->send_xon;


	return tsrn10_flow_ctrl_en(dev, fc_info, p_id, true);
}

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
static void
#else
static int
#endif
tsrn10_dev_mac_addr_set(struct rte_eth_dev *dev,
			struct rte_ether_addr *mac_addr)
{
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
	tsrn10_set_default_mac(dev, (uint8_t *)mac_addr);
#else
	return tsrn10_set_default_mac(dev, (uint8_t *)mac_addr);
#endif
}

#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void
#else
static int
#endif
tsrn10_dev_add_macaddr(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr,
		       uint32_t index, uint32_t vmdq __rte_unused)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (index > port->attr.max_mac_addrs) {
		PMD_DRV_LOG(ERR, "The Add Mac Index Is Outof Range");
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
		return;
#else
		return -EINVAL;
#endif
	}
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
	return tsrn10_set_rafb(dev, (uint8_t *)mac_addr, UINT8_MAX, index);
#else
	tsrn10_set_rafb(dev, (uint8_t *)mac_addr, UINT8_MAX, index);
#endif
}

static void
tsrn10_dev_remove_macaddr(struct rte_eth_dev *dev, uint32_t index)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (index > port->attr.max_mac_addrs) {
		PMD_DRV_LOG(ERR, "The Remove Mac Index Is Outof Range");
		return;
	}

	tsrn10_clear_rafb(dev, UINT8_MAX, index);
}

static int
tsrn10_dev_uc_hash_table_set(struct rte_eth_dev *dev,
			     struct rte_ether_addr *mac_addr, uint8_t add)
{
	if (!mac_addr)
		return -EINVAL;
	return tsrn10_setup_uta(dev, (uint8_t *)mac_addr, add);
}

static int
tsrn10_dev_uc_all_hash_table_set(struct rte_eth_dev *dev, uint8_t add)
{
	return tsrn10_uta_en(dev, add);
}

static int
tsrn10_dev_set_mc_addr_list(struct rte_eth_dev *dev,
			    struct rte_ether_addr *mc_addr_list,
			    uint32_t nb_mc_addr)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (nb_mc_addr > port->attr.max_mc_mac_hash)
		return -EINVAL;

	return tsrn10_update_mc_hash(dev, mc_addr_list, nb_mc_addr);
}

#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
static int
tsrn10_dev_flow_ops_get(__rte_unused struct rte_eth_dev *dev,
			const struct rte_flow_ops **ops)
{
	*ops = &tsrn10_flow_ops;

	return 0;
}
#else
static int tsrn10_filter_ctrl(struct rte_eth_dev *dev __rte_unused,
		enum rte_filter_type filter_type,
		enum rte_filter_op filter_op, void *arg)
{
	int ret = 0;

	switch (filter_type) {
#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	case RTE_ETH_FILTER_NTUPLE:
		ret = tsrn10_ntuple_filter_handle(dev, filter_op, arg);
		break;
	case RTE_ETH_FILTER_ETHERTYPE:
		ret = tsrn10_ethertype_filter_handle(dev, filter_op, arg);
		break;
	case RTE_ETH_FILTER_SYN:
		ret = tsrn10_syn_filter_handle(dev, filter_op, arg);
		break;
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	case RTE_ETH_FILTER_GENERIC:
		if (filter_op != RTE_ETH_FILTER_GET)
			return -EINVAL;
		*(const void **)arg = &tsrn10_flow_ops;
		break;
#endif
	default:
		PMD_DRV_LOG(WARNING, "Filter type (%d) not "
				"supported", filter_type);
		break;
	}

	return ret;
}
#endif

static int
tsrn10_dev_rss_reta_update(struct rte_eth_dev *dev,
			   struct rte_eth_rss_reta_entry64 *reta_conf,
			   uint16_t reta_size)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t dma_offset = port->attr.port_offset;
	uint32_t *indirtbl = &port->indirtbl[0];
	uint8_t p_id = port->attr.nr_port;
	struct tsrn10_rx_queue *rxq;
	uint16_t i, idx, shift;
	uint16_t dma_index;
	uint16_t qid = 0;

	if (reta_size > TSRN10_RSS_INDIR_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid reta size, reta_size:%d", reta_size);
		return -EINVAL;
	}


	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			indirtbl[i] = reta_conf[idx].reta[shift];
	}

	for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
		qid = indirtbl[i];
		if (qid < dev->data->nb_rx_queues) {
			rxq = dev->data->rx_queues[qid];
			dma_index = rxq->attr.index - dma_offset;
			tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i),
					dma_index);
			rxq->rx_offload_capa |= DEV_RX_OFFLOAD_RSS_HASH;
		} else {
			TSRN10_PMD_LOG(WARNING, "port[%d] reta[%d]-Queue=%d "
				"Rx Queue Num Is Out Range Of Cur Settings\n",
				dev->data->port_id, i, qid);
		}
	}
	port->reta_has_cfg = true;

	return 0;
}

static uint16_t
tsrn10_dma_to_queue_id(struct rte_eth_dev *dev, uint16_t dma_index)
{
	struct tsrn10_rx_queue *rxq;
	bool find = false;
	uint16_t idx;

	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = dev->data->rx_queues[idx];
		if (!rxq)
			continue;
		if (rxq->attr.index == dma_index) {
			find = true;
			break;
		}
	}
	if (find)
		return rxq->attr.queue_id;

	return UINT16_MAX;
}

static int
tsrn10_dev_rss_reta_query(struct rte_eth_dev *dev,
			  struct rte_eth_rss_reta_entry64 *reta_conf,
			  uint16_t reta_size)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t dma_offset = port->attr.port_offset;
	uint32_t *indirtbl = &port->indirtbl[0];
	uint8_t p_id = port->attr.nr_port;
	uint16_t i, idx, shift;
	uint16_t dma_index;
	uint16_t queue_id;

	if (reta_size > TSRN10_RSS_INDIR_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid reta size, reta_size:%d", reta_size);
		return -EINVAL;
	}

	for (i = 0; i < reta_size; i++) {
		dma_index = tsrn10_eth_rd(hw,
				    TSRN10_RSS_REDIR_TB(p_id, i));
		dma_index = dma_index + dma_offset;
		queue_id = tsrn10_dma_to_queue_id(dev, dma_index);
		if (queue_id == UINT16_MAX) {
			PMD_DRV_LOG(ERR, "Invalid rss-table value is the"
					" Sw-queue not Mathch Hardware?\n");
			return -EINVAL;
		}
		indirtbl[i] = queue_id;
	}
	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			reta_conf[idx].reta[shift] = (uint16_t)indirtbl[i];
	}

	return 0;
}

static int
tsrn10_dev_rss_hash_conf_get(struct rte_eth_dev *dev,
			     struct rte_eth_rss_conf *rss_conf)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t *hash_key;
	uint32_t rss_key;
	uint64_t rss_hf;
	uint32_t mrqc;
	uint16_t i;

	hash_key = rss_conf->rss_key;
	if (hash_key != NULL) {
		for (i = 0; i < 10; i++) {
			rss_key = tsrn10_eth_rd(hw, TSRN10_RSS_KEY_TABLE(9 - i));
			rss_key = rte_be_to_cpu_32(rss_key);
			hash_key[(i * 4)] = rss_key & 0x000000FF;
			hash_key[(i * 4) + 1] = (rss_key >> 8) & 0x000000FF;
			hash_key[(i * 4) + 2] = (rss_key >> 16) & 0x000000FF;
			hash_key[(i * 4) + 3] = (rss_key >> 24) & 0x000000FF;
		}
	}
	rss_hf = 0;
	mrqc = tsrn10_eth_rd(hw, TSRN10_RSS_MRQC_ADDR) & TSRN10_RSS_HASH_CFG_MASK;
	if (mrqc == 0) {
		rss_conf->rss_hf = 0;
		return 0;
	}
	for (i = 0; i < TSRN10_RSS_HASH_MAX_CFG; i++)
		if (rss_cfg[i].reg_val & mrqc)
			rss_hf |= rss_cfg[i].rss_flag;

	rss_conf->rss_hf = rss_hf;

	return 0;
}

static void
tsrn10_update_vxlan_port(struct tsrn10_hw *hw, uint16_t port)
{
	tsrn10_eth_wr(hw, TSRN10_ETH_VXLAN_PORT_CTRL, port);
}

static void
tsrn10_dev_add_vxlan_port(struct tsrn10_hw *hw, uint16_t port, bool add)
{
	if (add)
		tsrn10_update_vxlan_port(hw, port);
	else
		tsrn10_update_vxlan_port(hw, TSRN10_ETH_VXLAN_DEF_PORT);
}

static int
tsrn10_dev_udp_tunnel_port_add(struct rte_eth_dev *dev,
			       struct rte_eth_udp_tunnel *udp_tunnel)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int ret = 0;

	if (udp_tunnel == NULL)
		return -EINVAL;
	switch (udp_tunnel->prot_type) {
	case RTE_TUNNEL_TYPE_VXLAN:
		tsrn10_dev_add_vxlan_port(hw, udp_tunnel->udp_port, true);
		break;
	default:
		PMD_DRV_LOG(ERR, "Invalid tunnel type");
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int
tsrn10_dev_udp_tunnel_port_del(struct rte_eth_dev *dev,
			       struct rte_eth_udp_tunnel *udp_tunnel)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int ret = 0;

	if (udp_tunnel == NULL)
		return -EINVAL;

	switch (udp_tunnel->prot_type) {
	case RTE_TUNNEL_TYPE_VXLAN:
		tsrn10_dev_add_vxlan_port(hw, udp_tunnel->udp_port, false);
		break;
	default:
		PMD_DRV_LOG(ERR, "Invalid tunnel type");
		ret = -EINVAL;
		break;
	}

	return ret;
}

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
static int tsrn10_get_module_info(struct rte_eth_dev *dev,
				  struct rte_eth_dev_module_info *modinfo)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	char module_id, diag_supported, rc;

	rc = rnp_mbx_sfp_module_eeprom_info(dev, port->attr.nr_lane, 0xA0,
			SFF_MODULE_ID_OFFSET, 1,
			&module_id);
	if (rc || module_id != 0x3)
		return -EIO;
	rc = rnp_mbx_sfp_module_eeprom_info(dev, port->attr.nr_lane,
			0xA0, SFF_DIAG_SUPPORT_OFFSET, 1,
			&diag_supported);
	if (!rc) {
		switch (module_id) {
		case SFF_MODULE_ID_SFP:
			modinfo->type		= RTE_ETH_MODULE_SFF_8472;
			modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8472_LEN;
			if (!diag_supported)
				modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8436_LEN;
			break;
		case SFF_MODULE_ID_QSFP:
		case SFF_MODULE_ID_QSFP_PLUS:
			modinfo->type		= RTE_ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8436_LEN;
			break;
		case SFF_MODULE_ID_QSFP28:
			modinfo->type		= RTE_ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8636_LEN;
			break;
		default:
			TSRN10_PMD_LOG(INFO, "%s: not supported: module_id:0x%x "
					"diag_supported:0x%x\n", __func__,
					module_id, diag_supported);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static int tsrn10_get_module_eeprom(struct rte_eth_dev *dev,
				    struct rte_dev_eeprom_info *info)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint32_t datalen = info->length;
	uint32_t length = info->length;
	uint32_t start = info->offset;
	char *data = info->data;
	int rc;

	memset(data, 0, datalen);

	/* Read A0 portion of the EEPROM */
	if (start < RTE_ETH_MODULE_SFF_8436_LEN) {
		if (start + datalen > RTE_ETH_MODULE_SFF_8436_LEN)
			length = RTE_ETH_MODULE_SFF_8436_LEN - start;
		rc = rnp_mbx_sfp_module_eeprom_info(dev, port->attr.nr_lane,
				0xA0, start, length, data);
		if (rc)
			return rc;
		start += length;
		data += length;
		length = datalen - length;
	}

	/* Read A2 portion of the EEPROM */
	if (length) {
		start -= RTE_ETH_MODULE_SFF_8436_LEN;
		rc = rnp_mbx_sfp_module_eeprom_info(dev, port->attr.nr_lane,
				0xA2, start, length, data);
	}

	return 0;
}
#endif

static void
tsrn10_reta_table_update(struct rte_eth_dev *dev)
{

	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t dma_offset = port->attr.port_offset;
	uint32_t *indirtbl = &port->indirtbl[0];
	struct tsrn10_rx_queue *rxq;
	int i = 0, qid = 0, p_id;
	uint16_t dma_index;

	p_id = port->attr.nr_lane;
	for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
		qid = indirtbl[i];
		if (qid < dev->data->nb_rx_queues) {
			rxq = dev->data->rx_queues[qid];
			dma_index = rxq->attr.index - dma_offset;
			tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i),
					dma_index);
			rxq->rx_offload_capa |= DEV_RX_OFFLOAD_RSS_HASH;
		} else {
			TSRN10_PMD_LOG(WARNING, "port[%d] reta[%d]-Queue=%d "
					"Rx Queue Num Is Out Range Of Cur Settings\n",
					dev->data->port_id, i, qid);
		}
	}
}

static int
tsrn10_dev_rss_hash_update(struct rte_eth_dev *dev,
			   struct rte_eth_rss_conf *rss_conf)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (rss_conf->rss_key &&
			rss_conf->rss_key_len > TSRN10_RSS_MAX_KEY_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid rss key, rss_key_len:%d",
			    rss_conf->rss_key_len);
		return -EINVAL;
	}
	if (rss_conf->rss_hf &&
		(!(rss_conf->rss_hf & TSRN10_SUPPORT_RSS_OFFLOAD_ALL))) {
		PMD_DRV_LOG(ERR, "RSS Type Don't Support 0x%.2lx",
				rss_conf->rss_hf);
		return -EINVAL;
	}
	port->hw_rss_en = rss_conf->rss_hf ? true : false;
	if (!rss_conf->rss_hf) {
		tsrn10_disable_rss(dev);
	} else {
		tsrn10_rss_hash_set(dev, rss_conf);
		/* We Use Software Way to Achieve Multiple Port Mode
		 * Rss feature disable By Set RSS Table To Deafult Ring.
		 * So When Re Enable RSS, The Rss Reta Table Need To Set Last
		 * User Set State
		 */
		tsrn10_reta_table_update(dev);
	}
	port->rss_cfg = *rss_conf;

	return 0;
}

void tsrn10_tx_queue_release_mbuf(struct tsrn10_tx_queue *txq)
{
	struct tsrn10_tx_desc zero_bd;
	uint16_t i;

	memset(&zero_bd, 0, sizeof(zero_bd));
	if (!txq)
		return;

	if (txq->sw_ring) {
		for (i = 0; i < txq->attr.bd_count; i++) {
			if (txq->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
				txq->tx_bdr[i] = zero_bd;
			}
		}
	}
}

static void tsrn10_tx_queue_release(void *_txq)
{
	struct tsrn10_tx_queue *txq = (struct tsrn10_tx_queue *)_txq;

	PMD_INIT_FUNC_TRACE();

	if (txq) {
		tsrn10_tx_queue_release_mbuf(txq);

		if (txq->rz)
			rte_memzone_free(txq->rz);
		if (txq->sw_ring)
			rte_free(txq->sw_ring);
		rte_free(txq);
	}
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static void tsrn10_dev_txq_release(struct rte_eth_dev *dev,
				   uint16_t qid)
{
	tsrn10_tx_queue_release(dev->data->tx_queues[qid]);
}
#endif

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
void
tsrn10_tx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			 struct rte_eth_txq_info *qinfo)
{
	struct tsrn10_tx_queue *txq;

	txq = dev->data->tx_queues[queue_id];
	if (!txq)
		return;

	qinfo->nb_desc = txq->attr.bd_count;

	qinfo->conf.tx_free_thresh = txq->tx_free_thresh;
	qinfo->conf.tx_thresh.pthresh = TSRN10_TX_DESC_HIGH_WATER_TH;
	qinfo->conf.tx_rs_thresh = txq->tx_rs_thresh;
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
	qinfo->conf.txq_flags = txq->offloads;
#endif
	qinfo->conf.tx_deferred_start = !txq->tx_link || !txq->txq_started;
}
#endif
int tsrn10_alloc_rxbdr(struct rte_eth_dev *dev,
			      struct tsrn10_rx_queue *rxq,
			      uint16_t nb_rx_desc, int socket_id)
{
	uint32_t size = 0;
	const struct rte_memzone *rz = NULL;

	size = nb_rx_desc * sizeof(struct tsrn10_rxsw_entry);
	rxq->sw_ring = rte_zmalloc_socket("rx_swring", size,
			RTE_CACHE_LINE_SIZE, socket_id);

	if (rxq->sw_ring == NULL)
		return -ENOMEM;

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", rxq->attr.queue_id,
			TSRN10_RX_MAX_RING_SZ, TSRN10_BD_RING_ALIGN, socket_id);
#else
	rz = ring_dma_zone_reserve(dev, "rx_ring", rxq->attr.queue_id,
			TSRN10_RX_MAX_RING_SZ, socket_id);
#endif
	if (rz == NULL) {
		rte_free(rxq->sw_ring);
		rxq->sw_ring = NULL;
		return -ENOMEM;
	}
	rxq->rz = rz;
	memset(rz->addr, 0, TSRN10_RX_MAX_RING_SZ);
	rxq->rx_bdr = (struct tsrn10_rx_desc *)rz->addr;
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#ifndef RTE_LIBRTE_XEN_DOM0
	rxq->ring_phys_addr = (uint64_t)rz->phys_addr;
#else
	rxq->ring_phys_addr = rte_mem_phy2mch((rz)->memseg_id, (rz)->phys_addr);
#endif
#else
	rxq->ring_phys_addr = rz->iova;
#endif
	rxq->next_to_clean = 0;

	return 0;
}

uint8_t tsrn10_alloc_rxq_mbuf(struct tsrn10_rx_queue *rxq)
{
	struct tsrn10_rxsw_entry *rx_swbd = rxq->sw_ring;
	volatile struct tsrn10_rx_desc *rxd;
	struct tsrn10_rx_desc zero_bd;
	struct rte_mbuf *mbuf = NULL;
	uint64_t dma_addr;
	uint16_t i;

	memset(&zero_bd, 0, sizeof(zero_bd));
	if (rxq->next_to_clean) {
		for (i = rxq->next_to_clean; i < rxq->attr.bd_count; i++) {
			mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);

			if (!mbuf)
				return -ENOMEM;
			rte_mbuf_refcnt_set(mbuf, 1);
			mbuf->next = NULL;
			mbuf->data_off = RTE_PKTMBUF_HEADROOM;
			dma_addr = tsrn10_get_dma_addr(&rxq->attr, mbuf);
			rxq->rx_bdr[i] = zero_bd;
			rxd = &rxq->rx_bdr[i];
			rxd->d.pkt_addr = dma_addr;
			rxd->d.cmd = 0;
			mbuf->port = rxq->attr.rte_pid;
			rx_swbd[i].mbuf = mbuf;
		}
		for (i = 0; i < rxq->next_to_clean - 1; i++) {
			mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);

			if (!mbuf)
				return -ENOMEM;
			rte_mbuf_refcnt_set(mbuf, 1);
			mbuf->next = NULL;
			mbuf->data_off = RTE_PKTMBUF_HEADROOM;
			dma_addr = tsrn10_get_dma_addr(&rxq->attr, mbuf);

			rxq->rx_bdr[i] = zero_bd;
			rxd = &rxq->rx_bdr[i];
			rxd->d.pkt_addr = dma_addr;
			rxd->d.cmd = 0;
			mbuf->port = rxq->attr.rte_pid;
			rx_swbd[i].mbuf = mbuf;
		}
	} else {
		for (i = 0; i < rxq->attr.bd_count; i++) {
			mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);

			if (!mbuf)
				return -ENOMEM;
			rte_mbuf_refcnt_set(mbuf, 1);
			mbuf->next = NULL;
			mbuf->data_off = RTE_PKTMBUF_HEADROOM;
			dma_addr = tsrn10_get_dma_addr(&rxq->attr, mbuf);

			rxd = &rxq->rx_bdr[i];
			rxd->d.pkt_addr = dma_addr;
			rxd->d.cmd = 0;
			mbuf->port = rxq->attr.rte_pid;
			rx_swbd[i].mbuf = mbuf;
		}
	}

	return 0;
}

static inline void
tsrn10_rxq_prepare_setup(struct tsrn10_hw *hw,
			 struct tsrn10_rx_queue *rxq)
{
	tsrn10_dma_wr(hw,
			TSRN10_DMA_RXQ_START(rxq->attr.index), false);
}

static void
tsrn10_reset_xmit(struct tsrn10_hw *hw,
		  struct tsrn10_tx_queue *txq, struct rte_mbuf *mbuf)
{
	volatile struct tsrn10_tx_desc *txbd;
	struct tsrn10_txsw_entry *tx_entry;
	uint16_t timeout = 0;
	uint16_t tx_id;
	uint16_t head;

	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_START(txq->attr.index), 0);

	tx_id = txq->next_to_use;
	txbd = &txq->tx_bdr[tx_id];
	tx_entry = &txq->sw_ring[tx_id];
	tx_entry->mbuf = NULL;

	if (txq->attr.vf_num != UINT16_MAX) {
		txbd->c.vf_num = txq->attr.vf_num;
		txbd->c.cmd |= TSRN10_CTRL_DESC;

		tx_id = (tx_id + 1) & (txq->attr.bd_count - 1);
		txbd = &txq->tx_bdr[tx_id];
	}

	txbd->d.addr = tsrn10_get_dma_addr(&txq->attr, mbuf);
	txbd->d.blen = mbuf->data_len;
	txbd->d.cmd = rte_cpu_to_le_16(TSRN10_EOP);
	tx_id = (tx_id + 1) & (txq->attr.bd_count - 1);

	tsrn10_wr_reg(txq->tx_tailreg, tx_id);
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_START(txq->attr.index), 1);
	do {
		head = tsrn10_rd_reg(txq->tx_headreg);
		rte_delay_us(5);
		if (head == tx_id)
			break;
		timeout++;
	} while (timeout < 1000);
}

void
tsrn10_rx_queue_sw_reset(struct tsrn10_rx_queue *rxq)
{
	rxq->rx_free_trigger = (uint16_t)(rxq->rx_free_thresh - 1);
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;
	rxq->rx_hold = 0;
	rxq->rx_tail = 0;
	rxq->nb_rx_free = 0;
	rxq->rx_peak_idx = 0;
	rxq->rx_tail = rxq->next_to_clean;
	if (rxq->rx_tail) {
		if (rxq->next_to_clean < rxq->rx_free_thresh)
			rxq->rx_free_trigger = rxq->rx_free_thresh - 1;
		else
			rxq->rx_free_trigger = (rxq->rx_free_thresh *
			(rxq->next_to_clean / rxq->rx_free_thresh + 1)) - 1;
		if (rxq->rx_tail > 32) {
			rxq->rxrearm_start =
				((rxq->next_to_clean / 64) - 1) * 64;
			rxq->rxrearm_start = rxq->next_to_clean - 31;
			rxq->rxrearm_nb = 0;
		} else {
			rxq->rxrearm_start = 0;
			rxq->rxrearm_nb = rxq->rx_tail;
		}
	} else {
		rxq->rxrearm_start = 0;
		rxq->rxrearm_nb = 0;
	}

	memset(&rxq->stats, 0, sizeof(rxq->stats));
}

struct tsrn10_veb_cfg {
	uint32_t mac_hi;
	uint32_t mac_lo;
	uint16_t ring;
};

void
tsrn10_rx_queue_reset(struct rte_eth_dev *dev,
		      struct tsrn10_hw *hw,
		      struct tsrn10_rx_queue *rxq)
{
	/* 1.Prepare A Special unicast Mac Address Pkt */
	/* 2.disable ETH Send Pkts to this ring */
	/* 3.Check This Port Of Tx Queue Setup Has Been finished */
	/* 4.Setup Veb Table Special Mac And Rx Ring ID */
	/* 5.Alloc A mbuf copy pkt and simple_xmit it */
	/* 6.Setup RxQ Len is Head + 1 And Alloc A Rx Desc Store Head */
	/* 7.Check Rx Head Had Been to Zero And Recycle Resource */
	/* 8.Rollback Related Resigter */
	uint8_t reset_pcap[64] = {
		0x01, 0x02, 0x27, 0xe2, 0x9f, 0xa6, 0x08, 0x00,
		0x27, 0xfc, 0x6a, 0xc9, 0x08, 0x00, 0x45, 0x00,
		0x01, 0xc4, 0xb5, 0xd0, 0x00, 0x7a, 0x40, 0x01,
		0xbc, 0xea, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01,
		0x01, 0x01, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
		0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5,
		0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
		0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5};
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	volatile struct tsrn10_rx_desc *rxbd;
	uint8_t qidx = rxq->attr.queue_id;
	struct tsrn10_veb_cfg veb_cfg[4];
	struct rte_eth_txconf def_conf;
	struct rte_ether_hdr *eth_hdr;
	struct tsrn10_tx_queue *txq;
	uint16_t head, timeout = 0;
	struct rte_mbuf *m_mbuf[2];
	uint32_t maclow, machi;
	uint16_t try_count = 0;
	bool tx_new = false;
	uint32_t fc_ctrl;
	uint8_t *macaddr;
	uint16_t vf_id;
	uint16_t index;
	int8_t ret = 0;
	uint32_t ring;
	uint8_t idx;

	index = rxq->attr.index;
	memset(&veb_cfg, 0, sizeof(veb_cfg));
	/* disable eth send pkts to this ring */
	rte_spinlock_lock(&hw->fc_lock);
	fc_ctrl = tsrn10_eth_rd(hw, TSRN10_RING_FC_EN(index));
	tsrn10_eth_wr(hw, TSRN10_RING_FC_THRESH(index), 0);
	fc_ctrl |= 1 << (index % 32);
	tsrn10_eth_wr(hw, TSRN10_RING_FC_EN(index),
			fc_ctrl);
	rxq->next_to_clean = tsrn10_dma_rd(hw,
			TSRN10_DMA_RXQ_HEAD(rxq->attr.index));
	if (!rxq->next_to_clean)
		goto fc_unlock;
	if (qidx < dev->data->nb_tx_queues && dev->data->tx_queues[qidx]) {
		txq = (struct tsrn10_tx_queue *)dev->data->tx_queues[qidx];
		if (!txq)
			goto fc_unlock;
	} else {
		/* Tx queues Has Been Release */
		def_conf.tx_deferred_start = true;
		ret = tsrn10_tx_queue_setup(dev, qidx, rxq->attr.bd_count,
#if RTE_VERSION_NUM(17, 2, 0, 0) > RTE_VERSION && \
    RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION
				dev->pci_dev->device.numa_node, &def_conf);
#elif RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
				dev->pci_dev->numa_node, &def_conf);
#else
				dev->data->numa_node, &def_conf);
#endif
		if (ret)
			goto fc_unlock;

		txq = port->tx_queues[qidx];
		tx_new = true;
	}
	if (unlikely(rte_mempool_get_bulk(rxq->mb_pool, (void *)m_mbuf,
					2) < 0)) {
		TSRN10_PMD_LOG(WARNING, "port[%d] reset rx queue[%d] failed "
				"because mbuf alloc failed\n",
				dev->data->port_id, qidx);
		goto fc_unlock;
	}
	rte_mbuf_refcnt_set(m_mbuf[0], 1);
	rte_mbuf_refcnt_set(m_mbuf[1], 1);

	ring = rxq->attr.index;
	m_mbuf[0]->data_off = RTE_PKTMBUF_HEADROOM;
	rte_memcpy(rte_pktmbuf_mtod(m_mbuf[0], char *),
			reset_pcap, sizeof(reset_pcap));
	eth_hdr = rte_pktmbuf_mtod(m_mbuf[0], struct rte_ether_hdr *);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	macaddr = eth_hdr->dst_addr.addr_bytes;
#else
	macaddr = eth_hdr->d_addr.addr_bytes;
#endif
	m_mbuf[0]->data_len = 64;
	vf_id = (txq->attr.vf_num != UINT16_MAX) ? txq->attr.vf_num : ring / 2;
	macaddr[5] = ring;
	for (idx = 0; idx < 4; idx++) {
		maclow = (macaddr[2] << 24) | (macaddr[3] << 16) |
			(macaddr[4] << 8) | macaddr[5];
		machi = (macaddr[0] << 8) | macaddr[1];
		veb_cfg[idx].mac_lo = tsrn10_dma_rd(hw,
				TSRN10_VBE_MAC_LO(idx, vf_id));
		veb_cfg[idx].mac_hi = tsrn10_dma_rd(hw,
				TSRN10_VBE_MAC_HI(idx, vf_id));
		veb_cfg[idx].ring = tsrn10_dma_rd(hw,
				TSRN10_VEB_VF_RING(idx, vf_id));
		tsrn10_dma_wr(hw, TSRN10_VBE_MAC_LO(idx, vf_id), maclow);
		tsrn10_dma_wr(hw, TSRN10_VBE_MAC_HI(idx, vf_id), machi);
		ring |= ((RNP_VEB_SWITCH_VF_EN | vf_id) << 8);
		tsrn10_dma_wr(hw, TSRN10_VEB_VF_RING(idx, vf_id), ring);
	}
rxq_try_reset:
	rte_delay_us(100);
	txq->txq_started = false;
	timeout = 0;
	do {
		if (!tsrn10_dma_rd(hw, TSRN10_DMA_RXQ_READY(rxq->attr.index)))
			break;
		rte_delay_us(5);
		timeout++;
	} while (timeout < 100);

	timeout = 0;
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_START(rxq->attr.index), 0);
	do {
		if (tsrn10_dma_rd(hw, TSRN10_DMA_TXQ_READY(txq->attr.index)))
			break;
		rte_delay_us(10);

		timeout++;
	} while (timeout < 100);

	rxq->next_to_clean = tsrn10_dma_rd(hw,
			TSRN10_DMA_RXQ_HEAD(rxq->attr.index));
	rxbd = &rxq->rx_bdr[rxq->next_to_clean];
	rxbd->d.pkt_addr = tsrn10_get_dma_addr(&rxq->attr, m_mbuf[1]);
	if (rxq->next_to_clean != rxq->attr.bd_count - 1)
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_LEN(rxq->attr.index),
				rxq->next_to_clean + 1);
	tsrn10_wr_reg(rxq->rx_tailreg, 0);
	tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 1);
	tsrn10_reset_xmit(hw, txq, m_mbuf[0]);
	timeout = 0;
	do {
		if (rxbd->wb.vlan_cmd & rte_cpu_to_le_32(TSRN10_CMD_DD))
			break;
		rte_delay_us(10);
		timeout++;
	} while (timeout < 2000);
	head = tsrn10_dma_rd(hw,
			TSRN10_DMA_RXQ_HEAD(rxq->attr.index));
	if (head == 0)
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
	rxbd->d.pkt_addr = 0;
	rxbd->d.cmd = 0;
	if (tx_new)
		tsrn10_tx_queue_release(txq);
	else
		txq->next_to_use = tsrn10_dma_rd(hw,
				TSRN10_DMA_TXQ_HEAD(txq->attr.index));
	port->tx_queues[qidx] = NULL;
	rxq->next_to_clean = tsrn10_dma_rd(hw,
			TSRN10_DMA_RXQ_HEAD(rxq->attr.index));
	rxq->rx_tail = rxq->next_to_clean;
	if (rxq->rx_tail) {
		try_count++;
		if (try_count < 1000)
			goto rxq_try_reset;
	}
	for (idx = 0; idx < 4; idx++) {
		tsrn10_dma_wr(hw, TSRN10_VBE_MAC_LO(idx, vf_id),
				veb_cfg[idx].mac_lo);
		tsrn10_dma_wr(hw, TSRN10_VBE_MAC_HI(idx, vf_id),
				veb_cfg[idx].mac_hi);
		tsrn10_dma_wr(hw, TSRN10_VEB_VF_RING(idx, vf_id),
				veb_cfg[idx].ring);
	}
	if (txq->next_to_use && !tx_new) {
		tsrn10_tx_queue_reset(hw, txq);
		tsrn10_tx_queue_sw_reset(txq);
		tsrn10_tx_queue_release_mbuf(txq);
		txq->txq_started = true;
		tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_START(txq->attr.index), 1);
	}
	rte_mempool_put_bulk(rxq->mb_pool, (void **)m_mbuf, 2);
fc_unlock:
	tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_LEN(rxq->attr.index),
			rxq->attr.bd_count);
	fc_ctrl = tsrn10_eth_rd(hw, TSRN10_RING_FC_EN(index));
	fc_ctrl &= ~(1 << (index % 32));
	tsrn10_eth_wr(hw, TSRN10_RING_FC_EN(index), fc_ctrl);

	rte_spinlock_unlock(&hw->fc_lock);
}

void tsrn10_setup_rxbdr(struct rte_eth_dev *dev,
			struct tsrn10_hw *hw,
			struct tsrn10_rx_queue *rxq,
			struct rte_mempool *mb_pool)
{
	uint16_t max_desc = rxq->attr.bd_count;
	uint16_t idx = rxq->attr.index;
	phys_addr_t bd_address;
	uint32_t dmah, dmal;

	tsrn10_rxq_prepare_setup(hw, rxq);
	bd_address = (phys_addr_t)rxq->ring_phys_addr;
	dmah = upper_32_bits((uint64_t)bd_address);
	dmal = lower_32_bits((uint64_t)bd_address);

	if (hw->mbx.sriov_st)
		dmah |= (hw->mbx.sriov_st << 24);
	/* We must set sriov_state to hi dma_address high 8bit for vf isolation
	 * |---8bit-----|----------24bit--------|
	 * |sriov_state-|-------high dma address|
	 * |---------------8bit-----------------|
	 * |7bit | 6bit |5-0bit-----------------|
	 * |vf_en|pf_num|-------vf_num----------|
	 */
	tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_BASE_ADDR_LO(idx), dmal);
	tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_BASE_ADDR_HI(idx), dmah);
	tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_LEN(idx), max_desc);

	rxq->mb_pool = mb_pool;

	rxq->rx_tailreg = (uint32_t *)
		(hw->dma_base + TSRN10_DMA_RXQ_TAIL(idx));
	rxq->rx_headreg = (uint32_t *)
		(hw->dma_base + TSRN10_DMA_RXQ_HEAD(idx));

	rxq->next_to_clean = tsrn10_dma_rd(hw,
		TSRN10_DMA_RXQ_HEAD(idx));
	if (rxq->next_to_clean)
		tsrn10_rx_queue_reset(dev, hw, rxq);

	tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_DESC_FETCH_CTRL(idx),
			(TSRN10_RX_DEFAULT_BURST << 16) |
			TSRN10_RX_DESC_HIGH_WATER_TH);

	tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(idx), 500000000);
}

static int tsrn10_rx_queue_setup(struct rte_eth_dev *dev,
				 uint16_t qidx,
				 uint16_t nb_rx_desc,
				 unsigned int socket_id,
				 const struct rte_eth_rxconf *rx_conf,
				 struct rte_mempool *mb_pool)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_eth_adapter *adapter = port->adapt;
	struct rte_eth_dev_data *data = dev->data;
	struct tsrn10_hw *hw = &adapter->hw;
	struct tsrn10_rx_queue *rxq;
	uint64_t offloads;
	int err = 0;

	PMD_DRV_LOG(INFO, "RXQ[%d] setup nb-desc %d\n", qidx, nb_rx_desc);
	if (!port->port_stopped) {
		PMD_DRV_LOG(ERR, "RXQ[%d] Don't Support Dynamic Setup "
				"Port Must Be stopped\n", qidx);
		return -EINVAL;
	}

	if (rte_is_power_of_2(nb_rx_desc) == 0) {
		TSRN10_PMD_ERR("Rxq Desc Num Must power of 2\n");
		return -EINVAL;
	}

	if (nb_rx_desc > MAX_BD_COUNT)
		return -1;

	/* Check Whether Queue Has Been Create If So Release it */
	if (qidx < dev->data->nb_tx_queues &&
			dev->data->rx_queues[qidx] != NULL) {
		tsrn10_rx_queue_release(dev->data->rx_queues[qidx]);
		dev->data->rx_queues[qidx] = NULL;
	}
	rxq = rte_zmalloc_socket("tsrn10_rxq", sizeof(struct tsrn10_rx_queue),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL) {
		TSRN10_PMD_ERR("Failed to allocate RX ring memory");
		return -ENOMEM;
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

	rxq->attr.index = tsrn10_get_dma_ring_index(port, qidx);
	rxq->attr.bd_count = nb_rx_desc;
	rxq->attr.bd_mask = nb_rx_desc - 1;
	rxq->attr.queue_id = qidx;
	rxq->attr.lane_id = port->attr.nr_port;
	rxq->attr.vf_num = hw->mbx.vf_num;
	rxq->attr.sriov_st = hw->mbx.sriov_st;
	rxq->attr.rte_pid = dev->data->port_id;

	rxq->rx_offload_capa = offloads;
	rxq->rx_buf_len = (uint16_t)(rte_pktmbuf_data_room_size(mb_pool) -
			RTE_PKTMBUF_HEADROOM);

	err = tsrn10_alloc_rxbdr(dev, rxq, nb_rx_desc, socket_id);
	if (err)
		goto fail;

	PMD_DRV_LOG(INFO, "PF[%d] dev:[%d] hw-lane[%d] rx_qid[%d] "
			"dma_idx %d socket %d\n",
			hw->function, rxq->attr.rte_pid,
			rxq->attr.lane_id, qidx,
			rxq->attr.index, socket_id);
	rxq->rx_free_thresh = (rx_conf->rx_free_thresh) ?
		rx_conf->rx_free_thresh : TSRN10_DEFAULT_RX_FREE_THRESH;
	rxq->rx_free_trigger = rxq->rx_free_thresh - 1;
	data->rx_queues[qidx] = rxq;

	tsrn10_setup_rxbdr(dev, hw, rxq, mb_pool);
	if (!rxq->next_to_clean)
		rxq->nb_rx_free = nb_rx_desc - 1;
	else if (rxq->next_to_clean == rxq->attr.bd_count - 1)
		rxq->nb_rx_free = rxq->next_to_clean;
	else
		rxq->nb_rx_free = nb_rx_desc - 1;

	rxq->free_mbufs = rte_zmalloc_socket("rxq->free_mbufs",
			sizeof(struct rte_mbuf *) * rxq->attr.bd_count * 2,
			RTE_CACHE_LINE_SIZE, socket_id);
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;

	tsrn10_setup_rx_function(dev);

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
	if (offloads & DEV_RX_OFFLOAD_TIMESTAMP) {
		rxq->timestamp_all = 1;
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		/* Register mbuf field and flag for Rx timestamp */
		err = rte_mbuf_dyn_rx_timestamp_register(
				&tsrn10_timestamp_dynfield_offset,
				&tsrn10_timestamp_dynflag);
		if (err) {
			PMD_DRV_LOG(ERR,
					"Cannot register mbuf field/flag for timestamp");
			return -EINVAL;
		}
#endif
	}
#endif
#ifdef RTE_LIBRTE_IEEE1588
	rxq->ptp_en = 1;
#endif
	if (offloads & DEV_RX_OFFLOAD_VLAN_STRIP)
		tsrn10_vlan_strip_queue_set(dev, qidx, true);
	else
		tsrn10_vlan_strip_queue_set(dev, qidx, false);

	tsrn10_rxq_vec_setup_default(rxq);

	return 0;
fail:
	rte_free(rxq);

	return err;
}

void tsrn10_rx_queue_release_mbuf(struct tsrn10_rx_queue *rxq)
{
	struct tsrn10_rx_desc zero_bd;
	uint16_t i;

	if (!rxq)
		return;

	memset(&zero_bd, 0, sizeof(zero_bd));

	if (rxq->sw_ring) {
		for (i = 0; i < rxq->attr.bd_count; i++) {
			if (rxq->sw_ring[i].mbuf)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
			rxq->sw_ring[i].mbuf = NULL;
			rxq->rx_bdr[i] = zero_bd;
		}
	}
}

static void tsrn10_rx_queue_release(void *_rxq)
{
	struct tsrn10_rx_queue *rxq = (struct tsrn10_rx_queue *)_rxq;

	PMD_INIT_FUNC_TRACE();

	if (rxq) {
		tsrn10_rx_queue_release_mbuf(rxq);
		if (rxq->rz)
			rte_memzone_free(rxq->rz);
		if (rxq->sw_ring)
			rte_free(rxq->sw_ring);
		rte_free(rxq);
	}
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static void tsrn10_dev_rxq_release(struct rte_eth_dev *dev, uint16_t qid)
{
	tsrn10_rx_queue_release(dev->data->rx_queues[qid]);
}
#endif

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
void
tsrn10_rx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			 struct rte_eth_rxq_info *qinfo)
{
	struct tsrn10_rx_queue *rxq;

	rxq = dev->data->rx_queues[queue_id];
	if (!rxq)
		return;

	qinfo->mp = rxq->mb_pool;
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = rxq->attr.bd_count;

	qinfo->conf.rx_free_thresh = rxq->rx_free_thresh;
	qinfo->conf.rx_thresh.pthresh = TSRN10_RX_DESC_HIGH_WATER_TH;
	qinfo->conf.rx_drop_en = !rxq->rxq_started || !rxq->rx_link;
	qinfo->conf.rx_deferred_start = !rxq->rxq_started;
}
#endif

struct rte_tsrn10_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t offset;
	uint32_t reg_base;
	bool hi_addr_en;
};

#ifdef DEBUG_PERF
static const struct rte_tsrn10_xstats_name_off rte_tsrn10_debug_stats_str[] = {
	{"rx_alloc_mbuf_failed", offsetof(struct tsrn10_debug_stats,
			rx_alloc_mbuf_fail), 0, false},
	{"rx clean queue count", offsetof(struct tsrn10_debug_stats,
			rx_clean_count), 0, false},
	{"rx once success clean", offsetof(struct tsrn10_debug_stats,
			rx_desc_clean_num), 0, false},
	{"rx clean queue failed", offsetof(struct tsrn10_debug_stats,
			rx_desc_clean_fail), 0, false},
	{"rx desc is error", offsetof(struct tsrn10_debug_stats,
			rx_desc_err), 0, false},
#if 01
	{"rx burst size", offsetof(struct tsrn10_debug_stats,
			rx_burst_size), 0, false},
	{"rx_burst time", offsetof(struct tsrn10_debug_stats,
			rx_burst_time), 0, false},
	{"rx used cycle", offsetof(struct tsrn10_debug_stats,
			rx_used_cycle), 0, false},
	{"rx check cycle count ", offsetof(struct tsrn10_debug_stats,
			rx_cycle_check_count), 0, false},
	{"tx free mbuf is null", offsetof(struct tsrn10_debug_stats,
			tx_mbuf_err), 0, false},
	{"tx clean queue count", offsetof(struct tsrn10_debug_stats,
			tx_clean_count), 0, false},
	{"tx once clean success", offsetof(struct tsrn10_debug_stats,
			tx_desc_clean_num), 0, false},
	{"tx clean queue failed", offsetof(struct tsrn10_debug_stats,
			tx_desc_clean_fail), 0, false},
	{"tx rc desc is illegal", offsetof(struct tsrn10_debug_stats,
			tx_desc_err), 0, false},
	{"tx burst size", offsetof(struct tsrn10_debug_stats,
			tx_burst_size), 0, false},
	{"tx_burst time", offsetof(struct tsrn10_debug_stats,
			tx_burst_time), 0, false},
	{"tx used cycle", offsetof(struct tsrn10_debug_stats,
			tx_used_cycle), 0, false},
	{"tx check cycle count ", offsetof(struct tsrn10_debug_stats,
			tx_cycle_check_count), 0, false},
	{"tx last tail", offsetof(struct tsrn10_debug_stats,
		       tx_last_tail), 0, false},
	{"tx curl tail", offsetof(struct tsrn10_debug_stats,
			tx_curl_tail), 0, false},
	{"tx free desc", offsetof(struct tsrn10_debug_stats,
			tx_free_desc), 0, false},
	{"tx curl sw-head", offsetof(struct tsrn10_debug_stats,
			tx_next_to_clean), 0, false},
#endif
};
#endif

static const struct rte_tsrn10_xstats_name_off rte_tsrn10_rx_stats_str[] = {
	{"Mac Local Fault", offsetof(struct tsrn10_hw_stats,
		mac_local_fault), 0, false},
	{"Mac remote Fault", offsetof(struct tsrn10_hw_stats,
		mac_remote_fault), 0, false},
	{"Rx good bad Pkts", offsetof(struct tsrn10_hw_stats,
		rx_all_pkts), TSRN10_MMC_RX_GBFRMB, true},
	{"Rx good bad bytes", offsetof(struct tsrn10_hw_stats,
		rx_all_bytes), TSRN10_MMC_RX_GBOCTGB, true},
	{"Rx good Pkts", offsetof(struct tsrn10_hw_stats,
		rx_good_pkts), 0, false},
	{"RX good Bytes", offsetof(struct tsrn10_hw_stats,
		rx_good_bytes), TSRN10_MMC_RX_GOCTGB, true},
	{"Rx Broadcast Pkts", offsetof(struct tsrn10_hw_stats,
		rx_broadcast), TSRN10_MMC_RX_BCASTGB, true},
	{"Rx Multicast Pkts", offsetof(struct tsrn10_hw_stats,
		rx_multicast), TSRN10_MMC_RX_MCASTGB, true},
	{"Rx Crc Frames Err Pkts", offsetof(struct tsrn10_hw_stats,
		rx_crc_err), TSRN10_MMC_RX_CRCERB, true},
	{"Rx len Err with Crc err", offsetof(struct tsrn10_hw_stats,
		rx_runt_err), TSRN10_MMC_RX_RUNTERB, false},
	{"Rx jabber Error ", offsetof(struct tsrn10_hw_stats,
		rx_jabber_err), TSRN10_MMC_RX_JABBER_ERR, false},
	{"Rx len Err Without Other Error", offsetof(struct tsrn10_hw_stats,
		rx_undersize_err), TSRN10_MMC_RX_USIZEGB, false},
	{"Rx Len Shorter 64Bytes Without Err", offsetof(struct tsrn10_hw_stats,
		rx_undersize_err), TSRN10_MMC_RX_USIZEGB, false},
	{"Rx Len Oversize Max Support Err", offsetof(struct tsrn10_hw_stats,
		rx_oversize_err), TSRN10_MMC_RX_OSIZEGB, false},
	{"Rx 64Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_64octes_pkts), TSRN10_MMC_RX_64_BYTESB, true},
	{"Rx 65Bytes To 127Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_128to255_octes_pkts), TSRN10_MMC_RX_65TO127_BYTESB, true},
	{"Rx 128Bytes To 255Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_128to255_octes_pkts), TSRN10_MMC_RX_128TO255_BYTESB, true},
	{"Rx 256Bytes To 511Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_256to511_octes_pkts), TSRN10_MMC_RX_256TO511_BYTESB, true},
	{"Rx 512Bytes To 1023Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_512to1023_octes_pkts), TSRN10_MMC_RX_512TO1203_BYTESB, true},
	{"Rx Bigger 1024Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_1024tomax_octes_pkts), TSRN10_MMC_RX_1024TOMAX_BYTESB, true},
	{"Rx Unicast Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_unicast), TSRN10_MMC_RX_UCASTGB, true},
	{"Rx Len Err Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_len_err), TSRN10_MMC_RX_LENERRB, true},
	{"Rx Len Not Equal Real data_len", offsetof(struct tsrn10_hw_stats,
		rx_len_invaild), TSRN10_MMC_RX_OUTOF_RANGE, true},
	{"Rx Pause Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_pause), TSRN10_MMC_RX_PAUSEB, true},
	{"Rx Vlan Frame Num", offsetof(struct tsrn10_hw_stats,
		rx_vlan), TSRN10_MMC_RX_VLANGB, true},
	{"Rx Hw Watchdog Frame Err", offsetof(struct tsrn10_hw_stats,
		rx_watchdog_err), TSRN10_MMC_RX_WDOGERRB, true},
};

static const struct rte_tsrn10_xstats_name_off rte_tsrn10_tx_stats_str[] = {
	{"Tx Good Bad Pkts Num", offsetof(struct tsrn10_hw_stats,
		tx_all_pkts), TSRN10_MMC_TX_GBFRMB, true},
	{"Tx Good Bad Bytes", offsetof(struct tsrn10_hw_stats,
		tx_all_bytes), TSRN10_MMC_TX_GBOCTGB, true},
	{"Tx Good Broadcast Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_broadcast), TSRN10_MMC_TX_BCASTB, true},
	{"Tx Good Multicast Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_multicast), TSRN10_MMC_TX_MCASTB, true},
	{"Tx 64Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_64octes_pkts), TSRN10_MMC_TX_64_BYTESB, true},
	{"Tx 65 To 127 Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_65to127_octes_pkts), TSRN10_MMC_TX_65TO127_BYTESB, true},
	{"Tx 128 To 255 Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_128to255_octes_pkts), TSRN10_MMC_TX_128TO255_BYTEB, true},
	{"Tx 256 To 511 Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_256to511_octes_pkts), TSRN10_MMC_TX_256TO511_BYTEB, true},
	{"Tx 512 To 1023 Bytes Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_512to1023_octes_pkts), TSRN10_MMC_TX_512TO1023_BYTEB, true},
	{"Tx Bigger Than 1024 Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_1024tomax_octes_pkts), TSRN10_MMC_TX_1024TOMAX_BYTEB, true},
	{"Tx Good And Bad Unicast Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_all_unicast), TSRN10_MMC_TX_GBUCASTB, true},
	{"Tx Good And Bad Multicast Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_all_multicase), TSRN10_MMC_TX_GBMCASTB, true},
	{"Tx Good And Bad Broadcast Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_all_broadcast), TSRN10_MMC_TX_GBBCASTB, true},
	{"Tx Underflow Frame Err Num", offsetof(struct tsrn10_hw_stats,
		tx_underflow_err), TSRN10_MMC_TX_UNDRFLWB, true},
	{"Tx Good Frame Bytes", offsetof(struct tsrn10_hw_stats,
		tx_good_bytes), TSRN10_MMC_TX_GBYTESB, true},
	{"Tx Good Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_good_pkts), TSRN10_MMC_TX_GBFRMB, true},
	{"Tx Pause Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_pause_pkts), TSRN10_MMC_TX_PAUSEB, true},
	{"Tx Vlan Frame Num", offsetof(struct tsrn10_hw_stats,
		tx_vlan_pkts), TSRN10_MMC_TX_VLANB, true},
	{"Tx Queue Full", offsetof(struct tsrn10_hw_stats,
		tx_ring_full), 0, 0},
	{"Tx Full Drop", offsetof(struct tsrn10_hw_stats,
		tx_full_drop), 0, 0},
};
#define TSRN10_NB_RX_HW_STATS (RTE_DIM(rte_tsrn10_rx_stats_str))
#define TSRN10_NB_TX_HW_STATS (RTE_DIM(rte_tsrn10_tx_stats_str))
#ifdef DEBUG_PERF
#define TSRN10_NB_DEBUG_STATS (RTE_DIM(rte_tsrn10_debug_stats_str))
#endif

static inline void tsrn10_store_hw_stats(struct tsrn10_hw_stats *stats,
				  uint32_t offset, uint64_t val)
{
	*(uint64_t *)(((char *)stats) + offset) = val;
}

static void tsrn10_get_mmc_info(struct tsrn10_hw *hw,
				uint16_t p_id,
				struct tsrn10_hw_stats *stats,
				const struct rte_tsrn10_xstats_name_off *ptr)
{
	uint64_t count = 0;
	uint32_t offset;
	uint64_t hi_reg;

	if (ptr->reg_base) {
		count = tsrn10_mac_rd(hw, p_id, ptr->reg_base);
		if (ptr->hi_addr_en) {
			offset = ptr->reg_base + 4;
			hi_reg = tsrn10_mac_rd(hw, p_id, offset);
			count += (hi_reg << 32);
		}
		tsrn10_store_hw_stats(stats, ptr->offset, count);
	}
}

static void tsrn10_get_hw_stats(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw_stats *stats = &port->hw_stats;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	const struct rte_tsrn10_xstats_name_off *ptr;
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	struct tsrn10_tx_queue *txq;
	uint16_t i;

	for (i = 0; i < TSRN10_NB_RX_HW_STATS; i++) {
		ptr = &rte_tsrn10_rx_stats_str[i];
		tsrn10_get_mmc_info(hw, p_id, stats, ptr);
	}

	for (i = 0; i < TSRN10_NB_TX_HW_STATS; i++) {
		ptr = &rte_tsrn10_tx_stats_str[i];
		tsrn10_get_mmc_info(hw, p_id, stats, ptr);
	}
	stats->rx_good_pkts = stats->rx_all_pkts - stats->rx_crc_err -
			      stats->rx_len_err - stats->rx_watchdog_err;
	stats->rx_bad_pkts = stats->rx_crc_err + stats->rx_len_err +
			     stats->rx_watchdog_err;
	stats->tx_bad_pkts = stats->tx_underflow_err;
	stats->mac_local_fault = port->sw_stat.mac_local_fault;
	stats->mac_remote_fault = port->sw_stat.mac_remote_fault;

	stats->tx_full_drop = 0;
	stats->tx_ring_full = 0;
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = ((struct tsrn10_tx_queue **)
				(dev->data->tx_queues))[i];
		if (!txq)
			continue;
		stats->tx_full_drop += txq->stats.tx_full_drop;
		stats->tx_ring_full += txq->stats.tx_ring_full;
	}
}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10_stats_get(struct rte_eth_dev *dev,
		 struct rte_eth_stats *stats)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct rte_eth_dev_data *data = dev->data;
	uint64_t rx_cat_err = 0;
	uint64_t rx_miss = 0;
	int i = 0;

	PMD_INIT_FUNC_TRACE();

	tsrn10_get_hw_stats(dev);
	for (i = 0; i < data->nb_rx_queues; i++) {
		if (!data->rx_queues[i])
			continue;
		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = ((struct tsrn10_rx_queue **)
					(data->rx_queues))[i]->stats.ipackets;
			stats->q_ibytes[i] = ((struct tsrn10_rx_queue **)
					(data->rx_queues))[i]->stats.ibytes;
			stats->ipackets += stats->q_ipackets[i];
			stats->ibytes += stats->q_ibytes[i];
		} else {
			stats->ipackets += ((struct tsrn10_rx_queue **)
					(data->rx_queues))[i]->stats.ipackets;
			stats->ibytes += ((struct tsrn10_rx_queue **)
					(data->rx_queues))[i]->stats.ibytes;
		}
	}

	for (i = 0; i < data->nb_tx_queues; i++) {
		if (!data->tx_queues[i])
			continue;
		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = ((struct tsrn10_tx_queue **)
					(data->tx_queues))[i]->stats.opackets;
			stats->q_obytes[i] = ((struct tsrn10_tx_queue **)
					(data->tx_queues))[i]->stats.obytes;
			stats->opackets += stats->q_opackets[i];
			stats->obytes += stats->q_obytes[i];
		} else {
			stats->opackets += ((struct tsrn10_tx_queue **)
					(data->tx_queues))[i]->stats.opackets;
			stats->obytes += ((struct tsrn10_tx_queue **)
					(data->tx_queues))[i]->stats.obytes;
		}
	}
	rx_miss = tsrn10_eth_rd(hw,
			TSRN10_ETH_RXTRANS_DROP(port->attr.nr_port));
	if (rx_miss >= port->sw_stat.last_rx_miss)
		port->sw_stat.rx_miss_inc +=
			rx_miss - port->sw_stat.last_rx_miss;
	else
		/* Override */
		port->sw_stat.rx_miss_inc += rx_miss + UINT32_MAX;
	rx_cat_err = tsrn10_eth_rd(hw,
			TSRN10_ETH_RXTRANS_CAT_ERR(port->attr.nr_port));
	if (rx_cat_err >= port->sw_stat.last_rxcat_err)
		port->sw_stat.rxcat_err_inc +=
			rx_cat_err - port->sw_stat.last_rxcat_err;
	else
		/* Override */
		port->sw_stat.rxcat_err_inc += rx_cat_err + UINT32_MAX;

	port->sw_stat.last_rxcat_err = rx_cat_err;
	port->sw_stat.last_rx_miss = rx_miss;
	stats->ierrors = port->hw_stats.rx_bad_pkts;
	stats->imissed =
		port->sw_stat.rx_miss_inc + port->sw_stat.rxcat_err_inc;
	stats->oerrors = port->hw_stats.tx_underflow_err;

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10_stats_reset(struct rte_eth_dev *dev)
{
	struct tsrn10_hw_stats *stats = TSRN10_DEV_TO_HW_STATS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_rx_queue *rxq;
	struct tsrn10_tx_queue *txq;
	uint8_t idx;
	PMD_INIT_FUNC_TRACE();

	memset(stats, 0, sizeof(*stats));
	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = ((struct tsrn10_rx_queue **)
				(dev->data->rx_queues))[idx];
		if (!rxq)
			continue;
		memset(&rxq->stats, 0, sizeof(struct xstats));
	}
	for (idx = 0; idx < dev->data->nb_tx_queues; idx++) {
		txq = ((struct tsrn10_tx_queue **)
				(dev->data->tx_queues))[idx];
		if (!txq)
			continue;
		memset(&txq->stats, 0, sizeof(struct xstats));
	}
	port->sw_stat.rx_miss_inc = 0;
	port->sw_stat.rxcat_err_inc = 0;

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
static int
tsrn10_dev_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstats *xstats,
		      unsigned int n __rte_unused)
#else
static int
tsrn10_dev_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats,
		      unsigned int n __rte_unused)
#endif
{
	struct tsrn10_hw_stats *hw_stats = TSRN10_DEV_TO_HW_STATS(dev);
	uint32_t count = 0;
	uint8_t i;

#if RTE_VERSION_NUM(16, 4, 0, 0) < RTE_VERSION
	if (xstats != NULL) {
#else
	if (xstats != NULL && n) {
#endif
		tsrn10_get_hw_stats(dev);
		for (i = 0; i < TSRN10_NB_RX_HW_STATS; i++) {
			xstats[count].value = *(uint64_t *)(((char *)hw_stats) +
					rte_tsrn10_rx_stats_str[i].offset);
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[count].id = count;
#endif
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[count].name, sizeof(xstats[count].name),
					"%s", rte_tsrn10_rx_stats_str[i].name);
#endif
			count++;
		}

		for (i = 0; i < TSRN10_NB_TX_HW_STATS; i++) {
			xstats[count].value = *(uint64_t *)(((char *)hw_stats) +
					rte_tsrn10_tx_stats_str[i].offset);
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[count].id = count;
#endif
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[count].name, sizeof(xstats[count].name),
					"%s", rte_tsrn10_rx_stats_str[i].name);
#endif
			count++;
		}
#ifdef DEBUG_PERF
		struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
		struct tsrn10_debug_stats *debug_stats = &port->stats;

		for (i = 0; i < TSRN10_NB_DEBUG_STATS; i++) {
			xstats[count].value =
				*(uint64_t *)(((char *)debug_stats) +
					rte_tsrn10_debug_stats_str[i].offset);
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[count].id = count;
#endif
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[count].name, sizeof(xstats[count].name),
				"%s", rte_tsrn10_debug_stats_str[i].name);
#endif
			count++;
		}
#endif
	} else {
		return tsrn10_dev_cal_xstats_num();
	}

	return count;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10_dev_xstats_reset(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
#ifdef DEBUG_PERF
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
#endif
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t reg;

	/* Set MMC Reset HW Counter When Read Event */
	reg = tsrn10_mac_rd(hw, p_id, TSRN10_MMC_CTRL);
	tsrn10_mac_wr(hw, p_id, TSRN10_MMC_CTRL, TSRN10_MMC_RSTONRD);

	port->sw_stat.mac_local_fault = 0;
	port->sw_stat.mac_local_fault = 0;
	tsrn10_stats_reset(dev);
	tsrn10_get_hw_stats(dev);
#ifdef DEBUG_PERF
	memset(&port->stats, 0, sizeof(port->stats));
#endif
	reg = tsrn10_mac_rd(hw, p_id, TSRN10_MMC_CTRL);
	reg &= ~TSRN10_MMC_RSTONRD;
	tsrn10_mac_wr(hw, p_id, TSRN10_MMC_CTRL, reg);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static uint32_t tsrn10_dev_cal_xstats_num(void)
{
	uint32_t cnt = TSRN10_NB_RX_HW_STATS + TSRN10_NB_TX_HW_STATS;

#ifdef DEBUG_PERF
	cnt += TSRN10_NB_DEBUG_STATS;
#endif
	return cnt;
}

#if RTE_VERSION_NUM(16, 7, 0, 0) <= RTE_VERSION
static int
tsrn10_dev_xstats_get_names(__rte_unused struct rte_eth_dev *dev,
			    struct rte_eth_xstat_name *xstats_names,
			    __rte_unused unsigned int size)
{
	uint32_t i, count = 0;
	uint32_t xstats_cnt = tsrn10_dev_cal_xstats_num();

	if (xstats_names != NULL) {
		for (i = 0; i < TSRN10_NB_RX_HW_STATS; i++) {
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
			strlcpy(xstats_names[count].name,
				rte_tsrn10_rx_stats_str[i].name,
				sizeof(xstats_names[count].name));
#else
			snprintf(xstats_names[count].name,
				sizeof(xstats_names[count].name), "%s",
				rte_tsrn10_rx_stats_str[i].name);
#endif
			count++;
		}

		for (i = 0; i < TSRN10_NB_TX_HW_STATS; i++) {
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
			strlcpy(xstats_names[count].name,
				rte_tsrn10_tx_stats_str[i].name,
				sizeof(xstats_names[count].name));
#else
			snprintf(xstats_names[count].name,
				sizeof(xstats_names[count].name), "%s",
				rte_tsrn10_tx_stats_str[i].name);
#endif
			count++;
		}
#ifdef DEBUG_PERF
		for (i = 0; i < TSRN10_NB_DEBUG_STATS; i++) {
			strlcpy(xstats_names[count].name,
				rte_tsrn10_debug_stats_str[i].name,
				sizeof(xstats_names[count].name));
			count++;
		}
#endif
	}

	return xstats_cnt;
}
#endif

static void
tsrn10_interrupt_unregister(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	if (intr_handle)
		rte_intr_callback_unregister(intr_handle,
				tsrn10_dev_interrupt_handler, dev);
}

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
static int tsrn10_dev_close(struct rte_eth_dev *dev)
#else
static void tsrn10_dev_close(struct rte_eth_dev *dev)
#endif
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint16_t i;

	PMD_INIT_FUNC_TRACE();
	tsrn10_dev_stop(dev);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		tsrn10_rx_queue_release(dev->data->rx_queues[i]);
		dev->data->rx_queues[i] = NULL;
	}
	dev->data->nb_rx_queues = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		tsrn10_tx_queue_release(dev->data->tx_queues[i]);
		dev->data->tx_queues[i] = NULL;
	}
	dev->data->nb_tx_queues = 0;

	port->port_closed = 1;

	if (!adapter->unregistered && !system_no_interrupt) {
		rnp_mbx_link_event_enable(adapter->eth_dev, false);
		tsrn10_interrupt_unregister(adapter->eth_dev);
		adapter->unregistered = true;
	}
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	if (port->dev->process_private)
		free(port->dev->process_private);
#endif
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int tsrn10_promiscuous_enable(struct rte_eth_dev *dev)
#else
static void tsrn10_promiscuous_enable(struct rte_eth_dev *dev)
#endif
{
	PMD_INIT_FUNC_TRACE();

	tsrn10_update_mpfm(dev, TSRN10_MPF_MODE_PROMISC, true);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int tsrn10_promiscuous_disable(struct rte_eth_dev *dev)
#else
static void tsrn10_promiscuous_disable(struct rte_eth_dev *dev)
#endif
{
	PMD_INIT_FUNC_TRACE();

	tsrn10_update_mpfm(dev, TSRN10_MPF_MODE_PROMISC, false);

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#else
	return;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int tsrn10_allmulticast_enable(struct rte_eth_dev *dev)
#else
static void tsrn10_allmulticast_enable(struct rte_eth_dev *dev)
#endif
{
	PMD_INIT_FUNC_TRACE();

	tsrn10_update_mpfm(dev, TSRN10_MPF_MODE_ALLMULTI, true);

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#else
	return;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int tsrn10_allmulticast_disable(struct rte_eth_dev *dev)
#else
static void tsrn10_allmulticast_disable(struct rte_eth_dev *dev)
#endif
{
	PMD_INIT_FUNC_TRACE();
	if (dev->data->promiscuous == 1)
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
		return 0;
#else
		return; /* must remain in all_multicast mode */
#endif
	tsrn10_update_mpfm(dev, TSRN10_MPF_MODE_ALLMULTI, false);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#else
	return;
#endif
}

static uint32_t *tsrn10_support_ptypes_get(void)
{
	static uint32_t ptypes[] = {
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L2_ETHER_TIMESYNC,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_TUNNEL_VXLAN,
		RTE_PTYPE_TUNNEL_GRE,
		RTE_PTYPE_INNER_L3_IPV6,
		RTE_PTYPE_INNER_L3_IPV6_EXT,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_INNER_L4_SCTP,
		RTE_PTYPE_UNKNOWN,
	};

	return ptypes;
}

static const uint32_t *
tsrn10_dev_supported_ptypes_get(struct rte_eth_dev *dev)
{
	if (dev->rx_pkt_burst == tsrn10_recv_pkts)
		return tsrn10_support_ptypes_get();

	return NULL;
}

static uint16_t
tsrn10_verify_vaild_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint8_t max_port;
	uint8_t i = 0;

	max_port = adapter->num_ports;
	for (i = 0; i < max_port; i++) {
		port = adapter->port[i];
		mtu = RTE_MAX(mtu, port->cur_mtu);
	}
	return mtu;
}

int tsrn10_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
#endif
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint32_t frame_size = mtu + TSRN10_ETH_OVERHEAD;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t reg;

	PMD_INIT_FUNC_TRACE();

	/* check that mtu is within the allowed range */
	if (frame_size < TSRN10_MAC_MINFRM_SIZE ||
			frame_size > TSRN10_MAC_MAXFRM_SIZE)
		return -EINVAL;

	/*
	 * Refuse mtu that requires the support of scattered packets
	 * when this feature has not been enabled before.
	 */
	if (dev->data->dev_started &&
			!dev->data->scattered_rx && frame_size >
			dev->data->min_rx_buf_size - RTE_PKTMBUF_HEADROOM) {
		TSRN10_PMD_ERR("SG not enabled And Don't Support "
				"Dynamic Config Mtu Please Stop Port\n");
		return -EINVAL;
	}
	if (frame_size < RTE_ETHER_MIN_LEN) {
		PMD_DRV_LOG(ERR, "valid  packet length must be "
				"range from %u to  %u, "
				"when Jumbo Frame Feature disabled",
				(uint32_t)RTE_ETHER_MIN_LEN,
				(uint32_t)RTE_ETHER_MAX_LEN);
		return -EINVAL;
	}
	/* For One Pf Multiple Port The Mtu We Must Set
	 * The Biggest Mtu The Ports Belong To Pf
	 * Because Of The Control Button Is Only One
	 */
	port->cur_mtu = mtu;
	mtu = tsrn10_verify_vaild_mtu(dev, mtu);
	frame_size = mtu + TSRN10_ETH_OVERHEAD;
#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
	if (frame_size > RTE_ETHER_MAX_LEN)
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		rxmode->offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		rxmode->offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;
#else
		rxmode->jumbo_frame = 1;
	else
		rxmode->jumbo_frame = 0;
#endif
#endif

#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
	rxmode->max_rx_pkt_len = frame_size;
#endif
	/*setting the MTU*/

	tsrn10_eth_wr(hw, TSRN10_MAX_FRAME_CTRL, frame_size);
	tsrn10_eth_wr(hw, TSRN10_MIN_FRAME_CTRL, 60);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	if (frame_size > RTE_ETHER_MTU) {
#elif RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
	if (rxmode->offloads & DEV_RX_OFFLOAD_JUMBO_FRAME) {
#else
	if (rxmode->jumbo_frame) {
#endif
		/* To Protect Conflict Hw Resource */
		rte_spinlock_lock(&port->rx_mac_lock);
		reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_RX_CFG);
		reg |= TSRN10_MAC_JE;
		tsrn10_mac_wr(hw, p_id, TSRN10_MAC_RX_CFG, reg);
		rte_spinlock_unlock(&port->rx_mac_lock);
	}

	return 0;
}

static int
tsrn10_vlan_filter_set(struct rte_eth_dev *dev,
		       uint16_t vlan_id, int on)
{
	return tsrn10_add_vlan_filter(dev, vlan_id, on);
}

static void
tsrn10_vlan_hw_strip_config(struct rte_eth_dev *dev, bool en)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_rx_queue *rxq;
	uint16_t index;
	uint32_t reg;
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		index = rxq->attr.index;
		reg = tsrn10_eth_rd(hw, TSRN10_VLAN_Q_STRIP_CTRL(index));
		if (en)
			reg |= 1 << (index % 32);
		else
			reg &= ~(1 << (index % 32));

		tsrn10_eth_wr(hw, TSRN10_VLAN_Q_STRIP_CTRL(index), reg);
	}
}

static void
tsrn10_vlan_hw_filter_enable(struct rte_eth_dev *dev, bool on)
{
	tsrn10_vlan_filter_en(dev, on);
}

static void
tsrn10_vlan_hw_strip_enable(struct rte_eth_dev *dev, bool on)
{
	PMD_INIT_FUNC_TRACE();

	if (on)
		tsrn10_vlan_hw_strip_config(dev, true);
	else
		tsrn10_vlan_hw_strip_config(dev, false);
}

static void
tsrn10_double_vlan_enable(struct rte_eth_dev *dev, bool on)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t ctrl;

	/* En Double Vlan Engine */
	ctrl = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_VLAN_TAG);
	if (on)
		ctrl |= TSRN10_MAC_VLAN_EDVLP | TSRN10_MAC_VLAN_ESVL;
	else
		ctrl &= ~(TSRN10_MAC_VLAN_EDVLP | TSRN10_MAC_VLAN_ESVL);
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_VLAN_TAG, ctrl);
}

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
static int
tsrn10_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct rte_eth_rxmode *rxmode;

	rxmode = &dev->data->dev_conf.rxmode;
#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
	if (mask & ETH_QINQ_STRIP_MASK) {
		PMD_DRV_LOG(ERR, "QinQ Strip isn't supported.");
		return -ENOTSUP;
	}
#endif
	if (mask & ETH_VLAN_FILTER_MASK) {
		if (rxmode->offloads & DEV_RX_OFFLOAD_VLAN_FILTER)
			tsrn10_vlan_hw_filter_enable(dev, true);
		else
			tsrn10_vlan_hw_filter_enable(dev, false);
	}

	if (mask & ETH_VLAN_STRIP_MASK) {
		if (rxmode->offloads & DEV_RX_OFFLOAD_VLAN_STRIP)
			tsrn10_vlan_hw_strip_enable(dev, true);
		else
			tsrn10_vlan_hw_strip_enable(dev, false);
	}
	if (mask & ETH_VLAN_EXTEND_MASK) {
		if (rxmode->offloads & DEV_RX_OFFLOAD_VLAN_EXTEND)
			tsrn10_double_vlan_enable(dev, true);
		else
			tsrn10_double_vlan_enable(dev, false);
	}

	return 0;
}
#else
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
tsrn10_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	if (mask & ETH_VLAN_FILTER_MASK) {
		if (dev->data->dev_conf.rxmode.hw_vlan_filter)
			tsrn10_vlan_hw_filter_enable(dev, true);
		else
			tsrn10_vlan_hw_filter_enable(dev, false);
	}

	if (mask & ETH_VLAN_STRIP_MASK) {
		if (dev->data->dev_conf.rxmode.hw_vlan_strip)
			tsrn10_vlan_hw_strip_enable(dev, true);
		else
			tsrn10_vlan_hw_strip_enable(dev, false);
	}
	if (mask & ETH_VLAN_EXTEND_MASK) {
		if (dev->data->dev_conf.rxmode.hw_vlan_extend) {
			tsrn10_double_vlan_enable(dev, true);
			tsrn10_qinq_insert_offload_en(dev, true);
		} else {
			tsrn10_double_vlan_enable(dev, false);
			tsrn10_qinq_insert_offload_en(dev, false);
			tsrn10_vlan_insert_offload_en(dev, true);
		}
	}
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}
#endif

static void
tsrn10_vlan_strip_queue_set(struct rte_eth_dev *dev, uint16_t queue,
			    int on)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_rx_queue *rxq;
	uint32_t reg;

	rxq = dev->data->rx_queues[queue];
	if (rxq) {
		reg = tsrn10_eth_rd(hw,
				TSRN10_VLAN_Q_STRIP_CTRL(rxq->attr.index));
		if (on) {
			reg |= 1 << (rxq->attr.index % 32);
			rxq->rx_offload_capa |= DEV_RX_OFFLOAD_VLAN_STRIP;
		} else {
			reg &= ~(1 << (rxq->attr.index % 32));
			rxq->rx_offload_capa &= ~DEV_RX_OFFLOAD_VLAN_STRIP;
		}
		tsrn10_eth_wr(hw,
				TSRN10_VLAN_Q_STRIP_CTRL(rxq->attr.index), reg);
	}
}

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
static int
tsrn10_vlan_tpid_set(struct rte_eth_dev *dev,
		     enum rte_vlan_type vlan_type,
		     uint16_t tpid)
#else
static void
tsrn10_vlan_tpid_set(struct rte_eth_dev *dev,
		     uint16_t tpid)
#endif
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint8_t p_id = port->attr.nr_port;
	uint32_t vlan_ctrl;
	uint32_t hdr_type;
	uint32_t qinq;

	qinq = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_VLAN_TAG);

#if RTE_VERSION_NUM(16, 4, 0, 0) > RTE_VERSION
	enum rte_vlan_type vlan_type;
	vlan_type = ETH_VLAN_TYPE_OUTER;
#endif

	switch (tpid) {
	case RTE_ETHER_TYPE_VLAN:
		hdr_type = TSRN10_MAC_VLAN_INSERT_CVLAN;
		break;
	case RTE_ETHER_TYPE_QINQ:
		hdr_type = TSRN10_MAC_VLAN_INSERT_SVLAN;
		break;
	default:
		PMD_DRV_LOG(ERR, "vlan type tag insert just"
				" support 0x8100/0x88A8\n");
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		return -EINVAL;
#else
		return;
#endif
	}

	switch (vlan_type) {
	case ETH_VLAN_TYPE_INNER:
		if (qinq & TSRN10_MAC_VLAN_EDVLP) {
			vlan_ctrl = tsrn10_mac_rd(hw, p_id,
					TSRN10_MAC_INVLAN_INCL);
			vlan_ctrl &= ~TSRN10_MAC_VLAN_CSVL;
			vlan_ctrl |= hdr_type;
			tsrn10_mac_wr(hw, p_id, TSRN10_MAC_INVLAN_INCL,
					vlan_ctrl);
			port->invlan_type = hdr_type ?
				TSRN10_SVLAN_TYPE : TSRN10_CVLAN_TYPE;
		} else {
			PMD_DRV_LOG(ERR, "Inner Vlan type not support change"
				       " in single-vlan mode\n");
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
			return -EINVAL;
#else
			return;
#endif
		}
		break;
	case ETH_VLAN_TYPE_OUTER:
		if (qinq & TSRN10_MAC_VLAN_EDVLP) {
			vlan_ctrl = tsrn10_mac_rd(hw, p_id,
					TSRN10_MAC_VLAN_INCL);
			vlan_ctrl &= ~TSRN10_MAC_VLAN_CSVL;
			vlan_ctrl |= hdr_type;
			tsrn10_mac_wr(hw, p_id, TSRN10_MAC_VLAN_INCL,
					vlan_ctrl);
			port->outvlan_type = hdr_type ?
				TSRN10_SVLAN_TYPE : TSRN10_CVLAN_TYPE;
		} else {
			PMD_DRV_LOG(ERR, "Outer Vlan type not support change"
				       " in single-vlan mode\n");
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
			return -EINVAL;
#else
			return;
#endif
		}
		break;
	default:
		PMD_DRV_LOG(ERR, "vlan_type don't support");
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		return -EINVAL;
#else
		return;
#endif
	}

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static void tsrn10_vlan_insert_offload_en(struct rte_eth_dev *dev, bool on)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t ctrl;

	ctrl = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_VLAN_INCL);
	if (on) {
		ctrl |= TSRN10_MAC_VLAN_VLTI;
		ctrl |= TSRN10_MAC_VLAN_INSERT_CVLAN;
		ctrl &= ~TSRN10_MAC_VLAN_VLC;
		ctrl |= TSRN10_MAC_VLAN_VLC_ADD;
	} else {
		ctrl = 0;
	}

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_VLAN_INCL, ctrl);
}

static void tsrn10_qinq_insert_offload_en(struct rte_eth_dev *dev, bool on)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t cvlan_ctrl, svlan_ctrl;

	/* En Double Vlan Engine */
	tsrn10_double_vlan_enable(dev, on);
	/* SetUp Inner VLAN Mode*/
	cvlan_ctrl = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_INVLAN_INCL);
	if (on) {
		cvlan_ctrl |= TSRN10_MAC_VLAN_VLTI;
		cvlan_ctrl &= ~TSRN10_MAC_VLAN_CSVL;
		if (port->invlan_type)
			cvlan_ctrl |= TSRN10_MAC_VLAN_INSERT_SVLAN;
		else
			cvlan_ctrl |= TSRN10_MAC_VLAN_INSERT_CVLAN;

		cvlan_ctrl &= ~TSRN10_MAC_VLAN_VLC;
		cvlan_ctrl |= TSRN10_MAC_VLAN_VLC_ADD;
	} else {
		cvlan_ctrl = 0;
	}
	/* Setup Outer Vlan Mode */
	svlan_ctrl = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_VLAN_INCL);
	if (on) {
		svlan_ctrl |= TSRN10_MAC_VLAN_VLTI;
		svlan_ctrl &= ~TSRN10_MAC_VLAN_CSVL;
		if (port->outvlan_type)
			svlan_ctrl |= TSRN10_MAC_VLAN_INSERT_SVLAN;
		else
			svlan_ctrl |= TSRN10_MAC_VLAN_INSERT_CVLAN;
		svlan_ctrl &= ~TSRN10_MAC_VLAN_VLC;
		svlan_ctrl |= TSRN10_MAC_VLAN_VLC_ADD;
	} else {
		svlan_ctrl = 0;
	}

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_INVLAN_INCL, cvlan_ctrl);
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_VLAN_INCL, svlan_ctrl);
}

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
static int tsrn10_link_speed_convert_copper(uint32_t link_speed)
{
	uint32_t speed_bit = 0;
	uint16_t conf_bit;
	uint16_t bit_hi;
	uint16_t i = 0;

	link_speed &= ~ETH_LINK_SPEED_FIXED;
	if (link_speed == ETH_LINK_SPEED_AUTONEG) {
		speed_bit = RNP_LINK_SPEED_1GB_FULL |
			RNP_LINK_SPEED_100_FULL |
			RNP_LINK_SPEED_100_HALF |
			RNP_LINK_SPEED_10_FULL |
			RNP_LINK_SPEED_10_HALF;
		return speed_bit;
	}
	conf_bit = __builtin_popcountl(link_speed);
	for (i = 0; i < conf_bit; i++) {
		bit_hi = ffs(link_speed);
		if (!bit_hi)
			continue;
		bit_hi -= 1;
		switch (BIT(bit_hi)) {
		case ETH_LINK_SPEED_10M_HD:
			speed_bit |= RNP_SPEED_CAP_10M_HALF;
			break;
		case ETH_LINK_SPEED_10M:
			speed_bit |= RNP_SPEED_CAP_10M_FULL;
			break;
		case ETH_LINK_SPEED_100M:
			speed_bit |= RNP_SPEED_CAP_100M_FULL;
			break;
		case ETH_LINK_SPEED_100M_HD:
			speed_bit |= RNP_SPEED_CAP_100M_HALF;
			break;
		case ETH_LINK_SPEED_1G:
			speed_bit |= RNP_SPEED_CAP_1GB_FULL;
			break;
		}
		link_speed &= ~BIT(bit_hi);
	}

	return speed_bit;
}

static int
tsrn10_link_speed_covert_fiber(uint32_t link_speed)
{
	uint32_t speed_bit = 0;

	link_speed &= ~ETH_LINK_SPEED_FIXED;

	switch (link_speed) {
	case ETH_LINK_SPEED_1G:
		speed_bit = RNP_SPEED_CAP_1GB_FULL;
		break;
	case ETH_LINK_SPEED_10G:
		speed_bit = RNP_SPEED_CAP_10GB_FULL;
		break;
	case ETH_LINK_SPEED_AUTONEG:
		speed_bit = RNP_SPEED_CAP_1GB_FULL | RNP_SPEED_CAP_10GB_FULL;
		break;
	default:
		speed_bit = 0;
	}

	return speed_bit;
}

#else
static int
tsrn10_link_speed_convert_copper(struct rte_eth_dev *dev, uint32_t link_speed)
{
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	uint32_t speed_bit = 0;

	if (conf->link_duplex == ETH_LINK_HALF_DUPLEX) {
		switch (link_speed) {
		case ETH_LINK_SPEED_10:
			speed_bit = RNP_SPEED_CAP_10M_HALF;
			break;
		case ETH_LINK_SPEED_100:
			speed_bit = RNP_SPEED_CAP_100M_HALF;
			break;
		default:
			speed_bit = RNP_SPEED_CAP_UNKNOWN;
		}
	}
	if (conf->link_duplex == ETH_LINK_FULL_DUPLEX) {
		switch (link_speed) {
		case ETH_LINK_SPEED_10:
			speed_bit = RNP_SPEED_CAP_10M_FULL;
			break;
		case ETH_LINK_SPEED_100:
			speed_bit = RNP_SPEED_CAP_100M_FULL;
			break;
		case ETH_LINK_SPEED_1000:
			speed_bit = RNP_SPEED_CAP_1GB_FULL;
			break;
		default:
			speed_bit = RNP_SPEED_CAP_UNKNOWN;
		}
	}
	if (conf->link_duplex == ETH_LINK_AUTONEG_DUPLEX &&
		link_speed == ETH_LINK_SPEED_AUTONEG) {
		speed_bit = RNP_LINK_SPEED_1GB_FULL |
			RNP_LINK_SPEED_100_FULL |
			RNP_LINK_SPEED_100_HALF |
			RNP_LINK_SPEED_10_FULL |
			RNP_LINK_SPEED_10_HALF;
	}
	return speed_bit;
}

static int
tsrn10_link_speed_covert_fiber(struct rte_eth_dev *dev, uint32_t link_speeds)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	uint32_t speed_bit = 0;

	if (conf->link_duplex != ETH_LINK_FULL_DUPLEX) {
		PMD_INIT_LOG(ERR, "PortID[%d] Is not Support"
				"configure Half Duple Speed mode",
				port->attr.rte_pid);
		return 0;
	}
	switch (link_speeds) {
	case ETH_LINK_SPEED_1000:
		speed_bit = RNP_SPEED_CAP_1GB_FULL;
		break;
	case ETH_LINK_SPEED_10G:
		speed_bit = RNP_SPEED_CAP_10GB_FULL;
		break;
	case ETH_LINK_SPEED_AUTONEG:
		speed_bit = RNP_SPEED_CAP_10GB_FULL | RNP_SPEED_CAP_1GB_FULL;
		break;
	default:
		speed_bit = 0;
	}

	return speed_bit;
}
#endif

static int
tsrn10_verify_link_speed(struct rte_eth_dev *dev, uint32_t link_speeds)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t speed_cap = 0;

	if (port->attr.phy_meta.media_type == TSRN10_MEDIA_TYPE_COPPER)
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		speed_cap = tsrn10_link_speed_convert_copper(link_speeds);
#else
		speed_cap = tsrn10_link_speed_convert_copper(dev, link_speeds);
#endif
	else if (hw->force_10g_1g_speed_ablity) {
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		speed_cap = tsrn10_link_speed_covert_fiber(link_speeds);
#else
		speed_cap = tsrn10_link_speed_covert_fiber(dev, link_speeds);
#endif
	} else
		if (link_speeds == ETH_LINK_SPEED_AUTONEG)
			return 0;
	if (!speed_cap || !(speed_cap & port->attr.phy_meta.supported_link)) {
		PMD_INIT_LOG(ERR, "PortID[%d] Is not Support "
			       "configure this speed %d",
			       port->attr.rte_pid,
			       link_speeds);
		if (port->attr.phy_meta.media_type == TSRN10_MEDIA_TYPE_COPPER)
			return -EINVAL;
	}

	return 0;
}

static int tsrn10_verify_dev_conf(struct rte_eth_dev *dev)
{
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	int ret = -EINVAL;

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	ret = tsrn10_verify_link_speed(dev, conf->link_speeds);
#else
	ret = tsrn10_verify_link_speed(dev, conf->link_speed);
#endif
	if (ret)
		return ret;

	return 0;
}

static int tsrn10_dev_configure(struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	struct rte_intr_conf *intr_conf = &dev->data->dev_conf.intr_conf;
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_txmode *txmode = &dev->data->dev_conf.txmode;
#endif
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	ret = tsrn10_verify_dev_conf(dev);
	if (ret)
		return ret;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (txmode->offloads & DEV_TX_OFFLOAD_QINQ_INSERT &&
	    txmode->offloads & DEV_TX_OFFLOAD_VLAN_INSERT)
		tsrn10_qinq_insert_offload_en(dev, true);
	else
		tsrn10_qinq_insert_offload_en(dev, false);

	if (txmode->offloads & DEV_TX_OFFLOAD_VLAN_INSERT &&
	    !(txmode->offloads & DEV_TX_OFFLOAD_QINQ_INSERT))
		tsrn10_vlan_insert_offload_en(dev, true);

	if (!(txmode->offloads & DEV_TX_OFFLOAD_VLAN_INSERT))
		tsrn10_vlan_insert_offload_en(dev, false);
#else
	if (rxmode->hw_vlan_extend) {
		tsrn10_qinq_insert_offload_en(dev, true);
	} else {
		tsrn10_qinq_insert_offload_en(dev, false);
		tsrn10_vlan_insert_offload_en(dev, true);
	}
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rxmode->offloads & TSRN10_RX_CHECKSUM_SUPPORT)
#else
	if (rxmode->hw_ip_checksum)
#endif
		tsrn10_set_rx_cksum_offload(dev);
	else
		tsrn10_eth_wr(hw, TSRN10_HW_CHECK_ERR_CTRL,
				TSRN10_HW_CHECK_ERR_MASK);
	if (port->last_rx_num != dev->data->nb_rx_queues)
		port->rxq_num_changed = true;
	else
		port->rxq_num_changed = false;
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	if (system_no_interrupt && !intr_conf->lsc)
		dev->data->dev_flags &= ~RTE_ETH_DEV_INTR_LSC;
#endif

	return 0;
}

int tsrn10_rx_queue_start(struct rte_eth_dev *eth_dev, uint16_t qidx)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(eth_dev);
	struct tsrn10_rx_queue *rxq;
	uint32_t dma_idx;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	rxq = eth_dev->data->rx_queues[qidx];
	if (!rxq) {
		PMD_DRV_LOG(ERR, "RX queue %u is Null or Not setup\n",
				qidx);
		return -ENOMEM;
	}
	if (eth_dev->data->rx_queue_state[qidx] ==
			RTE_ETH_QUEUE_STATE_STOPPED) {
		/* enable ring */
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
		if (tsrn10_alloc_rxq_mbuf(rxq) != 0) {
			PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
					qidx);
			return -1;
		}
		rxq->nb_rx_free = rxq->attr.bd_count - 1;
		if (rxq->next_to_clean)
			if (rxq->next_to_clean >= 32)
				tsrn10_wr_reg(rxq->rx_tailreg,
						rxq->next_to_clean - 32);
			else
				tsrn10_wr_reg(rxq->rx_tailreg,
						rxq->attr.bd_count - 1);
		else
			tsrn10_wr_reg(rxq->rx_tailreg, rxq->attr.bd_count - 1);

		dma_idx = rxq->attr.index;
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 1);
		eth_dev->data->rx_queue_state[qidx] =
			RTE_ETH_QUEUE_STATE_STARTED;
		tsrn10_dma_wr(hw,
			TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(dma_idx), 500000000);
		rxq->rxq_started = true;
	}
#else
	if (qidx < eth_dev->data->nb_rx_queues) {
		rxq = eth_dev->data->rx_queues[qidx];
		if (!rxq)
			return -1;
		/* enable ring */
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
		if (tsrn10_alloc_rxq_mbuf(rxq) != 0) {
			PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
					qidx);
			return -1;
		}
		rxq->rxq_started = true;
		rxq->nb_rx_free = rxq->attr.bd_count - 1;
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

int tsrn10_rx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t qidx)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(eth_dev);
	struct tsrn10_rx_queue *rxq;
	uint16_t i = 0;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	if (qidx < eth_dev->data->nb_rx_queues) {
		rxq = eth_dev->data->rx_queues[qidx];
		if (!rxq) {
			PMD_DRV_LOG(ERR, "RX queue %u is Null or Not setup\n",
					qidx);
			return -EINVAL;
		}
		if (eth_dev->data->rx_queue_state[qidx] ==
				RTE_ETH_QUEUE_STATE_STARTED) {
			for (i = 0; i < TSRN10_MAX_RX_QUEUE_NUM; i++)
				tsrn10_dma_wr(hw,
					TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(i), 16);
			rxq->rxq_started = false;
			tsrn10_rx_queue_release_mbuf(rxq);
			tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
			tsrn10_rx_queue_reset(eth_dev, hw, rxq);
			tsrn10_rx_queue_sw_reset(rxq);
			eth_dev->data->rx_queue_state[qidx] =
				RTE_ETH_QUEUE_STATE_STOPPED;
			tsrn10_dma_wr(hw,
				TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
			for (i = 0; i < TSRN10_MAX_RX_QUEUE_NUM; i++)
				tsrn10_dma_wr(hw,
					TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(i), 500000000);
		}
	} else {
		return -1;
	}
#else
	if (qidx < eth_dev->data->nb_rx_queues) {
		rxq = eth_dev->data->rx_queues[qidx];
		if (!rxq) {
			PMD_DRV_LOG(ERR, "RX queue %u is Null or Not setup",
					qidx);
			return -EINVAL;
		}
		for (i = 0; i < TSRN10_MAX_RX_QUEUE_NUM; i++)
			tsrn10_eth_wr(hw,
				TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(i), 16);
		rxq->rxq_started = false;
		tsrn10_rx_queue_release_mbuf(rxq);
		tsrn10_dma_wr(hw, TSRN10_DMA_RXQ_START(rxq->attr.index), 0);
		tsrn10_rx_queue_reset(eth_dev, hw, rxq);
		tsrn10_rx_queue_sw_reset(rxq);
		tsrn10_dma_wr(hw,
				TSRN10_DMA_RXQ_START(rxq->attr.index), 0);

		for (i = 0; i < TSRN10_MAX_RX_QUEUE_NUM; i++)
			tsrn10_eth_wr(hw,
				TSRN10_DMA_RXQ_DROP_TIMEOUT_TH(i), 500000000);
	} else {
		return -1;
	}
#endif

	return 0;
}

int tsrn10_tx_queue_start(struct rte_eth_dev *eth_dev, uint16_t qidx)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(eth_dev);
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

static void
rnpm_xmit_nop_frame_ring(struct tsrn10_hw *hw __rte_unused,
			 struct tsrn10_tx_queue *txq,
			 uint16_t head)
{
	volatile struct tsrn10_tx_desc *tx_desc;
	uint16_t tx_id;

	tx_id = head;
	tx_desc = &txq->tx_bdr[tx_id];

	/* set length to 0 */
	tx_desc->d.blen = 0;
	tx_desc->d.addr = 0;
	tx_desc->d.cmd = rte_cpu_to_le_16(TSRN10_EOP);
	/* update tail */

	tsrn10_wr_reg(txq->tx_tailreg, 0);
}

void
tsrn10_tx_queue_sw_reset(struct tsrn10_tx_queue *txq)
{
	uint16_t remain = 0;

	txq->nb_tx_free = txq->attr.bd_count - 1;
	txq->tx_free_trigger = txq->tx_free_thresh + 1;
	txq->tx_next_dd = txq->tx_rs_thresh - 1;
	txq->tx_next_rs = txq->tx_rs_thresh - 1;
	txq->nb_tx_used = 0;
	txq->last_desc_cleaned = (uint16_t)(txq->attr.bd_count - 1);
	txq->tx_tail = txq->next_to_use;
	memset(&txq->stats, 0, sizeof(txq->stats));

	if (txq->tx_tail) {
		txq->nb_tx_free = txq->attr.bd_count - txq->next_to_use - 1;

		if (txq->tx_tail > txq->tx_rs_thresh) {
			remain = txq->tx_tail & txq->tx_rs_thresh;
			if (!remain)
				txq->tx_next_rs = txq->tx_tail + txq->tx_rs_thresh - 1;
			else
				txq->tx_next_rs = txq->tx_tail + remain - 1;
		} else {
			txq->tx_next_rs = txq->tx_rs_thresh - 1;
		}
		if (txq->tx_next_rs - txq->tx_tail < txq->tx_rs_thresh - 1)
			txq->tx_next_dd = txq->tx_next_rs + 2 * txq->tx_rs_thresh;
		else
			txq->tx_next_dd = txq->tx_next_rs + txq->tx_rs_thresh;

		remain = txq->tx_tail % txq->tx_free_thresh;

		if (remain > txq->tx_free_thresh / 2)
			txq->nb_tx_free = txq->tx_free_thresh + 1;
		else
			txq->nb_tx_free = txq->tx_free_thresh / 2 + 1;
	}
}

void tsrn10_tx_queue_reset(struct tsrn10_hw *hw,
				  struct tsrn10_tx_queue *txq)
{
	uint16_t try_count = 0;
	uint16_t timeout = 0;
	uint16_t head;

try_tx_reset:
	timeout = 0;
	/* Disable Tx Queue */
	tsrn10_dma_wr(hw,
			TSRN10_DMA_TXQ_START(txq->attr.index), 0);
	do {
		if (tsrn10_dma_rd(hw, TSRN10_DMA_TXQ_READY(txq->attr.index)))
			break;
		rte_delay_us(10);

		timeout++;
	} while (timeout < 100);
	head = tsrn10_dma_rd(hw, TSRN10_DMA_TXQ_HEAD(txq->attr.index));


	if (head != txq->attr.bd_count - 1)
		tsrn10_dma_wr(hw,
				TSRN10_DMA_TXQ_LEN(txq->attr.index), head + 1);
	/* Enable Tx Queue */
	tsrn10_dma_wr(hw,
			TSRN10_DMA_TXQ_START(txq->attr.index), 1);
	/* Reset Hw Head */
	rnpm_xmit_nop_frame_ring(hw, txq, head);
	timeout = 0;
	/* Check Reset Head Success */
	while ((head) && (timeout < 1000)) {
		head = tsrn10_dma_rd(hw, TSRN10_DMA_TXQ_HEAD(txq->attr.index));
		timeout++;
	}

	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_LEN(txq->attr.index),
			txq->attr.bd_count);

	txq->next_to_use = tsrn10_dma_rd(hw, TSRN10_DMA_TXQ_HEAD(txq->attr.index));
	if (txq->next_to_use) {
		try_count++;
		if (try_count > 10)
			return;
		goto try_tx_reset;
	}
	/* Disable Tx Queue */
	tsrn10_dma_wr(hw,
			TSRN10_DMA_TXQ_START(txq->attr.index), 0);
}

int tsrn10_tx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t qidx)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(eth_dev);
	struct tsrn10_tx_queue *txq;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	txq = eth_dev->data->tx_queues[qidx];
	if (!txq) {
		PMD_DRV_LOG(ERR, "TX queue %u is Null or Not setup\n",
				qidx);
		return -EINVAL;
	}
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
		if (!txq) {
			PMD_DRV_LOG(ERR, "TX queue %u is Null or Not setup",
					qidx);
			return -EINVAL;
		}
		txq->txq_started = TSRN10_TX_QUEUE_STOP;
		tsrn10_tx_queue_reset(hw, txq);
		tsrn10_tx_queue_sw_reset(txq);
		tsrn10_tx_queue_release_mbuf(txq);
	} else {
		return -1;
	}
#endif
	port->tx_queues[qidx] = NULL;

	return 0;
}

#define TSRN10_SAMPING_UINT	(1000000UL)
/* 1Mhz */
static int tsrn10_set_tx_rate(struct tsrn10_hw *hw,
			      uint16_t dma_index,
			      uint32_t max_rate)
{
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_RATE_CTRL_TM(dma_index),
			TSRN10_SAMPING_UINT * hw->axi_mhz);
	tsrn10_dma_wr(hw, TSRN10_DMA_TXQ_RATE_CTRL_TH(dma_index),
			(max_rate));

	return 0;
}

static int tsrn10_dev_txq_rate_limit(struct rte_eth_dev *dev,
				     uint16_t queue_idx, uint16_t tx_rate)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint32_t real_rate = 0;
	uint16_t dma_index;

	dma_index = tsrn10_get_dma_ring_index(port, queue_idx);

	if (!tx_rate)
		return tsrn10_set_tx_rate(hw, dma_index, 0);

	/* we need turn it to bytes/s */
	real_rate = (tx_rate * 1024 * 1024) / 8;

	tsrn10_set_tx_rate(hw, dma_index, real_rate);

	return 0;
}

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_tsrn10_map[] = {
#ifndef DISABLE_PF0
	{ RTE_PCI_DEVICE(0x1dab, 0x7001) },
#endif
#ifndef DISABLE_PF1
	{ RTE_PCI_DEVICE(0x1dab, 0x7002) },
#endif
	/* 10G or 40G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N10G) },
	/* 10G or 40G With Crypto Feature */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N10G_C) },
	/* 8x10G, 8x1G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N10L) },
	/* 8x10G, 8x1G With Crypto Features */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N10L_C) },
	/* 4x10G, 4X1G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N10G_X4) },
	/* 4x10G, 4X1G With Crypto Features */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N10G_X4_C) },
	/* 4*1G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N400L_X4) },
	/* 2*1G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, TSRN10_DEV_ID_N400L_X2) },
	{ .vendor_id = 0, /* */ },
};

/* Features supported by this driver */
static const struct eth_dev_ops tsrn10_ops = {
	.dev_configure		= tsrn10_dev_configure,
	.dev_start		= tsrn10_dev_start,
	.dev_stop		= tsrn10_dev_stop,
	.dev_close		= tsrn10_dev_close,
	.dev_set_link_up	= tsrn10_dev_set_link_up,
	.dev_set_link_down	= tsrn10_dev_set_link_down,
	/*.dev_reset		= tsrn10_dev_reset, */

	/* PROMISC */
	.promiscuous_enable	= tsrn10_promiscuous_enable,
	.promiscuous_disable	= tsrn10_promiscuous_disable,
	.allmulticast_enable	= tsrn10_allmulticast_enable,
	.allmulticast_disable	= tsrn10_allmulticast_disable,

	.link_update		= tsrn10_link_update,

	.get_reg		= tsrn10_dev_get_regs,

	/* Stats */
	.stats_get		= tsrn10_stats_get,
	.stats_reset		= tsrn10_dev_xstats_reset,
	.xstats_get		= tsrn10_dev_xstats_get,
#if RTE_VERSION_NUM(16, 7, 0, 0) <= RTE_VERSION
	.xstats_get_names	= tsrn10_dev_xstats_get_names,
#endif
	.xstats_reset		= tsrn10_dev_xstats_reset,

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	.fw_version_get		= tsrn10_fw_version_get,
#endif
	.dev_infos_get		= tsrn10_dev_infos_get,
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	.dev_supported_ptypes_get = tsrn10_dev_supported_ptypes_get,
#endif
	.mtu_set		= tsrn10_mtu_set,
	.vlan_filter_set	= tsrn10_vlan_filter_set,
	.vlan_offload_set	= tsrn10_vlan_offload_set,
	.vlan_strip_queue_set	= tsrn10_vlan_strip_queue_set,
	.vlan_tpid_set		= tsrn10_vlan_tpid_set,

	.rx_queue_setup		= tsrn10_rx_queue_setup,
	.rx_queue_start		= tsrn10_rx_queue_start,
	.rx_queue_stop		= tsrn10_rx_queue_stop,
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	.rx_queue_release	= tsrn10_dev_rxq_release,
#else
	.rx_queue_release	= tsrn10_rx_queue_release,
#endif

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.rxq_info_get		= tsrn10_rx_queue_info_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.rx_burst_mode_get	= tsrn10_rx_burst_mode_get,
#endif
	.tx_queue_setup		= tsrn10_tx_queue_setup,
	.tx_queue_start		= tsrn10_tx_queue_start,
	.tx_queue_stop		= tsrn10_tx_queue_stop,
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	.tx_queue_release	= tsrn10_dev_txq_release,
#else
	.tx_queue_release	= tsrn10_tx_queue_release,
#endif
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.txq_info_get		= tsrn10_tx_queue_info_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.tx_burst_mode_get	= tsrn10_tx_burst_mode_get,
#endif

	.set_queue_rate_limit	= tsrn10_dev_txq_rate_limit,

	.flow_ctrl_get		= tsrn10_flow_ctrl_get,
	.flow_ctrl_set		= tsrn10_flow_ctrl_set,

	.mac_addr_set		= tsrn10_dev_mac_addr_set,
	.mac_addr_add		= tsrn10_dev_add_macaddr,
	.mac_addr_remove	= tsrn10_dev_remove_macaddr,
	.uc_hash_table_set	= tsrn10_dev_uc_hash_table_set,
	.uc_all_hash_table_set	= tsrn10_dev_uc_all_hash_table_set,
	.set_mc_addr_list	= tsrn10_dev_set_mc_addr_list,

#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
	.flow_ops_get		= tsrn10_dev_flow_ops_get,
#else
	.filter_ctrl		= tsrn10_filter_ctrl,
#endif
	.reta_update		= tsrn10_dev_rss_reta_update,
	.reta_query		= tsrn10_dev_rss_reta_query,
	.rss_hash_update	= tsrn10_dev_rss_hash_update,
	.rss_hash_conf_get	= tsrn10_dev_rss_hash_conf_get,
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	.udp_tunnel_port_add	= tsrn10_dev_udp_tunnel_port_add,
	.udp_tunnel_port_del	= tsrn10_dev_udp_tunnel_port_del,
#endif

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	.get_module_info	= tsrn10_get_module_info,
	.get_module_eeprom	= tsrn10_get_module_eeprom,
#endif

#ifdef RTE_LIBRTE_IEEE1588
	.timesync_enable		= tsrn10_timesync_enable,
	.timesync_disable		= tsrn10_timesync_disable,
	.timesync_read_rx_timestamp	= tsrn10_timesync_read_rx_timestamp,
	.timesync_read_tx_timestamp	= tsrn10_timesync_read_tx_timestamp,
	.timesync_adjust_time		= tsrn10_timesync_adjust_time,
	.timesync_read_time		= tsrn10_timesync_read_time,
	.timesync_write_time		= tsrn10_timesync_write_time,
#endif

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	.rx_queue_count		= tsrn10_dev_rx_queue_count,
	.rx_descriptor_done	= tsrn10_dev_rx_descriptor_done,
#endif

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	.rx_descriptor_status	= tsrn10_dev_rx_descriptor_status,
	.tx_descriptor_status	= tsrn10_dev_tx_descriptor_status,
#endif
};

static const struct eth_dev_ops tsrn10_dev_secondary_ops = {
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	.dev_supported_ptypes_get	= tsrn10_dev_supported_ptypes_get,
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	.rx_queue_count		= tsrn10_dev_rx_queue_count,
	.rx_descriptor_done	= tsrn10_dev_rx_descriptor_done,
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	.rx_descriptor_status	= tsrn10_dev_rx_descriptor_status,
	.tx_descriptor_status	= tsrn10_dev_tx_descriptor_status,
#endif
	.reta_query		= tsrn10_dev_rss_reta_query,
	.rss_hash_conf_get	= tsrn10_dev_rss_hash_conf_get,
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.rxq_info_get		= tsrn10_rx_queue_info_get,
	.txq_info_get		= tsrn10_tx_queue_info_get,
#endif
	/* Stats */
	.stats_get              = tsrn10_stats_get,
	.stats_reset            = tsrn10_dev_xstats_reset,
	.xstats_get             = tsrn10_dev_xstats_get,
#if RTE_VERSION_NUM(16, 7, 0, 0) <= RTE_VERSION
	.xstats_get_names       = tsrn10_dev_xstats_get_names,
#endif
	.xstats_reset           = tsrn10_dev_xstats_reset,
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	.fw_version_get         = tsrn10_fw_version_get,
#endif
	.dev_infos_get          = tsrn10_dev_infos_get,
	.link_update            = tsrn10_link_update,
	.get_reg                = tsrn10_dev_get_regs,
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.rx_burst_mode_get      = tsrn10_rx_burst_mode_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.tx_burst_mode_get      = tsrn10_tx_burst_mode_get,
#endif
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	/* PROMISC */
	.promiscuous_enable	= tsrn10_promiscuous_enable,
	.promiscuous_disable	= tsrn10_promiscuous_disable,
	.allmulticast_enable	= tsrn10_allmulticast_enable,
	.allmulticast_disable	= tsrn10_allmulticast_disable,
#endif

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	.get_module_info	= tsrn10_get_module_info,
	.get_module_eeprom	= tsrn10_get_module_eeprom,
#endif
};

#ifdef USE
static inline void tsrn10_enable_intr(struct rte_eth_dev *eth_dev __rte_unused)
{
	struct tsrn10_hw *hw __rte_unused = TSRN10_DEV_TO_HW(eth_dev);

	PMD_INIT_FUNC_TRACE();
	/* hw_atl_itr_irq_msk_setlsw_set(hw, 0xffffffff); */
}

static void __rte_unused tsrn10_disable_intr(struct tsrn10_hw *hw __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	/* hw_atl_itr_irq_msk_clearlsw_set(hw, 0xffffffff); */
}
#endif

static void tsrn10_mac_rx_enable(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t mac_cfg;

	/* To Protect Conflict Hw Resource */
	rte_spinlock_lock(&port->rx_mac_lock);
	mac_cfg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_RX_CFG);
	mac_cfg |= TSRN10_MAC_RE;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (!(dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_KEEP_CRC))
#else
	if (!(dev->data->dev_conf.rxmode.hw_strip_crc))
#endif
		mac_cfg |= TSRN10_MAC_ACS | TSRN10_MAC_CST;
	if (port->jumbo_en) {
		mac_cfg |= TSRN10_MAC_JE;
		mac_cfg |= TSRN10_MAC_GPSLCE | TSRN10_MAC_WD;
	} else {
		mac_cfg &= ~TSRN10_MAC_JE;
		mac_cfg &= ~TSRN10_MAC_WD;
	}
	mac_cfg &= ~TSRN10_MAC_GPSL_MASK;
	mac_cfg |= (TSRN10_MAC_MAX_GPSL << TSRN10_MAC_CPSL_SHIFT);
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_RX_CFG, mac_cfg);
	rte_spinlock_unlock(&port->rx_mac_lock);
}

static void tsrn10_mac_rx_disable(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	struct tsrn10_rx_queue *rxq;
	uint16_t i = 0;
	uint32_t mac_cfg;
	uint16_t timeout;

	/* To Protect Conflict Hw Resource */
	rte_spinlock_lock(&port->rx_mac_lock);
	mac_cfg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_RX_CFG);
	mac_cfg &= ~TSRN10_MAC_RE;

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_RX_CFG, mac_cfg);
	rte_spinlock_unlock(&port->rx_mac_lock);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (rxq)
			tsrn10_rxq_prepare_setup(hw, rxq);
	}
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = (struct tsrn10_rx_queue *)dev->data->rx_queues[i];
		timeout = 0;
		if (!rxq)
			continue;
		do {
			if (tsrn10_dma_rd(hw,
				TSRN10_DMA_RXQ_READY(rxq->attr.index)))
				break;
			rte_delay_us(10);

			timeout++;
		} while (timeout < 2000);
	}

	if (dev->data->nb_rx_queues)
		for (i = 0; i < dev->data->nb_rx_queues; i++)
			tsrn10_rx_queue_stop(dev, i);
}

static void tsrn10_mac_tx_enable(struct rte_eth_dev *dev)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t mac_cfg;

	mac_cfg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TX_CFG);
	mac_cfg |= TSRN10_MAC_TE;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_TX_CFG, mac_cfg);
}

static void tsrn10_mac_tx_disable(struct rte_eth_dev *dev)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t ctrl;
	uint16_t i = 0;

	if (dev->data->nb_tx_queues)
		for (i = 0; i < dev->data->nb_tx_queues; i++)
			tsrn10_tx_queue_stop(dev, i);
	/* Must Wait For Tx Side Has Send Finish
	 * Before Disable Tx Side
	 */
	ctrl = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TX_CFG);
	ctrl &= ~TSRN10_MAC_TE;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_TX_CFG, ctrl);
}

static int tsrn10_mac_init(struct rte_eth_dev *dev)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t mac_cfg;

	tsrn10_mac_tx_enable(dev);
	tsrn10_mac_rx_enable(dev);

	mac_cfg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_LPI_CTRL);
	mac_cfg |= TSRN10_MAC_PLSDIS | TSRN10_MAC_PLS;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_LPI_CTRL, mac_cfg);

	return 0;
}

#ifdef MBX_API_PF
static void
tsrn10_setup_mbx_interrupt(struct rte_intr_handle *intr_handle __rte_unused)
{
}

static void tsrn10vf_hw_reset(struct tsrn10_hw *hw __rte_unused,
			      uint16_t vf_num __rte_unused)
{
	/* macvlan
	 * max_pkt_support
	 * queue info get
	 * set mac
	 * get mac
	 * reset
	 * VF reset we can do
	 * clear vlan strip according the ring-id(vf)
	 * ring rate limit and ring prioity
	 * vm vlan pool filter clear
	 * vlan mac veb clear from the dma-reg
	 * disable promisc
	 */
}

static void
tsrn10vf_set_mac(struct tsrn10_hw *hw __rte_unused,
		 uint16_t vf_num __rte_unused,
		 uint32_t *msg __rte_unused)
{
	struct tsrn10_eth_adapter *adapter = hw->back;
	struct tsrn10_vfinfo *vfinfo = &adapter->vfinfo[vf_num];
	int i;

	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++)
		vfinfo->vf_mac_addr[i] = msg[i];

	/* TODO Add According the ring base update mac address */
}

static void
tsrn10vf_get_queue_info(struct tsrn10_hw *hw __rte_unused,
			uint16_t vf_num __rte_unused,
			uint32_t *msg __rte_unused)
{
#if 0
	struct tsrn10_eth_adapter *adapter = hw->back;
	struct tsrn10_vfinfo *vfinfo = &adapter->vfinfo[vf_num];

	msg[TSRN10_VF_GET_RXQ_BASE] = vfinfo->rx_dma_quene_base;
	msg[TSRN10_VF_GET_TXQ_BASE] = vfinfo->tx_dma_quene_base;
	msg[TSRN10_VF_GET_VLAN_ID] = vfinfo->vf_vlan_id;
#endif
}

static inline void
tsrn10vf_get_mac(struct tsrn10_hw *hw __rte_unused,
		 uint16_t vf_num __rte_unused,
		 uint32_t *msg __rte_unused)
{
#if 0
	struct tsrn10_eth_adapter *adapter = hw->back;
	struct tsrn10_vfinfo *vfinfo = &adapter->vfinfo[vf_num];
	int i;

	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++)
		msg[i] = vfinfo->vf_mac_addr[i];
#endif
}

static void tsrn10_pf_mbx_api_process(struct tsrn10_hw *hw __rte_unused,
				      uint16_t vf_num __rte_unused,
				      uint16_t api_id __rte_unused)
{
	TSRN10_PMD_DEBUG("%s %d\n", __func__, __LINE__);
#if 0
	uint32_t msg[TSRN10_VFMBX_SIZE] = {0};
	uint16_t size = 0;
	/* send the ack and event done to VF */
	memset(msg, 0, sizeof(msg));

	switch (api_id) {
	case TSRN10_VF_RESET:
		tsrn10vf_hw_reset(hw, vf_num);
		break;
	case TSRN10_VF_SET_MAC_ADDR:
		tsrn10vf_set_mac(hw, vf_num, &msg[TSRN10_MBX_DATA_BASE]);
		break;
	case TSRN10_VF_GET_MAC_ADDR:
		tsrn10vf_get_mac(hw, vf_num, &msg[TSRN10_MBX_PF_WB_OFFSET]);
		size += RTE_ETHER_ADDR_LEN;
		break;
	case TSRN10_VF_GET_QUEUE:
		tsrn10vf_get_queue_info(hw, vf_num,
				&msg[TSRN10_MBX_PF_WB_OFFSET]);
		size += TSRN10_QUEUE_INFO_SIZE;
		break;
	case TSRN10_VF_GET_FW_VER:
		msg[TSRN10_MBX_PF_WB_OFFSET] = hw->mac.ops.get_fw_ver(hw);
		size += 1;
		break;
	default:
		break;
	}

	if (size) {
		size += TSRN10_MBX_CTRL_MSG_SIZE;
		hw->mbx.ops.write_posted(hw, msg, size, vf_num);
	}
#endif
}
#endif

#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void
tsrn10_dev_interrupt_handler(struct rte_intr_handle *handle __rte_unused,
			     void *parm)
#else
static void tsrn10_dev_interrupt_handler(void *parm)
#endif
{
	/* 1.Read MBX SHM Which vf request and API Event
	 * 2.disable ths VF-PF interrupt
	 * 3.Do the API Event
	 * 4.enable the VF-PF interrupt
	 */
	struct rte_eth_dev *dev = (struct rte_eth_dev *)parm;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_hw *hw __rte_unused = TSRN10_DEV_TO_HW(dev);
	uint32_t msg[TSRN10_VFMBX_SIZE] __rte_unused;
	uint16_t vf_num __rte_unused;

	rte_intr_disable(intr_handle);
	rnp_fw_msg_handler(adapter);
#ifdef MBX_API_PF
	for (i = 0; i < pci_dev->max_vfs; i++) {
		ret = hw->mbx.ops.read_posted(hw, msg, TSRN10_VFMBX_SIZE, i);
		if (ret)
			continue;
		vf_num = msg[TSRN10_MBX_API_VFID] & TSRN10_VFMBX_VFID_MASK;
		api_id = (msg[TSRN10_MBX_API_VFID] >> TSRN10_VFMBX_API_OFFSET) &
				TSRN10_VFMBX_API_MASK;
		irq_type = msg[TSRN10_MBX_IRQ_TYPE];
		PMD_DRV_LOG(INFO, "PF[%d] msg api_vf 0x%.2x api_id\n",
				hw->function, msg[TSRN10_MBX_API_VFID], api_id);
		if (irq_type == TSRN10_IRQ_MBX_VF && api_id)
			tsrn10_pf_mbx_api_process(hw, vf_num, api_id);
	}
#endif
	rte_intr_enable(intr_handle);
}

#ifdef TODO_CHECK_PFC
static void
tsrn10_set_fifo_mode(struct tsrn10_eth_adapter *adapter)
{
	struct tsrn10_hw *hw = &adapter->hw;
	uint32_t reg = 0;

	switch (adapter->mode) {
	case TSRN10_SINGLE_10G:
	case TSRN10_SINGLE_40G:
		reg = TSRN10_ETH_ONE_FIFO;
		break;
	case TSRN10_DUAL_10G:
		reg = TSRN10_ETH_TWO_FIFO;
		break;
	case TSRN10_QUAD_10G:
		reg = TSRN10_ETH_FOUR_FIFO;
		break;
	default:
		PMD_DRV_LOG(ERR, "Nic Mode Is Not Correct");
		break;
	}
	reg |= TSRN10_FIFO_CFG_EN << 16;
	tsrn10_eth_wr(hw, TSRN10_ETH_FIFO_CTRL, reg);
}
#endif

static void tsrn10_get_nic_attr(struct tsrn10_eth_adapter *adapter)
{
#ifdef USING_MBX
	struct tsrn10_hw *hw = &adapter->hw;
	int lane_mask = 0, err, mode = 0;

	rnp_mbx_link_event_enable(adapter->eth_dev, false);

	err = rnp_mbx_get_capability(adapter->eth_dev, &lane_mask, &mode);
	if (err < 0 || !lane_mask) {
		PMD_DRV_LOG(ERR, "%s: mbx_get_capability error! errcode=%d\n",
				__func__, hw->speed);
		return;
	}

	adapter->num_ports = __builtin_popcount(lane_mask);
	adapter->lane_mask = lane_mask;
	adapter->mode = mode;

	PMD_DRV_LOG(INFO, "max link speed:%d lane_mask:0x%x nic-mode:0x%x\n",
			(int)adapter->max_link_speed,
			(int)adapter->num_ports, adapter->mode);

	adapter->max_link_speed = hw->speed;

	if (adapter->num_ports && adapter->num_ports == 1)
		adapter->s_mode = TSRN10_SHARE_CORPORATE;
	else
		adapter->s_mode = TSRN10_SHARE_INDEPEND;
#else
	/* Must Get Adapter Mode */
	switch (adapter->mode) {
	case TSRN10_SINGLE_40G:
		adapter->num_ports = 1;
		adapter->max_link_speed = ETH_SPEED_NUM_40G;
		break;
	case TSRN10_SINGLE_10G:
		adapter->num_ports = 1;
		adapter->max_link_speed = ETH_SPEED_NUM_10G;
		break;
	case TSRN10_DUAL_10G:
		adapter->num_ports = 2;
		adapter->max_link_speed = ETH_SPEED_NUM_10G;
		adapter->s_mode = TSRN10_SHARE_INDEPEND;
		break;
	case TSRN10_QUAD_10G:
		adapter->num_ports = 4;
		adapter->max_link_speed = ETH_SPEED_NUM_10G;
		adapter->s_mode = TSRN10_SHARE_INDEPEND;
		break;
	default:
		PMD_DRV_LOG(ERR, "Nic Mode Is Not Correct");
	}
#endif
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	struct tsrn10_share_ops *share_priv;

	share_priv = adapter->share_priv;

	if (adapter->s_mode == TSRN10_SHARE_INDEPEND)
		share_priv->mac_api = tsrn10_mac_indep_ops;
	else
		share_priv->mac_api = tsrn10_mac_ops;

	share_priv->mbx_api = tsrn10_mbx_pf_ops;
	if (hw->is_sgmii)
		share_priv->phy_api = tsrn10_phy_ops;
	if (hw->force_10g_1g_speed_ablity)
		share_priv->phy_api = tsrn10_fiber_ops;
#else
	if (adapter->s_mode == TSRN10_SHARE_INDEPEND)
		hw->mac.ops = tsrn10_mac_indep_ops;
	else
		hw->mac.ops = tsrn10_mac_ops;
	hw->pcs.ops = pcs_ops_generic;
	hw->pma.ops = pma_ops_generic;
	if (hw->is_sgmii)
		hw->phy.ops = tsrn10_phy_ops;
	if (hw->force_10g_1g_speed_ablity)
		hw->phy.ops = tsrn10_fiber_ops;
#endif
}

static int32_t tsrn10_init_hw_pf(struct tsrn10_hw *hw)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_HW_TO_ADAPTER(hw);
	uint32_t version;
	uint32_t reg;

	PMD_INIT_FUNC_TRACE();
	version = tsrn10_rd_reg(hw->dev_version);
	PMD_DRV_LOG(INFO, "NIC HW Version:0x%.2x\n", version);

	/* Disable Rx/Tx Dma */
	tsrn10_wr_reg(hw->dma_axi_en, false);
	/* Check Dma Chanle Status */
	while (tsrn10_rd_reg(hw->dma_axi_st) == 0)
		;

	tsrn10_get_nic_attr(adapter);
	/* Reset Nic All Hardware */
	if (tsrn10_reset_hw(adapter->eth_dev, hw))
		return -EPERM;

	/* Rx Proto Offload No-BYPASS */
	tsrn10_eth_wr(hw, TSRN10_ETH_ENGINE_BYPASS, false);
	/* Enable Flow Filter Engine */
	tsrn10_eth_wr(hw, TSRN10_HOST_FILTER_EN, true);
	/* Enable VXLAN Parse */
	tsrn10_eth_wr(hw, TSRN10_EN_TUNNEL_VXLAN_PARSE, true);
	/* Enabled REDIR ACTION */
	tsrn10_eth_wr(hw, TSRN10_REDIR_CTRL, true);

	/* Setup Scatter DMA Mem Size */
	reg = ((RTE_ETHER_MAX_LEN / 16) << TSRN10_DMA_SCATTER_MEM_SHIFT);
	tsrn10_wr_reg(hw->nic_reg + TSRN10_DMA_CTRL, reg);
#ifdef TODO_CHECK_PFC
	tsrn10_set_fifo_mode(adapter);
#endif
#ifdef PHYTIUM_SUPPORT
#define TSRN10_DMA_PADDING	(1 << 8)
	reg = tsrn10_rd_reg(hw->nic_reg + TSRN10_DMA_CTRL);
	reg |= TSRN10_DMA_PADDING;
	tsrn10_wr_reg(hw->nic_reg + TSRN10_DMA_CTRL, reg);
#endif
	/* Enable Rx/Tx Dma */
	tsrn10_wr_reg(hw->dma_axi_en, 0b1111);

	tsrn10_wr_reg(hw->comm_reg_base + TSRN10_TX_QINQ_WORKAROUND, 1);

	return 0;
}

static int32_t
tsrn10_fc_enable(struct tsrn10_eth_port *port,
		 struct tsrn10_fc_info *fc,
		 uint8_t p_id, bool en)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(port->dev);
	uint32_t reg;
	uint8_t i;

	if (!en) {
		/* Setup Rx Flow Ctrl */
		reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_RX_FC);
		reg &= ~(TSRN10_MAC_RX_FC_PFCE |
			 TSRN10_MAC_RX_FC_UP |
			 TSRN10_MAC_RX_FC_RFE);
		/* Setup Tx Flow Ctrl Peer Tc */
		for (i = 0; i < fc->max_tc; i++) {
			reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_Q0_TX_FC(i));
			reg &= ~(TSRN10_MAC_FC_PT | TSRN10_MAC_FC_PLT |
				 TSRN10_MAC_FC_TEE);
			tsrn10_mac_wr(hw, p_id, TSRN10_MAC_Q0_TX_FC(i), reg);
		}
	} else {
		/* Setup Rx Flow Ctrl */
		reg = TSRN10_MAC_RX_FC_RFE;
		tsrn10_mac_wr(hw, p_id, TSRN10_MAC_RX_FC, reg);
		for (i = 0; i < fc->max_tc; i++) {
			/* Setup Tx Flow Ctrl Peer Tc */
			reg = TSRN10_MAC_FC_TEE |
			      fc->pause_time << TSRN10_MAC_FC_PT_OFFSET;
			tsrn10_mac_wr(hw, p_id, TSRN10_MAC_Q0_TX_FC(i), reg);
		}
		/* Setup Xon Rx Trigger Threshold */
		reg = fc->hi_water[0];
		tsrn10_eth_wr(hw, TSRN10_RX_FC_HI_WATER(p_id), reg);
		reg = fc->lo_water[0];
		tsrn10_eth_wr(hw, TSRN10_RX_FC_LO_WATER(p_id), reg);
	}
	if (fc->ctrl_fwd_en) {
		/* Forward The Mac Don't Unrecognized Pause Frame */
		reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
		reg |= TSRN10_MAC_PCF_NO_PAUSE << TSRN10_MAC_PCF_OFFSET;
		tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, reg);
	} else {
		/* Filter All Type Control Frame */
		reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
		reg &= ~TSRN10_MAC_PCF;
		tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, reg);
	}

	return 0;
}

static int32_t tsrn10_get_fw_version_pf(struct tsrn10_hw *hw)
{
	return TSRN10_GET_FW_VER(hw);
}

static int32_t tsrn10_get_mac_addr_pf(struct tsrn10_eth_port *port,
				      uint8_t lane,
				      uint8_t *macaddr)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(port->dev);

	return rnp_fw_get_macaddr(port->dev, hw->pf_vf_num, macaddr, lane);
}

static bool
tsrn10_sriov_en(struct tsrn10_eth_port *port)
{
	struct tsrn10_eth_adapter *adapt = TSRN10_PORT_TO_ADAPTER(port);

	return adapt->sriov;
}

static void
tsrn10_mac_res_take_in(struct tsrn10_eth_port *port,
		       uint8_t index)
{
	if (!port->mac_use_tb[index]) {
		port->mac_use_tb[index] = true;
		port->use_num_mac++;
	}
}

static void
tsrn10_mac_res_remove(struct tsrn10_eth_port *port,
		      uint8_t index)
{
	if (port->mac_use_tb[index]) {
		port->mac_use_tb[index] = false;
		port->use_num_mac--;
	}
}

static int32_t tsrn10_set_mac_addr_pf(struct tsrn10_eth_port *port,
				      uint8_t *mac, uint8_t vm_pool,
				      uint8_t index)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	struct tsrn10_port_attr *attr = &port->attr;
	uint8_t hw_idx;
	uint32_t value;

	if (port->use_num_mac > port->attr.max_mac_addrs ||
			index > port->attr.max_mac_addrs)
		return -ENOMEM;

	if (vm_pool != UINT8_MAX)
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + vm_pool + index;
	else
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + index;

	tsrn10_mac_res_take_in(port, hw_idx);

	value = (mac[0] << 8) | mac[1];
	value |= TSRN10_MAC_FILTER_EN;
	TSRN10_MACADDR_UPDATE_HI(hw, hw_idx, value);

	value = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
	TSRN10_MACADDR_UPDATE_LO(hw, hw_idx, value);

	return 0;
}

static void
tsrn10_remove_mac_from_hw(struct tsrn10_eth_port *port,
			  uint8_t vm_pool,
			  uint8_t index)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	struct tsrn10_port_attr *attr = &port->attr;
	uint16_t hw_idx;

	if (vm_pool != UINT8_MAX)
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + vm_pool + index;
	else
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + index;

	tsrn10_mac_res_remove(port, hw_idx);

	tsrn10_eth_wr(hw, TSRN10_RAL_BASE_ADDR(hw_idx), 0);
	tsrn10_eth_wr(hw, TSRN10_RAH_BASE_ADDR(hw_idx), 0);
}

static int32_t
tsrn10_clear_mac_addr_pf(struct tsrn10_eth_port *port,
			 uint8_t vm_pool,
			 uint8_t index)
{
	tsrn10_remove_mac_from_hw(port, vm_pool, index);

	return 0;
}

static int32_t
tsrn10_set_indep_mac_addr(struct tsrn10_eth_port *port,
			  uint8_t *addr, uint8_t vm_pool,
			  uint8_t index)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	struct tsrn10_port_attr *attr = &port->attr;
	uint32_t addr_hi = 0, addr_lo = 0;
	uint8_t *mac;

	if (port->use_num_mac > port->attr.max_mac_addrs ||
			index > port->attr.max_mac_addrs)
		return -ENOMEM;
	if (tsrn10_sriov_en(port) && vm_pool != UINT8_MAX) {
		PMD_DRV_LOG(ERR, "for resource indep mode we can't support sriov ");
		return -EINVAL;
	}

	tsrn10_mac_res_take_in(port, index);

	mac = (uint8_t *)&addr_lo;
	mac[0] = addr[0];
	mac[1] = addr[1];
	mac[2] = addr[2];
	mac[3] = addr[3];
	mac = (uint8_t *)&addr_hi;
	mac[0] = addr[4];
	mac[1] = addr[5];

	addr_hi |= TSRN10_MAC_AE;

	tsrn10_mac_wr(hw, attr->nr_port, TSRN10_MAC_ADDR_HI(index), addr_hi);
	tsrn10_mac_wr(hw, attr->nr_port, TSRN10_MAC_ADDR_LO(index), addr_lo);

	return 0;
}

static int32_t
tsrn10_clear_indep_mac_addr(struct tsrn10_eth_port *port,
			    uint8_t vm_pool, uint8_t index)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	struct tsrn10_port_attr *attr = &port->attr;

	if (tsrn10_sriov_en(port) && vm_pool != UINT8_MAX) {
		PMD_DRV_LOG(ERR, "for resource indep mode we can't support sriov ");
		return -EINVAL;
	}
	tsrn10_mac_res_remove(port, index);

	if (!index)
		tsrn10_mac_wr(hw, attr->nr_port, TSRN10_MAC_ADDR_DEF_HI, 0);
	else
		tsrn10_mac_wr(hw, attr->nr_port, TSRN10_MAC_ADDR_HI(index), 0);

	tsrn10_mac_wr(hw, attr->nr_port, TSRN10_MAC_ADDR_LO(index), 0);

	return 0;
}

static int32_t
tsrn10_set_default_mac_pf(struct tsrn10_eth_port *port,
			  uint8_t *mac)
{
	struct tsrn10_eth_adapter *adap = TSRN10_PORT_TO_ADAPTER(port);
	uint16_t max_vfs;

	if (port->s_mode == TSRN10_SHARE_INDEPEND)
		return tsrn10_set_indep_mac_addr(port, (uint8_t *)mac,
				UINT8_MAX, 0);

	max_vfs = adap->max_vfs;

	return tsrn10_set_mac_addr_pf(port, mac, max_vfs, 0);
}

static uint32_t
tsrn10_samp_mac_vector(struct tsrn10_eth_port *port, uint8_t *mc_addr)
{
	uint32_t vector = 0;

	switch (port->hash_filter_type) {
	case 0:   /* Use bits [11:0] of the address */
		vector = ((mc_addr[4] << 8) | (((u16)mc_addr[5])));
		break;
	case 1:   /* Use bits [12:1] of the address */
		vector = ((mc_addr[4] << 7) | (((u16)mc_addr[5]) >> 1));
		break;
	case 2:   /* Use bits [13:2] of the address */
		vector = ((mc_addr[4] << 6) | (((u16)mc_addr[5]) >> 2));
		break;
	case 3:   /* Use bits [14:3] of the address */
		vector = ((mc_addr[4] << 4) | (((u16)mc_addr[5]) >> 4));
		break;
	default:  /* Invalid mc_filter_type */
		PMD_DRV_LOG(ERR, "Mac Hash filter type param set incorrectly\n");
		break;
	}

	vector &= TSRN10_MAC_HASH_MASK;

	return vector;
}

static int32_t
tsrn10_update_uc_hash_table(struct tsrn10_eth_port *port, uint8_t *addr,
			    uint8_t add)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint32_t hash_bit;
	uint32_t uta_row;
	uint32_t uta_col;
	uint32_t vector;
	uint32_t reg;
#define TSRN10_UTA_BIT_SHIFT   (5)
#define TSRN10_UTA_BIT_MASK    ((1 << TSRN10_UTA_BIT_SHIFT) - 1)

	vector = tsrn10_samp_mac_vector(port, addr);
	/* UC Hash Table Array  of 128 32-bit Register.
	 * It Can Turn To 4096 Bit So For Unicast Hash Filter Algorithm
	 * High 7 Bit Is Hash Table Row Low 5 Bit Is Column
	 */
	uta_row = (vector >> TSRN10_UTA_BIT_SHIFT) & TSRN10_MAC_HASH_MASK;
	uta_col = vector & (TSRN10_UTA_BIT_MASK);
	hash_bit = port->uc_hash_table[uta_row] >> uta_col;

	if (hash_bit && add)
		return 0;

	reg = tsrn10_eth_rd(hw, TSRN10_UC_HASH_TB(uta_row));
	if (add) {
		reg |= (1 << uta_col);
		port->uc_hash_mac_addr++;
		port->uc_hash_table[uta_row] |= (1 << uta_col);
	} else {
		reg &= ~(1 << uta_col);
		port->uc_hash_mac_addr--;
		port->uc_hash_table[uta_row] &= ~(1 << uta_col);
	}
	tsrn10_eth_wr(hw, TSRN10_UC_HASH_TB(uta_row), reg);

	return 0;
}

static int32_t
tsrn10_en_uc_hash_tb_pf(struct tsrn10_eth_port *port, bool en)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint32_t idx;
	uint32_t reg;

	for (idx = 0; idx < port->attr.uc_hash_tb_size; idx++) {
		if (en)
			port->uc_hash_table[idx] = ~0;
		else
			port->uc_hash_table[idx] = 0;

		tsrn10_eth_wr(hw, TSRN10_UC_HASH_TB(idx), 0);
	}

	reg = tsrn10_eth_rd(hw, TSRN10_MAC_MCSTCTRL);

	if (en)
		reg |= TSRN10_MAC_UNICASE_TBL_EN;
	else
		reg &= ~TSRN10_MAC_UNICASE_TBL_EN;

	tsrn10_eth_wr(hw, TSRN10_MAC_MCSTCTRL, reg);

	return 0;
}

static int32_t
tsrn10_update_mc_hash_table(struct tsrn10_eth_port *port,
			    struct rte_ether_addr *mc_list, uint8_t nb_mc)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint32_t hash_bit;
	uint32_t mta_row;
	uint32_t mta_col;
	uint32_t vector;
	uint32_t value;
	uint32_t reg;
	uint16_t idx;

	memset(&port->mc_hash_table, 0, sizeof(port->mc_hash_table));

	for (idx = 0; idx < port->attr.mc_hash_tb_size; idx++)
		tsrn10_eth_wr(hw, TSRN10_MC_HASH_TB(idx), 0);

	port->mc_hash_mac_addr = 0;
	for (idx = 0; idx < nb_mc; idx++) {
		vector = tsrn10_samp_mac_vector(port, (uint8_t *)mc_list);
		/* MC Hash Table Array  of 128 32-bit Register.
		 * It Can Turn To 4096 Bit So For Unicast Hash Filter Algorithm
		 * High 7 Bit Is Hash Table Row Low 5 Bit Is Column
		 */
		mta_row = (vector >> port->hash_table_shift) & 0x7f;
		mta_col = vector & (TSRN10_UTA_BIT_MASK);
		/* check weather the Hash Bit has Been Set */
		hash_bit = 1 << mta_col;
		value = port->mc_hash_table[mta_row];
		if (!(value & hash_bit)) {
			reg = tsrn10_eth_rd(hw, TSRN10_MC_HASH_TB(mta_row));
			reg |= hash_bit;
			tsrn10_eth_wr(hw, TSRN10_MC_HASH_TB(mta_row), reg);
			port->mc_hash_mac_addr++;
			port->mc_hash_table[mta_row] |= hash_bit;
		}
		mc_list++;
	}

	return 0;
}

static int32_t
tsrn10_update_mpfm_pf(struct tsrn10_eth_port *port,
		      enum tsrn10_mpf_modes mode, bool en)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint8_t p_id = port->attr.nr_port;
	uint32_t mac_filter_ctrl;
	uint32_t filter_ctrl;
	uint32_t bypass_ctrl;
	uint32_t bypass = 0;

	bypass_ctrl = tsrn10_eth_rd(hw, TSRN10_MAC_FCTRL);
	bypass_ctrl |= TSRN10_MAC_FCTRL_BAM;

	filter_ctrl = TSRN10_MAC_MULTICASE_TBL_EN | TSRN10_MAC_UNICASE_TBL_EN;
	tsrn10_eth_wr(hw, TSRN10_MAC_MCSTCTRL, filter_ctrl);

	switch (mode) {
	case TSRN10_MPF_MODE_NONE:
		bypass = 0;
		break;
	case TSRN10_MPF_MODE_MULTI:
		bypass = TSRN10_MAC_FCTRL_MPE;
		break;
	case TSRN10_MPF_MODE_ALLMULTI:
		bypass = TSRN10_MAC_FCTRL_MPE;
		break;
	case TSRN10_MPF_MODE_PROMISC:
		bypass = TSRN10_MAC_FCTRL_UPE | TSRN10_MAC_FCTRL_MPE;
		break;
	default:
		PMD_DRV_LOG(ERR, "update_mpfm argument is invalid");
		return -EINVAL;
	}
	if (en)
		bypass_ctrl |= bypass;
	else
		bypass_ctrl &= ~bypass;

	tsrn10_eth_wr(hw, TSRN10_MAC_FCTRL, bypass_ctrl);
	mac_filter_ctrl = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
	mac_filter_ctrl |= TSRN10_MAC_PM | TSRN10_MAC_PROMISC_EN;
	mac_filter_ctrl &= ~TSRN10_MAC_RA;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, mac_filter_ctrl);

	return 0;
}

static int32_t
tsrn10_add_vlan_filter_pf(struct tsrn10_eth_port *port,
		       uint16_t vlan, bool add)
{
	struct tsrn10_vlan_filter *vfta_tb = &port->vfta;
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint32_t vid_idx;
	uint32_t vid_bit;
	uint32_t vfta;

	vid_idx = (uint32_t)((vlan >> 5) & 0x7F);
	vid_bit = (uint32_t)(1 << (vlan & 0x1F));
	vfta = tsrn10_eth_rd(hw, TSRN10_VFTA_HASH_TABLE(vid_idx));
	if (add)
		vfta |= vid_bit;
	else
		vfta &= ~vid_bit;
	tsrn10_eth_wr(hw, TSRN10_VFTA_HASH_TABLE(vid_idx), vfta);

	/* update local VFTA copy */
	vfta_tb->vfta_entries[vid_idx] = vfta;

	return 0;
}

static int32_t
tsrn10_en_vlan_filter_pf(struct tsrn10_eth_port *port, bool en)
{
	struct tsrn10_vlan_filter *vfta = &port->vfta;
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint32_t ctrl;
	uint8_t i;
	/* En/Dis All Vlan Filter Configuration */

	ctrl = tsrn10_eth_rd(hw, TSRN10_VLAN_FILTER_CTRL);
	if (en)
		ctrl |= TSRN10_VLAN_FILTER_EN;
	else
		ctrl &= ~TSRN10_VLAN_FILTER_EN;
	tsrn10_eth_wr(hw, TSRN10_VLAN_FILTER_CTRL, ctrl);
	/* write whatever is in local vfta copy */
	for (i = 0; i < TSRN10_MAX_VFTA_SIZE; i++)
		tsrn10_eth_wr(hw, TSRN10_VFTA_HASH_TABLE(i),
				vfta->vfta_entries[i]);

	return 0;
}

static uint32_t
tsrn10_calc_crc32(uint32_t seed, uint8_t *mac, uint32_t len)
{
#define TSRN10_CRC32_POLY_LE 0xedb88320
	uint32_t crc = seed;
	uint32_t i;

	while (len--) {
		crc ^= *mac++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ?
					TSRN10_CRC32_POLY_LE : 0);
	}

	return crc;
}

static int32_t
tsrn10_update_indep_uc_hash_table(struct tsrn10_eth_port *port,
				  uint8_t *addr,
				  uint8_t add)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint8_t p_id = port->attr.nr_port;
	uint32_t hash_bit;
	uint32_t uta_row;
	uint32_t uta_col;
	uint32_t crc;
	uint32_t reg;

	crc = bitrev32(~tsrn10_calc_crc32(~0, addr, RTE_ETHER_ADDR_LEN));
	crc >>= port->hash_table_shift;
	uta_row = crc >> TSRN10_UTA_BIT_SHIFT;
	uta_col = crc & TSRN10_UTA_BIT_MASK;

	hash_bit = port->uc_hash_table[uta_row] >> uta_col;

	reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_UC_HASH_TB(uta_row));
	if (hash_bit && add)
		return 0;

	if (add) {
		reg |= (1 << uta_col);
		port->uc_hash_mac_addr++;
		port->uc_hash_table[uta_row] |= (1 << uta_col);
	} else {
		reg &= ~(1 << uta_col);
		port->uc_hash_mac_addr--;
		port->uc_hash_table[uta_row] &= ~(1 << uta_col);
	}

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_UC_HASH_TB(uta_row),
			port->uc_hash_table[uta_row]);

	if (port->uc_hash_mac_addr) {
		reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
		reg |= TSRN10_MAC_HUC | TSRN10_MAC_HPF;
		tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, reg);
	} else {
		reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
		reg &= ~(TSRN10_MAC_HUC | TSRN10_MAC_HPF);
		tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, reg);
	}

	return 0;
}

static int32_t
tsrn10_en_indep_uc_hash_table(struct tsrn10_eth_port *port, bool add)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint8_t p_id = port->attr.nr_port;
	uint32_t idx;
	uint32_t reg;

	for (idx = 0; idx < port->attr.uc_hash_tb_size; idx++) {
		if (add)
			port->uc_hash_table[idx] = ~0;
		else
			port->uc_hash_table[idx] = 0;

		tsrn10_mac_wr(hw, p_id, TSRN10_MAC_UC_HASH_TB(idx),
				port->uc_hash_table[idx]);
	}

	reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
	if (add)
		reg |= TSRN10_MAC_HUC;

	else
		reg &= ~TSRN10_MAC_HUC;

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, reg);

	return 0;
}

static int32_t
tsrn10_update_indep_mc_hash_table(struct tsrn10_eth_port *port,
				  struct rte_ether_addr *mc_list,
				  uint8_t nb_mc)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	struct tsrn10_port_attr *attr = &port->attr;
	uint32_t idx = 1;
	/* Clear All Mcast Address rule Before Set New Rule */
	/* clear unicast addresses */
	/* We Will use Unicast Address For Multicast Perfect Match */

	for (idx = 1; idx < port->attr.max_mc_mac_hash; idx++) {
		if (rte_is_zero_ether_addr(&port->dev->data->mac_addrs[idx]))
			continue;
		memset(&port->dev->data->mac_addrs[idx], 0,
				sizeof(struct rte_ether_addr));
	}

	for (idx = 1; idx < port->attr.max_mc_mac_hash; idx++) {
		tsrn10_mac_res_remove(port, idx);
		tsrn10_mac_wr(hw, attr->nr_port, TSRN10_MAC_ADDR_HI(idx), 0);
		tsrn10_mac_wr(hw, attr->nr_port, TSRN10_MAC_ADDR_LO(idx), 0);
	}

	idx = 1;
	while (nb_mc--) {
		tsrn10_set_indep_mac_addr(port, (uint8_t *)mc_list++,
				UINT8_MAX, idx++);
	}

	return 0;
}

static int32_t
tsrn10_indep_en_vlan_filter(struct tsrn10_eth_port *port, bool en)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint8_t p_id = port->attr.nr_port;
	uint32_t flt_reg, vlan_reg;

	flt_reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
	vlan_reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_VLAN_TAG);

	if (en) {
		flt_reg |= TSRN10_MAC_VTFE;
		vlan_reg |= (TSRN10_MAC_VLAN_VTHM | TSRN10_MAC_VLAN_ETV);
		/* Work Around For HW Vlan Filter.
		 * BIT 0-11 Must Can't Be Zero So Add vlan Id 1
		 * So What Ever Vlan Filter So Vlan-ID 1
		 * Pkt Will Pass The Vlan-Filter
		 */
		vlan_reg |= TSRN10_MAC_VLAN_HASH_EN;
	} else {
		flt_reg &= ~TSRN10_MAC_VTFE;
		vlan_reg &= ~(TSRN10_MAC_VLAN_VTHM | TSRN10_MAC_VLAN_ETV);
		vlan_reg &= ~TSRN10_MAC_VLAN_HASH_EN;
	}
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, flt_reg);
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_VLAN_TAG, vlan_reg);

	return 0;
}

static void
tsrn10_indep_update_vlan_hash(struct tsrn10_eth_port *port)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint16_t p_id = port->attr.nr_port;
	uint16_t vid_le;
	uint32_t crc;
	uint16_t vid;
	uint16_t hash = 0;
	uint64_t vid_idx, vid_bit;

	/* Generate VLAN Hash Table */
	for (vid = 0; vid < VLAN_N_VID; vid++) {
		vid_idx = VLAN_BITMAP_IDX(vid);
		vid_bit = port->vlans_bitmap[vid_idx];
		vid_bit = (uint64_t)vid_bit >>
			(vid - (BITS_TO_LONGS(VLAN_N_VID) * vid_idx));
		/* If Vid isn't Set, Calc Next Vid Hash Value */
		if (!(vid_bit & 1))
			continue;

		vid_le = rte_cpu_to_le_16(vid);
		crc = bitrev32(~tsrn10_vid_crc32_le(vid_le)) >> 28;
		hash |= (1 << crc);
	}
	/* Update Vlan Hash Table */
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_VLAN_HASH_TB, hash);
}

static int32_t
tsrn10_indep_add_vlan_filter(struct tsrn10_eth_port *port,
			     uint16_t vid,
			     bool add)
{
	unsigned long vid_bit, vid_idx;

	vid_bit = VLAN_BITMAP_BIT(vid);
	vid_idx = VLAN_BITMAP_IDX(vid);

	if (add)
		port->vlans_bitmap[vid_idx] |= vid_bit;
	else
		port->vlans_bitmap[vid_idx] &= ~vid_bit;

	tsrn10_indep_update_vlan_hash(port);

	return 0;
}

static int32_t
tsrn10_update_indep_mpfm(struct tsrn10_eth_port *port,
			 enum tsrn10_mpf_modes mode, bool en)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint8_t p_id = port->attr.nr_port;
	uint32_t disable = 0, enable = 0;
	uint32_t reg;

	reg = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL);
	/* Make Sure Not All Receive modes Are Available */
	reg &= ~TSRN10_MAC_RA;
	switch (mode) {
	case TSRN10_MPF_MODE_NONE:
		break;
	case TSRN10_MPF_MODE_MULTI:
		disable = TSRN10_MAC_PM | TSRN10_MAC_PROMISC_EN;
		enable = TSRN10_MAC_HPF;
		break;
	case TSRN10_MPF_MODE_ALLMULTI:
		enable = TSRN10_MAC_PM;
		disable = 0;
		break;
	case TSRN10_MPF_MODE_PROMISC:
		enable = TSRN10_MAC_PROMISC_EN;
		disable = 0;
		break;
	default:
		PMD_DRV_LOG(ERR, "update_mpfm argument is invalid");
		return -EINVAL;
	}
	if (en) {
		reg &= ~disable;
		reg |= enable;
	} else {
		reg &= ~enable;
		reg |= disable;
	}
	/* disable common filter when indep mode */
	reg |= TSRN10_MAC_HPF;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_PKT_FLT_CTRL, reg);
	tsrn10_eth_wr(hw, TSRN10_MAC_FCTRL, TSRN10_MAC_FCTRL_BYPASS);

	return 0;
}

struct tsrn10_mac_api tsrn10_mac_indep_ops = {
	.set_default_mac	= tsrn10_set_default_mac_pf,
	.get_fw_ver		= tsrn10_get_fw_version_pf,
	.reset_hw		= tsrn10_reset_hw_pf,
	.init_hw		= tsrn10_init_hw_pf,
	.fc_enable		= tsrn10_fc_enable,
	.set_rafb		= tsrn10_set_indep_mac_addr,
	.clear_rafb		= tsrn10_clear_indep_mac_addr,
	.update_uta		= tsrn10_update_indep_uc_hash_table,
	.enable_uta		= tsrn10_en_indep_uc_hash_table,
	.update_mta		= tsrn10_update_indep_mc_hash_table,
	.update_mpfm		= tsrn10_update_indep_mpfm,
	.add_vlan_f		= tsrn10_indep_add_vlan_filter,
	.en_vlan_f		= tsrn10_indep_en_vlan_filter,
	.get_mac_addr		= tsrn10_get_mac_addr_pf,
};

struct tsrn10_mac_api tsrn10_mac_ops = {
	.set_default_mac	= tsrn10_set_default_mac_pf,
	.get_fw_ver		= tsrn10_get_fw_version_pf,
	.reset_hw		= tsrn10_reset_hw_pf,
	.init_hw		= tsrn10_init_hw_pf,
	.fc_enable		= tsrn10_fc_enable,
	.set_rafb		= tsrn10_set_mac_addr_pf,
	.clear_rafb		= tsrn10_clear_mac_addr_pf,
	.update_uta		= tsrn10_update_uc_hash_table,
	.enable_uta		= tsrn10_en_uc_hash_tb_pf,
	.update_mpfm		= tsrn10_update_mpfm_pf,
	.update_mta		= tsrn10_update_mc_hash_table,
	.add_vlan_f		= tsrn10_add_vlan_filter_pf,
	.en_vlan_f		= tsrn10_en_vlan_filter_pf,
	.get_mac_addr		= tsrn10_get_mac_addr_pf,
};

struct tsrn10_phy_api tsrn10_phy_ops = {
	.setup_link		= tsrn10_setup_link_phy,
};

struct tsrn10_phy_api tsrn10_fiber_ops = {
	.setup_link		= tsrn10_setup_link_fiber,
};

static int
tsrn10_special_ops_init(struct tsrn10_eth_adapter *adap,
			struct rte_eth_dev *dev __rte_unused)
{
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	struct tsrn10_share_ops *share_priv;

	/* allocate process_private memory this must can't
	 * belone to the dpdk mem resource manager
	 * such as from rte_malloc or rte_dma_zone..
	 */
	/* use the process_prive point to resolve secondary process
	 * use point-func. This point is per process will be safe to cover.
	 * This will cause secondary process core-dump because of IPC
	 * Secondary will call primary process point func virt-address
	 * secondary process don't alloc user/pmd to alloc or free
	 * the memory of dpdk-mem resource it will cause hugepage
	 * mem exception
	 * be careful for secondary Process to use the share-mem of
	 * point correlation
	 */
	share_priv = calloc(1, sizeof(*share_priv));
	if (!share_priv) {
		PMD_DRV_LOG(ERR, "calloc share_priv failed");
		return -ENOMEM;
	}

	dev->process_private = share_priv;
	if (adap->s_mode == TSRN10_SHARE_INDEPEND)
		share_priv->mac_api = tsrn10_mac_indep_ops;
	else
		share_priv->mac_api = tsrn10_mac_ops;

	share_priv->mbx_api = tsrn10_mbx_pf_ops;
	share_priv->phy_api = tsrn10_phy_ops;

	return 0;
#else
	struct tsrn10_hw *hw = &adap->hw;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		if (adap->s_mode == TSRN10_SHARE_INDEPEND)
			hw->mac.ops = tsrn10_mac_indep_ops;
		else
			hw->mac.ops = tsrn10_mac_ops;
		hw->mbx.ops = tsrn10_mbx_pf_ops;
		hw->phy.ops = tsrn10_phy_ops;
	}

	return 0;
#endif
}

static void
tsrn10_setup_veb_mac_tb(struct tsrn10_eth_adapter *adapter,
			uint8_t *mac, uint16_t vf_id)
{
	/* For now we just support one port per PF use Sriov
	 * TODO Need to support 2/4 port per PF sriov mode ?
	 * when this time, we must config four veb table with
	 * same value avoid veb drop pkts
	 */
	struct tsrn10_hw *hw = &adapter->hw;
	uint16_t tb_idx;
	uint32_t mac_h, mac_l;

	for (tb_idx = 0; tb_idx < MAX_VEB_TABLES_NUM; tb_idx++) {
		mac_l = (mac[2] << 24) | (mac[3] << 16) |
			(mac[4] << 8) | mac[5];
		mac_h = (mac[0] << 8) | mac[1];
		tsrn10_veb_wr(hw,
			TSRN10_VBE_MAC_HI(tb_idx, vf_id), mac_h);
		tsrn10_veb_wr(hw,
			TSRN10_VBE_MAC_LO(tb_idx, vf_id), mac_l);
	}
}

static void
tsrn10_setup_veb_ring_tb(struct tsrn10_eth_adapter *adapter,
			 struct tsrn10_vfinfo *vfinfo)
{
	/* Setup Ring OF VF belong relationship
	 * of VEB ring Table
	 * For One port per PF we must set four table same value to
	 * avoid VEB drop pkts.
	 */
	struct tsrn10_hw *hw = &adapter->hw;
	uint16_t vf_num = vfinfo->pool_num;
	uint16_t tb_idx;
	uint16_t reg;

	for (tb_idx = 0; tb_idx < MAX_VEB_TABLES_NUM; tb_idx++) {
		reg = vfinfo->rx_dma_quene_base;
		reg |= (RNP_VEB_SWITCH_VF_EN | vf_num)
		       << TSRN10_VEB_RING_CFG_OFFSET;
		tsrn10_veb_wr(hw,
			      TSRN10_VEB_VF_RING(tb_idx, vf_num), reg);
	}
}

static void
tsrn10_setup_veb_table(struct rte_eth_dev *dev, uint16_t vf_num)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_vfinfo *vfinfo = adapter->vfinfo;
	uint16_t vf_id;

	for (vf_id = 0; vf_id < vf_num; vf_id++) {
		tsrn10_setup_veb_mac_tb(adapter,
				vfinfo[vf_id].vf_mac_addr, vf_id);
		tsrn10_setup_veb_ring_tb(adapter, &vfinfo[vf_id]);
	}
}

static void
tsrn10_setup_vf_rar_pool_tb(struct rte_eth_dev *dev, uint16_t vf_num)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_vfinfo *vfinfo = adapter->vfinfo;
	struct tsrn10_hw *hw = &adapter->hw;
	uint32_t mac_h, mac_l;
	uint16_t vf_id;
	uint8_t *mac;

	for (vf_id = 0; vf_id < vf_num; vf_id++) {
		mac = vfinfo[vf_id].vf_mac_addr;
		mac_l = (mac[2] << 24) | (mac[3] << 16) |
			(mac[4] << 8) | mac[5];
#define TSRN10_VF_RAR_EN	(1 << 31)
		mac_h = (mac[0] << 8) | mac[1] | TSRN10_MAC_FILTER_EN;
		tsrn10_eth_wr(hw, TSRN10_RAL_BASE_ADDR(vf_id), mac_l);
		tsrn10_eth_wr(hw, TSRN10_RAH_BASE_ADDR(vf_id), mac_h);
		tsrn10_eth_wr(hw, TSRN10_MPSAR_BASE_ADDR(vf_id),
				vfinfo[vf_id].pool_num);
	}
	mac = (uint8_t *)dev->data->mac_addrs;
	mac_l = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
	mac_h = (mac[0] << 8) | mac[1] | TSRN10_MAC_FILTER_EN;

	tsrn10_eth_wr(hw, TSRN10_RAL_BASE_ADDR(vf_id), mac_l);
	tsrn10_eth_wr(hw, TSRN10_RAH_BASE_ADDR(vf_id), mac_h);
	tsrn10_eth_wr(hw, TSRN10_MPSAR_BASE_ADDR(vf_id), 1);
}

static void tsrn10_vf_generate_mac(struct rte_eth_dev *dev, uint16_t vf_num)
{
	uint16_t i;
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_eth_adapter *adapter = port->adapt;

	struct tsrn10_vfinfo *vfinfo = adapter->vfinfo;

	for (i = 0; i < vf_num; i++)
		tsrn10_random_mac_addr(vfinfo[i].vf_mac_addr);

	TSRN10_PMD_LOG(INFO, "PF[%d] vf[0] macaddrss 0x%.2x:0x%.2x:0x%.2x:"
			"0x%.2x:0x%.2x:0x%.2x\n", adapter->hw.function,
			vfinfo[i].vf_mac_addr[0],
			vfinfo[i].vf_mac_addr[1],
			vfinfo[i].vf_mac_addr[2],
			vfinfo[i].vf_mac_addr[3],
			vfinfo[i].vf_mac_addr[4],
			vfinfo[i].vf_mac_addr[5]);
}

static void tsrn10_vf_resource_setup(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_adapter *adapt = TSRN10_DEV_TO_ADAPTER(dev);
	uint16_t nb_queues = RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool;
	uint16_t vf_num =  RTE_ETH_DEV_SRIOV(dev).active;
	struct tsrn10_vfinfo *vfinfo = adapt->vfinfo;
	uint16_t i = 0;

	vf_num = adapt->max_vfs;
	for (i = 0; i < vf_num; i++) {
		vfinfo[i].pool_num = i;
		vfinfo[i].rx_queue_num = nb_queues;
		vfinfo[i].tx_queue_num = nb_queues;
		vfinfo[i].rx_dma_quene_base = i * nb_queues;
		vfinfo[i].tx_dma_quene_base = i * nb_queues;
		vfinfo[i].vf_id = i;
	}
}

static int32_t tsrn10_init_pf_manage(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_hw *hw = &adapter->hw;
	struct tsrn10_vfinfo *vfinfo = NULL;
	int32_t ret = 0;
	uint16_t vf_num;
	uint16_t nb_q_per_pool;

	PMD_INIT_FUNC_TRACE();

	RTE_ETH_DEV_SRIOV(dev).active = 0;

	vf_num = adapter->max_vfs;
	if (vf_num == 0 || adapter->mode != TSRN10_SINGLE_10G)
		return ret;

	vfinfo = rte_zmalloc("vfinfo",
			sizeof(struct tsrn10_vfinfo) * vf_num, 0);
	if (vfinfo == NULL) {
		PMD_INIT_LOG(ERR,
				"Cannot Allocate Memory for VF Info");
		return -ENOMEM;
	}
#if RTE_VERSION_NUM(20, 5, 0, 0) <= RTE_VERSION
	ret = rte_eth_switch_domain_alloc(&adapter->switch_domain_id);
	if (ret) {
		PMD_INIT_LOG(ERR,
			"failed To Allocate Switch Domain For Device %d", ret);
		rte_free(vfinfo);
		vfinfo = NULL;
		return ret;
	}
#endif
	adapter->vfinfo = vfinfo;
	/* IF PF IN DPDK Pf Is The End Of Vf Support */
	hw->mbx.vf_num = 64;
	hw->mbx.sriov_st = (BIT(7) | (hw->mbx.pf_num << 6) | hw->mbx.vf_num);
	hw->pf_vf_num = hw->mbx.sriov_st;

	if (vf_num >= TSRN10_SRIOV_VF_POOLS_64) {
		nb_q_per_pool = 1;
		RTE_ETH_DEV_SRIOV(dev).active = TSRN10_SRIOV_VF_POOLS_128;
	} else if (vf_num >= ETH_32_POOLS) {
		nb_q_per_pool = 2;
		RTE_ETH_DEV_SRIOV(dev).active = TSRN10_SRIOV_VF_POOLS_64;
	} else if (vf_num >= 16) {
		nb_q_per_pool = 4;
		RTE_ETH_DEV_SRIOV(dev).active = TSRN10_SRIOV_VF_POOLS_32;
	} else {
		nb_q_per_pool = 8;
		RTE_ETH_DEV_SRIOV(dev).active = TSRN10_SRIOV_VF_POOLS_16;
	}
	nb_q_per_pool = 2;

	RTE_ETH_DEV_SRIOV(dev).active = 1;
	RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool = nb_q_per_pool;
	/* PF Ring Resource Will Use After VF occupat */
	RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx =
		(uint16_t)(vf_num * nb_q_per_pool);
	/* Enabled Sriov */
	tsrn10_enable_sriov(hw, true);
	/* Setup VF Ring Resource Division*/
	tsrn10_vf_resource_setup(dev);
	/* Setup VF MAC Address */
	tsrn10_vf_generate_mac(dev, vf_num);
	/* Setup Veb Table */
	tsrn10_setup_veb_table(dev, vf_num);
	/* Setup Vf recive address range */
	tsrn10_setup_vf_rar_pool_tb(dev, vf_num);

	return 0;
}

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
static const char *const tsrn10_valid_arguments[] = {
#else
static const char *tsrn10_valid_arguments[] = {
#endif
	TSRN10_HW_MAC_LOOPBACK_ARG,
	TSRN10_FW_UPDATE,
	TSRN10_RX_FUNC_SELECT,
	TSRN10_TX_FUNC_SELECT,
	TSRN10_FW_4X10G_10G_1G_DET,
	TSRN10_FW_FORCE_SPEED_1G,
	NULL
};

static int
tsrn10_parse_handle_devarg(const char *key, const char *value,
			   void *extra_args)
{
	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	if (strcmp(key, TSRN10_HW_MAC_LOOPBACK_ARG) == 0) {
		uint16_t *n = extra_args;
		*n			= (uint16_t)strtoul(value, NULL, 10);
		if (*n == USHRT_MAX && errno == ERANGE)
			return -1;
	} else if (strcmp(key, TSRN10_FW_UPDATE) == 0) {
		struct tsrn10_eth_adapter *adapter =
			(struct tsrn10_eth_adapter *)extra_args;

		adapter->do_fw_update = true;
		adapter->fw_path = strdup(value);
	} else if (strcmp(key, TSRN10_FW_4X10G_10G_1G_DET) == 0) {
		struct tsrn10_eth_adapter *adapter =
			(struct tsrn10_eth_adapter *)extra_args;
		if (adapter->num_ports == 2 && adapter->hw.speed == 10 * 1000) {
			adapter->fw_sfp_10g_1g_auto_det =
				(strcmp(value, "on") == 0) ? true : false;
		} else {
			adapter->fw_sfp_10g_1g_auto_det = false;
		}
	} else if (strcmp(key, TSRN10_FW_FORCE_SPEED_1G) == 0) {
		struct tsrn10_eth_adapter *adapter =
			(struct tsrn10_eth_adapter *)extra_args;
		if (adapter->num_ports == 2) {
			if (strcmp(value, "on") == 0)
				adapter->fw_force_speed_1g = FOCE_SPEED_1G_ENABLED;
			else if (strcmp(value, "off") == 0)
				adapter->fw_force_speed_1g = FOCE_SPEED_1G_DISABLED;
		}
	} else {
		return -1;
	}

	return 0;
}

static int
tsrn10_parse_io_select_func(const char *key, const char *value, void *extra_args)
{
	uint8_t select = TSRN10_IO_FUNC_USE_NONE;

	RTE_SET_USED(key);

	if (strcmp(value, "vec") == 0)
		select = TSRN10_IO_FUNC_USE_VEC;
	else if (strcmp(value, "simple") == 0)
		select = TSRN10_IO_FUNC_USE_SIMPLE;
	else if (strcmp(value, "common") == 0)
		select = TSRN10_IO_FUNC_USE_COMMON;

	*(uint8_t *)extra_args = select;

	return 0;
}

static void
tsrn10_parse_devargs(struct tsrn10_eth_adapter *adapter,
		     struct rte_devargs *devargs)
{
	uint8_t rx_io_func = TSRN10_IO_FUNC_USE_NONE;
	uint8_t tx_io_func = TSRN10_IO_FUNC_USE_NONE;
	struct rte_kvargs *kvlist;
	bool loopback_en = false;

	adapter->do_fw_update = false;
	adapter->fw_sfp_10g_1g_auto_det = false;
	adapter->fw_force_speed_1g = FOCE_SPEED_1G_NOT_SET;

	if (!devargs)
		goto def;

	kvlist = rte_kvargs_parse(devargs->args, tsrn10_valid_arguments);
	if (kvlist == NULL)
		goto def;

	if (rte_kvargs_count(kvlist, TSRN10_HW_MAC_LOOPBACK_ARG) == 1)
		rte_kvargs_process(kvlist, TSRN10_HW_MAC_LOOPBACK_ARG,
				&tsrn10_parse_handle_devarg, &loopback_en);


	if (rte_kvargs_count(kvlist, TSRN10_FW_4X10G_10G_1G_DET) == 1)
		rte_kvargs_process(kvlist,
				TSRN10_FW_4X10G_10G_1G_DET,
				&tsrn10_parse_handle_devarg,
				adapter);

	if (rte_kvargs_count(kvlist, TSRN10_FW_FORCE_SPEED_1G) == 1)
		rte_kvargs_process(kvlist,
				TSRN10_FW_FORCE_SPEED_1G,
				&tsrn10_parse_handle_devarg,
				adapter);

	if (rte_kvargs_count(kvlist, TSRN10_FW_UPDATE) == 1)
		rte_kvargs_process(kvlist, TSRN10_FW_UPDATE,
				&tsrn10_parse_handle_devarg, adapter);
	if (rte_kvargs_count(kvlist, TSRN10_RX_FUNC_SELECT) == 1)
		rte_kvargs_process(kvlist, TSRN10_RX_FUNC_SELECT,
				&tsrn10_parse_io_select_func, &rx_io_func);
	if (rte_kvargs_count(kvlist, TSRN10_TX_FUNC_SELECT) == 1)
		rte_kvargs_process(kvlist, TSRN10_TX_FUNC_SELECT,
				&tsrn10_parse_io_select_func, &tx_io_func);
	rte_kvargs_free(kvlist);
def:
	adapter->loopback_en = loopback_en;
	adapter->rx_func_sec = rx_io_func;
	adapter->tx_func_sec = tx_io_func;
}

static int tsrn10_post_handle(struct tsrn10_eth_adapter *adapter)
{
	if (adapter->do_fw_update && adapter->fw_path) {
		rnp_fw_update(adapter);
		adapter->do_fw_update = 0;
	}

	if (adapter->fw_sfp_10g_1g_auto_det && adapter->port[0])
		rnp_hw_set_fw_10g_1g_auto_detch(adapter->port[0]->dev, 1);

	if (adapter->fw_force_speed_1g != FOCE_SPEED_1G_NOT_SET && adapter->port[0])
		rnp_hw_set_fw_force_speed_1g(adapter->port[0]->dev,
			(adapter->fw_force_speed_1g == FOCE_SPEED_1G_ENABLED) ? 1 : 0);
	return 0;
}

static void
tsrn10_setup_port_attr(struct tsrn10_eth_port *port,
		       struct rte_eth_dev *dev,
		       uint8_t num_ports,
		       uint8_t p_id)
{
	struct tsrn10_port_attr *attr = &port->attr;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint32_t lane_bit;

	if (port->s_mode == TSRN10_SHARE_INDEPEND) {
		attr->max_mac_addrs = TSRN10_PORT_MAX_MACADDR;
		attr->max_uc_mac_hash = TSRN10_PORT_MAX_UC_MAC_SIZE;
		attr->uc_hash_tb_size = TSRN10_PORT_MAX_UC_HASH_TB;
		attr->max_mc_mac_hash = TSRN10_PORT_MAX_MACADDR;
		attr->max_vlan_hash = TSRN10_PORT_MAX_VLAN_HASH;
		port->hash_table_shift = 26 - (attr->max_uc_mac_hash >> 7);
	} else {
		attr->max_mac_addrs = TSRN10_MAX_MAC_ADDRS / num_ports;
		attr->max_uc_mac_hash = TSRN10_MAX_UC_MAC_SIZE / num_ports;
		attr->uc_hash_tb_size = TSRN10_MAX_UC_HASH_TB;
		attr->max_mc_mac_hash = TSRN10_MAX_MC_MAC_SIZE / num_ports;
		attr->mc_hash_tb_size = TSRN10_MAC_MC_HASH_TB;
		attr->max_vlan_hash = TSRN10_MAX_VLAN_HASH_TB_SIZE / num_ports;
		port->hash_table_shift = TSRN10_UTA_BIT_SHIFT;
	}
	if (hw->device_id == TSRN10_DEV_ID_N400L_X4) {
		attr->max_rx_queues = TSRN10_N400_MAX_RX_QUEUE_NUM;
		attr->max_tx_queues = TSRN10_N400_MAX_TX_QUEUE_NUM;
	} else {
		attr->max_rx_queues = TSRN10_MAX_RX_QUEUE_NUM / num_ports;
		attr->max_tx_queues = TSRN10_MAX_TX_QUEUE_NUM / num_ports;
	}

	attr->rte_pid = dev->data->port_id;
	lane_bit = hw->phy_port_ids[p_id] & (hw->max_port_num - 1);

	attr->nr_port = lane_bit;
	attr->port_offset = tsrn10_eth_rd(hw,
			TSRN10_TC_PORT_MAP_TB(attr->nr_port));

	rnp_mbx_get_lane_stat(dev, p_id);

	PMD_DRV_LOG(INFO, "PF[%d] SW-ETH-PORT[%d]<->PHY_LANE[%d]\n",
			hw->function, p_id, lane_bit);
}

static void
tsrn10_tcam_init(struct tsrn10_eth_port *port, bool en)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW(port);
	uint16_t idx;
	uint32_t action = 0;
	/* Enable Or Disable TCAM Engine */
	tsrn10_nicx_wr(hw, TSRN10_TCAM_ENABLE, false);
	tsrn10_nicx_wr(hw, TSRN10_TCAM_CONFIG_AVAIL_EN, en);
	/* Enable Tcam Rule Wrtie Access */
	tsrn10_nicx_wr(hw, TSRN10_TCAM_MODE_CTRL, TSRN10_ACL_RAM_MODE);
	tsrn10_nicx_wr(hw, TSRN10_TCAM_CACHE_EN, en);
	for (idx = 0; idx < TSRN10_MAX_TCAM_NTUPLE_RULE; idx++) {
		/* Clear Ip Src Rule*/
		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF(idx), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF_MASK(idx), 0);
		/* Clear Ip Dst Rule*/
		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF(idx), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF_MASK(idx), 0);
		/* Clear L4Port Rule */
		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF(idx), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF_MASK(idx), 0);
		action = TSRN10_TCAM_ACT_RDIR_PORT |
			12 << TSRN10_TCAM_ACT_PHY_OFFSET;
		action |= TSRN10_TCAM_ACT_PASS;
		/* Clear Rule Action */
		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACTQF(idx), action);
		/* Clear Rule Mark Id */
		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACT_MARK(idx), 0);
	}
	/* Disable Tcam Rule Wrtie Access */
	tsrn10_nicx_wr(hw, TSRN10_TCAM_MODE_CTRL, TSRN10_ACL_TCAM_MODE);
}

static void
tsrn10_init_filter_setup(struct tsrn10_eth_port *port,
			 uint8_t num_ports,
			 struct tsrn10_hw *hw __rte_unused)
{
	struct tsrn10_filter_info *filter_info = &port->filter;
	uint32_t en;

	/* init filter info */
	memset(filter_info, 0,
			sizeof(struct tsrn10_filter_info));
	/* init 5tuple filter list */
	TAILQ_INIT(&filter_info->fivetuple_list);
	TAILQ_INIT(&filter_info->flow_list);
	TAILQ_INIT(&filter_info->ethertype_list);
	TAILQ_INIT(&filter_info->rss_cfg_list);

	if (filter_info->mode == TSRN10_TUPLE_TCAM_MODE)
		filter_info->max_ntuple_num = TSRN10_MAX_TCAM_NTUPLE_RULE;
	else
		filter_info->max_ntuple_num = TSRN10_MAX_NTUPLE_RULE;

	filter_info->max_ethertype_rule_num = TSRN10_MAX_ETYPE_RULE_NUM / num_ports;
	filter_info->ethertype_rule_base =
		filter_info->max_ethertype_rule_num * port->attr.nr_lane;
	filter_info->max_ntuple_num = filter_info->max_ntuple_num / num_ports;
	filter_info->ntuple_rule_base =
		filter_info->max_ntuple_num * port->attr.nr_lane;

	en = filter_info->mode == TSRN10_TUPLE_TCAM_MODE ? true : false;
	tsrn10_tcam_init(port, en);
}

static int
tsrn10_init_port_resource(struct tsrn10_eth_adapter *adapter,
			  struct rte_eth_dev *dev,
			  char *name,
			  uint8_t p_id)
{
	struct tsrn10_fc_info *fc_info = TSRN10_DEV_TO_FC_INFO(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_pci_device *pci_dev = adapter->pdev;
	struct tsrn10_hw *hw = &adapter->hw;

	port->adapt = adapter;
	port->rx_func_sec = adapter->rx_func_sec;
	port->tx_func_sec = adapter->tx_func_sec;
	port->s_mode = adapter->s_mode;
	port->port_stopped = 1;
	port->dev = dev;
	port->hw = hw;

	/* Get Link Flow Ctrl Default Info */
	fc_info->hi_water[0] = TSRN10_FC_DEF_HIGH_WATER;
	fc_info->lo_water[0] = TSRN10_FC_DEF_LOW_WATER;
	fc_info->mode = TSRN10_FC_NONE;
	fc_info->pause_time = TSRN10_FC_DEF_PAUSE_TM;
	fc_info->send_xon = 1;
	fc_info->max_tc = TSRN10_MAX_TC_SUPPORT / adapter->num_ports;

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	dev->device = &pci_dev->device;
#endif
	rte_eth_copy_pci_info(dev, pci_dev);
	dev->dev_ops = &tsrn10_ops;

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	dev->rx_queue_count       = tsrn10_dev_rx_queue_count;
#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
	dev->rx_descriptor_done   = tsrn10_dev_rx_descriptor_done;
#endif
	dev->rx_descriptor_status = tsrn10_dev_rx_descriptor_status;
	dev->tx_descriptor_status = tsrn10_dev_tx_descriptor_status;
#endif
	dev->rx_pkt_burst = &tsrn10_recv_pkts;
	dev->tx_pkt_burst = &tsrn10_xmit_pkts;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	dev->tx_pkt_prepare = &tsrn10_prep_pkts;
#endif
	/* Default QINQ Insert Prolicy */
	port->invlan_type = TSRN10_CVLAN_TYPE;
	port->outvlan_type = TSRN10_SVLAN_TYPE;

	tsrn10_setup_port_attr(port, dev, adapter->num_ports, p_id);
	tsrn10_init_filter_setup(port, adapter->num_ports, hw);
	/* Four mac address will be store a speical reg TODO */
	tsrn10_get_mac_addr(dev, port->mac_addr);

	dev->data->mac_addrs = rte_zmalloc(name,
#if RTE_VERSION_NUM(19, 8, 0, 0) < RTE_VERSION
			sizeof(struct rte_ether_addr) *
#else
			sizeof(struct ether_addr) *
#endif
			port->attr.max_mac_addrs, 0);
	if (!dev->data->mac_addrs) {
		PMD_DRV_LOG(ERR, "Memory allocation "
				"for MAC failed! Exiting.\n");
		return -ENOMEM;
	}
	/* Allocate memory for storing hash filter MAC addresses */
	dev->data->hash_mac_addrs = rte_zmalloc("tsrn10",
			RTE_ETHER_ADDR_LEN * port->attr.max_uc_mac_hash, 0);
	if (dev->data->hash_mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate %d bytes "
				"needed to store MAC addresses",
			RTE_ETHER_ADDR_LEN * port->attr.max_uc_mac_hash);
		return -ENOMEM;
	}

	tsrn10_set_default_mac(dev, port->mac_addr);
#if RTE_VERSION_NUM(19, 8, 0, 0) < RTE_VERSION
	rte_ether_addr_copy((const struct rte_ether_addr *)port->mac_addr,
			dev->data->mac_addrs);
#else
	ether_addr_copy((struct ether_addr *)port->mac_addr,
			dev->data->mac_addrs);
#endif
	/* MTU */
	dev->data->mtu = RTE_ETHER_MAX_LEN -
		RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
	adapter->port[p_id] = port;
#if RTE_VERSION_NUM(18, 2, 2, 16) <= RTE_VERSION
	rte_eth_dev_probing_finish(dev);
#endif

	return 0;
}

static struct rte_eth_dev *
tsrn10_alloc_eth_port(struct rte_pci_device *master_pci, char *name)
{
	struct tsrn10_eth_port *port;
	struct rte_eth_dev *eth_dev;

#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
	eth_dev = rte_eth_dev_allocate(name, RTE_ETH_DEV_PCI);
#else
	eth_dev = rte_eth_dev_allocate(name);
#endif
#if RTE_VERSION_NUM(16, 11, 0, 0) >= RTE_VERSION
	eth_dev->pci_dev = master_pci;
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) >= RTE_VERSION
	eth_dev->driver = (struct eth_driver *)master_pci->driver;
#endif

	if (!eth_dev) {
		PMD_DRV_LOG(ERR, "Could not allocate "
				"eth_dev for %s\n", name);
		return NULL;
	}
#if RTE_VERSION_NUM(17, 2, 0, 0) > RTE_VERSION
	TAILQ_INIT(&(eth_dev->link_intr_cbs));
#endif
#if RTE_VERSION_NUM(16, 11, 0, 16) >= RTE_VERSION
	eth_dev->driver = (struct eth_driver *)master_pci->driver;
#endif
	port = rte_zmalloc_socket(name,
			sizeof(*port),
			RTE_CACHE_LINE_SIZE,
#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
			master_pci->numa_node);
#else
			master_pci->device.numa_node);
#endif
	if (!port) {
		PMD_DRV_LOG(ERR, "Could not allocate "
				"tsrn10_eth_port for %s\n", name);
		return NULL;
	}
	eth_dev->data->dev_private = port;
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	eth_dev->process_private = calloc(1, sizeof(struct tsrn10_share_ops));
	if (!eth_dev->process_private) {
		PMD_DRV_LOG(ERR, "Could not calloc "
				"for Process_priv\n");
		goto fail_calloc;
	}
#endif
	return eth_dev;
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
fail_calloc:
	rte_free(port);
	rte_eth_dev_release_port(eth_dev);

	return NULL;
#endif
}

static void tsrn10_policy_lookback(struct tsrn10_eth_adapter *adapter)
{
	struct tsrn10_hw *hw = &adapter->hw;
	struct tsrn10_eth_port *port;
	uint32_t ctrl_reg = 0;
	uint16_t p_id;

	tsrn10_eth_wr(hw, TSRN10_INPUT_USE_CTRL, 0xf);
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
		port = adapter->port[p_id];
		if (hw->pf_vf_num & TSRN10_PF_NB_MASK) {
			if (port->attr.nr_port)
				ctrl_reg = BIT(29) | (6 << 16);
			else
				ctrl_reg = BIT(29) | (4 << 16);
		} else {
			if (port->attr.nr_port)
				ctrl_reg = BIT(29) | (2 << 16);
			else
				ctrl_reg = BIT(29) | (0 << 16);
		}
		tsrn10_eth_wr(hw, TSRN10_INPUT_POLICY(port->attr.nr_port),
				ctrl_reg);
	}
}

static int
tsrn10_dev_secondary_init(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	char name[RTE_ETH_NAME_MAX_LEN] = "";
	struct tsrn10_eth_adapter *adapter;
	struct rte_eth_dev *eth_dev;
	char device_name[PCI_PRI_STR_SIZE] = "";
	uint16_t p_id;
	int ret;

	adapter = port->adapt;
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
		strlcpy(device_name, dev->data->name,
				strlen(dev->data->name) + 1);
#else
		strlcpy(device_name, pci_dev->device.name,
				strlen(pci_dev->device.name) + 1);
#endif
		if (p_id == 0)
			/* rte_eth_dev_pci_allocate used device.name
			 *  alloc eth_dev
			 */
			memcpy(name, device_name, strlen(device_name));
		else
			snprintf(name, sizeof(name), "tsrn10_eth_%s_%d",
					device_name, p_id);
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
		eth_dev = rte_eth_dev_attach_secondary(name);
#else
		if (p_id) {
#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
			eth_dev = rte_eth_dev_allocate(name, RTE_ETH_DEV_PCI);
#else
			eth_dev = rte_eth_dev_allocate(name);
#endif
			eth_dev->driver = (struct eth_driver *)pci_dev->driver;
#if RTE_VERSION_NUM(17, 2, 0, 0) > RTE_VERSION
			eth_dev->pci_dev = pci_dev;
#endif
			/* init user callbacks */
			TAILQ_INIT(&eth_dev->link_intr_cbs);
		} else {
			eth_dev = dev;
		}
#endif
		if (eth_dev) {
			ret = tsrn10_special_ops_init(adapter, eth_dev);
			if (ret) {
				PMD_DRV_LOG(ERR, "secondary calloc "
						"share_priv failed");
				return ret;
			}
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
			if (p_id > 0)
				eth_dev->device = &pci_dev->device;
#endif
			eth_dev->dev_ops = &tsrn10_dev_secondary_ops;
			eth_dev->rx_pkt_burst = &tsrn10_recv_pkts;
			eth_dev->tx_pkt_burst = &tsrn10_xmit_pkts;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
			eth_dev->tx_pkt_prepare = &tsrn10_prep_pkts;
#endif
#if RTE_VERSION_NUM(18, 2, 4, 4) <= RTE_VERSION
			rte_eth_dev_probing_finish(eth_dev);
#endif
		}
	}
	return 0;
}

static int tsrn10_nic_init(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_ethertype_rule rule;
	char name[RTE_ETH_NAME_MAX_LEN] = " ";
	struct tsrn10_eth_adapter *adapter;
	struct rte_eth_dev *eth_dev;
	struct tsrn10_hw *hw;
	int32_t ret = 0, p_id;
	uint16_t idx = 0;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		tsrn10_dev_secondary_init(dev);

		return 0;
	}
#ifdef PATCH_RELEASE_VERSION
	const char *version = PATCH_RELEASE_VERSION;
	PMD_DRV_LOG(INFO, "DPDK_PATCH_RELEASE Version %s\n", version);
#endif
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "tsrn10_adapter_%d", dev->data->port_id);
	adapter = rte_zmalloc(name, sizeof(struct tsrn10_eth_adapter), 0);
	if (!adapter)
		return -1;
	hw = &adapter->hw;
	adapter->pdev = pci_dev;
	adapter->eth_dev = dev;
	hw->back = (void *)adapter;

	hw->nic_reg = (char *)pci_dev->mem_resource[TSRN10_CFG_BAR].addr;
	hw->iobar0 = (char *)pci_dev->mem_resource[0].addr;
	hw->iobar0_len = pci_dev->mem_resource[0].len;
	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->device_id = pci_dev->id.device_id;

	adapter->max_vfs = pci_dev->max_vfs;
	/* TODO We need Use Device Id To Change The Resource Mode */
	ret = tsrn10_special_ops_init(adapter, dev);
	port->adapt = adapter;
	port->hw = hw;
	if (ret) {
		TSRN10_PMD_ERR("share prive resource init failed");
		return ret;
	}

#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	adapter->share_priv = dev->process_private;
#endif
	tsrn10_init_mbx_ops_pf(hw);

	ret = tsrn10_init_hw(dev);
	if (ret != 0) {
		TSRN10_PMD_ERR("Hardware initialization failed");
		return -1;
	}
#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
	tsrn10_parse_devargs(adapter, pci_dev->devargs);
#else
	tsrn10_parse_devargs(adapter, pci_dev->device.devargs);
#endif
	/* TODO Need To use Device Id */
	/* When In single PF manager two port mode.
	 * The Unknown packet in the 1 port must change port offset
	 * 1 to 2. otherwize 1 port unknown pcaket will into 0 port
	 */
#define TSRN10_UNKNOW_PKT_OFFSET	(2)
#define TSRN10_TARGET_PORT		(1)
	if (adapter->num_ports == 2)
		tsrn10_eth_wr(hw, TSRN10_TC_PORT_MAP_TB(TSRN10_TARGET_PORT),
				TSRN10_UNKNOW_PKT_OFFSET);
	/* We will create additional devices
	 * based on the number of requested ports
	 */
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
		char device_name[64] = "";
		strlcpy(device_name, dev->data->name,
				strlen(dev->data->name) + 1);
		snprintf(name, sizeof(name), "%s_%d",
				device_name,
				p_id);
#else
		snprintf(name, sizeof(name), "%s_%d",
				adapter->pdev->device.name,
				p_id);
#endif

		/* port 0 resource has been alloced When Probe */
		if (!p_id)
			eth_dev = dev;
		else
			eth_dev = tsrn10_alloc_eth_port(pci_dev, name);
		if (!eth_dev)
			goto error;
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
		if (p_id)
			rte_memcpy(eth_dev->process_private,
					adapter->share_priv,
					sizeof(*adapter->share_priv));
#endif
#ifndef USING_MBX
		hw->lane_of_port[p_id] = p_id;
#endif
		ret = tsrn10_init_port_resource(adapter, eth_dev, name, p_id);
		if (ret)
			return -ENOMEM;

		tsrn10_mac_rx_disable(eth_dev);
		tsrn10_mac_tx_disable(eth_dev);
#ifdef RTE_LIBRTE_IEEE1588
		tsrn10_ptp_init(eth_dev);
#endif
	}
	/* If Sriov VF Feature Enable Init Resource Manage info */
	tsrn10_init_pf_manage(dev);
	/* Setup Mailbox interrupt mask */
	rte_intr_disable(intr_handle);
	hw->mbx.irq_enabled = false;
	/* Enable Link Update Event Interrupt */
	rte_intr_callback_register(intr_handle,
			tsrn10_dev_interrupt_handler, dev);
	if (adapter->loopback_en) {
		if (adapter->num_ports == 2)
			tsrn10_policy_lookback(adapter);
		else
			tsrn10_eth_wr(hw, TSRN10_ETH_MAC_LOOPBACK, true);
	}

	for (idx = 0; idx < 4; idx++) {
try:
		tsrn10_mac_wr(hw, idx, TSRN10_MAC_PKT_FLT_CTRL, 0);
		if (tsrn10_mac_rd(hw, idx, TSRN10_MAC_PKT_FLT_CTRL))
			goto try;
	}

	rnp_mbx_link_event_enable(adapter->eth_dev, true);
	tsrn10_eth_wr(hw, TSRN10_RX_FC_ENABLE, 1);

	memset(&rule, 0, sizeof(rule));
	rule.queue = 0;
	rule.param.action = TSRN10_FILTER_PASS;
	tsrn10_set_unknow_packet_rule(adapter->eth_dev, &rule);

	/* Workaround For Hardware Tx Hang */
	for (idx = 0; idx < TSRN10_MAX_RX_QUEUE_NUM; idx++)
		tsrn10_dma_wr(hw,
				TSRN10_DMA_TXQ_START(idx), true);
	hw->mbx.irq_enabled = true;
	rte_intr_enable(intr_handle);
#ifdef RTE_LIBRTE_PMD_TSRN10_NO_IRQ
	system_no_interrupt = 1;
#endif
	if (system_no_interrupt) {
		/* no intr multiplex */
		hw->mbx.irq_enabled = false;
		rnp_mbx_link_event_enable(adapter->eth_dev, false);
		rte_intr_disable(intr_handle);
		rte_intr_callback_unregister(intr_handle,
				tsrn10_dev_interrupt_handler, dev);
	}
	ret = tsrn10_post_handle(adapter);
	if (ret)
		return ret;

	return 0;
error:
	return ret;
}

static int tsrn10_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(eth_dev);

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;


	if (port && !port->port_closed)
		tsrn10_dev_close(port->dev);

	return 0;
}

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION

static int tsrn10_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			    struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *eth_dev;
	int ret;

	eth_dev = rte_eth_dev_pci_allocate(pci_dev,
			sizeof(struct tsrn10_eth_port));

	if (eth_dev == NULL)
		return -ENOMEM;

	ret = tsrn10_nic_init(eth_dev);

	return ret;
}

static int tsrn10_pci_remove(struct rte_pci_device *pci_dev)
{
	struct tsrn10_eth_adapter *adapter;
	struct tsrn10_eth_port *port;
	struct rte_eth_dev *eth_dev;
	struct tsrn10_hw *hw;
	uint16_t idx;

	eth_dev = rte_eth_dev_allocated(pci_dev->device.name);
	if (!eth_dev)
		return 0;
	adapter = TSRN10_DEV_TO_ADAPTER(eth_dev);
	hw = TSRN10_DEV_TO_HW(eth_dev);
	tsrn10_dma_wr(hw, TSRN10_FIRMWARE_SYNC,
			TSRN10_DRIVER_REMOVE);
	for (idx = 0; idx < adapter->num_ports; idx++) {
		port = adapter->port[idx];
		if (port) {
			tsrn10_dev_uninit(port->dev);
#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
			rte_eth_dev_release_port(port->dev);
#endif
		}
	}
	if (adapter->hw.cookie_pool)
		rte_free(adapter->hw.cookie_pool);

	return 0;
}

static struct rte_pci_driver rte_tsrn10_pmd = {
	.id_table   = pci_id_tsrn10_map,
	.drv_flags  = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe      = tsrn10_pci_probe,
	.remove     = tsrn10_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_tsrn10, rte_tsrn10_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_tsrn10, pci_id_tsrn10_map);
RTE_PMD_REGISTER_KMOD_DEP(net_tsrn10, "* igb_uio | vfio-pci");

#ifdef RTE_PARSE_ARGS_SUPPORTED
RTE_PMD_REGISTER_PARAM_STRING(net_tsrn10,
		TSRN10_HW_MAC_LOOPBACK_ARG "=1 "
		TSRN10_FW_UPDATE "=<filename> "
		TSRN10_FW_FORCE_SPEED_1G "=on|off ");
#endif

RTE_INIT(tsrn10_pmd_init_log)
{
	tsrn10_logtype_pmd = rte_log_register("pmd.net.tsrn10");
	if (tsrn10_logtype_pmd >= 0)
		rte_log_set_level(tsrn10_logtype_pmd, RTE_LOG_NOTICE);
#ifdef RTE_LIBRTE_TSRN10_DEBUG
	if (tsrn10_logtype_pmd >= 0)
		rte_log_set_level(tsrn10_logtype_pmd, RTE_LOG_DEBUG);
#endif
}
#else
static struct eth_driver rte_tsrn10_pmd = {
	.pci_drv = {
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
		.name = "rte_tsrn10_pmd",
#endif
		.id_table = pci_id_tsrn10_map,
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
	.eth_dev_init = tsrn10_nic_init,
	.eth_dev_uninit = tsrn10_dev_uninit,
	.dev_private_size = sizeof(struct tsrn10_eth_port),
};

#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
RTE_PMD_REGISTER_PCI(net_tsrn10, rte_tsrn10_pmd.pci_drv);
RTE_PMD_REGISTER_PCI_TABLE(net_tsrn10, pci_id_tsrn10_map);
#if RTE_VERSION_NUM(17, 2, 0, 16) == RTE_VERSION
/* RTE_VERSION = 17.02 */
RTE_PMD_REGISTER_KMOD_DEP(net_tsrn10, "* igb_uio | uio_pci_generic | vfio");
#endif
#else /* RTE_VERSION < 16.04 */
static int
/*
 * Driver initialization routine.
 * Invoked once at EAL init time.
 * Register itself as the [Poll Mode] Driver of PCI TSRN10 devices.
 */
rte_tsrn10_pmd_init(const char *name __rte_unused,
		    const char *params __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	rte_eth_driver_register(&rte_tsrn10_pmd);
	return 0;
}
static struct rte_driver rte_tsrn10_driver = {
	.type = PMD_PDEV,
	.init = rte_tsrn10_pmd_init,
};
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
PMD_REGISTER_DRIVER(rte_tsrn10_driver);
#else
PMD_REGISTER_DRIVER(rte_tsrn10_driver, tsrn10);
DRIVER_REGISTER_PCI_TABLE(tsrn10, pci_id_tsrn10_map);
#endif
#endif /* <= 16.04 */

#endif
