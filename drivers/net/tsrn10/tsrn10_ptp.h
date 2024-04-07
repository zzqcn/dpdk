#ifndef __TSRN10_PTP_H__
#define __TSRN10_PTP_H__

#include "base/tsrn10_common.h"
/* PTP Timestamp control register defines */
#define TSRN10_PTP_TCR_TSENA		BIT(0)  /*Timestamp Enable*/
#define TSRN10_PTP_TCR_TSCFUPDT		BIT(1)  /* Timestamp Fine/Coarse Update */
#define TSRN10_PTP_TCR_TSINIT		BIT(2)  /* Timestamp Initialize */
#define TSRN10_PTP_TCR_TSUPDT		BIT(3)  /* Timestamp Update */
#define TSRN10_PTP_TCR_TSTRIG		BIT(4)  /* Timestamp Interrupt Trigger Enable */
#define TSRN10_PTP_TCR_TSADDREG		BIT(5)  /* Addend Reg Update */
#define TSRN10_PTP_TCR_TSENALL		BIT(8)  /* Enable Timestamp for All Frames */
#define TSRN10_PTP_TCR_TSCTRLSSR	BIT(9)	/* Digital or Binary Rollover Control */
#define TSRN10_PTP_TCR_TSVER2ENA	BIT(10) /* Enable PTP packet Processing for Version 2 Format */
#define TSRN10_PTP_TCR_TSIPENA		BIT(11) /* Enable Processing of PTP over Ethernet Frames */
#define TSRN10_PTP_TCR_TSIPV6ENA	BIT(12) /* Enable Processing of PTP Frames Sent over IPv6-UDP */
#define TSRN10_PTP_TCR_TSIPV4ENA	BIT(13) /* Enable Processing of PTP Frames Sent over IPv4-UDP */
#define TSRN10_PTP_TCR_TSEVNTENA	BIT(14) /* Enable Timestamp Snapshot for Event Messages */
#define TSRN10_PTP_TCR_TSMSTRENA	BIT(15) /* Enable Snapshot for Messages Relevant to Master */
/* Note 802.1 AS(1588v2) Is work Over Ethernet Frame
 * and 1588v1 Is work Over UDP
 */

/* Select PTP packets for Taking Snapshots
 * On mac specifically:
 * Enable SYNC, Pdelay_Req, Pdelay_Resp when TSEVNTENA is enabled.
 * or
 * Enable  SYNC, Follow_Up, Delay_Req, Delay_Resp, Pdelay_Req, Pdelay_Resp,
 * Pdelay_Resp_Follow_Up if TSEVNTENA is disabled
 */
#define TSRN10_PTP_TCR_SNAPTYPSEL_1	BIT(16)
#define TSRN10_PTP_TCR_TSENMACADDR	BIT(18) /* Enable MAC address for PTP Frame Filtering */
#define TSRN10_PTP_TCR_ESTI		BIT(20) /* External System Time Input Or MAC Internal Clock*/
#define TSRN10_PTP_TCR_AV8021ASMEN	BIT(28) /* AV802.1 AS Mode Enable*/
/*Sub Second increament define */
#define TSRN10_PTP_SSIR_SSINC_MASK	(0xff) /* Sub-second increment value */
#define TSRN10_PTP_SSIR_SSINC_SHIFT	(16)   /* Sub-second increment offset */


#define TSRN10_MAC_TXTSC		BIT(15) /* TX timestamp reg is fill complete */
#define TSRN10_MAC_TXTSSTSLO		GENMASK(30, 0)  /*nano second avalid value  */

#define TSRN10_RX_SEC_MASK		GENMASK(30, 0)
#define TSRN10_RX_NSEC_MASK		GENMASK(30, 0)
#define TSRN10_RX_TIME_RESERVE		(8)
#define TSRN10_RX_SEC_SIZE		(4)
#define TSRN10_RX_NANOSEC_SIZE		(4)
#define TSRN10_RX_HWTS_OFFSET		(TSRN10_RX_SEC_SIZE + \
		TSRN10_RX_NANOSEC_SIZE + TSRN10_RX_TIME_RESERVE)

#define PTP_STNSUR_ADDSUB_SHIFT         (31)
#define PTP_DIGITAL_ROLLOVER_MODE       0x3B9AC9FF
#define PTP_BINARY_ROLLOVER_MODE        0x7FFFFFFF      /* ns */

#define PTP_HWTX_TIME_VALUE_MASK        GENMASK(31, 0)
#define PTP_GET_TX_HWTS_FINISH          (1)
#define PTP_GET_TX_HWTS_UPDATE          (0)
/*hardware ts can't so fake ts from the software clock */
#define DEBUG_PTP_HARD_SOFTWAY

#define TSRN10_PTP_SYNC (0x0)

extern uint64_t tsrn10_timestamp_dynflag;
extern int tsrn10_timestamp_dynfield_offset;

struct tsrn10_hw;

struct tsrn10_hwtimestamp {
	void (*cfg_hw_tstamp)(struct tsrn10_hw *hw, uint8_t p_id, u32 data);
	void (*cfg_sub_sec_increment)(struct tsrn10_hw *hw,
				      uint8_t p_id, u32 ptp_clock, u32 *ssinc);
	void (*cfg_mac_irq_enable)(struct tsrn10_hw *hw,
				   uint8_t p_id, uint8_t on);
	int (*init_systime)(struct tsrn10_hw *hw, uint8_t p_id,
			    u32 sec, u32 nsec);
	int (*cfg_addend)(struct tsrn10_hw *hw, uint8_t p_id, u32 addend);
	int (*adjust_systime)(struct tsrn10_hw *hw, uint8_t p_id,
			      u32 sec, u32 nsec, int add_sub);
	void (*get_systime)(struct tsrn10_hw *hw, uint8_t p_id, u64 *systime);
};

struct tsrn10_rx_queue;
int tsrn10_timesync_write_time(struct rte_eth_dev *dev,
			       const struct timespec *ts);

int tsrn10_timesync_read_time(struct rte_eth_dev *dev,
			      struct timespec *timestamp);
int tsrn10_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
				      struct timespec *timestamp);
int tsrn10_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
				      struct timespec *timestamp,
				      uint32_t flags);
int tsrn10_timesync_adjust_time(struct rte_eth_dev *dev, int64_t delta);
int tsrn10_timesync_disable(struct rte_eth_dev *dev);
int tsrn10_timesync_enable(struct rte_eth_dev *dev);
void tsrn10_ptp_init(struct rte_eth_dev *dev);
void tsrn10_rx_get_timestamp(struct rte_mbuf *m, struct tsrn10_rx_queue *rxq);
#endif /* __TSRN10_PTP_H__*/
