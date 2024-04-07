#include <time.h>
#include <sys/time.h>
#include <stdint.h>

#include <rte_time.h>
#include "tsrn10.h"
#include "base/tsrn10_mac_regs.h"
#include "tsrn10_ptp.h"

#define PTP_PROTOCOL	(0x88F7)
struct clock_id {
	uint8_t id[8];
};

struct port_id {
	struct clock_id	clock_id;
	uint16_t	port_number;
}  __attribute__((packed));

struct ptp_header {
	uint8_t		msg_type;
	uint8_t		ver;
	uint16_t	message_length;
	uint8_t		domain_number;
	uint8_t		reserved1;
	uint8_t		flag_field[2];
	int64_t		correction;
	uint32_t	reserved2;
	struct port_id	source_port_id;
	uint16_t	seq_id;
	uint8_t		control;
	int8_t		log_message_interval;
} __attribute__((packed));

static inline uint64_t
div_u64_rem(uint64_t dividend, uint32_t divisor, uint32_t *remainder)
{
	*remainder = dividend % divisor;

	return dividend / divisor;
}

static inline uint64_t
div_u64(uint64_t dividend, uint32_t divisor)
{
	uint32_t remainder;

	return div_u64_rem(dividend, divisor, &remainder);
}

#ifdef PTP_DEBUG
static void tsrn10_print_human_timestamp(uint64_t ns, const char *direct)
{
	struct timespec net_time;
	time_t ts;

	net_time = rte_ns_to_timespec(ns);
	ts = net_time.tv_sec;

	printf("[%s] %.24s %.9ld ns\n", direct, ctime(&ts), net_time.tv_nsec);
}
#endif

void tsrn10_rx_get_timestamp(struct rte_mbuf *m, struct tsrn10_rx_queue *rxq)
{
	struct tsrn10_eth_port *port =
		TSRN10_DEV_TO_PORT(&rte_eth_devices[rxq->attr.rte_pid]);
	struct timespec ts_info;
	struct timespec *ts;
	uint64_t timestamp;

	/* because of rx hwstamp store before the mac head
	 * skb->head and skb->data is point to same location when call alloc_skb
	 * so we must move 16 bytes the skb->data to the mac head location
	 * but for the head point if we need move the skb->head need to be diss
	 * low8bytes is null high8bytes is timestamp
	 * high32bit is seconds low32bits is nanoseconds
	 */
#define TSRN10_RX_PTP_TM_PAD	(16)
	ts = (struct timespec *)rte_pktmbuf_mtod_offset(m, uint64_t *,
			TSRN10_RX_TIME_RESERVE);
	m->data_off += TSRN10_RX_HWTS_OFFSET;
	ts_info.tv_sec = rte_be_to_cpu_32(ts->tv_sec);
	ts_info.tv_nsec = rte_be_to_cpu_32(ts->tv_nsec);
	timestamp = rte_timespec_to_ns(&ts_info);

	m->data_len -= TSRN10_RX_PTP_TM_PAD;
	m->pkt_len -= TSRN10_RX_PTP_TM_PAD;
#ifdef PTP_DEBUG
	tsrn10_print_human_timestamp(m->timestamp, "RX");
#endif
	if (rxq->timestamp_all) {
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION && \
    RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
		m->ol_flags |= PKT_RX_TIMESTAMP;
		m->timestamp = timestamp;
#else
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		if (tsrn10_timestamp_dynflag) {
			*RTE_MBUF_DYNFIELD(m,
					(tsrn10_timestamp_dynfield_offset),
					rte_mbuf_timestamp_t *) = timestamp;
			m->ol_flags |= tsrn10_timestamp_dynflag;
		}
#endif
#endif
	}
	if (!(m->packet_type & RTE_PTYPE_L3_MASK) &&
			rxq->ptp_en) {
		m->packet_type |= RTE_PTYPE_L2_ETHER_TIMESYNC;
		m->ol_flags |= RTE_MBUF_F_RX_IEEE1588_PTP |
			RTE_MBUF_F_RX_IEEE1588_TMST;
		m->packet_type &= ~RTE_PTYPE_L2_ETHER;
		rte_atomic64_set(&port->ptp_sync_timestamp,
				timestamp);
	}
}

static void tsrn10_get_systime(struct tsrn10_hw *hw, uint8_t p_id, uint64_t *systime)
{
	uint64_t ns;

	/* Get the TSSS value */
	ns = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_SYS_TIME_NANOSEC_CFG);
	/* Get the TSS and convert sec time value to nanosecond */
	ns += tsrn10_mac_rd(hw, p_id, TSRN10_MAC_SYS_TIME_SEC_CFG) * 1000000000ULL;

	if (systime)
		*systime = ns;
}

static void tsrn10_cfg_mac_irq_en(struct tsrn10_hw *hw, uint8_t p_id, uint8_t on)
{
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_INTERRUPT_ENABLE, on);
}

static int tsrn10_cfg_addend(struct tsrn10_hw *hw, uint8_t p_id, u32 addend)
{
	u32 value;
	int limit;

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_TS_ADDEND, addend);
	/* issue command to update the addend value */
	value = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL);
	value |= TSRN10_PTP_TCR_TSADDREG;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_TS_CTRL, value);

	/* wait for present addend update to complete */
	limit = 10;
	while (limit--) {
		if (!(tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL) & TSRN10_PTP_TCR_TSADDREG))
			break;
		rte_delay_ms(10);
	}
	if (limit < 0)
		return -EBUSY;

	return 0;
}

/* PTP and HW Timer ops */
static void tsrn10_cf_hw_tstamp(struct tsrn10_hw *hw, uint8_t p_id, uint32_t data)
{
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_TS_CTRL, data);
}

static void tsrn10_cfg_sub_sec_increment(struct tsrn10_hw *hw, uint8_t p_id,
					 uint32_t ptp_clock, uint32_t *ssinc)
{
	u32 value = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL);
	unsigned long data;
	u32 reg_value;

	/* in "fine adjustement mode" set sub-second
	 * increment to twice the number of nanoseconds of a clock cycle.
	 * The calculation of the default_addend value by the caller will set it
	 * to mid-range = 2^31 when the remainder of this division is zero,
	 * which will make the accumulator overflow once every 2 ptp_clock
	 * cycles, adding twice the number of nanoseconds of a clock cycle :
	 * 2000000000ULL / ptp_clock.
	 */
	if (ptp_clock == 0) {
		TSRN10_PMD_LOG(ERR, "%s:%dthis is a bug that the syskernel "
			       "clock is zero\n", __func__, __LINE__);
		return;
	}
	if (value & TSRN10_PTP_TCR_TSCFUPDT)
		data = (2000000000ULL / ptp_clock);
	else
		data = (1000000000ULL / ptp_clock);

	/* 0.465ns accuracy */
	if (!(value & TSRN10_PTP_TCR_TSCTRLSSR))
		data = (data * 1000) / 465;

	data &= TSRN10_PTP_SSIR_SSINC_MASK;

	reg_value = data;

	reg_value <<= TSRN10_PTP_SSIR_SSINC_SHIFT;

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_SUB_SECOND_INCREMENT, reg_value);

	if (ssinc)
		*ssinc = data;
}

static int
tsrn10_init_systime(struct tsrn10_hw *hw, uint8_t p_id,
		    uint32_t sec, uint32_t nsec)
{
	uint32_t try_time = 1000;
	u32 value;

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_SYS_TIME_SEC_UPDATE, sec);
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_SYS_TIME_NANOSEC_UPDATE, nsec);
	/* issue command to initialize the system time value */
	value = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL);
	value |= TSRN10_PTP_TCR_TSINIT;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_TS_CTRL, value);

	/* wait for present system time initialize to complete */
	while (try_time-- &&
			(tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL) &
			 TSRN10_PTP_TCR_TSINIT))
		rte_delay_us(10000);
	if (try_time)
		return 0;
	else
		return -EINVAL;
}

static int tsrn10_adjust_systime(struct tsrn10_hw *hw, uint8_t p_id,
				 uint32_t sec, uint32_t nsec,
				 int add_sub)
{
	uint32_t value;
	int limit;

	if (add_sub) {
		/* If the new sec value needs to be subtracted with
		 * the system time, then TSRN10_MAC_STSUR reg should be
		 * programmed with (2^32 – <new_sec_value>)
		 */
		sec = -sec;

		value = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL);
		if (value & TSRN10_PTP_TCR_TSCTRLSSR)
			nsec = (PTP_DIGITAL_ROLLOVER_MODE - nsec);
		else
			nsec = (PTP_BINARY_ROLLOVER_MODE - nsec);
	}

	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_SYS_TIME_SEC_UPDATE, sec);
	value = (add_sub << PTP_STNSUR_ADDSUB_SHIFT) | nsec;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_SYS_TIME_NANOSEC_UPDATE, value);

	/* issue command to initialize the system time value */
	value = tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL);
	value |= TSRN10_PTP_TCR_TSUPDT;
	tsrn10_mac_wr(hw, p_id, TSRN10_MAC_TS_CTRL, value);

	/* wait for present system time adjust/update to complete */
	limit = 10;
	while (limit--) {
		if (!(tsrn10_mac_rd(hw, p_id, TSRN10_MAC_TS_CTRL) &
					TSRN10_PTP_TCR_TSUPDT))
			break;
		rte_delay_ms(10);
	}
	if (limit < 0)
		return -EBUSY;

	return 0;
}

const struct tsrn10_hwtimestamp ptp_api = {
	.cfg_hw_tstamp = tsrn10_cf_hw_tstamp,
	.cfg_sub_sec_increment = tsrn10_cfg_sub_sec_increment,
	.cfg_mac_irq_enable = tsrn10_cfg_mac_irq_en,
	.init_systime = tsrn10_init_systime,
	.cfg_addend = tsrn10_cfg_addend,
	.adjust_systime = tsrn10_adjust_systime,
	.get_systime = tsrn10_get_systime,
};

void tsrn10_ptp_init(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	port->ptp.hwts_ops = ptp_api;
	port->ptp.clk_ptp_rate = 60000000;/* 60Mhz */
}

int tsrn10_timesync_enable(struct rte_eth_dev *dev)
{
	struct tsrn10_ptp_info *ptp = TSRN10_DEV_TO_PTP_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	struct timespec now;
	uint32_t sec_inc = 0;
	uint64_t temp = 0;
	uint32_t reg;

	/* 1.Mask the Timestamp Trigger interrupt */
	ptp->hwts_ops.cfg_mac_irq_enable(hw, p_id, false);
	/* 2.enable time stamping */
	/* 2.1 clear all bytes about time ctrl reg
	 * Setup Default PTP Work mode
	 */
	ptp->hwts_ops.cfg_hw_tstamp(hw, p_id, 0);
	reg = TSRN10_PTP_TCR_TSENA | TSRN10_PTP_TCR_TSCFUPDT |
		TSRN10_PTP_TCR_TSCTRLSSR | TSRN10_PTP_TCR_TSENALL;
#if 0
	/* Only Snapshot Timestamp L2 ether 802.1AS Event Packet */
	reg |= TSRN10_PTP_TCR_TSVER2ENA | TSRN10_PTP_TCR_TSIPENA |
		TSRN10_PTP_TCR_TSIPENA | TSRN10_PTP_TCR_TSEVNTENA;
#endif

	ptp->hwts_ops.cfg_hw_tstamp(hw, p_id, reg);
	/* 3.Program the PTPclock frequency */
	/* program Sub Second Increment reg */
	ptp->hwts_ops.cfg_sub_sec_increment(hw,
			p_id,
			ptp->clk_ptp_rate,
			&sec_inc);
	/* 4.If use fine correction approach then,
	 * Program MAC_Timestamp_Addend register
	 */
	if (sec_inc == 0) {
		TSRN10_PMD_LOG(ERR, "%s:%d the sec_inc is zero this is a bug\n",
				__func__, __LINE__);
		return -EFAULT;
	}
	temp = div_u64(1000000000ULL, sec_inc);
	/* Store sub second increment and flags for later use */
	ptp->sub_second_inc = sec_inc;
	/* calculate default added value:
	 * formula is :
	 * addend = (2^32)/freq_div_ratio;
	 * where, freq_div_ratio = 1e9ns/sec_inc
	 */
	temp = (u64)(temp << 32);
	if (ptp->clk_ptp_rate == 0) {
		ptp->clk_ptp_rate = 1000;
		TSRN10_PMD_LOG(ERR, "%s:%d clk_ptp_rate is zero\n",
				__func__, __LINE__);
	}

	ptp->default_addend = div_u64(temp, ptp->clk_ptp_rate);

	ptp->hwts_ops.cfg_addend(hw, p_id, ptp->default_addend);
	/* 5.Poll wait for the TCR Update Addend Register*/
	/* 6.enabled Fine Update method */
	/* 7.program the second and nanosecond register*/
	/*TODO If we need to enable one-step timestamp */

	/* initialize system time */
	/* lower 32 bits of tv_sec are safe until y2106 */
	clock_gettime(CLOCK_REALTIME, &now);
#ifdef PTP_DEBUG
	tsrn10_print_human_timestamp(rte_timespec_to_ns(&now),
			"Debug_init");
#endif
	ptp->hwts_ops.init_systime(hw, p_id,
			(uint32_t)now.tv_sec, now.tv_nsec);

	ptp->hwts_ops.cfg_mac_irq_enable(hw, p_id, true);

	return 0;
}

int tsrn10_timesync_disable(struct rte_eth_dev *dev)
{
	struct tsrn10_ptp_info *ptp = TSRN10_DEV_TO_PTP_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	/* Disable Timestamp For All Type Pkts*/
	ptp->hwts_ops.cfg_hw_tstamp(hw, p_id, 0);
	/* Disable Time Update Addend */
	ptp->hwts_ops.cfg_addend(hw, p_id, 0);

	return 0;
}

static int
tsrn10_ptp_adjfreq(struct tsrn10_hw *hw, uint8_t p_id,
		   struct tsrn10_ptp_info *ptp, int32_t delta)
{
	uint32_t diff, addend;
	int neg_adj = 0;
	uint64_t adj;

	if (delta < 0) {
		neg_adj = 1;
		delta = -delta;
	}
	addend = ptp->default_addend;
	adj = addend;
	adj *= delta;
	diff = div_u64(adj, 1000000000ULL);
	addend = neg_adj ? (addend - diff) : (addend + diff);

	return ptp->hwts_ops.cfg_addend(hw, p_id, addend);
}

int tsrn10_timesync_adjust_time(struct rte_eth_dev *dev, int64_t delta)
{
	struct tsrn10_ptp_info *ptp = TSRN10_DEV_TO_PTP_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint32_t quotient, reminder;
	uint32_t sec, nsec;
	int neg_adj = 0;

	if (delta < 0) {
		neg_adj = 1;
		delta = -delta;
	}
	if (!delta)
		return 0;

	quotient = div_u64_rem(delta, 1000000000ULL, &reminder);
	sec = quotient;
	nsec = reminder;
	ptp->hwts_ops.adjust_systime(hw, p_id, sec, nsec, neg_adj);
	/* Need TO adjust The Freq ? */
	tsrn10_ptp_adjfreq(hw, p_id, ptp, delta);

	return 0;
}

int tsrn10_timesync_write_time(struct rte_eth_dev *dev,
			       const struct timespec *ts)
{
	struct tsrn10_ptp_info *ptp = TSRN10_DEV_TO_PTP_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);

#ifdef PTP_DEBUG
	tsrn10_print_human_timestamp(rte_timespec_to_ns(ts),
			"write_time_api_change");
#endif
	return ptp->hwts_ops.init_systime(hw, p_id, ts->tv_sec, ts->tv_nsec);
}

int tsrn10_timesync_read_time(struct rte_eth_dev *dev,
			      struct timespec *timestamp)
{
	struct tsrn10_ptp_info *ptp = TSRN10_DEV_TO_PTP_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint64_t systime;

	if (timestamp) {
		ptp->hwts_ops.get_systime(hw, p_id, &systime);
		*timestamp = rte_ns_to_timespec(systime);
#ifdef PTP_DEBUG
		tsrn10_print_human_timestamp(rte_timespec_to_ns(timestamp),
				"read_time_api");
#endif
	}

	return 0;
}

int tsrn10_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
				      struct timespec *timestamp)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t p_id = TSRN10_DEV_TO_PORT_ID(dev);
	uint64_t nanosec, sec;
	uint64_t ns;

	if (tsrn10_eth_rd(hw, TSRN10_ETH_PTP_TX_TS_ST(p_id)) & 0x01) {
		/* read and add nsec, sec turn to nsec*/

		nanosec = tsrn10_eth_rd(hw, TSRN10_ETH_PTP_TX_LTIMES(p_id));
		sec = tsrn10_eth_rd(hw, TSRN10_ETH_PTP_TX_HTIMES(p_id));
		/* when we read the timestamp finish need to notice the hardware
		 * that the timestamp need to update via set tx_hwts_clear-reg
		 * from high to low
		 */
		tsrn10_eth_wr(hw, TSRN10_ETH_PTP_TX_CLEAR(p_id),
				PTP_GET_TX_HWTS_FINISH);
		tsrn10_eth_wr(hw, TSRN10_ETH_PTP_TX_CLEAR(p_id),
				PTP_GET_TX_HWTS_UPDATE);
		rte_wmb();
		ns = nanosec & PTP_HWTX_TIME_VALUE_MASK;
		ns += (sec & PTP_HWTX_TIME_VALUE_MASK) * 1000000000ULL;
		if (timestamp)
			*timestamp = rte_ns_to_timespec(ns);
#ifdef PTP_DEBUG
		tsrn10_print_human_timestamp(rte_timespec_to_ns(timestamp),
				"Read_TxSYNC_api");
#endif

		return 0;
	}
	return -EINVAL;
}

int tsrn10_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
				      struct timespec *timestamp,
				      uint32_t flags __rte_unused)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint64_t ns;

	ns = rte_atomic64_read(&port->ptp_sync_timestamp);
	if (ns) {
		*timestamp = rte_ns_to_timespec(ns);
#ifdef PTP_DEBUG
		tsrn10_print_human_timestamp(rte_timespec_to_ns(timestamp),
				"Read_RxSYNC_api");
#endif

		rte_atomic64_set(&port->ptp_sync_timestamp, 0);

		return 0;
	}

	return -EINVAL;
}
