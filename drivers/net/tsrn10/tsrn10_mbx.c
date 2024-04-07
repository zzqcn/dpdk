#include <rte_cycles.h>

#include "tsrn10.h"
#include "tsrn10_mbx.h"
#include "tsrn10_mbx_fw.h"

#define RNP_MAX_VF_FUNCTIONS 64

/* #define MBX_RD_DEBUG */
/* #define MBX_WR_DEBUG */

#define dbg printf


/* == VEC == */
#define VF2PF_MBOX_VEC(VF) (0xa5100 + 4 * (VF))
#define CPU2PF_MBOX_VEC    (0xa5300)

/* == PF <--> VF mailbox ==== */
#define SHARE_MEM_BYTES     (64)	/* 64bytes */
/* for PF1 rtl will remap 6000 to 0xb000 */
#define PF_VF_SHM(vf)       ((0xa6000) + (64 * (vf)))
#define PF2VF_COUNTER(vf)   (PF_VF_SHM(vf) + 0)
#define VF2PF_COUNTER(vf)   (PF_VF_SHM(vf) + 4)
#define PF_VF_SHM_DATA(vf)  (PF_VF_SHM(vf) + 8)
#define PF2VF_MBOX_CTRL(vf) ((0xa7100) + (4 * (vf)))
#define PF_VF_MBOX_MASK_LO  ((0xa7200))
#define PF_VF_MBOX_MASK_HI  ((0xa7300))

/* === CPU <--> PF === */
#define CPU_PF_SHM       (0xaa000)
#define CPU2PF_COUNTER   (CPU_PF_SHM + 0)
#define PF2CPU_COUNTER   (CPU_PF_SHM + 4)
#define CPU_PF_SHM_DATA  (CPU_PF_SHM + 8)
#define PF2CPU_MBOX_CTRL (0xaa100)
#define CPU_PF_MBOX_MASK (0xaa300)

/* === CPU <--> VF === */
#define CPU_VF_SHM(vf) (0xa8000 + (64 * (vf)))
#define CPU2VF_COUNTER(vf) (CPU_VF_SHM(vf) + 0)
#define VF2CPU_COUNTER(vf) (CPU_VF_SHM(vf) + 4)
#define CPU_VF_SHM_DATA(vf) (CPU_VF_SHM(vf) + 8)
#define VF2CPU_MBOX_CTRL(vf) (0xa9000 + 64 * (vf))
#define CPU_VF_MBOX_MASK_LO(vf) (0xa9200 + 64 * (vf))
#define CPU_VF_MBOX_MASK_HI(vf) (0xa9300 + 64 * (vf))


#define MBOX_CTRL_REQ (1 << 0)  /* WO */
/* VF:WR, PF:RO */
/* #define MBOX_CTRL_VF_HOLD_SHM       (1 << 2) */
#define MBOX_CTRL_PF_HOLD_SHM (1 << 3)  /* VF:RO, PF:WR */
/* for pf <--> cpu */
/* #define MBOX_CTRL_PF_CPU_HOLD_SHM   (1 << 3) */

#define MBOX_IRQ_EN      0
#define MBOX_IRQ_DISABLE 1

/****************************PF MBX OPS************************************/

static inline u16 rnp_mbx_get_req(struct tsrn10_hw *hw, int reg)
{
	rte_mb();
	return mbx_rd32(hw, reg) & 0xffff;
}

static inline u16 rnp_mbx_get_ack(struct tsrn10_hw *hw, int reg)
{
	rte_mb();
	return (mbx_rd32(hw, reg) >> 16) & 0xffff;
}

static inline void rnp_mbx_inc_pf_req(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	int reg = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_COUNTER : PF2VF_COUNTER(mbx_id);
	u32 v = mbx_rd32(hw, reg);
	u16 req;

	req = (v & 0xffff);
	req++;
	v &= ~(0x0000ffff);
	v |= req;

	rte_mb();
	mbx_wr32(hw, reg, v);

	/* update stats */
	/* hw->mbx.stats.msgs_tx++; */
}

static inline void rnp_mbx_inc_pf_ack(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	int reg = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_COUNTER : PF2VF_COUNTER(mbx_id);
	u32 v = mbx_rd32(hw, reg);
	u16 ack;

	ack = (v >> 16) & 0xffff;
	ack++;
	v &= ~(0xffff0000);
	v |= (ack << 16);

	rte_mb();
	mbx_wr32(hw, reg, v);

	/* update stats */
	/* hw->mbx.stats.msgs_rx++; */
}

/**
 *  rnp_poll_for_msg - Wait for message notification
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification
 **/
static int32_t rnp_poll_for_msg(struct rte_eth_dev *dev, enum MBX_ID mbx_id)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	if (!countdown || !ops->check_for_msg)
		goto out;

	while (countdown && ops->check_for_msg(hw, mbx_id)) {
		countdown--;
		if (!countdown)
			break;
		rte_delay_us_block(mbx->usec_delay);
	}

out:
	return countdown ? 0 : -ETIME;
}

/**
 *  rnp_poll_for_ack - Wait for message acknowledgment
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message acknowledgment
 **/
static int32_t rnp_poll_for_ack(struct rte_eth_dev *dev, enum MBX_ID mbx_id)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	if (!countdown || !ops->check_for_ack)
		goto out;

	while (countdown && ops->check_for_ack(hw, mbx_id)) {
		countdown--;
		if (!countdown)
			break;
		rte_delay_us_block(mbx->usec_delay);
	}

out:
	return countdown ? 0 : -ETIME;
}

/**
 *  rnp_read_posted_mbx - Wait for message notification and receive message
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification and
 *  copied it into the receive buffer.
 **/
static int32_t
tsrn10_read_posted_mbx_pf(struct rte_eth_dev *dev, u32 *msg, u16 size,
			  enum MBX_ID mbx_id)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;
	int32_t ret_val = -ETIME;

	if (!ops->read || !countdown)
		return -EOPNOTSUPP;

	ret_val = rnp_poll_for_msg(dev, mbx_id);

	/* if ack received read message, otherwise we timed out */
	if (!ret_val)
		return ops->read(hw, msg, size, mbx_id);
	return ret_val;
}

/**
 *  rnp_write_posted_mbx - Write a message to the mailbox, wait for ack
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully copied message into the buffer and
 *  received an ack to that message within delay * timeout period
 **/
static int32_t
tsrn10_write_posted_mbx_pf(struct rte_eth_dev *dev, u32 *msg, u16 size,
			   enum MBX_ID mbx_id)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	int32_t ret_val = -ETIME;

	/* exit if either we can't write or there isn't a defined timeout */
	if (!ops->write || !mbx->timeout)
		goto out;

	/* send msg and hold buffer lock */
	if (ops->write)
		ret_val = ops->write(hw, msg, size, mbx_id);

	/* if msg sent wait until we receive an ack */
	if (!ret_val)
		ret_val = rnp_poll_for_ack(dev, mbx_id);
out:
	return ret_val;
}

/**
 *  rnp_check_for_msg_pf - checks to see if the VF has sent mail
 *  @hw: pointer to the HW structure
 *  @vf_number: the VF index
 *
 *  returns SUCCESS if the VF has set the Status bit or else ERR_MBX
 **/
static int32_t tsrn10_check_for_msg_pf(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	int32_t ret_val = -ETIME;

	if (mbx_id == MBX_CM3CPU) {
		if (rnp_mbx_get_req(hw, CPU2PF_COUNTER) != hw->mbx.cpu_req) {
			ret_val = 0;
			/* hw->mbx.stats.reqs++; */
		}
	} else {
		if (rnp_mbx_get_req(hw, VF2PF_COUNTER(mbx_id)) != hw->mbx.vf_req) {
			ret_val = 0;
			/* hw->mbx.stats.reqs++; */
		}
	}

	return ret_val;
}

/**
 *  rnp_check_for_ack_pf - checks to see if the VF has ACKed
 *  @hw: pointer to the HW structure
 *  @vf_number: the VF index
 *
 *  returns SUCCESS if the VF has set the Status bit or else ERR_MBX
 **/
static int32_t tsrn10_check_for_ack_pf(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	int32_t ret_val = -ETIME;

	if (mbx_id == MBX_CM3CPU) {
		if (rnp_mbx_get_ack(hw, CPU2PF_COUNTER) != hw->mbx.cpu_ack) {
			ret_val = 0;
			/* hw->mbx.stats.acks++; */
		}
	} else {
		if (rnp_mbx_get_ack(hw, VF2PF_COUNTER(mbx_id)) != hw->mbx.vf_ack) {
			ret_val = 0;
			/* hw->mbx.stats.acks++; */
		}
	}

	return ret_val;
}

/**
 *  rnp_obtain_mbx_lock_pf - obtain mailbox lock
 *  @hw: pointer to the HW structure
 *  @mbx_id: the VF index or CPU
 *
 *  return SUCCESS if we obtained the mailbox lock
 **/
static int32_t rnp_obtain_mbx_lock_pf(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	int32_t ret_val = -ETIME;
	int try_cnt = 5000;  /* 500ms */
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_MBOX_CTRL : PF2VF_MBOX_CTRL(mbx_id);

	while (try_cnt-- > 0) {
		/* Take ownership of the buffer */
		mbx_wr32(hw, CTRL_REG, MBOX_CTRL_PF_HOLD_SHM);

		/* reserve mailbox for cm3 use */
		if (mbx_rd32(hw, CTRL_REG) & MBOX_CTRL_PF_HOLD_SHM)
			return 0;
		rte_delay_us_block(100);
	}

	TSRN10_PMD_LOG(WARNING, "%s: failed to get:%d lock\n",
			__func__, mbx_id);
	return ret_val;
}

/**
 *  rnp_write_mbx_pf - Places a message in the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: the VF index
 *
 *  returns SUCCESS if it successfully copied message into the buffer
 **/
static int32_t tsrn10_write_mbx_pf(struct tsrn10_hw *hw, u32 *msg,
				   u16 size, enum MBX_ID mbx_id)
{
	u32 DATA_REG = (mbx_id == MBX_CM3CPU) ?
		CPU_PF_SHM_DATA : PF_VF_SHM_DATA(mbx_id);
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_MBOX_CTRL : PF2VF_MBOX_CTRL(mbx_id);
	int32_t ret_val = 0;
	u32 stat __rte_unused;
	u16 i;

	if (size > RNP_VFMAILBOX_SIZE) {
		TSRN10_PMD_LOG(ERR, "%s: size:%d should <%d\n", __func__,
				size, RNP_VFMAILBOX_SIZE);
		return -EINVAL;
	}

	/* lock the mailbox to prevent pf/vf/cpu race condition */
	ret_val = rnp_obtain_mbx_lock_pf(hw, mbx_id);
	if (ret_val) {
		TSRN10_PMD_LOG(WARNING, "PF[%d] Can't Get Mbx-Lock Try Again\n",
			hw->function);
		return ret_val;
	}

	/* copy the caller specified message to the mailbox memory buffer */
	for (i = 0; i < size; i++) {
#ifdef MBX_WR_DEBUG
		mbx_pwr32(hw, DATA_REG + i * 4, msg[i]);
#else
		mbx_wr32(hw, DATA_REG + i * 4, msg[i]);
#endif
	}

	/* flush msg and acks as we are overwriting the message buffer */
	if (mbx_id == MBX_CM3CPU)
		hw->mbx.cpu_ack = rnp_mbx_get_ack(hw, CPU2PF_COUNTER);
	else
		hw->mbx.vf_ack = rnp_mbx_get_ack(hw, VF2PF_COUNTER(mbx_id));

	rnp_mbx_inc_pf_req(hw, mbx_id);
	rte_mb();

	rte_delay_us(300);

	/* Interrupt VF/CM3 to tell it a message
	 * has been sent and release buffer
	 */
	mbx_wr32(hw, CTRL_REG, MBOX_CTRL_REQ);

	return 0;
}

/**
 *  rnp_read_mbx_pf - Read a message from the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @vf_number: the VF index
 *
 *  This function copies a message from the mailbox buffer to the caller's
 *  memory buffer.  The presumption is that the caller knows that there was
 *  a message due to a VF/CPU request so no polling for message is needed.
 **/
static int32_t tsrn10_read_mbx_pf(struct tsrn10_hw *hw, u32 *msg,
				  u16 size, enum MBX_ID mbx_id)
{
	u32 BUF_REG  = (mbx_id == MBX_CM3CPU) ?
		CPU_PF_SHM_DATA : PF_VF_SHM_DATA(mbx_id);
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_MBOX_CTRL : PF2VF_MBOX_CTRL(mbx_id);
	int32_t ret_val = -EIO;
	u32 stat __rte_unused, i;
	if (size > RNP_VFMAILBOX_SIZE) {
		TSRN10_PMD_LOG(ERR, "%s: size:%d should <%d\n", __func__,
				size, RNP_VFMAILBOX_SIZE);
		return -EINVAL;
	}
	/* lock the mailbox to prevent pf/vf race condition */
	ret_val = rnp_obtain_mbx_lock_pf(hw, mbx_id);
	if (ret_val)
		goto out_no_read;

	/* copy the message from the mailbox memory buffer */
	for (i = 0; i < size; i++) {
#ifdef MBX_RD_DEBUG
		msg[i] = mbx_prd32(hw, BUF_REG + 4 * i);
#else
		msg[i] = mbx_rd32(hw, BUF_REG + 4 * i);
#endif
	}
	mbx_wr32(hw, BUF_REG, 0);

	/* update req. used by rnpvf_check_for_msg_vf  */
	if (mbx_id == MBX_CM3CPU)
		hw->mbx.cpu_req = rnp_mbx_get_req(hw, CPU2PF_COUNTER);
	else
		hw->mbx.vf_req = rnp_mbx_get_req(hw, VF2PF_COUNTER(mbx_id));

	/* this ack maybe too earier? */
	/* Acknowledge receipt and release mailbox, then we're done */
	rnp_mbx_inc_pf_ack(hw, mbx_id);

	rte_mb();

	/* free ownership of the buffer */
	mbx_wr32(hw, CTRL_REG, 0);

out_no_read:

	return ret_val;
}

static void rnp_mbx_reset_pf(struct tsrn10_hw *hw)
{
	int idx __rte_unused, v, i __rte_unused;

	v = mbx_rd32(hw, CPU2PF_COUNTER);
	hw->mbx.cpu_req = v & 0xffff;
	hw->mbx.cpu_ack = (v >> 16) & 0xffff;
	/* release   pf->cm3 buffer lock */
	mbx_wr32(hw, PF2CPU_MBOX_CTRL, 0);

	rte_mb();
	/* enable irq to fw */
	mbx_wr32(hw, CPU_PF_MBOX_MASK, 0);
	/* reset link sync bit */
	tsrn10_wr_reg(hw->dev_dummy, TSRN10_LINK_SYNC_MAGIC);
}

#ifdef USE
static int rnp_mbx_configure_pf(struct tsrn10_hw *hw, int nr_vec, bool enable)
{
	int idx = 0;
	u32 v;

	if (enable) {
		for (idx = 0; idx < RNP_MAX_VF_FUNCTIONS; idx++) {
			v                   = mbx_rd32(hw, VF2PF_COUNTER(idx));
			hw->mbx.vf_req = v & 0xffff;
			hw->mbx.vf_ack = (v >> 16) & 0xffff;

			/* release pf<->vf pfu buffer lock */
			mbx_wr32(hw, PF2VF_MBOX_CTRL(idx), 0);
		}
		/* reset pf->cm3 status */
		v = mbx_rd32(hw, CPU2PF_COUNTER);
		hw->mbx.cpu_req = v & 0xffff;
		hw->mbx.cpu_ack = (v >> 16) & 0xffff;
		/* release   pf->cm3 buffer lock */
		mbx_wr32(hw, PF2CPU_MBOX_CTRL, 0);

		/* allow VF to PF MBX IRQ */
		/* vf to pf req interrupt */
		for (idx = 0; idx < RNP_MAX_VF_FUNCTIONS; idx++)
			mbx_wr32(hw, VF2PF_MBOX_VEC(idx), nr_vec);
		/* allow vf to vectors */
		mbx_wr32(hw, PF_VF_MBOX_MASK_LO, 0);
		/* enable irq */
		mbx_wr32(hw, PF_VF_MBOX_MASK_HI, 0);

		/* bind cm3cpu mbx to irq */
		/* cm3 and VF63 share #63 irq */
		mbx_wr32(hw, CPU2PF_MBOX_VEC, nr_vec);
		/* allow CM3CPU to PF MBX IRQ */
		mbx_wr32(hw, CPU_PF_MBOX_MASK, 0);
	} else {
		/* disable irq */
		mbx_wr32(hw, PF_VF_MBOX_MASK_LO, 0xffffffff);
		/* disable irq */
		mbx_wr32(hw, PF_VF_MBOX_MASK_HI, 0xffffffff);
		/* disable CM3CPU to PF MBX IRQ */
		mbx_wr32(hw, CPU_PF_MBOX_MASK, 0xffffffff);

		/* reset vf->pf status/ctrl */
		for (idx = 0; idx < RNP_MAX_VF_FUNCTIONS; idx++)
			mbx_wr32(hw, PF2VF_MBOX_CTRL(idx), 0);

		/* reset pf->cm3 ctrl */
		mbx_wr32(hw, PF2CPU_MBOX_CTRL, 0);
	}

	return 0;
}
#endif

static int get_pfvfnum(struct tsrn10_hw *hw)
{
	uint32_t addr_mask;
	uint32_t offset;
	uint32_t val;
#define TSRN10_PF_NUM_REG 	(0x75f000)
#define TSRN10_PFVF_SHIFT	(4)
#define TSRN10_PF_SHIFT		(6)
#define TSRN10_PF_BIT_MASK	BIT(6)

	addr_mask = hw->iobar0_len - 1;
	offset = TSRN10_PF_NUM_REG & addr_mask;
	val = tsrn10_rd_reg(hw->iobar0 + offset);

	return val >> TSRN10_PFVF_SHIFT;
}

struct tsrn10_mbx_api tsrn10_mbx_pf_ops = {
	.read		= tsrn10_read_mbx_pf,
	.write		= tsrn10_write_mbx_pf,
	.read_posted	= tsrn10_read_posted_mbx_pf,
	.write_posted	= tsrn10_write_posted_mbx_pf,
	.check_for_msg	= tsrn10_check_for_msg_pf,
	.check_for_ack	= tsrn10_check_for_ack_pf,
};

void tsrn10_init_mbx_ops_pf(struct tsrn10_hw *hw)
{
	struct tsrn10_eth_adapter *adapter = hw->back;
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	struct mbx_req_cookie *cookie;

	mbx->size       = RNP_VFMAILBOX_SIZE;
	mbx->usec_delay = TSRN10_MBX_DELAY_US;
	mbx->timeout	= (TSRN10_MBX_TIMEOUT_SECONDS * 1000 * 1000) /
				mbx->usec_delay;

#ifdef VF_ISO_EN
	if (hw->device_id == TSRN10_DEV_ID_N10G) {
		uint32_t vf_isolat_off = TSRN10_VF_ISOLATE_CTRL &
				(hw->iobar0_len - 1);
		tsrn10_wr_reg(hw->iobar0 + vf_isolat_off, 0);
	}
#endif
	mbx->sriov_st = 0;
	hw->pf_vf_num = get_pfvfnum(hw);
	mbx->vf_num = UINT16_MAX;
	mbx->pf_num = (hw->pf_vf_num & TSRN10_PF_BIT_MASK) >> TSRN10_PF_SHIFT;
	hw->function = mbx->pf_num;
#if RTE_VERSION_NUM(18, 11, 0, 0) > RTE_VERSION
	mbx->ops = tsrn10_mbx_pf_ops;
#endif
	/* Retrieving and storing the HW base address of device */
	tsrn10_reg_offset_init(hw);
	snprintf(hw->cookie_p_name, RTE_MEMZONE_NAMESIZE, "mbx_req_cookie%d_%d",
				hw->function, adapter->eth_dev->data->port_id);
	hw->cookie_pool = tsrn10_memzone_reserve(hw->cookie_p_name,
			sizeof(struct mbx_req_cookie));

	cookie = (struct mbx_req_cookie *)hw->cookie_pool;
	if (cookie) {
		cookie->timeout_ms = 1000;
		cookie->magic = COOKIE_MAGIC;
		cookie->priv_len = TSRN10_MAX_SHARE_MEM;
	}

	rnp_mbx_reset_pf(hw);
}

/****************************VF MBX OPS************************************/

static inline u16 rnpvf_mbx_get_req(struct tsrn10_hw *hw, int reg)
{
	return mbx_rd32(hw, reg) & 0xffff;
}

static inline u16 rnpvf_mbx_get_ack(struct tsrn10_hw *hw, int reg)
{
	return (mbx_rd32(hw, reg) >> 16) & 0xffff;
}

static s32 rnpvf_obtain_mbx_lock_vf(struct tsrn10_hw *hw __rte_unused,
				    enum MBX_ID mbx_id __rte_unused)
{
	/* Lock Mem Is Operate By SW Way */
#if 0
	s32 ret_val = RNP_ERR_MBX;
	u8 vfnum = VFNUM(hw->pf_vf_num);
	u32 CTRL_REG = (mbx_id == MBX_FW) ? VF2CPU_MBOX_CTRL(vfnum) : VF2PF_MBOX_CTRL(vfnum);

	/* Take ownership of the buffer */
	mbx_wr32(hw, CTRL_REG, MBOX_CTRL_VF_HOLD_SHM);

	/* reserve mailbox for vf use */
	if (mbx_rd32(hw, CTRL_REG) & MBOX_CTRL_VF_HOLD_SHM)
		ret_val = 0;
	return ret_val;
#else
	return 0;
#endif
}

static inline void rnpvf_mbx_inc_vfack(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	u16 ack;
	u8 vfnum = VFNUM(hw->pf_vf_num);
	int reg = (mbx_id == MBX_CM3CPU) ?
		VF2CPU_COUNTER(vfnum) : VF2PF_COUNTER(vfnum);
	u32 v = mbx_rd32(hw, reg);

	ack = (v >> 16) & 0xffff;
	ack++;
	v &= ~(0xffff0000);
	v |= (ack << 16);

	mbx_wr32(hw, reg, v);

	/* update stats */
	hw->mbx.stats.msgs_rx++;
}

static inline void rnpvf_mbx_inc_vfreq(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	u16 req;
	u8 vfnum = VFNUM(hw->pf_vf_num);
	int reg = (mbx_id == MBX_FW) ? VF2CPU_COUNTER(vfnum) : VF2PF_COUNTER(vfnum);
	u32 v = mbx_rd32(hw, reg);

	req = (v & 0xffff);
	req++;
	v &= ~(0x0000ffff);
	v |= req;

	mbx_wr32(hw, reg, v);

	/* update stats */
	hw->mbx.stats.msgs_tx++;
}

static s32 tsrn10_check_for_ack_vf(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	s32 ret_val = RNP_ERR_MBX;
	u8 vfnum = VFNUM(hw->pf_vf_num);

	if (mbx_id == MBX_FW) {
		if (rnpvf_mbx_get_ack(hw, CPU2VF_COUNTER(vfnum)) !=
				hw->mbx.cpu_ack) {
			ret_val = 0;
			hw->mbx.stats.acks++;
		}
	} else {
		if (rnpvf_mbx_get_ack(hw, PF2VF_COUNTER(vfnum)) !=
				hw->mbx.pf_ack) {
			ret_val = 0;
			hw->mbx.stats.acks++;
		}
	}

	return ret_val;
}

/**
 *  rnpvf_poll_for_msg - Wait for message notification
 *  @hw: pointer to the HW structure
 *
 *  returns 0 if it successfully received a message notification
 **/
static s32 rnpvf_poll_for_msg(struct rte_eth_dev *dev, bool to_cm3)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	while (countdown && ops->check_for_msg(hw, to_cm3)) {
		countdown--;
		rte_delay_us(mbx->usec_delay);
	}

	/* if we failed, all future posted messages fail until reset */
	if (!countdown) {
		mbx->timeout = 0;
		dbg("%s timeout\n", __func__);
	}

	return countdown ? 0 : RNP_ERR_MBX;
}

/**
 *  rnpvf_poll_for_ack - Wait for message acknowledgment
 *  @hw: pointer to the HW structure
 *
 *  returns 0 if it successfully received a message acknowledgment
 **/
static s32 rnpvf_poll_for_ack(struct rte_eth_dev *dev, enum MBX_ID mbx_id)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	if (!countdown || !ops->check_for_ack)
		goto out;

	while (countdown && ops->check_for_ack(hw, mbx_id)) {
		countdown--;
		rte_delay_us(mbx->usec_delay);
	}

	/* if we failed, all future posted messages fail until reset */
	if (!countdown) {
		mbx->timeout = 0;
		dbg("%s timeout\n", __func__);
	}

	return countdown ? 0 : RNP_ERR_MBX;
out:
	return -EOPNOTSUPP;
}

#ifdef USE
static int32_t
tsrn10_check_for_bit_vf(struct tsrn10_hw *hw __rte_unused,
			uint32_t mask __rte_unused,
			enum MBX_ID mbx_id __rte_unused)
{
	return -1;
}
#endif

static int32_t tsrn10_check_for_msg_vf(struct tsrn10_hw *hw, enum MBX_ID mbx_id)
{
	s32 ret_val = RNP_ERR_MBX;
	u8 vfnum = VFNUM(hw->pf_vf_num);

	if (mbx_id == MBX_FW) {
		if (rnpvf_mbx_get_req(hw, CPU2VF_COUNTER(vfnum)) !=
				hw->mbx.cpu_req) {
			ret_val = 0;
			hw->mbx.stats.reqs++;
		}
	} else {
		if (rnpvf_mbx_get_req(hw, PF2VF_COUNTER(vfnum)) !=
				hw->mbx.pf_req) {
			ret_val = 0;
			hw->mbx.stats.reqs++;
		}
	}

	return ret_val;
}

static int32_t
tsrn10_write_mbx_vf(struct tsrn10_hw *hw, uint32_t *msg, uint16_t blocksize,
		    enum MBX_ID mbx_id)
{
	s32 ret_val;
	u32 i;
	u8 vfnum = VFNUM(hw->pf_vf_num);
	u32 DATA_REG =
		(mbx_id == MBX_FW) ? CPU_VF_SHM_DATA(vfnum) : PF_VF_SHM_DATA(vfnum);
	u32 CTRL_REG =
		(mbx_id == MBX_FW) ? VF2CPU_MBOX_CTRL(vfnum) : VF2PF_MBOX_CTRL(vfnum);

	/* lock the mailbox to prevent pf/vf race condition */
	ret_val = rnpvf_obtain_mbx_lock_vf(hw, mbx_id);
	if (ret_val)
		goto out_no_write;

	/* add mailbox_id [27:21] */
#define VF_NUM_OFFSET (21)
	if (mbx_id != MBX_FW)
		msg[0] |= ((hw->pf_vf_num & 0x3f) << VF_NUM_OFFSET);

	PMD_DRV_LOG(INFO, "VF->PF MSG[0] Is 0x%.2x\n", msg[0]);

	/* copy the caller specified message to the mailbox memory buffer */
	for (i = 0; i < blocksize; i++)
		mbx_wr32(hw, DATA_REG + i * 4, msg[i]);

	/* update acks. used by rnpvf_check_for_ack_vf  */
	if (mbx_id == MBX_FW)
		hw->mbx.cpu_ack = rnpvf_mbx_get_ack(hw, CPU2VF_COUNTER(vfnum));
	else
		hw->mbx.pf_ack = rnpvf_mbx_get_ack(hw, PF2VF_COUNTER(vfnum));
	rnpvf_mbx_inc_vfreq(hw, mbx_id);

	/* Drop VFU and interrupt the PF/CM3 to
	 * tell it a message has been sent
	 */
	mbx_wr32(hw, CTRL_REG, MBOX_CTRL_REQ);

out_no_write:
	return ret_val;
}

static int32_t
tsrn10_read_mbx_vf(struct tsrn10_hw *hw, uint32_t *msg, uint16_t blocksize,
		   enum MBX_ID mbx_id)
{
	s32 ret_val = 0;
	uint16_t i = 0;
	u8 vfnum = VFNUM(hw->pf_vf_num);
	u32 BUF_REG = (mbx_id == MBX_FW) ?
		CPU_VF_SHM_DATA(vfnum) : PF_VF_SHM_DATA(vfnum);
	u32 CTRL_REG = (mbx_id == MBX_FW) ?
		VF2CPU_MBOX_CTRL(vfnum) : VF2PF_MBOX_CTRL(vfnum);

	/* lock the mailbox to prevent pf/vf race condition */
	ret_val = rnpvf_obtain_mbx_lock_vf(hw, mbx_id);
	if (ret_val)
		goto out_no_read;

	/* copy the message from the mailbox memory buffer */
	for (i = 0; i < blocksize; i++)
		msg[i] = mbx_rd32(hw, BUF_REG + 4 * i);
	mbx_wr32(hw, BUF_REG, 0);
	/* clear vf_num */
#define RNP_VF_NUM_MASK (0x7f << 21)
	msg[0] &= (~RNP_VF_NUM_MASK);
	PMD_DRV_LOG(INFO, "pf->vf msg[0] is %x\n", msg[0]);

	/* update req. used by rnpvf_check_for_msg_vf  */
	if (mbx_id == MBX_CM3CPU)
		hw->mbx.cpu_req = rnpvf_mbx_get_req(hw, CPU2VF_COUNTER(vfnum));
	else
		hw->mbx.pf_req = rnpvf_mbx_get_req(hw, PF2VF_COUNTER(vfnum));
	/* Acknowledge receipt and release mailbox, then we're done */
	rnpvf_mbx_inc_vfack(hw, mbx_id);

	/* free ownership of the buffer */
	mbx_wr32(hw, CTRL_REG, 0);

out_no_read:
	return ret_val;
}

static int32_t
tsrn10_pool_read_mbx_vf(struct rte_eth_dev *dev, uint32_t *msg, uint16_t blocksize,
			enum MBX_ID mbx_id)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	s32 ret_val = -RNP_ERR_MBX;

	if (!ops->read)
		goto out;

	ret_val = rnpvf_poll_for_msg(dev, mbx_id);

	/* if ack received read message, otherwise we timed out */
	if (!ret_val) {
		ret_val = ops->read(hw, msg, blocksize, mbx_id);
		TSRN10_PMD_LOG(INFO, "vf[%d] read ret_val %d\n",
				mbx->vf_num, ret_val);
	}
out:
	return ret_val;
}

static int32_t
tsrn10_pool_write_mbx_vf(struct rte_eth_dev *dev, uint32_t *msg,
			 uint16_t blocksize, enum MBX_ID mbx_id)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	s32 ret_val = -RNP_ERR_MBX;

	/* exit if either we can't write or there isn't a defined timeout */
	if (!ops->write || !mbx->timeout)
		goto out;

	/* send msg */
	ret_val = ops->write(hw, msg, blocksize, mbx_id);

	/* if msg sent wait until we receive an ack */
	if (!ret_val)
		ret_val = rnpvf_poll_for_ack(dev, mbx_id);
out:
	return ret_val;
}

struct tsrn10_mbx_api tsrn10_mbx_vf_ops = {
	.read		= tsrn10_read_mbx_vf,
	.write		= tsrn10_write_mbx_vf,
	.read_posted	= tsrn10_pool_read_mbx_vf,
	.write_posted	= tsrn10_pool_write_mbx_vf,
	.check_for_msg	= tsrn10_check_for_msg_vf,
	.check_for_ack	= tsrn10_check_for_ack_vf,
};

void tsrn10_init_mbx_ops_vf(struct tsrn10_hw *hw)
{
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	uint32_t pfvfnum_off, vf_num;

	mbx->size	= TSRN10_VFMBX_SIZE;
	mbx->usec_delay = TSRN10_MBX_DELAY_US;
	mbx->timeout = (TSRN10_MBX_TIMEOUT_SECONDS * 1000 * 1000) /
				mbx->usec_delay;

	pfvfnum_off = TSRN10_VF_NUM & (hw->iobar0_len - 1);
	vf_num = tsrn10_rd_reg(hw->iobar0 + pfvfnum_off);
	hw->mbx.sriov_st = ((vf_num & VF_NUM_MASK_TEMP) >> VF_NUM_OFF);

	mbx->vf_num            = mbx->sriov_st & TSRN10_VF_NB_MASK;
	mbx->pf_num            = mbx->sriov_st & TSRN10_PF_NB_MASK;
	hw->pf_vf_num          = mbx->sriov_st;
#if RTE_VERSION_NUM(18, 11, 0, 0) > RTE_VERSION
	mbx->ops               = tsrn10_mbx_vf_ops;
#endif
	mbx->stats.msgs_tx = 0;
	mbx->stats.msgs_rx = 0;
	mbx->stats.reqs = 0;
	mbx->stats.acks = 0;
	mbx->stats.rsts = 0;
}

int32_t tsrn10_init_hw_vf(struct tsrn10_hw *hw __rte_unused)
{
	return -1;
}

uint64_t tsrn10_get_real_speed(uint32_t speed)
{
	uint64_t real_speed;

	switch (speed) {
	case RNP_LINK_SPEED_100_FULL:
		real_speed = ETH_SPEED_NUM_100M;
		break;
	case RNP_LINK_SPEED_1GB_FULL:
		real_speed = ETH_SPEED_NUM_1G;
		break;
	case RNP_LINK_SPEED_10GB_FULL:
		real_speed = ETH_SPEED_NUM_10G;
		break;
	case RNP_LINK_SPEED_40GB_FULL:
		real_speed = ETH_SPEED_NUM_40G;
		break;
	default:
		real_speed = 0;
	}

	return real_speed;
}

int32_t tsrn10_reset_hw_vf(struct tsrn10_hw *hw)
{
	struct tsrn10vf_eth_adapter *adapter = hw->back;
	struct rte_eth_dev *dev = adapter->port->dev;
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	s32 ret_val = RNP_ERR_INVALID_MAC_ADDR;
	u32 msgbuf[RNP_VF_PERMADDR_MSG_LEN];
	u8 *addr = (u8 *)(&msgbuf[1]);
	u32 feature = 0;
	u32 speed;
	u32 vlan;
	int try_cnt = 3;

	/* reset the api version */
	hw->api_version = 0;

	/* mailbox timeout can now become active */
	mbx->timeout = RNP_VF_MBX_INIT_TIMEOUT;

	while (try_cnt--) {
		msgbuf[0] = RNP_VF_RESET;
		ops->write_posted(dev, msgbuf, 1, false);
		/* ack write back maybe too fast */
		rte_delay_ms(10);

		/* set our "perm_addr" based on info provided by PF */
		/* also set up the mc_filter_type which is piggy backed
		 * on the mac address in word 3
		 */
		ret_val =
			ops->read_posted(dev, msgbuf,
					RNP_VF_PERMADDR_MSG_LEN, false);
		if (!ret_val)
			break;
	}
	if (ret_val)
		return ret_val;

	rte_delay_ms(1000);
	/* New versions of the PF may NACK the reset return message
	 * to indicate that no MAC address has yet been assigned for
	 * the VF.
	 */
	if (msgbuf[0] != (RNP_VF_RESET | RNP_VT_MSGTYPE_ACK) &&
			msgbuf[0] != (RNP_VF_RESET | RNP_VT_MSGTYPE_NACK))
		return RNP_ERR_INVALID_MAC_ADDR;
	/* we get mac address from mailbox */

	memcpy(hw->mac.set_addr, addr, 6);

	/* phy status */
	hw->phy_type = (msgbuf[RNP_VF_PHY_TYPE_WORD] & 0xffff);

	vlan = msgbuf[RNP_VF_VLAN_WORD];
	if (vlan & 0xffff)
		hw->vf_vlan = vlan & 0xffff;

	hw->fw_version = msgbuf[RNP_VF_FW_VERSION_WORD];

	if (msgbuf[RNP_VF_LINK_STATUS_WORD] & RNP_PF_LINK_UP) {
		adapter->link_up = true;
		speed = msgbuf[RNP_VF_LINK_STATUS_WORD] & 0xffff;
		adapter->max_link_speed = tsrn10_get_real_speed(speed);
	} else {
		adapter->link_up = false;
		adapter->max_link_speed = 0;
	}
	feature = msgbuf[RNP_VF_RNP_VF_FEATURE];
	adapter->vlan_change_allow = feature & RNP_VF_RNP_VF_FILTER_EN;
	hw->nic_mode = TSRN10_SINGLE_10G;

	return 0;
}

int32_t tsrn10_get_queue_info_vf(struct rte_eth_dev *dev)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	s32 ret_val = 0;
	u32 msgbuf[6];

	rte_atomic16_set(&mbx->state, TSRN10_STATE_MBX_POLLING);
	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] |= RNP_VF_GET_QUEUES;

	ret_val = ops->write_posted(dev, msgbuf, 1, false);

	rte_delay_ms(10);

	if (!ret_val)
		ret_val = ops->read_posted(dev, msgbuf, 6, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	if (!ret_val && (msgbuf[0] == (RNP_VF_GET_QUEUES | RNP_VT_MSGTYPE_NACK)))
		return -ENOMEM;

#define MSG_TX_NUM_WORD		(1)
#define MSG_RX_NUM_WORD		(2)
#define MSG_RING_BASE_WORD	(5)

	port->attr.queue_ring_base = msgbuf[MSG_RING_BASE_WORD];
	port->attr.max_tx_queues = msgbuf[MSG_TX_NUM_WORD];
	port->attr.max_rx_queues = msgbuf[MSG_RX_NUM_WORD];

	rte_atomic16_set(&mbx->state, 0);

	return 0;
}

int32_t tsrn10_get_mac_addr_vf(struct tsrn10_eth_port *port,
			       uint8_t lane __rte_unused,
			       uint8_t *addr)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(port->dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(port->dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	uint8_t *macaddr = hw->mac.assign_addr;
	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val = 0;

	rte_atomic16_set(&mbx->state, TSRN10_STATE_MBX_POLLING);
	memset(msgbuf, 0, sizeof(msgbuf));
	/*
	 * If index is one then this is the start of a new list and needs
	 * indication to the PF so it can do it's own list management.
	 * If it is zero then that tells the PF to just clear all of
	 * this VF's macvlans and there is no new list.
	 */
	msgbuf[0] |= RNP_VF_GET_MACVLAN;
	ret_val = ops->write_posted(port->dev, msgbuf, 1, false);

	if (!ret_val)
		ret_val = ops->read_posted(port->dev, msgbuf, 3, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	if (!ret_val)
		if (msgbuf[0] == (RNP_VF_GET_MACVLAN | RNP_VT_MSGTYPE_NACK))
			ret_val = -ENOMEM;

	memcpy(macaddr, msg_addr, RTE_ETHER_ADDR_LEN);
	memcpy(addr, macaddr, RTE_ETHER_ADDR_LEN);

	rte_atomic16_set(&mbx->state, 0);

	return ret_val;
}

static void
tsrn10vf_setup_veb_tb(struct tsrn10_eth_port *port, uint8_t *macaddr)
{
	struct tsrn10_hw *hw = TSRN10_PORT_TO_HW_VF(port);
	uint32_t maclow, machi;
	uint16_t vf_id;
	uint16_t ring;
	uint8_t idx;

	vf_id = hw->mbx.vf_num;
	if (!macaddr) {
		TSRN10_PMD_ERR("VF[%d] Set VEB Table Failed\n", vf_id);
		return;
	}
	for (idx = 0; idx < 4; idx++) {
		maclow = (macaddr[2] << 24) | (macaddr[3] << 16) |
			(macaddr[4] << 8) | macaddr[5];
		machi = (macaddr[0] << 8) | macaddr[1];
		tsrn10_dma_wr(hw, TSRN10_VBE_MAC_LO(idx, vf_id), maclow);
		tsrn10_dma_wr(hw, TSRN10_VBE_MAC_HI(idx, vf_id), machi);
		ring = ((RNP_VEB_SWITCH_VF_EN | vf_id) << 8);
		ring |= port->attr.queue_ring_base;
		tsrn10_dma_wr(hw, TSRN10_VEB_VF_RING(idx, vf_id), ring);
	}
}

int32_t tsrn10_set_mac_addr_vf(struct tsrn10_eth_port *port,
			       uint8_t *macaddr, uint8_t vm_pool __rte_unused,
			       uint8_t p_id __rte_unused)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(port->dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(port->dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;

	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val;
	rte_atomic16_set(&mbx->state, TSRN10_STATE_MBX_POLLING);

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNP_VF_SET_MAC_ADDR;
	memcpy(msg_addr, macaddr, 6);
	ret_val = ops->write_posted(port->dev, msgbuf, 3, false);

	if (!ret_val)
		ret_val = ops->read_posted(port->dev, msgbuf, 3, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	rte_atomic16_set(&mbx->state, 0);

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
		(msgbuf[0] == (RNP_VF_SET_MAC_ADDR | RNP_VT_MSGTYPE_NACK))) {
		tsrn10_get_mac_addr_vf(port, port->attr.nr_lane,
					port->mac_addr);
		return -1;
	}
	tsrn10vf_setup_veb_tb(port, macaddr);

	return ret_val;
}

int rnpvf_set_mtu(struct rte_eth_dev *dev, int mtu)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	rte_atomic16_set(&mbx->state, TSRN10_STATE_MBX_POLLING);

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNP_VF_SET_MTU;
	msgbuf[1] = mtu;

	ret_val = ops->write_posted(dev, msgbuf, 2, false);

	if (!ret_val)
		ret_val = ops->read_posted(dev, msgbuf, 2, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
			(msgbuf[0] == (RNP_VF_SET_MTU | RNP_VT_MSGTYPE_NACK))) {
		/* set mtu failed */
		return -1;
	}

	rte_atomic16_set(&mbx->state, 0);

	return ret_val;
}

int
rnpvf_get_max_mtu(struct rte_eth_dev *dev)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	struct tsrn10_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	rte_atomic16_set(&mbx->state, TSRN10_STATE_MBX_POLLING);

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNP_VF_GET_MAX_MTU;

	ret_val = ops->write_posted(dev, msgbuf, 2, false);

	if (!ret_val)
		ret_val = ops->read_posted(dev, msgbuf, 2, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
			(msgbuf[0] == (RNP_VF_SET_MTU | RNP_VT_MSGTYPE_NACK))) {
		/* get mtu failed */
		return -1;
	}
	port->attr.max_mtu = msgbuf[1];
	if (ret_val)
		return ret_val;

	rte_atomic16_set(&mbx->state, 0);

	return 0;
}

int
rnpvf_set_vlan_q_strip(struct rte_eth_dev *dev, uint16_t dma_qid, bool on)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	u32 msgbuf[4];
	s32 err;

	rte_atomic16_set(&hw->mbx.state, TSRN10_STATE_MBX_POLLING);

	memset(msgbuf, 0, sizeof(msgbuf));

	msgbuf[0] = RNP_VF_SET_VLAN_STRIP;
	msgbuf[1] = on ? (TSRN10VF_VLAN_STRIP_EN) : 0;
	msgbuf[1] |= TSRN10VF_OPT_SEL_QUEUE;
	msgbuf[2] = dma_qid;

	err = ops->write_posted(dev, msgbuf, 3,
			false);
	if (err)
		goto mbx_err;
	err = ops->read_posted(dev, msgbuf, 1, false);
	if (err)
		goto mbx_err;

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNP_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNP_VF_SET_VLAN_STRIP | RNP_VT_MSGTYPE_ACK))
		err = -EINVAL;
mbx_err:
	rte_atomic16_set(&hw->mbx.state, 0);

	return err;
}

s32 rnpvf_set_vfta_vf(struct rte_eth_dev *dev, u32 vlan,
		      bool vlan_on)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);
	u32 msgbuf[2];
	s32 err;

	rte_atomic16_set(&hw->mbx.state, TSRN10_STATE_MBX_POLLING);
	msgbuf[0] = RNP_VF_SET_VLAN;
	msgbuf[1] = vlan;
	/* Setting the 8 bit field MSG INFO to TRUE indicates "add" */
	msgbuf[0] |= vlan_on << RNP_VT_MSGINFO_SHIFT;
	err = ops->write_posted(dev, msgbuf, 2, false);
	if (err) {
		PMD_DRV_LOG(ERR, "vlan write_posted failed\n");
		goto mbx_err;
	}

	err = ops->read_posted(dev, msgbuf, 2, false);
	if (err) {
		PMD_DRV_LOG(ERR, "vlan read_posted failed\n");
		goto mbx_err;
	}

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNP_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNP_VF_SET_VLAN | RNP_VT_MSGTYPE_ACK))
		err = -EINVAL;
mbx_err:
	rte_atomic16_set(&hw->mbx.state, 0);

	return err;
}

int tsrn10_get_fw_version_vf(struct tsrn10_hw *hw __rte_unused)
{
	return -1;
}

void
tsrn10vf_get_link_status(struct rte_eth_dev *dev)
{
	struct tsrn10vf_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER_VF(dev);
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW_VF(dev);

	u32 msgbuf[3];
	s32 ret_val = -1;

	rte_atomic16_set(&hw->mbx.state, TSRN10_STATE_MBX_POLLING);
	msgbuf[0] = RNP_VF_GET_LINK;
	ops->write_posted(dev, msgbuf, 1, false);
	rte_delay_ms(2);
	ret_val =
		ops->read_posted(dev, msgbuf, 2, false);
	if (ret_val == 0) {
		if (msgbuf[1] & RNP_PF_LINK_UP) {
			port->attr.link_ready = true;
			adapter->max_link_speed = msgbuf[1] & 0xffff;
		} else {
			port->attr.link_ready = false;
			adapter->max_link_speed = 0;
		}
	} else {
		TSRN10_PMD_LOG(ERR, "tsrn10vf error! mbx GET_LINK failed!\n");
	}
	rte_atomic16_set(&hw->mbx.state, 0);
}
