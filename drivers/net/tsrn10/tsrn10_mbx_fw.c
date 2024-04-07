#include <linux/wait.h>
#include <stdio.h>

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
#include <rte_malloc.h>
#include <rte_alarm.h>

#include "tsrn10.h"
#include "tsrn10_mbx.h"
#include "tsrn10_mbx_fw.h"

#define RNP_FW_MAILBOX_SIZE RNP_VFMAILBOX_SIZE

#define dbg_here printf("%s %d\n", __func__, __LINE__)

void *tsrn10_memzone_reserve(const char *name, unsigned int size)
{
#define NO_FLAGS 0
	const struct rte_memzone *mz = NULL;

	if (name) {
		if (size) {
			mz = rte_memzone_reserve(name, size,
					rte_socket_id(), NO_FLAGS);
			if (mz)
				memset(mz->addr, 0, size);
		} else {
			mz = rte_memzone_lookup(name);
		}
		return mz ? mz->addr : NULL;
	}
	return NULL;
}

/* DEFINE_SEMAPHORE(pf_cpu_lock); */

static int rnp_mbx_fw_post_req(struct rte_eth_dev *dev,
			       struct mbx_fw_cmd_req *req,
			       struct mbx_req_cookie *cookie)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int err = 0;
	int timeout_cnt;
#define WAIT_MS 10

	cookie->done = 0;

	rte_spinlock_lock(&hw->fw_lock);

	/* down_interruptible(&pf_cpu_lock); */
	err = ops->write(
		hw, (u32 *)req, (req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		TSRN10_PMD_LOG(ERR, "rnp_write_mbx failed!\n");
		goto quit;
	}

	timeout_cnt = cookie->timeout_ms / WAIT_MS;
	while (timeout_cnt > 0) {
		rte_delay_ms(WAIT_MS);
		timeout_cnt--;
		if (cookie->done)
			break;
	}

quit:
	rte_spinlock_unlock(&hw->fw_lock);
	return err;
}

static int
rnp_mbx_write_posted_locked(struct rte_eth_dev *dev, struct mbx_fw_cmd_req *req)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int err = 0;

	rte_spinlock_lock(&hw->fw_lock);

	err = ops->write_posted(
		dev, (u32 *)req, (req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		TSRN10_PMD_LOG(ERR, "%s failed!\n", __func__);
		goto quit;
	}

quit:
	rte_spinlock_unlock(&hw->fw_lock);
	return err;
}

static int
rnp_fw_send_cmd_wait(struct rte_eth_dev *dev, struct mbx_fw_cmd_req *req,
		     struct mbx_fw_cmd_reply *reply)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int err;

	rte_spinlock_lock(&hw->fw_lock);

	err = ops->write_posted(
		dev, (u32 *)req, (req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		TSRN10_PMD_LOG(
			ERR, "%s: write_posted failed! err:0x%x\n", __func__, err);
		rte_spinlock_unlock(&hw->fw_lock);
		return err;
	}

	err = ops->read_posted(dev, (u32 *)reply, sizeof(*reply) / 4, MBX_FW);
	rte_spinlock_unlock(&hw->fw_lock);
	if (err) {
		TSRN10_PMD_LOG(ERR,
				"%s: read_posted failed! err:0x%x. "
				"req-op:0x%x\n",
				__func__,
				err,
				req->opcode);
		goto err_quit;
	}

	if (reply->error_code) {
		TSRN10_PMD_LOG(ERR,
				"%s: reply err:0x%x. req-op:0x%x\n",
				__func__,
				reply->error_code,
				req->opcode);
		err = -reply->error_code;
		goto err_quit;
	}

	return 0;
err_quit:
	TSRN10_PMD_LOG(ERR,
			"%s:PF[%d]: req:%08x_%08x_%08x_%08x "
			"reply:%08x_%08x_%08x_%08x\n",
			__func__,
			hw->function,
			((int *)req)[0],
			((int *)req)[1],
			((int *)req)[2],
			((int *)req)[3],
			((int *)reply)[0],
			((int *)reply)[1],
			((int *)reply)[2],
			((int *)reply)[3]);

	return err;
}

int rnp_mbx_link_event_enable(struct rte_eth_dev *dev, int enable)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	rte_spinlock_lock(&hw->link_sync);
	if (enable) {
		int v = tsrn10_rd_reg(hw->dev_dummy);
		v &= ~(0xffff0000);
		v |= 0xa5a40000;
		tsrn10_wr_reg(hw->dev_dummy, v);
	} else {
		tsrn10_wr_reg(hw->dev_dummy, 0);
	}
	rte_spinlock_unlock(&hw->link_sync);

	build_link_set_event_mask(
		&req, BIT(EVT_LINK_UP), (enable & 1) << EVT_LINK_UP, &req);

	rte_spinlock_lock(&hw->fw_lock);
	err = ops->write_posted(
		dev, (u32 *)&req, (req.datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	rte_spinlock_unlock(&hw->fw_lock);

	rte_delay_ms(200);
	return err;
}

static int rnp_maintain_req(struct rte_eth_dev *dev,
			    int cmd,
			    int arg0,
			    int req_data_bytes,
			    int reply_bytes,
			    phys_addr_t dma_phy_addr)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_req req;
	int err;

	if (!hw->mbx.irq_enabled)
		return -EIO;
	cookie = tsrn10_memzone_reserve(hw->cookie_p_name, 0);
	if (!cookie)
		return -ENOMEM;
	memset(&req, 0, sizeof(req));
	cookie->timeout_ms = 60 * 1000; /* 60s */

	build_maintain_req(&req,
			cookie,
			cmd,
			arg0,
			req_data_bytes,
			reply_bytes,
			dma_phy_addr & 0xffffffff,
			(dma_phy_addr >> 32) & 0xffffffff);

	err = rnp_mbx_fw_post_req(dev, &req, cookie);

	return (err) ? -EIO : 0;
}

static inline void tsrn10_link_stat_reset(struct tsrn10_hw *hw, uint16_t lane)
{
	uint32_t state;

	rte_spinlock_lock(&hw->link_sync);
	state = tsrn10_rd_reg(hw->dev_dummy);
	state &= ~0xffff0000;
	state |= 0xa5a40000;
	state &= ~BIT(lane);

	tsrn10_wr_reg(hw->dev_dummy, state);
	rte_spinlock_unlock(&hw->link_sync);
}

int rnp_mbx_ifup_down(struct rte_eth_dev *dev, int nr_lane, int up)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_ifup_down(&req, nr_lane, up);

	rte_spinlock_lock(&hw->fw_lock);
	err = ops->write_posted(
		dev, (u32 *)&req, (req.datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	rte_spinlock_unlock(&hw->fw_lock);
	/* force firmware send irq event to dpdk */
	if (!err && up)
		tsrn10_link_stat_reset(hw, nr_lane);
	return err;
}

static int rnp_mbx_sfp_read(struct rte_eth_dev *dev,
			    int nr_lane,
			    int sfp_i2c_addr,
			    int reg,
			    int cnt,
			    char *out_buf)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err = -EIO;

	if (cnt > MBX_SFP_READ_MAX_CNT || !out_buf) {
		TSRN10_PMD_LOG(ERR,
				"%s: cnt:%d should <= %d out_buf:%p\n",
				__func__,
				cnt,
				MBX_SFP_READ_MAX_CNT,
				out_buf);
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));

	if (hw->mbx.irq_enabled) {
		cookie = tsrn10_memzone_reserve(hw->cookie_p_name, 0);
		if (!cookie)
			return -ENOMEM;
		memset(cookie->priv, 0, cookie->priv_len);
		build_mbx_sfp_read(&req, nr_lane, sfp_i2c_addr, reg, cnt, cookie);

		if (!rnp_mbx_fw_post_req(dev, &req, cookie)) {
			/* err */
			memcpy(out_buf, cookie->priv, cnt);
			err = 0;
		}
		return err;
	}

	memset(&reply, 0, sizeof(reply));
	build_mbx_sfp_read(&req, nr_lane, sfp_i2c_addr, reg, cnt, &reply);

	err = rnp_fw_send_cmd_wait(dev, &req, &reply);
	if (!err)
		memcpy(out_buf, reply.sfp_read.value, cnt);

	return err;
}

int rnp_mbx_sfp_module_eeprom_info(struct rte_eth_dev *dev,
				   int nr_lane,
				   int sfp_addr,
				   int reg,
				   int data_len,
				   char *buf)
{
	int left = data_len;
	int cnt, err;

	do {
		cnt = (left > MBX_SFP_READ_MAX_CNT) ? MBX_SFP_READ_MAX_CNT : left;
		err = rnp_mbx_sfp_read(dev, nr_lane, sfp_addr, reg, cnt, buf);
		if (err) {
			TSRN10_PMD_LOG(ERR, "%s: error:%d\n", __func__, err);
			return err;
		}
		reg += cnt;
		buf += cnt;
		left -= cnt;
	} while (left > 0);

	return 0;
}

int
rnp_mbx_get_lane_stat(struct rte_eth_dev *dev, int nr_lane)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_phy_meta *phy_meta = &port->attr.phy_meta;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct lane_stat_data *lane_stat;
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err = 0;

	memset(&req, 0, sizeof(req));

	if (hw->mbx.irq_enabled) {
		cookie = tsrn10_memzone_reserve(hw->cookie_p_name, 0);

		if (!cookie)
			return -ENOMEM;
		memset(cookie->priv, 0, cookie->priv_len);
		lane_stat = (struct lane_stat_data *)cookie->priv;
		build_get_lane_status_req(&req, nr_lane, cookie);
		err = rnp_mbx_fw_post_req(dev, &req, cookie);
		if (err)
			goto quit;
	} else {
		memset(&reply, 0, sizeof(reply));
		build_get_lane_status_req(&req, nr_lane, &req);
		err = rnp_fw_send_cmd_wait(dev, &req, &reply);
		if (err)
			goto quit;
		lane_stat = (struct lane_stat_data *)reply.data;
	}

	phy_meta->supported_link = lane_stat->supported_link;
	phy_meta->is_backplane = lane_stat->is_backplane;
	phy_meta->phy_identifier = lane_stat->phy_addr;
	phy_meta->link_autoneg = lane_stat->autoneg;
	phy_meta->link_duplex = lane_stat->duplex;
	phy_meta->phy_type = lane_stat->phy_type;
	phy_meta->is_sgmii = lane_stat->is_sgmii;
	phy_meta->fec = lane_stat->fec;

	if (phy_meta->is_sgmii) {
		phy_meta->media_type = TSRN10_MEDIA_TYPE_COPPER;
		phy_meta->supported_link |=
			RNP_SPEED_CAP_100M_HALF | RNP_SPEED_CAP_10M_HALF;
	} else if (phy_meta->is_backplane) {
		phy_meta->media_type = TSRN10_MEDIA_TYPE_BACKPLANE;
	} else {
		phy_meta->media_type = TSRN10_MEDIA_TYPE_FIBER;
	}

	return 0;
quit:
	return err;
}

int rnp_mbx_phy_write(struct rte_eth_dev *dev, u32 reg, u32 val)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_fw_cmd_req req;
	char nr_lane;
	int err;

	memset(&req, 0, sizeof(req));
	nr_lane = port->attr.nr_lane;

	build_set_phy_reg(&req, NULL, PHY_EXTERNAL_PHY_MDIO, nr_lane,
			reg, val, 0);
	rte_spinlock_lock(&hw->fw_lock);
	err = ops->write_posted(
		dev, (u32 *)&req, (req.datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	rte_spinlock_unlock(&hw->fw_lock);

	return err;
}

int rnp_mbx_phy_read(struct rte_eth_dev *dev, u32 reg, u32 *val)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_fw_cmd_reply reply;
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_req req;
	int err = -EIO;
	char nr_lane;

	nr_lane = port->attr.nr_lane;
	memset(&req, 0, sizeof(req));

	if (hw->mbx.irq_enabled) {
		cookie = tsrn10_memzone_reserve(hw->cookie_p_name, 0);
		if (!cookie)
			return -ENOMEM;
		build_get_phy_reg(&req, cookie, PHY_EXTERNAL_PHY_MDIO,
				nr_lane, reg);
		err = rnp_mbx_fw_post_req(dev, &req, cookie);
		if (err)
			return err;
		memcpy(val, cookie->priv, 4);
		err = 0;
	} else {
		memset(&reply, 0, sizeof(reply));
		build_get_phy_reg(&req, &reply, PHY_EXTERNAL_PHY_MDIO,
				nr_lane, reg);

		err = rnp_fw_send_cmd_wait(dev, &req, &reply);
		if (!err)
			*val = reply.r_reg.value;
	}

	return err;
}

int rnp_mbx_phy_link_set(struct rte_eth_dev *dev, int nr_lane, int speeds)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));

	build_phy_link_set(&req, speeds, nr_lane);
	rte_spinlock_lock(&hw->fw_lock);
	err = ops->write_posted(
		dev, (u32 *)&req, (req.datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	rte_spinlock_unlock(&hw->fw_lock);

	return err;
}

int rnp_mbx_fw_reset_phy(struct rte_eth_dev *dev)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_fw_cmd_reply reply;
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_req req;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (hw->mbx.irq_enabled) {
		cookie = tsrn10_memzone_reserve(hw->cookie_p_name, 0);
		if (!cookie)
			return -ENOMEM;
		memset(cookie->priv, 0, cookie->priv_len);
		build_reset_phy_req(&req, cookie);
		return rnp_mbx_fw_post_req(dev, &req, cookie);
	}
	build_reset_phy_req(&req, &req);

	return rnp_fw_send_cmd_wait(dev, &req, &reply);
}

int
rnp_fw_get_macaddr(struct rte_eth_dev *dev,
		       int pfvfnum,
		       u8 *mac_addr,
		       int nr_lane)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	struct mac_addr *mac;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (!mac_addr)
		return -EINVAL;

	if (hw->mbx.irq_enabled) {
		cookie = tsrn10_memzone_reserve(hw->cookie_p_name, 0);
		if (!cookie)
			return -ENOMEM;
		memset(cookie->priv, 0, cookie->priv_len);
		mac = (struct mac_addr *)cookie->priv;
		build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, cookie);
		err = rnp_mbx_fw_post_req(dev, &req, cookie);
		if (err)
			goto quit;

		if ((1 << nr_lane) & mac->lanes) {
			memcpy(mac_addr, mac->addrs[nr_lane].mac, 6);
			err = 0;
		} else {
			err = -ENODATA;
		}
quit:
		return err;
	}
	build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, &req);
	err = rnp_fw_send_cmd_wait(dev, &req, &reply);
	if (err) {
		TSRN10_PMD_LOG(ERR, "%s: failed. err:%d\n", __func__, err);
		return err;
	}

	if ((1 << nr_lane) & reply.mac_addr.lanes) {
		memcpy(mac_addr, reply.mac_addr.addrs[nr_lane].mac, 6);
		return 0;
	}

	return -ENODATA;
}

int rnp_fw_get_capablity(struct rte_eth_dev *dev, struct phy_abilities *abil)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_phy_abalities_req(&req, &req);

	err = rnp_fw_send_cmd_wait(dev, &req, &reply);
	if (err)
		return err;

	memcpy(abil, &reply.phy_abilities, sizeof(*abil));

	return 0;
}

#define RNP_MBX_API_MAX_RETRY (10)
int rnp_mbx_get_capability(struct rte_eth_dev *dev,
			   int *lane_mask,
			   int *nic_mode)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct phy_abilities ablity;
	uint16_t temp_lmask;
	uint16_t lane_bit = 0;
	uint16_t retry = 0;
	int lane_cnt = 0;
	uint8_t lane_idx;
	int err = -EIO;
	uint8_t idx;

	memset(&ablity, 0, sizeof(ablity));

	/* enable CM3CPU to PF MBX IRQ */
	/* wr32(hw, CPU_PF_MBOX_MASK, 0); */

	do {
		err = rnp_fw_get_capablity(dev, &ablity);
		if (retry > RNP_MBX_API_MAX_RETRY)
			break;
		retry++;
	} while (err);
	if (!err) {
		hw->lane_mask = ablity.lane_mask;
		hw->nic_mode = ablity.nic_mode;
		hw->pfvfnum = ablity.pfnum;
		hw->speed = ablity.speed;
		hw->fw_version = ablity.fw_version;
		hw->axi_mhz = ablity.axi_mhz;
		hw->fw_uid = ablity.fw_uid;
		if (ablity.phy_type == PHY_TYPE_SGMII) {
			hw->is_sgmii = 1;
			hw->sgmii_phy_id = ablity.phy_id;
		}
		if (hw->nic_mode == TSRN10_SINGLE_10G &&
				hw->fw_version >= 0x00050201 &&
				ablity.speed == ETH_SPEED_NUM_10G) {
			hw->force_speed_stat = FORCE_SPEED_STAT_DISABLED;
			hw->force_10g_1g_speed_ablity = 1;
		}

		if (lane_mask)
			*lane_mask = hw->lane_mask;
		if (nic_mode)
			*nic_mode = hw->nic_mode;

		lane_cnt = __builtin_popcount(hw->lane_mask);
		temp_lmask = hw->lane_mask;
		for (idx = 0; idx < lane_cnt; idx++) {
			hw->phy_port_ids[idx] = ablity.port_ids[idx];
			lane_bit = ffs(temp_lmask) - 1;
			lane_idx = ablity.port_ids[idx] % lane_cnt;
			hw->lane_of_port[lane_idx] = lane_bit;
			temp_lmask &= ~BIT(lane_bit);
		}
		hw->max_port_num = lane_cnt;
	}

	TSRN10_PMD_LOG(INFO,
			"%s: nic-mode:%d lane_cnt:%d lane_mask:0x%x "
			"pfvfnum:0x%x, fw_version:0x%08x, ports:%d-%d-%d-%d\n",
			__func__,
			hw->nic_mode,
			lane_cnt,
			hw->lane_mask,
			hw->pfvfnum,
			ablity.fw_version,
			ablity.port_ids[0],
			ablity.port_ids[1],
			ablity.port_ids[2],
			ablity.port_ids[3]);

	if (lane_cnt <= 0 || lane_cnt > 4)
		return -EIO;

	return err;
}

int rnp_mbx_set_dump(struct rte_eth_dev *dev, int flag)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	build_set_dump(&req, port->attr.nr_lane, flag);

	err = rnp_mbx_write_posted_locked(dev, &req);

	return err;
}

int rnp_hw_set_fw_10g_1g_auto_detch(struct rte_eth_dev *dev, int enable)
{
	return rnp_mbx_set_dump(dev, 0x01140000 | (enable & 1));
}

int rnp_hw_set_fw_force_speed_1g(struct rte_eth_dev *dev, int enable)
{
	return rnp_mbx_set_dump(dev, 0x01150000 | (enable & 1));
}

static int rnp_mbx_force_speed(struct rte_eth_dev *dev, int speed)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int cmd = 0x01150000; /* disable force speed */

	if (hw->force_10g_1g_speed_ablity == 0)
		return -EINVAL;

	if (speed == RNP_LINK_SPEED_10GB_FULL) {
		cmd = 0x01150002;
		hw->force_speed_stat = FORCE_SPEED_STAT_10G;
	} else if (speed == RNP_LINK_SPEED_1GB_FULL) {
		cmd = 0x01150001;
		hw->force_speed_stat = FORCE_SPEED_STAT_1G;
	} else {
		cmd = 0x01150000;
		hw->force_speed_stat = FORCE_SPEED_STAT_DISABLED;
	}

	return rnp_mbx_set_dump(dev, cmd);
}

void tsrn10_link_stat_mark(struct tsrn10_hw *hw, int nr_lane, int up)
{
	u32 v;

	rte_spinlock_lock(&hw->link_sync);
	v = tsrn10_rd_reg(hw->dev_dummy);
	v &= ~(0xffff0000);
	v |= 0xa5a40000;
	if (up)
		v |= BIT(nr_lane);
	else
		v &= ~BIT(nr_lane);
	tsrn10_wr_reg(hw->dev_dummy, v);

	rte_spinlock_unlock(&hw->link_sync);
}

#if RTE_VERSION < RTE_VERSION_NUM(17, 11, 0, 0)
#define iova phys_addr
#endif

struct maintain_req {
	int magic;
#define MAINTAIN_MAGIC 0xa6a7a8a9

	int	 cmd;
	int	 arg0;
	int	 req_data_bytes;
	int	 reply_bytes;
	char data[0];
} __attribute__((packed));

int rnp_fw_update(struct tsrn10_eth_adapter *adapter)
{
	const struct rte_memzone *rz = NULL;
	struct maintain_req *mt;
	FILE *file;
	int fsz;
#define MAX_FW_BIN_SZ (552 * 1024)
#define FW_256KB	  (256 * 1024)

	TSRN10_PMD_LOG(INFO, "%s: %s\n", __func__, adapter->fw_path);

	file = fopen(adapter->fw_path, "rb");
	if (!file) {
		TSRN10_PMD_LOG(ERR,
				"TSRN10: [%s] %s can't open for read\n",
				__func__,
				adapter->fw_path);
		return -ENOENT;
	}
	/* get dma */
	rz = rte_memzone_reserve("fw_update", MAX_FW_BIN_SZ, SOCKET_ID_ANY, 4);
	if (rz == NULL) {
		TSRN10_PMD_LOG(ERR, "TSRN10: [%s] not memory:%d\n", __func__,
			MAX_FW_BIN_SZ);
		return -EFBIG;
	}
	memset(rz->addr, 0xff, rz->len);
	mt = (struct maintain_req *)rz->addr;

	/* read data */
	fsz = fread(mt->data, 1, rz->len, file);
	if (fsz <= 0) {
		TSRN10_PMD_LOG(INFO, "TSRN10: [%s] read failed! err:%d\n",
			__func__, fsz);
		return -EIO;
	}
	fclose(file);

	if (fsz > ((256 + 4) * 1024)) {
		printf("fw length:%d is two big. not supported!\n", fsz);
		return -EINVAL;
	}

	TSRN10_PMD_LOG(NOTICE, "TSRN10: fw update ...\n");
	fflush(stdout);

	/* ==== update fw */
	mt->magic	= MAINTAIN_MAGIC;
	mt->cmd		= MT_WRITE_FLASH;
	mt->arg0	= 1;
	mt->req_data_bytes = (fsz > FW_256KB) ? FW_256KB : fsz;
	mt->reply_bytes	= 0;

	if (rnp_maintain_req(adapter->eth_dev, mt->cmd, mt->arg0,
				mt->req_data_bytes, mt->reply_bytes, rz->iova))
		TSRN10_PMD_LOG(ERR, "maintain request failed!\n");
	else
		TSRN10_PMD_LOG(INFO, "maintail request done!\n");

	/* ==== update cfg */
	if (fsz > FW_256KB) {
		mt->magic	= MAINTAIN_MAGIC;
		mt->cmd		= MT_WRITE_FLASH;
		mt->arg0	= 2;
		mt->req_data_bytes = 4096;
		mt->reply_bytes	   = 0;
		memcpy(mt->data, mt->data + FW_256KB, mt->req_data_bytes);

		if (rnp_maintain_req(adapter->eth_dev,
					mt->cmd, mt->arg0, mt->req_data_bytes,
					mt->reply_bytes, rz->iova))
			TSRN10_PMD_LOG(ERR, "maintain request failed!\n");
		else
			TSRN10_PMD_LOG(INFO, "maintail request done!\n");
	}

	TSRN10_PMD_LOG(NOTICE, "done\n");
	fflush(stdout);

	rte_memzone_free(rz);

	exit(0);

	return 0;
}

void tsrn10_link_report(struct rte_eth_dev *dev, bool link_en)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_rx_queue *rxq;
	struct tsrn10_tx_queue *txq;
	struct rte_eth_link link;
	uint8_t idx;

	/* Avoid Hardware Fault When Link Down Send Pkts */
	if (link_en) {
		for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
			rxq = dev->data->rx_queues[idx];
			if (!rxq)
				continue;
			rxq->rx_link = true;
		}

		for (idx = 0; idx < dev->data->nb_tx_queues; idx++) {
			txq = dev->data->tx_queues[idx];
			if (!txq)
				continue;
			txq->tx_link = true;
		}
	} else {
		for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
			rxq = dev->data->rx_queues[idx];
			if (!rxq)
				continue;
			rxq->rx_link = false;
		}
		for (idx = 0; idx < dev->data->nb_tx_queues; idx++) {
			txq = dev->data->tx_queues[idx];
			if (!txq)
				continue;
			txq->tx_link = false;
		}
	}

	link.link_duplex =
		link_en ? port->attr.phy_meta.link_duplex : ETH_LINK_FULL_DUPLEX;
	link.link_status = link_en ? ETH_LINK_UP : ETH_LINK_DOWN;
	link.link_speed = link_en ? port->attr.speed :
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
				ETH_SPEED_NUM_UNKNOWN;
#else
				ETH_SPEED_NUM_NONE;
#endif
	TSRN10_PMD_LOG(INFO,
			"\nPF[%d]link changed: changed_lane:0x%x, "
			"status:0x%x\n",
			hw->pf_vf_num & TSRN10_PF_NB_MASK ? 1 : 0,
			port->attr.nr_port,
			link_en);
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	link.link_autoneg = port->attr.phy_meta.link_autoneg
		? ETH_LINK_SPEED_AUTONEG
		: ETH_LINK_SPEED_FIXED;
#else
	if (port->attr.phy_meta.link_autoneg)
		link.link_duplex = ETH_LINK_AUTONEG_DUPLEX;
#endif
	/* Report Link Info To Upper Firmwork */
	rte_eth_linkstatus_set(dev, &link);
	/* Notice Event Process Link Status Change */
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
#elif (RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION && \
	   RTE_VERSION_NUM(17, 8, 0, 0) > RTE_VERSION) ||  \
	(RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION &&    \
	 RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION)
	_rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
#elif RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
	_rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL, NULL);
#else
	_rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC);
#endif
	/* Notce Firmware LSC Event SW Received */
	tsrn10_link_stat_mark(hw, port->attr.nr_port, link_en);
}

static void tsrn10_dev_alarm_link_handler(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint32_t status;

	status = port->attr.link_ready;
	tsrn10_link_report(dev, status);
}

static void tsrn10_link_event(struct tsrn10_eth_adapter *adapter,
			      struct mbx_fw_cmd_req *req)
{
	struct tsrn10_hw *hw = &adapter->hw;
	struct tsrn10_eth_port *port;
	bool link_change = false;
	uint32_t lane_bit;
	uint32_t sync_bit;
	uint32_t link_en;
	uint32_t link;
	uint32_t ctrl;
	int i;

	for (i = 0; i < adapter->num_ports; i++) {
		port = adapter->port[i];
		if (port == NULL)
			continue;
		link_change = false;
		lane_bit = port->attr.nr_port;
		if (rte_atomic64_read(&port->state) != TSRN10_PORT_STATE_FINISH)
			continue;
		if (!(BIT(lane_bit) & req->link_stat.changed_lanes))
			continue;
		link_en = BIT(lane_bit) & req->link_stat.lane_status;
		sync_bit = BIT(lane_bit) & tsrn10_rd_reg(hw->dev_dummy);

		if (link_en) {
			/* Port Link Change To Up */
			if (!port->attr.link_ready) {
				link_change = true;
				port->attr.link_ready = true;
			}
			if (req->link_stat.port_st_magic == SPEED_VALID_MAGIC) {
				port->attr.speed = req->link_stat.st[lane_bit].speed;
				port->attr.phy_meta.link_duplex =
					req->link_stat.st[lane_bit].duplex;
				port->attr.phy_meta.link_autoneg =
					req->link_stat.st[lane_bit].autoneg;
				PMD_INIT_LOG(INFO,
						"phy_id %d speed %d duplex "
						"%d issgmii %d PortID %d\n",
						req->link_stat.st[lane_bit].phy_addr,
						req->link_stat.st[lane_bit].speed,
						req->link_stat.st[lane_bit].duplex,
						req->link_stat.st[lane_bit].is_sgmii,
						port->attr.rte_pid);
			}
		} else {
			/* Port Link to Down */
			if (port->attr.link_ready) {
				link_change = true;
				port->attr.link_ready = false;
			}
			link = tsrn10_mac_rd(hw, port->attr.nr_port,
					TSRN10_MAC_INT_STATUS);
			switch (link & TSRN10_MAC_LS_MASK) {
			case TSRN10_MAC_LS_LOCAL_FAULT:
				port->sw_stat.mac_local_fault++;
				break;
			case TSRN10_MAC_LS_REMOT_FAULT:
				port->sw_stat.mac_remote_fault++;
			}
		}
		if (link_change || sync_bit != link_en) {
			/* WorkAround For Hardware When Link Down
			 * Eth Module Tx-side Can't Drop In some condition
			 * So back The Packet To Rx Side To Drop Packet
			 */
			/* To Protect Conflict Hw Resource */
			rte_spinlock_lock(&port->rx_mac_lock);
			ctrl = tsrn10_mac_rd(hw, lane_bit, TSRN10_MAC_RX_CFG);
			if (port->attr.link_ready) {
				ctrl &= ~TSRN10_MAC_LM;
				tsrn10_eth_wr(hw,
					TSRN10_RX_FIFO_FULL_THRETH(lane_bit),
					TSRN10_RX_DEFAULT_VAL);
			} else {
				tsrn10_eth_wr(hw,
					TSRN10_RX_FIFO_FULL_THRETH(lane_bit),
					TSRN10_RX_WORKAROUND_VAL);
				ctrl |= TSRN10_MAC_LM;
			}
			tsrn10_mac_wr(hw, lane_bit, TSRN10_MAC_RX_CFG, ctrl);
			rte_spinlock_unlock(&port->rx_mac_lock);
			rte_eal_alarm_set(TSRN10_ALARM_INTERVAL,
					tsrn10_dev_alarm_link_handler,
					(void *)port->dev);
		}
	}
}

static inline int rnp_mbx_fw_req_handler(struct tsrn10_eth_adapter *adapter,
					 struct mbx_fw_cmd_req *req)
{
	switch (req->opcode) {
	case LINK_STATUS_EVENT:
		tsrn10_link_event(adapter, req);
		break;
	default:
		break;
	}

	return 0;
}

static inline int
rnp_mbx_fw_reply_handler(struct tsrn10_eth_adapter *adapter __rte_unused,
			 struct mbx_fw_cmd_reply *reply)
{
	struct mbx_req_cookie *cookie;
	/* dbg_here; */
	cookie = reply->cookie;
	if (!cookie || cookie->magic != COOKIE_MAGIC) {
		TSRN10_PMD_LOG(ERR,
				"[%s] invalid cookie:%p opcode: "
				"0x%x v0:0x%x\n",
				__func__,
				cookie,
				reply->opcode,
				*((int *)reply));
		return -EIO;
	}

	if (cookie->priv_len > 0)
		memcpy(cookie->priv, reply->data, cookie->priv_len);

	cookie->done = 1;

	if (reply->flags & FLAGS_ERR)
		cookie->errcode = reply->error_code;
	else
		cookie->errcode = 0;

	return 0;
}

static inline int rnp_rcv_msg_from_fw(struct tsrn10_eth_adapter *adapter)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(adapter->eth_dev);
	struct tsrn10_hw *hw = &adapter->hw;
	u32 msgbuf[RNP_FW_MAILBOX_SIZE];
	uint16_t check_state;
	int retval;

	retval = ops->read(hw, msgbuf, RNP_FW_MAILBOX_SIZE, MBX_FW);
	if (retval) {
		PMD_DRV_LOG(ERR, "Error receiving message from FW\n");
		return retval;
	}
#define RNP_MBX_SYNC_MASK GENMASK(15, 0)

	check_state = msgbuf[0] & RNP_MBX_SYNC_MASK;
	/* this is a message we already processed, do nothing */
	if (check_state & FLAGS_DD)
		return rnp_mbx_fw_reply_handler(adapter,
				(struct mbx_fw_cmd_reply *)msgbuf);
	else
		return rnp_mbx_fw_req_handler(adapter,
				(struct mbx_fw_cmd_req *)msgbuf);
}

static void rnp_rcv_ack_from_fw(struct tsrn10_eth_adapter *adapter)
{
	struct tsrn10_hw *hw __rte_unused = &adapter->hw;
	u32 msg __rte_unused = RNP_VT_MSGTYPE_NACK;
	/* do-nothing */
}

int rnp_fw_msg_handler(struct tsrn10_eth_adapter *adapter)
{
	struct tsrn10_mbx_api *ops = TSRN10_DEV_TO_MBX_OPS(adapter->eth_dev);
	struct tsrn10_hw *hw = &adapter->hw;

	/* == check cpureq */
	if (!ops->check_for_msg(hw, MBX_FW))
		rnp_rcv_msg_from_fw(adapter);

	/* process any acks */
	if (!ops->check_for_ack(hw, MBX_FW))
		rnp_rcv_ack_from_fw(adapter);

	return 0;
}

/*
 * [23:20]:lane3 speed,[19:16]:lane2 speed,[15:12]:lane1 speed,
 * [11:8]:lane0 speed *0: 10M 1: 100M 2: 1G 3: 10G 4: 25G 5: 40G
 */
int
rnp_mbx_get_lane_speed(struct rte_eth_dev *dev, int nr_lane)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int v = tsrn10_rd_reg(hw->dev_dummy + 0x30000);
	int lane_speeds = (v >> 8) & 0xfff;

	switch ((lane_speeds >> (4 * nr_lane)) & 0xf) {
	case 0:
		return 10;
	case 1:
		return 100;
	case 2:
		return 1000;
	case 3:
		return 10000;
	case 4:
		return 25000;
	case 5:
		return 40000;
	}

	return 0;
}

int tsrn10_setup_link_fiber(struct rte_eth_dev *dev, struct tsrn10_phy_cfg *cfg)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	int ret;

	if ((!cfg->autoneg && !cfg->duplex) || !hw->force_10g_1g_speed_ablity)
		return -EINVAL;
	if (cfg->autoneg)
		ret = rnp_mbx_force_speed(dev, 0);
	else
		ret = rnp_mbx_force_speed(dev, cfg->speed);

	return ret;
}
