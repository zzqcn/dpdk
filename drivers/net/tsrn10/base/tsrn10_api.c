#include "tsrn10.h"

#include "tsrn10_api.h"

int
tsrn10_init_hw(struct rte_eth_dev *dev)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);

	if (ops->init_hw)
		return ops->init_hw(hw);
	return -EOPNOTSUPP;
}

int
tsrn10_reset_hw(struct rte_eth_dev *dev, struct tsrn10_hw *hw)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);

	if (ops->reset_hw)
		return ops->reset_hw(hw);
	return -EOPNOTSUPP;
}

int
tsrn10_set_default_mac(struct rte_eth_dev *dev, uint8_t *mac_addr)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->set_default_mac)
		return ops->set_default_mac(port, mac_addr);
	return -EOPNOTSUPP;
}

int
tsrn10_get_fw_version(struct rte_eth_dev *dev, struct tsrn10_hw *hw)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);

	if (ops->get_fw_ver)
		return ops->get_fw_ver(hw);
	return -EOPNOTSUPP;
}

int
tsrn10_flow_ctrl_en(struct rte_eth_dev *dev, struct tsrn10_fc_info *fc,
		    uint8_t p_id, bool en)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->fc_enable)
		return ops->fc_enable(port, fc, p_id, en);
	return -EOPNOTSUPP;
}

int
tsrn10_set_rafb(struct rte_eth_dev *dev, uint8_t *addr,
		uint8_t vm_pool, uint8_t index)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->set_rafb)
		return ops->set_rafb(port, addr, vm_pool, index);
	return -EOPNOTSUPP;
}

int
tsrn10_clear_rafb(struct rte_eth_dev *dev,
		  uint8_t vm_pool, uint8_t index)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->clear_rafb)
		return ops->clear_rafb(port, vm_pool, index);
	return -EOPNOTSUPP;
}

int
tsrn10_setup_uta(struct rte_eth_dev *dev,
		 uint8_t *addr, uint8_t add)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->update_uta)
		return ops->update_uta(port, (uint8_t *)addr, add);
	return -EOPNOTSUPP;
}

int
tsrn10_uta_en(struct rte_eth_dev *dev, bool en)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->clear_rafb)
		return ops->enable_uta(port, en);
	return -EOPNOTSUPP;
}

int
tsrn10_update_mc_hash(struct rte_eth_dev *dev,
		      struct rte_ether_addr *mc_list,
		      uint8_t nb_mc)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->update_mta)
		return ops->update_mta(port, mc_list, nb_mc);
	return -EOPNOTSUPP;
}

int
tsrn10_update_mpfm(struct rte_eth_dev *dev,
		   enum tsrn10_mpf_modes mode, bool en)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->update_mpfm)
		return ops->update_mpfm(port, mode, en);
	return -EOPNOTSUPP;
}

int
tsrn10_add_vlan_filter(struct rte_eth_dev *dev, uint16_t vid, bool add)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->add_vlan_f)
		return ops->add_vlan_f(port, vid, add);
	return -EOPNOTSUPP;
}

int
tsrn10_vlan_filter_en(struct rte_eth_dev *dev, bool en)
{
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);

	if (ops->en_vlan_f)
		return ops->en_vlan_f(port, en);
	return -EOPNOTSUPP;
}

int
tsrn10_get_mac_addr(struct rte_eth_dev *dev, uint8_t *macaddr)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_mac_api *ops = TSRN10_DEV_TO_MAC_OPS(port->dev);

	if (!macaddr)
		return -EINVAL;
	if (ops->get_mac_addr)
		return ops->get_mac_addr(port, port->attr.nr_lane, macaddr);
	return -EOPNOTSUPP;
}

int
tsrn10_set_port_link(struct rte_eth_dev *dev, struct tsrn10_phy_cfg *cfg)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_phy_api *ops = TSRN10_DEV_TO_PHY_OPS(port->dev);

	if (!cfg)
		return -EINVAL;
	if (ops->setup_link)
		return ops->setup_link(dev, cfg);
	return -EOPNOTSUPP;
}
