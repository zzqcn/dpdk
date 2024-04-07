#ifndef __TSRN10_API_H__
#define __TSRN10_API_H__

int
tsrn10_init_hw(struct rte_eth_dev *dev);
int
tsrn10_reset_hw(struct rte_eth_dev *dev, struct tsrn10_hw *hw);
int
tsrn10_set_default_mac(struct rte_eth_dev *dev, uint8_t *mac_addr);
int
tsrn10_get_fw_version(struct rte_eth_dev *dev, struct tsrn10_hw *hw);
int
tsrn10_flow_ctrl_en(struct rte_eth_dev *dev, struct tsrn10_fc_info *fc,
		    uint8_t p_id, bool en);
int
tsrn10_set_rafb(struct rte_eth_dev *dev, uint8_t *addr,
		uint8_t vm_pool, uint8_t index);
int
tsrn10_clear_rafb(struct rte_eth_dev *dev,
		  uint8_t vm_pool, uint8_t index);
int
tsrn10_setup_uta(struct rte_eth_dev *dev,
		 uint8_t *addr, uint8_t add);
int
tsrn10_uta_en(struct rte_eth_dev *dev, bool en);
int
tsrn10_update_mc_hash(struct rte_eth_dev *dev,
		      struct rte_ether_addr *mc_list,
		      uint8_t nb_mc);
int
tsrn10_update_mpfm(struct rte_eth_dev *dev,
		   enum tsrn10_mpf_modes mode, bool en);
int
tsrn10_add_vlan_filter(struct rte_eth_dev *dev, uint16_t vid, bool add);
int
tsrn10_vlan_filter_en(struct rte_eth_dev *dev, bool en);
int
tsrn10_get_mac_addr(struct rte_eth_dev *dev, uint8_t *macaddr);

#endif
