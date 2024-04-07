#include <stdio.h>

#include "tsrn10.h"
#include "tsrn10_mbx.h"
#include "tsrn10_mbx_fw.h"
#include "tsrn10_phy.h"

int tsrn10_setup_link_phy(struct rte_eth_dev *dev, struct tsrn10_phy_cfg *cfg)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	uint32_t advertised_cfg = 0;
	bool force_autoned = 0;
	uint32_t bmcr_cfg = 0;
	uint32_t ctrl1000 = 0;
	uint32_t link_speed;
	uint32_t value = 0;
	uint16_t conf_bit;
	uint32_t bit_hi;
	uint8_t i = 0;

	if (port->attr.phy_meta.media_type != TSRN10_MEDIA_TYPE_COPPER)
		return -EOPNOTSUPP;

	link_speed = cfg->speed;
	conf_bit = __builtin_popcountl(link_speed);
	for (i = 0; i < conf_bit; i++) {
		bit_hi = ffs(link_speed);
		if (!bit_hi)
			continue;
		bit_hi -= 1;
		switch (BIT(bit_hi)) {
		case RNP_LINK_SPEED_1GB_FULL:
			bmcr_cfg |= TSRN10_BMCR_SPEED1000;
			ctrl1000 |= TSRN10_ADVERTISE_1000FULL;
			/* For 1000Base Phy Need use autoned to support it */
			force_autoned = 1;
			break;
		case RNP_LINK_SPEED_100_FULL:
			bmcr_cfg |= TSRN10_BMCR_SPEED100;
			advertised_cfg |= TSRN10_ADVERTISE_100FULL;
			break;
		case RNP_LINK_SPEED_100_HALF:
			bmcr_cfg |= TSRN10_BMCR_SPEED100;
			advertised_cfg |= TSRN10_ADVERTISE_100HALF;
			break;
		case RNP_LINK_SPEED_10_FULL:
			bmcr_cfg |= TSRN10_BMCR_SPEED10;
			advertised_cfg |= TSRN10_ADVERTISE_10FULL;
			break;
		case RNP_LINK_SPEED_10_HALF:
			bmcr_cfg |= TSRN10_BMCR_SPEED10;
			advertised_cfg |= TSRN10_ADVERTISE_10HALF;
			break;
		}
		link_speed &= ~BIT(bit_hi);
	}
	if (!conf_bit) {
		/* autoneg all speed */
		bmcr_cfg = TSRN10_BMCR_SPEED100 |
			TSRN10_BMCR_SPEED1000 |
			TSRN10_BMCR_SPEED10;
		advertised_cfg = TSRN10_ADVERTISE_ALL;
		ctrl1000 = TSRN10_ADVERTISE_1000FULL;
	}
	if (cfg->duplex)
		bmcr_cfg |= TSRN10_BMCR_FULLDPLX;
	if (cfg->autoneg || force_autoned) {
		/* clear 100/10base-T Self-negotiation ability */
		rnp_mbx_phy_read(dev, TSRN10_MII_ADVERTISE, &value);
		value &= ~TSRN10_ADVERTISE_MASK;
		/* enable 100/10base-T Self-negotiation ability */
		value |= advertised_cfg;
		rnp_mbx_phy_write(dev, TSRN10_MII_ADVERTISE, value);
		/* clear 1000base-T Self-negotiation ability */
		rnp_mbx_phy_read(dev, TSRN10_MII_CTRL1000, &value);
		value &= ~TSRN10_ADVERTISE_CTRL1000_MASK;
		/* enable 1000base-T Self-negotiation ability */
		value |= ctrl1000;
		rnp_mbx_phy_write(dev, TSRN10_MII_CTRL1000, value);
		/* software reset to make the above configuration take effect */
		rnp_mbx_phy_read(dev, TSRN10_MII_BMCR, &value);
		value |= bmcr_cfg;
		/* start antoneg */
		value |= TSRN10_BMCR_RESET |
			TSRN10_BMCR_ANRESTART | TSRN10_BMCR_ANENABLE;
		rnp_mbx_phy_write(dev, TSRN10_MII_BMCR, value);
	} else {
		bmcr_cfg |= TSRN10_BMCR_RESET;
		rnp_mbx_phy_write(dev, TSRN10_MII_BMCR, bmcr_cfg);
	}
	/* power on in UTP mode */
	rnp_mbx_phy_read(dev, TSRN10_MII_BMCR, &value);
	value &= ~TSRN10_BMCR_PDOWN;
	rnp_mbx_phy_write(dev, TSRN10_MII_BMCR, value);

	return 0;
}

void tsrn10_get_phy_info(struct rte_eth_dev *dev, uint32_t *identifier)
{
	uint32_t id_1, id_2;

	rnp_mbx_phy_read(dev, TSRN10_MII_PHYSID1, &id_1);
	rnp_mbx_phy_read(dev, TSRN10_MII_PHYSID2, &id_2);

	*identifier = (uint32_t)(id_1 << TSRN10_MII_PHYSID1_OFFSET) |
			(uint32_t)(id_2 & TSRN10_MII_PHYSID2_MASK);
}
