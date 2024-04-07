#ifndef __TSRN10_PHY_H__
#define __TSRN10_PHY_H__

/* Generic MII registers. */
#define TSRN10_MII_BMCR			0x00	/* Basic mode control register */
#define TSRN10_MII_BMSR			0x01	/* Basic mode status register  */
#define TSRN10_MII_PHYSID1		0x02	/* PHYS ID 1                   */
#define TSRN10_MII_PHYSID2		0x03	/* PHYS ID 2                   */
#define TSRN10_MII_ADVERTISE		0x04	/* Advertisement control reg   */
#define TSRN10_MII_LPA			0x05	/* Link partner ability reg    */
#define TSRN10_MII_EXPANSION		0x06	/* Expansion register          */
#define TSRN10_MII_CTRL1000		0x09	/* 1000BASE-T control          */
#define TSRN10_MII_STAT1000		0x0a	/* 1000BASE-T status           */
#define	TSRN10_MII_MMD_CTRL		0x0d	/* MMD Access Control Register */
#define	TSRN10_MII_MMD_DATA		0x0e	/* MMD Access Data Register */
#define TSRN10_MII_ESTATUS		0x0f	/* Extended Status             */
#define TSRN10_MII_DCOUNTER		0x12	/* Disconnect counter          */
#define TSRN10_MII_FCSCOUNTER		0x13	/* False carrier counter       */
#define TSRN10_MII_NWAYTEST		0x14	/* N-way auto-neg test reg     */
#define TSRN10_MII_RERRCOUNTER		0x15	/* Receive error counter       */
#define TSRN10_MII_SREVISION		0x16	/* Silicon revision            */
#define TSRN10_MII_RESV1		0x17	/* Reserved...                 */
#define TSRN10_MII_LBRERROR		0x18	/* Lpback, rx, bypass error    */
#define TSRN10_MII_PHYADDR		0x19	/* PHY address                 */
#define TSRN10_MII_RESV2		0x1a	/* Reserved...                 */
#define TSRN10_MII_TPISTATUS		0x1b	/* TPI status for 10mbps       */
#define TSRN10_MII_NCONFIG		0x1c	/* Network interface config    */

/* Basic mode control register. */
#define TSRN10_BMCR_RESV		0x003f	/* Unused...                   */
#define TSRN10_BMCR_SPEED1000		BIT(6)	/* MSB of Speed (1000)         */
#define TSRN10_BMCR_CTST		BIT(7)	/* Collision test              */
#define TSRN10_BMCR_FULLDPLX		BIT(8)	/* Full duplex                 */
#define TSRN10_BMCR_ANRESTART		BIT(9)	/* Auto negotiation restart    */
#define TSRN10_BMCR_ISOLATE		BIT(10)	/* Isolate data paths from MII */
#define TSRN10_BMCR_PDOWN		BIT(11)	/* Enable low power state      */
#define TSRN10_BMCR_ANENABLE		BIT(12)	/* Enable auto negotiation     */
#define TSRN10_BMCR_SPEED100		BIT(13)	/* Select 100Mbps              */
#define TSRN10_BMCR_LOOPBACK		BIT(14)	/* TXD loopback bits           */
#define TSRN10_BMCR_RESET		BIT(15)	/* Reset to default state      */
#define TSRN10_BMCR_SPEED10		0x0000	/* Select 10Mbps               */

/* PHYS ID */
#define TSRN10_MII_PHYSID2_MASK		GENMASK(15, 0)
#define TSRN10_MII_PHYSID1_OFFSET	(16)

/* Advertisement control register. */
#define TSRN10_ADVERTISE_SLCT		0x001f	/* Selector bits               */
#define TSRN10_ADVERTISE_CSMA		BIT(0)	/* Only selector supported     */
#define TSRN10_ADVERTISE_10HALF		BIT(5)	/* Try for 10mbps half-duplex  */
#define TSRN10_ADVERTISE_1000XFULL	BIT(5)	/* Try for 1000BASE-X full-duplex */
#define TSRN10_ADVERTISE_10FULL		BIT(6)	/* Try for 10mbps full-duplex  */
#define TSRN10_ADVERTISE_1000XHALF	BIT(6)	/* Try for 1000BASE-X half-duplex */
#define TSRN10_ADVERTISE_100HALF	BIT(7)	/* Try for 100mbps half-duplex */
#define TSRN10_ADVERTISE_1000XPAUSE	BIT(7)	/* Try for 1000BASE-X pause    */
#define TSRN10_ADVERTISE_100FULL	BIT(8)	/* Try for 100mbps full-duplex */
#define TSRN10_ADVERTISE_1000XPSE_ASYM	BIT(8)	/* Try for 1000BASE-X asym pause */
#define TSRN10_ADVERTISE_100BASE4	BIT(9)	/* Try for 100mbps 4k packets  */
#define TSRN10_ADVERTISE_PAUSE_CAP	BIT(10)	/* Try for pause               */
#define TSRN10_ADVERTISE_PAUSE_ASYM	BIT(11)	/* Try for asymmetric pause    */
#define TSRN10_ADVERTISE_RESV		BIT(12)	/* Unused...                   */
#define TSRN10_ADVERTISE_RFAULT		BIT(13)	/* Say we can detect faults    */
#define TSRN10_ADVERTISE_LPACK		BIT(14)	/* Ack link partners response  */
#define TSRN10_ADVERTISE_NPAGE		BIT(15)	/* Next page bit               */
#define TSRN10_ADVERTISE_MASK		GENMASK(8, 5)

#define TSRN10_ADVERTISE_FULL		(TSRN10_ADVERTISE_100FULL | TSRN10_ADVERTISE_10FULL | \
					TSRN10_ADVERTISE_CSMA)
#define TSRN10_ADVERTISE_ALL		(TSRN10_ADVERTISE_10HALF | TSRN10_ADVERTISE_10FULL | \
					TSRN10_ADVERTISE_100HALF | TSRN10_ADVERTISE_100FULL)
/* 1000BASE-T Control register */
#define TSRN10_ADVERTISE_1000FULL	0x0200  /* Advertise 1000BASE-T full duplex */
#define TSRN10_ADVERTISE_1000HALF	0x0100  /* Advertise 1000BASE-T half duplex */
#define TSRN10_ADVERTISE_CTRL1000_MASK	GENMASK(9, 8)
#define TSRN10_CTL1000_PREFER_MASTER	0x0400  /* prefer to operate as master */
#define TSRN10_CTL1000_AS_MASTER	0x0800
#define TSRN10_CTL1000_ENABLE_MASTER	0x1000

/* Support PHY ID */
#define TSRN10_YT8614_PHY_ID		(0x4f51e91a)

void tsrn10_get_phy_info(struct rte_eth_dev *dev, uint32_t *identifier);
int tsrn10_setup_link_phy(struct rte_eth_dev *dev, struct tsrn10_phy_cfg *cfg);

#endif /* __TSRN10_PHY_H__*/
