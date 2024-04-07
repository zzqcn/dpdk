#ifndef __TSRN10_TCAM_H__
#define __TSRN10_TCAM_H__

#define TSRN10_TCAM_BASE		(0xc0000)

/* L4 SRC/DST Port Queue Filter */
#define TSRN10_TCAM_L4PQF(n) \
	(TSRN10_TCAM_BASE + 0x00 + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))
#define TSRN10_TCAM_SRC_L4P_OFFSET	(16)
/* L3 DST IP Queue Filter  */
#define TSRN10_TCAM_DIPQF(n) \
	(TSRN10_TCAM_BASE + 0x04 + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))
/* L3 SRC IP Queue Filter */
#define TSRN10_TCAM_SIPQF(n) \
	(TSRN10_TCAM_BASE + 0x08 + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))
/* Action Queue Filter */
#define TSRN10_TCAM_ACTQF(n) \
	(TSRN10_TCAM_BASE + 0x0c + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))
#define TSRN10_TCAM_ACT_DROP		BIT(31)
#define TSRN10_TCAM_ACT_PASS		(0)
#define TSRN10_TCAM_ACT_RING_EN		BIT(30)
#define TSRN10_TCAM_ACT_RDIR_PORT	BIT(29)
#define TSRN10_TCAM_ACT_MARK_EN		BIT(28)
#define TSRN10_TCAM_ACT_QID_OFFSET	(16)
#define TSRN10_TCAM_ACT_PHY_OFFSET	(24)

/* L4 SRC/DST Port Queue Filter Mask */
#define TSRN10_TCAM_L4PQF_MASK(n) \
	(TSRN10_TCAM_BASE + 0x20 + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))
#define TSRN10_TCAM_SRC_L4_MASK_OFFSET	(16)
/* DST IP Queue Filter Mask */
#define TSRN10_TCAM_DIPQF_MASK(n) \
	(TSRN10_TCAM_BASE + 0x24 + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))
/* SRC IP Queue Filter Mask */
#define TSRN10_TCAM_SIPQF_MASK(n) \
	(TSRN10_TCAM_BASE + 0x28 + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))

/* ACTION Queue Filter Mark */
#define TSRN10_TCAM_ACT_MARK(n) \
	(TSRN10_TCAM_BASE + 0x2c + 0x40 * ((n) / 2) + 0x10 * ((n) % 2))
#define TSRN10_TCAM_ACT_MARK_OFFSET	(16)
#define TSRN10_TCAM_MARK_MASK		GENMASK(15, 0)

enum tsrn10_tcam_mode {
	TSRN10_ACL_CAM_MODE,
	TSRN10_ACL_TCAM_MODE,
	TSRN10_ACL_RAM_MODE,
};

#define TSRN10_TCAM_ENABLE		(0x18024)
#define TSRN10_TCAM_CONFIG_AVAIL_EN	(0x38050)
#define TSRN10_TCAM_MODE_CTRL		(0xe0000)
#define TSRN10_TCAM_CACHE_EN		(0xe0004)

#endif /* __TSRN10_TCAM_H__ */
