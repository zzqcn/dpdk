#include "tsrn10.h"
#include "base/tsrn10_pcs.h"

#define VR_XS_PMA_SNPS_CR_CTRL  (0x18000 + (0xa0))
#define VR_XS_PMA_SNPS_CR_ADDR  (0x18000 + (0xa1))
#define VR_XS_PMA_SNPS_CR_DATA  (0x18000 + (0xa2))

static uint32_t
tsrn10_read_pcs(struct tsrn10_hw *hw, uint8_t p_id, uint32_t addr)
{
	uint32_t reg_hi, reg_lo;
	uint32_t value;

	reg_hi = addr >> 8;
	reg_lo = (addr & 0xff) << 2;

	tsrn10_nicx_wr(hw, TSRN10_PCS_BASE(p_id) + (0xff << 2), reg_hi);
	value = tsrn10_nicx_rd(hw, TSRN10_PCS_BASE(p_id) + reg_lo);

	return value;
}

static void
tsrn10_write_pcs(struct tsrn10_hw *hw,
		 uint8_t p_id, uint32_t addr, uint32_t value)
{
	uint32_t reg_hi, reg_lo;

	reg_hi = addr >> 8;
	reg_lo = (addr & 0xff) << 2;

	tsrn10_nicx_wr(hw, TSRN10_PCS_BASE(p_id) + (0xff << 2), reg_hi);
	tsrn10_nicx_wr(hw, TSRN10_PCS_BASE(p_id) + reg_lo, value);
}

static void
tsrn10_write_pma(struct tsrn10_hw *hw,
		 uint8_t p_id, uint32_t addr, uint32_t value)
{
	uint32_t v;

	do {
		v = tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	} while ((v & BIT(0)));

	tsrn10_write_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_ADDR, addr);
	tsrn10_write_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_DATA, value);

	v = tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	v |= BIT(1);
	tsrn10_write_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL, v);

	v = tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	v |= BIT(0);
	tsrn10_write_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL, v);

	do {
		v = tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	} while ((v & BIT(0)));
}

static uint32_t
tsrn10_read_pma(struct tsrn10_hw *hw, uint8_t p_id, uint32_t addr)
{
	uint32_t v;

	do {
		v = tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	} while ((v & BIT(0)));


	tsrn10_write_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_ADDR, addr);

	v = tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	tsrn10_write_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL, v & 1);

	v =  tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	v |= BIT(0);
	tsrn10_write_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL, v);

	do {
		v = tsrn10_read_pcs(hw, p_id, VR_XS_PMA_SNPS_CR_CTRL);
	} while ((v & BIT(0)));

	return tsrn10_read_pcs(hw, p_id,  VR_XS_PMA_SNPS_CR_DATA);
}

struct tsrn10_pcs_operations pcs_ops_generic = {
	.read = tsrn10_read_pcs,
	.write = tsrn10_write_pcs,
};

struct tsrn10_pma_operations pma_ops_generic = {
	.read = tsrn10_read_pma,
	.write = tsrn10_write_pma,
};
