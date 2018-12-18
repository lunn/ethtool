#include <stdio.h>
#include <string.h>

#include "internal.h"

/* Macros and dump functions for the 16-bit mv88e6xxx per-port registers */

#define REG(_reg, _name, _val) \
	printf("%.02u: %-38.38s 0x%.4x\n", _reg, _name, _val)

#define FIELD(_name, _fmt, ...) \
	printf("      %-36.36s " _fmt "\n", _name, ##__VA_ARGS__)

#define FIELD_BITMAP(_name, _val) \
	FIELD(_name, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", \
	      ((_val) & 0x0001) ? "0 " : "", \
	      ((_val) & 0x0002) ? "1 " : "", \
	      ((_val) & 0x0004) ? "2 " : "", \
	      ((_val) & 0x0008) ? "3 " : "", \
	      ((_val) & 0x0010) ? "4 " : "", \
	      ((_val) & 0x0020) ? "5 " : "", \
	      ((_val) & 0x0040) ? "6 " : "", \
	      ((_val) & 0x0080) ? "7 " : "", \
	      ((_val) & 0x0100) ? "8 " : "", \
	      ((_val) & 0x0200) ? "9 " : "", \
	      ((_val) & 0x0400) ? "10 " : "", \
	      ((_val) & 0x0800) ? "11 " : "", \
	      ((_val) & 0x1000) ? "12 " : "", \
	      ((_val) & 0x2000) ? "13 " : "", \
	      ((_val) & 0x4000) ? "14 " : "", \
	      ((_val) & 0x8000) ? "15 " : "")

struct dsa_mv88e6xxx_switch {
	void (*dump)(int reg, u16 val);
	const char *name;
	u16 id;
};

static const struct dsa_mv88e6xxx_switch dsa_mv88e6xxx_switches[] = {
};

static int dsa_mv88e6xxx_dump_regs(struct ethtool_regs *regs)
{
	const struct dsa_mv88e6xxx_switch *sw = NULL;
	const u16 *data = (u16 *)regs->data;
	u16 id;
	int i;

	/* Marvell chips have 32 per-port 16-bit registers */
	if (regs->len < 32 * 2)
		return 1;

	id = regs->version & 0xfff0;

	for (i = 0; i < ARRAY_SIZE(dsa_mv88e6xxx_switches); i++) {
		if (id == dsa_mv88e6xxx_switches[i].id) {
			sw = &dsa_mv88e6xxx_switches[i];
			break;
		}
	}

	if (!sw)
		return 1;

	printf("%s Switch Port Registers\n", sw->name);
	printf("------------------------------\n");

	for (i = 0; i < 32; i++)
		if (sw->dump)
			sw->dump(i, data[i]);
		else
			REG(i, "", data[i]);

	return 0;
}

#undef FIELD_BITMAP
#undef FIELD
#undef REG

int dsa_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs)
{
	/* DSA per-driver register dump */
	if (!dsa_mv88e6xxx_dump_regs(regs))
		return 0;

	/* Fallback to hexdump */
	return 1;
}
