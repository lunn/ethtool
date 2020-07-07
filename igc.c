/* Copyright (c) 2020 Intel Corporation */
#include <stdio.h>
#include "internal.h"

#define RAH_RAH					0x0000FFFF
#define RAH_ASEL				0x00010000
#define RAH_QSEL				0x000C0000
#define RAH_QSEL_EN				0x10000000
#define RAH_AV					0x80000000

#define RAH_QSEL_SHIFT				18

static const char *bit_to_boolean(u32 val)
{
	return val ? "True" : "False";
}

int igc_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs)
{
	u32 reg;
	int offset, i;
	u32 *regs_buff = (u32 *)regs->data;
	u8 version = (u8)(regs->version >> 24);

	if (version != 2)
		return -1;

	for (offset = 0; offset < 172; offset++) {
		reg = regs_buff[offset];
		printf("%04d: 0x%08X\n", offset, reg);
	}

	offset = 172;

	for (i = 0; i < 16; i++) {
		reg = regs_buff[offset + i];
		printf("%04d: RAL (Receive Address Low %02d)               \n"
		       "    Receive Address Low:                       %08X\n",
		       offset + i, i,
		       reg);
	}

	offset = 188;

	for (i = 0; i < 16; i++) {
		reg = regs_buff[offset + i];
		printf("%04d: RAH (Receive Address High %02d)              \n"
		       "    Receive Address High:                      %04X\n"
		       "    Address Select:                            %s\n"
		       "    Queue Select:                              %d\n"
		       "    Queue Select Enable:                       %s\n"
		       "    Address Valid:                             %s\n",
		       offset + i, i,
		       reg & RAH_RAH,
		       reg & RAH_ASEL ? "Source" : "Destination",
		       (reg & RAH_QSEL) >> RAH_QSEL_SHIFT,
		       bit_to_boolean(reg & RAH_QSEL_EN),
		       bit_to_boolean(reg & RAH_AV));
	}

	return 0;
}
