/* Copyright (c) 2020 Intel Corporation */
#include <stdio.h>
#include "internal.h"

#define RAH_RAH					0x0000FFFF
#define RAH_ASEL				0x00010000
#define RAH_QSEL				0x000C0000
#define RAH_QSEL_EN				0x10000000
#define RAH_AV					0x80000000
#define RCTL_RXEN				0x00000002
#define RCTL_SBP				0x00000004
#define RCTL_UPE				0x00000008
#define RCTL_MPE				0x00000010
#define RCTL_LPE				0x00000020
#define RCTL_LBM				0x000000C0
#define RCTL_LBM_PHY				0x00000000
#define RCTL_LBM_MAC				0x00000040
#define RCTL_HSEL				0x00000300
#define RCTL_HSEL_MULTICAST			0x00000000
#define RCTL_HSEL_UNICAST			0x00000100
#define RCTL_HSEL_BOTH				0x00000200
#define RCTL_MO					0x00003000
#define RCTL_MO_47_36				0x00000000
#define RCTL_MO_43_32				0x00001000
#define RCTL_MO_39_28				0x00002000
#define RCTL_BAM				0x00008000
#define RCTL_BSIZE				0x00030000
#define RCTL_BSIZE_2048				0x00000000
#define RCTL_BSIZE_1024				0x00010000
#define RCTL_BSIZE_512				0x00020000
#define RCTL_VFE				0x00040000
#define RCTL_CFIEN				0x00080000
#define RCTL_CFI				0x00100000
#define RCTL_PSP				0x00200000
#define RCTL_DPF				0x00400000
#define RCTL_PMCF				0x00800000
#define RCTL_SECRC				0x04000000

#define RAH_QSEL_SHIFT				18

static const char *bit_to_boolean(u32 val)
{
	return val ? "True" : "False";
}

static const char *bit_to_enable(u32 val)
{
	return val ? "Enabled" : "Disabled";
}

int igc_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs)
{
	u32 reg;
	int offset, i;
	u32 *regs_buff = (u32 *)regs->data;
	u8 version = (u8)(regs->version >> 24);

	if (version != 2)
		return -1;

	for (offset = 0; offset < 24; offset++) {
		reg = regs_buff[offset];
		printf("%04d: 0x%08X\n", offset, reg);
	}

	offset = 24;

	reg = regs_buff[offset];
	printf("%04d: RCTL (Receive Control Register)              \n"
	       "    Receiver:                                    %s\n"
	       "    Stop Bad Packets:                            %s\n"
	       "    Unicast Promiscuous:                         %s\n"
	       "    Multicast Promiscuous:                       %s\n"
	       "    Long Packet Reception:                       %s\n"
	       "    Loopback Model:                              %s\n"
	       "    Hash Select for MTA:                         %s\n"
	       "    Multicast/Unicast Table Offset:              %s\n"
	       "    Broadcast Accept Mode:                       %s\n"
	       "    Receive Buffer Size:                         %s\n"
	       "    VLAN Filter:                                 %s\n"
	       "    Canonical Form Indicator:                    %s\n"
	       "    Canonical Form Indicator Bit:                %s\n"
	       "    Pad Small Receive Packets:                   %s\n"
	       "    Discard Pause Frames:                        %s\n"
	       "    Pass MAC Control Frames:                     %s\n"
	       "    Strip Ethernet CRC:                          %s\n",
	       offset,
	       bit_to_enable(reg & RCTL_RXEN),
	       bit_to_enable(reg & RCTL_SBP),
	       bit_to_enable(reg & RCTL_UPE),
	       bit_to_enable(reg & RCTL_MPE),
	       bit_to_enable(reg & RCTL_LPE),
	       (reg & RCTL_LBM) == RCTL_LBM_PHY ? "PHY" :
	       (reg & RCTL_LBM) == RCTL_LBM_MAC ? "MAC" :
	       "Undefined",
	       (reg & RCTL_HSEL) == RCTL_HSEL_MULTICAST ? "Multicast Only" :
	       (reg & RCTL_HSEL) == RCTL_HSEL_UNICAST ? "Unicast Only" :
	       (reg & RCTL_HSEL) == RCTL_HSEL_BOTH ? "Multicast and Unicast" :
	       "Reserved",
	       (reg & RCTL_MO) == RCTL_MO_47_36 ? "Bits [47:36]" :
	       (reg & RCTL_MO) == RCTL_MO_43_32 ? "Bits [43:32]" :
	       (reg & RCTL_MO) == RCTL_MO_39_28 ? "Bits [39:28]" :
	       "Bits [35:24]",
	       bit_to_enable(reg & RCTL_BAM),
	       (reg & RCTL_BSIZE) == RCTL_BSIZE_2048 ? "2048 Bytes" :
	       (reg & RCTL_BSIZE) == RCTL_BSIZE_1024 ? "1024 Bytes" :
	       (reg & RCTL_BSIZE) == RCTL_BSIZE_512 ? "512 Bytes" :
	       "256 Bytes",
	       bit_to_enable(reg & RCTL_VFE),
	       bit_to_enable(reg & RCTL_CFIEN),
	       reg & RCTL_CFI ? "Discarded" : "Accepted",
	       bit_to_enable(reg & RCTL_PSP),
	       bit_to_enable(reg & RCTL_DPF),
	       bit_to_enable(reg & RCTL_PMCF),
	       bit_to_enable(reg & RCTL_SECRC));

	for (offset = 25; offset < 172; offset++) {
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
