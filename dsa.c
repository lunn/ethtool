#include <stdio.h>
#include <string.h>

#include "internal.h"

/* Macros and dump functions for the 16-bit mv88e6xxx per-port registers */

#define REG(_reg, _name, _val) \
	printf("%.02u: %-38.38s 0x%.4x\n", _reg, _name, _val)

#define REGHEX(_reg, _name, _val)					\
	printf("%.04x: %-38.38s 0x%.4x\n", _reg, _name, _val)

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

static void dsa_mv88e6161(int reg, u16 val)
{
	switch (reg) {
	case 0:
		REG(reg, "Port Status", val);
		FIELD("Pause Enabled", "%u", !!(val & 0x8000));
		FIELD("My Pause", "%u", !!(val & 0x4000));
		FIELD("Half-duplex Flow Control", "%u", !!(val & 0x2000));
		FIELD("802.3 PHY Detected", "%u", !!(val & 0x1000));
		FIELD("Link Status", "%s", val & 0x0800 ? "Up" : "Down");
		FIELD("Duplex", "%s", val & 0x0400 ? "Full" : "Half");
		FIELD("Speed", "%s",
		      (val & 0x0300) == 0x0000 ? "10 Mbps" :
		      (val & 0x0300) == 0x0100 ? "100 Mbps" :
		      (val & 0x0300) == 0x0200 ? "1000 Mbps" :
		      (val & 0x0300) == 0x0300 ? "Reserved" : "?");
		FIELD("Auto-Media Detect Disable", "%u", !!(val & 0x0040));
		FIELD("Transmitter Paused", "%u", !!(val & 0x0020));
		FIELD("Flow Control", "%u", !!(val & 0x0010));
		FIELD("Config Duplex", "%s", val & 0x0008 ? "Full" : "Half");
		FIELD("Config Mode", "0x%x", val & 0x0007);
		break;
	case 1:
		REG(reg, "PCS Control", val);
		FIELD("Flow Control's Forced value", "%u", !!(val & 0x0080));
		FIELD("Force Flow Control", "%u", !!(val & 0x0040));
		FIELD("Link's Forced value", "%s", val & 0x0020 ? "Up" : "Down");
		FIELD("Force Link", "%u", !!(val & 0x0010));
		FIELD("Duplex's Forced value", "%s", val & 0x0008 ? "Full" : "Half");
		FIELD("Force Duplex", "%u", !!(val & 0x0004));
		FIELD("Force Speed", "%s",
		      (val & 0x0003) == 0x0000 ? "10 Mbps" :
		      (val & 0x0003) == 0x0001 ? "100 Mbps" :
		      (val & 0x0003) == 0x0002 ? "1000 Mbps" :
		      (val & 0x0003) == 0x0003 ? "Not forced" : "?");
		break;
	case 2:
		REG(reg, "Jamming Control", val);
		break;
	case 3:
		REG(reg, "Switch Identifier", val);
		break;
	case 4:
		REG(reg, "Port Control", val);
		FIELD("Source Address Filtering controls", "%s",
		      (val & 0xc000) == 0x0000 ? "Disabled" :
		      (val & 0xc000) == 0x4000 ? "Drop On Lock" :
		      (val & 0xc000) == 0x8000 ? "Drop On Unlock" :
		      (val & 0xc000) == 0xc000 ? "Drop to CPU" : "?");
		FIELD("Egress Mode", "%s",
		      (val & 0x3000) == 0x0000 ? "Unmodified" :
		      (val & 0x3000) == 0x1000 ? "Untagged" :
		      (val & 0x3000) == 0x2000 ? "Tagged" :
		      (val & 0x3000) == 0x3000 ? "Reserved" : "?");
		FIELD("Ingress & Egress Header Mode", "%u", !!(val & 0x0800));
		FIELD("IGMP and MLD Snooping", "%u", !!(val & 0x0400));
		FIELD("Frame Mode", "%s",
		      (val & 0x0300) == 0x0000 ? "Normal" :
		      (val & 0x0300) == 0x0100 ? "DSA" :
		      (val & 0x0300) == 0x0200 ? "Provider" :
		      (val & 0x0300) == 0x0300 ? "Ether Type DSA" : "?");
		FIELD("VLAN Tunnel", "%u", !!(val & 0x0080));
		FIELD("TagIfBoth", "%u", !!(val & 0x0040));
		FIELD("Initial Priority assignment", "%s",
		      (val & 0x0030) == 0x0000 ? "Defaults" :
		      (val & 0x0030) == 0x0010 ? "Tag Priority" :
		      (val & 0x0030) == 0x0020 ? "IP Priority" :
		      (val & 0x0030) == 0x0030 ? "Tag & IP Priority" : "?");
		FIELD("Egress Flooding mode", "%s",
		      (val & 0x000c) == 0x0000 ? "No unknown DA" :
		      (val & 0x000c) == 0x0004 ? "No unknown multicast DA" :
		      (val & 0x000c) == 0x0008 ? "No unknown unicast DA" :
		      (val & 0x000c) == 0x000c ? "Allow unknown DA" : "?");
		FIELD("Port State", "%s",
		      (val & 0x0003) == 0x0000 ? "Disabled" :
		      (val & 0x0003) == 0x0001 ? "Blocking/Listening" :
		      (val & 0x0003) == 0x0002 ? "Learning" :
		      (val & 0x0003) == 0x0003 ? "Forwarding" : "?");
		break;
	case 5:
		REG(reg, "Port Control 1", val);
		FIELD("Message Port", "%u", !!(val & 0x8000));
		FIELD("Trunk Port", "%u", !!(val & 0x4000));
		FIELD("Trunk ID", "%u", (val & 0x0f00) >> 8);
		FIELD("FID[5:4]", "0x%.2x", (val & 0x0003) << 4);
		break;
	case 6:
		REG(reg, "Port Base VLAN Map (Header)", val);
		FIELD("FID[3:0]", "0x%.2x", (val & 0xf000) >> 12);
		FIELD_BITMAP("VLANTable", val & 0x003f);
		break;
	case 7:
		REG(reg, "Default VLAN ID & Priority", val);
		FIELD("Default Priority", "0x%x", (val & 0xe000) >> 13);
		FIELD("Force to use Default VID", "%u", !!(val & 0x1000));
		FIELD("Default VLAN Identifier", "%u", val & 0x0fff);
		break;
	case 8:
		REG(reg, "Port Control 2", val);
		FIELD("Force good FCS in the frame", "%u", !!(val & 0x8000));
		FIELD("Jumbo Mode", "%s",
		      (val & 0x3000) == 0x0000 ? "1522" :
		      (val & 0x3000) == 0x1000 ? "2048" :
		      (val & 0x3000) == 0x2000 ? "10240" :
		      (val & 0x3000) == 0x3000 ? "Reserved" : "?");
		FIELD("802.1QMode", "%s",
		      (val & 0x0c00) == 0x0000 ? "Disabled" :
		      (val & 0x0c00) == 0x0400 ? "Fallback" :
		      (val & 0x0c00) == 0x0800 ? "Check" :
		      (val & 0x0c00) == 0x0c00 ? "Secure" : "?");
		FIELD("Discard Tagged Frames", "%u", !!(val & 0x0200));
		FIELD("Discard Untagged Frames", "%u", !!(val & 0x0100));
		FIELD("Map using DA hits", "%u", !!(val & 0x0080));
		FIELD("ARP Mirror enable", "%u", !!(val & 0x0040));
		FIELD("Egress Monitor Source Port", "%u", !!(val & 0x0020));
		FIELD("Ingress Monitor Source Port", "%u", !!(val & 0x0010));
		break;
	case 9:
		REG(reg, "Egress Rate Control", val);
		break;
	case 10:
		REG(reg, "Egress Rate Control 2", val);
		break;
	case 11:
		REG(reg, "Port Association Vector", val);
		break;
	case 12:
		REG(reg, "Port ATU Control", val);
		break;
	case 13:
		REG(reg, "Priority Override", val);
		break;
	case 15:
		REG(reg, "PortEType", val);
		break;
	case 16:
		REG(reg, "InDiscardsLo Frame Counter", val);
		break;
	case 17:
		REG(reg, "InDiscardsHi Frame Counter", val);
		break;
	case 18:
		REG(reg, "InFiltered Frame Counter", val);
		break;
	case 19:
		REG(reg, "OutFiltered Frame Counter", val);
		break;
	case 24:
		REG(reg, "Tag Remap 0-3", val);
		break;
	case 25:
		REG(reg, "Tag Remap 4-7", val);
		break;
	case 27:
		REG(reg, "Queue Counters", val);
		break;
	default:
		REG(reg, "Reserved", val);
		break;
	}
}

static void dsa_mv88e6185(int reg, u16 val)
{
	switch (reg) {
	case 0:
		REG(reg, "Port Status", val);
		break;
	case 1:
		REG(reg, "PCS Control", val);
		break;
	case 3:
		REG(reg, "Switch Identifier", val);
		break;
	case 4:
		REG(reg, "Port Control", val);
		break;
	case 5:
		REG(reg, "Port Control 1", val);
		break;
	case 6:
		REG(reg, "Port Base VLAN Map (Header)", val);
		break;
	case 7:
		REG(reg, "Default VLAN ID & Priority", val);
		break;
	case 8:
		REG(reg, "Port Control 2", val);
		break;
	case 9:
		REG(reg, "Rate Control", val);
		break;
	case 10:
		REG(reg, "Rate Control 2", val);
		break;
	case 11:
		REG(reg, "Port Association Vector", val);
		break;
	case 16:
		REG(reg, "InDiscardsLo Frame Counter", val);
		break;
	case 17:
		REG(reg, "InDiscardsHi Frame Counter", val);
		break;
	case 18:
		REG(reg, "InFiltered Frame Counter", val);
		break;
	case 19:
		REG(reg, "OutFiltered Frame Counter", val);
		break;
	case 24:
		REG(reg, "Tag Remap 0-3", val);
		break;
	case 25:
		REG(reg, "Tag Remap 4-7", val);
		break;
	default:
		REG(reg, "Reserved", val);
		break;
	}
};

static void dsa_mv88e6352(int reg, u16 val)
{
	switch (reg) {
	case 0:
		REG(reg, "Port Status", val);
		FIELD("Pause Enabled", "%u", !!(val & 0x8000));
		FIELD("My Pause", "%u", !!(val & 0x4000));
		FIELD("802.3 PHY Detected", "%u", !!(val & 0x1000));
		FIELD("Link Status", "%s", val & 0x0800 ? "Up" : "Down");
		FIELD("Duplex", "%s", val & 0x0400 ? "Full" : "Half");
		FIELD("Speed", "%s",
		      (val & 0x0300) == 0x0000 ? "10 Mbps" :
		      (val & 0x0300) == 0x0100 ? "100 or 200 Mbps" :
		      (val & 0x0300) == 0x0200 ? "1000 Mbps" :
		      (val & 0x0300) == 0x0300 ? "Reserved" : "?");
		FIELD("EEE Enabled", "%u", !!(val & 0x0040));
		FIELD("Transmitter Paused", "%u", !!(val & 0x0020));
		FIELD("Flow Control", "%u", !!(val & 0x0010));
		FIELD("Config Mode", "0x%x", val & 0x000f);
		break;
	case 1:
		REG(reg, "Physical Control", val);
		FIELD("RGMII Receive Timing Control", "%s", val & 0x8000 ? "Delay" : "Default");
		FIELD("RGMII Transmit Timing Control", "%s", val & 0x4000 ? "Delay" : "Default");
		FIELD("200 BASE Mode", "%s", val & 0x1000 ? "200" : "100");
		FIELD("Flow Control's Forced value", "%u", !!(val & 0x0080));
		FIELD("Force Flow Control", "%u", !!(val & 0x0040));
		FIELD("Link's Forced value", "%s", val & 0x0020 ? "Up" : "Down");
		FIELD("Force Link", "%u", !!(val & 0x0010));
		FIELD("Duplex's Forced value", "%s", val & 0x0008 ? "Full" : "Half");
		FIELD("Force Duplex", "%u", !!(val & 0x0004));
		FIELD("Force Speed", "%s",
		      (val & 0x0003) == 0x0000 ? "10 Mbps" :
		      (val & 0x0003) == 0x0001 ? "100 or 200 Mbps" :
		      (val & 0x0003) == 0x0002 ? "1000 Mbps" :
		      (val & 0x0003) == 0x0003 ? "Not forced" : "?");
		break;
	case 2:
		REG(reg, "Jamming Control", val);
		break;
	case 3:
		REG(reg, "Switch Identifier", val);
		break;
	case 4:
		REG(reg, "Port Control", val);
		FIELD("Source Address Filtering controls", "%s",
		      (val & 0xc000) == 0x0000 ? "Disabled" :
		      (val & 0xc000) == 0x4000 ? "Drop On Lock" :
		      (val & 0xc000) == 0x8000 ? "Drop On Unlock" :
		      (val & 0xc000) == 0xc000 ? "Drop to CPU" : "?");
		FIELD("Egress Mode", "%s",
		      (val & 0x3000) == 0x0000 ? "Unmodified" :
		      (val & 0x3000) == 0x1000 ? "Untagged" :
		      (val & 0x3000) == 0x2000 ? "Tagged" :
		      (val & 0x3000) == 0x3000 ? "Reserved" : "?");
		FIELD("Ingress & Egress Header Mode", "%u", !!(val & 0x0800));
		FIELD("IGMP and MLD Snooping", "%u", !!(val & 0x0400));
		FIELD("Frame Mode", "%s",
		      (val & 0x0300) == 0x0000 ? "Normal" :
		      (val & 0x0300) == 0x0100 ? "DSA" :
		      (val & 0x0300) == 0x0200 ? "Provider" :
		      (val & 0x0300) == 0x0300 ? "Ether Type DSA" : "?");
		FIELD("VLAN Tunnel", "%u", !!(val & 0x0080));
		FIELD("TagIfBoth", "%u", !!(val & 0x0040));
		FIELD("Initial Priority assignment", "%s",
		      (val & 0x0030) == 0x0000 ? "Defaults" :
		      (val & 0x0030) == 0x0010 ? "Tag Priority" :
		      (val & 0x0030) == 0x0020 ? "IP Priority" :
		      (val & 0x0030) == 0x0030 ? "Tag & IP Priority" : "?");
		FIELD("Egress Flooding mode", "%s",
		      (val & 0x000c) == 0x0000 ? "No unknown DA" :
		      (val & 0x000c) == 0x0004 ? "No unknown multicast DA" :
		      (val & 0x000c) == 0x0008 ? "No unknown unicast DA" :
		      (val & 0x000c) == 0x000c ? "Allow unknown DA" : "?");
		FIELD("Port State", "%s",
		      (val & 0x0003) == 0x0000 ? "Disabled" :
		      (val & 0x0003) == 0x0001 ? "Blocking/Listening" :
		      (val & 0x0003) == 0x0002 ? "Learning" :
		      (val & 0x0003) == 0x0003 ? "Forwarding" : "?");
		break;
	case 5:
		REG(reg, "Port Control 1", val);
		FIELD("Message Port", "%u", !!(val & 0x8000));
		FIELD("Trunk Port", "%u", !!(val & 0x4000));
		FIELD("Trunk ID", "%u", (val & 0x0f00) >> 8);
		FIELD("FID[11:4]", "0x%.3x", (val & 0x00ff) << 4);
		break;
	case 6:
		REG(reg, "Port Base VLAN Map (Header)", val);
		FIELD("FID[3:0]", "0x%.3x", (val & 0xf000) >> 12);
		FIELD_BITMAP("VLANTable", val & 0x007f);
		break;
	case 7:
		REG(reg, "Default VLAN ID & Priority", val);
		FIELD("Default Priority", "0x%x", (val & 0xe000) >> 13);
		FIELD("Force to use Default VID", "%u", !!(val & 0x1000));
		FIELD("Default VLAN Identifier", "%u", val & 0x0fff);
		break;
	case 8:
		REG(reg, "Port Control 2", val);
		FIELD("Force good FCS in the frame", "%u", !!(val & 0x8000));
		FIELD("Jumbo Mode", "%s",
		      (val & 0x3000) == 0x0000 ? "1522" :
		      (val & 0x3000) == 0x1000 ? "2048" :
		      (val & 0x3000) == 0x2000 ? "10240" :
		      (val & 0x3000) == 0x3000 ? "Reserved" : "?");
		FIELD("802.1QMode", "%s",
		      (val & 0x0c00) == 0x0000 ? "Disabled" :
		      (val & 0x0c00) == 0x0400 ? "Fallback" :
		      (val & 0x0c00) == 0x0800 ? "Check" :
		      (val & 0x0c00) == 0x0c00 ? "Secure" : "?");
		FIELD("Discard Tagged Frames", "%u", !!(val & 0x0200));
		FIELD("Discard Untagged Frames", "%u", !!(val & 0x0100));
		FIELD("Map using DA hits", "%u", !!(val & 0x0080));
		FIELD("ARP Mirror enable", "%u", !!(val & 0x0040));
		FIELD("Egress Monitor Source Port", "%u", !!(val & 0x0020));
		FIELD("Ingress Monitor Source Port", "%u", !!(val & 0x0010));
		FIELD("Use Default Queue Priority", "%u", !!(val & 0x0008));
		FIELD("Default Queue Priority", "0x%x", (val & 0x0006) >> 1);
		break;
	case 9:
		REG(reg, "Egress Rate Control", val);
		break;
	case 10:
		REG(reg, "Egress Rate Control 2", val);
		break;
	case 11:
		REG(reg, "Port Association Vector", val);
		break;
	case 12:
		REG(reg, "Port ATU Control", val);
		break;
	case 13:
		REG(reg, "Override", val);
		break;
	case 14:
		REG(reg, "Policy Control", val);
		break;
	case 15:
		REG(reg, "Port Ether Type", val);
		break;
	case 16:
		REG(reg, "InDiscardsLo Frame Counter", val);
		break;
	case 17:
		REG(reg, "InDiscardsHi Frame Counter", val);
		break;
	case 18:
		REG(reg, "InFiltered/TcamCtr Frame Counter", val);
		break;
	case 19:
		REG(reg, "Rx Frame Counter", val);
		break;
	case 22:
		REG(reg, "LED Control", val);
		break;
	case 24:
		REG(reg, "Tag Remap 0-3", val);
		break;
	case 25:
		REG(reg, "Tag Remap 4-7", val);
		break;
	case 27:
		REG(reg, "Queue Counters", val);
		break;
	default:
		REG(reg, "Reserved", val);
		break;
	}
};

static const u16 mv88e6390_serdes_regs[] = {
	/* SERDES common registers */
	0xf00a, 0xf00b, 0xf00c,
	0xf010, 0xf011, 0xf012, 0xf013,
	0xf016, 0xf017, 0xf018,
	0xf01b, 0xf01c, 0xf01d, 0xf01e, 0xf01f,
	0xf020, 0xf021, 0xf022, 0xf023, 0xf024, 0xf025, 0xf026, 0xf027,
	0xf028, 0xf029,
	0xf030, 0xf031, 0xf032, 0xf033, 0xf034, 0xf035, 0xf036, 0xf037,
	0xf038, 0xf039,
	/* SGMII */
	0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
	0x2008,
	0x200f,
	0xa000, 0xa001, 0xa002, 0xa003,
	/* 10Gbase-X */
	0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007,
	0x1008,
	0x100e, 0x100f,
	0x1018, 0x1019,
	0x9000, 0x9001, 0x9002, 0x9003, 0x9004,
	0x9006,
	0x9010, 0x9011, 0x9012, 0x9013, 0x9014, 0x9015, 0x9016,
	/* 10Gbase-R */
	0x1020, 0x1021, 0x1022, 0x1023, 0x1024, 0x1025, 0x1026, 0x1027,
	0x1028, 0x1029, 0x102a, 0x102b,
};

static void dsa_mv88e6390(int reg, u16 val)
{
	if (reg > 31)
		reg = mv88e6390_serdes_regs[reg - 32];

	switch (reg) {
	case 0:
		REG(reg, "Port Status", val);
		FIELD("Transmit Pause Enable bit", "%u", !!(val & 0x8000));
		FIELD("Receive Pause Enable bit", "%u", !!(val & 0x4000));
		FIELD("802.3 PHY Detected", "%u", !!(val & 0x1000));
		FIELD("Link Status", "%s", val & 0x0800 ? "Up" : "Down");
		FIELD("Duplex", "%s", val & 0x0400 ? "Full" : "Half");
		FIELD("Speed", "%s",
		      (val & 0x0300) == 0x0000 ? "10 Mbps" :
		      (val & 0x0300) == 0x0100 ? "100 or 200 Mbps" :
		      (val & 0x0300) == 0x0200 ? "1000 Mbps" :
		      (val & 0x0300) == 0x0300 ? "10 Gb or 2500 Mbps" : "?");
		FIELD("Duplex Fixed", "%u", !!(val & 0x0080));
		FIELD("EEE Enabled", "%u", !!(val & 0x0040));
		FIELD("Transmitter Paused", "%u", !!(val & 0x0020));
		FIELD("Flow Control", "%u", !!(val & 0x0010));
		FIELD("Config Mode", "0x%x", val & 0x000f);
		break;
	case 1:
		REG(reg, "Physical Control", val);
		FIELD("RGMII Receive Timing Control", "%s", val & 0x8000 ? "Delay" : "Default");
		FIELD("RGMII Transmit Timing Control", "%s", val & 0x4000 ? "Delay" : "Default");
		FIELD("Force Speed", "%u", !!(val & 0x2000));
		FIELD("Alternate Speed Mode", "%s", val & 0x1000 ? "Alternate" : "Normal");
		FIELD("MII PHY Mode", "%s", val & 0x0800 ? "PHY" : "MAC");
		FIELD("EEE force value", "%u", !!(val & 0x0200));
		FIELD("Force EEE", "%u", !!(val & 0x0100));
		FIELD("Link's Forced value", "%s", val & 0x0020 ? "Up" : "Down");
		FIELD("Force Link", "%u", !!(val & 0x0010));
		FIELD("Duplex's Forced value", "%s", val & 0x0008 ? "Full" : "Half");
		FIELD("Force Duplex", "%u", !!(val & 0x0004));
		FIELD("Force Speed", "%s",
		      (val & 0x0003) == 0x0000 ? "10 Mbps" :
		      (val & 0x0003) == 0x0001 ? "100 or 200 Mbps" :
		      (val & 0x0003) == 0x0002 ? "1000 Mbps" :
		      (val & 0x0003) == 0x0003 ? "10 Gb or 2500 Mbps" : "?");
		break;
	case 2:
		REG(reg, "Flow Control", val);
		break;
	case 3:
		REG(reg, "Switch Identifier", val);
		break;
	case 4:
		REG(reg, "Port Control", val);
		FIELD("Source Address Filtering controls", "%s",
		      (val & 0xc000) == 0x0000 ? "Disabled" :
		      (val & 0xc000) == 0x4000 ? "Drop On Lock" :
		      (val & 0xc000) == 0x8000 ? "Drop On Unlock" :
		      (val & 0xc000) == 0xc000 ? "Drop to CPU" : "?");
		FIELD("Egress Mode", "%s",
		      (val & 0x3000) == 0x0000 ? "Unmodified" :
		      (val & 0x3000) == 0x1000 ? "Untagged" :
		      (val & 0x3000) == 0x2000 ? "Tagged" :
		      (val & 0x3000) == 0x3000 ? "Reserved" : "?");
		FIELD("Ingress & Egress Header Mode", "%u", !!(val & 0x0800));
		FIELD("IGMP and MLD Snooping", "%u", !!(val & 0x0400));
		FIELD("Frame Mode", "%s",
		      (val & 0x0300) == 0x0000 ? "Normal" :
		      (val & 0x0300) == 0x0100 ? "DSA" :
		      (val & 0x0300) == 0x0200 ? "Provider" :
		      (val & 0x0300) == 0x0300 ? "Ether Type DSA" : "?");
		FIELD("VLAN Tunnel", "%u", !!(val & 0x0080));
		FIELD("TagIfBoth", "%u", !!(val & 0x0040));
		FIELD("Initial Priority assignment", "%s",
		      (val & 0x0030) == 0x0000 ? "Defaults" :
		      (val & 0x0030) == 0x0010 ? "Tag Priority" :
		      (val & 0x0030) == 0x0020 ? "IP Priority" :
		      (val & 0x0030) == 0x0030 ? "Tag & IP Priority" : "?");
		FIELD("Egress Flooding mode", "%s",
		      (val & 0x000c) == 0x0000 ? "No unknown DA" :
		      (val & 0x000c) == 0x0004 ? "No unknown multicast DA" :
		      (val & 0x000c) == 0x0008 ? "No unknown unicast DA" :
		      (val & 0x000c) == 0x000c ? "Allow unknown DA" : "?");
		FIELD("Port State", "%s",
		      (val & 0x0003) == 0x0000 ? "Disabled" :
		      (val & 0x0003) == 0x0001 ? "Blocking/Listening" :
		      (val & 0x0003) == 0x0002 ? "Learning" :
		      (val & 0x0003) == 0x0003 ? "Forwarding" : "?");
		break;
	case 5:
		REG(reg, "Port Control 1", val);
		FIELD("Message Port", "%u", !!(val & 0x8000));
		FIELD("LAG Port", "%u", !!(val & 0x4000));
		FIELD("VTU Page", "%u", !!(val & 0x2000));
		FIELD("LAG ID", "%u", (val & 0x0f00) >> 8);
		FIELD("FID[11:4]", "0x%.3x", (val & 0x00ff) << 4);
		break;
	case 6:
		REG(reg, "Port Base VLAN Map (Header)", val);
		FIELD("FID[3:0]", "0x%.3x", (val & 0xf000) >> 12);
		FIELD("Force Mapping", "%u", !!(val & 0x0800));
		FIELD_BITMAP("VLANTable", val & 0x007ff);
		break;
	case 7:
		REG(reg, "Default VLAN ID & Priority", val);
		FIELD("Default Priority", "0x%x", (val & 0xe000) >> 13);
		FIELD("Force to use Default VID", "%u", !!(val & 0x1000));
		FIELD("Default VLAN Identifier", "%u", val & 0x0fff);
		break;
	case 8:
		REG(reg, "Port Control 2", val);
		FIELD("Force good FCS in the frame", "%u", !!(val & 0x8000));
		FIELD("Allow bad FCS", "%u", !!(val & 0x4000));
		FIELD("Jumbo Mode", "%s",
		      (val & 0x3000) == 0x0000 ? "1522" :
		      (val & 0x3000) == 0x1000 ? "2048" :
		      (val & 0x3000) == 0x2000 ? "10240" :
		      (val & 0x3000) == 0x3000 ? "Reserved" : "?");
		FIELD("802.1QMode", "%s",
		      (val & 0x0c00) == 0x0000 ? "Disabled" :
		      (val & 0x0c00) == 0x0400 ? "Fallback" :
		      (val & 0x0c00) == 0x0800 ? "Check" :
		      (val & 0x0c00) == 0x0c00 ? "Secure" : "?");
		FIELD("Discard Tagged Frames", "%u", !!(val & 0x0200));
		FIELD("Discard Untagged Frames", "%u", !!(val & 0x0100));
		FIELD("Map using DA hits", "%u", !!(val & 0x0080));
		FIELD("ARP Mirror enable", "%u", !!(val & 0x0040));
		FIELD("Egress Monitor Source Port", "%u", !!(val & 0x0020));
		FIELD("Ingress Monitor Source Port", "%u", !!(val & 0x0010));
		FIELD("Allow VID of Zero", "%u", !!(val & 0x0008));
		FIELD("Default Queue Priority", "0x%x", val & 0x0007);
		break;
	case 9:
		REG(reg, "Egress Rate Control", val);
		break;
	case 10:
		REG(reg, "Egress Rate Control 2", val);
		break;
	case 11:
		REG(reg, "Port Association Vector", val);
		break;
	case 12:
		REG(reg, "Port ATU Control", val);
		break;
	case 13:
		REG(reg, "Override", val);
		break;
	case 14:
		REG(reg, "Policy Control", val);
		break;
	case 15:
		REG(reg, "Port Ether Type", val);
		break;
	case 16 ... 21:
		REG(reg, "Reserved", val);
		break;
	case 22:
		REG(reg, "LED Control", val);
		break;
	case 23:
		REG(reg, "IP Priority Mapping Table", val);
		break;
	case 24:
		REG(reg, "IEEE Priority Mapping Table", val);
		break;
	case 25:
		REG(reg, "Port Control 3", val);
		break;
	case 26:
		REG(reg, "Reserved", val);
		break;
	case 27:
		REG(reg, "Queue Counters", val);
		break;
	case 28:
		REG(reg, "Queue Control", val);
		break;
	case 29:
		REG(reg, "Reserved", val);
		break;
	case 30:
		REG(reg, "Cut Through Control", val);
		break;
	case 31:
		REG(reg, "Debug Counters", val);
		break;

        /* SERDES Common registers */
	case 0xf00a:
		REGHEX(reg, "FIFO and CRC Int Enable", val);
		break;
	case 0xf00b:
		REGHEX(reg, "FIFO and CRC Int Status", val);
		break;
	case 0xf00c:
		REGHEX(reg, "PPM FIFO Control 1", val);
		break;
	case 0xf010:
		REGHEX(reg, "Packet Generation Control 1", val);
		break;
	case 0xf011:
		REGHEX(reg, "Packet Generation Control 2", val);
		break;
	case 0xf012:
		REGHEX(reg, "Initial Payload 0-1/Packet Generation", val);
		break;
	case 0xf013:
		REGHEX(reg, "Initial Payload 2-3/Packet Generation", val);
		break;
	case 0xf016:
		REGHEX(reg, "Packet Generation Length", val);
		break;
	case 0xf017:
		REGHEX(reg, "Packet Generation Burst Sequence", val);
		break;
	case 0xf018:
		REGHEX(reg, "Packet Generation IPG", val);
		break;
	case 0xf01b:
		REGHEX(reg, "Transmit Packet Counter [15:0]", val);
		break;
	case 0xf01c:
		REGHEX(reg, "Transmit Packet Counter [31:16]", val);
		break;
	case 0xf01d:
		REGHEX(reg, "Transmit Packet Counter [47:32]", val);
		break;
	case 0xf01e:
		REGHEX(reg, "Transmit Byte Counter [15:0]", val);
		break;
	case 0xf01f:
		REGHEX(reg, "Transmit Byte Counter [31:16]", val);
		break;
	case 0xf020:
		REGHEX(reg, "Transmit Byte Counter [47:32]", val);
		break;
	case 0xf021:
		REGHEX(reg, "Receive Packet Counter [15:0]", val);
		break;
	case 0xf022:
		REGHEX(reg, "Receive Packet Counter [31:16]", val);
		break;
	case 0xf023:
		REGHEX(reg, "Receive Byte Count [15:0]", val);
		break;
	case 0xf024:
		REGHEX(reg, "Receive Byte Count [31:16]", val);
		break;
	case 0xf025:
		REGHEX(reg, "Receive Byte Count [47:32]", val);
		break;
	case 0xf026:
		REGHEX(reg, "Receive Packet Error Count [15:0]", val);
		break;
	case 0xf027:
		REGHEX(reg, "Receive Packet Error Count [31:16]", val);
		break;
	case 0xf028:
		REGHEX(reg, "Receive Packet Error Count [47:32]", val);
		break;
	case 0xf029:
		REGHEX(reg, "PRBS Control", val);
		break;
	case 0xf030:
		REGHEX(reg, "PRBS Symbol Tx Counter [15:0]", val);
		break;
	case 0xf031:
		REGHEX(reg, "PRBS Symbol Tx Counter [31:16]", val);
		break;
	case 0xf032:
		REGHEX(reg, "PRBS Symbol Tx Counter [47:32]", val);
		break;
	case 0xf033:
		REGHEX(reg, "PRBS Symbol Rx Counter [15:0]", val);
		break;
	case 0xf034:
		REGHEX(reg, "PRBS Symbol Rx Counter [31:16]", val);
		break;
	case 0xf035:
		REGHEX(reg, "PRBS Symbol Rx Counter [47:32]", val);
		break;
	case 0xf036:
		REGHEX(reg, "PRBS Error Count [15:0]", val);
		break;
	case 0xf037:
		REGHEX(reg, "PRBS Error Count [31:16]", val);
		break;
	case 0xf038:
		REGHEX(reg, "PRBS Error Count [47:32]", val);
		break;
	case 0xf039:
		REGHEX(reg, "Receive Packet Counter [47:32]", val);
		break;
	case 0x2000:
		REGHEX(reg, "1000BASE-X/SGMII Control Register", val);
		FIELD("Reset", "%u", !!(val & 0x8000));
		FIELD("Loopback", "%u", !!(val & 0x4000));
		FIELD("SGMII Speed", "%s",
		      (val & (0x2000 | 0x0100)) == 0x0000 ? "10 Mbps" :
		      (val & (0x2000 | 0x0100)) == 0x2000 ? "100 Mbps" :
		      (val & (0x2000 | 0x0100)) == 0x0100 ? "1000 Mbps" :
		      (val & (0x2000 | 0x0100)) == (0x2000 | 0x0100) ?
		      	"Reserved" : "?");
		FIELD("Autoneg Enable", "%u", !!(val & 0x1000));
		FIELD("Power down", "%u", !!(val & 0x0800));
		FIELD("Isolate", "%u", !!(val & 0x0400));
		FIELD("Restart Autonet", "%u", !!(val & 0x0200));
		FIELD("Duplex", "%s", val & 0x0100 ? "Full" : "Half");
		break;
	case 0x2001:
		REGHEX(reg, "1000BASE-X/SGMII Status Register", val);
		FIELD("Autoneg Complete", "%u", !!(val & 0x0020));
		FIELD("Remote Fault", "%u", !!(val & 0x0010));
		FIELD("Link Status", "%s", val & 0x0004 ? "Up" : "Down");
		break;
	case 0x2002:
		REGHEX(reg, "PHY Identifier", val);
		break;
	case 0x2003:
		REGHEX(reg, "PHY Identifier", val);
		break;
	case 0x2004:
		REGHEX(reg, "SGMII (Media side) Auto-Negotiation Advertisement",
		       val);
		FIELD("Link Status", "%s", val & 0x8000 ? "Up" : "Down");
		FIELD("Duplex", "%s", val & 0x1000 ? "Full" : "Half");
		FIELD("SGMII Speed", "%s",
		      (val & 0x0c00) == 0x0000 ? "10 Mbps" :
		      (val & 0x0c00) == 0x0400 ? "100 Mbps" :
		      (val & 0x0c00) == 0x0800 ? "1000 Mbps" :
		      (val & 0x0c00) == 0x0c00 ? "Reserved" : "?");
		FIELD("Transmit Pause", "%u", !!(val & 0x0200));
		FIELD("Receive Pause", "%u", !!(val & 0x0100));
		FIELD("Fibre/Copper", "%s", val & 0x0080 ? "Fibre" : "Copper");
		FIELD("EEE mode", "%u", !!(val & 0x0040));
		FIELD("Clock stopped during LPI", "%u", !!(val & 0x0020));
		break;
	case 0x2005:
		REGHEX(reg, "SGMII (Media side) Link Partner Ability Register",
		       val);
		FIELD("Acknowledge", "%u", !!(val & 0x4000));
		break;
	case 0x2006:
		REGHEX(reg, "1000BASE-X Auto-Negotiation Expansion Register",
		       val);
		break;
	case 0x2007:
		REGHEX(reg, "1000BASE-X Next Page Transmit Register", val);
		break;
	case 0x2008:
		REGHEX(reg, "1000BASE-X Link Partner Next Page Register", val);
		break;
	case 0x200f:
		REGHEX(reg, "Extended Status Register", val);
		break;
	case 0xa000:
		REGHEX(reg, "1000BASE-X Timer Mode Select Register", val);
		break;
	case 0xa001:
		REGHEX(reg, "1000BASE-X Interrupt Enable Register ", val);
		FIELD("Speed Changed", "%u", !!(val & 0x4000));
		FIELD("Duplex Changed", "%u", !!(val & 0x2000));
		FIELD("Page Received", "%u", !!(val & 0x1000));
		FIELD("Autoneg Complete", "%u", !!(val & 0x0800));
		FIELD("Link Up->Link Down", "%u", !!(val & 0x0400));
		FIELD("Link Down->Link Up", "%u", !!(val & 0x0200));
		FIELD("Symbol Error", "%u", !!(val & 0x0100));
		FIELD("False Carrier", "%u", !!(val & 0x0080));
		break;
	case 0xa002:
		REGHEX(reg, "1000BASE-X Interrupt Status Register ", val);
		FIELD("Speed Changed", "%u", !!(val & 0x4000));
		FIELD("Duplex Changed", "%u", !!(val & 0x2000));
		FIELD("Page Received", "%u", !!(val & 0x1000));
		FIELD("Autoneg Complete", "%u", !!(val & 0x0800));
		FIELD("Link Up->Link Down", "%u", !!(val & 0x0400));
		FIELD("Link Down->Link Up", "%u", !!(val & 0x0200));
		FIELD("Symbol Error", "%u", !!(val & 0x0100));
		FIELD("False Carrier", "%u", !!(val & 0x0080));
		break;
	case 0xa003:
		REGHEX(reg, "1000BASE-X PHY Specific Status", val);
		FIELD("Speed", "%s",
		      (val & 0xc000) == 0x0000 ? "10 Mbps" :
		      (val & 0xc000) == 0x4000 ? "100 Mbps" :
		      (val & 0xc000) == 0x8000 ? "1000 Mbps" :
		      (val & 0xc000) == 0xc000 ? "Reserved" : "?");
		FIELD("Duplex", "%s", val & 0x2000 ? "Full" : "Half");
		FIELD("Page Received", "%u", !!(val & 0x1000));
		FIELD("Speed/Duplex Resolved", "%u", !!(val & 0x0800));
		FIELD("Link", "%s", val & 0x0400 ? "Up" : "Down");
		FIELD("Sync", "%u", !!(val & 0x0020));
		FIELD("Energy Detect", "%u", !!(val & 0x0010));
		FIELD("Transmit Pause", "%u", !!(val & 0x00080));
		FIELD("Receive Pause", "%u", !!(val & 0x00040));
		break;

	case 0x1000:
		REGHEX(reg, "10GBASE-X4 PCS Control 1", val);
		break;
	case 0x1001:
		REGHEX(reg, "10GBASE-X4 PCS Status 1", val);
		break;
	case 0x1002:
		REGHEX(reg, "PCS Device Identifier 1", val);
		break;
	case 0x1003:
		REGHEX(reg, "PCS Device Identifier 2", val);
		break;
	case 0x1004:
		REGHEX(reg, "CS Speed Ability", val);
		break;
	case 0x1005:
		REGHEX(reg, "PCS Devices In Package 1", val);
		break;
	case 0x1006:
		REGHEX(reg, "PCS Devices In Package 2", val);
		break;
	case 0x1008:
		REGHEX(reg, "10GBASE-X4 PCS Status 2", val);
		break;
	case 0x100e:
		REGHEX(reg, "PCS Package Identifier 1", val);
		break;
	case 0x100f:
		REGHEX(reg, "PCS Package Identifier 2", val);
		break;
	case 0x1018:
		REGHEX(reg, "10GBase-X Lane Status", val);
		break;
	case 0x1019:
		REGHEX(reg, "10GBase-X Test Control", val);
		break;
	case 0x9000:
		REGHEX(reg, "10GBase-X Control", val);
		break;
	case 0x9001:
		REGHEX(reg, "10GBase-X Interrupt Enable 1", val);
		break;
	case 0x9002:
		REGHEX(reg, "10GBase-X Interrupt Enable 2", val);
		break;
	case 0x9003:
		REGHEX(reg, "10GBase-X Interrupt Status 1", val);
		break;
	case 0x9004:
		REGHEX(reg, "10GBase-X Interrupt Status 2", val);
		break;
	case 0x9006:
		REGHEX(reg, "10GBase-X Real Time Status", val);
		break;
	case 0x9010:
		REGHEX(reg, "10GBase-X Random Sequence Control", val);
		break;
	case 0x9011:
		REGHEX(reg, "10GBase-X Jitter Packet Transmit Counter LSB",
		       val);
		break;
	case 0x9012:
		REGHEX(reg, "10GBase-X Jitter Packet Transmit Counter MSB",
		       val);
		break;
	case 0x9013:
		REGHEX(reg, "10GBase-X Jitter Packet Received Counter LSB",
		       val);
		break;
	case 0x9014:
		REGHEX(reg, "10GBase-X Jitter Packet Received Counter MSB",
		       val);
		break;
	case 0x9015:
		REGHEX(reg, "10GBase-X Jitter Packet Error Counter LSB",
		       val);
		break;
	case 0x9016:
		REGHEX(reg, "10GBase-X Jitter Packet Error Counter MSB",
		       val);
		break;
	case 0x1020:
		REGHEX(reg, "10GBASE-R PCS Status 1", val);
		break;
	case 0x1021:
		REGHEX(reg, "10GBASE-R PCS Status 2", val);
		break;
	case 0x1022:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed A 0", val);
		break;
	case 0x1023:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed A 1", val);
		break;
	case 0x1024:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed A 2", val);
		break;
	case 0x1025:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed A 3", val);
		break;
	case 0x1026:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed B 0", val);
		break;
	case 0x1027:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed B 1", val);
		break;
	case 0x1028:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed B 2", val);
		break;
	case 0x1029:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Seed B 3", val);
		break;
	case 0x102a:
		REGHEX(reg, "10GBASE-R PCS Test Pattern Control", val);
		break;
	case 0x102b:
		REGHEX(reg, "10GBASE-R PCS Test Error Counter", val);
		break;
	default:
		REGHEX(reg, "Reserved", val);
		break;
	}
};

struct dsa_mv88e6xxx_switch {
	void (*dump)(int reg, u16 val);
	const char *name;
	u16 id;
};

static const struct dsa_mv88e6xxx_switch dsa_mv88e6xxx_switches[] = {
	{ .id = 0x04a0, .name = "88E6085 ", .dump = NULL },
	{ .id = 0x0950, .name = "88E6095 ", .dump = NULL },
	{ .id = 0x0990, .name = "88E6097 ", .dump = NULL },
	{ .id = 0x0a00, .name = "88E6190X", .dump = dsa_mv88e6390 },
	{ .id = 0x0a10, .name = "88E6390X", .dump = dsa_mv88e6390 },
	{ .id = 0x1060, .name = "88E6131 ", .dump = NULL },
	{ .id = 0x1150, .name = "88E6320 ", .dump = NULL },
	{ .id = 0x1210, .name = "88E6123 ", .dump = dsa_mv88e6161 },
	{ .id = 0x1610, .name = "88E6161 ", .dump = dsa_mv88e6161 },
	{ .id = 0x1650, .name = "88E6165 ", .dump = NULL },
	{ .id = 0x1710, .name = "88E6171 ", .dump = NULL },
	{ .id = 0x1720, .name = "88E6172 ", .dump = dsa_mv88e6352 },
	{ .id = 0x1750, .name = "88E6175 ", .dump = NULL },
	{ .id = 0x1760, .name = "88E6176 ", .dump = dsa_mv88e6352 },
	{ .id = 0x1900, .name = "88E6190 ", .dump = dsa_mv88e6390 },
	{ .id = 0x1910, .name = "88E6191 ", .dump = NULL },
	{ .id = 0x1a70, .name = "88E6185 ", .dump = dsa_mv88e6185 },
	{ .id = 0x2400, .name = "88E6240 ", .dump = dsa_mv88e6352 },
	{ .id = 0x2900, .name = "88E6290 ", .dump = dsa_mv88e6390 },
	{ .id = 0x3100, .name = "88E6321 ", .dump = NULL },
	{ .id = 0x3400, .name = "88E6141 ", .dump = NULL },
	{ .id = 0x3410, .name = "88E6341 ", .dump = NULL },
	{ .id = 0x3520, .name = "88E6352 ", .dump = dsa_mv88e6352 },
	{ .id = 0x3710, .name = "88E6350 ", .dump = NULL },
	{ .id = 0x3750, .name = "88E6351 ", .dump = NULL },
	{ .id = 0x3900, .name = "88E6390 ", .dump = dsa_mv88e6390 },
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

	/* Dump the SERDES registers, if provided */
	if (regs->len > 32 * 2) {
		printf("\n%s Switch Port SERDES Registers\n", sw->name);
		printf("-------------------------------------\n");
		for (i = 32; i < regs->len / 2; i++)
			if (sw->dump)
				sw->dump(i, data[i]);
			else
				REG(i, "", data[i]);
	}

	return 0;
}

#undef FIELD_BITMAP
#undef FIELD
#undef REG

int dsa_dump_regs(struct ethtool_drvinfo *info maybe_unused,
		  struct ethtool_regs *regs)
{
	/* DSA per-driver register dump */
	if (!dsa_mv88e6xxx_dump_regs(regs))
		return 0;

	/* Fallback to hexdump */
	return 1;
}
