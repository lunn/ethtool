#include "internal.h"
#include "common.h"

char *so_timestamping_labels[N_SOTS] = {
	"hardware-transmit     (SOF_TIMESTAMPING_TX_HARDWARE)",
	"software-transmit     (SOF_TIMESTAMPING_TX_SOFTWARE)",
	"hardware-receive      (SOF_TIMESTAMPING_RX_HARDWARE)",
	"software-receive      (SOF_TIMESTAMPING_RX_SOFTWARE)",
	"software-system-clock (SOF_TIMESTAMPING_SOFTWARE)",
	"hardware-legacy-clock (SOF_TIMESTAMPING_SYS_HARDWARE)",
	"hardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)",
};

char *tx_type_labels[N_TX_TYPES] = {
	"off                   (HWTSTAMP_TX_OFF)",
	"on                    (HWTSTAMP_TX_ON)",
	"one-step-sync         (HWTSTAMP_TX_ONESTEP_SYNC)",
};

char *rx_filter_labels[N_RX_FILTERS] = {
	"none                  (HWTSTAMP_FILTER_NONE)",
	"all                   (HWTSTAMP_FILTER_ALL)",
	"some                  (HWTSTAMP_FILTER_SOME)",
	"ptpv1-l4-event        (HWTSTAMP_FILTER_PTP_V1_L4_EVENT)",
	"ptpv1-l4-sync         (HWTSTAMP_FILTER_PTP_V1_L4_SYNC)",
	"ptpv1-l4-delay-req    (HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ)",
	"ptpv2-l4-event        (HWTSTAMP_FILTER_PTP_V2_L4_EVENT)",
	"ptpv2-l4-sync         (HWTSTAMP_FILTER_PTP_V2_L4_SYNC)",
	"ptpv2-l4-delay-req    (HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ)",
	"ptpv2-l2-event        (HWTSTAMP_FILTER_PTP_V2_L2_EVENT)",
	"ptpv2-l2-sync         (HWTSTAMP_FILTER_PTP_V2_L2_SYNC)",
	"ptpv2-l2-delay-req    (HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ)",
	"ptpv2-event           (HWTSTAMP_FILTER_PTP_V2_EVENT)",
	"ptpv2-sync            (HWTSTAMP_FILTER_PTP_V2_SYNC)",
	"ptpv2-delay-req       (HWTSTAMP_FILTER_PTP_V2_DELAY_REQ)",
	"ntp-all               (HWTSTAMP_FILTER_NTP_ALL)",
};

#ifndef HAVE_NETIF_MSG
enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};
#endif

const struct flag_info flags_msglvl[] = {
	{ "drv",	NETIF_MSG_DRV },
	{ "probe",	NETIF_MSG_PROBE },
	{ "link",	NETIF_MSG_LINK },
	{ "timer",	NETIF_MSG_TIMER },
	{ "ifdown",	NETIF_MSG_IFDOWN },
	{ "ifup",	NETIF_MSG_IFUP },
	{ "rx_err",	NETIF_MSG_RX_ERR },
	{ "tx_err",	NETIF_MSG_TX_ERR },
	{ "tx_queued",	NETIF_MSG_TX_QUEUED },
	{ "intr",	NETIF_MSG_INTR },
	{ "tx_done",	NETIF_MSG_TX_DONE },
	{ "rx_status",	NETIF_MSG_RX_STATUS },
	{ "pktdata",	NETIF_MSG_PKTDATA },
	{ "hw",		NETIF_MSG_HW },
	{ "wol",	NETIF_MSG_WOL },
	{}
};
const unsigned int n_flags_msglvl = ARRAY_SIZE(flags_msglvl) - 1;

const char *names_duplex[] = {
	[DUPLEX_HALF]		= "Half",
	[DUPLEX_FULL]		= "Full",
};
DEFINE_ENUM_COUNT(duplex);

const char *names_port[] = {
	[PORT_TP]		= "Twisted Pair",
	[PORT_AUI]		= "AUI",
	[PORT_BNC]		= "BNC",
	[PORT_MII]		= "MII",
	[PORT_FIBRE]		= "FIBRE",
	[PORT_DA]		= "Direct Attach Copper",
	[PORT_NONE]		= "None",
	[PORT_OTHER]		= "Other",
};
DEFINE_ENUM_COUNT(port);

const char *names_transceiver[] = {
	[XCVR_INTERNAL]		= "internal",
	[XCVR_EXTERNAL]		= "external",
};
DEFINE_ENUM_COUNT(transceiver);

/* the practice of putting completely unrelated flags into link mode bitmaps
 * is rather unfortunate but as even ethtool_link_ksettings preserved that,
 * there is little chance of getting them separated any time soon so let's
 * sort them out ourselves
 */
const struct link_mode_info link_modes[] = {
        [ETHTOOL_LINK_MODE_10baseT_Half_BIT] =
		{ LM_CLASS_REAL,	10,	DUPLEX_HALF },
        [ETHTOOL_LINK_MODE_10baseT_Full_BIT] =
		{ LM_CLASS_REAL,	10,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_100baseT_Half_BIT] =
		{ LM_CLASS_REAL,	100,	DUPLEX_HALF },
        [ETHTOOL_LINK_MODE_100baseT_Full_BIT] =
		{ LM_CLASS_REAL,	100,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_1000baseT_Half_BIT] =
		{ LM_CLASS_REAL,	1000,	DUPLEX_HALF },
        [ETHTOOL_LINK_MODE_1000baseT_Full_BIT] =
		{ LM_CLASS_REAL,	1000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_Autoneg_BIT] =
		{ LM_CLASS_AUTONEG },
        [ETHTOOL_LINK_MODE_TP_BIT] =
		{ LM_CLASS_PORT },
        [ETHTOOL_LINK_MODE_AUI_BIT] =
		{ LM_CLASS_PORT },
        [ETHTOOL_LINK_MODE_MII_BIT] =
		{ LM_CLASS_PORT },
        [ETHTOOL_LINK_MODE_FIBRE_BIT] =
		{ LM_CLASS_PORT },
        [ETHTOOL_LINK_MODE_BNC_BIT] =
		{ LM_CLASS_PORT },
        [ETHTOOL_LINK_MODE_10000baseT_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_Pause_BIT] =
		{ LM_CLASS_PAUSE },
        [ETHTOOL_LINK_MODE_Asym_Pause_BIT] =
		{ LM_CLASS_PAUSE },
        [ETHTOOL_LINK_MODE_2500baseX_Full_BIT] =
		{ LM_CLASS_REAL,	2500,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_Backplane_BIT] =
		{ LM_CLASS_PORT },
        [ETHTOOL_LINK_MODE_1000baseKX_Full_BIT] =
		{ LM_CLASS_REAL,	1000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseKR_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseR_FEC_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT] =
		{ LM_CLASS_REAL,	20000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT] =
		{ LM_CLASS_REAL,	20000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT] =
		{ LM_CLASS_REAL,	40000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT] =
		{ LM_CLASS_REAL,	40000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT] =
		{ LM_CLASS_REAL,	40000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT] =
		{ LM_CLASS_REAL,	40000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT] =
		{ LM_CLASS_REAL,	56000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT] =
		{ LM_CLASS_REAL,	56000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT] =
		{ LM_CLASS_REAL,	56000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT] =
		{ LM_CLASS_REAL,	56000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_25000baseCR_Full_BIT] =
		{ LM_CLASS_REAL,	25000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_25000baseKR_Full_BIT] =
		{ LM_CLASS_REAL,	25000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_25000baseSR_Full_BIT] =
		{ LM_CLASS_REAL,	25000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_1000baseX_Full_BIT] =
		{ LM_CLASS_REAL,	1000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseCR_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseSR_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseLR_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_10000baseER_Full_BIT] =
		{ LM_CLASS_REAL,	10000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_2500baseT_Full_BIT] =
		{ LM_CLASS_REAL,	2500,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_5000baseT_Full_BIT] =
		{ LM_CLASS_REAL,	5000,	DUPLEX_FULL },
        [ETHTOOL_LINK_MODE_FEC_NONE_BIT] =
		{ LM_CLASS_FEC },
        [ETHTOOL_LINK_MODE_FEC_RS_BIT] =
		{ LM_CLASS_FEC },
        [ETHTOOL_LINK_MODE_FEC_BASER_BIT] =
		{ LM_CLASS_FEC },
};
const unsigned int link_modes_count = ARRAY_SIZE(link_modes);

void print_flags(const struct flag_info *info, unsigned int n_info, u32 value)
{
	const char *sep = "";

	while (n_info) {
		if (value & info->value) {
			printf("%s%s", sep, info->name);
			sep = " ";
			value &= ~info->value;
		}
		++info;
		--n_info;
	}

	/* Print any unrecognised flags in hex */
	if (value)
		printf("%s%#x", sep, value);
}

void __print_enum(const char *const *info, unsigned int n_info, unsigned int val,
		const char *label, const char *unknown)
{
	if (val >= n_info || !info[val]) {
		printf("%s", label);
		printf(unknown, val);
		fputc('\n', stdout);
	} else {
		printf("%s%s\n", label, info[val]);
	}
}

static char *unparse_wolopts(int wolopts)
{
	static char buf[16];
	char *p = buf;

	memset(buf, 0, sizeof(buf));

	if (wolopts) {
		if (wolopts & WAKE_PHY)
			*p++ = 'p';
		if (wolopts & WAKE_UCAST)
			*p++ = 'u';
		if (wolopts & WAKE_MCAST)
			*p++ = 'm';
		if (wolopts & WAKE_BCAST)
			*p++ = 'b';
		if (wolopts & WAKE_ARP)
			*p++ = 'a';
		if (wolopts & WAKE_MAGIC)
			*p++ = 'g';
		if (wolopts & WAKE_MAGICSECURE)
			*p++ = 's';
		if (wolopts & WAKE_FILTER)
			*p++ = 'f';
	} else {
		*p = 'd';
	}

	return buf;
}

int dump_wol(struct ethtool_wolinfo *wol)
{
	fprintf(stdout, "	Supports Wake-on: %s\n",
		unparse_wolopts(wol->supported));
	fprintf(stdout, "	Wake-on: %s\n",
		unparse_wolopts(wol->wolopts));
	if (wol->supported & WAKE_MAGICSECURE) {
		int i;
		int delim = 0;

		fprintf(stdout, "        SecureOn password: ");
		for (i = 0; i < SOPASS_MAX; i++) {
			fprintf(stdout, "%s%02x", delim?":":"", wol->sopass[i]);
			delim = 1;
		}
		fprintf(stdout, "\n");
	}

	return 0;
}

void dump_mdix(u8 mdix, u8 mdix_ctrl)
{
	fprintf(stdout, "	MDI-X: ");
	if (mdix_ctrl == ETH_TP_MDI) {
		fprintf(stdout, "off (forced)\n");
	} else if (mdix_ctrl == ETH_TP_MDI_X) {
		fprintf(stdout, "on (forced)\n");
	} else {
		switch (mdix) {
		case ETH_TP_MDI:
			fprintf(stdout, "off");
			break;
		case ETH_TP_MDI_X:
			fprintf(stdout, "on");
			break;
		default:
			fprintf(stdout, "Unknown");
			break;
		}
		if (mdix_ctrl == ETH_TP_MDI_AUTO)
			fprintf(stdout, " (auto)");
		fprintf(stdout, "\n");
	}
}
