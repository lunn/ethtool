/*
 * settings.c - netlink implementation of settings commands
 *
 * Implementation of "ethtool <dev>" and "ethtool -s <dev> ...".
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "bitset.h"
#include "parser.h"

/* GET_SETTINGS */

struct link_mode_info {
	enum link_mode_class	class;
	u32			speed;
	u8			duplex;
};

static const char *const names_duplex[] = {
	[DUPLEX_HALF]		= "Half",
	[DUPLEX_FULL]		= "Full",
};

static const char *const names_port[] = {
	[PORT_TP]		= "Twisted Pair",
	[PORT_AUI]		= "AUI",
	[PORT_BNC]		= "BNC",
	[PORT_MII]		= "MII",
	[PORT_FIBRE]		= "FIBRE",
	[PORT_DA]		= "Direct Attach Copper",
	[PORT_NONE]		= "None",
	[PORT_OTHER]		= "Other",
};

static const char *const names_transceiver[] = {
	[XCVR_INTERNAL]		= "internal",
	[XCVR_EXTERNAL]		= "external",
};

/* the practice of putting completely unrelated flags into link mode bitmaps
 * is rather unfortunate but as even ethtool_link_ksettings preserved that,
 * there is little chance of getting them separated any time soon so let's
 * sort them out ourselves
 */
static const struct link_mode_info link_modes[] = {
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
	[ETHTOOL_LINK_MODE_50000baseKR_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_50000baseSR_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_50000baseCR_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_50000baseDR_Full_BIT] =
		{ LM_CLASS_REAL,	50000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT] =
		{ LM_CLASS_REAL,	100000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT] =
		{ LM_CLASS_REAL,	200000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT] =
		{ LM_CLASS_REAL,	200000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT] =
		{ LM_CLASS_REAL,	200000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT] =
		{ LM_CLASS_REAL,	200000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT] =
		{ LM_CLASS_REAL,	200000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_100baseT1_Full_BIT] =
		{ LM_CLASS_REAL,	100,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_1000baseT1_Full_BIT] =
		{ LM_CLASS_REAL,	1000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT] =
		{ LM_CLASS_REAL,	400000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT] =
		{ LM_CLASS_REAL,	400000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT] =
		{ LM_CLASS_REAL,	400000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT] =
		{ LM_CLASS_REAL,	400000,	DUPLEX_FULL },
	[ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT] =
		{ LM_CLASS_REAL,	400000,	DUPLEX_FULL },
};
const unsigned int link_modes_count = ARRAY_SIZE(link_modes);

static bool lm_class_match(unsigned int mode, enum link_mode_class class)
{
	unsigned int mode_class = (mode < link_modes_count) ?
				   link_modes[mode].class : LM_CLASS_UNKNOWN;

	return mode_class == class ||
	       (class == LM_CLASS_REAL && mode_class == LM_CLASS_UNKNOWN);
}

static void print_enum(const char *const *info, unsigned int n_info,
		       unsigned int val, const char *label)
{
	if (val >= n_info || !info[val])
		printf("\t%s: Unknown! (%d)\n", label, val);
	else
		printf("\t%s: %s\n", label, info[val]);
}

static int dump_pause(const struct nlattr *attr, bool mask, const char *label)
{
	bool pause, asym;
	int ret = 0;

	pause = bitset_get_bit(attr, mask, ETHTOOL_LINK_MODE_Pause_BIT, &ret);
	if (ret < 0)
		goto err;
	asym = bitset_get_bit(attr, mask, ETHTOOL_LINK_MODE_Asym_Pause_BIT,
			      &ret);
	if (ret < 0)
		goto err;

	printf("\t%s", label);
	if (pause)
		printf("%s\n", asym ?  "Symmetric Receive-only" : "Symmetric");
	else
		printf("%s\n", asym ? "Transmit-only" : "No");

	return 0;
err:
	fprintf(stderr, "malformed netlink message (pause modes)\n");
	return ret;
}

static void print_banner(struct nl_context *nlctx)
{
	if (nlctx->no_banner)
		return;
	printf("Settings for %s:\n", nlctx->devname);
	nlctx->no_banner = true;
}

int dump_link_modes(struct nl_context *nlctx, const struct nlattr *bitset,
		    bool mask, unsigned int class, const char *before,
		    const char *between, const char *after, const char *if_none)
{
	const struct nlattr *bitset_tb[ETHTOOL_A_BITSET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(bitset_tb);
	const unsigned int before_len = strlen(before);
	const struct nlattr *bits;
	const struct nlattr *bit;
	bool first = true;
	int prev = -2;
	int ret;

	ret = mnl_attr_parse_nested(bitset, attr_cb, &bitset_tb_info);
	bits = bitset_tb[ETHTOOL_A_BITSET_BITS];
	if (ret < 0)
		goto err_nonl;
	if (!bits) {
		const struct stringset *lm_strings;
		unsigned int count;
		unsigned int idx;
		const char *name;

		ret = netlink_init_ethnl2_socket(nlctx);
		if (ret < 0)
			goto err_nonl;
		lm_strings = global_stringset(ETH_SS_LINK_MODES,
					      nlctx->ethnl2_socket);
		bits = mask ? bitset_tb[ETHTOOL_A_BITSET_MASK] :
			      bitset_tb[ETHTOOL_A_BITSET_VALUE];
		ret = -EFAULT;
		if (!bits || !bitset_tb[ETHTOOL_A_BITSET_SIZE])
			goto err_nonl;
		count = mnl_attr_get_u32(bitset_tb[ETHTOOL_A_BITSET_SIZE]);
		if (mnl_attr_get_payload_len(bits) / 4 < (count + 31) / 32)
			goto err_nonl;

		printf("\t%s", before);
		for (idx = 0; idx < count; idx++) {
			const uint32_t *raw_data = mnl_attr_get_payload(bits);
			char buff[14];

			if (!(raw_data[idx / 32] & (1U << (idx % 32))))
				continue;
			if (!lm_class_match(idx, class))
				continue;
			name = get_string(lm_strings, idx);
			if (!name) {
				snprintf(buff, sizeof(buff), "BIT%u", idx);
				name = buff;
			}
			if (first)
				first = false;
			/* ugly hack to preserve old output format */
			if (class == LM_CLASS_REAL && (prev == idx - 1) &&
			    prev < link_modes_count &&
			    link_modes[prev].class == LM_CLASS_REAL &&
			    link_modes[prev].duplex == DUPLEX_HALF)
				putchar(' ');
			else if (between)
				printf("\t%s", between);
			else
				printf("\n\t%*s", before_len, "");
			printf("%s", name);
			prev = idx;
		}
		goto after;
	}

	printf("\t%s", before);
	mnl_attr_for_each_nested(bit, bits) {
		const struct nlattr *tb[ETHTOOL_A_BITSET_BIT_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);
		unsigned int idx;
		const char *name;

		if (mnl_attr_get_type(bit) != ETHTOOL_A_BITSET_BITS_BIT)
			continue;
		ret = mnl_attr_parse_nested(bit, attr_cb, &tb_info);
		if (ret < 0)
			goto err;
		ret = -EFAULT;
		if (!tb[ETHTOOL_A_BITSET_BIT_INDEX] ||
		    !tb[ETHTOOL_A_BITSET_BIT_NAME])
			goto err;
		if (!mask && !tb[ETHTOOL_A_BITSET_BIT_VALUE])
			continue;

		idx = mnl_attr_get_u32(tb[ETHTOOL_A_BITSET_BIT_INDEX]);
		name = mnl_attr_get_str(tb[ETHTOOL_A_BITSET_BIT_NAME]);
		if (!lm_class_match(idx, class))
			continue;
		if (first) {
			first = false;
		} else {
			/* ugly hack to preserve old output format */
			if ((class == LM_CLASS_REAL) && (prev == idx - 1) &&
			    (prev < link_modes_count) &&
			    (link_modes[prev].class == LM_CLASS_REAL) &&
			    (link_modes[prev].duplex == DUPLEX_HALF))
				putchar(' ');
			else if (between)
				printf("\t%s", between);
			else
				printf("\n\t%*s", before_len, "");
		}
		printf("%s", name);
		prev = idx;
	}
after:
	if (first && if_none)
		printf("%s", if_none);
	printf(after);

	return 0;
err:
	putchar('\n');
err_nonl:
	fflush(stdout);
	fprintf(stderr, "malformed netlink message (link_modes)\n");
	return ret;
}

static int dump_our_modes(struct nl_context *nlctx, const struct nlattr *attr)
{
	bool autoneg;
	int ret;

	print_banner(nlctx);
	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_PORT,
			      "Supported ports: [ ", " ", " ]\n", NULL);
	if (ret < 0)
		return ret;

	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_REAL,
			      "Supported link modes:   ", NULL, "\n",
			      "Not reported");
	if (ret < 0)
		return ret;
	ret = dump_pause(attr, true, "Supported pause frame use: ");
	if (ret < 0)
		return ret;

	autoneg = bitset_get_bit(attr, true, ETHTOOL_LINK_MODE_Autoneg_BIT,
				 &ret);
	if (ret < 0)
		return ret;
	printf("\tSupports auto-negotiation: %s\n", autoneg ? "Yes" : "No");

	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_FEC,
			      "Supported FEC modes: ", " ", "\n",
			      "Not reported");
	if (ret < 0)
		return ret;

	ret = dump_link_modes(nlctx, attr, false, LM_CLASS_REAL,
			      "Advertised link modes:  ", NULL, "\n",
			      "Not reported");
	if (ret < 0)
		return ret;

	ret = dump_pause(attr, false, "Advertised pause frame use: ");
	if (ret < 0)
		return ret;
	autoneg = bitset_get_bit(attr, false, ETHTOOL_LINK_MODE_Autoneg_BIT,
				 &ret);
	if (ret < 0)
		return ret;
	printf("\tAdvertised auto-negotiation: %s\n", autoneg ? "Yes" : "No");

	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_FEC,
			      "Advertised FEC modes: ", " ", "\n",
			      "Not reported");
	return ret;
}

static int dump_peer_modes(struct nl_context *nlctx, const struct nlattr *attr)
{
	bool autoneg;
	int ret;

	print_banner(nlctx);
	ret = dump_link_modes(nlctx, attr, false, LM_CLASS_REAL,
			      "Link partner advertised link modes:  ",
			      NULL, "\n", "Not reported");
	if (ret < 0)
		return ret;

	ret = dump_pause(attr, false,
			 "Link partner advertised pause frame use: ");
	if (ret < 0)
		return ret;

	autoneg = bitset_get_bit(attr, false,
				 ETHTOOL_LINK_MODE_Autoneg_BIT, &ret);
	if (ret < 0)
		return ret;
	printf("\tLink partner advertised auto-negotiation: %s\n",
	       autoneg ? "Yes" : "No");

	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_FEC,
			      "Link partner advertised FEC modes: ",
			      " ", "\n", "No");
	return ret;
}

int linkmodes_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_LINKMODES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		nlctx->no_banner = false;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_LINKMODES_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (tb[ETHTOOL_A_LINKMODES_OURS]) {
		ret = dump_our_modes(nlctx, tb[ETHTOOL_A_LINKMODES_OURS]);
		if (ret < 0)
			goto err;
	}
	if (tb[ETHTOOL_A_LINKMODES_PEER]) {
		ret = dump_peer_modes(nlctx, tb[ETHTOOL_A_LINKMODES_PEER]);
		if (ret < 0)
			goto err;
	}
	if (tb[ETHTOOL_A_LINKMODES_SPEED]) {
		uint32_t val = mnl_attr_get_u32(tb[ETHTOOL_A_LINKMODES_SPEED]);

		print_banner(nlctx);
		if (val == 0 || val == (uint16_t)(-1) || val == (uint32_t)(-1))
			printf("\tSpeed: Unknown!\n");
		else
			printf("\tSpeed: %uMb/s\n", val);
	}
	if (tb[ETHTOOL_A_LINKMODES_DUPLEX]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKMODES_DUPLEX]);

		print_banner(nlctx);
		print_enum(names_duplex, ARRAY_SIZE(names_duplex), val,
			   "Duplex");
	}
	if (tb[ETHTOOL_A_LINKMODES_AUTONEG]) {
		int autoneg = mnl_attr_get_u8(tb[ETHTOOL_A_LINKMODES_AUTONEG]);

		print_banner(nlctx);
		printf("\tAuto-negotiation: %s\n",
		       (autoneg == AUTONEG_DISABLE) ? "off" : "on");
	}

	return MNL_CB_OK;
err:
	if (nlctx->is_monitor || nlctx->is_dump)
		return MNL_CB_OK;
	fputs("No data available\n", stdout);
	nlctx->exit_code = 75;
	return MNL_CB_ERROR;
}

int linkinfo_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_LINKINFO_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int port = -1;
	int ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		nlctx->no_banner = false;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_LINKINFO_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (tb[ETHTOOL_A_LINKINFO_PORT]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_PORT]);

		print_banner(nlctx);
		print_enum(names_port, ARRAY_SIZE(names_port), val, "Port");
		port = val;
	}
	if (tb[ETHTOOL_A_LINKINFO_PHYADDR]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_PHYADDR]);

		print_banner(nlctx);
		printf("\tPHYAD: %u\n", val);
	}
	if (tb[ETHTOOL_A_LINKINFO_TRANSCEIVER]) {
		uint8_t val;

		val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_TRANSCEIVER]);
		print_banner(nlctx);
		print_enum(names_transceiver, ARRAY_SIZE(names_transceiver),
			   val, "Transceiver");
	}
	if (tb[ETHTOOL_A_LINKINFO_TP_MDIX] && tb[ETHTOOL_A_LINKINFO_TP_MDIX] &&
	    port == PORT_TP) {
		uint8_t mdix = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_TP_MDIX]);
		uint8_t mdix_ctrl =
			mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_TP_MDIX_CTRL]);

		print_banner(nlctx);
		dump_mdix(mdix, mdix_ctrl);
	}

	return MNL_CB_OK;
}

int linkstate_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_LINKSTATE_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		nlctx->no_banner = false;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_LINKSTATE_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (tb[ETHTOOL_A_LINKSTATE_LINK]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKSTATE_LINK]);

		print_banner(nlctx);
		printf("\tLink detected: %s\n", val ? "yes" : "no");
	}

	return MNL_CB_OK;
}

void wol_modes_cb(unsigned int idx, const char *name, bool val, void *data)
{
	struct ethtool_wolinfo *wol = data;

	if (idx >= 32)
		return;
	wol->supported |= (1U << idx);
	if (val)
		wol->wolopts |= (1U << idx);
}

int wol_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_WOL_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	struct ethtool_wolinfo wol = {};
	int ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		nlctx->no_banner = false;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_WOL_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (tb[ETHTOOL_A_WOL_MODES])
		walk_bitset(tb[ETHTOOL_A_WOL_MODES], NULL, wol_modes_cb, &wol);
	if (tb[ETHTOOL_A_WOL_SOPASS]) {
		unsigned int len;

		len = mnl_attr_get_payload_len(tb[ETHTOOL_A_WOL_SOPASS]);
		if (len != SOPASS_MAX)
			fprintf(stderr, "invalid SecureOn password length %u (should be %u)\n",
				len, SOPASS_MAX);
		else
			memcpy(wol.sopass,
			       mnl_attr_get_payload(tb[ETHTOOL_A_WOL_SOPASS]),
			       SOPASS_MAX);
	}
	print_banner(nlctx);
	dump_wol(&wol);

	return MNL_CB_OK;
}

void msgmask_cb(unsigned int idx, const char *name, bool val, void *data)
{
	u32 *msg_mask = data;

	if (idx >= 32)
		return;
	if (val)
		*msg_mask |= (1U << idx);
}

void msgmask_cb2(unsigned int idx, const char *name, bool val, void *data)
{
	if (val)
		printf(" %s", name);
}

int debug_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_DEBUG_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const struct stringset *msgmask_strings = NULL;
	struct nl_context *nlctx = data;
	u32 msg_mask = 0;
	int ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		nlctx->no_banner = false;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_DEBUG_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (!tb[ETHTOOL_A_DEBUG_MSGMASK])
		return MNL_CB_OK;
	if (bitset_is_compact(tb[ETHTOOL_A_DEBUG_MSGMASK])) {
		ret = netlink_init_ethnl2_socket(nlctx);
		if (ret < 0)
			return MNL_CB_OK;
		msgmask_strings = global_stringset(ETH_SS_MSG_CLASSES,
						   nlctx->ethnl2_socket);
	}

	print_banner(nlctx);
	walk_bitset(tb[ETHTOOL_A_DEBUG_MSGMASK], NULL, msgmask_cb, &msg_mask);
	printf("        Current message level: 0x%08x (%u)\n"
	       "                              ",
	       msg_mask, msg_mask);
	walk_bitset(tb[ETHTOOL_A_DEBUG_MSGMASK], msgmask_strings, msgmask_cb2,
		    NULL);
	fputc('\n', stdout);

	return MNL_CB_OK;
}

static int gset_request(struct nl_socket *nlsk, uint8_t msg_type,
			uint16_t hdr_attr, mnl_cb_t cb)
{
	int ret;

	ret = nlsock_prep_get_request(nlsk, msg_type, hdr_attr, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, cb);
}

int nl_gset(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	nlctx->suppress_nlerr = 1;

	ret = gset_request(nlsk, ETHTOOL_MSG_LINKMODES_GET,
			   ETHTOOL_A_LINKMODES_HEADER, linkmodes_reply_cb);
	if (ret == -ENODEV)
		return ret;

	ret = gset_request(nlsk, ETHTOOL_MSG_LINKINFO_GET,
			   ETHTOOL_A_LINKINFO_HEADER, linkinfo_reply_cb);
	if (ret == -ENODEV)
		return ret;

	ret = gset_request(nlsk, ETHTOOL_MSG_WOL_GET, ETHTOOL_A_WOL_HEADER,
			   wol_reply_cb);
	if (ret == -ENODEV)
		return ret;

	ret = gset_request(nlsk, ETHTOOL_MSG_DEBUG_GET, ETHTOOL_A_DEBUG_HEADER,
			   debug_reply_cb);
	if (ret == -ENODEV)
		return ret;

	ret = gset_request(nlsk, ETHTOOL_MSG_LINKSTATE_GET,
			   ETHTOOL_A_LINKSTATE_HEADER, linkstate_reply_cb);
	if (ret == -ENODEV)
		return ret;

	if (!nlctx->no_banner) {
		printf("No data available\n");
		return 75;
	}


	return 0;
}

/* SET_SETTINGS */

enum {
	WAKE_PHY_BIT		= 0,
	WAKE_UCAST_BIT		= 1,
	WAKE_MCAST_BIT		= 2,
	WAKE_BCAST_BIT		= 3,
	WAKE_ARP_BIT		= 4,
	WAKE_MAGIC_BIT		= 5,
	WAKE_MAGICSECURE_BIT	= 6,
	WAKE_FILTER_BIT		= 7,
};

#define WAKE_ALL (WAKE_PHY | WAKE_UCAST | WAKE_MCAST | WAKE_BCAST | WAKE_ARP | \
		  WAKE_MAGIC | WAKE_MAGICSECURE)

static const struct lookup_entry_u8 port_values[] = {
	{ .arg = "tp",		.val = PORT_TP },
	{ .arg = "aui",		.val = PORT_AUI },
	{ .arg = "mii",		.val = PORT_MII },
	{ .arg = "fibre",	.val = PORT_FIBRE },
	{ .arg = "bnc",		.val = PORT_BNC },
	{ .arg = "da",		.val = PORT_DA },
	{}
};

static const struct lookup_entry_u8 mdix_values[] = {
	{ .arg = "auto",	.val = ETH_TP_MDI_AUTO },
	{ .arg = "on",		.val = ETH_TP_MDI_X },
	{ .arg = "off",		.val = ETH_TP_MDI },
	{}
};

static const struct error_parser_data xcvr_parser_data = {
	.err_msg	= "deprecated parameter '%s' not supported by kernel\n",
	.ret_val	= -EINVAL,
	.extra_args	= 1,
};

static const struct lookup_entry_u8 autoneg_values[] = {
	{ .arg = "off",		.val = AUTONEG_DISABLE },
	{ .arg = "on",		.val = AUTONEG_ENABLE },
	{}
};

static const struct bitset_parser_data advertise_parser_data = {
	.no_mask	= false,
	.force_hex	= true,
};

static const struct lookup_entry_u32 duplex_values[] = {
	{ .arg = "half",	.val = DUPLEX_HALF },
	{ .arg = "full",	.val = DUPLEX_FULL },
	{}
};

char wol_bit_chars[WOL_MODE_COUNT] = {
	[WAKE_PHY_BIT]		= 'p',
	[WAKE_UCAST_BIT]	= 'u',
	[WAKE_MCAST_BIT]	= 'm',
	[WAKE_BCAST_BIT]	= 'b',
	[WAKE_ARP_BIT]		= 'a',
	[WAKE_MAGIC_BIT]	= 'g',
	[WAKE_MAGICSECURE_BIT]	= 's',
	[WAKE_FILTER_BIT]	= 'f',
};

const struct char_bitset_parser_data wol_parser_data = {
	.bit_chars	= wol_bit_chars,
	.nbits		= WOL_MODE_COUNT,
	.reset_char	= 'd',
};

const struct byte_str_parser_data sopass_parser_data = {
	.min_len	= 6,
	.max_len	= 6,
	.delim		= ':',
};

static const struct bitset_parser_data msglvl_parser_data = {
	.no_mask	= false,
	.force_hex	= false,
};

static const struct param_parser sset_params[] = {
	{
		.arg		= "port",
		.group		= ETHTOOL_MSG_LINKINFO_SET,
		.type		= ETHTOOL_A_LINKINFO_PORT,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= port_values,
		.min_argc	= 1,
	},
	{
		.arg		= "mdix",
		.group		= ETHTOOL_MSG_LINKINFO_SET,
		.type		= ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= mdix_values,
		.min_argc	= 1,
	},
	{
		.arg		= "phyad",
		.group		= ETHTOOL_MSG_LINKINFO_SET,
		.type		= ETHTOOL_A_LINKINFO_PHYADDR,
		.handler	= nl_parse_direct_u8,
		.min_argc	= 1,
	},
	{
		.arg		= "xcvr",
		.group		= ETHTOOL_MSG_LINKINFO_SET,
		.handler	= nl_parse_error,
		.handler_data	= &xcvr_parser_data,
		.min_argc	= 1,
	},
	{
		.arg		= "autoneg",
		.group		= ETHTOOL_MSG_LINKMODES_SET,
		.type		= ETHTOOL_A_LINKMODES_AUTONEG,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= autoneg_values,
		.min_argc	= 1,
	},
	{
		.arg		= "advertise",
		.group		= ETHTOOL_MSG_LINKMODES_SET,
		.type		= ETHTOOL_A_LINKMODES_OURS,
		.handler	= nl_parse_bitset,
		.handler_data	= &advertise_parser_data,
		.min_argc	= 1,
	},
	{
		.arg		= "speed",
		.group		= ETHTOOL_MSG_LINKMODES_SET,
		.type		= ETHTOOL_A_LINKMODES_SPEED,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "duplex",
		.group		= ETHTOOL_MSG_LINKMODES_SET,
		.type		= ETHTOOL_A_LINKMODES_DUPLEX,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= duplex_values,
		.min_argc	= 1,
	},
	{
		.arg		= "wol",
		.group		= ETHTOOL_MSG_WOL_SET,
		.type		= ETHTOOL_A_WOL_MODES,
		.handler	= nl_parse_char_bitset,
		.handler_data	= &wol_parser_data,
		.min_argc	= 1,
	},
	{
		.arg		= "sopass",
		.group		= ETHTOOL_MSG_WOL_SET,
		.type		= ETHTOOL_A_WOL_SOPASS,
		.handler	= nl_parse_byte_str,
		.handler_data	= &sopass_parser_data,
		.min_argc	= 1,
	},
	{
		.arg		= "msglvl",
		.group		= ETHTOOL_MSG_DEBUG_SET,
		.type		= ETHTOOL_A_DEBUG_MSGMASK,
		.handler	= nl_parse_bitset,
		.handler_data	= &msglvl_parser_data,
		.min_argc	= 1,
	},
	{}
};

int nl_sset(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	int ret;

	nlctx->cmd = "-s";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;

	ret = nl_parser(nlctx, sset_params, NULL, PARSER_GROUP_MSG);
	if (ret < 0)
		return 1;

	if (ret == 0)
		return 0;
	return nlctx->exit_code ?: 75;
}
