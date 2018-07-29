#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "parser.h"

/* GET_SETTINGS */

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

static void print_banner(struct nl_context *nlctx, bool *first)
{
	if (!*first)
		return;
	printf("Settings for %s:\n", nlctx->devname);
	*first = false;
}

static int dump_our_modes(struct nl_context *nlctx, const struct nlattr *attr,
			  bool *first)
{
	bool autoneg;
	int ret;

	print_banner(nlctx, first);
	ret = dump_link_modes(attr, true, LM_CLASS_PORT, "Supported ports: [ ",
			      " ", " ]\n", NULL);
	if (ret < 0)
		return ret;

	ret = dump_link_modes(attr, true, LM_CLASS_REAL,
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

	ret = dump_link_modes(attr, true, LM_CLASS_FEC, "Supported FEC modes: ",
			      " ", "\n", "Not reported");
	if (ret < 0)
		return ret;

	ret = dump_link_modes(attr, false, LM_CLASS_REAL,
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

	ret = dump_link_modes(attr, true, LM_CLASS_FEC,
			      "Advertised FEC modes: ", " ", "\n",
			      "Not reported");
	return ret;
}

static int dump_peer_modes(struct nl_context *nlctx, const struct nlattr *attr,
			   bool *first)
{
	bool autoneg;
	int ret;

	print_banner(nlctx, first);
	ret = dump_link_modes(attr, false, LM_CLASS_REAL,
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

	ret = dump_link_modes(attr, true, LM_CLASS_FEC,
			      "Link partner advertised FEC modes: ",
			      " ", "\n", "No");
	return ret;
}

static int dump_modes(struct nl_context *nlctx, const struct nlattr *nest,
		      bool *first, int *lm_autoneg)
{
	const struct nlattr *tb[ETHTOOL_A_LINKMODES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EFAULT;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	if (tb[ETHTOOL_A_LINKMODES_OURS]) {
	    ret = dump_our_modes(nlctx, tb[ETHTOOL_A_LINKMODES_OURS], first);
	    if (ret < 0)
		    return ret;
	}
	if (tb[ETHTOOL_A_LINKMODES_PEER]) {
	    ret = dump_peer_modes(nlctx, tb[ETHTOOL_A_LINKMODES_PEER], first);
	    if (ret < 0)
		    return ret;
	}
	if (tb[ETHTOOL_A_LINKMODES_SPEED]) {
		uint32_t val = mnl_attr_get_u32(tb[ETHTOOL_A_LINKMODES_SPEED]);

		print_banner(nlctx, first);
		if (val == 0 || val == (uint16_t)(-1) || val == (uint32_t)(-1))
			printf("\tSpeed: Unknown!\n");
		else
			printf("\tSpeed: %uMb/s\n", val);
	}
	if (tb[ETHTOOL_A_LINKMODES_DUPLEX]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKMODES_DUPLEX]);

		print_banner(nlctx, first);
		print_enum(names_duplex, val, "\tDuplex: ", "Unknown! (%i)");
	}
	if (tb[ETHTOOL_A_LINKMODES_AUTONEG])
		*lm_autoneg = mnl_attr_get_u8(tb[ETHTOOL_A_LINKMODES_AUTONEG]);
	else
		*lm_autoneg = -1;

	return 0;
}

static int dump_link_info(struct nl_context *nlctx, const struct nlattr *nest,
			   bool *first, int lm_autoneg)
{
	const struct nlattr *tb[ETHTOOL_A_LINKINFO_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int port = -1;
	int ret;

	if (!nest)
		return 0;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	if (tb[ETHTOOL_A_LINKINFO_PORT]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_PORT]);

		print_banner(nlctx, first);
		print_enum(names_port, val, "\tPort: ", "Unknown! (%i)\n");
		port = val;
	}
	if (tb[ETHTOOL_A_LINKINFO_PHYADDR]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_PHYADDR]);

		print_banner(nlctx, first);
		printf("\tPHYAD: %u\n", val);
	}
	if (tb[ETHTOOL_A_LINKINFO_TRANSCEIVER]) {
		uint8_t val;

		val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_TRANSCEIVER]);
		print_banner(nlctx, first);
		print_enum(names_transceiver, val, "\tTransceiver: ",
			   "Unknown!");
	}
	if (lm_autoneg >= 0) {
		print_banner(nlctx, first);
		printf("\tAuto-negotiation: %s\n",
		       (lm_autoneg == AUTONEG_DISABLE) ? "off" : "on");
	}
	if (tb[ETHTOOL_A_LINKINFO_TP_MDIX] && tb[ETHTOOL_A_LINKINFO_TP_MDIX] &&
	    port == PORT_TP) {
		uint8_t mdix = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_TP_MDIX]);
		uint8_t mdix_ctrl =
			mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_TP_MDIX_CTRL]);

		print_banner(nlctx, first);
		dump_mdix(mdix, mdix_ctrl);
	}

	return 0;
}

static int dump_wol_info(struct nl_context *nlctx, const struct nlattr *nest,
			 bool *first)
{
	const struct nlattr *tb[ETHTOOL_A_WOL_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct ethtool_wolinfo wolinfo = {};
	const struct nla_bitfield32 *wol_bf;
	int ret;

	if (!nest)
		return -EFAULT;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	wol_bf = mnl_attr_get_payload(tb[ETHTOOL_A_WOL_MODES]);

	print_banner(nlctx, first);
	wolinfo.wolopts = wol_bf->value;
	wolinfo.supported = wol_bf->selector;
	if (tb[ETHTOOL_A_WOL_SOPASS])
		nl_copy_payload(wolinfo.sopass, SOPASS_MAX,
				tb[ETHTOOL_A_WOL_SOPASS]);
	return dump_wol(&wolinfo) ? -EFAULT : 0;
}


static int dump_debug(struct nl_context *nlctx, const struct nlattr *nest,
		      bool *first)
{
	const struct nlattr *tb[ETHTOOL_A_DEBUG_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nla_bitfield32 *val;
	uint32_t msglvl;
	int ret;

	if (!nest)
		return -EFAULT;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	val = mnl_attr_get_payload(tb[ETHTOOL_A_DEBUG_MSG_MASK]);
	msglvl = val->value;

	print_banner(nlctx, first);
	printf("	Current message level: 0x%08x (%d)\n"
	       "			       ",
	       msglvl, msglvl);
	print_flags(flags_msglvl, n_flags_msglvl, msglvl);
	fputc('\n', stdout);

	return 0;
}

static int dump_link_state(struct nl_context *nlctx, const struct nlattr *nest,
			   bool *first)
{
	const struct nlattr *tb[ETHTOOL_A_LINKSTATE_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EFAULT;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	if (tb[ETHTOOL_A_LINKSTATE_LINK]) {
		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKSTATE_LINK]);

		print_banner(nlctx, first);
		printf("\tLink detected: %s\n", val ? "yes" : "no");
	}

	return 0;
}

uint32_t *get_compact_bitset_value(const struct nlattr *bitset)
{
        const struct nlattr *tb[ETHTOOL_A_BITSET_MAX + 1] = {};
        DECLARE_ATTR_TB_INFO(tb);
	unsigned int count;
        int ret;

        ret = mnl_attr_parse_nested(bitset, attr_cb, &tb_info);
        if (ret < 0 ||
	    !tb[ETHTOOL_A_BITSET_SIZE] || !tb[ETHTOOL_A_BITSET_VALUE])
		return NULL;
	count = mnl_attr_get_u32(tb[ETHTOOL_A_BITSET_SIZE]);
	if (32 * mnl_attr_get_payload_len(tb[ETHTOOL_A_BITSET_VALUE]) < count)
		return NULL;

	return mnl_attr_get_payload(tb[ETHTOOL_A_BITSET_VALUE]);
}

uint32_t *get_compact_bitset_mask(const struct nlattr *bitset)
{
        const struct nlattr *tb[ETHTOOL_A_BITSET_MAX + 1] = {};
        DECLARE_ATTR_TB_INFO(tb);
	unsigned int count;
        int ret;

        ret = mnl_attr_parse_nested(bitset, attr_cb, &tb_info);
        if (ret < 0 || !tb[ETHTOOL_A_BITSET_SIZE] || !tb[ETHTOOL_A_BITSET_MASK])
		return NULL;
	count = mnl_attr_get_u32(tb[ETHTOOL_A_BITSET_SIZE]);
	if (32 * mnl_attr_get_payload_len(tb[ETHTOOL_A_BITSET_MASK]) < count)
		return NULL;

	return mnl_attr_get_payload(tb[ETHTOOL_A_BITSET_MASK]);
}

struct feature_results {
	uint32_t	*hw;
	uint32_t	*wanted;
	uint32_t	*active;
	uint32_t	*nochange;
	unsigned int	count;
	unsigned int	words;
};

static int prepare_feature_results(const struct nlattr *bitset,
				   struct feature_results *dest)
{
	const struct nlattr *tb[ETHTOOL_A_FEATURES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	unsigned int count;
	int ret;

	memset(dest, '\0', sizeof(*dest));
	ret = mnl_attr_parse_nested(bitset, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	if (!tb[ETHTOOL_A_FEATURES_HW] || !tb[ETHTOOL_A_FEATURES_WANTED] ||
	    !tb[ETHTOOL_A_FEATURES_ACTIVE] || !tb[ETHTOOL_A_FEATURES_NOCHANGE])
		return -EFAULT;
	count = bitset_get_count(tb[ETHTOOL_A_FEATURES_HW], &ret);
	if (ret < 0)
		return -EFAULT;
	if ((bitset_get_count(tb[ETHTOOL_A_FEATURES_WANTED], &ret) != count) ||
	    (bitset_get_count(tb[ETHTOOL_A_FEATURES_ACTIVE], &ret) != count) ||
	    (bitset_get_count(tb[ETHTOOL_A_FEATURES_NOCHANGE], &ret) != count))
		return -EFAULT;
	dest->hw = get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_HW]);
	dest->wanted = get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_WANTED]);
	dest->active = get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_ACTIVE]);
	dest->nochange =
		get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_NOCHANGE]);
	if (!dest->hw || !dest->wanted || !dest->active || !dest->nochange)
		return -EFAULT;
	dest->count = count;
	dest->words = (count + 31) / 32;

	return 0;
}

static bool feature_on(const uint32_t *bitmap, unsigned int idx)
{
	return bitmap[idx / 32] & (1 << (idx % 32));
}

static void dump_feature(const struct feature_results *results,
			 const uint32_t *ref, const uint32_t *ref_mask,
			 unsigned int idx, const char *name, const char *prefix)
{
	const char *suffix = "";

	if (!name || !*name)
		return;
	if (ref) {
		if (ref_mask && !feature_on(ref_mask, idx))
			return;
		if ((!ref_mask || feature_on(ref_mask, idx)) &&
		    (feature_on(results->active, idx) == feature_on(ref, idx)))
			return;
	}

	if (!feature_on(results->hw, idx) || feature_on(results->nochange, idx))
		suffix = " [fixed]";
	else if (feature_on(results->active, idx) !=
		 feature_on(results->wanted, idx))
		suffix = feature_on(results->wanted, idx) ?
			 " [requested on]" : " [requested off]";
	printf("%s%s: %s%s\n", prefix, name,
	       feature_on(results->active, idx) ? "on" : "off", suffix);
}

/* this assumes pattern contains no more than one asterisk */
static bool _flag_pattern_match(const char *name, const char *pattern)
{
	const char *p_ast = strchr(pattern, '*');

	if (p_ast) {
		size_t name_len = strlen(name);
		size_t pattern_len = strlen(pattern);

		if (name_len + 1 < pattern_len)
			return false;
		if (strncmp(name, pattern, p_ast - pattern))
			return false;
		pattern_len -= (p_ast - pattern) + 1;
		name += name_len  - pattern_len;
		pattern = p_ast + 1;
	}
	return !strcmp(name, pattern);
}

static bool flag_pattern_match(const char *name, const char *pattern)
{
	bool ret = _flag_pattern_match(name, pattern);

	return ret;
}

int dump_features(const struct nlattr *bitset)
{
	const struct stringset *feature_names;
	struct feature_results results;
	unsigned int i, j;
	int *feature_flags = NULL;
	int ret;

	ret = prepare_feature_results(bitset, &results);
	if (ret < 0)
		return -EFAULT;

	ret = -ENOMEM;
	feature_flags = calloc(results.count, sizeof(feature_flags[0]));
	if (!feature_flags)
	       goto out_free;
	feature_names = global_stringset(ETH_SS_FEATURES);

	/* map netdev features to legacy flags */
	for (i = 0; i < results.count; i++) {
		const char *name = get_string(feature_names, i);
		feature_flags[i] = -1;

		if (!name || !*name)
			continue;
		for (j = 0; j < OFF_FLAG_DEF_SIZE; j++) {
			const char *flag_name = off_flag_def[j].kernel_name;

			if (flag_pattern_match(name, flag_name)) {
				feature_flags[i] = j;
				break;
			}
		}
	}
	/* show legacy flags and their matching features first */
	for (i = 0; i < OFF_FLAG_DEF_SIZE; i++) {
		unsigned int n_match = 0;
		bool flag_value = false;

		for (j = 0; j < results.count; j++) {
			if (feature_flags[j] == i) {
				n_match++;
				flag_value = flag_value ||
					     feature_on(results.active, j);
			}
		}
		if (n_match != 1)
			printf("%s: %s\n", off_flag_def[i].long_name,
			       flag_value ? "on" : "off");
		if (n_match == 0)
			continue;
		for (j = 0; j < results.count; j++) {
			const char *name = get_string(feature_names, j);

			if (feature_flags[j] != i)
				continue;
			if (n_match == 1)
				dump_feature(&results, NULL, NULL, j,
					     off_flag_def[i].long_name, "");
			else
				dump_feature(&results, NULL, NULL, j, name,
					     "\t");
		}
	}
	/* and, finally, remaining netdev_features not matching legacy flags */
	for (i = 0; i < results.count; i++) {
		const char *name = get_string(feature_names, i);

		if (!name || !*name || feature_flags[i] >= 0)
			continue;
		dump_feature(&results, NULL, NULL, i, name, "");
	}

out_free:
	free(feature_flags);
	return 0;
}

int settings_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_SETTINGS_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int lm_autoneg = -1;
	bool allfail = true;
	bool first = true;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_SETTINGS_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (mask_ok(nlctx, ETHTOOL_IM_SETTINGS_LINKMODES)) {
		ret = dump_modes(nlctx, tb[ETHTOOL_A_SETTINGS_LINK_MODES],
				 &first,
				 &lm_autoneg);
		if (ret == 0)
			allfail = false;
	}
	if (mask_ok(nlctx, ETHTOOL_IM_SETTINGS_LINKINFO)) {
		ret = dump_link_info(nlctx, tb[ETHTOOL_A_SETTINGS_LINK_INFO],
				     &first, lm_autoneg);
		if (ret == 0)
			allfail = false;
	}
	if (tb[ETHTOOL_A_SETTINGS_WOL] &&
	    mask_ok(nlctx, ETHTOOL_IM_SETTINGS_WOL)) {
		ret = dump_wol_info(nlctx, tb[ETHTOOL_A_SETTINGS_WOL], &first);
		if (ret == 0)
			allfail = false;
	}
	if (tb[ETHTOOL_A_SETTINGS_DEBUG] &&
	    mask_ok(nlctx, ETHTOOL_IM_SETTINGS_DEBUG)) {
		ret = dump_debug(nlctx, tb[ETHTOOL_A_SETTINGS_DEBUG], &first);
		if (ret == 0)
			allfail = false;
	}
	if (tb[ETHTOOL_A_SETTINGS_LINK_STATE] &&
	    mask_ok(nlctx, ETHTOOL_IM_SETTINGS_LINKSTATE)) {
		ret = dump_link_state(nlctx,
				      tb[ETHTOOL_A_SETTINGS_LINK_STATE],
				      &first);
		if (ret == 0)
			allfail = false;
	};
	if (tb[ETHTOOL_A_SETTINGS_FEATURES] &&
	    mask_ok(nlctx, ETHTOOL_IM_SETTINGS_FEATURES)) {
		int ret;

		printf("Features for %s:\n", nlctx->devname);
		ret = dump_features(tb[ETHTOOL_A_SETTINGS_FEATURES]);
		if (ret == 0)
			allfail = false;
	}

	if (allfail && !nlctx->is_monitor && !nlctx->is_dump) {
		fputs("No data available\n", stdout);
		nlctx->exit_code = 75;
		return MNL_CB_ERROR;
	}
	return MNL_CB_OK;
}

int settings_request(struct cmd_context *ctx, uint32_t info_mask)
{
	bool compact = info_mask & ETHTOOL_IM_SETTINGS_FEATURES;
	struct nl_context *nlctx = ctx->nlctx;
	int ret;

	if (compact)
		load_global_strings(nlctx);

	ret = ethnl_prep_get_request(ctx, ETHNL_CMD_GET_SETTINGS,
				     ETHTOOL_A_SETTINGS_DEV);
	if (ret < 0)
		return ret;
	if (ethnla_put_u32(nlctx, ETHTOOL_A_SETTINGS_INFOMASK, info_mask) ||
	    ethnla_put_flag(nlctx, ETHTOOL_A_SETTINGS_COMPACT, compact))
		return -EMSGSIZE;
	return ethnl_send_get_request(nlctx, settings_reply_cb);
}

int nl_gset(struct cmd_context *ctx)
{
	int ret;

	ret = settings_request(ctx, ETHTOOL_IM_SETTINGS_LINKINFO |
				    ETHTOOL_IM_SETTINGS_LINKMODES |
				    ETHTOOL_IM_SETTINGS_LINKSTATE |
				    ETHTOOL_IM_SETTINGS_DEBUG |
				    ETHTOOL_IM_SETTINGS_WOL);
	return (ret < 0) ? 75 : 0;
}

int nl_gfeatures(struct cmd_context *ctx)
{
	return settings_request(ctx, ETHTOOL_IM_SETTINGS_FEATURES);
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

const struct bitfield32_parser_special wol_parser_specials[] = {
	{ 'd', 0U },
	{}
};
const struct bitfield32_parser_data wol_parser_data = {
	.bits = {
		[WAKE_PHY_BIT]		= 'p',
		[WAKE_UCAST_BIT]	= 'u',
		[WAKE_MCAST_BIT]	= 'm',
		[WAKE_BCAST_BIT]	= 'b',
		[WAKE_ARP_BIT]		= 'a',
		[WAKE_MAGIC_BIT]	= 'g',
		[WAKE_MAGICSECURE_BIT]	= 's',
		[WAKE_FILTER_BIT]	= 'f',
	},
	.specials = wol_parser_specials,
};

static const struct lookup_entry_u32 duplex_values[] = {
	{ .arg = "half",	.val = DUPLEX_HALF },
	{ .arg = "full",	.val = DUPLEX_FULL },
	{}
};

static const struct lookup_entry_u8 port_values[] = {
	{ .arg = "tp",		.val = PORT_TP },
	{ .arg = "aui",		.val = PORT_AUI },
	{ .arg = "bnc",		.val = PORT_BNC },
	{ .arg = "mii",		.val = PORT_MII },
	{ .arg = "fibre",	.val = PORT_FIBRE },
	{}
};

static const struct lookup_entry_u8 mdix_values[] = {
	{ .arg = "auto",	.val = ETH_TP_MDI_AUTO },
	{ .arg = "on",		.val = ETH_TP_MDI_X },
	{ .arg = "off",		.val = ETH_TP_MDI },
	{}
};

static const struct lookup_entry_u8 autoneg_values[] = {
	{ .arg = "off",		.val = AUTONEG_DISABLE },
	{ .arg = "on",		.val = AUTONEG_ENABLE },
	{}
};

static const struct param_parser sset_params[] = {
	{
		.arg		= "port",
		.nest		= ETHTOOL_A_SETTINGS_LINK_INFO,
		.type		= ETHTOOL_A_LINKINFO_PORT,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= port_values,
		.min_argc	= 1,
	},
	{
		.arg		= "mdix",
		.nest		= ETHTOOL_A_SETTINGS_LINK_INFO,
		.type		= ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= mdix_values,
		.min_argc	= 1,
	},
	{
		.arg		= "phyad",
		.nest		= ETHTOOL_A_SETTINGS_LINK_INFO,
		.type		= ETHTOOL_A_LINKINFO_PHYADDR,
		.handler	= nl_parse_direct_u8,
		.min_argc	= 1,
	},
	{
		.arg		= "autoneg",
		.nest		= ETHTOOL_A_SETTINGS_LINK_MODES,
		.type		= ETHTOOL_A_LINKMODES_AUTONEG,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= autoneg_values,
		.min_argc	= 1,
	},
	{
		.arg		= "advertise",
		.nest		= ETHTOOL_A_SETTINGS_LINK_MODES,
		.type		= ETHTOOL_A_LINKMODES_OURS,
		.handler	= nl_parse_bitset,
		.min_argc	= 1,
	},
	{
		.arg		= "speed",
		.nest		= ETHTOOL_A_SETTINGS_LINK_MODES,
		.type		= ETHTOOL_A_LINKMODES_SPEED,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "duplex",
		.nest		= ETHTOOL_A_SETTINGS_LINK_MODES,
		.type		= ETHTOOL_A_LINKMODES_DUPLEX,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= duplex_values,
		.min_argc	= 1,
	},
	{
		.arg		= "wol",
		.nest		= ETHTOOL_A_SETTINGS_WOL,
		.type		= ETHTOOL_A_WOL_MODES,
		.handler	= nl_parse_char_bitfield32,
		.handler_data	= &wol_parser_data,
		.min_argc	= 1,
	},
	{
		.arg		= "sopass",
		.nest		= ETHTOOL_A_SETTINGS_WOL,
		.type		= ETHTOOL_A_WOL_SOPASS,
		.handler	= nl_parse_mac_addr,
		.min_argc	= 1,
	},
	{
		.arg		= "msglvl",
		.nest		= ETHTOOL_A_SETTINGS_DEBUG,
		.type		= ETHTOOL_A_DEBUG_MSG_MASK,
		.handler	= nl_parse_bitfield32,
		.handler_data	= flags_msglvl,
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
	ret = msg_init(nlctx, ETHNL_CMD_SET_SETTINGS,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return 2;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_SETTINGS_DEV, ctx->devname))
		return -EMSGSIZE;

	ret = nl_parser(nlctx, sset_params, NULL);
	if (ret < 0)
		return 2;

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		return 75;
	ret = ethnl_process_reply(nlctx, nomsg_reply_cb);
	if (ret == 0)
		return 0;
	return nlctx->exit_code ?: 75;
}
