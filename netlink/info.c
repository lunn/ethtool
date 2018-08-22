#include <errno.h>

#include "../internal.h"
#include "netlink.h"
#include "common.h"
#include "strset.h"

static const uint32_t drvinfo_strsets[] = {
	ETH_SS_STATS,
	ETH_SS_TEST,
	ETH_SS_PRIV_FLAGS,
};

static int strcounts_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	struct nl_context *nlctx = data;
	uint32_t *drvinfo_features = nlctx->cmd_private;
	const struct nlattr *attr;
	int ret;

	mnl_attr_for_each(attr, nlhdr, GENL_HDRLEN) {
		const struct nlattr *tb[ETHTOOL_A_STRINGSET_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);
		uint32_t count;
		uint32_t id;

		if (mnl_attr_get_type(attr) != ETHTOOL_A_STRSET_STRINGSET)
			continue;
		ret = mnl_attr_parse_nested(attr, attr_cb, &tb_info);
		if (ret < 0)
			continue;
		if (!tb[ETHTOOL_A_STRINGSET_ID] ||
		    !tb[ETHTOOL_A_STRINGSET_COUNT])
			continue;

		id = mnl_attr_get_u32(tb[ETHTOOL_A_STRINGSET_ID]);
		count = mnl_attr_get_u32(tb[ETHTOOL_A_STRINGSET_COUNT]);
		if (id >= 32)
			continue;
		if (count > 0)
			*drvinfo_features |= (1U << id);
	}

	return MNL_CB_OK;
}

static int put_strset_id(struct nl_context *nlctx, uint32_t id)
{
	struct nlattr *nest;

	nest = ethnla_nest_start(nlctx, ETHTOOL_A_STRSET_STRINGSET);
	if (!nest)
		return -EMSGSIZE;
	if (ethnla_put_u32(nlctx, ETHTOOL_A_STRINGSET_ID, id)) {
		mnl_attr_nest_cancel(nlctx->nlhdr, nest);
		return -EMSGSIZE;
	}
	mnl_attr_nest_end(nlctx->nlhdr, nest);

	return 0;
}

static int show_drvinfo_features(struct nl_context *nlctx)
{
	uint32_t drvinfo_features = 0;
	int ret;
	int i;

	ret = msg_init(nlctx, ETHNL_CMD_GET_STRSET, NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return ret;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_STRSET_DEV, nlctx->devname) ||
	    ethnla_put_flag(nlctx, ETHTOOL_A_STRSET_COUNTS, true))
		return -EMSGSIZE;

	for (i = 0; i < ARRAY_SIZE(drvinfo_strsets); i++) {
		ret = put_strset_id(nlctx, drvinfo_strsets[i]);
		if (ret < 0)
			return ret;
	}

	nlctx->cmd_private = &drvinfo_features;
	ret = ethnl_send_get_request(nlctx, strcounts_reply_cb);
	if (ret < 0)
		goto out;

	printf("supports-statistics: %s\n",
	       drvinfo_features & (1U << ETH_SS_STATS) ? "yes" : "no");
	printf("supports-test: %s\n",
	       drvinfo_features & (1U << ETH_SS_TEST) ? "yes" : "no");
	printf("supports-priv-flags: %s\n",
	       drvinfo_features & (1U << ETH_SS_PRIV_FLAGS) ? "yes" : "no");
out:
	nlctx->cmd_private = NULL;
	return ret;
}

static int show_drvinfo(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_DRVINFO_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		printf("\nDriver info for %s:\n", nlctx->devname);
	show_string(tb, ETHTOOL_A_DRVINFO_DRIVER, "driver");
	show_string(tb, ETHTOOL_A_DRVINFO_FWVERSION, "firmware-version");
	show_string(tb, ETHTOOL_A_DRVINFO_EROM_VER, "expansion-rom-version");
	show_string(tb, ETHTOOL_A_DRVINFO_BUSINFO, "bus-info");

	nlctx->aux_nlctx->devname = nlctx->devname;
	show_drvinfo_features(nlctx->aux_nlctx);

	return MNL_CB_OK;
}

static void show_one_ts_flag(unsigned int idx, const char *name, bool val,
			     void *data)
{
	if (val)
		printf("\t%s\n",
		       idx < N_SOTS ? so_timestamping_labels[idx] : name);
}

static void show_one_tx_type(unsigned int idx, const char *name, bool val,
			     void *data)
{
	if (val)
		printf("\t%s\n",
		       idx < N_TX_TYPES ? tx_type_labels[idx] : name);
}

static void show_one_rx_filter(unsigned int idx, const char *name, bool val,
			       void *data)
{
	if (val)
		printf("\t%s\n",
		       idx < N_RX_FILTERS ? rx_filter_labels[idx] : name);
}

static int show_tsinfo(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_TSINFO_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		putchar('\n');
	printf("\nTime stamping parameters for %s:\n", nlctx->devname);

	if (tb[ETHTOOL_A_TSINFO_TIMESTAMPING]) {
		printf("Capabilities:");
		if (bitset_is_empty(tb[ETHTOOL_A_TSINFO_TIMESTAMPING], false,
				    &ret)) {
			fputs(" none\n", stdout);
		} else {
			fputc('\n', stdout);
			walk_bitset(tb[ETHTOOL_A_TSINFO_TIMESTAMPING],
				    global_stringset(ETH_SS_TSTAMP_SOF),
				    show_one_ts_flag, NULL);
		}
	}

	printf("PTP Hardware Clock: ");
	if (tb[ETHTOOL_A_TSINFO_PHC_INDEX])
		printf("%u\n",
		       mnl_attr_get_u32(tb[ETHTOOL_A_TSINFO_PHC_INDEX]));
	else
		printf("none\n");

	if (tb[ETHTOOL_A_TSINFO_TX_TYPES]) {
		printf("Hardware Transmit Timestamp Modes:");
		if (bitset_is_empty(tb[ETHTOOL_A_TSINFO_TX_TYPES], false,
				    &ret)) {
			fputs(" none\n", stdout);
		} else {
			fputc('\n', stdout);
			walk_bitset(tb[ETHTOOL_A_TSINFO_TX_TYPES],
				    global_stringset(ETH_SS_TSTAMP_TX_TYPE),
				    show_one_tx_type, NULL);
		}
	}

	if (tb[ETHTOOL_A_TSINFO_RX_FILTERS]) {
		printf("Hardware Receive Filter Modes:");
		if (bitset_is_empty(tb[ETHTOOL_A_TSINFO_TX_TYPES], false,
				    &ret)) {
			fputs(" none\n", stdout);
		} else {
			fputc('\n', stdout);
			walk_bitset(tb[ETHTOOL_A_TSINFO_RX_FILTERS],
				    global_stringset(ETH_SS_TSTAMP_RX_FILTER),
				    show_one_rx_filter, NULL);
		}
	}

	return MNL_CB_OK;
}

int info_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_INFO_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_INFO_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (mask_ok(nlctx, ETHTOOL_IM_INFO_DRVINFO)) {
		ret = show_drvinfo(nlctx, tb[ETHTOOL_A_INFO_DRVINFO]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_INFO_DRVINFO)) {
			nlctx->exit_code = 1;
			errno = -ret;
			perror("Cannot get device driver info");
			return MNL_CB_ERROR;
		}
	}
	if (mask_ok(nlctx, ETHTOOL_IM_INFO_TSINFO)) {
		ret = show_tsinfo(nlctx, tb[ETHTOOL_A_INFO_TSINFO]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_INFO_TSINFO)) {
			nlctx->exit_code = 1;
			errno = -ret;
			perror("Cannot get device time stamping settings");
			return MNL_CB_ERROR;
		}
	}

	return MNL_CB_OK;
}

static int info_request(struct cmd_context *ctx, uint32_t info_mask)
{
	int ret;

	if (info_mask & ETHTOOL_IM_INFO_DRVINFO) {
		ret = init_aux_nlctx(ctx->nlctx);
		if (ret < 0)
			return ret;
	}

	ret = ethnl_prep_get_request(ctx, ETHNL_CMD_GET_INFO,
				     ETHTOOL_A_INFO_DEV);
	if (ret < 0)
		return ret;
	if (ethnla_put_u32(ctx->nlctx, ETHTOOL_A_INFO_INFOMASK, info_mask))
		return -EMSGSIZE;
	return ethnl_send_get_request(ctx->nlctx, info_reply_cb);
}

int nl_gdrv(struct cmd_context *ctx)
{
	return info_request(ctx, ETHTOOL_IM_INFO_DRVINFO);
}

int nl_tsinfo(struct cmd_context *ctx)
{
	return info_request(ctx, ETHTOOL_IM_INFO_TSINFO);
}
