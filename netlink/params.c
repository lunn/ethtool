#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "parser.h"

/* GET_PARAMS */

static int show_coalesce(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_COALESCE_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	printf("Coalesce parameters for %s:\n", nlctx->devname);
	printf("Adaptive RX: %s  TX: %s\n",
	       u8_to_bool(tb[ETHTOOL_A_COALESCE_RX_USE_ADAPTIVE]),
	       u8_to_bool(tb[ETHTOOL_A_COALESCE_TX_USE_ADAPTIVE]));
	show_u32(tb[ETHTOOL_A_COALESCE_STATS_BLOCK_USECS],
		 "stats-block-usecs: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL],
		 "sample-interval: ");
	show_u32(tb[ETHTOOL_A_COALESCE_PKT_RATE_LOW], "pkt-rate-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_PKT_RATE_HIGH], "pkt-rate-high: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS], "rx-usecs: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAXFRM], "rx-frames: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS_IRQ], "rx-usecs-irq: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAXFRM_IRQ], "rx-frames-irq: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS], "tx-usecs: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAXFRM], "tx-frames: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS_IRQ], "tx-usecs-irq: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAXFRM_IRQ], "tx-frames-irq: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS_LOW], "rx-usecs-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAXFRM_LOW], "rx-frame-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS_LOW], "tx-usecs-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAXFRM_LOW], "tx-frame-low: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS_HIGH], "rx-usecs-high: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAXFRM_HIGH], "rx-frame-high: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS_HIGH], "tx-usecs-high: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAXFRM_HIGH], "tx-frame-high: ");
	putchar('\n');

	return 0;
}

static int show_ring(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_RING_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	printf("Ring parameters for %s:\n", nlctx->devname);
	printf("Pre-set maximums:\n");
	show_u32(tb[ETHTOOL_A_RING_RX_MAX_PENDING], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_RING_RX_MINI_MAX_PENDING], "RX Mini:\t");
	show_u32(tb[ETHTOOL_A_RING_RX_JUMBO_MAX_PENDING], "RX Jumbo:\t");
	show_u32(tb[ETHTOOL_A_RING_TX_MAX_PENDING], "TX:\t\t");
	printf("Current hardware settings:\n");
	show_u32(tb[ETHTOOL_A_RING_RX_PENDING], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_RING_RX_MINI_PENDING], "RX Mini:\t");
	show_u32(tb[ETHTOOL_A_RING_RX_JUMBO_PENDING], "RX Jumbo:\t");
	show_u32(tb[ETHTOOL_A_RING_TX_PENDING], "TX:\t\t");
	putchar('\n');

	return 0;
}

static int show_pause(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_PAUSE_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	printf("Pause parameters for %s:\n", nlctx->devname);
	show_bool(tb[ETHTOOL_A_PAUSE_AUTONEG], "Autonegotiate:\t");
	show_bool(tb[ETHTOOL_A_PAUSE_RX], "RX:\t\t");
	show_bool(tb[ETHTOOL_A_PAUSE_TX], "TX:\t\t");
	/* ToDo: query negotiated pause frame usage */
	putchar('\n');

	return 0;
}

static int show_channels(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_CHANNELS_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	printf("Channel parameters for %s:\n", nlctx->devname);
	printf("Pre-set maximums:\n");
	show_u32(tb[ETHTOOL_A_CHANNELS_MAX_RX], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_MAX_TX], "TX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_MAX_OTHER], "Other:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_MAX_COMBINED], "Combined:\t");
	printf("Current hardware settings:\n");
	show_u32(tb[ETHTOOL_A_CHANNELS_RX_COUNT], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_TX_COUNT], "TX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_OTHER_COUNT], "Other:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_COMBINED_COUNT], "Combined:\t");
	putchar('\n');

	return 0;
}

static int show_eee(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_EEE_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	bool active, enabled, tx_lpi_enabled;
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	if (!tb[ETHTOOL_A_EEE_LINK_MODES] || !tb[ETHTOOL_A_EEE_PEER_MODES] ||
	    !tb[ETHTOOL_A_EEE_ACTIVE] || !tb[ETHTOOL_A_EEE_ENABLED] ||
	    !tb[ETHTOOL_A_EEE_TX_LPI_ENABLED] ||!tb[ETHTOOL_A_EEE_TX_LPI_TIMER])
		return -EFAULT;


	active = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_ACTIVE]);
	enabled = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_ENABLED]);
	tx_lpi_enabled = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_TX_LPI_ENABLED]);

	printf("EEE Settings for %s:\n", nlctx->devname);
	printf("\tEEE status: ");
	if (bitset_is_empty(tb[ETHTOOL_A_EEE_LINK_MODES], true, &ret)) {
		printf("not supported\n");
		return 0;
	}
	if (!enabled)
		printf("disabled\n");
	else
		printf("enabled - %s\n", active ? "active" : "inactive");
	printf("\tTx LPI: ");
	if (tx_lpi_enabled)
		printf("%u (us)\n",
		       mnl_attr_get_u32(tb[ETHTOOL_A_EEE_TX_LPI_TIMER]));
	else
		printf("disabled\n");

	ret = dump_link_modes(tb[ETHTOOL_A_EEE_LINK_MODES], true,
			      LM_CLASS_REAL,
			      "Supported EEE link modes:  ", NULL, "\n",
			      "Not reported");
	ret = dump_link_modes(tb[ETHTOOL_A_EEE_LINK_MODES], false,
			      LM_CLASS_REAL,
			      "Advertised EEE link modes:  ", NULL, "\n",
			      "Not reported");
	ret = dump_link_modes(tb[ETHTOOL_A_EEE_PEER_MODES], false,
			      LM_CLASS_REAL,
			      "Link partner advertised EEE link modes:  ", NULL,
			      "\n", "Not reported");

	return 0;
}

static int show_fec(struct nl_context *nlctx, const struct nlattr *nest)
{
	const struct nlattr *tb[ETHTOOL_A_FEC_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	if (!nest)
		return -EOPNOTSUPP;
	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	printf("FEC parameters for %s:\n", nlctx->devname);
	if (tb[ETHTOOL_A_FEC_MODES]) {
		const struct nla_bitfield32 *fec_encs =
			mnl_attr_get_payload(tb[ETHTOOL_A_FEC_MODES]);

		printf("Configured FEC encodings:\t");
		print_flags(flags_fecenc, n_flags_fecenc, fec_encs->selector);
		putchar('\n');
		printf("Active FEC encoding:\t");
		print_flags(flags_fecenc, n_flags_fecenc, fec_encs->value);
		putchar('\n');
	}
	putchar('\n');

	return 0;
}

int params_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_PARAMS_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_PARAMS_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (mask_ok(nlctx, ETHTOOL_IM_PARAMS_COALESCE)) {
		ret = show_coalesce(nlctx, tb[ETHTOOL_A_PARAMS_COALESCE]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_PARAMS_COALESCE)) {
			nlctx->exit_code = 82;
			errno = -ret;
			perror("Cannot get device coalesce settings");
			return MNL_CB_ERROR;
		}
	}
	if (mask_ok(nlctx, ETHTOOL_IM_PARAMS_RING)) {
		ret = show_ring(nlctx, tb[ETHTOOL_A_PARAMS_RING]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_PARAMS_RING)) {
			nlctx->exit_code = 76;
			errno = -ret;
			perror("Cannot get device ring settings");
			return MNL_CB_ERROR;
		}
	}
	if (mask_ok(nlctx, ETHTOOL_IM_PARAMS_PAUSE)) {
		ret = show_pause(nlctx, tb[ETHTOOL_A_PARAMS_PAUSE]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_PARAMS_PAUSE)) {
			nlctx->exit_code = 76;
			errno = -ret;
			perror("Cannot get device pause settings");
			return MNL_CB_ERROR;
		}
	}
	if (mask_ok(nlctx, ETHTOOL_IM_PARAMS_CHANNELS)) {
		ret = show_channels(nlctx, tb[ETHTOOL_A_PARAMS_CHANNELS]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_PARAMS_CHANNELS)) {
			nlctx->exit_code = 1;
			errno = -ret;
			perror("Cannot get device channel parameters");
			return MNL_CB_ERROR;
		}
	}
	if (mask_ok(nlctx, ETHTOOL_IM_PARAMS_EEE)) {
		ret = show_eee(nlctx, tb[ETHTOOL_A_PARAMS_EEE]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_PARAMS_EEE)) {
			nlctx->exit_code = 1;
			errno = -ret;
			perror("Cannot get device EEE settings");
			return MNL_CB_ERROR;
		}
	}
	if (mask_ok(nlctx, ETHTOOL_IM_PARAMS_FEC)) {
		ret = show_fec(nlctx, tb[ETHTOOL_A_PARAMS_FEC]);
		if ((ret < 0) && show_only(nlctx, ETHTOOL_IM_PARAMS_FEC)) {
			nlctx->exit_code = 1;
			errno = -ret;
			perror("Cannot get device FEC settings");
			return MNL_CB_ERROR;
		}
	}

	return MNL_CB_OK;
}

static int params_request(struct cmd_context *ctx, uint32_t info_mask)
{
	int ret;

	ret = ethnl_prep_get_request(ctx, ETHNL_CMD_GET_PARAMS,
				     ETHTOOL_A_PARAMS_DEV);
	if (ret < 0)
		return ret;
	if (ethnla_put_u32(ctx->nlctx, ETHTOOL_A_PARAMS_INFOMASK, info_mask))
		return -EMSGSIZE;
	return ethnl_send_get_request(ctx->nlctx, params_reply_cb);
}

int nl_gcoalesce(struct cmd_context *ctx)
{
	return params_request(ctx, ETHTOOL_IM_PARAMS_COALESCE);
}

int nl_gring(struct cmd_context *ctx)
{
	return params_request(ctx, ETHTOOL_IM_PARAMS_RING);
}

int nl_gpause(struct cmd_context *ctx)
{
	return params_request(ctx, ETHTOOL_IM_PARAMS_PAUSE);
}

int nl_gchannels(struct cmd_context *ctx)
{
	return params_request(ctx, ETHTOOL_IM_PARAMS_CHANNELS);
}

int nl_geee(struct cmd_context *ctx)
{
	return params_request(ctx, ETHTOOL_IM_PARAMS_EEE);
}

int nl_gfec(struct cmd_context *ctx)
{
	return params_request(ctx, ETHTOOL_IM_PARAMS_FEC);
}

/* SET_PARAMS */

static int nl_set_param(struct cmd_context *ctx, const char *opt,
			const struct param_parser *params, uint16_t nest_type)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nlattr *nest;
	int ret;

	nlctx->cmd = opt;
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	ret = msg_init(nlctx, ETHNL_CMD_SET_PARAMS, NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return 2;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_PARAMS_DEV, ctx->devname))
		return -EMSGSIZE;

	nest = ethnla_nest_start(nlctx, nest_type);
	if (!nest) {
		fprintf(stderr, "ethtool(%s): failed to allocate message\n",
			opt);
		return 76;
	}

	ret = nl_parser(nlctx, params, NULL);
	if (ret < 0)
		return 2;
	mnl_attr_nest_end(nlctx->nlhdr, nest);

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		return 75;
	ret = ethnl_process_reply(nlctx, nomsg_reply_cb);
	if (ret == 0)
		return 0;
	return nlctx->exit_code ?: 81;
}

static const struct param_parser scoalesce_params[] = {
	{
		.arg		= "adaptive-rx",
		.type		= ETHTOOL_A_COALESCE_RX_USE_ADAPTIVE,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{
		.arg		= "adaptive-tx",
		.type		= ETHTOOL_A_COALESCE_TX_USE_ADAPTIVE,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{
		.arg		= "sample-interval",
		.type		= ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "stats-block-usecs",
		.type		= ETHTOOL_A_COALESCE_STATS_BLOCK_USECS,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "pkt-rate-low",
		.type		= ETHTOOL_A_COALESCE_PKT_RATE_LOW,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "pkt-rate-high",
		.type		= ETHTOOL_A_COALESCE_PKT_RATE_HIGH,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-usecs",
		.type		= ETHTOOL_A_COALESCE_RX_USECS,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-frames",
		.type		= ETHTOOL_A_COALESCE_RX_MAXFRM,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-usecs-irq",
		.type		= ETHTOOL_A_COALESCE_RX_USECS_IRQ,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-frames-irq",
		.type		= ETHTOOL_A_COALESCE_RX_MAXFRM_IRQ,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-usecs",
		.type		= ETHTOOL_A_COALESCE_TX_USECS,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-frames",
		.type		= ETHTOOL_A_COALESCE_TX_MAXFRM,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-usecs-irq",
		.type		= ETHTOOL_A_COALESCE_TX_USECS_IRQ,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-frames-irq",
		.type		= ETHTOOL_A_COALESCE_TX_MAXFRM_IRQ,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-usecs-low",
		.type		= ETHTOOL_A_COALESCE_RX_USECS_LOW,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-frames-low",
		.type		= ETHTOOL_A_COALESCE_RX_MAXFRM_LOW,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-usecs-low",
		.type		= ETHTOOL_A_COALESCE_TX_USECS_LOW,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-frames-low",
		.type		= ETHTOOL_A_COALESCE_TX_MAXFRM_LOW,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-usecs-high",
		.type		= ETHTOOL_A_COALESCE_RX_USECS_HIGH,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-frames-high",
		.type		= ETHTOOL_A_COALESCE_RX_MAXFRM_HIGH,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-usecs-high",
		.type		= ETHTOOL_A_COALESCE_TX_USECS_HIGH,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-frames-high",
		.type		= ETHTOOL_A_COALESCE_TX_MAXFRM_HIGH,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{}
};

int nl_scoalesce(struct cmd_context *ctx)
{
	return nl_set_param(ctx, "-C", scoalesce_params,
			    ETHTOOL_A_PARAMS_COALESCE);
}

static const struct param_parser sring_params[] = {
	{
		.arg		= "rx",
		.type		= ETHTOOL_A_RING_RX_PENDING,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-mini",
		.type		= ETHTOOL_A_RING_RX_MINI_PENDING,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "rx-jumbo",
		.type		= ETHTOOL_A_RING_RX_JUMBO_PENDING,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx",
		.type		= ETHTOOL_A_RING_TX_PENDING,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{}
};

int nl_sring(struct cmd_context *ctx)
{
	return nl_set_param(ctx, "-G", sring_params, ETHTOOL_A_PARAMS_RING);
}

static const struct param_parser spause_params[] = {
	{
		.arg		= "autoneg",
		.type		= ETHTOOL_A_PAUSE_AUTONEG,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{
		.arg		= "rx",
		.type		= ETHTOOL_A_PAUSE_RX,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{
		.arg		= "tx",
		.type		= ETHTOOL_A_PAUSE_TX,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{}
};

int nl_spause(struct cmd_context *ctx)
{
	return nl_set_param(ctx, "-A", spause_params, ETHTOOL_A_PARAMS_PAUSE);
}

static const struct param_parser schannels_params[] = {
	{
		.arg		= "rx",
		.type		= ETHTOOL_A_CHANNELS_RX_COUNT,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "tx",
		.type		= ETHTOOL_A_CHANNELS_TX_COUNT,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "other",
		.type		= ETHTOOL_A_CHANNELS_OTHER_COUNT,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "combined",
		.type		= ETHTOOL_A_CHANNELS_COMBINED_COUNT,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{}
};

int nl_schannels(struct cmd_context *ctx)
{
	return nl_set_param(ctx, "-L", schannels_params,
			    ETHTOOL_A_PARAMS_CHANNELS);
}

static const struct param_parser seee_params[] = {
	{
		.arg		= "advertise",
		.type		= ETHTOOL_A_EEE_LINK_MODES,
		.handler	= nl_parse_bitset,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-lpi",
		.type		= ETHTOOL_A_EEE_TX_LPI_ENABLED,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{
		.arg		= "tx-timer",
		.type		= ETHTOOL_A_EEE_TX_LPI_TIMER,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "eee",
		.type		= ETHTOOL_A_EEE_ENABLED,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{}
};

int nl_seee(struct cmd_context *ctx)
{
	return nl_set_param(ctx, "--set-eee", seee_params,
			    ETHTOOL_A_PARAMS_EEE);
}

static const struct param_parser sfec_params[] = {
	{
		.arg		= "encoding",
		.type		= ETHTOOL_A_FEC_MODES,
		.handler	= nl_parse_bitlist,
		.handler_data	= flags_fecenc,
		.min_argc	= 1,
	},
	{}
};

int nl_sfec(struct cmd_context *ctx)
{
	return nl_set_param(ctx, "--set-fec", sfec_params,
			    ETHTOOL_A_PARAMS_FEC);
}
