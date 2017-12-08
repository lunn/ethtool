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
