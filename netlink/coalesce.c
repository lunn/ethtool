/*
 * coalesce.c - netlink implementation of coalescing commands
 *
 * Implementation of "ethtool -c <dev>"
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"

/* COALESCE_GET */

int coalesce_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_COALESCE_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	bool silent;
	int err_ret;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_COALESCE_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		putchar('\n');
	printf("Coalesce parameters for %s:\n", nlctx->devname);
	printf("Adaptive RX: %s  TX: %s\n",
	       u8_to_bool(tb[ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX]),
	       u8_to_bool(tb[ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX]));
	show_u32(tb[ETHTOOL_A_COALESCE_STATS_BLOCK_USECS],
		 "stats-block-usecs: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL],
		 "sample-interval: ");
	show_u32(tb[ETHTOOL_A_COALESCE_PKT_RATE_LOW], "pkt-rate-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_PKT_RATE_HIGH], "pkt-rate-high: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS], "rx-usecs: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAX_FRAMES], "rx-frames: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS_IRQ], "rx-usecs-irq: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ], "rx-frames-irq: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS], "tx-usecs: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAX_FRAMES], "tx-frames: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS_IRQ], "tx-usecs-irq: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ], "tx-frames-irq: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS_LOW], "rx-usecs-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW], "rx-frame-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS_LOW], "tx-usecs-low: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW], "tx-frame-low: ");
	putchar('\n');
	show_u32(tb[ETHTOOL_A_COALESCE_RX_USECS_HIGH], "rx-usecs-high: ");
	show_u32(tb[ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH], "rx-frame-high: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_USECS_HIGH], "tx-usecs-high: ");
	show_u32(tb[ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH], "tx-frame-high: ");
	putchar('\n');

	return MNL_CB_OK;
}

int nl_gcoalesce(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_COALESCE_GET,
				      ETHTOOL_A_COALESCE_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, coalesce_reply_cb);
}
