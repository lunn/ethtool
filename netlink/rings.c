/*
 * rings.c - netlink implementation of ring commands
 *
 * Implementation of "ethtool -g <dev>"
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"

/* RINGS_GET */

int rings_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_RINGS_MAX + 1] = {};
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
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_RINGS_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		putchar('\n');
	printf("Ring parameters for %s:\n", nlctx->devname);
	printf("Pre-set maximums:\n");
	show_u32(tb[ETHTOOL_A_RINGS_RX_MAX], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_RINGS_RX_MINI_MAX], "RX Mini:\t");
	show_u32(tb[ETHTOOL_A_RINGS_RX_JUMBO_MAX], "RX Jumbo:\t");
	show_u32(tb[ETHTOOL_A_RINGS_TX_MAX], "TX:\t\t");
	printf("Current hardware settings:\n");
	show_u32(tb[ETHTOOL_A_RINGS_RX], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_RINGS_RX_MINI], "RX Mini:\t");
	show_u32(tb[ETHTOOL_A_RINGS_RX_JUMBO], "RX Jumbo:\t");
	show_u32(tb[ETHTOOL_A_RINGS_TX], "TX:\t\t");

	return MNL_CB_OK;
}

int nl_gring(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_RINGS_GET,
				      ETHTOOL_A_RINGS_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, rings_reply_cb);
}
