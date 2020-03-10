/*
 * channels.c - netlink implementation of channel commands
 *
 * Implementation of "ethtool -l <dev>"
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"

/* CHANNELS_GET */

int channels_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_CHANNELS_MAX + 1] = {};
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
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_CHANNELS_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		putchar('\n');
	printf("Channel parameters for %s:\n", nlctx->devname);
	printf("Pre-set maximums:\n");
	show_u32(tb[ETHTOOL_A_CHANNELS_RX_MAX], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_TX_MAX], "TX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_OTHER_MAX], "Other:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_COMBINED_MAX], "Combined:\t");
	printf("Current hardware settings:\n");
	show_u32(tb[ETHTOOL_A_CHANNELS_RX_COUNT], "RX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_TX_COUNT], "TX:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_OTHER_COUNT], "Other:\t\t");
	show_u32(tb[ETHTOOL_A_CHANNELS_COMBINED_COUNT], "Combined:\t");

	return MNL_CB_OK;
}

int nl_gchannels(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_CHANNELS_GET,
				      ETHTOOL_A_CHANNELS_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, channels_reply_cb);
}
