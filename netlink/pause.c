/*
 * pause.c - netlink implementation of pause commands
 *
 * Implementation of "ethtool -a <dev>"
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "bitset.h"

/* PAUSE_GET */

struct pause_autoneg_status {
	bool	pause;
	bool	asym_pause;
};

static void pause_autoneg_walker(unsigned int idx, const char *name, bool val,
				 void *data)
{
	struct pause_autoneg_status *status = data;

	if (idx == ETHTOOL_LINK_MODE_Pause_BIT)
		status->pause = val;
	if (idx == ETHTOOL_LINK_MODE_Asym_Pause_BIT)
		status->asym_pause = val;
}

static int pause_autoneg_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_LINKMODES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct pause_autoneg_status ours = {};
	struct pause_autoneg_status peer = {};
	struct nl_context *nlctx = data;
	bool rx_status = false;
	bool tx_status = false;
	bool silent;
	int err_ret;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;

	if (!tb[ETHTOOL_A_LINKMODES_OURS] || !tb[ETHTOOL_A_LINKMODES_PEER])
		return MNL_CB_OK;
	ret = walk_bitset(tb[ETHTOOL_A_LINKMODES_OURS], NULL,
			  pause_autoneg_walker, &ours);
	if (ret < 0)
		return err_ret;
	ret = walk_bitset(tb[ETHTOOL_A_LINKMODES_PEER], NULL,
			  pause_autoneg_walker, &peer);
	if (ret < 0)
		return err_ret;

	if (ours.pause && peer.pause) {
		rx_status = true;
		tx_status = true;
	} else if (ours.asym_pause && peer.asym_pause) {
		if (ours.pause)
			rx_status = true;
		else if (peer.pause)
			tx_status = true;
	}
	printf("RX negotiated: %s\nTX negotiated: %s\n",
	       rx_status ? "on" : "off", tx_status ? "on" : "off");

	return MNL_CB_OK;
}

static int show_pause_autoneg_status(struct nl_context *nlctx)
{
	const char *saved_devname;
	int ret;

	saved_devname = nlctx->ctx->devname;
	nlctx->ctx->devname = nlctx->devname;
	ret = netlink_init_ethnl2_socket(nlctx);
	if (ret < 0)
		goto out;

	ret = nlsock_prep_get_request(nlctx->ethnl2_socket,
				      ETHTOOL_MSG_LINKMODES_GET,
				      ETHTOOL_A_LINKMODES_HEADER,
				      ETHTOOL_FLAG_COMPACT_BITSETS);
	if (ret < 0)
		goto out;
	ret = nlsock_send_get_request(nlctx->ethnl2_socket, pause_autoneg_cb);

out:
	nlctx->ctx->devname = saved_devname;
	return ret;
}

int pause_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_PAUSE_MAX + 1] = {};
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
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_PAUSE_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		putchar('\n');
	printf("Pause parameters for %s:\n", nlctx->devname);
	show_bool(tb[ETHTOOL_A_PAUSE_AUTONEG], "Autonegotiate:\t");
	show_bool(tb[ETHTOOL_A_PAUSE_RX], "RX:\t\t");
	show_bool(tb[ETHTOOL_A_PAUSE_TX], "TX:\t\t");
	if (!nlctx->is_monitor && tb[ETHTOOL_A_PAUSE_AUTONEG] &&
	    mnl_attr_get_u8(tb[ETHTOOL_A_PAUSE_AUTONEG])) {
		ret = show_pause_autoneg_status(nlctx);
		if (ret < 0)
			return err_ret;
	}
	if (!silent)
		putchar('\n');

	return MNL_CB_OK;
}

int nl_gpause(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_PAUSE_GET,
				      ETHTOOL_A_PAUSE_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, pause_reply_cb);
}
