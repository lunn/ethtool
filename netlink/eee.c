/*
 * eee.c - netlink implementation of eee commands
 *
 * Implementation of "ethtool --show-eee <dev>"
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "bitset.h"

/* EEE_GET */

int eee_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_EEE_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	bool enabled, active, tx_lpi_enabled;
	struct nl_context *nlctx = data;
	bool silent;
	int err_ret;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_EEE_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (!tb[ETHTOOL_A_EEE_MODES_OURS] ||
	    !tb[ETHTOOL_A_EEE_ACTIVE] || !tb[ETHTOOL_A_EEE_ENABLED] ||
	    !tb[ETHTOOL_A_EEE_TX_LPI_ENABLED] ||
	    !tb[ETHTOOL_A_EEE_TX_LPI_TIMER]) {
		fprintf(stderr, "Malformed response from kernel\n");
		return err_ret;
	}
	active = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_ACTIVE]);
	enabled = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_ENABLED]);
	tx_lpi_enabled = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_TX_LPI_ENABLED]);

	if (silent)
		putchar('\n');
	printf("EEE settings for %s:\n", nlctx->devname);
	printf("\tEEE status: ");
	if (bitset_is_empty(tb[ETHTOOL_A_EEE_MODES_OURS], true, &ret)) {
		printf("not supported\n");
		return MNL_CB_OK;
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

	ret = dump_link_modes(nlctx, tb[ETHTOOL_A_EEE_MODES_OURS], true,
			      LM_CLASS_REAL,
			      "Supported EEE link modes:  ", NULL, "\n",
			      "Not reported");
	if (ret < 0)
		return err_ret;
	ret = dump_link_modes(nlctx, tb[ETHTOOL_A_EEE_MODES_OURS], false,
			      LM_CLASS_REAL,
			      "Advertised EEE link modes:  ", NULL, "\n",
			      "Not reported");
	if (ret < 0)
		return err_ret;
	ret = dump_link_modes(nlctx, tb[ETHTOOL_A_EEE_MODES_PEER], false,
			      LM_CLASS_REAL,
			      "Link partner advertised EEE link modes:  ", NULL,
			      "\n", "Not reported");
	if (ret < 0)
		return err_ret;

	return MNL_CB_OK;
}

int nl_geee(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_EEE_GET, true))
		return -EOPNOTSUPP;
	if (ctx->argc > 0) {
		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
			*ctx->argp);
		return 1;
	}

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_EEE_GET,
				      ETHTOOL_A_EEE_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, eee_reply_cb);
}
