#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

/* ACT_NWAY_RST */

int nwayrst_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_NWAYRST_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_NWAYRST_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	printf("Autonegotiation restarted on device %s\n", nlctx->devname);

	return MNL_CB_OK;
}

int nl_nway_rst(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	int ret;

	nlctx->cmd = "-r";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	ret = msg_init(nlctx, ETHNL_CMD_ACT_NWAY_RST,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return -EFAULT;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_NWAYRST_DEV, ctx->devname))
		return -EMSGSIZE;

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		return -EFAULT;
	ret = ethnl_process_reply(nlctx, nomsg_reply_cb);
	if (ret < 0)
		fprintf(stderr, "Cannot restart autonegotiation\n");

	return ret;
}
