/*
 * netlink.c - basic infrastructure for netlink code
 *
 * Heart of the netlink interface implementation.
 */

#include <errno.h>

#include "../internal.h"
#include "netlink.h"
#include "extapi.h"

/* Used as reply callback for requests where no reply is expected (e.g. most
 * "set" type commands)
 */
int nomsg_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);

	fprintf(stderr, "received unexpected message: len=%u type=%u cmd=%u\n",
		nlhdr->nlmsg_len, nlhdr->nlmsg_type, ghdr->cmd);
	return MNL_CB_OK;
}

/* standard attribute parser callback; it fills provided array with pointers
 * to attributes like kernel nla_parse(). We must expect to run on top of
 * a newer kernel which may send attributes that we do not know (yet). Rather
 * than treating them as an error, just ignore them.
 */
int attr_cb(const struct nlattr *attr, void *data)
{
	const struct attr_tb_info *tb_info = data;
	int type = mnl_attr_get_type(attr);

	if (type >= 0 && type <= tb_info->max_type)
		tb_info->tb[type] = attr;

	return MNL_CB_OK;
}

/* initialization */

int netlink_init(struct cmd_context *ctx)
{
	struct nl_context *nlctx;

	nlctx = calloc(1, sizeof(*nlctx));
	if (!nlctx)
		return -ENOMEM;
	nlctx->ctx = ctx;

	ctx->nlctx = nlctx;

	return 0;
}

void netlink_done(struct cmd_context *ctx)
{
	if (!ctx->nlctx)
		return;

	free(ctx->nlctx);
	ctx->nlctx = NULL;
}
