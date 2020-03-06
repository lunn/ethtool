/*
 * netlink.c - basic infrastructure for netlink code
 *
 * Heart of the netlink interface implementation.
 */

#include <errno.h>

#include "../internal.h"
#include "netlink.h"
#include "extapi.h"

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
