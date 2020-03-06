/*
 * netlink.c - basic infrastructure for netlink code
 *
 * Heart of the netlink interface implementation.
 */

#include <errno.h>

#include "../internal.h"
#include "netlink.h"
#include "extapi.h"
#include "msgbuff.h"
#include "nlsock.h"

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

struct fam_info {
	const char	*fam_name;
	const char	*grp_name;
	uint16_t	fam_id;
	uint32_t	grp_id;
};

static void find_mc_group(struct nlattr *nest, struct fam_info *info)
{
	const struct nlattr *grp_tb[CTRL_ATTR_MCAST_GRP_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(grp_tb);
	struct nlattr *grp_attr;
	int ret;

	mnl_attr_for_each_nested(grp_attr, nest) {
		ret = mnl_attr_parse_nested(grp_attr, attr_cb, &grp_tb_info);
		if (ret < 0)
			return;
		if (!grp_tb[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !grp_tb[CTRL_ATTR_MCAST_GRP_ID])
			continue;
		if (strcmp(mnl_attr_get_str(grp_tb[CTRL_ATTR_MCAST_GRP_NAME]),
			   info->grp_name))
			continue;
		info->grp_id =
			mnl_attr_get_u32(grp_tb[CTRL_ATTR_MCAST_GRP_ID]);
		return;
	}
}

static int family_info_cb(const struct nlmsghdr *nlhdr, void *data)
{
	struct fam_info *info = data;
	struct nlattr *attr;

	mnl_attr_for_each(attr, nlhdr, GENL_HDRLEN) {
		switch (mnl_attr_get_type(attr)) {
		case CTRL_ATTR_FAMILY_ID:
			info->fam_id = mnl_attr_get_u16(attr);
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			find_mc_group(attr, info);
			break;
		}
	}

	return MNL_CB_OK;
}

static int get_genl_family(struct nl_socket *nlsk, struct fam_info *info)
{
	struct nl_msg_buff *msgbuff = &nlsk->msgbuff;
	int ret;

	nlsk->nlctx->suppress_nlerr = 2;
	ret = __msg_init(msgbuff, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			 NLM_F_REQUEST | NLM_F_ACK, 1);
	if (ret < 0)
		goto out;
	ret = -EMSGSIZE;
	if (ethnla_put_strz(msgbuff, CTRL_ATTR_FAMILY_NAME, info->fam_name))
		goto out;

	nlsock_sendmsg(nlsk, NULL);
	nlsock_process_reply(nlsk, family_info_cb, info);
	ret = info->fam_id ? 0 : -EADDRNOTAVAIL;

out:
	nlsk->nlctx->suppress_nlerr = 0;
	return ret;
}

int netlink_init(struct cmd_context *ctx)
{
	struct fam_info info = {
		.fam_name	= ETHTOOL_GENL_NAME,
		.grp_name	= ETHTOOL_MCGRP_MONITOR_NAME,
	};
	struct nl_context *nlctx;
	int ret;

	nlctx = calloc(1, sizeof(*nlctx));
	if (!nlctx)
		return -ENOMEM;
	nlctx->ctx = ctx;
	ret = nlsock_init(nlctx, &nlctx->ethnl_socket, NETLINK_GENERIC);
	if (ret < 0)
		goto out_free;
	ret = get_genl_family(nlctx->ethnl_socket, &info);
	if (ret < 0)
		goto out_nlsk;
	nlctx->ethnl_fam = info.fam_id;
	nlctx->ethnl_mongrp = info.grp_id;

	ctx->nlctx = nlctx;
	return 0;

out_nlsk:
	nlsock_done(nlctx->ethnl_socket);
out_free:
	free(nlctx);
	return ret;
}

void netlink_done(struct cmd_context *ctx)
{
	if (!ctx->nlctx)
		return;

	free(ctx->nlctx);
	ctx->nlctx = NULL;
}
