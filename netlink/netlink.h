/*
 * netlink.h - common interface for all netlink code
 *
 * Declarations of data structures, global data and helpers for netlink code
 */

#ifndef ETHTOOL_NETLINK_INT_H__
#define ETHTOOL_NETLINK_INT_H__

#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/ethtool_netlink.h>
#include "nlsock.h"

#define WILDCARD_DEVNAME "*"

struct nl_context {
	struct cmd_context	*ctx;
	void			*cmd_private;
	const char		*devname;
	bool			is_dump;
	int			exit_code;
	unsigned int		suppress_nlerr;
	uint16_t		ethnl_fam;
	uint32_t		ethnl_mongrp;
	struct nl_socket	*ethnl_socket;
	struct nl_socket	*ethnl2_socket;
};

struct attr_tb_info {
	const struct nlattr **tb;
	unsigned int max_type;
};

#define DECLARE_ATTR_TB_INFO(tbl) \
	struct attr_tb_info tbl ## _info = { (tbl), (MNL_ARRAY_SIZE(tbl) - 1) }

int nomsg_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int attr_cb(const struct nlattr *attr, void *data);

static inline int netlink_init_ethnl2_socket(struct nl_context *nlctx)
{
	if (nlctx->ethnl2_socket)
		return 0;
	return nlsock_init(nlctx, &nlctx->ethnl2_socket, NETLINK_GENERIC);
}

#endif /* ETHTOOL_NETLINK_INT_H__ */
