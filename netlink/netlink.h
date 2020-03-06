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

#define WILDCARD_DEVNAME "*"

struct nl_context {
	struct cmd_context	*ctx;
	void			*cmd_private;
	const char		*devname;
	bool			is_dump;
	int			exit_code;
	unsigned int		suppress_nlerr;
};

#endif /* ETHTOOL_NETLINK_INT_H__ */
