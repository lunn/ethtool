/*
 * extapi.h - external interface of netlink code
 *
 * Declarations needed by non-netlink code (mostly ethtool.c).
 */

#ifndef ETHTOOL_EXTAPI_H__
#define ETHTOOL_EXTAPI_H__

struct cmd_context;
struct nl_context;

#ifdef ETHTOOL_ENABLE_NETLINK

int netlink_init(struct cmd_context *ctx);
void netlink_done(struct cmd_context *ctx);

#else /* ETHTOOL_ENABLE_NETLINK */

static inline int netlink_init(struct cmd_context *ctx maybe_unused)
{
	return -EOPNOTSUPP;
}

static inline void netlink_done(struct cmd_context *ctx maybe_unused)
{
}

#endif /* ETHTOOL_ENABLE_NETLINK */

#endif /* ETHTOOL_EXTAPI_H__ */
