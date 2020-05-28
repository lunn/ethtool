/*
 * extapi.h - external interface of netlink code
 *
 * Declarations needed by non-netlink code (mostly ethtool.c).
 */

#ifndef ETHTOOL_EXTAPI_H__
#define ETHTOOL_EXTAPI_H__

struct cmd_context;
struct nl_context;

typedef int (*nl_func_t)(struct cmd_context *);

#ifdef ETHTOOL_ENABLE_NETLINK

void netlink_run_handler(struct cmd_context *ctx, nl_func_t nlfunc,
			 bool no_fallback);

int nl_gset(struct cmd_context *ctx);
int nl_sset(struct cmd_context *ctx);
int nl_permaddr(struct cmd_context *ctx);
int nl_gfeatures(struct cmd_context *ctx);
int nl_sfeatures(struct cmd_context *ctx);
int nl_gprivflags(struct cmd_context *ctx);
int nl_sprivflags(struct cmd_context *ctx);
int nl_gring(struct cmd_context *ctx);
int nl_sring(struct cmd_context *ctx);
int nl_monitor(struct cmd_context *ctx);

void nl_monitor_usage(void);

#else /* ETHTOOL_ENABLE_NETLINK */

static inline void netlink_run_handler(struct cmd_context *ctx,
				       nl_func_t nlfunc, bool no_fallback)
{
}

static inline int nl_monitor(struct cmd_context *ctx)
{
	fprintf(stderr, "Netlink not supported by ethtool, option --monitor unsupported.\n");
	return -EOPNOTSUPP;
}

static inline void nl_monitor_usage(void)
{
}

#define nl_gset			NULL
#define nl_sset			NULL
#define nl_permaddr		NULL
#define nl_gfeatures		NULL
#define nl_sfeatures		NULL
#define nl_gprivflags		NULL
#define nl_sprivflags		NULL
#define nl_gring		NULL
#define nl_sring		NULL

#endif /* ETHTOOL_ENABLE_NETLINK */

#endif /* ETHTOOL_EXTAPI_H__ */
