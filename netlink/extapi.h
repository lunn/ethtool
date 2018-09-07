/*
 * extapi.h - external netlink interface
 *
 * interface for general non-netlink code
 */

#ifndef ETHTOOL_EXTAPI_H__
#define ETHTOOL_EXTAPI_H__

struct cmd_context;
struct nl_context;

int netlink_init(struct cmd_context *ctx);
void netlink_done(struct cmd_context *ctx);

int nl_gdrv(struct cmd_context *ctx);
int nl_tsinfo(struct cmd_context *ctx);
int nl_gset(struct cmd_context *ctx);
int nl_sset(struct cmd_context *ctx);
int nl_gfeatures(struct cmd_context *ctx);
int nl_sfeatures(struct cmd_context *ctx);
int nl_gprivflags(struct cmd_context *ctx);
int nl_sprivflags(struct cmd_context *ctx);
int nl_monitor(struct cmd_context *ctx);

void monitor_usage();

#endif /* ETHTOOL_EXTAPI_H__ */
