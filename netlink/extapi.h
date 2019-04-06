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
int nl_gcoalesce(struct cmd_context *ctx);
int nl_gring(struct cmd_context *ctx);
int nl_gpause(struct cmd_context *ctx);
int nl_gchannels(struct cmd_context *ctx);
int nl_geee(struct cmd_context *ctx);
int nl_gfec(struct cmd_context *ctx);
int nl_scoalesce(struct cmd_context *ctx);
int nl_sring(struct cmd_context *ctx);
int nl_spause(struct cmd_context *ctx);
int nl_schannels(struct cmd_context *ctx);
int nl_seee(struct cmd_context *ctx);
int nl_sfec(struct cmd_context *ctx);
int nl_nway_rst(struct cmd_context *ctx);
int nl_phys_id(struct cmd_context *ctx);
int nl_reset(struct cmd_context *ctx);
int nl_grxfh(struct cmd_context *ctx);
int nl_srxfh(struct cmd_context *ctx);
int nl_grxclass(struct cmd_context *ctx);
int nl_srxclass(struct cmd_context *ctx);
int nl_cable_test(struct cmd_context *ctx);
int nl_monitor(struct cmd_context *ctx);

void monitor_usage();

#endif /* ETHTOOL_EXTAPI_H__ */
