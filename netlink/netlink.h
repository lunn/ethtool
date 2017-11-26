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

#define MAX_MSG_SIZE (4 << 20)		/* 4 MB */
#define WILDCARD_DEVNAME "*"

struct nl_context {
	unsigned long debug;
	int ethnl_fam;
	uint32_t mon_mcgrp_id;
	struct mnl_socket *sk;
	struct nl_context *aux_nlctx;
	void *cmd_private;
	char *buff;
	unsigned int buffsize;
	unsigned int port;
	unsigned int seq;
	struct nlmsghdr *nlhdr;
	struct genlmsghdr *gnlhdr;
	void *msg;
	const char *devname;
	bool is_dump;
	const char *cmd;
	const char *param;
	char **argp;
	int argc;
	int exit_code;
	bool suppress_nlerr;
	bool is_monitor;
	uint8_t filter_cmd;
	uint32_t filter_mask;
	const char *filter_devname;
};

struct attr_tb_info {
	const struct nlattr **tb;
	unsigned int max_type;
};
#define DECLARE_ATTR_TB_INFO(tbl) \
	struct attr_tb_info tbl ## _info = { (tbl), (MNL_ARRAY_SIZE(tbl) - 1) }

struct stringset;

unsigned int nl_copy_payload(void *buff, unsigned int maxlen,
			     const struct nlattr *attr);
bool ethnla_put(struct nl_context *nlctx, uint16_t type, size_t len,
		const void *data);
struct nlattr *ethnla_nest_start(struct nl_context *nlctx, uint16_t type);
bool ethnla_put_dev(struct nl_context *nlctx, uint16_t type,
		    const char *devname);
const char *get_dev_name(const struct nlattr *nest);
int get_dev_info(const struct nlattr *nest, int *ifindex, char *ifname);

uint32_t bitset_get_count(const struct nlattr *bitset, int *retptr);
bool bitset_get_bit(const struct nlattr *bitset, bool mask, unsigned int idx,
		    int *retptr);
bool bitset_is_empty(const struct nlattr *bitset, bool mask, int *retptr);
typedef void (*bitset_walk_callback)(unsigned int, const char *, bool, void *);
int walk_bitset(const struct nlattr *bitset, const struct stringset *label,
		bitset_walk_callback cb, void *data);

int dump_link_modes(const struct nlattr *bitset, bool mask, unsigned class,
		    const char *before, const char *between, const char *after,
		    const char *if_none);

int msg_init(struct nl_context *nlctx, int cmd, unsigned int flags);
int ethnl_process_reply(struct nl_context *nlctx, mnl_cb_t reply_cb);
int attr_cb(const struct nlattr *attr, void *data);
int ethnl_prep_get_request(struct cmd_context *ctx, unsigned int nlcmd,
			   uint16_t dev_attrtype);
int ethnl_send_get_request(struct nl_context *nlctx, mnl_cb_t cb);
int __init_aux_nlctx(struct nl_context *nlctx);

/* put data wrappers */

static inline bool ethnla_put_u32(struct nl_context *nlctx, uint16_t type,
				  uint32_t data)
{
	return ethnla_put(nlctx, type, sizeof(uint32_t), &data);
}

static inline bool ethnla_put_u8(struct nl_context *nlctx, uint16_t type,
				 uint8_t data)
{
	return ethnla_put(nlctx, type, sizeof(uint8_t), &data);
}

static inline bool ethnla_put_flag(struct nl_context *nlctx, uint16_t type,
				   bool val)
{
	if (val)
		return ethnla_put(nlctx, type, 0, &val);
	else
		return false;
}

static inline bool ethnla_put_bitfield32(struct nl_context *nlctx,
					 uint16_t type, uint32_t value,
					 uint32_t selector)
{
	struct nla_bitfield32 val = {
		.value		= value,
		.selector	= selector,
	};

	return ethnla_put(nlctx, type, sizeof(val), &val);
}

static inline bool ethnla_put_strz(struct nl_context *nlctx, uint16_t type,
				   const char *data)
{
	return ethnla_put(nlctx, type, strlen(data) + 1, data);
}

ssize_t ethnl_sendmsg(struct nl_context *nlctx);

/* dump helpers */

static inline const char *u8_to_bool(const struct nlattr *attr)
{
	if (attr)
		return mnl_attr_get_u8(attr) ? "on" : "off";
	else
		return "n/a";
}

static inline void show_u32(const struct nlattr *attr, const char *lbl)
{
	if (attr)
		printf("%s%u\n", lbl, mnl_attr_get_u32(attr));
}

static inline void show_bool(const struct nlattr *attr, const char *lbl)
{
	if (attr)
		printf("%s%s\n", lbl, mnl_attr_get_u8(attr) ? "on" : "off");
}

static inline void show_string(const struct nlattr **tb, unsigned int idx,
			       const char *label)
{
	printf("%s: %s\n", label, tb[idx] ? mnl_attr_get_str(tb[idx]) : "");
}

/* reply content filtering */

static inline bool mask_ok(const struct nl_context *nlctx, uint32_t bits)
{
	return !nlctx->filter_mask || (nlctx->filter_mask & bits);
}

static inline bool dev_ok(const struct nl_context *nlctx)
{
	return !nlctx->filter_devname ||
	       (nlctx->devname &&
		!strcmp(nlctx->devname, nlctx->filter_devname));
}

static inline bool show_only(const struct nl_context *nlctx, uint32_t bits)
{
	if (nlctx->is_monitor || !nlctx->filter_mask)
		return false;
	return nlctx->filter_mask & ~bits;
}

/* misc */

static inline bool debug_on(unsigned long debug, unsigned int bit)
{
	return (debug & (1 << bit));
}

static inline int init_aux_nlctx(struct nl_context *nlctx)
{
	return nlctx->aux_nlctx ? 0 : __init_aux_nlctx(nlctx);
}

static inline void copy_devname(char *dst, const char *src)
{
	strncpy(dst, src, IFNAMSIZ);
	dst[IFNAMSIZ - 1] = '\0';
}

#endif /* ETHTOOL_NETLINK_INT_H__ */
