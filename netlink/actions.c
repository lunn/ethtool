#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"
#include "strset.h"

/* ACT_NWAY_RST */

int nwayrst_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_NWAYRST_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_NWAYRST_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	printf("Autonegotiation restarted on device %s\n", nlctx->devname);

	return MNL_CB_OK;
}

int nl_nway_rst(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	int ret;

	nlctx->cmd = "-r";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	ret = msg_init(nlctx, ETHNL_CMD_ACT_NWAY_RST,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return -EFAULT;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_NWAYRST_DEV, ctx->devname))
		return -EMSGSIZE;

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		return -EFAULT;
	ret = ethnl_process_reply(nlctx, nomsg_reply_cb);
	if (ret < 0)
		fprintf(stderr, "Cannot restart autonegotiation\n");

	return ret;
}

/* ACT_PHYS_ID */

int physid_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_PHYSID_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	uint32_t timeout = 0;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_PHYSID_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;
	if(tb[ETHTOOL_A_PHYSID_LENGTH])
		timeout = mnl_attr_get_u32(tb[ETHTOOL_A_PHYSID_LENGTH]);

	if (timeout) {
		printf("NIC identification for %s started", nlctx->devname);
		if (timeout < UINT32_MAX)
			printf(", timeout %u seconds", timeout);
		putchar('\n');
	} else {
		printf("NIC identification for %s finshed\n", nlctx->devname);
	}

	return MNL_CB_OK;
}

int nl_phys_id(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	bool have_length = false;
	uint32_t length;
	int ret;

	nlctx->cmd = "-p";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	if (nlctx->argc > 1) {
		fprintf(stderr,
			"only one argument expected for -p / --identify\n");
		return 2;
	}
	if (nlctx->argc > 0) {
		ret = parse_u32(nlctx->argp[0], &length);
		if (ret < 0) {
			fprintf(stderr,
				"invalid argument '%s' for -p / --identify\n",
				nlctx->argp[0]);
			return 2;
		}
		have_length = true;
		nlctx->argp++;
		nlctx->argc--;
	}

	ret = msg_init(nlctx, ETHNL_CMD_ACT_PHYS_ID,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return -EFAULT;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_PHYSID_DEV, ctx->devname))
		return -EMSGSIZE;
	if (have_length &&
	    ethnla_put_u32(nlctx, ETHTOOL_A_PHYSID_LENGTH, length))
		return -EMSGSIZE;

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		return -EFAULT;
	ret = ethnl_process_reply(nlctx, nomsg_reply_cb);
	if (ret < 0)
		fprintf(stderr, "Cannot identify NIC\n");

	return ret;
}

/* ACT_RESET */

struct reset_walk_data {
	uint32_t flags_t;
	uint32_t flags_f;
	bool shared;
};

void reset_walk_cb(unsigned int idx, const char *name, bool val, void *__data)
{
	struct reset_walk_data *data = __data;
	u32 mask = 1U << (idx + (data->shared ? ETH_RESET_SHARED_SHIFT : 0));

	if (val)
		data->flags_t |= mask;
	else
		data->flags_f |= mask;
}

int reset_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_RESET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	const struct stringset *labels = global_stringset(ETH_SS_RESET_FLAGS);
	struct reset_walk_data walk_data = {};
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_RESET_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (tb[ETHTOOL_A_RESET_ALL]) {
		walk_data.flags_t = ETH_RESET_ALL;
		goto show;
	}
	walk_data.shared = true;
	if (tb[ETHTOOL_A_RESET_SHARED])
		walk_bitset(tb[ETHTOOL_A_RESET_SHARED], labels, reset_walk_cb,
			    &walk_data);

	if (tb[ETHTOOL_A_RESET_ALL_DEDICATED]) {
		walk_data.flags_t |= ETH_RESET_DEDICATED;
		goto show;
	}
	walk_data.shared = false;
	if (tb[ETHTOOL_A_RESET_DEDICATED])
		walk_bitset(tb[ETHTOOL_A_RESET_DEDICATED], labels,
			    reset_walk_cb,
			    &walk_data);

show:
	if (nlctx->is_monitor)
		putchar('\n');
	printf("Reset performed on %s\n", nlctx->devname);
	printf("Components reset:     0x%x\n", walk_data.flags_t);
	if (walk_data.flags_f)
		printf("Components not reset: 0x%x\n", walk_data.flags_f);

	return MNL_CB_OK;
}

static int fill_bitset_from_u32(struct nl_context *nlctx, uint16_t type,
				uint32_t value)
{
	struct nlattr *nest = ethnla_nest_start(nlctx, type);

	if (!nest)
		return -EMSGSIZE;
	if (ethnla_put_u32(nlctx, ETHTOOL_A_BITSET_SIZE, nsb(value)) ||
	    ethnla_put_u32(nlctx, ETHTOOL_A_BITSET_VALUE, value) ||
	    ethnla_put_u32(nlctx, ETHTOOL_A_BITSET_MASK, value))
		return -EMSGSIZE;
	mnl_attr_nest_end(nlctx->nlhdr, nest);

	return 0;
}


static int fill_reset(struct nl_context *nlctx, uint32_t flags)
{
	int ret;

	if (flags == ETH_RESET_ALL)
		return ethnla_put_flag(nlctx, ETHTOOL_A_RESET_ALL, true) ?
		       -EMSGSIZE : 0;

	if ((flags & ETH_RESET_DEDICATED) == ETH_RESET_DEDICATED) {
		if (ethnla_put_flag(nlctx, ETHTOOL_A_RESET_ALL_DEDICATED, true))
			return -EMSGSIZE;
	} else if (flags & ETH_RESET_DEDICATED) {
		ret = fill_bitset_from_u32(nlctx, ETHTOOL_A_RESET_DEDICATED,
					   flags & ETH_RESET_DEDICATED);
		if (ret < 0)
			return ret;
	}

	if (flags >> ETH_RESET_SHARED_SHIFT) {
		ret = fill_bitset_from_u32(nlctx, ETHTOOL_A_RESET_SHARED,
					   flags >> ETH_RESET_SHARED_SHIFT);
		if (ret < 0)
			return ret;
	}
	return 0;
}

#define SHARED_SUFFIX "-shared"
#define SHARED_SUFFIX_LEN 7
static int parse_reset(struct nl_context *nlctx)
{
	bool all_dedicated = false;
	struct nlmsghdr *nlhdr = nlctx->nlhdr;
	struct nlattr *bitset;
	struct nlattr *bits;
	unsigned int i;
	uint32_t flags;
	int ret;

	if (nlctx->argc < 1)
		return -EINVAL;
	ret = parse_u32(nlctx->argp[0], &flags);
	if (ret == 0)
		return fill_reset(nlctx, flags);

	for (i = 0; i < nlctx->argc; i++) {
		if (!strcmp(nlctx->argp[i], "all")) {
			if (ethnla_put_flag(nlctx, ETHTOOL_A_RESET_ALL, true))
				return -EMSGSIZE;
			else
				return 0;
		}
		if (!strcmp(nlctx->argp[i], "dedicated"))
			all_dedicated = true;
	}
	if (all_dedicated) {
	       if (ethnla_put_flag(nlctx, ETHTOOL_A_RESET_ALL_DEDICATED, true))
		       return -EMSGSIZE;
	       goto check_shared;
	}

	bitset = bits = NULL;
	for (i = 0; i < nlctx->argc; i++) {
		const char *arg = nlctx->argp[i];
		int len = strlen(arg) - SHARED_SUFFIX_LEN;
		struct nlattr *bit;

		if (len >= 0 && !strcmp(arg + len, SHARED_SUFFIX))
			continue;
		if (!bitset) {
			bitset = ethnla_nest_start(nlctx,
						   ETHTOOL_A_RESET_DEDICATED);
			if (!bitset)
				return -EMSGSIZE;
			if (ethnla_put_flag(nlctx, ETHTOOL_A_BITSET_LIST, true))
				return -EMSGSIZE;
			bits = ethnla_nest_start(nlctx, ETHTOOL_A_BITSET_BITS);
			if (!bits)
				return -EMSGSIZE;
		}

		bit = ethnla_nest_start(nlctx, ETHTOOL_A_BITS_BIT);
		if (!bit)
			return -EMSGSIZE;
		if (ethnla_put_strz(nlctx, ETHTOOL_A_BIT_NAME, arg))
			return -EMSGSIZE;
		mnl_attr_nest_end(nlhdr, bit);
	}
	if (bitset) {
		mnl_attr_nest_end(nlhdr, bits);
		mnl_attr_nest_end(nlhdr, bitset);
	}

check_shared:
	bitset = bits = NULL;
	for (i = 0; i < nlctx->argc; i++) {
		const char *arg = nlctx->argp[i];
		int len = strlen(arg) - SHARED_SUFFIX_LEN;
		struct nlattr *bit;
		char *tail;

		if (!strcmp(arg, "dedicated"))
			continue;
		if (len < 0 || strcmp(arg + len, SHARED_SUFFIX))
			continue;
		if (!bitset) {
			bitset = ethnla_nest_start(nlctx,
						   ETHTOOL_A_RESET_SHARED);
			if (!bitset)
				return -EMSGSIZE;
			if (ethnla_put_flag(nlctx, ETHTOOL_A_BITSET_LIST, true))
				return -EMSGSIZE;
			bits = ethnla_nest_start(nlctx, ETHTOOL_A_BITSET_BITS);
			if (!bits)
				return -EMSGSIZE;
		}

		bit = ethnla_nest_start(nlctx, ETHTOOL_A_BITS_BIT);
		if (!bit)
			return -EMSGSIZE;
		tail = mnl_nlmsg_get_payload_tail(nlhdr);
		if (ethnla_put(nlctx, ETHTOOL_A_BIT_NAME, len + 1, arg))
			return -EMSGSIZE;
		tail[MNL_ATTR_HDRLEN + len] = '\0';
		mnl_attr_nest_end(nlhdr, bit);
	}
	if (bitset) {
		mnl_attr_nest_end(nlhdr, bits);
		mnl_attr_nest_end(nlhdr, bitset);
	}

	return 0;
}

int nl_reset(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	int ret;

	nlctx->cmd = "-p";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;

	ret = msg_init(nlctx, ETHNL_CMD_ACT_RESET, NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return -EFAULT;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_RESET_DEV, ctx->devname) ||
	    ethnla_put_flag(nlctx, ETHTOOL_A_RESET_COMPACT, true))
		return -EMSGSIZE;
	ret = parse_reset(nlctx);
	if (ret < 0)
		return ret;

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		return -EFAULT;
	ret = ethnl_process_reply(nlctx, reset_reply_cb);
	if (ret < 0)
		fprintf(stderr, "Cannot identify NIC\n");

	return ret;
}

/* ACT_CABLE_TEST */

int cable_test_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_TEST_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_CABLE_TEST_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	printf("Starting cable test on device %s\n", nlctx->devname);

	return MNL_CB_OK;
}

static int cable_test_results_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);
	struct nl_context *nlctx = data;
	struct nlattr *evattr;

	if (ghdr->cmd != ETHNL_CMD_EVENT)
		return MNL_CB_OK;

	if (nlhdr->nlmsg_seq != nlctx->seq)
		return MNL_CB_OK;

	mnl_attr_for_each(evattr, nlhdr, GENL_HDRLEN) {
		switch(mnl_attr_get_type(evattr)) {
		case ETHTOOL_A_EVENT_CABLE_TEST:
			monitor_cable_test(nlctx, evattr);
			return MNL_CB_STOP;
		default:
			break;
		}
	}
	return MNL_CB_OK;
}

static int cable_test_process_results(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	uint32_t grpid = nlctx->mon_mcgrp_id;
	int ret;

	if (!grpid) {
		fprintf(stderr, "multicast group 'monitor' not found\n");
		return -EOPNOTSUPP;
	}

	ret = mnl_socket_setsockopt(nlctx->sk, NETLINK_ADD_MEMBERSHIP,
				    &grpid, sizeof(grpid));
	if (ret < 0)
		return ret;

	nlctx->is_monitor = true;
	nlctx->port = 0;

	return ethnl_process_reply(nlctx, cable_test_results_cb);
}

int nl_cable_test(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	int ret;

	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	ret = msg_init(nlctx, ETHNL_CMD_ACT_CABLE_TEST,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return -EFAULT;
	if (ethnla_put_dev(nlctx, ETHTOOL_A_CABLE_TEST_DEV, ctx->devname))
		return -EMSGSIZE;

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		return -EFAULT;
	ret = ethnl_process_reply(nlctx, nomsg_reply_cb);

	if (ret < 0)
		fprintf(stderr, "Cannot start cable test\n");
	else
		cable_test_process_results(ctx);
	return ret;
}
