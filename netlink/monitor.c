#include <errno.h>

#include "../internal.h"
#include "netlink.h"
#include "strset.h"

static void monitor_newdev(struct nl_context *nlctx, struct nlattr *evattr)
{
	const struct nlattr *tb[ETHTOOL_A_NEWDEV_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const char *devname;
	int ret;

	ret = mnl_attr_parse_nested(evattr, attr_cb, &tb_info);
	if (ret < 0)
		return;
	if (!tb[ETHTOOL_A_NEWDEV_DEV])
		return;
	devname = get_dev_name(tb[ETHTOOL_A_NEWDEV_DEV]);
	if (!devname)
		return;
	printf("New device %s registered.\n", devname);

	ret = init_aux_nlctx(nlctx);
	if (ret < 0)
		return;
	load_perdev_strings(nlctx->aux_nlctx, devname);
}

static void monitor_deldev(struct nl_context *nlctx, struct nlattr *evattr)
{
	const struct nlattr *tb[ETHTOOL_A_DELDEV_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const char *devname;
	int ret;

	ret = mnl_attr_parse_nested(evattr, attr_cb, &tb_info);
	if (ret < 0)
		return;
	if (!tb[ETHTOOL_A_DELDEV_DEV])
		return;
	devname = get_dev_name(tb[ETHTOOL_A_DELDEV_DEV]);
	if (!devname)
		return;
	printf("Device %s unregistered.\n", devname);

	free_perdev_strings(devname);
}

static void monitor_renamedev(struct nl_context *nlctx, struct nlattr *evattr)
{
	const struct nlattr *tb[ETHTOOL_A_RENAMEDEV_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	char oldname[IFNAMSIZ] = "";
	char newname[IFNAMSIZ];
	int ifindex;
	int ret;

	ret = mnl_attr_parse_nested(evattr, attr_cb, &tb_info);
	if (ret < 0)
		return;
	if (!tb[ETHTOOL_A_RENAMEDEV_DEV])
		return;
	ret = get_dev_info(tb[ETHTOOL_A_RENAMEDEV_DEV], &ifindex, newname);
	if (ret < 0)
		return;

	ret = rename_perdev_strings(ifindex, newname, oldname);
	if (ret < 0)
		load_perdev_strings(nlctx->aux_nlctx, newname);
	else
		printf("Device %s renamed to %s.\n", oldname, newname);
}

static int get_cable_test_result(const struct nlattr *nest, uint8_t *pair,
			  uint16_t *code)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_RESULT_MAX+1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0 ||
	    !tb[ETHTOOL_A_CABLE_RESULT_PAIR] ||
	    !tb[ETHTOOL_A_CABLE_RESULT_CODE])
		return -EFAULT;

	*pair = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_RESULT_PAIR]);
	*code = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_RESULT_CODE]);

	return 0;
}

static int get_cable_test_fault_length(const struct nlattr *nest,
				       uint8_t *pair, int *cm)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_FAULT_LENGTH_MAX+1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0 ||
	    !tb[ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR] ||
	    !tb[ETHTOOL_A_CABLE_FAULT_LENGTH_CM])
		return -EFAULT;

	*pair = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR]);
	*cm = mnl_attr_get_u16(tb[ETHTOOL_A_CABLE_FAULT_LENGTH_CM]);

	return 0;
}

static char *code2txt(uint16_t code)
{
	switch(code) {
	case ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC:
	default:
		return "Unknown";
	case ETHTOOL_A_CABLE_RESULT_CODE_OK:
		return "OK";
	case ETHTOOL_A_CABLE_RESULT_CODE_OPEN:
		return "Open Circuit";
	case ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT:
		return "Short within Pair";
	case ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT:
		return "Short to another pair";
	}
}

static int monitor_cable_test_event(struct nl_context *nlctx,
				    struct nlattr *evattr)
{
	char name[IFNAMSIZ] = "";
	uint16_t code;
	uint8_t pair;
	int ifindex;
	int ret;
	int cm;

	switch (mnl_attr_get_type(evattr)) {
	case ETHTOOL_A_CABLE_TEST_EVENT_DEV:
		ret = get_dev_info(evattr, &ifindex, name);
		if (ret < 0)
			return ret;

		printf("Cable test for device %s.\n", name);
		break;

	case ETHTOOL_A_CABLE_TEST_EVENT_RESULT:
		ret = get_cable_test_result(evattr, &pair, &code);
		if (ret < 0)
			return ret;

		printf("Pair: %d, result: %s\n", pair, code2txt(code));
		break;

	case ETHTOOL_A_CABLE_TEST_EVENT_FAULT_LENGTH:
		ret = get_cable_test_fault_length(evattr, &pair, &cm);
		if (ret < 0)
			return ret;

		printf("Pair: %d, fault length: %0.2fm\n", pair,
		       (float)cm / 100);
		break;
	}
	return 0;
}

void monitor_cable_test(struct nl_context *nlctx, struct nlattr *evattr)
{
	struct nlattr *pos;
	int ret;

	mnl_attr_for_each_nested(pos,  evattr) {
		ret = monitor_cable_test_event(nlctx, pos);
		if (ret < 0)
			return;
	}
}

static int monitor_event_cb(const struct nlmsghdr *nlhdr, void *data)
{
	struct nl_context *nlctx = data;
	struct nlattr *evattr;

	mnl_attr_for_each(evattr, nlhdr, GENL_HDRLEN) {
		switch(mnl_attr_get_type(evattr)) {
		case ETHTOOL_A_EVENT_NEWDEV:
			monitor_newdev(nlctx, evattr);
			break;
		case ETHTOOL_A_EVENT_DELDEV:
			monitor_deldev(nlctx, evattr);
			break;
		case ETHTOOL_A_EVENT_RENAMEDEV:
			monitor_renamedev(nlctx, evattr);
			break;
		case ETHTOOL_A_EVENT_CABLE_TEST:
			monitor_cable_test(nlctx, evattr);
			break;
		}
	}

	return MNL_CB_OK;
}

int info_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int settings_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int params_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int nwayrst_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int physid_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int reset_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int rxflow_reply_cb(const struct nlmsghdr *nlhdr, void *data);
int cable_test_reply_cb(const struct nlmsghdr *nlhdr, void *data);

static struct {
	uint8_t		cmd;
	mnl_cb_t	cb;
} monitor_callbacks[] = {
	{
		.cmd	= ETHNL_CMD_EVENT,
		.cb	= monitor_event_cb,
	},
	{
		.cmd	= ETHNL_CMD_SET_INFO,
		.cb	= info_reply_cb,
	},
	{
		.cmd	= ETHNL_CMD_SET_SETTINGS,
		.cb	= settings_reply_cb,
	},
	{
		.cmd	= ETHNL_CMD_SET_PARAMS,
		.cb	= params_reply_cb,
	},
	{
		.cmd	= ETHNL_CMD_ACT_NWAY_RST,
		.cb	= nwayrst_reply_cb,
	},
	{
		.cmd	= ETHNL_CMD_ACT_PHYS_ID,
		.cb	= physid_reply_cb,
	},
	{
		.cmd	= ETHNL_CMD_ACT_RESET,
		.cb	= reset_reply_cb,
	},
	{
		.cmd	= ETHNL_CMD_SET_RXFLOW,
		.cb	= rxflow_reply_cb,
	},
	{
		.cmd	= ETHNL_CMD_ACT_CABLE_TEST,
		.cb	= cable_test_reply_cb,
	},
};

static int monitor_any_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);
	struct nl_context *nlctx = data;
	unsigned i;

	if (nlctx->filter_cmd && ghdr->cmd != nlctx->filter_cmd)
		return MNL_CB_OK;

	for (i = 0; i < MNL_ARRAY_SIZE(monitor_callbacks); i++)
		if (monitor_callbacks[i].cmd == ghdr->cmd)
			return monitor_callbacks[i].cb(nlhdr, data);

	return MNL_CB_OK;
}

struct monitor_option {
	const char	*pattern;
	uint8_t		cmd;
	uint32_t	info_mask;
};

static struct monitor_option monitor_opts[] = {
	{
		.pattern	= "|--all",
		.cmd		= 0,
	},
	{
		.pattern	= "-i|--driver",
		.cmd		= ETHNL_CMD_SET_INFO,
	},
	{
		.pattern	= "-s|--change",
		.cmd		= ETHNL_CMD_SET_SETTINGS,
		.info_mask	= ETHTOOL_IM_SETTINGS_LINKINFO |
				  ETHTOOL_IM_SETTINGS_LINKMODES |
				  ETHTOOL_IM_SETTINGS_LINKSTATE |
				  ETHTOOL_IM_SETTINGS_DEBUG |
				  ETHTOOL_IM_SETTINGS_WOL,
	},
	{
		.pattern	= "-k|--show-features|--show-offload|"
				  "-K|--features|--offload",
		.cmd		= ETHNL_CMD_SET_SETTINGS,
		.info_mask	= ETHTOOL_IM_SETTINGS_FEATURES,
	},
	{
		.pattern	= "--show-priv-flags|--set-priv-flags",
		.cmd		= ETHNL_CMD_SET_SETTINGS,
		.info_mask	= ETHTOOL_IM_SETTINGS_PRIVFLAGS,
	},
	{
		.pattern	= "-c|--show-coalesce|-C|--coalesce",
		.cmd		= ETHNL_CMD_SET_PARAMS,
		.info_mask	= ETHTOOL_IM_PARAMS_COALESCE,
	},
	{
		.pattern	= "-g|--show-ring|-G|--set-ring",
		.cmd		= ETHNL_CMD_SET_PARAMS,
		.info_mask	= ETHTOOL_IM_PARAMS_RING,
	},
	{
		.pattern	= "-a|--show-pause|-A|--pause",
		.cmd		= ETHNL_CMD_SET_PARAMS,
		.info_mask	= ETHTOOL_IM_PARAMS_PAUSE,
	},
	{
		.pattern	= "-l|--show-channels|-L|--set-channels",
		.cmd		= ETHNL_CMD_SET_PARAMS,
		.info_mask	= ETHTOOL_IM_PARAMS_CHANNELS,
	},
	{
		.pattern	= "--show-eee|--set-eee",
		.cmd		= ETHNL_CMD_SET_PARAMS,
		.info_mask	= ETHTOOL_IM_PARAMS_EEE,
	},
	{
		.pattern	= "--show-fec|--set-fec",
		.cmd		= ETHNL_CMD_SET_PARAMS,
		.info_mask	= ETHTOOL_IM_PARAMS_FEC,
	},
	{
		.pattern	= "-r|--negotiate",
		.cmd		= ETHNL_CMD_ACT_NWAY_RST,
	},
	{
		.pattern	= "-p|--identify",
		.cmd		= ETHNL_CMD_ACT_PHYS_ID,
	},
	{
		.pattern	= "--reset",
		.cmd		= ETHNL_CMD_ACT_RESET,
	},
	{
		.pattern	= "-x|--show-rxfh|--show-rxfh-indir|"
				  "-X|--rxfh|--set-rxfh-indir",
		.cmd		= ETHNL_CMD_SET_RXFLOW,
	},
	{
		.pattern	= "--cable-test",
		.cmd		= ETHNL_CMD_ACT_CABLE_TEST,
	},
};

static bool pattern_match(const char *s, const char *pattern)
{
	const char *opt = pattern;
	const char *next;
	int slen = strlen(s);
	int optlen;

	do {
		next = opt;
		while (*next && *next != '|')
			next++;
		optlen = next - opt;
		if (slen == optlen && !strncmp(s, opt, optlen))
			return true;

		opt = next;
		if (*opt == '|')
			opt++;
	} while (*opt);

	return false;
}

static int parse_monitor(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	char **argp = ctx->argp;
	int argc = ctx->argc;
	const char *opt = "";
	unsigned int i;

	if (*argp && argp[0][0] == '-') {
		opt = *argp;
		argp++;
		argc--;
	}
	for (i = 0; i < MNL_ARRAY_SIZE(monitor_opts); i++) {
		if (pattern_match(opt, monitor_opts[i].pattern)) {
			nlctx->filter_cmd = monitor_opts[i].cmd;
			nlctx->filter_mask = monitor_opts[i].info_mask;
			goto opt_found;
		}
	}
	fprintf(stderr, "monitoring for option '%s' not supported\n", *argp);
	return -1;

opt_found:
	if (*argp && strcmp(*argp, WILDCARD_DEVNAME))
		ctx->devname = *argp;
	return 0;
}

int nl_monitor(struct cmd_context *ctx)
{
	bool is_dev;
	struct nl_context *nlctx = ctx->nlctx;
	uint32_t grpid = nlctx->mon_mcgrp_id;
	int ret;

	if (!grpid) {
		fprintf(stderr, "multicast group 'monitor' not found\n");
		return -EOPNOTSUPP;
	}
	if (parse_monitor(ctx) < 0)
		return 1;
	is_dev = ctx->devname && strcmp(ctx->devname, WILDCARD_DEVNAME);

	ret = load_global_strings(nlctx);
	if (ret < 0)
		return ret;
	ret = mnl_socket_setsockopt(nlctx->sk, NETLINK_ADD_MEMBERSHIP,
				    &grpid, sizeof(grpid));
	if (ret < 0)
		return ret;
	ret = load_perdev_strings(nlctx, is_dev ? ctx->devname : NULL);
	if (ret < 0)
		return ret;

	nlctx->filter_devname = ctx->devname;
	nlctx->is_monitor = true;
	nlctx->port = 0;
	nlctx->seq = 0;

	fputs("listening...\n", stdout);
	fflush(stdout);
	ret = ethnl_process_reply(nlctx, monitor_any_cb);
	free_perdev_strings(NULL);
	return ret;
}

void monitor_usage()
{
	const char *p;
	unsigned i;

	fputs("        ethtool --monitor               Show kernel notifications\n",
	      stdout);
	fputs("                ( [ --all ]", stdout);
	for (i = 1; i < MNL_ARRAY_SIZE(monitor_opts); i++) {
		fputs("\n                  | ", stdout);
		for (p = monitor_opts[i].pattern; *p; p++)
			if (*p == '|')
				fputs(" | ", stdout);
			else
				fputc(*p, stdout);
	}
	fputs(" )\n", stdout);
	fputs("                [ DEVNAME | * ]\n", stdout);
}
