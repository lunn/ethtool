/*
 * cable_test.c - netlink implementation of cable test command
 *
 * Implementation of ethtool --cable-test <dev>
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"

struct cable_test_context {
	bool breakout;
};

static int nl_get_cable_test_result(const struct nlattr *nest, uint8_t *pair,
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

static int nl_get_cable_test_fault_length(const struct nlattr *nest,
					  uint8_t *pair, unsigned int *cm)
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
	*cm = mnl_attr_get_u32(tb[ETHTOOL_A_CABLE_FAULT_LENGTH_CM]);

	return 0;
}

static char *nl_code2txt(uint16_t code)
{
	switch (code) {
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

static char *nl_pair2txt(uint8_t pair)
{
	switch (pair) {
	case ETHTOOL_A_CABLE_PAIR_A:
		return "Pair A";
	case ETHTOOL_A_CABLE_PAIR_B:
		return "Pair B";
	case ETHTOOL_A_CABLE_PAIR_C:
		return "Pair C";
	case ETHTOOL_A_CABLE_PAIR_D:
		return "Pair D";
	default:
		return "Unexpected pair";
	}
}

static int nl_cable_test_ntf_attr(struct nlattr *evattr)
{
	unsigned int cm;
	uint16_t code;
	uint8_t pair;
	int ret;

	switch (mnl_attr_get_type(evattr)) {
	case ETHTOOL_A_CABLE_NEST_RESULT:
		ret = nl_get_cable_test_result(evattr, &pair, &code);
		if (ret < 0)
			return ret;

		printf("%s, result: %s\n", nl_pair2txt(pair),
		       nl_code2txt(code));
		break;

	case ETHTOOL_A_CABLE_NEST_FAULT_LENGTH:
		ret = nl_get_cable_test_fault_length(evattr, &pair, &cm);
		if (ret < 0)
			return ret;

		printf("%s, fault length: %0.2fm\n",
		       nl_pair2txt(pair), (float)cm / 100);
		break;
	}
	return 0;
}

static void cable_test_ntf_nest(const struct nlattr *nest)
{
	struct nlattr *pos;
	int ret;

	mnl_attr_for_each_nested(pos, nest) {
		ret = nl_cable_test_ntf_attr(pos);
		if (ret < 0)
			return;
	}
}

/* Returns MNL_CB_STOP when the test is complete. Used when executing
 * a test, but not suitable for monitor.
 */
static int cable_test_ntf_stop_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_TEST_NTF_MAX + 1] = {};
	u8 status = ETHTOOL_A_CABLE_TEST_NTF_STATUS_UNSPEC;
	struct cable_test_context *ctctx;
	struct nl_context *nlctx = data;
	DECLARE_ATTR_TB_INFO(tb);
	bool silent;
	int err_ret;
	int ret;

	ctctx = nlctx->cmd_private;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;

	nlctx->devname = get_dev_name(tb[ETHTOOL_A_CABLE_TEST_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (tb[ETHTOOL_A_CABLE_TEST_NTF_STATUS])
		status = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_TEST_NTF_STATUS]);

	switch (status) {
	case ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED:
		printf("Cable test started for device %s.\n",
		       nlctx->devname);
		break;
	case ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED:
		printf("Cable test completed for device %s.\n",
		       nlctx->devname);
		break;
	default:
		break;
	}

	if (tb[ETHTOOL_A_CABLE_TEST_NTF_NEST])
		cable_test_ntf_nest(tb[ETHTOOL_A_CABLE_TEST_NTF_NEST]);

	if (status == ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED) {
		if (ctctx)
			ctctx->breakout = true;
		return MNL_CB_STOP;
	}

	return MNL_CB_OK;
}

/* Wrapper around cable_test_ntf_stop_cb() which does not return STOP,
 * used for monitor
 */
int cable_test_ntf_cb(const struct nlmsghdr *nlhdr, void *data)
{
	int status = cable_test_ntf_stop_cb(nlhdr, data);

	if (status == MNL_CB_STOP)
		status = MNL_CB_OK;

	return status;
}

static int nl_cable_test_results_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);

	if (ghdr->cmd != ETHTOOL_MSG_CABLE_TEST_NTF)
		return MNL_CB_OK;

	return cable_test_ntf_stop_cb(nlhdr, data);
}

/* Receive the broadcasted messages until we get the cable test
 * results
 */
static int nl_cable_test_process_results(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	struct cable_test_context ctctx;
	int err;

	nlctx->is_monitor = true;
	nlsk->port = 0;
	nlsk->seq = 0;

	ctctx.breakout = false;
	nlctx->cmd_private = &ctctx;

	while (!ctctx.breakout) {
		err = nlsock_process_reply(nlsk, nl_cable_test_results_cb,
					   nlctx);
		if (err)
			return err;
	}

	return err;
}

int nl_cable_test(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	uint32_t grpid = nlctx->ethnl_mongrp;
	int ret;

	/* Join the multicast group so we can receive the results in a
	 * race free way.
	 */
	if (!grpid) {
		fprintf(stderr, "multicast group 'monitor' not found\n");
		return -EOPNOTSUPP;
	}

	ret = mnl_socket_setsockopt(nlsk->sk, NETLINK_ADD_MEMBERSHIP,
				    &grpid, sizeof(grpid));
	if (ret < 0)
		return ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_CABLE_TEST_ACT,
				      ETHTOOL_A_CABLE_TEST_HEADER, 0);
	if (ret < 0)
		return ret;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		fprintf(stderr, "Cannot start cable test\n");
	else
		ret = nl_cable_test_process_results(ctx);
	return ret;
}
