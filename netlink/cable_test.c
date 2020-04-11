/*
 * cable_test.c - netlink implementation of cable test command
 *
 * Implementation of ethtool <dev> --cable-test
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

static bool breakout;

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

static int nl_cable_test_ntf_attr(struct nlattr *evattr,
				  struct nl_context *nlctx)
{
	struct cmd_context *ctx =  nlctx->ctx;
	unsigned int cm;
	uint16_t code;
	uint8_t pair;
	int ret;

	switch (mnl_attr_get_type(evattr)) {
	case ETHTOOL_A_CABLE_TEST_NTF_RESULT:
		ret = nl_get_cable_test_result(evattr, &pair, &code);
		if (ret < 0)
			return ret;

		if (ctx->jw) {
			jsonw_start_object(ctx->jw);
			jsonw_string_field(ctx->jw, "pair", nl_pair2txt(pair));
			jsonw_string_field(ctx->jw, "code", nl_code2txt(code));
			jsonw_end_object(ctx->jw);
		} else {
			printf("Pair: %s, result: %s\n", nl_pair2txt(pair),
			       nl_code2txt(code));
		}

		break;

	case ETHTOOL_A_CABLE_TEST_NTF_FAULT_LENGTH:
		ret = nl_get_cable_test_fault_length(evattr, &pair, &cm);
		if (ret < 0)
			return ret;
		if (ctx->jw) {
			jsonw_start_object(ctx->jw);
			jsonw_string_field(ctx->jw, "pair", nl_pair2txt(pair));
			jsonw_float_field(ctx->jw, "length", (float)cm / 100);
			jsonw_end_object(ctx->jw);
		} else {
			printf("Pair: %s, fault length: %0.2fm\n",
			       nl_pair2txt(pair), (float)cm / 100);
		}
		break;
	}
	return 0;
}

static void cable_test_ntf_nest(const struct nlattr *nest,
				struct nl_context *nlctx)
{
	struct nlattr *pos;
	int ret;

	mnl_attr_for_each_nested(pos, nest) {
		ret = nl_cable_test_ntf_attr(pos, nlctx);
		if (ret < 0)
			return;
	}
}

/* Returns MNL_CB_STOP when the test is complete. Used when executing
   a test, but not suitable for monitor. */
static int cable_test_ntf_stop_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_TEST_NTF_MAX + 1] = {};
	u8 status = ETHTOOL_A_CABLE_TEST_NTF_STATUS_UNSPEC;
	struct nl_context *nlctx = data;
	struct cmd_context *ctx =  nlctx->ctx;
	DECLARE_ATTR_TB_INFO(tb);
	bool silent;
	int err_ret;
	int ret;

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
	
	if (!ctx->json) {
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
	}
	if (tb[ETHTOOL_A_CABLE_TEST_NTF_NEST])
		cable_test_ntf_nest(tb[ETHTOOL_A_CABLE_TEST_NTF_NEST], nlctx);

	if (status == ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED) {
		breakout = true;
		return MNL_CB_STOP;
	}

	return MNL_CB_OK;
}

/* Wrapper around cable_test_ntf_stop_cb() which does not return STOP,
 * used for monitor */
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

	if (ghdr->cmd != ETHTOOL_MSG_CABLE_TEST_NTF) {
		return MNL_CB_OK;
	}

	return cable_test_ntf_stop_cb(nlhdr, data);
}

/* Receive the broadcasted messages until we get the cable test
 * results
 */
static int nl_cable_test_process_results(struct cmd_context *ctx)
{
        struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int err;

        nlctx->is_monitor = true;
        nlsk->port = 0;
	nlsk->seq = 0;

	breakout = false;

	while (!breakout) {
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
	else {
		if (ctx->json) {
			ctx->jw =  jsonw_new(stdout);
			jsonw_pretty(ctx->jw, true);
			jsonw_start_array(ctx->jw);
		}

		ret = nl_cable_test_process_results(ctx);

		if (ctx->json) {
			jsonw_end_array(ctx->jw);
			jsonw_destroy(&ctx->jw);
		}
	}

	return ret;
}

static int nl_cable_test_tdr_results_cb(const struct nlmsghdr *nlhdr,
					void *data)
{
	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);

	if (ghdr->cmd != ETHTOOL_MSG_CABLE_TEST_TDR_NTF) {
		return MNL_CB_OK;
	}

	cable_test_tdr_ntf_cb(nlhdr, data);

	return MNL_CB_STOP;
}

/* Receive the broadcasted messages until we get the cable test
 * results
 */
static int nl_cable_test_tdr_process_results(struct cmd_context *ctx)
{
        struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;

        nlctx->is_monitor = true;
        nlsk->port = 0;
	nlsk->seq = 0;

        return nlsock_process_reply(nlsk, nl_cable_test_tdr_results_cb, nlctx);
}

static const struct param_parser tdr_params[] = {
	{
		.arg		= "first",
		.type		= ETHTOOL_A_CABLE_TEST_TDR_FIRST,
		.handler	= nl_parse_direct_u16,
	},
	{
		.arg		= "last",
		.type		= ETHTOOL_A_CABLE_TEST_TDR_LAST,
		.handler	= nl_parse_direct_u16,
	},
	{
		.arg		= "step",
		.type		= ETHTOOL_A_CABLE_TEST_TDR_STEP,
		.handler	= nl_parse_direct_u16,
	},
	{
		.arg		= "pair",
		.type		= ETHTOOL_A_CABLE_TEST_TDR_PAIR,
		.handler	= nl_parse_direct_u8,
	},
	{}
};

int nl_cable_test_tdr(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
        uint32_t grpid = nlctx->ethnl_mongrp;
	int ret;

	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;

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

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
				      ETHTOOL_A_CABLE_TEST_TDR_HEADER, 0);
	if (ret < 0)
		return ret;

	ret = nl_parser(nlctx, tdr_params, NULL, PARSER_GROUP_NONE);
	if (ret < 0)
		return ret;

	ret = nlsock_send_get_request(nlsk, NULL);
	if (ret)
		fprintf(stderr, "Cannot start cable test TDR\n");
	else
		ret = nl_cable_test_tdr_process_results(ctx);
	return ret;
}

static int nl_get_cable_test_tdr_amplitude(const struct nlattr *nest,
					   uint8_t *pair, int16_t *mV)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_AMPLITUDE_MAX+1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	uint16_t mV_unsigned;
	int ret;

	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0 ||
	    !tb[ETHTOOL_A_CABLE_AMPLITUDE_PAIR] ||
	    !tb[ETHTOOL_A_CABLE_AMPLITUDE_mV])
		return -EFAULT;

	*pair = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_AMPLITUDE_PAIR]);
	mV_unsigned = mnl_attr_get_u16(tb[ETHTOOL_A_CABLE_AMPLITUDE_mV]);
	*mV = (int16_t)(mV_unsigned);

	return 0;
}

static int nl_get_cable_test_tdr_pulse(const struct nlattr *nest, int16_t *mV)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_PULSE_MAX+1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	uint16_t mV_unsigned;
	int ret;

	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0 ||
	    !tb[ETHTOOL_A_CABLE_PULSE_mV])
		return -EFAULT;

	mV_unsigned = mnl_attr_get_u16(tb[ETHTOOL_A_CABLE_PULSE_mV]);
	*mV = (int16_t)(mV_unsigned);

	return 0;
}

static int nl_get_cable_test_tdr_step(const struct nlattr *nest,
				      uint16_t *first, uint16_t *last,
				      uint16_t *step)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_STEP_MAX+1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0 ||
	    !tb[ETHTOOL_A_CABLE_STEP_FIRST_DISTANCE] ||
	    !tb[ETHTOOL_A_CABLE_STEP_LAST_DISTANCE] ||
	    !tb[ETHTOOL_A_CABLE_STEP_STEP_DISTANCE])
		return -EFAULT;

	*first = mnl_attr_get_u16(tb[ETHTOOL_A_CABLE_STEP_FIRST_DISTANCE]);
	*last = mnl_attr_get_u16(tb[ETHTOOL_A_CABLE_STEP_LAST_DISTANCE]);
	*step = mnl_attr_get_u16(tb[ETHTOOL_A_CABLE_STEP_STEP_DISTANCE]);

	return 0;
}

static int nl_cable_test_tdr_ntf_attr(struct nlattr *evattr,
				      struct nl_context *nlctx)
{
	struct cmd_context *ctx =  nlctx->ctx;
	uint16_t first, last, step;
	uint8_t pair;
	int16_t mV;
	int ret;

	switch (mnl_attr_get_type(evattr)) {
	case ETHTOOL_A_CABLE_TEST_TDR_NTF_AMPLITUDE:
		ret = nl_get_cable_test_tdr_amplitude(
			evattr, &pair, &mV);
		if (ret < 0)
			return ret;

		if (ctx->jw) {
			jsonw_start_object(ctx->jw);
			jsonw_string_field(ctx->jw, "pair", nl_pair2txt(pair));
			jsonw_int_field(ctx->jw, "amplitude", mV);
			jsonw_end_object(ctx->jw);
		} else {
			printf("Pair: %s, amplitude %4d\n",
			       nl_pair2txt(pair), mV);
		}

		break;

	case ETHTOOL_A_CABLE_TEST_TDR_NTF_PULSE:
		ret = nl_get_cable_test_tdr_pulse(evattr, &mV);
		if (ret < 0)
			return ret;

		if (ctx->jw) {
			jsonw_start_object(ctx->jw);
			jsonw_uint_field(ctx->jw, "pulse", mV);
			jsonw_end_object(ctx->jw);
		} else {
			printf("TDR pulse %dmV\n", mV);
		}

		break;
	case ETHTOOL_A_CABLE_TEST_TDR_NTF_STEP:
		ret = nl_get_cable_test_tdr_step(evattr, &first, &last, &step);
		if (ret < 0)
			return ret;

		if (ctx->jw) {
			jsonw_start_object(ctx->jw);
			jsonw_uint_field(ctx->jw, "first", first);
			jsonw_uint_field(ctx->jw, "last", last);
			jsonw_uint_field(ctx->jw, "step", step);
			jsonw_end_object(ctx->jw);
		} else {
			printf("Step configuration %d-%d meters in %dm steps\n",
			       first, last, step);
		}
		break;
	}
	return 0;
}

static void cable_test_tdr_ntf_nest(const struct nlattr *nest,
				    struct nl_context *nlctx)
{
	struct nlattr *pos;
	int ret;

	mnl_attr_for_each_nested(pos, nest) {
		ret = nl_cable_test_tdr_ntf_attr(pos, nlctx);
		if (ret < 0)
			return;
	}
}

int cable_test_tdr_ntf_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX + 1] = {};
	struct nl_context *nlctx = data;
	struct cmd_context *ctx =  nlctx->ctx;

	DECLARE_ATTR_TB_INFO(tb);
	bool silent;
	int err_ret;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;

	nlctx->devname = get_dev_name(tb[ETHTOOL_A_CABLE_TEST_TDR_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (ctx->json) {
		ctx->jw =  jsonw_new(stdout);
		jsonw_pretty(ctx->jw, true);
		jsonw_start_array(ctx->jw);
	} else {
		printf("Cable test TDR results for device %s.\n",
		       nlctx->devname);
	}

	cable_test_tdr_ntf_nest(tb[ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST], nlctx);

	if (ctx->json) {
		jsonw_end_array(ctx->jw);
		jsonw_destroy(&ctx->jw);
	}

	return MNL_CB_OK;
}
