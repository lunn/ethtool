/*
 * module-eeprom.c - netlink implementation of module eeprom get command
 *
 * ethtool -m <dev>
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../sff-common.h"
#include "../qsfp.h"
#include "../qsfp-dd.h"
#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

#define ETH_I2C_ADDRESS_LOW	0x50
#define ETH_I2C_ADDRESS_HIGH	0x51
#define ETH_I2C_MAX_ADDRESS	0x7F

static struct
{
	u8 dump_hex;
	u8 dump_raw;
	u32 offset;
	u32 length;
	u32 pageno;
	u32 bank;
	u32 i2c_address;
} getmodule_cmd_params;

static int getmodule_parse_u32(struct nl_context *nlctx,
			       uint16_t type __maybe_unused,
			       const void *data,
			       struct nl_msg_buff *msgbuff __maybe_unused,
			       void *dest __maybe_unused)
{
	const char *arg = *nlctx->argp;
	uint32_t val;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	ret = parse_u32(arg, &val);
	if (ret < 0) {
		fprintf(stderr, "ethtool (%s): invalid value '%s' for parameter '%s'\n",
			nlctx->cmd, arg, nlctx->param);
		return ret;
	}

	if (data)
		*(uint32_t *)data = val;
	return 0;
}

static const struct param_parser getmodule_params[] = {
	{
		.arg		= "hex",
		.handler	= nl_parse_u8bool,
		.dest_offset	= 0,
		.min_argc	= 1,
	},
	{
		.arg		= "raw",
		.handler	= nl_parse_u8bool,
		.dest_offset	= sizeof(u8),
		.min_argc	= 1,
	},
	{
		.arg		= "offset",
		.handler	= getmodule_parse_u32,
		.handler_data	= &getmodule_cmd_params.offset,
		.min_argc	= 1,
	},
	{
		.arg		= "length",
		.handler	= getmodule_parse_u32,
		.handler_data	= &getmodule_cmd_params.length,
		.min_argc	= 1,
	},
	{
		.arg		= "page",
		.handler	= getmodule_parse_u32,
		.handler_data	= &getmodule_cmd_params.pageno,
		.min_argc	= 1,
	},
	{
		.arg		= "bank",
		.handler	= getmodule_parse_u32,
		.handler_data	= &getmodule_cmd_params.bank,
		.min_argc	= 1,
	},
	{
		.arg		= "i2c",
		.handler	= getmodule_parse_u32,
		.handler_data	= &getmodule_cmd_params.i2c_address,
		.min_argc	= 1,
	},
	{}
};

static struct ethtool_module_eeprom *page_join(struct ethtool_module_eeprom *page_a,
					       struct ethtool_module_eeprom *page_b)
{
	struct ethtool_module_eeprom *joined_page;
	u32 total_length;

	if (!page_a || !page_b ||
	    page_a->pageno != page_b->pageno ||
	    page_a->bank != page_b->bank ||
	    page_a->i2c_address != page_b->i2c_address)
		return NULL;

	total_length = page_a->length + page_b->length;
	joined_page = calloc(1, sizeof(*joined_page));
	joined_page->data = calloc(1, total_length);
	joined_page->pageno = page_a->pageno;
	joined_page->bank = page_a->bank;
	joined_page->length = total_length;
	joined_page->i2c_address = page_a->i2c_address;

	if (page_a->offset < page_b->offset) {
		memcpy(joined_page->data, page_a->data, page_a->length);
		memcpy(joined_page->data + page_a->length, page_b->data, page_b->length);
		joined_page->offset = page_a->offset;
	} else {
		memcpy(joined_page->data, page_b->data, page_b->length);
		memcpy(joined_page->data + page_b->length, page_a->data, page_a->length);
		joined_page->offset = page_b->offset;
	}

	return joined_page;
}

static int getmodule_page_fetch_reply_cb(const struct nlmsghdr *nlhdr,
					 void *data)
{
	const struct nlattr *tb[ETHTOOL_A_MODULE_EEPROM_DATA + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct ethtool_module_eeprom *lower_page;
	struct ethtool_module_eeprom *response;
	struct ethtool_module_eeprom *request;
	struct ethtool_module_eeprom *joined;
	u8 *eeprom_data;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	if (!tb[ETHTOOL_A_MODULE_EEPROM_DATA]) {
		fprintf(stderr, "Malformed netlink message (getmodule)\n");
		return MNL_CB_ERROR;
	}

	response = calloc(1, sizeof(*response));
	if (!response)
		return -ENOMEM;

	request = (struct ethtool_module_eeprom *)data;
	response->offset = request->offset;
	response->pageno = request->pageno;
	response->bank = request->bank;
	response->i2c_address = request->i2c_address;
	response->length = mnl_attr_get_payload_len(tb[ETHTOOL_A_MODULE_EEPROM_DATA]);
	eeprom_data = mnl_attr_get_payload(tb[ETHTOOL_A_MODULE_EEPROM_DATA]);

	response->data = malloc(response->length);
	memcpy(response->data, eeprom_data, response->length);

	if (!request->pageno) {
		lower_page = sff_cache_get(NULL, request->pageno, request->bank,
					   response->i2c_address);
		if (lower_page) {
			joined = page_join(lower_page, response);
			sff_page_free(response);
			sff_cache_delete(lower_page);
			return sff_cache_add(joined);
		}
	}

	return sff_cache_add(response);
}

int nl_page_fetch(struct nl_context *nlctx,
		  const struct ethtool_module_eeprom *request)
{
	struct nl_socket *nlsock = nlctx->ethnl_socket;
	struct nl_msg_buff *msg = &nlsock->msgbuff;
	struct ethtool_module_eeprom *page;
	int ret;

	if (!request || request->i2c_address > ETH_I2C_MAX_ADDRESS)
		return -EINVAL;

	/* Satisfy request right away, if region is already in cache */
	page = sff_cache_get(NULL, request->pageno, request->bank,
			     request->i2c_address);
	if (page && page->offset <= request->offset &&
	    page->offset + page->length >= request->offset + request->length) {
		return 0;
	}

	ret = nlsock_prep_get_request(nlsock, ETHTOOL_MSG_MODULE_EEPROM_GET,
				      ETHTOOL_A_MODULE_EEPROM_HEADER, 0);
	if (ret < 0)
		return ret;

	if (ethnla_put_u32(msg, ETHTOOL_A_MODULE_EEPROM_LENGTH, request->length) ||
	    ethnla_put_u32(msg, ETHTOOL_A_MODULE_EEPROM_OFFSET, request->offset) ||
	    ethnla_put_u8(msg, ETHTOOL_A_MODULE_EEPROM_PAGE, request->pageno) ||
	    ethnla_put_u8(msg, ETHTOOL_A_MODULE_EEPROM_BANK, request->bank) ||
	    ethnla_put_u8(msg, ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS, request->i2c_address))
		return -EMSGSIZE;

	ret = nlsock_sendmsg(nlsock, NULL);
	if (ret < 0)
		return ret;
	ret = nlsock_process_reply(nlsock, getmodule_page_fetch_reply_cb, (void *)request);
	if (ret < 0)
		return ret;

	return nlsock_process_reply(nlsock, nomsg_reply_cb, NULL);
}

static bool page_available(struct ethtool_module_eeprom *which)
{
	struct ethtool_module_eeprom *page_zero = sff_cache_get(
		NULL, 0, 0, ETH_I2C_ADDRESS_LOW);
	u8 id = page_zero->data[SFF8636_ID_OFFSET];
	u8 flat_mem = page_zero->data[2] & 0x80;

	switch (id) {
	case SFF8024_ID_SOLDERED_MODULE:
	case SFF8024_ID_SFP:
		return (!which->bank && which->pageno <= 1);
	case SFF8024_ID_QSFP:
	case SFF8024_ID_QSFP28:
	case SFF8024_ID_QSFP_PLUS:
		return (!which->bank && which->pageno <= 3);
	case SFF8024_ID_QSFP_DD:
	case SFF8024_ID_DSFP:
		return (which->pageno > 0 && !flat_mem);
	default:
		return true;
	}
}

static int decoder_prefetch(struct nl_context *nlctx)
{
	struct ethtool_module_eeprom *page_zero_lower = sff_cache_get(
		NULL, 0, 0, ETH_I2C_ADDRESS_LOW);
	struct ethtool_module_eeprom request = {0};
	u8 module_id = page_zero_lower->data[0];
	int err = 0;

	/* Fetch rest of page 00 */
	request.i2c_address = ETH_I2C_ADDRESS_LOW;
	request.offset = 128;
	request.length = 128;
	err = nl_page_fetch(nlctx, &request);
	if (err)
		return err;

	switch (module_id) {
	case SFF8024_ID_QSFP:
	case SFF8024_ID_QSFP28:
	case SFF8024_ID_QSFP_PLUS:
		memset(&request, 0, sizeof(request));
		request.i2c_address = ETH_I2C_ADDRESS_LOW;
		request.offset = 128;
		request.length = 128;
		request.pageno = 3;
		break;
	case SFF8024_ID_QSFP_DD:
	case SFF8024_ID_DSFP:
		memset(&request, 0, sizeof(request));
		request.i2c_address = ETH_I2C_ADDRESS_LOW;
		request.offset = 128;
		request.length = 128;
		request.pageno = 1;
		break;
	}

	return nl_page_fetch(nlctx, &request);
}

static void decoder_print(struct nl_context *nlctx)
{
	struct ethtool_module_eeprom *page_three = sff_cache_get(
		NULL, 3, 0, ETH_I2C_ADDRESS_LOW);
	struct ethtool_module_eeprom *page_zero = sff_cache_get(
		NULL, 0, 0, ETH_I2C_ADDRESS_LOW);
	struct ethtool_module_eeprom *page_one = sff_cache_get(
		NULL, 1, 0, ETH_I2C_ADDRESS_LOW);
	u8 module_id = page_zero->data[SFF8636_ID_OFFSET];

	switch (module_id) {
	case SFF8024_ID_SOLDERED_MODULE:
	case SFF8024_ID_SFP:
		sff8079_show_all(nlctx->ctx);
		break;
	case SFF8024_ID_QSFP:
	case SFF8024_ID_QSFP28:
	case SFF8024_ID_QSFP_PLUS:
		sff8636_show_all_paged(page_zero, page_three);
		break;
	case SFF8024_ID_QSFP_DD:
	case SFF8024_ID_DSFP:
		cmis4_show_all(page_zero, page_one);
		break;
	default:
		dump_hex(stdout, page_zero->data, page_zero->length, page_zero->offset);
		break;
	}
}

int nl_getmodule(struct cmd_context *ctx)
{
	struct ethtool_module_eeprom request = {0};
	struct ethtool_module_eeprom *reply_page;
	struct nl_context *nlctx = ctx->nlctx;
	u32 dump_length;
	u8 *eeprom_data;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_MODULE_EEPROM_GET, false))
		return -EOPNOTSUPP;

	nlctx->cmd = "-m";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	ret = nl_parser(nlctx, getmodule_params, &getmodule_cmd_params, PARSER_GROUP_NONE, NULL);
	if (ret < 0)
		return 1;

	if (getmodule_cmd_params.dump_hex && getmodule_cmd_params.dump_raw) {
		fprintf(stderr, "Hex and raw dump cannot be specified together\n");
		return 1;
	}

	request.i2c_address = ETH_I2C_ADDRESS_LOW;
	request.length = 128;
	ret = nl_page_fetch(nlctx, &request);
	if (ret)
		goto cleanup;

#ifdef ETHTOOL_ENABLE_PRETTY_DUMP
	if (getmodule_cmd_params.bank ||
	    getmodule_cmd_params.pageno ||
	    getmodule_cmd_params.offset || getmodule_cmd_params.length)
#endif
		getmodule_cmd_params.dump_hex = true;

	request.offset = getmodule_cmd_params.offset;
	request.length = getmodule_cmd_params.length ?: 128;
	request.pageno = getmodule_cmd_params.pageno;
	request.bank = getmodule_cmd_params.bank;
	request.i2c_address = getmodule_cmd_params.i2c_address ?: ETH_I2C_ADDRESS_LOW;

	if (getmodule_cmd_params.dump_hex || getmodule_cmd_params.dump_raw) {
		if (!page_available(&request))
			goto err_invalid;

		ret = nl_page_fetch(nlctx, &request);
		if (ret < 0)
			return ret;
		reply_page = sff_cache_get(NULL, request.pageno, request.bank,
					   request.i2c_address);
		if (!reply_page)
			goto err_invalid;

		eeprom_data = reply_page->data + (request.offset - reply_page->offset);
		dump_length = reply_page->length < request.length ? reply_page->length : request.length;
		if (getmodule_cmd_params.dump_raw)
			fwrite(eeprom_data, 1, request.length, stdout);
		else
			dump_hex(stdout, eeprom_data, dump_length, request.offset);
	} else {
		ret = decoder_prefetch(nlctx);
		if (ret)
			goto cleanup;
		decoder_print(nlctx);
	}

err_invalid:
	ret = -EINVAL;
cleanup:
	sff_cache_free();
	return ret;
}

