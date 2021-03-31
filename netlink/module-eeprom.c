/*
 * module-eeprom.c - netlink implementation of module eeprom get command
 *
 * ethtool -m <dev>
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "../sff-common.h"
#include "../qsfp.h"
#include "../qsfp-dd.h"
#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

#define GETMODULE_I2C_ADDRESS_LOW	0x50
#define GETMODULE_I2C_ADDRESS_HIGH	0x51

static struct
{
	u8 dump_hex;
	u8 dump_raw;
	u32 offset;
	u32 length;
	u32 page;
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
		.handler_data	= &getmodule_cmd_params.page,
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

/* List utilities */

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

static void list_add(struct list_head *new, struct list_head *head)
{
	head->next->prev = new;
	new->next = head->next;
	new->prev = head;
	head->next = new;
}

static void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = NULL;
	entry->prev = NULL;
}

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

struct page_entry {
	struct list_head link;
	struct ethtool_module_eeprom *page;
};

static struct list_head page_list = LIST_HEAD_INIT(page_list);

static int cache_add(struct ethtool_module_eeprom *page)
{
	struct page_entry *entry = malloc(sizeof(*entry));

	if (!entry || !page)
		return -1;
	entry->page = page;

	list_add(&entry->link, &page_list);
	return 0;
}

static void page_free(struct ethtool_module_eeprom *page)
{
	free(page->data);
	free(page);
}

static void cache_delete(uint32_t page, uint32_t bank)
{
	struct ethtool_module_eeprom *entry;
	struct list_head *head, *next;

	list_for_each_safe(head, next, &page_list) {
		entry = ((struct page_entry *)head)->page;
		if (entry->page == page &&
		    entry->bank == bank) {
			list_del(head);
			free(head);
			page_free(entry);
			break;
		}
	}
}

static void cache_free(void)
{
	struct ethtool_module_eeprom *entry;
	struct list_head *head, *next;

	list_for_each_safe(head, next, &page_list) {
		entry = ((struct page_entry *)head)->page;
		list_del(head);
		free(head);
		page_free(entry);
	}
}

/* TODO: improve comment or get rid of it
 *
 * Concatenate an arbitrary number of data arrays from provided page pointers
 */
static u8 *page_concat_data(int arg_num, ...)
{
	struct ethtool_module_eeprom *page;
	va_list ap, ap_copy;
	u32 concat_size = 0;
	u32 offset = 0;
	int i = 0;
	u8 *array;

	va_start(ap, arg_num);
	va_copy(ap_copy, ap);
	while (i < arg_num) {
		page = va_arg(ap, struct ethtool_module_eeprom *);
		concat_size += page->length;
		i++;
	}

	i = 0;
	array = calloc(1, concat_size);
	while (i < arg_num) {
		page = va_arg(ap_copy, struct ethtool_module_eeprom *);
		memcpy(array + offset, page->data, page->length);
		offset += page->length;
		i++;
	}

	va_end(ap);
	va_end(ap_copy);
	return array;
}


/* Join pages in a primitive way without overlap checks
 * TODO: make this less primitive
 */
static struct ethtool_module_eeprom *page_join(struct ethtool_module_eeprom *page_a,
					       struct ethtool_module_eeprom *page_b)
{
	struct ethtool_module_eeprom *tmp;
	u32 total_length;

	if (!page_a || !page_b ||
	    page_a->page != page_b->page ||
	    page_a->bank != page_b->bank ||
	    page_a->i2c_address != page_b->i2c_address)
		return NULL;

	total_length = page_a->length + page_b->length;
	tmp = calloc(1, sizeof(*tmp));
	tmp->data = calloc(1, total_length);
	tmp->page = page_a->page;
	tmp->bank = page_a->bank;
	tmp->length = total_length;
	tmp->i2c_address = page_a->i2c_address;

	if (page_a->offset < page_b->offset) {
		memcpy(tmp->data, page_a->data, page_a->length);
		memcpy(tmp->data + page_a->length, page_b->data, page_b->length);
		tmp->offset = page_a->offset;
	} else {
		memcpy(tmp->data, page_b->data, page_b->length);
		memcpy(tmp->data + page_b->length, page_a->data, page_a->length);
		tmp->offset = page_b->offset;
	}

	return tmp;
}

static struct ethtool_module_eeprom *cache_get(u32 page, u32 bank)
{
	struct ethtool_module_eeprom *entry;
	struct list_head *head, *next;

	list_for_each_safe(head, next, &page_list) {
		entry = ((struct page_entry *)head)->page;
		if (entry->page == page &&
		    entry->bank == bank)
			return entry;
	}

	return NULL;
}

static int getmodule_page_fetch_reply_cb(const struct nlmsghdr *nlhdr,
					 void *data)
{
	const struct nlattr *tb[ETHTOOL_A_MODULE_EEPROM_DATA + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct ethtool_module_eeprom *request;
	struct ethtool_module_eeprom *page;
	struct ethtool_module_eeprom *response;
	struct ethtool_module_eeprom *existing_page;
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
		return ENOMEM;

	request = (struct ethtool_module_eeprom *)data;
	response->offset = request->offset;
	response->page = request->page;
	response->bank = request->bank;
	response->i2c_address = request->i2c_address;
	response->length = mnl_attr_get_payload_len(tb[ETHTOOL_A_MODULE_EEPROM_DATA]);
	eeprom_data = mnl_attr_get_payload(tb[ETHTOOL_A_MODULE_EEPROM_DATA]);

	response->data = malloc(response->length);
	memcpy(response->data, eeprom_data, response->length);

	if (!request->page) {
		existing_page = cache_get(request->page, request->bank);
		if (existing_page) {
			page = page_join(existing_page, response);
			page_free(response);
			cache_delete(existing_page->page, existing_page->bank);
			return cache_add(page);
		}
	}

	return cache_add(response);
}

static int page_fetch(struct nl_context *nlctx, const struct ethtool_module_eeprom *request)
{
	struct nl_socket *nlsock = nlctx->ethnl_socket;
	struct nl_msg_buff *msg = &nlsock->msgbuff;
	struct ethtool_module_eeprom *page;
	int ret;

	if (!request)
		return EINVAL;

	/* Satisfy request right away, if region is already in cache */
	page = cache_get(request->page, request->bank);
	if (page &&
	    page->i2c_address == request->i2c_address && 
	    page->offset <= request->offset &&
	    page->offset + page->length >= request->offset + request->length) {
		return 0;
	}

	ret = nlsock_prep_get_request(nlsock, ETHTOOL_MSG_MODULE_EEPROM_GET,
				      ETHTOOL_A_MODULE_EEPROM_HEADER, 0);
	if (ret < 0)
		return ret;

	if (ethnla_put_u32(msg, ETHTOOL_A_MODULE_EEPROM_LENGTH, request->length) ||
	    ethnla_put_u32(msg, ETHTOOL_A_MODULE_EEPROM_OFFSET, request->offset) ||
	    ethnla_put_u8(msg, ETHTOOL_A_MODULE_EEPROM_PAGE, request->page) ||
	    ethnla_put_u8(msg, ETHTOOL_A_MODULE_EEPROM_BANK, request->bank) ||
	    ethnla_put_u8(msg, ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS, request->i2c_address))
		return EMSGSIZE;

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
	struct ethtool_module_eeprom *page_zero = cache_get(0, 0);
	u8 id = page_zero->data[SFF8636_ID_OFFSET];
	u8 flat_mem = page_zero->data[2] & 0x80;

	switch (id) {
	case SFF8024_ID_SOLDERED_MODULE:
	case SFF8024_ID_SFP:
		return (!which->bank && which->page <= 1);
	case SFF8024_ID_QSFP:
	case SFF8024_ID_QSFP28:
	case SFF8024_ID_QSFP_PLUS:
		return (!which->bank && which->page <= 3);
	case SFF8024_ID_QSFP_DD:
	case SFF8024_ID_DSFP:
		return (which->page > 0 && !flat_mem);
	default:
		return true;
	}
}

static int decoder_prefetch(struct nl_context *nlctx)
{
	struct ethtool_module_eeprom *page_zero_lower = cache_get(0, 0);
	struct ethtool_module_eeprom request = {0};
	u8 module_id = page_zero_lower->data[0];
	int err = 0;

	request.i2c_address = GETMODULE_I2C_ADDRESS_LOW;
	request.offset = 128;
	request.length = 128;
	err = page_fetch(nlctx, &request);
	if (err)
		return err;

	switch (module_id) {
	case SFF8024_ID_QSFP:
	case SFF8024_ID_QSFP28:
	case SFF8024_ID_QSFP_PLUS:
		memset(&request, 0, sizeof(request));
		request.i2c_address = GETMODULE_I2C_ADDRESS_LOW;
		request.offset = 128;
		request.length = 128;
		request.page = 3;
		err = page_fetch(nlctx, &request);
		break;
	case SFF8024_ID_QSFP_DD:
	case SFF8024_ID_DSFP:
		memset(&request, 0, sizeof(request));
		request.i2c_address = GETMODULE_I2C_ADDRESS_LOW;
		request.offset = 128;
		request.length = 128;
		request.page = 1;
		err = page_fetch(nlctx, &request);
		break;
	default:
		memset(&request, 0, sizeof(request));
		request.i2c_address = GETMODULE_I2C_ADDRESS_LOW;
		request.length = 256;
		err = page_fetch(nlctx, &request);
		break;
	}

	return err;
}

static void decoder_print(void)
{
	struct ethtool_module_eeprom *page_zero = cache_get(0, 0);
	struct ethtool_module_eeprom *page_one = cache_get(1, 0);
	u8 module_id = page_zero->data[SFF8636_ID_OFFSET];

	switch (module_id) {
	case SFF8024_ID_SFP:
		sff8079_show_all(page_zero->data);
		break;
	case SFF8024_ID_QSFP:
	case SFF8024_ID_QSFP28:
	case SFF8024_ID_QSFP_PLUS:
		sff8636_show_all(page_zero->data, page_zero->length);
		break;
	case SFF8024_ID_QSFP_DD:
		qsfp_dd_show_all(page_zero->data);
		break;
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
	u8 *eeprom_data;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_MODULE_EEPROM_GET, false))
		return EOPNOTSUPP;

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

	request.i2c_address = GETMODULE_I2C_ADDRESS_LOW;
	request.length = 128;
	ret = page_fetch(nlctx, &request);
	if (ret)
		goto cleanup;

#ifdef ETHTOOL_ENABLE_PRETTY_DUMP
	if (getmodule_cmd_params.bank ||
	    getmodule_cmd_params.page ||
	    getmodule_cmd_params.offset || getmodule_cmd_params.length)
#endif
		getmodule_cmd_params.dump_hex = true;

	request.offset = getmodule_cmd_params.offset;
	request.length = getmodule_cmd_params.length ?: 128;
	request.page = getmodule_cmd_params.page;
	request.bank = getmodule_cmd_params.bank;
	request.i2c_address = getmodule_cmd_params.i2c_address ?: GETMODULE_I2C_ADDRESS_LOW;

	if (getmodule_cmd_params.dump_hex || getmodule_cmd_params.dump_raw) {
		if (!page_available(&request))
			goto err_invalid;

		ret = page_fetch(nlctx, &request);
		if (ret < 0)
			return ret;
		reply_page = cache_get(request.page, request.bank);
		if (!reply_page)
			goto err_invalid;

		eeprom_data = reply_page->data + request.offset - reply_page->offset;
		if (getmodule_cmd_params.dump_raw)
			fwrite(eeprom_data, 1, request.length, stdout);
		else
			dump_hex(stdout, eeprom_data, request.length, request.offset);
	} else {
		ret = decoder_prefetch(nlctx);
		if (ret)
			goto cleanup;
		decoder_print();
	}

err_invalid:
	ret = EINVAL;
cleanup:
	cache_free();
	return ret;
}

