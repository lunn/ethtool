/*
 * parser.c - netlink command line parser
 *
 * Implementation of command line parser used by netlink code.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

static void parser_err_unknown_param(struct nl_context *nlctx)
{
	fprintf(stderr, "ethtool (%s): unknown parameter '%s'\n", nlctx->cmd,
		nlctx->param);
}

static void parser_err_dup_param(struct nl_context *nlctx)
{
	fprintf(stderr, "ethtool (%s): duplicate parameter '%s'\n", nlctx->cmd,
		nlctx->param);
}

static void parser_err_min_argc(struct nl_context *nlctx, unsigned int min_argc)
{
	if (min_argc == 1)
		fprintf(stderr, "ethtool (%s): no value for parameter '%s'\n",
			nlctx->cmd, nlctx->param);
	else
		fprintf(stderr,
			"ethtool (%s): parameter '%s' requires %u words\n",
			nlctx->cmd, nlctx->param, min_argc);
}

static void parser_err_invalid_value(struct nl_context *nlctx, const char *val)
{
	fprintf(stderr, "ethtool (%s): invalid value '%s' for parameter '%s'\n",
		nlctx->cmd, val, nlctx->param);
}

static bool __prefix_0x(const char *p)
{
	return p[0] == '0' && (p[1] == 'x' || p[1] == 'X');
}

static int __parse_u32(const char *arg, uint32_t *result, uint32_t min,
		       uint32_t max, int base)
{
	unsigned long long val;
	char *endptr;

	if (!arg || !arg[0])
		return -EINVAL;
	val = strtoul(arg, &endptr, base);
	if (*endptr || val < min || val > max)
		return -EINVAL;

	*result = (uint32_t)val;
	return 0;
}

static int parse_u32d(const char *arg, uint32_t *result)
{
	return __parse_u32(arg, result, 0, 0xffffffff, 10);
}

static int parse_x32(const char *arg, uint32_t *result)
{
	return __parse_u32(arg, result, 0, 0xffffffff, 16);
}

int parse_u32(const char *arg, uint32_t *result)
{
	if (!arg)
		return -EINVAL;
	if (__prefix_0x(arg))
		return parse_x32(arg + 2, result);
	else
		return parse_u32d(arg, result);
}

static int parse_u8(const char *arg, uint8_t *result)
{
	uint32_t val;
	int ret = parse_u32(arg, &val);

	if (ret < 0)
		return ret;
	if (val > UINT8_MAX)
		return -EINVAL;

	*result = (uint8_t)val;
	return 0;
}

static int lookup_u32(const char *arg, uint32_t *result,
		      const struct lookup_entry_u32 *tbl)
{
	if (!arg)
		return -EINVAL;
	while (tbl->arg) {
		if (!strcmp(tbl->arg, arg)) {
			*result = tbl->val;
			return 0;
		}
		tbl++;
	}

	return -EINVAL;
}

static int lookup_u8(const char *arg, uint8_t *result,
		     const struct lookup_entry_u8 *tbl)
{
	if (!arg)
		return -EINVAL;
	while (tbl->arg) {
		if (!strcmp(tbl->arg, arg)) {
			*result = tbl->val;
			return 0;
		}
		tbl++;
	}

	return -EINVAL;
}

/* Parser handler for a flag. Expects a name (with no additional argument),
 * generates NLA_FLAG or sets a bool (if the name was present).
 */
int nl_parse_flag(struct nl_context *nlctx, uint16_t type, const void *data,
		  struct nl_msg_buff *msgbuff, void *dest)
{
	if (dest)
		*(bool *)dest = true;
	return (type && ethnla_put_flag(msgbuff, type, true)) ? -EMSGSIZE : 0;
}

/* Parser handler for null terminated string. Expects a string argument,
 * generates NLA_NUL_STRING or fills const char *
 */
int nl_parse_string(struct nl_context *nlctx, uint16_t type, const void *data,
		    struct nl_msg_buff *msgbuff, void *dest)
{
	const char *arg = *nlctx->argp;

	nlctx->argp++;
	nlctx->argc--;

	if (dest)
		*(const char **)dest = arg;
	return (type && ethnla_put_strz(msgbuff, type, arg)) ? -EMSGSIZE : 0;
}

/* Parser handler for unsigned 32-bit integer. Expects a numeric argument
 * (may use 0x prefix), generates NLA_U32 or fills an uint32_t.
 */
int nl_parse_direct_u32(struct nl_context *nlctx, uint16_t type,
			const void *data, struct nl_msg_buff *msgbuff,
			void *dest)
{
	const char *arg = *nlctx->argp;
	uint32_t val;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	ret = parse_u32(arg, &val);
	if (ret < 0) {
		parser_err_invalid_value(nlctx, arg);
		return ret;
	}

	if (dest)
		*(uint32_t *)dest = val;
	return (type && ethnla_put_u32(msgbuff, type, val)) ? -EMSGSIZE : 0;
}

/* Parser handler for unsigned 32-bit integer. Expects a numeric argument
 * (may use 0x prefix), generates NLA_U32 or fills an uint32_t.
 */
int nl_parse_direct_u8(struct nl_context *nlctx, uint16_t type,
		       const void *data, struct nl_msg_buff *msgbuff,
		       void *dest)
{
	const char *arg = *nlctx->argp;
	uint8_t val;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	ret = parse_u8(arg, &val);
	if (ret < 0) {
		parser_err_invalid_value(nlctx, arg);
		return ret;
	}

	if (dest)
		*(uint8_t *)dest = val;
	return (type && ethnla_put_u8(msgbuff, type, val)) ? -EMSGSIZE : 0;
}

/* Parser handler for (tri-state) bool. Expects "name on|off", generates
 * NLA_U8 which is 1 for "on" and 0 for "off".
 */
int nl_parse_u8bool(struct nl_context *nlctx, uint16_t type, const void *data,
		    struct nl_msg_buff *msgbuff, void *dest)
{
	const char *arg = *nlctx->argp;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	if (!strcmp(arg, "on")) {
		if (dest)
			*(uint8_t *)dest = 1;
		ret = type ? ethnla_put_u8(msgbuff, type, 1) : 0;
	} else if (!strcmp(arg, "off")) {
		if (dest)
			*(uint8_t *)dest = 0;
		ret = type ? ethnla_put_u8(msgbuff, type, 0) : 0;
	} else {
		parser_err_invalid_value(nlctx, arg);
		return -EINVAL;
	}

	return ret ? -EMSGSIZE : 0;
}

/* Parser handler for 32-bit lookup value. Expects a string argument, looks it
 * up in a table, generates NLA_U32 or fills uint32_t variable. The @data
 * parameter is a null terminated array of struct lookup_entry_u32.
 */
int nl_parse_lookup_u32(struct nl_context *nlctx, uint16_t type,
			const void *data, struct nl_msg_buff *msgbuff,
			void *dest)
{
	const char *arg = *nlctx->argp;
	uint32_t val;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	ret = lookup_u32(arg, &val, data);
	if (ret < 0) {
		parser_err_invalid_value(nlctx, arg);
		return ret;
	}

	if (dest)
		*(uint32_t *)dest = val;
	return (type && ethnla_put_u32(msgbuff, type, val)) ? -EMSGSIZE : 0;
}

/* Parser handler for 8-bit lookup value. Expects a string argument, looks it
 * up in a table, generates NLA_U8 or fills uint8_t variable. The @data
 * parameter is a null terminated array of struct lookup_entry_u8.
 */
int nl_parse_lookup_u8(struct nl_context *nlctx, uint16_t type,
		       const void *data, struct nl_msg_buff *msgbuff,
		       void *dest)
{
	const char *arg = *nlctx->argp;
	uint8_t val;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	ret = lookup_u8(arg, &val, data);
	if (ret < 0) {
		parser_err_invalid_value(nlctx, arg);
		return ret;
	}

	if (dest)
		*(uint8_t *)dest = val;
	return (type && ethnla_put_u8(msgbuff, type, val)) ? -EMSGSIZE : 0;
}

static bool __is_hex(char c)
{
	if (isdigit(c))
		return true;
	else
		return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static unsigned int __hex_val(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 0xa;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 0xa;
	return 0;
}

static bool __bytestr_delim(const char *p, char delim)
{
	return !*p || (delim ? (*p == delim) : !__is_hex(*p));
}

/* Parser handler for generic byte string in MAC-like format. Expects string
 * argument in the "[[:xdigit:]]{2}(:[[:xdigit:]]{2})*" format, generates
 * NLA_BINARY or fills a struct byte_str_value (if @dest is not null and the
 * handler succeeds, caller is responsible for freeing the value). The @data
 * parameter points to struct byte_str_parser_data.
 */
int nl_parse_byte_str(struct nl_context *nlctx, uint16_t type, const void *data,
		      struct nl_msg_buff *msgbuff, void *dest)
{
	const struct byte_str_parser_data *pdata = data;
	struct byte_str_value *dest_value = dest;
	const char *arg = *nlctx->argp;
	uint8_t *val = NULL;
	unsigned int len, i;
	const char *p;
	int ret;

	nlctx->argp++;
	nlctx->argc--;

	len = 0;
	p = arg;
	if (!*p)
		goto err;
	while (true) {
		len++;
		if (!__bytestr_delim(p, pdata->delim))
			p++;
		if (!__bytestr_delim(p, pdata->delim))
			p++;
		if (!__bytestr_delim(p, pdata->delim))
			goto err;
		if (!*p)
			break;
		p++;
		if (*p && __bytestr_delim(p, pdata->delim))
			goto err;
	}
	if (len < pdata->min_len || (pdata->max_len && len > pdata->max_len))
		goto err;
	val = malloc(len);
	if (!val)
		return -ENOMEM;

	p = arg;
	for (i = 0; i < len; i++) {
		uint8_t byte = 0;

		if (!__is_hex(*p))
			goto err;
		while (__is_hex(*p))
			byte = 16 * byte + __hex_val(*p++);
		if (!__bytestr_delim(p, pdata->delim))
			goto err;
		val[i] = byte;
		if (*p)
			p++;
	}
	ret = type ? ethnla_put(msgbuff, type, len, val) : 0;
	if (dest) {
		dest_value->len = len;
		dest_value->data = val;
	} else {
		free(val);
	}
	return ret;

err:
	free(val);
	fprintf(stderr, "ethtool (%s): invalid value '%s' of parameter '%s'\n",
		nlctx->cmd, arg, nlctx->param);
	return -EINVAL;
}

/* Parser handler for parameters recognized for backward compatibility but
 * supposed to fail without passing to kernel. Does not generate any netlink
 * attributes of fill any variable. The @data parameter points to struct
 * error_parser_params (error message, return value and number of extra
 * arguments to skip).
 */
int nl_parse_error(struct nl_context *nlctx, uint16_t type, const void *data,
		   struct nl_msg_buff *msgbuff, void *dest)
{
	const struct error_parser_data *parser_data = data;
	unsigned int skip = parser_data->extra_args;

	fprintf(stderr, "ethtool (%s): ", nlctx->cmd);
	fprintf(stderr, parser_data->err_msg, nlctx->param);
	if (nlctx->argc < skip) {
		fprintf(stderr, "ethtool (%s): too few arguments for parameter '%s' (expected %u)\n",
			nlctx->cmd, nlctx->param, skip);
	} else {
		nlctx->argp += skip;
		nlctx->argc -= skip;
	}

	return parser_data->ret_val;
}

/* parser implementation */

static const struct param_parser *find_parser(const struct param_parser *params,
					      const char *arg)
{
	const struct param_parser *parser;

	for (parser = params; parser->arg; parser++)
		if (!strcmp(arg, parser->arg))
			return parser;
	return NULL;
}

static bool __parser_bit(const uint64_t *map, unsigned int idx)
{
	return map[idx / 64] & (1 << (idx % 64));
}

static void __parser_set(uint64_t *map, unsigned int idx)
{
	map[idx / 64] |= (1 << (idx % 64));
}

struct tmp_buff {
	struct nl_msg_buff	msgbuff;
	unsigned int		id;
	unsigned int		orig_len;
	struct tmp_buff		*next;
};

static struct tmp_buff *tmp_buff_find(struct tmp_buff *head, unsigned int id)
{
	struct tmp_buff *buff;

	for (buff = head; buff; buff = buff->next)
		if (buff->id == id)
			break;

	return buff;
}

static struct tmp_buff *tmp_buff_find_or_create(struct tmp_buff **phead,
						unsigned int id)
{
	struct tmp_buff **pbuff;
	struct tmp_buff *new_buff;

	for (pbuff = phead; *pbuff; pbuff = &(*pbuff)->next)
		if ((*pbuff)->id == id)
			return *pbuff;

	new_buff = malloc(sizeof(*new_buff));
	if (!new_buff)
		return NULL;
	new_buff->id = id;
	msgbuff_init(&new_buff->msgbuff);
	new_buff->next = NULL;
	*pbuff = new_buff;

	return new_buff;
}

static void tmp_buff_destroy(struct tmp_buff *head)
{
	struct tmp_buff *buff = head;
	struct tmp_buff *next;

	while (buff) {
		next = buff->next;
		msgbuff_done(&buff->msgbuff);
		free(buff);
		buff = next;
	}
}

/* Main entry point of parser implementation.
 * @nlctx: netlink context
 * @params:      array of struct param_parser describing expected arguments
 *               and their handlers; the array must be terminated by null
 *               element {}
 * @dest:        optional destination to copy parsed data to (at
 *               param_parser::offset)
 * @group_style: defines if identifiers in .group represent separate messages,
 *               nested attributes or are not allowed
 */
int nl_parser(struct nl_context *nlctx, const struct param_parser *params,
	      void *dest, enum parser_group_style group_style)
{
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	const struct param_parser *parser;
	struct tmp_buff *buffs = NULL;
	struct tmp_buff *buff;
	unsigned int n_params;
	uint64_t *params_seen;
	int ret;

	n_params = 0;
	for (parser = params; parser->arg; parser++) {
		struct nl_msg_buff *msgbuff;
		struct nlattr *nest;

		n_params++;
		if (group_style == PARSER_GROUP_NONE || !parser->group)
			continue;
		ret = -ENOMEM;
		buff = tmp_buff_find_or_create(&buffs, parser->group);
		if (!buff)
			goto out_free_buffs;
		msgbuff = &buff->msgbuff;

		switch (group_style) {
		case PARSER_GROUP_NEST:
			ret = -EMSGSIZE;
			nest = ethnla_nest_start(&buff->msgbuff, parser->group);
			if (!nest)
				goto out_free_buffs;
			break;
		case PARSER_GROUP_MSG:
			ret = msg_init(nlctx, msgbuff, parser->group,
				       NLM_F_REQUEST | NLM_F_ACK);
			if (ret < 0)
				goto out_free_buffs;
			if (ethnla_fill_header(msgbuff,
					       ETHTOOL_A_LINKINFO_HEADER,
					       nlctx->devname, 0))
				goto out_free_buffs;
			break;
		default:
			break;
		}

		buff->orig_len = msgbuff_len(msgbuff);
	}
	ret = -ENOMEM;
	params_seen = calloc(DIV_ROUND_UP(n_params, 64), sizeof(uint64_t));
	if (!params_seen)
		goto out_free_buffs;

	while (nlctx->argc > 0) {
		struct nl_msg_buff *msgbuff;
		void *param_dest;

		nlctx->param = *nlctx->argp;
		ret = -EINVAL;
		parser = find_parser(params, nlctx->param);
		if (!parser) {
			parser_err_unknown_param(nlctx);
			goto out_free;
		}

		/* check duplicates and minimum number of arguments */
		if (__parser_bit(params_seen, parser - params)) {
			parser_err_dup_param(nlctx);
			goto out_free;
		}
		nlctx->argc--;
		nlctx->argp++;
		if (nlctx->argc < parser->min_argc) {
			parser_err_min_argc(nlctx, parser->min_argc);
			goto out_free;
		}
		__parser_set(params_seen, parser - params);

		buff = NULL;
		if (parser->group)
			buff = tmp_buff_find(buffs, parser->group);
		msgbuff = buff ? &buff->msgbuff : &nlsk->msgbuff;

		param_dest = dest ? (dest + parser->dest_offset) : NULL;
		ret = parser->handler(nlctx, parser->type, parser->handler_data,
				      msgbuff, param_dest);
		if (ret < 0)
			goto out_free;
	}

	for (buff = buffs; buff; buff = buff->next) {
		struct nl_msg_buff *msgbuff = &buff->msgbuff;

		if (group_style == PARSER_GROUP_NONE ||
		    msgbuff_len(msgbuff) == buff->orig_len)
			continue;
		switch (group_style) {
		case PARSER_GROUP_NEST:
			ethnla_nest_end(msgbuff, msgbuff->payload);
			ret = msgbuff_append(&nlsk->msgbuff, msgbuff);
			if (ret < 0)
				goto out_free;
			break;
		case PARSER_GROUP_MSG:
			ret = nlsock_sendmsg(nlsk, msgbuff);
			if (ret < 0)
				goto out_free;
			ret = nlsock_process_reply(nlsk, nomsg_reply_cb, NULL);
			if (ret < 0)
				goto out_free;
			break;
		default:
			break;
		}
	}

	ret = 0;
out_free:
	free(params_seen);
out_free_buffs:
	tmp_buff_destroy(buffs);
	return ret;
}
