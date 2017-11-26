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

static void parser_err_invalid_flag(struct nl_context *nlctx, const char *flag)
{
	fprintf(stderr, "ethtool (%s): flag '%s' for parameter '%s' is not "
			"followed by 'on' or 'off'\n",
		nlctx->cmd, flag, nlctx->param);
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
	if ((arg[0] == '0') && (arg[1] == 'x' || arg[1] == 'X'))
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

/* Parser handler for a flag. Generates NLA_FLAG attribute or fills a bool. */
int nl_parse_flag(struct nl_context *nlctx, uint16_t type, const void *data,
		  void *dest)
{
	if (dest)
		*(bool *)dest = true;
	return (type && ethnla_put_flag(nlctx, type, true)) ? -EMSGSIZE : 0;
}

/* Just pick next argument and generate NLA_STRING (or fill const char *). */
int nl_parse_string(struct nl_context *nlctx, uint16_t type, const void *data,
		    void *dest)
{
	const char *arg = *nlctx->argp;

	nlctx->argp++;
	nlctx->argc--;

	if (dest)
		*(const char **)dest = arg;
	return (type && ethnla_put_strz(nlctx, type, arg)) ? -EMSGSIZE : 0;
}

/* parser handler for unsigned 32-bit integer */
int nl_parse_direct_u32(struct nl_context *nlctx, uint16_t type,
			const void *data, void *dest)
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
	return (type && ethnla_put_u32(nlctx, type, val)) ? -EMSGSIZE : 0;
}

/* parser handler for unsigned 8-bit integer */
int nl_parse_direct_u8(struct nl_context *nlctx, uint16_t type,
		       const void *data, void *dest)
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
	return (type && ethnla_put_u8(nlctx, type, val)) ? -EMSGSIZE : 0;
}

/* parser handler for bool represented by NLA_U8; this allows three states:
 * on, of and unspecified/unknown
 */
int nl_parse_u8bool(struct nl_context *nlctx, uint16_t type, const void *data,
		    void *dest)
{
	const char *arg = *nlctx->argp;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	if (!strcmp(arg, "on")) {
		if (dest)
			*(uint8_t *)dest = 1;
		ret = type ? ethnla_put_u8(nlctx, type, 1) : 0;
	} else if (!strcmp(arg, "off")) {
		if (dest)
			*(uint8_t *)dest = 0;
		ret = type ? ethnla_put_u8(nlctx, type, 0) : 0;
	} else {
		parser_err_invalid_value(nlctx, arg);
		return -EINVAL;
	}

	return ret ? -EMSGSIZE : 0;
}

/* parser handler for 32-bit unsigned integer passed as a string to look up in
 * a table
 */
int nl_parse_lookup_u32(struct nl_context *nlctx, uint16_t type,
			const void *data, void *dest)
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
	return (type && ethnla_put_u32(nlctx, type, val)) ? -EMSGSIZE : 0;
}

/* parser handler for 8-bit unsigned integer passed as a string to look up in
 * a table
 */
int nl_parse_lookup_u8(struct nl_context *nlctx, uint16_t type,
		       const void *data, void *dest)
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
	return (type && ethnla_put_u8(nlctx, type, val)) ? -EMSGSIZE : 0;
}

/* Parser handler for a simple bitmap consisting of 32-bit value and 32-bit
 * mask. Passed either as a numeric value optionally followed by '/' and
 * a mask or as a series of "name on/off" pairs. Parsing stops at the end
 * of command line or at "--" marker.
 */
int nl_parse_bitfield32(struct nl_context *nlctx, uint16_t type,
			const void *data, void *dest)
{
	const char *arg = *nlctx->argp;
	const struct flag_info *flags = data;
	uint32_t value, selector;
	int ret;

	ret = parse_u32(arg, &value);
	if (isdigit(arg[0])) {
		char *buff;
		char *mask;

		nlctx->argp++;
		nlctx->argc--;
		if (!type && !dest)
			return 0;

		buff = strdup(arg);
		if (!buff)
			return -ENOMEM;
		mask = strchr(buff, '/');
		if (mask) {
			/* numeric value / mask */
			*mask = '\0';
			mask++;
			ret = parse_u32(mask, &selector);
			if (ret < 0) {
				parser_err_invalid_value(nlctx, mask);
				free(buff);
				return ret;
			}
		} else {
			/* numeric value */
			selector = ~(uint32_t)0;
		}

		ret = parse_u32(buff, &value);
		free(buff);
		if (ret < 0) {
			parser_err_invalid_value(nlctx, arg);
			return ret;
		}
	} else {
		/* flag on/off... [--] */
		value = 0;
		selector = 0;
		while (nlctx->argc > 0) {
			const struct flag_info *flag = flags;

			if (!strcmp(*nlctx->argp, "--")) {
				nlctx->argp++;
				nlctx->argc--;
				break;
			}
			if (nlctx->argc < 2 ||
			    (strcmp(nlctx->argp[1], "on") &&
			     strcmp(nlctx->argp[1], "off"))) {
				parser_err_invalid_flag(nlctx, *nlctx->argp);
				return -EINVAL;
			}
			while (flag->name && strcmp(*nlctx->argp, flag->name))
				flag++;
			if (!flag->name) {
				parser_err_invalid_value(nlctx, *nlctx->argp);
				return -EINVAL;
			}
			selector |= flag->value;
			if (!strcmp(nlctx->argp[1], "on"))
				value |= flag->value;

			nlctx->argp += 2;
			nlctx->argc -= 2;
		}
	}

	if (dest) {
		struct nla_bitfield32 *d = dest;

		d->value = value;
		d->selector = selector;
	}
	return type ? ethnla_put_bitfield32(nlctx, type, value, selector) : 0;
}

static int __nl_parse_char_bitfield32(struct nl_context *nlctx, const char *str,
				      const struct bitfield32_parser_data *pdata,
				      uint32_t *result)
{
	unsigned int i;
	const char *p;
	int ret;

	ret = parse_u32(str, result);
	if (ret == 0)
		return 0;

	*result = 0;
	for (p = str; *p; p++) {
		const struct bitfield32_parser_special *special;

		for (special = pdata->specials; special->name; special++) {
			if (*p == special->name) {
				*result = special->val;
				break;
			}
		}
		if (special->name)
			continue;

		for (i = 0; i < 32; i++) {
			if (pdata->bits[i] == *p) {
				*result |= (1U << i);
				break;
			}
		}
		if (i == 32) {
			fprintf(stderr,
				"ethtool (%s): invalid bitfield '%s'\n",
				nlctx->cmd, str);
			return -EINVAL;
		}
	}

	return 0;
}

int nl_parse_char_bitfield32(struct nl_context *nlctx, uint16_t type,
			     const void *data, void *dest)
{
	char *arg = *nlctx->argp;
	char *mask = strchr(arg, '/');
	uint32_t value, selector;
	int ret;

	nlctx->argp++;
	nlctx->argc--;
	if (!type && !dest)
		return 0;
	arg = strdup(arg);
	if (!arg)
		return -ENOMEM;

	mask = strchr(arg, '/');
	if (mask)
		*(mask++) = '\0';

	ret = __nl_parse_char_bitfield32(nlctx, arg, data, &value);
	if (ret < 0)
		goto out;

	if (!mask) {
		selector = ~(uint32_t)0;
	} else {
		ret = __nl_parse_char_bitfield32(nlctx, mask, data, &selector);
		if (ret < 0)
			goto out;
	}

	if (dest) {
		struct nla_bitfield32 *target = dest;

		target->value = value;
		target->selector = selector;
	}
	ret = type ? ethnla_put_bitfield32(nlctx, type, value, selector) : 0;
out:
	free(arg);
	return ret;
}

static bool is_hex(char c)
{
	if (isdigit(c))
		return true;
	else
		return (c >= 'a' && c <= 'f');
}

/* Return true if a bitset argument should be parsed as numeric, i.e.
 * (a) it starts with '0x'
 * (b) it consists only of hex digits and at most one slash which can be
 *     optionally followed by "0x"; if no_mask is true, slash is not allowed
 */
static bool is_numeric_bitset(const char *arg, bool no_mask)
{
	const char *p = arg;
	bool has_slash = false;

	if (!arg)
		return false;
	if (arg[0] == '0' && arg[1] == 'x')
		return true;
	while (*p) {
		if (*p == '/') {
			if (has_slash || no_mask)
				return false;
			has_slash = true;
			p++;
			if (p[0] == '0' && p[1] == 'x')
				p += 2;
			continue;
		}
		if (!is_hex(*p))
			return false;
		p++;
	}
	return true;
}

/* number of significant bits */
unsigned int nsb(uint32_t x)
{
	unsigned int ret = 0;

	if (x & 0xffff0000U) {
		x >>= 16;
		ret += 16;
	}
	if (x & 0xff00U) {
		x >>= 8;
		ret += 8;
	}
	if (x & 0xf0U) {
		x >>= 4;
		ret += 4;
	}
	if (x & 0xcU) {
		x >>= 2;
		ret += 2;
	}
	if (x & 0x2U) {
		x >>= 1;
		ret += 1;
	}

	return ret + x;
}

/* Parse hex string (without leading "0x") into a bitmap consisting of 32-bit
 * words. Caller must make sure arg is at least len characters long and dst has
 * place for at least (len + 7) / 8 32-bit words.
 * Returns number of significant bits in the bitmap on success and negative
 * value on error.
 */
static int parse_hex_string(const char *arg, unsigned int len, uint32_t *dst)
{
	const char *p = arg;
	unsigned int nwords = (len + 7) / 8;
	unsigned int nbits = 0;
	char buff[9];

	memset(dst, '\0', nwords * sizeof(uint32_t));
	while (len > 0) {
		unsigned int chunk = (len % 8) ?: 8;
		unsigned long val;
		char *endp;

		memcpy(buff, p, chunk);
		buff[chunk] = '\0';
		val = strtoul(buff, &endp, 16);
		if (*endp)
			return -EINVAL;
		*dst++ = (uint32_t)val;
		if (nbits)
			nbits += 8 * chunk;
		else
			nbits = nsb(val);

		p += chunk;
		len -= chunk;
	}
	return nbits;
}

static int nl_parse_bitset_compact(struct nl_context *nlctx, uint16_t type,
				   bool no_mask)
{
	const char *arg = *nlctx->argp;
	unsigned int nwords, len1, len2;
	struct nlattr *nest;
	const char *maskptr;
	uint32_t *value = NULL;
	uint32_t *mask = NULL;
	int nbits;
	int ret = 0;

	if (!type)
		goto out;
	if (arg[0] == '0' && arg[1] == 'x')
		arg += 2;

	maskptr = strchr(arg, '/');
	if (maskptr && no_mask)
		return -EINVAL;
	len1 = maskptr ? ( maskptr - arg) : strlen(arg);
	nwords = (len1 + 7) / 8;
	nbits = 0;

	if (maskptr) {
		ret = -ENOMEM;
		mask = malloc(nwords * sizeof(uint32_t));
		if (!mask)
			goto out_free;
		maskptr++;
		if (maskptr[0] == '0' && maskptr[1] == 'x')
			maskptr += 2;
		len2 = strlen(maskptr);
		if (len2 > len1)
			nwords = (len2 + 7) / 8;
		mask = malloc(nwords * sizeof(uint32_t));
		if (!mask)
			return -ENOMEM;
		ret = parse_hex_string(maskptr, strlen(maskptr), mask);
		if (ret < 0)
			goto out_free;
		nbits = ret;
	}

	value = malloc(nwords * sizeof(uint32_t));
	if (!value)
		return -ENOMEM;
	ret = parse_hex_string(arg, len1, value);
	if (ret < 0)
		goto out_free;
	nbits = (nbits < ret) ? ret : nbits;
	nwords = (nbits + 31) / 32;

	ret = 0;
	if (!type)
		goto out_free;
	ret = -EMSGSIZE;
	if (!(nest = ethnla_nest_start(nlctx, type)) ||
	    ethnla_put_flag(nlctx, ETHTOOL_A_BITSET_LIST, !mask) ||
	    ethnla_put_u32(nlctx, ETHTOOL_A_BITSET_SIZE, nbits) ||
	    ethnla_put(nlctx, ETHTOOL_A_BITSET_VALUE, nwords * sizeof(uint32_t),
		       value) ||
	    (mask &&
	     ethnla_put(nlctx, ETHTOOL_A_BITSET_MASK, nwords * sizeof(uint32_t),
			mask)))
		goto out_free;
	mnl_attr_nest_end(nlctx->nlhdr, nest);
	ret = 0;

out_free:
	free(value);
	free(mask);
out:
	nlctx->argp++;
	nlctx->argc--;
	return ret;
}

static int nl_parse_bitset_verbose(struct nl_context *nlctx, uint16_t type,
				   bool list)
{
	struct nlmsghdr *nlhdr = nlctx->nlhdr;
	struct nlattr *bitset_attr;
	struct nlattr *bits_attr;
	struct nlattr *bit_attr;
	int ret;

	if (!type) {
		/* no output, only skip to the end of bitset arguments */
		while (nlctx->argc > 0) {
			if (!strcmp(*nlctx->argp, "--")) {
				nlctx->argp++;
				nlctx->argc--;
				break;
			}
			if (list) {
				nlctx->argp++;
				nlctx->argc--;
			} else {
				if (nlctx->argc < 2 ||
				    (strcmp(nlctx->argp[1], "on") &&
				     strcmp(nlctx->argp[1], "off")))
					return -EINVAL;
				nlctx->argp += 2;
				nlctx->argc -= 2;
			}
		}
		return 0;
	}

	bitset_attr = ethnla_nest_start(nlctx, type);
	if (!bitset_attr)
		return -EMSGSIZE;
	ret = -EMSGSIZE;
	if (list && ethnla_put_flag(nlctx, ETHTOOL_A_BITSET_LIST, true))
		goto err;
	bits_attr = ethnla_nest_start(nlctx, ETHTOOL_A_BITSET_BITS);
	if (!bits_attr)
		goto err;

	while (nlctx->argc > 0) {
		bool bit_val = true;

		if (!strcmp(*nlctx->argp, "--")) {
			nlctx->argp++;
			nlctx->argc--;
			break;
		}
		ret = -EINVAL;
		if (!list) {
			if (nlctx->argc < 2 ||
			    (strcmp(nlctx->argp[1], "on") &&
			     strcmp(nlctx->argp[1], "off"))) {
				parser_err_invalid_flag(nlctx, *nlctx->argp);
				goto err;
			}
			bit_val = !strcmp(nlctx->argp[1], "on");
		}

		ret = -EMSGSIZE;
		bit_attr = ethnla_nest_start(nlctx, ETHTOOL_A_BITS_BIT);
		if (!bit_attr)
			goto err;
		if (ethnla_put_strz(nlctx, ETHTOOL_A_BIT_NAME, nlctx->argp[0]))
			goto err;
		if (!list &&
		    ethnla_put_flag(nlctx, ETHTOOL_A_BIT_VALUE, bit_val))
			goto err;
		mnl_attr_nest_end(nlhdr, bit_attr);

		nlctx->argp += (list ? 1 : 2);
		nlctx->argc -= (list ? 1 : 2);
	}

	mnl_attr_nest_end(nlhdr, bits_attr);
	mnl_attr_nest_end(nlhdr, bitset_attr);
	return 0;
err:
	mnl_attr_nest_cancel(nlhdr, bitset_attr);
	return ret;
}

/* parse arguments to fill a bitset nested attribute; accepts either numeric
 * representation (number optionally followed by '/' and another number (mask))
 * or list of flag names followed by "on" or "off"; resulting bitset will use
 * compact format for numeric representation and verbose for flag list; this
 * handler can only put bitset representation into a message, dest is ignored
 * @nlctx: netlink context
 * @type: bitset attribute type to use
 * @data: unused
 * @dest: unused
 */
int nl_parse_bitset(struct nl_context *nlctx, uint16_t type, const void *data,
		    void *dest)
{
	if (is_numeric_bitset(*nlctx->argp, false))
		return nl_parse_bitset_compact(nlctx, type, false);
	else
		return nl_parse_bitset_verbose(nlctx, type, false);
}

/* parse arguments to fill a bitset nested attribute; accepts either numeric
 * representation or a simple list of flag names; resulting bitset will have
 * ETHTOOL_A_BITSET_LIST flag and no mask; this handler can only put bitset
 * representation into a message, dest is ignored
 * @nlctx: netlink context
 * @type: bitset attribute type to use
 * @data: unused
 * @dest: unused
 */
int nl_parse_bitlist(struct nl_context *nlctx, uint16_t type, const void *data,
		     void *dest)
{
	if (is_numeric_bitset(*nlctx->argp, true))
		return nl_parse_bitset_compact(nlctx, type, true);
	else
		return nl_parse_bitset_verbose(nlctx, type, true);
}

static bool bytestr_delim(const char *p, char delim)
{
	return !*p || (delim ? (*p == delim) : !is_hex(*p));
}

unsigned int hex_val(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 0xa;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 0xa;
	return 0;
}

/* Parser handler for generic byte string in MAC-like format. If @dest is not
 * null, it is interpreted as a pointer to struct byte_str_value to be filled
 * with with byte string length and pointer to its contents. In such case,
 * caller is responsible to free the data pointer allocated by this function
 */
int nl_parse_byte_str(struct nl_context *nlctx, uint16_t type, const void *data,
		      void *dest)
{
	const struct byte_str_params *params = data;
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
		if (!bytestr_delim(p, params->delim))
			p++;
		if (!bytestr_delim(p, params->delim))
			p++;
		if (!bytestr_delim(p, params->delim))
			goto err;
		if (!*p)
			break;
		p++;
		if (*p && bytestr_delim(p, params->delim))
			goto err;
	}
	if (len < params->min_len || (params->max_len && len > params->max_len))
		goto err;
	val = malloc(len);
	if (!val)
		return -ENOMEM;

	p = arg;
	for (i = 0; i < len; i++) {
		uint8_t byte = 0;

		if (!is_hex(*p))
			goto err;
		while (is_hex(*p))
			byte = 16 * byte + hex_val(*p++);
		if (!bytestr_delim(p, params->delim))
			goto err;
		val[i] = byte;
		if (*p)
			p++;
	}
	ret = type ? ethnla_put(nlctx, type, len, val) : 0;
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

/* parser handler for (6-byte) MAC address in the usual format */
int nl_parse_mac_addr(struct nl_context *nlctx, uint16_t type, const void *data,
		      void *dest)
{
	const char *arg = *nlctx->argp;
	uint8_t val[ETH_ALEN];
	unsigned int i;
	const char *p;

	nlctx->argp++;
	nlctx->argc--;

	p = arg;
	i = 0;
	while (i < ETH_ALEN && *p) {
		char *endp;
		unsigned long byte = strtoul(p, &endp, 16);

		if ((endp - p > 2) || (*endp && *endp != ':'))
			goto err;
		val[i++] = (uint8_t) byte;
		p = endp + (*endp ? 1 : 0);
	}
	if (i < ETH_ALEN)
		goto err;

	if (dest)
		memcpy(dest, val, ETH_ALEN);
	return type ? ethnla_put(nlctx, type, ETH_ALEN, val) : 0;

err:
	fprintf(stderr, "ethtool (%s): invalid value '%s' of parameter '%s'\n",
		nlctx->cmd, arg, nlctx->param);
	return -EINVAL;
}

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

struct arg_info {
	const struct param_parser *parser;	/* matching parser */
	int next;				/* offset of next parameter */
	bool processed;				/* param processed already */
};

/* Main entry point of parser implementation.
 * @nlctx: netlink context
 * @params: array of struct param_parser describing expected arguments and
 *          their handlers; the array must be terminated by null element {}
 * @dest: optional destination to copy parsed data to (at param_parser::offset)
 */
int nl_parser(struct nl_context *nlctx, const struct param_parser *params,
	      void *dest)
{
	char **orig_argp = nlctx->argp;
	int orig_argc = nlctx->argc;
	const struct param_parser *parser;
	struct arg_info *args_info;
	unsigned int args_left;
	unsigned int n_params;
	uint64_t *params_seen;
	unsigned int idx;
	int ret;

	n_params = 0;
	for (parser = params; parser->arg; parser++)
		n_params++;
	params_seen = calloc(DIV_ROUND_UP(n_params, 64), sizeof(uint64_t));
	if (!params_seen)
		return -ENOMEM;
	ret = -ENOMEM;
	args_info = calloc(orig_argc, sizeof(struct arg_info));
	if (!args_info)
		goto out_free;

	/* first run: process unnested args and mark arg_info so that we do not
	 * have to repeat parser lookup and dry parse in subsequent runs
	 */
	args_left = 0;
	while (nlctx->argc > 0) {
		idx = orig_argc - nlctx->argc;

		nlctx->param = *nlctx->argp;
		ret = -EINVAL;
		parser = find_parser(params, nlctx->param);
		if (!parser) {
			parser_err_unknown_param(nlctx);
			goto out_free;
		}
		args_info[idx].parser = parser;

		/* check duplicate and minimum number of arguments */
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

		if (parser->nest) {
			/* nested parameter; only let the parser find next
			 * parameter, mark it down and increment the counter
			 */
			ret = parser->handler(nlctx, 0, parser->handler_data,
					      NULL);
			if (ret < 0)
				goto out_free;
			args_left++;
		} else {
			void *param_dest = dest ? (dest + parser->dest_offset)
					        : NULL;

			/* unnested parameter, process normally and mark as
			 * processed
			 */
			ret = parser->handler(nlctx, parser->type,
					      parser->handler_data, param_dest);
			if (ret < 0)
				goto out_free;
			args_info[idx].processed = true;
		}
		args_info[idx].next = orig_argc - nlctx->argc;
	}

	/* process nested parameters (if any); we can omit some checks this
	 * time and can use the information marked down first time
	 */
	while (args_left) {
		nlctx->argp = orig_argp;
		nlctx->argc = orig_argc;
		struct nlattr *nest;
		uint16_t nest_type;
		idx = 0;

		/* we know thare must be something left (args_left > 0) */
		while (args_info[idx].processed)
			idx = args_info[idx].next;
		nlctx->argp = orig_argp + idx;
		nlctx->argc = orig_argc - idx;

		parser = args_info[idx].parser;
		nest_type = parser->nest;
		ret = -ENOMEM;
		nest = ethnla_nest_start(nlctx, nest_type);
		if (!nest)
			goto out_free;

		do {
			nlctx->param = *nlctx->argp;
			nlctx->argp++;
			nlctx->argc--;
			ret = parser->handler(nlctx, parser->type,
					      parser->handler_data,
					      dest ? dest + parser->dest_offset
						   : NULL);
			if (ret < 0)
				goto out_free;

			args_info[idx].processed = true;
			if (--args_left == 0)
				break;
			idx = orig_argc - nlctx->argc;

			while (idx < orig_argc &&
			       (args_info[idx].processed ||
				args_info[idx].parser->nest != nest_type))
				idx = args_info[idx].next;
			nlctx->argp = orig_argp + idx;
			nlctx->argc = orig_argc - idx;
			parser = args_info[idx].parser;
		} while (nlctx->argc > 0);

		mnl_attr_nest_end(nlctx->nlhdr, nest);
	}
	ret = 0;

out_free:
	free(args_info);
	free(params_seen);
	return ret;
}
