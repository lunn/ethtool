#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "parser.h"

static const char *flow_type_labels[] = {
	[TCP_V4_FLOW]		= "TCP over IPv4",
	[UDP_V4_FLOW]		= "UDP over IPv4",
	[SCTP_V4_FLOW]		= "SCTP over IPv4",
	[AH_ESP_V4_FLOW]	= "IPSEC AH/ESP over IPv4",
	[AH_V4_FLOW]		= "IPSEC AH over IPv4",
	[ESP_V4_FLOW]		= "IPSEC ESP over IPv4",
	[TCP_V6_FLOW]		= "TCP over IPv6",
	[UDP_V6_FLOW]		= "UDP over IPv6",
	[SCTP_V6_FLOW]		= "SCTP over IPv6",
	[AH_ESP_V6_FLOW]	= "IPSEC AH/ESP over IPv6",
	[AH_V6_FLOW]		= "IPSEC AH over IPv6",
	[ESP_V6_FLOW]		= "IPSEC ESP over IPv6",
	[IPV4_FLOW]		= "Generic IPv4",
	[IPV6_FLOW]		= "Generic IPv6",
};

static const char *hash_field_labels[] = {
	[1]	= "L2DA",
	[2]	= "VLAN tag",
	[3]	= "L3 proto",
	[4]	= "IP SA",
	[5]	= "IP DA",
	[6]	= "L4 bytes 0 & 1 [TCP/UDP src port]",
	[7]	= "L4 bytes 2 & 3 [TCP/UDP dst port]",
};

/* GET_RXFLOW */

static int apply_block(uint32_t *table, unsigned int size,
		       const struct nlattr *block, unsigned int entry_size)
{
	const struct nlattr *tb[ETHTOOL_A_ITBLK_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const uint32_t *src32;
	const uint16_t *src16;
	const uint8_t *src8;
	unsigned int start, blen, i;
	int ret;

	ret = mnl_attr_parse_nested(block, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	if (!tb[ETHTOOL_A_ITBLK_START] || !tb[ETHTOOL_A_ITBLK_DATA])
		return -EFAULT;

	start = mnl_attr_get_u32(tb[ETHTOOL_A_ITBLK_START]);
	if (start >= size)
		return -EFAULT;
	if (tb[ETHTOOL_A_ITBLK_LEN]) {
		blen = mnl_attr_get_u32(tb[ETHTOOL_A_ITBLK_LEN]);
		if (start + blen > size)
			return -EFAULT;
	} else {
		blen = size - start;
	}
	if (mnl_attr_get_payload_len(tb[ETHTOOL_A_ITBLK_DATA]) <
	    blen * entry_size)
		return -EFAULT;

	switch(entry_size) {
	case 4:
		src32 = mnl_attr_get_payload(tb[ETHTOOL_A_ITBLK_DATA]);
		memcpy(table + start, src32, blen * entry_size);
		break;
	case 2:
		src16 = mnl_attr_get_payload(tb[ETHTOOL_A_ITBLK_DATA]);
		for (i = 0; i < blen; i++)
			table[start + i] = src16[i];
		break;
	case 1:
		src8 = mnl_attr_get_payload(tb[ETHTOOL_A_ITBLK_DATA]);
		for (i = 0; i < blen; i++)
			table[start + i] = src8[i];
		break;
	}

	return 0;
}

static int apply_pattern(uint32_t *table, unsigned int size,
			 const struct nlattr *pattern, unsigned int n_rings)
{
	const struct nlattr *tb[ETHTOOL_A_ITPAT_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	unsigned int min_ring = 0;
	unsigned int max_ring = n_rings - 1;
	unsigned int offset = 0;
	unsigned int start, blen, mod, n, i;
	int ret;

	ret = mnl_attr_parse_nested(pattern, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	if (!tb[ETHTOOL_A_ITPAT_START])
		return -EFAULT;
	start = mnl_attr_get_u32(tb[ETHTOOL_A_ITPAT_START]);
	if (start >= size)
		return -EFAULT;
	if (tb[ETHTOOL_A_ITPAT_LEN]) {
		blen = mnl_attr_get_u32(tb[ETHTOOL_A_ITPAT_LEN]);
		if (start + blen > size)
			return -EFAULT;
	} else {
		blen = size - start;
	}
	if (tb[ETHTOOL_A_ITPAT_MIN_RING])
		min_ring = mnl_attr_get_u32(tb[ETHTOOL_A_ITPAT_MIN_RING]);
	if (tb[ETHTOOL_A_ITPAT_MAX_RING])
		max_ring = mnl_attr_get_u32(tb[ETHTOOL_A_ITPAT_MAX_RING]);
	if (tb[ETHTOOL_A_ITPAT_OFFSET])
		offset = mnl_attr_get_u32(tb[ETHTOOL_A_ITPAT_OFFSET]);
	if (min_ring >= n_rings || max_ring < min_ring || max_ring >= n_rings)
		return -EFAULT;
	mod = max_ring - min_ring + 1;

	for (i = 0; i < blen && i < mod; i++)
		table[start + i] = min_ring + (start + i + offset) % mod;
	n = blen / mod;
	for (i = 0; i < n - 1; i++)
		memcpy(table + start + i * mod, table + start,
		       mod * sizeof(table[0]));
	if (blen % mod)
		memcpy(table + start + n * mod, table + start, blen % mod);

	return 0;
}

static int dump_indir_tbl(struct nl_context *nlctx, const struct nlattr *tb[])
{
	const struct nlattr *patch;
	uint32_t n_rings, size;
	uint32_t context = 0;
	uint32_t *table;
	unsigned int i;
	int ret;

	if (tb[ETHTOOL_A_RXFLOW_CONTEXT])
		context = mnl_attr_get_u32(tb[ETHTOOL_A_RXFLOW_CONTEXT]);
	if (nlctx->is_monitor || nlctx->is_dump)
		putchar('\n');
	size = mnl_attr_get_u32(tb[ETHTOOL_A_RXFLOW_INDTBL_SIZE]);
	if (!size)
		return -EOPNOTSUPP;
	table = calloc(size, sizeof(table[0]));
	if (!table)
		return -ENOMEM;

	n_rings = mnl_attr_get_u32(tb[ETHTOOL_A_RXFLOW_NRINGS]);
	printf("RX flow hash indirection table for %s with %u RX ring(s)",
	       nlctx->devname, n_rings);
	if (context)
		printf(", context %u", context);
	printf(":\n");

	mnl_attr_for_each_nested(patch, tb[ETHTOOL_A_RXFLOW_INDIR_TBL]) {
		uint16_t ptype = mnl_attr_get_type(patch);

		switch(ptype) {
		case ETHTOOL_A_INDTBL_BLOCK32 :
			ret = apply_block(table, size, patch, 4);
			break;
		case ETHTOOL_A_INDTBL_BLOCK16 :
			ret = apply_block(table, size, patch, 2);
			break;
		case ETHTOOL_A_INDTBL_BLOCK8 :
			ret = apply_block(table, size, patch, 1);
			break;
		case ETHTOOL_A_INDTBL_PATTERN :
			ret = apply_pattern(table, size, patch, n_rings);
			break;
		default:
			fprintf(stderr, "unknown indir table data type %u\n",
				ptype);
			ret = -EFAULT;
		}
		if (ret < 0)
			goto out_free;
	}
	for (i = 0; i < size; i++) {
		if (i % 8 == 0)
			printf("%5u: ", i);
		printf(" %5u", table[i]);
		if (i % 8 == 7)
			putchar('\n');
	}
	if (size % 8)
		putchar('\n');
	ret = 0;

out_free:
	free(table);
	return ret;
}

static int dump_hash_key(const struct nlattr *attr, bool allow_empty)
{
	unsigned int len, i;
	uint8_t *key;

	if (allow_empty && !attr)
		return 0;
	printf("RSS hash key:\n");
	if (!attr)
		return -EOPNOTSUPP;
	len = mnl_attr_get_payload_len(attr);
	if (!len)
		return -EOPNOTSUPP;
	key = mnl_attr_get_payload(attr);

	for (i = 0; i < len; i++)
		printf("%02x%c", key[i], (i == len - 1) ? '\n' : ':');

	return 0;
}

static void dump_hashfn_walk_cb(unsigned int idx, const char *name, bool val,
				void *data)
{
	printf("    %s: %s\n", name, val ? "on" : "off");
}

static void dump_hash_fields(uint32_t fields)
{
	unsigned int i;

	printf(" use these fields for computing Hash flow key:\n");
	if (!fields) {
		printf("None\n\n");
		return;
	}

	for (i = 0; i < 32; i++) {
		if (!(fields & (1U << i)))
			continue;
		if (i < MNL_ARRAY_SIZE(hash_field_labels) &&
		    hash_field_labels[i])
			printf("%s\n", hash_field_labels[i]);
		else
			printf("unknown (bit %u)\n", i);
	}
	putchar('\n');
}

static int dump_hashopts(const struct nlattr *opts, const uint32_t *req_type)
{
	const struct nlattr *opt;
	int ret;


	mnl_attr_for_each_nested(opt, opts) {
		const struct nlattr *tb[ETHTOOL_A_RXHASHOPT_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);
		const struct nla_bitfield32 *fields;
		uint32_t flow_type;

		if (mnl_attr_get_type(opt) != ETHTOOL_A_RXHASHOPTS_OPT)
			continue;
		ret = mnl_attr_parse_nested(opt, attr_cb, &tb_info);
		if (ret < 0 || !tb[ETHTOOL_A_RXHASHOPT_FLOWTYPE])
			continue;
		flow_type = mnl_attr_get_u32(tb[ETHTOOL_A_RXHASHOPT_FLOWTYPE]);
		if (req_type && flow_type != *req_type)
			continue;

		if (flow_type >= MNL_ARRAY_SIZE(flow_type_labels) ||
		    !flow_type_labels[flow_type])
			printf("BIT%u flows", flow_type);
		else
			printf("%s flows", flow_type_labels[flow_type]);

		fields = tb[ETHTOOL_A_RXHASHOPT_FIELDS] ?
			 mnl_attr_get_payload(tb[ETHTOOL_A_RXHASHOPT_FIELDS]) :
			 NULL;
		if (tb[ETHTOOL_A_RXHASHOPT_DISCARD])
			printf(" - All matching flows discarded on RX\n");
		else
			dump_hash_fields(fields ? fields->value : 0);
	}

	return 0;
}

int rxflow_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_RXFLOW_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_RXFLOW_DEV]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (mask_ok(nlctx, ETHTOOL_IM_RXFLOW_INDTBL) &&
	    tb[ETHTOOL_A_RXFLOW_NRINGS] && tb[ETHTOOL_A_RXFLOW_INDIR_TBL] &&
	    tb[ETHTOOL_A_RXFLOW_INDTBL_SIZE]) {
		ret = dump_indir_tbl(nlctx, tb);
		if (ret < 0)
			fprintf(stderr, "Indirection table dump failed\n");
	}
	if (mask_ok(nlctx, ETHTOOL_IM_RXFLOW_HKEY)) {
		ret = dump_hash_key(tb[ETHTOOL_A_RXFLOW_HASH_KEY],
				    nlctx->is_monitor);
		if (ret < 0)
			printf("Operation not supported\n");
	}
	if (mask_ok(nlctx, ETHTOOL_IM_RXFLOW_HASHFN)) {
		if (tb[ETHTOOL_A_RXFLOW_HASH_FN]) {
			printf("RSS hash function:\n");
			walk_bitset(tb[ETHTOOL_A_RXFLOW_HASH_FN],
				    global_stringset(ETH_SS_RSS_HASH_FUNCS),
				    dump_hashfn_walk_cb, NULL);
		} else if (!nlctx->is_monitor) {
			printf("RSS hash function:\n");
			printf("    Operation not supported\n");
		}
	}
	if (mask_ok(nlctx, ETHTOOL_IM_RXFLOW_HASHOPTS)) {
		ret = dump_hashopts(tb[ETHTOOL_A_RXFLOW_HASH_OPTS],
				    nlctx->cmd_private);
		if (ret < 0)
			printf("Cannot get RX network flow hashing options: %s\n",
			       strerror(-ret));
	}

	return MNL_CB_OK;
}

static const struct param_parser grxfh_params[] = {
	{
		.arg		= "context",
		.type		= ETHTOOL_A_RXFLOW_CONTEXT,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{}
};

#define GRXFH_REQ_MASK ETHTOOL_IM_RXFLOW_HASHFN | ETHTOOL_IM_RXFLOW_HKEY | \
		       ETHTOOL_IM_RXFLOW_INDTBL
int nl_grxfh(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	uint32_t context = 0;
	int ret;

	nlctx->cmd = "-x";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->filter_mask = GRXFH_REQ_MASK;

	ret = ethnl_prep_get_request(ctx, ETHNL_CMD_GET_RXFLOW,
				     ETHTOOL_A_RXFLOW_DEV);
	if (ret < 0)
		return ret;
	if (ethnla_put_u32(nlctx, ETHTOOL_A_RXFLOW_INFOMASK, GRXFH_REQ_MASK))
		return -EMSGSIZE;
	/* ETHTOOL_A_RXFLOW_COMPACT = false */
	ret = nl_parser(nlctx, grxfh_params, NULL);
	if (ret < 0)
		return ret;
	if (context && ethnla_put_u32(nlctx, ETHTOOL_A_RXFLOW_CONTEXT, context))
		return -EMSGSIZE;

	return ethnl_send_get_request(nlctx, rxflow_reply_cb);
}

struct hashopts_params {
	uint32_t	flow_type;
	uint32_t	context;
};

static const struct lookup_entry_u32 flow_types[] = {
	{ .arg = "all",		.val = 0 },
	{ .arg = "*",		.val = 0 },
	{ .arg = "tcp4",	.val = TCP_V4_FLOW },
	{ .arg = "udp4",	.val = UDP_V4_FLOW },
	{ .arg = "sctp4",	.val = SCTP_V4_FLOW },
	{ .arg = "ah4",		.val = AH_V4_FLOW },
	{ .arg = "esp4",	.val = ESP_V4_FLOW },
	{ .arg = "tcp6",	.val = TCP_V6_FLOW },
	{ .arg = "udp6",	.val = UDP_V6_FLOW },
	{ .arg = "sctp6",	.val = SCTP_V6_FLOW },
	{ .arg = "ah6",		.val = AH_V6_FLOW },
	{ .arg = "esp6",	.val = ESP_V6_FLOW },
	{}
};

static const struct param_parser get_hashopts_parser[] = {
	{
		.arg		= "rx-flow-hash",
		.handler	= nl_parse_lookup_u32,
		.handler_data	= flow_types,
		.dest_offset	= offsetof(struct hashopts_params, flow_type),
		.min_argc	= 1,
	},
	{
		.arg		= "context",
		.handler	= nl_parse_direct_u32,
		.dest_offset	= offsetof(struct hashopts_params, context),
		.min_argc	= 1,
	},
	{}
};

static int ethnl_get_hashopts(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct hashopts_params params = {};
	int ret;

	ret = nl_parser(nlctx, get_hashopts_parser, &params);
	if (ret < 0)
		exit(2);

	ret = ethnl_prep_get_request(ctx, ETHNL_CMD_GET_RXFLOW,
				     ETHTOOL_A_RXFLOW_DEV);
	if (ret < 0)
		return ret;
	if (ethnla_put_u32(nlctx, ETHTOOL_A_RXFLOW_INFOMASK,
			   ETHTOOL_IM_RXFLOW_HASHOPTS))
		return -EMSGSIZE;
	/* ETHTOOL_A_RXFLOW_COMPACT = false */
	ret = nl_parser(nlctx, grxfh_params, NULL);
	if (ret < 0)
		return ret;
	if (params.context &&
	    ethnla_put_u32(nlctx, ETHTOOL_A_RXFLOW_CONTEXT, params.context))
		return -EMSGSIZE;
	if (params.flow_type)
		nlctx->cmd_private = &params.flow_type;

	ret = ethnl_send_get_request(nlctx, rxflow_reply_cb);
	nlctx->cmd_private = NULL;
	return ret;
}

int nl_grxclass(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	const char *arg;

	nlctx->cmd = "-n";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->filter_mask = ETHTOOL_IM_RXFLOW_HASHOPTS;

	if (nlctx->argc == 0) {
		fprintf(stderr, "ethtool: missing argument for '-n'\n");
		exit(2);
	}
	arg = ctx->argp[0];

	if (!strcmp(arg, "rx-flow-hash")) {
		return ethnl_get_hashopts(ctx);
	} else {
		fprintf(stderr, "ethtool: unknown argument '%s' for '-n'\n",
			arg);
		exit(2);
	}
}

/* SET_RXFLOW */

struct indtbl_weights {
	uint32_t	count;
	uint32_t	sum;
	uint32_t	*weights;
};

struct srxfh_data {
	uint32_t		context;
	struct byte_str_value	hkey;
	const char		*hfunc;
	uint32_t		equal;
	struct indtbl_weights	weight;
	bool			it_default;
	bool			ctx_delete;
};

static int srxfh_parse_context(struct nl_context *nlctx, uint16_t type,
			       const void *data, void *dest)
{
	const char *arg = nlctx->argp[0];
	uint32_t val;

	nlctx->argp++;
	nlctx->argc--;

	if (!strcmp(arg, "new")) {
		val = ETH_RXFH_CONTEXT_ALLOC;
	} else {
		int ret = parse_u32(arg, &val);

		if (ret < 0) {
			fprintf(stderr, "invalid RSS context id '%s'\n", arg);
			return -EINVAL;
		}
		if (val == ETH_RXFH_CONTEXT_ALLOC) {
			fprintf(stderr, "RSS context id 0x%08x is reserved\n",
				val);
			return -EINVAL;
		}
	}

	if (dest)
		*(uint32_t *)dest = val;
	return type ? ethnla_put_u32(nlctx, type, val) : 0;
}

static int srxfh_parse_weight(struct nl_context *nlctx, uint16_t type,
			      const void *parser_data, void *dest)
{
	struct indtbl_weights *data = dest;
	unsigned int i;
	char **argp;
	int ret;

	for (i = 0; i < nlctx->argc && strcmp(nlctx->argp[i], "--"); i++)
		;
	data->count = i;
	argp = nlctx->argp;
	nlctx->argp += i;
	nlctx->argc -= i;
	if (nlctx->argc && !strcmp(nlctx->argp[0], "--")) {
		nlctx->argp++;
		nlctx->argc--;
	}

	data->weights = calloc(data->count, sizeof(data->weights[0]));
	if (!data->weights)
		return -ENOMEM;

	for (i = 0; i < data->count; i++) {
		ret = parse_u32(argp[i], &data->weights[i]);
		if (ret < 0)
			goto err_free;
		data->sum += data->weights[i];
	}
	if (!data->sum) {
		fprintf(stderr, "At least one weight must be non-zero\n");
		ret = -EINVAL;
		goto err_free;
	}

	return 0;
err_free:
	free(data->weights);
	memset(data, '\0', sizeof(*data));
	return ret;
}

static const struct byte_str_params hkey_parser_data = {
	.min_len	= 1,
	.delim		= ':',
};

static const struct param_parser srxfh_params[] = {
	{
		.arg		= "context",
		.handler	= srxfh_parse_context,
		.min_argc	= 1,
		.dest_offset	= offsetof(struct srxfh_data, context),
	},
	{
		.arg		= "hkey",
		.handler	= nl_parse_byte_str,
		.handler_data	= &hkey_parser_data,
		.min_argc	= 1,
		.dest_offset	= offsetof(struct srxfh_data, hkey),
	},
	{
		.arg		= "hfunc",
		.handler	= nl_parse_string,
		.min_argc	= 1,
		.dest_offset	= offsetof(struct srxfh_data, hfunc),
	},
	{
		.arg		= "equal",
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
		.dest_offset	= offsetof(struct srxfh_data, equal),
	},
	{
		.arg		= "weight",
		.handler	= srxfh_parse_weight,
		.min_argc	= 1,
		.dest_offset	= offsetof(struct srxfh_data, weight),
	},
	{
		.arg		= "default",
		.handler	= nl_parse_flag,
		.dest_offset	= offsetof(struct srxfh_data, it_default),
	},
	{
		.arg		= "delete",
		.handler	= nl_parse_flag,
		.dest_offset	= offsetof(struct srxfh_data, ctx_delete),
	},
	{}
};

int srxfh_sanity_checks(const struct srxfh_data *data)
{
	if (data->ctx_delete &&
	    (!data->context || data->context == ETH_RXFH_CONTEXT_ALLOC)) {
		fprintf(stderr, "ethtool -X: 'delete' requires context id\n");
		return -EINVAL;
	}
	if (data->ctx_delete &&
	    (data->hkey.data || data->hfunc || data->equal ||
	     data->weight.count || data->it_default)) {
		fprintf(stderr, "ethtool -X: 'delete' cannot be combined with"
				" other arguments except 'context'\n");
		return -EINVAL;
	}
	if ((data->equal && (data->weight.count || data->it_default)) ||
	    (data->weight.count && data->it_default)) {
		fprintf(stderr, "ethtool -X: 'equal', 'weight' and 'default'"
				" are mutually exclusive\n");
		return -EINVAL;
	}
	if (data->context && data->it_default) {
		fprintf(stderr, "ethtool -X: 'default' is only allowed without"
				"context id\n");
		return -EINVAL;
	}

	return 0;
}

static int fill_indtbl_equal(struct nl_context *nlctx, uint32_t num)
{
	struct nlattr *patch;

	patch = ethnla_nest_start(nlctx, ETHTOOL_A_INDTBL_PATTERN);
	if (!patch)
		return -EMSGSIZE;

	if (ethnla_put_u32(nlctx, ETHTOOL_A_ITPAT_MIN_RING, 0) ||
	    ethnla_put_u32(nlctx, ETHTOOL_A_ITPAT_MAX_RING, num - 1)) {
		mnl_attr_nest_cancel(nlctx->nlhdr, patch);
		return -EMSGSIZE;
	}

	mnl_attr_nest_end(nlctx->nlhdr, patch);
	return 0;
}

static int fill_indtbl_weight(struct nl_context *nlctx,
			      const struct indtbl_weights *data)
{
	struct nlattr *patch;

	patch = ethnla_nest_start(nlctx, ETHTOOL_A_INDTBL_WEIGHTS);
	if (!patch)
		return -EMSGSIZE;

	if (ethnla_put(nlctx, ETHTOOL_A_ITWGHT_WEIGHTS,
		       data->count * sizeof(data->weights[0]),
		       data->weights)) {
		mnl_attr_nest_cancel(nlctx->nlhdr, patch);
		return -EMSGSIZE;
	}

	mnl_attr_nest_end(nlctx->nlhdr, patch);
	return 0;
}

static int fill_indtbl(struct nl_context *nlctx, const struct srxfh_data *data)
{
	struct nlattr *table;
	int ret;

	if (!data->equal && !data->weight.count && !data->it_default)
		return 0;
	table = ethnla_nest_start(nlctx, ETHTOOL_A_RXFLOW_INDIR_TBL);
	if (!table)
		return -EMSGSIZE;

	ret = 0;
	if (data->equal)
		ret = fill_indtbl_equal(nlctx, data->equal);
	if (data->weight.count)
		ret = fill_indtbl_weight(nlctx, &data->weight);
	if (ret < 0)
		goto err;

	/* if neither equal nor weight was used, it's default so sending
	 * an empty nested attribute is what we want
	 */
	mnl_attr_nest_end(nlctx->nlhdr, table);
	return 0;
err:
	mnl_attr_nest_cancel(nlctx->nlhdr, table);
	return ret;
}

static int fill_hfunc(struct nl_context *nlctx, const char *hashfn)
{
	struct nlmsghdr *nlhdr = nlctx->nlhdr;
	struct nlattr *bitset_attr;
	struct nlattr *bits_attr;
	struct nlattr *bit_attr;

	if (!hashfn)
		return 0;
	bitset_attr = ethnla_nest_start(nlctx, ETHTOOL_A_RXFLOW_HASH_FN);
	if (!bitset_attr)
		return -EMSGSIZE;
	if (ethnla_put_flag(nlctx, ETHTOOL_A_BITSET_LIST, true))
		return -EMSGSIZE;
	bits_attr = ethnla_nest_start(nlctx, ETHTOOL_A_BITSET_BITS);
	if (!bits_attr)
		goto err;
	bit_attr = ethnla_nest_start(nlctx, ETHTOOL_A_BITS_BIT);
	if (!bits_attr)
		goto err;

	if (ethnla_put_strz(nlctx, ETHTOOL_A_BIT_NAME, hashfn))
		goto err;

	mnl_attr_nest_end(nlhdr, bit_attr);
	mnl_attr_nest_end(nlhdr, bits_attr);
	mnl_attr_nest_end(nlhdr, bitset_attr);
	return 0;
err:
	mnl_attr_nest_cancel(nlhdr, bitset_attr);
	return -EMSGSIZE;
}

static int fill_srxfh(struct nl_context *nlctx, const struct srxfh_data *data)
{
	uint32_t op = ETHTOOL_RXFLOW_CTXOP_SET;
	uint32_t context = data->context;

	/* context delete request is special, handle it separately */
	if (data->ctx_delete) {
		if (ethnla_put_u32(nlctx, ETHTOOL_A_RXFLOW_CTXOP,
				   ETHTOOL_RXFLOW_CTXOP_DEL))
			return -EMSGSIZE;
		if (ethnla_put_u32(nlctx, ETHTOOL_A_RXFLOW_CONTEXT, context))
			return -EMSGSIZE;
		return 0;
	}

	if (context == ETH_RXFH_CONTEXT_ALLOC) {
		op = ETHTOOL_RXFLOW_CTXOP_NEW;
		context = 0;
	}
	if (ethnla_put_u32(nlctx, ETHTOOL_A_RXFLOW_CTXOP, op))
		return -EMSGSIZE;
	if (fill_hfunc(nlctx, data->hfunc))
		return -EMSGSIZE;
	if (data->hkey.data && ethnla_put(nlctx, ETHTOOL_A_RXFLOW_HASH_KEY,
					  data->hkey.len, data->hkey.data))
		return -EMSGSIZE;
	return fill_indtbl(nlctx, data);
}

int nl_srxfh(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct srxfh_data data = {};
	int ret;

	nlctx->cmd = "-X";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	ret = nl_parser(nlctx, srxfh_params, &data);
	if (ret < 0)
		return 2;
	ret = srxfh_sanity_checks(&data);
	if (ret < 0)
		return 2;

	ret = ethnl_prep_get_request(ctx, ETHNL_CMD_SET_RXFLOW,
				     ETHTOOL_A_RXFLOW_DEV);
	if (ret < 0)
		goto out_free;
	ret = fill_srxfh(nlctx, &data);
	if (ret < 0)
		goto out_free;

	ret = ethnl_send_get_request(nlctx, nomsg_reply_cb);
out_free:
	free(data.hkey.data);
	free(data.weight.weights);
	return ret;
}
