#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "parser.h"

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

