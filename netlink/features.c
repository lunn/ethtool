/*
 * features.c - netlink implementation of netdev features commands
 *
 * Implementation of "ethtool -k <dev>".
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "bitset.h"

/* FEATURES_GET */

struct feature_results {
	uint32_t	*hw;
	uint32_t	*wanted;
	uint32_t	*active;
	uint32_t	*nochange;
	unsigned int	count;
	unsigned int	words;
};

static int prepare_feature_results(const struct nlattr *const *tb,
				   struct feature_results *dest)
{
	unsigned int count;
	int ret;

	memset(dest, '\0', sizeof(*dest));
	if (!tb[ETHTOOL_A_FEATURES_HW] || !tb[ETHTOOL_A_FEATURES_WANTED] ||
	    !tb[ETHTOOL_A_FEATURES_ACTIVE] || !tb[ETHTOOL_A_FEATURES_NOCHANGE])
		return -EFAULT;
	count = bitset_get_count(tb[ETHTOOL_A_FEATURES_HW], &ret);
	if (ret < 0)
		return -EFAULT;
	if ((bitset_get_count(tb[ETHTOOL_A_FEATURES_WANTED], &ret) != count) ||
	    (bitset_get_count(tb[ETHTOOL_A_FEATURES_ACTIVE], &ret) != count) ||
	    (bitset_get_count(tb[ETHTOOL_A_FEATURES_NOCHANGE], &ret) != count))
		return -EFAULT;
	dest->hw = get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_HW]);
	dest->wanted = get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_WANTED]);
	dest->active = get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_ACTIVE]);
	dest->nochange =
		get_compact_bitset_value(tb[ETHTOOL_A_FEATURES_NOCHANGE]);
	if (!dest->hw || !dest->wanted || !dest->active || !dest->nochange)
		return -EFAULT;
	dest->count = count;
	dest->words = (count + 31) / 32;

	return 0;
}

static bool feature_on(const uint32_t *bitmap, unsigned int idx)
{
	return bitmap[idx / 32] & (1 << (idx % 32));
}

static void dump_feature(const struct feature_results *results,
			 const uint32_t *ref, const uint32_t *ref_mask,
			 unsigned int idx, const char *name, const char *prefix)
{
	const char *suffix = "";

	if (!name || !*name)
		return;
	if (ref) {
		if (ref_mask && !feature_on(ref_mask, idx))
			return;
		if ((!ref_mask || feature_on(ref_mask, idx)) &&
		    (feature_on(results->active, idx) == feature_on(ref, idx)))
			return;
	}

	if (!feature_on(results->hw, idx) || feature_on(results->nochange, idx))
		suffix = " [fixed]";
	else if (feature_on(results->active, idx) !=
		 feature_on(results->wanted, idx))
		suffix = feature_on(results->wanted, idx) ?
			" [requested on]" : " [requested off]";
	printf("%s%s: %s%s\n", prefix, name,
	       feature_on(results->active, idx) ? "on" : "off", suffix);
}

/* this assumes pattern contains no more than one asterisk */
static bool flag_pattern_match(const char *name, const char *pattern)
{
	const char *p_ast = strchr(pattern, '*');

	if (p_ast) {
		size_t name_len = strlen(name);
		size_t pattern_len = strlen(pattern);

		if (name_len + 1 < pattern_len)
			return false;
		if (strncmp(name, pattern, p_ast - pattern))
			return false;
		pattern_len -= (p_ast - pattern) + 1;
		name += name_len  - pattern_len;
		pattern = p_ast + 1;
	}
	return !strcmp(name, pattern);
}

int dump_features(const struct nlattr *const *tb,
		  const struct stringset *feature_names)
{
	struct feature_results results;
	unsigned int i, j;
	int *feature_flags = NULL;
	int ret;

	ret = prepare_feature_results(tb, &results);
	if (ret < 0)
		return -EFAULT;

	ret = -ENOMEM;
	feature_flags = calloc(results.count, sizeof(feature_flags[0]));
	if (!feature_flags)
		goto out_free;

	/* map netdev features to legacy flags */
	for (i = 0; i < results.count; i++) {
		const char *name = get_string(feature_names, i);
		feature_flags[i] = -1;

		if (!name || !*name)
			continue;
		for (j = 0; j < OFF_FLAG_DEF_SIZE; j++) {
			const char *flag_name = off_flag_def[j].kernel_name;

			if (flag_pattern_match(name, flag_name)) {
				feature_flags[i] = j;
				break;
			}
		}
	}
	/* show legacy flags and their matching features first */
	for (i = 0; i < OFF_FLAG_DEF_SIZE; i++) {
		unsigned int n_match = 0;
		bool flag_value = false;

		/* no kernel with netlink interface supports UFO */
		if (off_flag_def[i].value == ETH_FLAG_UFO)
			continue;

		for (j = 0; j < results.count; j++) {
			if (feature_flags[j] == i) {
				n_match++;
				flag_value = flag_value ||
					feature_on(results.active, j);
			}
		}
		if (n_match != 1)
			printf("%s: %s\n", off_flag_def[i].long_name,
			       flag_value ? "on" : "off");
		if (n_match == 0)
			continue;
		for (j = 0; j < results.count; j++) {
			const char *name = get_string(feature_names, j);

			if (feature_flags[j] != i)
				continue;
			if (n_match == 1)
				dump_feature(&results, NULL, NULL, j,
					     off_flag_def[i].long_name, "");
			else
				dump_feature(&results, NULL, NULL, j, name,
					     "\t");
		}
	}
	/* and, finally, remaining netdev_features not matching legacy flags */
	for (i = 0; i < results.count; i++) {
		const char *name = get_string(feature_names, i);

		if (!name || !*name || feature_flags[i] >= 0)
			continue;
		dump_feature(&results, NULL, NULL, i, name, "");
	}

out_free:
	free(feature_flags);
	return 0;
}

int features_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_FEATURES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const struct stringset *feature_names;
	struct nl_context *nlctx = data;
	bool silent;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	if (!nlctx->is_monitor) {
		ret = netlink_init_ethnl2_socket(nlctx);
		if (ret < 0)
			return MNL_CB_ERROR;
	}
	feature_names = global_stringset(ETH_SS_FEATURES, nlctx->ethnl2_socket);

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return silent ? MNL_CB_OK : MNL_CB_ERROR;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_FEATURES_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (silent)
		putchar('\n');
	printf("Features for %s:\n", nlctx->devname);
	ret = dump_features(tb, feature_names);
	return (silent || !ret) ? MNL_CB_OK : MNL_CB_ERROR;
}

int nl_gfeatures(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_FEATURES_GET,
				      ETHTOOL_A_FEATURES_HEADER,
				      ETHTOOL_FLAG_COMPACT_BITSETS);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, features_reply_cb);
}
