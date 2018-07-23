#include <errno.h>
#include <string.h>

#include "../internal.h"
#include "netlink.h"

struct stringset {
	const char		**strings;
	void			*raw_data;
	unsigned int		count;
};

struct perdev_strings {
	int			ifindex;
	char			devname[IFNAMSIZ];
	struct stringset	strings[ETH_SS_COUNT];
	struct perdev_strings	*next;
};

/* universal string sets */
static struct stringset global_strings[ETH_SS_COUNT];
/* linked list of string sets related to network devices */
static struct perdev_strings *device_strings;

static void drop_stringset(struct stringset *set)
{
	if (!set)
		return;

	free(set->strings);
	free(set->raw_data);
	set->count = 0;
}

static int import_stringset(struct stringset *dest, const struct nlattr *nest)
{
	const struct nlattr *tb_stringset[ETHTOOL_A_STRINGSET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb_stringset);
	const struct nlattr *string;
	unsigned int size;
	unsigned int count;
	unsigned int idx;
	int ret;

	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_stringset_info);
	if (ret < 0)
		return ret;
	if (!tb_stringset[ETHTOOL_A_STRINGSET_ID] ||
	    !tb_stringset[ETHTOOL_A_STRINGSET_COUNT] ||
	    !tb_stringset[ETHTOOL_A_STRINGSET_STRINGS])
		return -EFAULT;
	idx = mnl_attr_get_u32(tb_stringset[ETHTOOL_A_STRINGSET_ID]);
	if (idx >= ETH_SS_COUNT)
		return 0;
	count = mnl_attr_get_u32(tb_stringset[ETHTOOL_A_STRINGSET_COUNT]);
	if (count == 0)
		return 0;

	size = mnl_attr_get_len(tb_stringset[ETHTOOL_A_STRINGSET_STRINGS]);
	ret = -ENOMEM;
	dest[idx].raw_data = malloc(size);
	if (!dest[idx].raw_data)
		goto err;
	memcpy(dest[idx].raw_data, tb_stringset[ETHTOOL_A_STRINGSET_STRINGS],
	       size);
	dest[idx].strings = calloc(count, sizeof(dest[idx].strings[0]));
	if (!dest[idx].strings)
		goto err;
	dest[idx].count = count;

	nest = dest[idx].raw_data;
	mnl_attr_for_each_nested(string, nest) {
		const struct nlattr *tb[ETHTOOL_A_STRING_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);
		unsigned int i;

		if (mnl_attr_get_type(string) != ETHTOOL_A_STRINGS_STRING)
			continue;
		ret = mnl_attr_parse_nested(string, attr_cb, &tb_info);
		if (ret < 0)
			goto err;
		ret = -EFAULT;
		if (!tb[ETHTOOL_A_STRING_INDEX] || !tb[ETHTOOL_A_STRING_VALUE])
			goto err;

		i = mnl_attr_get_u32(tb[ETHTOOL_A_STRING_INDEX]);
		if (i >= count)
			goto err;
		dest[idx].strings[i] =
			mnl_attr_get_payload(tb[ETHTOOL_A_STRING_VALUE]);
	}

	return 0;
err:
	drop_stringset(&dest[idx]);
	return ret;
}

static const char *stringset_names[] = {
	[ETH_SS_TEST] = "test",
	[ETH_SS_STATS] = "stats",
	[ETH_SS_PRIV_FLAGS] = "priv-flags",
	[ETH_SS_NTUPLE_FILTERS] = "ntuple-filters",
	[ETH_SS_FEATURES] = "features",
	[ETH_SS_RSS_HASH_FUNCS] = "rss-hash-funcs",
	[ETH_SS_TUNABLES] = "tunables",
	[ETH_SS_PHY_STATS] = "phy-stats",
	[ETH_SS_PHY_TUNABLES] = "phy-tunables",
	[ETH_SS_LINK_MODES] = "link-modes",
};

void debug_stringsets(const struct stringset *sets)
{
	unsigned int i;

	for (i = 0; i < ETH_SS_COUNT; i++) {
		if (sets[i].count > 0) {
			printf("    set %s, count %u\n", stringset_names[i],
			       sets[i].count);
		}
	}
}

void debug_strings()
{
	struct perdev_strings *pd;

	fputs("global strings:\n", stdout);
	debug_stringsets(global_strings);

	for (pd = device_strings; pd; pd = pd->next) {
		printf("strings for %s:\n", pd->devname);
		debug_stringsets(pd->strings);
	}
}

static int strset_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_STRSET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	char devname[IFNAMSIZ] = "";
	struct stringset *dest;
	struct nlattr *attr;
	int ifindex = 0;
	unsigned int i;
	int ret;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	if (tb[ETHTOOL_A_STRSET_DEV]) {
		ret = get_dev_info(tb[ETHTOOL_A_STRSET_DEV], &ifindex,
				   devname);
		if (ret < 0)
			return MNL_CB_OK;
		nlctx->devname = devname;
	}
	if (ifindex && !dev_ok(nlctx))
		return MNL_CB_OK;

	if (ifindex) {
		struct perdev_strings *perdev = device_strings;

		while (perdev && perdev->ifindex != ifindex)
			perdev = perdev->next;
		if (perdev) {
			for (i = 0; i < ETH_SS_COUNT; i++)
				drop_stringset(&perdev->strings[i]);
		} else {
			perdev = calloc(sizeof(*perdev), 1);
			if (!perdev)
				return -ENOMEM;
			perdev->ifindex = ifindex;
			copy_devname(perdev->devname, devname);
			perdev->next = device_strings;
			device_strings = perdev;
		}
		dest = perdev->strings;
	} else {
		for (i = 0; i < ETH_SS_COUNT; i++)
			drop_stringset(&global_strings[i]);
		dest = global_strings;
	}

	mnl_attr_for_each(attr, nlhdr, GENL_HDRLEN) {
		if (mnl_attr_get_type(attr) == ETHTOOL_A_STRSET_STRINGSET)
			import_stringset(dest, attr);
	}

	return MNL_CB_OK;
}

/* interface */

const struct stringset *global_stringset(unsigned int type)
{
	if (type >= ETH_SS_COUNT)
		return NULL;
	return &global_strings[type];
}

const struct stringset *perdev_stringset(const char *dev, unsigned int type)
{
	const struct perdev_strings *p;

	if (type >= ETH_SS_COUNT)
		return NULL;
	for (p = device_strings; p; p = p->next)
		if (!strcmp(p->devname, dev))
			return &p->strings[type];

	return NULL;
}

unsigned int get_count(const struct stringset *set)
{
	return set->count;
}

const char *get_string(const struct stringset *set, unsigned int idx)
{
	if (idx >= set->count)
		return NULL;
	return set->strings[idx];
}

int load_global_strings(struct nl_context *nlctx)
{
	int ret;

	ret = msg_init(nlctx, ETHNL_CMD_GET_STRSET, NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return ret;
	ret = ethnl_send_get_request(nlctx, strset_reply_cb);
	return ret;
}

int load_perdev_strings(struct nl_context *nlctx, const char *dev)
{
	int ret;

	ret = msg_init(nlctx, ETHNL_CMD_GET_STRSET,
		       NLM_F_REQUEST | NLM_F_ACK | (dev ? 0 : NLM_F_DUMP));
	if (ret < 0)
		return ret;
	if (dev) {
		if (ethnla_put_dev(nlctx, ETHTOOL_A_STRSET_DEV, dev))
			return -EMSGSIZE;
	}
	ret = ethnl_send_get_request(nlctx, strset_reply_cb);
	return ret;
}

void free_perdev_strings(const char *devname)
{
	struct perdev_strings **p = &device_strings;
	unsigned int i;

	p = &device_strings;
	while (*p) {
		struct perdev_strings *perdev = *p;

		if (devname && strcmp(perdev->devname, devname)) {
			p = &((*p)->next);
			continue;
		}
		*p = perdev->next;
		for (i = 0; i < ETH_SS_COUNT; i++)
			drop_stringset(&perdev->strings[i]);
		free(perdev);
	}

	if (!devname) {
		for (i = 0; i < ETH_SS_COUNT; i++)
			drop_stringset(&global_strings[i]);
	}
}

int rename_perdev_strings(int ifindex, const char *newname, char *oldname)
{
	struct perdev_strings *perdev = device_strings;

	while (perdev && perdev->ifindex != ifindex)
		perdev = perdev->next;
	if (!perdev)
		return -ENODEV;

	if (oldname)
		copy_devname(oldname, perdev->devname);
	copy_devname(perdev->devname, newname);
	return 0;
}

void cleanup_all_strings(void)
{
	struct perdev_strings *perdev;
	unsigned int i;

	for (i = 0; i < ETH_SS_COUNT; i++)
		drop_stringset(&global_strings[i]);

	perdev = device_strings;
	while (perdev) {
		device_strings = perdev->next;
		for (i = 0; i < ETH_SS_COUNT; i++)
			drop_stringset(&perdev->strings[i]);
		free(perdev);
		perdev = device_strings;
	}
}
