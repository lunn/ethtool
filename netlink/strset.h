#ifndef ETHTOOL_NETLINK_STRSET_H__
#define ETHTOOL_NETLINK_STRSET_H__

struct stringset;

const struct stringset *global_stringset(unsigned int type);
const struct stringset *perdev_stringset(const char *dev, unsigned int type);

unsigned int get_count(const struct stringset *set);
const char *get_string(const struct stringset *set, unsigned int idx);

int load_global_strings(struct nl_context *nlctx);
int load_perdev_strings(struct nl_context *nlctx, const char *dev);
void free_perdev_strings(const char *devname);
int rename_perdev_strings(int ifindex, const char *newname, char *oldname);
void cleanup_all_strings(void);

#endif /* ETHTOOL_NETLINK_STRSET_H__ */
