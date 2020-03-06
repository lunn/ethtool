/*
 * common.h - common code header
 *
 * Declarations for data and functions shared by ioctl and netlink code.
 */

#ifndef ETHTOOL_COMMON_H__
#define ETHTOOL_COMMON_H__

#include "internal.h"

#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

struct flag_info {
	const char *name;
	u32 value;
};

extern const struct flag_info flags_msglvl[];
extern const unsigned int n_flags_msglvl;

void print_flags(const struct flag_info *info, unsigned int n_info, u32 value);
int dump_wol(struct ethtool_wolinfo *wol);
void dump_mdix(u8 mdix, u8 mdix_ctrl);

#endif /* ETHTOOL_COMMON_H__ */
