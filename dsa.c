#include <stdio.h>
#include <string.h>

#include "internal.h"

int dsa_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs)
{
	/* DSA per-driver register dump */

	/* Fallback to hexdump */
	return 1;
}
