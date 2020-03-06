/*
 * desc-genlctrl.c - genetlink control format descriptions
 *
 * Descriptions of genetlink control messages and attributes for pretty print.
 */

#include <linux/genetlink.h>

#include "../internal.h"
#include "prettymsg.h"

static const struct pretty_nla_desc __attrop_desc[] = {
	NLATTR_DESC_INVALID(CTRL_ATTR_OP_UNSPEC),
	NLATTR_DESC_U32(CTRL_ATTR_OP_ID),
	NLATTR_DESC_X32(CTRL_ATTR_OP_FLAGS),
};

static const struct pretty_nla_desc __attrops_desc[] = {
	NLATTR_DESC_NESTED(0, attrop),
};

static const struct pretty_nla_desc __mcgrp_desc[] = {
	NLATTR_DESC_INVALID(CTRL_ATTR_MCAST_GRP_UNSPEC),
	NLATTR_DESC_STRING(CTRL_ATTR_MCAST_GRP_NAME),
	NLATTR_DESC_U32(CTRL_ATTR_MCAST_GRP_ID),
};

static const struct pretty_nla_desc __mcgrps_desc[] = {
	NLATTR_DESC_NESTED(0, mcgrp),
};

static const struct pretty_nla_desc __attr_desc[] = {
	NLATTR_DESC_INVALID(CTRL_ATTR_UNSPEC),
	NLATTR_DESC_U16(CTRL_ATTR_FAMILY_ID),
	NLATTR_DESC_STRING(CTRL_ATTR_FAMILY_NAME),
	NLATTR_DESC_U32(CTRL_ATTR_VERSION),
	NLATTR_DESC_U32(CTRL_ATTR_HDRSIZE),
	NLATTR_DESC_U32(CTRL_ATTR_MAXATTR),
	NLATTR_DESC_ARRAY(CTRL_ATTR_OPS, attrops),
	NLATTR_DESC_ARRAY(CTRL_ATTR_MCAST_GROUPS, mcgrps),
};

const struct pretty_nlmsg_desc genlctrl_msg_desc[] = {
	NLMSG_DESC_INVALID(CTRL_CMD_UNSPEC),
	NLMSG_DESC(CTRL_CMD_NEWFAMILY, attr),
	NLMSG_DESC(CTRL_CMD_DELFAMILY, attr),
	NLMSG_DESC(CTRL_CMD_GETFAMILY, attr),
	NLMSG_DESC(CTRL_CMD_NEWOPS, attr),
	NLMSG_DESC(CTRL_CMD_DELOPS, attr),
	NLMSG_DESC(CTRL_CMD_GETOPS, attr),
	NLMSG_DESC(CTRL_CMD_NEWMCAST_GRP, attr),
	NLMSG_DESC(CTRL_CMD_DELMCAST_GRP, attr),
	NLMSG_DESC(CTRL_CMD_GETMCAST_GRP, attr),
};

const unsigned int genlctrl_msg_n_desc = ARRAY_SIZE(genlctrl_msg_desc);
