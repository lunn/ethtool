#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "extapi.h"
#include "strset.h"

/* misc helpers */

unsigned int nl_copy_payload(void *buff, unsigned int maxlen,
			     const struct nlattr *attr)
{
	unsigned int len = mnl_attr_get_payload_len(attr);

	if (len > maxlen)
		len = maxlen;
	memcpy(buff, mnl_attr_get_payload(attr), len);

	return len;
}

/* standard attribute parser callback
 * While we trust kernel not to send us malformed messages, we must expect
 * to run on top of newer kernel which may send attributes that we do not
 * know (yet). Rather than treating them as an error, just ignore them.
 */
int attr_cb(const struct nlattr *attr, void *data)
{
	const struct attr_tb_info *tb_info = data;
	int type = mnl_attr_get_type(attr);

	if (type >= 0 && type <= tb_info->max_type)
		tb_info->tb[type] = attr;

	return MNL_CB_OK;
}

uint32_t bitset_get_count(const struct nlattr *bitset, int *retptr)
{
	const struct nlattr *attr;

	mnl_attr_for_each_nested(attr, bitset) {
		if (mnl_attr_get_type(attr) != ETHTOOL_A_BITSET_SIZE)
			continue;
		*retptr = 0;
		return mnl_attr_get_u32(attr);
	}

	*retptr = -EFAULT;
	return 0;
}

bool bitset_get_bit(const struct nlattr *bitset, bool mask, unsigned int idx,
		    int *retptr)
{
	const struct nlattr *bitset_tb[ETHTOOL_A_BITSET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(bitset_tb);
	const struct nlattr *bits;
	const struct nlattr *bit;
	int ret;

	*retptr = 0;
	ret = mnl_attr_parse_nested(bitset, attr_cb, &bitset_tb_info);
	if (ret < 0)
		goto err;

	bits = mask ? bitset_tb[ETHTOOL_A_BITSET_MASK] :
		      bitset_tb[ETHTOOL_A_BITSET_VALUE];
	if (bits) {
		const uint32_t *bitmap =
			(const uint32_t *)mnl_attr_get_payload(bits);

		if (idx >= 8 * mnl_attr_get_payload_len(bits))
			return false;
		return bitmap[idx / 32] & (1U << (idx % 32));
	}

	bits = bitset_tb[ETHTOOL_A_BITSET_BITS];
	if (!bits)
		goto err;
	mnl_attr_for_each_nested(bit, bits) {
		const struct nlattr *tb[ETHTOOL_A_BIT_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);
		unsigned int my_idx;

		if (mnl_attr_get_type(bit) != ETHTOOL_A_BITS_BIT)
			continue;
		ret = mnl_attr_parse_nested(bit, attr_cb, &tb_info);
		if (ret < 0)
			goto err;
		ret = -EFAULT;
		if (!tb[ETHTOOL_A_BIT_INDEX])
			goto err;

		my_idx = mnl_attr_get_u32(tb[ETHTOOL_A_BIT_INDEX]);
		if (my_idx == idx)
			return mask || tb[ETHTOOL_A_BIT_VALUE];
	}

	return false;
err:
	fprintf(stderr, "malformed netlink message (bitset)\n");
	*retptr = ret;
	return false;
}

bool bitset_is_empty(const struct nlattr *bitset, bool mask, int *retptr)
{
	const struct nlattr *bitset_tb[ETHTOOL_A_BITSET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(bitset_tb);
	const struct nlattr *bits;
	const struct nlattr *bit;
	int ret;

	*retptr = 0;
	ret = mnl_attr_parse_nested(bitset, attr_cb, &bitset_tb_info);
	if (ret < 0)
		goto err;

	bits = mask ? bitset_tb[ETHTOOL_A_BITSET_MASK] :
		      bitset_tb[ETHTOOL_A_BITSET_VALUE];
	if (bits) {
		const uint32_t *bitmap =
			(const uint32_t *)mnl_attr_get_payload(bits);
		unsigned int n = mnl_attr_get_payload_len(bits);
		unsigned int i;

		ret = -EFAULT;
		if (n % 4)
			goto err;
		for (i = 0; i < n / 4; i++)
			if (bitmap[i])
				return false;
		return true;
	}

	bits = bitset_tb[ETHTOOL_A_BITSET_BITS];
	if (!bits)
		goto err;
	mnl_attr_for_each_nested(bit, bits) {
		const struct nlattr *tb[ETHTOOL_A_BIT_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);

		if (mnl_attr_get_type(bit) != ETHTOOL_A_BITS_BIT)
			continue;
		if (mask || bitset_tb[ETHTOOL_A_BITSET_LIST])
			return false;

		ret = mnl_attr_parse_nested(bit, attr_cb, &tb_info);
		if (ret < 0)
			goto err;
		if (tb[ETHTOOL_A_BIT_VALUE])
			return false;
	}

	return true;
err:
	fprintf(stderr, "malformed netlink message (bitset)\n");
	*retptr = ret;
	return true;
}

int walk_bitset(const struct nlattr *bitset, const struct stringset *labels,
		bitset_walk_callback cb, void *data)
{
	const struct nlattr *bitset_tb[ETHTOOL_A_BITSET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(bitset_tb);
	const struct nlattr *bits;
	const struct nlattr *bit;
	bool is_list;
	int ret;

	ret = mnl_attr_parse_nested(bitset, attr_cb, &bitset_tb_info);
	if (ret < 0)
		return ret;
	is_list = bitset_tb[ETHTOOL_A_BITSET_LIST];

	bits = bitset_tb[ETHTOOL_A_BITSET_VALUE];
	if (bits) {
		const struct nlattr *mask = bitset_tb[ETHTOOL_A_BITSET_MASK];
		unsigned int count, nwords, idx;
		uint32_t *val_bm;
		uint32_t *mask_bm;

		if (!bitset_tb[ETHTOOL_A_BITSET_SIZE])
			return -EFAULT;
		count = mnl_attr_get_u32(bitset_tb[ETHTOOL_A_BITSET_SIZE]);
		nwords = (count + 31) / 32;
		if ((mnl_attr_get_payload_len(bits) / 4 < nwords) ||
		    (mask && mnl_attr_get_payload_len(mask) / 4 < nwords))
			return -EFAULT;

		val_bm = mnl_attr_get_payload(bits);
		mask_bm = mask ? mnl_attr_get_payload(mask) : NULL;
		for (idx = 0; idx < count; idx++)
			if (!mask_bm || (mask_bm[idx / 32] & (1 << (idx % 32))))
				cb(idx, get_string(labels, idx),
				   val_bm[idx / 32] & (1 << (idx % 32)), data);
		return 0;
	}

	bits = bitset_tb[ETHTOOL_A_BITSET_BITS];
	if (!bits)
		return -EFAULT;
	mnl_attr_for_each_nested(bit, bits) {
		const struct nlattr *tb[ETHTOOL_A_BIT_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);
		const char *name;
		unsigned int idx;

		if (mnl_attr_get_type(bit) != ETHTOOL_A_BITS_BIT)
			continue;

		ret = mnl_attr_parse_nested(bit, attr_cb, &tb_info);
		if (ret < 0 ||
		    !tb[ETHTOOL_A_BIT_INDEX] || !tb[ETHTOOL_A_BIT_NAME])
			return -EFAULT;

		idx = mnl_attr_get_u32(tb[ETHTOOL_A_BIT_INDEX]);
		name = mnl_attr_get_str(tb[ETHTOOL_A_BIT_NAME]);
		cb(idx, name, is_list || tb[ETHTOOL_A_BIT_VALUE], data);
	}

	return 0;
}

static int msg_realloc(struct nl_context *nlctx, unsigned int new_size)
{
	unsigned int nlhdr_offset = (char *)nlctx->nlhdr - nlctx->buff;
	unsigned int gnlhdr_offset = (char *)nlctx->gnlhdr - nlctx->buff;
	unsigned int msg_offset = (char *)nlctx->msg - nlctx->buff;
	unsigned int old_size = nlctx->buffsize;
	char *new_buff;

	if (!new_size)
		new_size = old_size + MNL_SOCKET_BUFFER_SIZE;
	if (new_size <= old_size)
		return 0;
	if (new_size > MAX_MSG_SIZE)
		return -EMSGSIZE;
	new_buff = realloc(nlctx->buff, new_size);
	if (!new_buff) {
		nlctx->buff = NULL;
		nlctx->buffsize = 0;
		return -ENOMEM;
	}
	if (new_buff != nlctx->buff) {
		if (new_size > old_size)
			memset(new_buff + old_size, '\0', new_size - old_size);
		nlctx->nlhdr = (struct nlmsghdr *)(new_buff + nlhdr_offset);
		nlctx->gnlhdr = (struct genlmsghdr *)(new_buff + gnlhdr_offset);
		nlctx->msg = new_buff + msg_offset;
		nlctx->buff = new_buff;
	}
	nlctx->buffsize = new_size;

	return 0;
}

static int __msg_init(struct nl_context *nlctx, int family, int cmd,
		      unsigned int flags, int version)
{
	struct nlmsghdr *nlhdr;
	struct genlmsghdr *gnlhdr;
	int ret;

	ret = msg_realloc(nlctx, MNL_SOCKET_BUFFER_SIZE);
	if (ret < 0)
		return ret;
	nlctx->seq++;
	memset(nlctx->buff, '\0', NLMSG_HDRLEN + GENL_HDRLEN);

	nlhdr = mnl_nlmsg_put_header(nlctx->buff);
	nlhdr->nlmsg_type = family;
	nlhdr->nlmsg_flags = flags;
	nlhdr->nlmsg_seq = nlctx->seq;
	nlctx->nlhdr = nlhdr;

	gnlhdr = mnl_nlmsg_put_extra_header(nlhdr, sizeof(*gnlhdr));
	gnlhdr->cmd = cmd;
	gnlhdr->version = version;
	nlctx->gnlhdr = gnlhdr;

	return 0;
}

int msg_init(struct nl_context *nlctx, int cmd, unsigned int flags)
{
	int ret;

	ret = __msg_init(nlctx, nlctx->ethnl_fam, cmd, flags,
			 ETHTOOL_GENL_VERSION);
	if (ret < 0)
		return ret;
	nlctx->msg = mnl_nlmsg_get_payload_offset(nlctx->nlhdr, GENL_HDRLEN);

	return 0;
}

static int ethnl_process_ack(struct nl_context *nlctx, ssize_t len)
{
	struct nlmsghdr *nlhdr = (struct nlmsghdr *)nlctx->buff;
	struct nlmsgerr *nlerr = mnl_nlmsg_get_payload(nlhdr);
	const struct nlattr *tb[NLMSGERR_ATTR_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	unsigned int tlv_offset = sizeof(*nlerr);

	if (len < NLMSG_HDRLEN + sizeof(*nlerr))
		return -EFAULT;
	if (nlctx->suppress_nlerr || !(nlhdr->nlmsg_flags & NLM_F_ACK_TLVS))
		goto out;
	if (!(nlhdr->nlmsg_flags & NLM_F_CAPPED))
		tlv_offset += MNL_ALIGN(mnl_nlmsg_get_payload_len(&nlerr->msg));

	if (mnl_attr_parse(nlhdr, tlv_offset, attr_cb, &tb_info) < 0)
		goto out;
	if (tb[NLMSGERR_ATTR_MSG]) {
		const char *msg = mnl_attr_get_str(tb[NLMSGERR_ATTR_MSG]);

		fprintf(stderr, "netlink %s: %s\n",
			nlerr->error ? "error" : "warning", msg);
	}

out:
	if (nlerr->error) {
		errno = -nlerr->error;
		if (!nlctx->suppress_nlerr)
			perror("netlink error");
	}
	return nlerr->error;
}

static const char *ethnl_cmd_names[] = {
	[ETHNL_CMD_NOOP]		= "NOOP",
	[ETHNL_CMD_EVENT]		= "EVENT",
	[ETHNL_CMD_GET_STRSET]		= "GET_STRSET",
	[ETHNL_CMD_SET_STRSET]		= "SET_STRSET",
	[ETHNL_CMD_GET_INFO]		= "GET_INFO",
	[ETHNL_CMD_SET_INFO]		= "SET_INFO",
	[ETHNL_CMD_GET_SETTINGS]	= "GET_SETTINGS",
	[ETHNL_CMD_SET_SETTINGS]	= "SET_SETTINGS",
	[ETHNL_CMD_GET_PARAMS]		= "GET_PARAMS",
	[ETHNL_CMD_SET_PARAMS]		= "SET_PARAMS",
	[ETHNL_CMD_ACT_NWAY_RST]	= "ACT_NWAY_RST",
	[ETHNL_CMD_ACT_PHYS_ID]		= "ACT_PHYS_ID",
	[ETHNL_CMD_ACT_RESET]		= "ACT_RESET",
	[ETHNL_CMD_GET_RXFLOW]		= "GET_RXFLOW",
	[ETHNL_CMD_SET_RXFLOW]		= "SET_RXFLOW",
};

static const char *type_str(unsigned int type, unsigned int ethnl_fam)
{
	if (type == ethnl_fam)
		return "ethtool";

	switch(type) {
	case NLMSG_NOOP:
		return "noop";
	case NLMSG_ERROR:
		return "error";
	case NLMSG_DONE:
		return "done";
	case NLMSG_OVERRUN:
		return "overrun";
	case GENL_ID_CTRL:
		return "genl-ctrl";
	}

	return "unknown";
}

static void debug_msg_summary(struct nl_context *nlctx,
			      const struct nlmsghdr *nlhdr)
{
	fprintf(stderr, "    msg length %u family %u (%s) flags %04x",
		nlhdr->nlmsg_len, nlhdr->nlmsg_type,
		type_str(nlhdr->nlmsg_type, nlctx->ethnl_fam),
		nlhdr->nlmsg_flags);
	if (nlhdr->nlmsg_type == nlctx->ethnl_fam &&
	    nlhdr->nlmsg_len >= NLMSG_HDRLEN + GENL_HDRLEN) {
		const struct genlmsghdr *ghdr = mnl_nlmsg_get_payload(nlhdr);
		unsigned int cmd = ghdr->cmd;
		const char *cmd_name = "unknown";

		if (cmd < MNL_ARRAY_SIZE(ethnl_cmd_names) &&
		    ethnl_cmd_names[cmd])
			cmd_name = ethnl_cmd_names[cmd];
		fprintf(stderr, " ethtool cmd %u (%s)", cmd, cmd_name);
	}
	fputc('\n', stderr);
}

static void debug_msg(struct nl_context *nlctx, const void *data,
		      unsigned len, bool outgoing)
{
	bool summary = debug_on(nlctx->debug, DEBUG_NL_MSGS);
	bool dump = debug_on(nlctx->debug,
			     outgoing ? DEBUG_NL_DUMP_SND : DEBUG_NL_DUMP_RCV);
	const char *dirlabel = outgoing ? "sending" : "received";
	const struct nlmsghdr *nlhdr = data;
	int left = len;

	if (!summary && !dump)
		return;
	fprintf(stderr, "%s packet (%u bytes):\n", dirlabel, len);

	while (nlhdr && left > 0 && mnl_nlmsg_ok(nlhdr, left)) {
		if (summary)
			debug_msg_summary(nlctx, nlhdr);
		if (dump)
			mnl_nlmsg_fprintf(stderr, nlhdr, nlhdr->nlmsg_len,
					  GENL_HDRLEN);

		nlhdr = mnl_nlmsg_next(nlhdr, &left);
	}
}

int ethnl_process_reply(struct nl_context *nlctx, mnl_cb_t reply_cb)
{
	struct nlmsghdr *nlhdr;
	ssize_t len;
	int ret;

	do {
		msg_realloc(nlctx, 65536);
		len = mnl_socket_recvfrom(nlctx->sk, nlctx->buff,
					  nlctx->buffsize);
		if (len <= 0)
			return (len ? -EFAULT : 0);
		debug_msg(nlctx, nlctx->buff, len, false);
		if (len < NLMSG_HDRLEN)
			return -EFAULT;

		nlhdr = (struct nlmsghdr *)nlctx->buff;
		if (nlhdr->nlmsg_type == NLMSG_ERROR)
			return ethnl_process_ack(nlctx, len);

		nlctx->nlhdr = nlhdr;
		nlctx->gnlhdr = mnl_nlmsg_get_payload(nlhdr);
		nlctx->msg = mnl_nlmsg_get_payload_offset(nlhdr, GENL_HDRLEN);
		ret = mnl_cb_run(nlctx->buff, len, nlctx->seq, nlctx->port,
				 reply_cb, nlctx);
	} while (ret > 0);

	return ret;
}

/* safe message composition */

bool ethnla_put(struct nl_context *nlctx, uint16_t type, size_t len,
		const void *data)
{
	struct nlmsghdr *nlhdr = nlctx->nlhdr;

	while (!mnl_attr_put_check(nlhdr, nlctx->buffsize, type, len, data)) {
		int ret = msg_realloc(nlctx, 0);

		if (ret < 0)
			return true;
	}

	return false;
}

struct nlattr *ethnla_nest_start(struct nl_context *nlctx, uint16_t type)
{
	struct nlmsghdr *nlhdr = nlctx->nlhdr;
	struct nlattr *attr;

	do {
		attr = mnl_attr_nest_start_check(nlhdr, nlctx->buffsize, type);
		if (attr)
			return attr;
	} while (msg_realloc(nlctx, 0) == 0);

	return NULL;
}

bool ethnla_put_dev(struct nl_context *nlctx, uint16_t type,
		    const char *devname)
{
	struct nlattr *nest = ethnla_nest_start(nlctx, type);
	struct nlmsghdr *nlhdr = nlctx->nlhdr;

	if (!nest)
		return true;
	if (ethnla_put_strz(nlctx, ETHTOOL_A_DEV_NAME, devname)) {
		mnl_attr_nest_cancel(nlhdr, nest);
		return true;
	}
	mnl_attr_nest_end(nlhdr, nest);

	return false;
}

const char *get_dev_name(const struct nlattr *nest)
{
	const struct nlattr *dev_tb[ETHTOOL_A_DEV_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(dev_tb);
	int ret;

	if (!nest)
		return NULL;
	ret = mnl_attr_parse_nested(nest, attr_cb, &dev_tb_info);
	if (ret < 0 || !dev_tb[ETHTOOL_A_DEV_NAME])
		return "(none)";
	return mnl_attr_get_str(dev_tb[ETHTOOL_A_DEV_NAME]);
}

int get_dev_info(const struct nlattr *nest, int *ifindex, char *ifname)
{
	const struct nlattr *dev_tb[ETHTOOL_A_DEV_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(dev_tb);
	int ret;

	if (ifindex)
		*ifindex = 0;
	if (ifname)
		memset(ifname, '\0', IFNAMSIZ);

	if (!nest)
		return -EFAULT;
	ret = mnl_attr_parse_nested(nest, attr_cb, &dev_tb_info);
	if (ret < 0 ||
	    (ifindex && !dev_tb[ETHTOOL_A_DEV_INDEX]) ||
	    (ifname && !dev_tb[ETHTOOL_A_DEV_NAME]))
		return -EFAULT;

	if (ifindex)
		*ifindex = mnl_attr_get_u32(dev_tb[ETHTOOL_A_DEV_INDEX]);
	if (ifname) {
		strncpy(ifname, mnl_attr_get_str(dev_tb[ETHTOOL_A_DEV_NAME]),
			IFNAMSIZ);
		if (ifname[IFNAMSIZ - 1]) {
			ifname[IFNAMSIZ - 1] = '\0';
			fprintf(stderr, "kernel device name too long: '%s'\n",
				mnl_attr_get_str(dev_tb[ETHTOOL_A_DEV_NAME]));
			return -EFAULT;
		}
	}
	return 0;
}

int dump_link_modes(const struct nlattr *bitset, bool mask, unsigned class,
		    const char *before, const char *between, const char *after,
		    const char *if_none)
{
	const struct nlattr *bitset_tb[ETHTOOL_A_BITSET_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(bitset_tb);
	const unsigned int before_len = strlen(before);
	const struct nlattr *bits;
	const struct nlattr *bit;
	bool first = true;
	int prev = -2;
	int ret;

	ret = mnl_attr_parse_nested(bitset, attr_cb, &bitset_tb_info);
	bits = bitset_tb[ETHTOOL_A_BITSET_BITS];
	if (ret < 0)
		goto err_nonl;
	if (!bits) {
		const struct stringset *lm_strings =
			global_stringset(ETH_SS_LINK_MODES);
		unsigned int count;
		unsigned int idx;
		const char *name;

		bits = mask ? bitset_tb[ETHTOOL_A_BITSET_MASK] :
			      bitset_tb[ETHTOOL_A_BITSET_VALUE];
		ret = -EFAULT;
		if (!bits || !bitset_tb[ETHTOOL_A_BITSET_SIZE])
			goto err_nonl;
		count = mnl_attr_get_u32(bitset_tb[ETHTOOL_A_BITSET_SIZE]);
		if (mnl_attr_get_payload_len(bits) / 4 < (count + 31) / 32)
			goto err_nonl;

		printf("\t%s", before);
		for (idx = 0; idx < count; idx++) {
			const uint32_t *raw_data = mnl_attr_get_payload(bits);
			char buff[10];

			if (!(raw_data[idx / 32] & (1U << (idx % 32))))
				continue;
			if (!lm_class_match(idx, class))
				continue;
			name = get_string(lm_strings, idx);
			if (!name) {
				snprintf(buff, sizeof(buff), "BIT%u", idx);
				name = buff;
			}
			if (first)
				first = false;
			/* ugly hack to preserve old output format */
			if ((class == LM_CLASS_REAL) && (prev == idx - 1) &&
			    (prev < link_modes_count) &&
			    (link_modes[prev].class == LM_CLASS_REAL) &&
			    (link_modes[prev].duplex == DUPLEX_HALF))
				putchar(' ');
			else if (between)
				printf("\t%s", between);
			else
				printf("\n\t%*s", before_len, "");
			printf("%s", name);
			prev = idx;
		}
		goto after;
	}

	printf("\t%s", before);
	mnl_attr_for_each_nested(bit, bits) {
		const struct nlattr *tb[ETHTOOL_A_BIT_MAX + 1] = {};
		DECLARE_ATTR_TB_INFO(tb);
		unsigned int idx;
		const char *name;

		if (mnl_attr_get_type(bit) != ETHTOOL_A_BITS_BIT)
			continue;
		ret = mnl_attr_parse_nested(bit, attr_cb, &tb_info);
		if (ret < 0)
			goto err;
		ret = -EFAULT;
		if (!tb[ETHTOOL_A_BIT_INDEX] || !tb[ETHTOOL_A_BIT_NAME])
			goto err;
		if (!mask && !tb[ETHTOOL_A_BIT_VALUE])
			continue;

		idx = mnl_attr_get_u32(tb[ETHTOOL_A_BIT_INDEX]);
		name = mnl_attr_get_str(tb[ETHTOOL_A_BIT_NAME]);
		if (!lm_class_match(idx, class))
			continue;
		if (first) {
			first = false;
		} else {
			/* ugly hack to preserve old output format */
			if ((class == LM_CLASS_REAL) && (prev == idx - 1) &&
			    (prev < link_modes_count) &&
			    (link_modes[prev].class == LM_CLASS_REAL) &&
			    (link_modes[prev].duplex == DUPLEX_HALF))
				putchar(' ');
			else if (between)
				printf("\t%s", between);
			else
				printf("\n\t%*s", before_len, "");
		}
		printf("%s", name);
		prev = idx;
	}
after:
	if (first && if_none)
		printf("%s", if_none);
	printf(after);

	return 0;
err:
	putchar('\n');
err_nonl:
	fflush(stdout);
	fprintf(stderr, "malformed netlink message (link_modes)\n");
	return ret;
}

/* request helpers */

int ethnl_prep_get_request(struct cmd_context *ctx, unsigned int nlcmd,
			   uint16_t dev_attrtype)
{
	bool is_dev = ctx->devname && strcmp(ctx->devname, WILDCARD_DEVNAME);
	struct nl_context *nlctx = ctx->nlctx;
	int ret;

	nlctx->is_dump = !is_dev;
	ret = msg_init(nlctx, nlcmd,
		       NLM_F_REQUEST | NLM_F_ACK | (is_dev ? 0 : NLM_F_DUMP));
	if (ret < 0)
		return ret;

	if (is_dev) {
		if (ethnla_put_dev(nlctx, dev_attrtype, ctx->devname))
			return -EMSGSIZE;
	}

	return 0;
}

ssize_t ethnl_sendmsg(struct nl_context *nlctx)
{
	struct nlmsghdr *nlhdr = nlctx->nlhdr;

	debug_msg(nlctx, nlctx->buff, nlhdr->nlmsg_len, true);
	return mnl_socket_sendto(nlctx->sk, nlhdr, nlhdr->nlmsg_len);
}

int ethnl_send_get_request(struct nl_context *nlctx, mnl_cb_t cb)
{
	int ret;

	ret = ethnl_sendmsg(nlctx);
	if (ret < 0)
		goto err;
	ret = ethnl_process_reply(nlctx, cb);
	if (ret == 0)
		return 0;
err:
	return nlctx->exit_code ?: 1;
}

/* get ethtool family id */

static void ethnl_find_monitor_group(struct nl_context *nlctx,
				     struct nlattr *nest)
{
	const struct nlattr *grp_tb[CTRL_ATTR_MCAST_GRP_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(grp_tb);
	struct nlattr *grp_attr;
	int ret;

	nlctx->mon_mcgrp_id = 0;
	mnl_attr_for_each_nested(grp_attr, nest) {
		ret = mnl_attr_parse_nested(grp_attr, attr_cb, &grp_tb_info);
		if (ret < 0)
			return;
		if (!grp_tb[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !grp_tb[CTRL_ATTR_MCAST_GRP_ID])
			continue;
		if (strcmp(mnl_attr_get_str(grp_tb[CTRL_ATTR_MCAST_GRP_NAME]),
			   ETHTOOL_MCGRP_MONITOR_NAME))
			continue;
		nlctx->mon_mcgrp_id =
			mnl_attr_get_u32(grp_tb[CTRL_ATTR_MCAST_GRP_ID]);
		return;
	}
}

static int ethnl_family_cb(const struct nlmsghdr *nlhdr, void *data)
{
	struct nl_context *nlctx = data;
	struct nlattr *attr;

	nlctx->ethnl_fam = 0;
	mnl_attr_for_each(attr, nlhdr, GENL_HDRLEN) {
		switch(mnl_attr_get_type(attr)) {
		case CTRL_ATTR_FAMILY_ID:
			nlctx->ethnl_fam = mnl_attr_get_u16(attr);
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			ethnl_find_monitor_group(nlctx, attr);
			break;
		}
	}

	return (nlctx->ethnl_fam ? MNL_CB_OK : MNL_CB_ERROR);
}

static int get_ethnl_family(struct nl_context *nlctx)
{
	int ret;

	nlctx->suppress_nlerr = true;
	ret = __msg_init(nlctx, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			 NLM_F_REQUEST | NLM_F_ACK, 1);
	if (ret < 0)
		return ret;
	mnl_attr_put_strz(nlctx->nlhdr, CTRL_ATTR_FAMILY_NAME,
			  ETHTOOL_GENL_NAME);

	ethnl_sendmsg(nlctx);
	ethnl_process_reply(nlctx, ethnl_family_cb);
	if (!nlctx->ethnl_fam)
		return -EADDRNOTAVAIL;

	nlctx->suppress_nlerr = false;
	return 0;
}

int nomsg_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);

	fprintf(stderr, "received unexpected message: len=%u type=%u cmd=%u\n",
	       nlhdr->nlmsg_len, nlhdr->nlmsg_type, ghdr->cmd);
	return MNL_CB_OK;
}

/* initialization */

static int nlctx_init(struct nl_context *nlctx, unsigned long debug)
{
	int ret;
	int val;

	memset(nlctx, '\0', sizeof(*nlctx));
	nlctx->debug = debug;
	nlctx->seq = (int)time(NULL);
	nlctx->sk = mnl_socket_open(NETLINK_GENERIC);
	if (!nlctx->sk)
		return -ECONNREFUSED;
	val = 1;
	mnl_socket_setsockopt(nlctx->sk, NETLINK_EXT_ACK, &val, sizeof(val));
	ret = mnl_socket_bind(nlctx->sk, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0)
		return ret;
	nlctx->port = mnl_socket_get_portid(nlctx->sk);

	return 0;
}

static int nlctx_done(struct nl_context *nlctx)
{
	if (nlctx->sk)
		mnl_socket_close(nlctx->sk);
	free(nlctx->buff);
	if (nlctx->aux_nlctx) {
		nlctx_done(nlctx->aux_nlctx);
		free(nlctx->aux_nlctx);
	}
	free(nlctx->cmd_private);
	memset(nlctx, '\0', sizeof(*nlctx));

	return 0;
}

int __init_aux_nlctx(struct nl_context *nlctx)
{
	struct nl_context *aux;
	int ret;

	if (nlctx->aux_nlctx)
		return 0;
	aux = malloc(sizeof(*aux));
	if (!aux)
		return -ENOMEM;
	ret = nlctx_init(aux, nlctx->debug);
	if (ret < 0) {
		free(aux);
		return ret;
	}

	aux->ethnl_fam = nlctx->ethnl_fam;
	aux->mon_mcgrp_id = nlctx->mon_mcgrp_id;
	nlctx->aux_nlctx = aux;

	return 0;
}

int netlink_init(struct cmd_context *ctx)
{
	struct nl_context *nlctx;
	int ret;

	nlctx = malloc(sizeof(*nlctx));
	if (!nlctx)
		return -ENOMEM;
	ret = nlctx_init(nlctx, ctx->debug);
	if (ret < 0)
		goto err_freenlctx;

	ret = get_ethnl_family(nlctx);
	if (ret < 0)
		goto err_uninit;

	ctx->nlctx = nlctx;
	return 0;

err_uninit:
	nlctx_done(nlctx);
err_freenlctx:
	free(nlctx);
	ctx->nlctx = NULL;
	return ret;
}

void netlink_done(struct cmd_context *ctx)
{
	if (!ctx->nlctx)
		return;

	nlctx_done(ctx->nlctx);
	free(ctx->nlctx);
	ctx->nlctx = NULL;
	cleanup_all_strings();
}
