#ifndef ETHTOOL_NETLINK_PARSER_H__
#define ETHTOOL_NETLINK_PARSER_H__

#include <stddef.h>

#include "netlink.h"

struct lookup_entry_u32 {
	const char	*arg;
	uint32_t	val;
};

struct lookup_entry_u16 {
	const char	*arg;
	uint16_t	val;
};

struct lookup_entry_u8 {
	const char	*arg;
	uint8_t		val;
};

struct bitfield32_parser_special {
	char		name;
	uint32_t	val;
};

struct bitfield32_parser_data {
	char					bits[32];
	const struct bitfield32_parser_special	*specials;
};

struct byte_str_params {
	unsigned int	min_len;
	unsigned int	max_len;
	char		delim;
};

struct byte_str_value {
	unsigned int	len;
	u8		*data;
};

typedef int (*param_parser_cb_t)(struct nl_context *, uint16_t, const void *,
				 void *);

struct param_parser {
	const char		*arg;
	uint16_t		nest;
	uint16_t		type;
	param_parser_cb_t	handler;
	const void		*handler_data;
	unsigned int		min_argc;
	unsigned int		dest_offset;
};

unsigned int nsb(uint32_t x);
int parse_u32(const char *arg, uint32_t *result);

int nl_parse_flag(struct nl_context *nlctx, uint16_t type, const void *data,
		  void *dest);
int nl_parse_string(struct nl_context *nlctx, uint16_t type, const void *data,
		    void *dest);
int nl_parse_direct_u32(struct nl_context *nlctx, uint16_t type,
			const void *data, void *dest);
int nl_parse_direct_u8(struct nl_context *nlctx, uint16_t type,
		       const void *data, void *dest);
int nl_parse_u8bool(struct nl_context *nlctx, uint16_t type, const void *data,
		    void *dest);
int nl_parse_lookup_u32(struct nl_context *nlctx, uint16_t type,
			const void *data, void *dest);
int nl_parse_lookup_u8(struct nl_context *nlctx, uint16_t type,
		       const void *data, void *dest);
int nl_parse_bitfield32(struct nl_context *nlctx, uint16_t type,
			const void *data, void *dest);
int nl_parse_char_bitfield32(struct nl_context *nlctx, uint16_t type,
			     const void *data, void *dest);
int nl_parse_bitset(struct nl_context *nlctx, uint16_t type, const void *data,
		    void *dest);
int nl_parse_bitlist(struct nl_context *nlctx, uint16_t type, const void *data,
		     void *dest);
int nl_parse_byte_str(struct nl_context *nlctx, uint16_t type,
		      const void *data, void *dest);

int nl_parser(struct nl_context *nlctx, const struct param_parser *params,
	      void *dest);

#endif /* ETHTOOL_NETLINK_PARSER_H__ */
