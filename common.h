#ifndef ETHTOOL_COMMON_H__
#define ETHTOOL_COMMON_H__

#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

#define N_SOTS 7
extern char *so_timestamping_labels[N_SOTS];
#define N_TX_TYPES (HWTSTAMP_TX_ONESTEP_SYNC + 1)
extern char *tx_type_labels[N_TX_TYPES];
#define N_RX_FILTERS (HWTSTAMP_FILTER_NTP_ALL + 1)
extern char *rx_filter_labels[N_RX_FILTERS];

struct flag_info {
	const char *name;
	u32 value;
};

extern const struct flag_info flags_msglvl[];
extern const unsigned int n_flags_msglvl;


enum link_mode_class {
	LM_CLASS_UNKNOWN,
	LM_CLASS_REAL,
	LM_CLASS_AUTONEG,
	LM_CLASS_PORT,
	LM_CLASS_PAUSE,
	LM_CLASS_FEC,
};

struct link_mode_info {
	enum link_mode_class	class;
	u32			speed;
	u8			duplex;
};

struct off_flag_def {
	const char *short_name;
	const char *long_name;
	const char *kernel_name;
	u32 get_cmd, set_cmd;
	u32 value;
	/* For features exposed through ETHTOOL_GFLAGS, the oldest
	 * kernel version for which we can trust the result.  Where
	 * the flag was added at the same time the kernel started
	 * supporting the feature, this is 0 (to allow for backports).
	 * Where the feature was supported before the flag was added,
	 * it is the version that introduced the flag.
	 */
	u32 min_kernel_ver;
};

#define OFF_FLAG_DEF_SIZE 12
extern const struct off_flag_def off_flag_def[OFF_FLAG_DEF_SIZE];

extern const struct link_mode_info link_modes[];
extern const unsigned int link_modes_count;

static inline bool lm_class_match(unsigned int mode, enum link_mode_class class)
{
	unsigned int mode_class = (mode < link_modes_count) ?
				   link_modes[mode].class : LM_CLASS_UNKNOWN;

	if (mode_class == class)
		return true;
	return (mode_class == class) ||
	       ((class == LM_CLASS_REAL) && (mode_class = LM_CLASS_UNKNOWN));
}

#define DECLARE_ENUM_NAMES(obj) \
	extern const char *names_ ## obj[]; \
	extern const unsigned int names_ ## obj ## _count
#define DEFINE_ENUM_COUNT(obj) \
	const unsigned int names_ ## obj ## _count = ARRAY_SIZE(names_ ## obj)
#define print_enum(array, val, label, unknown) \
	__print_enum(array, array ## _count, val, label, unknown)

DECLARE_ENUM_NAMES(duplex);
DECLARE_ENUM_NAMES(port);
DECLARE_ENUM_NAMES(transceiver);

void print_flags(const struct flag_info *info, unsigned int n_info, u32 value);
void __print_enum(const char *const *info, unsigned int n_info,
		  unsigned int val, const char *label, const char *unknown);
int dump_wol(struct ethtool_wolinfo *wol);
void dump_mdix(u8 mdix, u8 mdix_ctrl);

#endif /* ETHTOOL_COMMON_H__ */
