#ifndef ETHTOOL_COMMON_H__
#define ETHTOOL_COMMON_H__

#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

#define N_SOTS 7
extern char *so_timestamping_labels[N_SOTS];
#define N_TX_TYPES (HWTSTAMP_TX_ONESTEP_SYNC + 1)
extern char *tx_type_labels[N_TX_TYPES];
#define N_RX_FILTERS (HWTSTAMP_FILTER_NTP_ALL + 1)
extern char *rx_filter_labels[N_RX_FILTERS];

#endif /* ETHTOOL_COMMON_H__ */
