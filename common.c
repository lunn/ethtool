#include "internal.h"
#include "common.h"

char *so_timestamping_labels[N_SOTS] = {
	"hardware-transmit     (SOF_TIMESTAMPING_TX_HARDWARE)",
	"software-transmit     (SOF_TIMESTAMPING_TX_SOFTWARE)",
	"hardware-receive      (SOF_TIMESTAMPING_RX_HARDWARE)",
	"software-receive      (SOF_TIMESTAMPING_RX_SOFTWARE)",
	"software-system-clock (SOF_TIMESTAMPING_SOFTWARE)",
	"hardware-legacy-clock (SOF_TIMESTAMPING_SYS_HARDWARE)",
	"hardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)",
};

char *tx_type_labels[N_TX_TYPES] = {
	"off                   (HWTSTAMP_TX_OFF)",
	"on                    (HWTSTAMP_TX_ON)",
	"one-step-sync         (HWTSTAMP_TX_ONESTEP_SYNC)",
};

char *rx_filter_labels[N_RX_FILTERS] = {
	"none                  (HWTSTAMP_FILTER_NONE)",
	"all                   (HWTSTAMP_FILTER_ALL)",
	"some                  (HWTSTAMP_FILTER_SOME)",
	"ptpv1-l4-event        (HWTSTAMP_FILTER_PTP_V1_L4_EVENT)",
	"ptpv1-l4-sync         (HWTSTAMP_FILTER_PTP_V1_L4_SYNC)",
	"ptpv1-l4-delay-req    (HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ)",
	"ptpv2-l4-event        (HWTSTAMP_FILTER_PTP_V2_L4_EVENT)",
	"ptpv2-l4-sync         (HWTSTAMP_FILTER_PTP_V2_L4_SYNC)",
	"ptpv2-l4-delay-req    (HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ)",
	"ptpv2-l2-event        (HWTSTAMP_FILTER_PTP_V2_L2_EVENT)",
	"ptpv2-l2-sync         (HWTSTAMP_FILTER_PTP_V2_L2_SYNC)",
	"ptpv2-l2-delay-req    (HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ)",
	"ptpv2-event           (HWTSTAMP_FILTER_PTP_V2_EVENT)",
	"ptpv2-sync            (HWTSTAMP_FILTER_PTP_V2_SYNC)",
	"ptpv2-delay-req       (HWTSTAMP_FILTER_PTP_V2_DELAY_REQ)",
	"ntp-all               (HWTSTAMP_FILTER_NTP_ALL)",
};
