/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_STATS_H__
#define DECT_STATS_H__

#include <stdint.h>
#include <zephyr.h> // For k_mutex
#include <dect_nr_plus/dect_types.h> // For MAX_PEERS, SHORT_RD_ID_LEN_BYTES

/**
 * @brief Enum for global statistic types.
 */
typedef enum {
	STATS_TX_FRAMES,
	STATS_RX_FRAMES,
	STATS_TX_DATA_BYTES,
	STATS_RX_DATA_BYTES,
	STATS_TX_DROPS_NO_MEM,
	STATS_RX_DROPS_NO_MEM,
	STATS_TX_DROPS_QUEUE_FULL,
	STATS_RX_DROPS_QUEUE_FULL,
	STATS_MAC_MIC_FAILURES,
	STATS_MAC_CRC_ERRORS,
	STATS_DLC_CRC_ERRORS,
	STATS_SECURITY_HANDSHAKES_INITIATED,
	STATS_SECURITY_HANDSHAKES_PROCESSED,
	STATS_SECURITY_HANDSHAKES_SUCCESS,
	STATS_SECURITY_HANDSHAKES_FAILURES,
	STATS_CHANNEL_RESELECTION_ATTEMPTS,
	STATS_CHANNEL_RESELECTION_SUCCESS,
	STATS_MOBILITY_HANDOVER_REQUESTS_TX,
	STATS_MOBILITY_HANDOVER_RESPONSES_RX,
	STATS_MOBILITY_HANDOVER_ACCEPTS_TX,
	STATS_MOBILITY_HANDOVER_REJECTS_TX,
	STATS_MOBILITY_HANDOVER_SUCCESS,
	STATS_MOBILITY_HANDOVER_FAILURES,
	STATS_MOBILITY_HANDOVER_TIMEOUT_FAILURES,
	STATS_MOBILITY_HANDOVER_UNSUPPORTED_FAILURES,
	STATS_ROUTING_RREQ_TX,
	STATS_ROUTING_RREP_TX,
	STATS_ROUTING_RERR_TX,
	STATS_ROUTING_RREQ_RX,
	STATS_ROUTING_RREP_RX,
	STATS_ROUTING_RERR_RX,
	STATS_ROUTING_TX_DROPS,
	STATS_ROUTING_RX_DROPS,
	STATS_BCC_BEACONS_TX,
	STATS_BCC_BEACONS_RX,
	STATS_BCC_BEACON_IE_ERRORS,
	STATS_CVG_TX_DROPS,
	STATS_CVG_RX_DROPS,
	STATS_CVG_FRAG_DROPS,
	STATS_CVG_REASSEMBLY_DROPS,
	STATS_DLC_TX_DROPS,
	STATS_DLC_RX_DROPS,
	STATS_MAC_TX_DROPS,
	STATS_MAC_RX_DROPS,
	STATS_SECURITY_TX_DROPS,
	STATS_SECURITY_RX_DROPS,
	STATS_CHANNEL_MGR_TX_DROPS,
	STATS_CHANNEL_MGR_RX_DROPS,
	STATS_DLC_TX_REQUESTS,
	STATS_DLC_TX_SUCCESS,
	STATS_DLC_TX_FAILURES,
	STATS_DLC_RETRANSMISSIONS,
	STATS_DLC_RX_DUPLICATES,
	STATS_DLC_RX_OUT_OF_WINDOW,
	STATS_DLC_RX_IN_ORDER,
	STATS_DLC_TX_ACKS,
	STATS_DLC_RX_ACKS,
	STATS_PHY_TX_FAILED,
	STATS_PHY_RX_CRC_ERRORS,
	STATS_PHY_EVENTS_DROPPED,
	STATS_MAC_SCAN_ATTEMPTS,
	STATS_MAC_SCAN_FAILURES,
	STATS_MAC_SYNC_SUCCESS,
	STATS_MAC_SYNC_FAILURES,
	STATS_MAC_ASSOC_ATTEMPTS,
	STATS_MAC_ASSOC_SUCCESS,
	STATS_MAC_ASSOC_FAILURES,
	STATS_MAC_LINK_FAILURES,
	STATS_MAC_TX_BEACONS,
	STATS_RX_MAC_BEACONS,
	STATS_RX_MAC_ASSOC_REQUESTS,
	STATS_RX_MAC_ASSOC_RESPONSES,
	STATS_RX_MAC_DROPS,
	STATS_TX_MAC_DROPS,
	STATS_HARQ_PROCESSES_ALLOCATED,
	STATS_HARQ_PROCESSES_FREED,
	STATS_HARQ_PROCESSES_FAILED_ALLOC,
	STATS_HARQ_RETRANSMISSIONS,
	STATS_HARQ_SUCCESS_COUNT,
	STATS_HARQ_FAILURES_COUNT,
	STATS_HARQ_RESETS,
	STATS_RX_MAC_PCC,
	STATS_RX_MAC_PDC,
	STATS_RX_MAC_PCC_CRC_ERRORS,
	STATS_RX_MAC_PDC_CRC_ERRORS,
	STATS_TX_PHY_OPS_COMPLETED,
	STATS_CHANNEL_CHANGES,
	STATS_CHANNEL_BLACKLISTED,
	STATS_CHANNEL_WHITELISTED,
	STATS_POWER_MODE_CHANGES,
	STATS_POWER_MODE_TRANSITION_FAILURES,
	STATS_TX_APP_DATA_REQUESTS,
	STATS_TX_APP_DATA_BYTES,
	STATS_RX_APP_DATA_BYTES,
	STATS_CVG_FRAG_TX,
	STATS_CVG_FRAG_RX,
	STATS_CVG_REASSEMBLY_SUCCESS,
	STATS_CVG_REASSEMBLY_FAILURES,
	STATS_ROUTING_ROUTE_ADD,
	STATS_ROUTING_ROUTE_EXPIRE,
	STATS_ROUTING_ROUTE_ERROR,
	STATS_SECURITY_REKEYS,
	STATS_6LO_COMPRESSION_SUCCESS,
	STATS_6LO_COMPRESSION_FAILURES,
	STATS_6LO_DECOMPRESSION_SUCCESS,
	STATS_6LO_DECOMPRESSION_FAILURES,
} dect_global_stat_t;

/**
 * @brief Enum for peer-specific statistic types.
 */
typedef enum {
	PEER_STATS_TX_FRAMES,
	PEER_STATS_RX_FRAMES,
	PEER_STATS_TX_DATA_BYTES,
	PEER_STATS_RX_DATA_BYTES,
	PEER_STATS_DLC_RETRANSMISSIONS,
	PEER_STATS_DLC_CRC_ERRORS,
	PEER_STATS_MAC_MIC_FAILURES,
	PEER_STATS_HARQ_TX_SUCCESS,
	PEER_STATS_HARQ_TX_RETRANSMISSIONS,
	PEER_STATS_HARQ_RX_COMBINED,
	PEER_STATS_HARQ_TX_FAILURES,
	PEER_STATS_MAC_HANDOVER_REQUESTS_TX,
	PEER_STATS_MAC_HANDOVER_RESPONSES_RX,
	PEER_STATS_MAC_HANDOVER_FAILURES,
} dect_peer_stat_t;

/**
 * @brief Per-peer statistics structure.
 */
typedef struct {
	uint16_t short_rd_id; /**< Short RD ID of the peer. */
	uint32_t tx_frames;   /**< Number of frames transmitted to this peer. */
	uint32_t rx_frames;   /**< Number of frames received from this peer. */
	uint32_t tx_data_bytes; /**< Number of data bytes transmitted to this peer. */
	uint32_t rx_data_bytes; /**< Number of data bytes received from this peer. */
	uint32_t dlc_retransmissions; /**< Number of DLC retransmissions for this peer. */
	uint32_t dlc_crc_errors;      /**< Number of DLC CRC errors from this peer. */
	uint32_t mac_mic_failures;    /**< Number of MAC MIC failures from this peer. */
	// Add more peer-specific stats as needed
	uint32_t mac_handover_requests_tx; /**< Number of MAC Handover Requests transmitted to this peer. */
	uint32_t mac_handover_responses_rx; /**< Number of MAC Handover Responses received from this peer. */
	uint32_t mac_handover_failures; /**< Number of MAC Handover failures related to this peer. */
	uint32_t harq_tx_success;       /**< Number of HARQ transmissions that succeeded on first attempt for this peer. */
	uint32_t harq_tx_retransmissions; /**< Number of HARQ retransmissions for this peer. */
	uint32_t harq_rx_combined;      /**< Number of HARQ RX packets successfully combined for this peer. */
	uint32_t harq_tx_failures;      /**< Number of HARQ TX failures for this peer (after max retransmissions). */
} dect_peer_stats_t;

/**
 * @brief Global DECT NR+ statistics structure.
 */
typedef struct {
	uint32_t total_tx_frames;       /**< Total number of frames transmitted by this device. */
	uint32_t total_rx_frames;       /**< Total number of frames received by this device. */
	uint32_t total_tx_data_bytes;   /**< Total number of data bytes transmitted. */
	uint32_t total_rx_data_bytes;   /**< Total number of data bytes received. */
	uint32_t tx_drops_no_mem;       /**< Number of TX packets dropped due to no memory (any layer). */
	uint32_t rx_drops_no_mem;       /**< Number of RX packets dropped due to no memory (any layer). */
	uint32_t tx_drops_queue_full;   /**< Number of TX packets dropped due to message queue full (any layer). */
	uint32_t rx_drops_queue_full;   /**< Number of RX packets dropped due to message queue full (any layer). */
	uint32_t mac_mic_failures;      /**< Total MAC MIC failures (due to invalid MICs). */
	uint32_t mac_crc_errors;        /**< Total MAC CRC errors. */
	uint32_t dlc_crc_errors;        /**< Total DLC CRC errors. */
	uint32_t security_handshakes_initiated; /**< Number of security handshakes initiated. */
	uint32_t security_handshakes_processed; /**< Number of security handshakes processed (challenge/response). */
	uint32_t security_handshakes_success; /**< Number of successful security handshakes. */
	uint32_t security_handshakes_failures; /**< Number of failed security handshakes (timeout, invalid MIC). */
	uint32_t channel_reselection_attempts; /**< Number of channel reselection attempts. */
	uint32_t channel_reselection_success; /**< Number of successful channel reselection attempts. */
	uint32_t mobility_handover_requests_tx; /**< Total Handover Requests transmitted. */
	uint32_t mobility_handover_responses_rx; /**< Total Handover Responses received. */
	uint32_t mobility_handover_accepts_tx; /**< Total Handover Accepts transmitted by current FP. */
	uint32_t mobility_handover_rejects_tx; /**< Total Handover Rejects transmitted by current FP. */
	uint32_t mobility_handover_success; /**< Total successful handovers completed. */
	uint32_t mobility_handover_failures; /**< Total handover failures. */
	uint32_t mobility_handover_timeout_failures; /**< Total handover failures due to timeout. */
	uint32_t mobility_handover_unsupported_failures; /**< Total handover failures due to unsupported features. */
	uint32_t routing_rreq_tx;       /**< Number of Route Request (RREQ) PDUs transmitted. */
	uint32_t routing_rrep_tx;       /**< Number of Route Reply (RREP) PDUs transmitted. */
	uint32_t routing_rerr_tx;       /**< Number of Route Error (RERR) PDUs transmitted. */
	uint32_t routing_rreq_rx;       /**< Number of RREQ PDUs received. */
	uint32_t routing_rrep_rx;       /**< Number of RREP PDUs received. */
	uint32_t routing_rerr_rx;       /**< Number of RERR PDUs received. */
	uint32_t routing_tx_drops;      /**< Number of routing PDUs dropped (e.g., no route, queue full). */
	uint32_t routing_rx_drops;      /**< Number of routing PDUs dropped (e.g., malformed, unknown type). */
	uint32_t bcc_beacons_tx;        /**< Number of Broadcast Control Channel (BCC) beacons transmitted. */
	uint32_t bcc_beacons_rx;        /**< Number of BCC beacons received. */
	uint32_t bcc_beacon_ie_errors;  /**< Number of BCC beacon IE parsing errors. */
	uint32_t cvg_tx_drops;          /**< Number of CVG TX packets dropped (e.g., queue full to DLC). */
	uint32_t cvg_rx_drops;          /**< Number of CVG RX packets dropped (e.g., reassembly issues). */
	uint32_t cvg_frag_drops;        /**< Number of CVG fragments dropped (e.g., SDU too large for frag). */
	uint32_t cvg_reassembly_drops;  /**< Number of CVG reassembly failures (e.g., timeout, incomplete). */
	uint32_t dlc_tx_drops;          /**< Number of DLC TX packets dropped (e.g., queue full to MAC, ARQ buffer full). */
	uint32_t dlc_rx_drops;          /**< Number of DLC RX packets dropped (e.g., malformed, unknown type). */
	uint32_t mac_tx_drops;          /**< Number of MAC TX packets dropped (e.g., queue full to PHY). */
	uint32_t mac_rx_drops;          /**< Number of MAC RX packets dropped (e.g., malformed, invalid PDU type). */
	uint32_t security_tx_drops;     /**< Number of Security TX packets dropped (e.g., failed allocation, queue full). */
	uint32_t security_rx_drops;     /**< Number of Security RX packets dropped (e.g., malformed challenge/response). */
	uint32_t channel_mgr_tx_drops;  /**< NEW: Number of Channel Manager TX operations dropped (e.g., failed PHY call). */
	uint32_t channel_mgr_rx_drops;  /**< NEW: Number of Channel Manager RX operations dropped (e.g., failed scan). */

	// Fields to be added for full consistency with dect_stats.c:
	uint32_t dlc_tx_requests;        /**< Number of requests to DLC TX. */
	uint32_t dlc_tx_success;         /**< Number of successful DLC TX completions. */
	uint32_t dlc_tx_failures;        /**< Number of failed DLC TX attempts. */
	uint32_t dlc_retransmissions;    /**< Number of DLC retransmissions. */
	uint32_t dlc_rx_duplicates;      /**< Number of duplicate DLC RX frames. */
	uint32_t dlc_rx_out_of_window;   /**< Number of DLC RX frames out of window. */
	uint32_t dlc_rx_in_order;        /**< Number of in-order DLC RX frames. */
	uint32_t dlc_tx_acks;            /**< Number of DLC ACKs transmitted. */
	uint32_t dlc_rx_acks;            /**< Number of DLC ACKs received. */
	uint32_t phy_tx_failed;          /**< Number of PHY TX operations that failed. */
	uint32_t phy_rx_crc_errors;      /**< Number of PHY RX frames with CRC errors. */
	uint32_t phy_events_dropped;     /**< Number of PHY events dropped. */
	uint32_t mac_scan_attempts;      /**< Number of MAC scan attempts. */
	uint32_t mac_scan_failures;      /**< Number of MAC scan failures. */
	uint32_t mac_sync_success;       /**< Number of successful MAC synchronizations. */
	uint32_t mac_sync_failures;      /**< Number of MAC synchronization failures. */
	uint32_t mac_assoc_attempts;     /**< Number of MAC association attempts. */
	uint32_t mac_assoc_success;      /**< Number of successful MAC associations. */
	uint32_t mac_assoc_failures;     /**< Number of MAC association failures. */
	uint32_t mac_link_failures;      /**< Number of total MAC link failures. */
	uint32_t mac_tx_beacons;         /**< Number of MAC beacons transmitted. */
	uint32_t rx_mac_beacons;         /**< Number of MAC beacons received. */
	uint32_t rx_mac_assoc_requests;  /**< Number of MAC association requests received. */
	uint32_t rx_mac_assoc_responses; /**< Number of MAC association responses received. */
	uint32_t rx_mac_drops;           /**< Number of MAC frames dropped on RX. */
	uint32_t tx_mac_drops;           /**< Number of MAC frames dropped on TX. */
	uint32_t harq_processes_allocated; /**< Number of HARQ processes allocated. */
	uint32_t harq_processes_freed;   /**< Number of HARQ processes freed. */
	uint32_t harq_processes_failed_alloc; /**< Number of HARQ processes failed allocation. */
	uint32_t harq_retransmissions;   /**< Number of HARQ retransmissions performed. */
	uint32_t harq_success_count;     /**< Number of HARQ transmissions completed successfully. */
	uint32_t harq_failures_count;    /**< Number of HARQ transmissions failed after max retransmissions. */
	uint32_t harq_resets;            /**< Number of HARQ resets. */
	uint32_t rx_mac_pcc;             /**< Number of MAC PCC PDUs received. */
	uint32_t rx_mac_pdc;             /**< Number of MAC PDC PDUs received. */
	uint32_t rx_mac_pcc_crc_errors;  /**< Number of MAC PCC PDUs with CRC errors. */
	uint32_t rx_mac_pdc_crc_errors;  /**< Number of MAC PDC PDUs with CRC errors. */
	uint32_t tx_phy_ops_completed;   /**< Number of PHY operations that completed transmission. */
	uint32_t channel_changes;        /**< Number of channel changes. */
	uint32_t channel_blacklisted;    /**< Number of channels blacklisted. */
	uint32_t channel_whitelisted;    /**< Number of channels whitelisted. */
	uint32_t power_mode_changes;     /**< Number of power mode changes. */
	uint32_t power_mode_transition_failures; /**< Number of power mode transition failures. */
	uint32_t tx_app_data_requests;   /**< Number of application data TX requests. */
	uint32_t tx_app_data_bytes;      /**< Number of application data bytes transmitted. */
	uint32_t rx_app_data_bytes;      /**< Number of application data bytes received. */
	uint32_t cvg_frag_tx;            /**< Number of CVG fragments transmitted. */
	uint32_t cvg_frag_rx;            /**< Number of CVG fragments received. */
	uint32_t cvg_reassembly_success; /**< Number of CVG reassembly successes. */
	uint32_t cvg_reassembly_failures;/**< Number of CVG reassembly failures. */
	uint32_t routing_route_add;      /**< Number of routing table entries added. */
	uint32_t routing_route_expire;   /**< Number of routing table entries expired. */
	uint32_t routing_route_error;    /**< Number of routing errors. */
	uint32_t security_rekeys;        /**< Number of security re-keying attempts. */
	uint32_t sixlo_compression_success; /**< Number of 6LoWPAN compression successes. */
	uint32_t sixlo_compression_failures; /**< Number of 6LoWPAN compression failures. */
	uint32_t sixlo_decompression_success; /**< Number of 6LoWPAN decompression successes. */
	uint32_t sixlo_decompression_failures; /**< Number of 6LoWPAN decompression failures. */

	uint8_t num_active_peers;       /**< Current number of active peers. */
	dect_peer_stats_t peer_stats[MAX_PEERS]; /**< Per-peer statistics array. */

	K_MUTEX_DEFINE(mutex); /**< Mutex to protect statistics access. */
} dect_stats_t;

/**
 * @brief Global statistics instance.
 * Defined in dect_stats.c.
 */
extern dect_stats_t dect_stats;

/**
 * @brief Initializes the DECT NR+ statistics module.
 * Sets all statistics counters to zero.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_stats_init(void);

/**
 * @brief Updates a global statistic counter.
 *
 * @param stat The global statistic field to update (e.g., dect_stats.total_tx_frames).
 * @param value The value to add to the counter.
 */
#define STATS_INC_GLOBAL(stat, value) \
	do { \
		k_mutex_lock(&dect_stats.mutex, K_FOREVER); \
		stat += (value); \
		k_mutex_unlock(&dect_stats.mutex); \
	} while (0)

/**
 * @brief Simple increment macro for global statistics.
 *
 * @param stat The global statistic field to increment (e.g., dect_stats.total_tx_frames).
 */
#define STATS_INC(stat) STATS_INC_GLOBAL(stat, 1)


/**
 * @brief Updates a peer-specific statistic counter.
 * If the peer does not exist, a new entry is created.
 *
 * @param short_rd_id The Short RD ID of the peer.
 * @param field The field within `dect_peer_stats_t` to update.
 * @param value The value to add to the counter.
 */
#define STATS_INC_PEER(short_rd_id, field, value) \
	do { \
		k_mutex_lock(&dect_stats.mutex, K_FOREVER); \
		int peer_idx = find_peer_stats_entry(short_rd_id); \
		if (peer_idx == -1) { \
			peer_idx = get_or_create_peer_stats_entry(short_rd_id); \
		} \
		if (peer_idx != -1) { \
			dect_stats.peer_stats[peer_idx].field += (value); \
		} \
		k_mutex_unlock(&dect_stats.mutex); \
	} while (0)

/**
 * @brief Prints the current DECT NR+ stack statistics.
 * This function provides a way for the application to query performance metrics.
 */
// void dect_nr_plus_print_stats(void); // See Subsystem file dect_nr_plus_subsystem.h
void dect_stats_print(void)

/**
 * @brief Updates a global statistic counter.
 * // [FIX]: Added missing public function declaration.
 * @param stat_type The global statistic field to update (from `dect_global_stat_t`).
 * @param value The value to add to the counter.
 */
void dect_stats_update_global(dect_global_stat_t stat_type, int32_t value);

/**
 * @brief Updates a peer-specific statistic counter.
 * If the peer does not exist, a new entry is created.
 * // [FIX]: Added missing public function declaration.
 * @param short_rd_id The Short RD ID of the peer.
 * @param stat_type The field within `dect_peer_stats_t` to update (from `dect_peer_stat_t`).
 * @param value The value to add to the counter.
 */
void dect_stats_update_peer(uint16_t short_rd_id, dect_peer_stat_t stat_type, int32_t value);

#endif /* DECT_STATS_H__ */

/* End of File
 * Last Amended: 2025-06-09 17:00 BST: Added tx_drops_no_mem and rx_drops_no_mem to dect_stats_t.
 * Last Amended: 2025-06-09 17:45 BST: Added CVG-specific drop statistics (cvg_tx_drops, cvg_rx_drops, cvg_frag_drops, cvg_reassembly_drops).
 * Last Amended: 2025-06-09 18:00 BST: Added DLC-specific drop statistics (dlc_tx_drops, dlc_rx_drops).
 * Last Amended: 2025-06-09 18:15 BST: Added MAC-specific drop statistics (mac_tx_drops, mac_rx_drops).
 * Last Amended: 2025-06-09 18:40 BST: Added Security-specific drop statistics (security_tx_drops, security_rx_drops).
 * Last Amended: 2025-06-09 19:35 BST: Added Channel Manager-specific drop statistics (channel_mgr_tx_drops, channel_mgr_rx_drops).
 */
