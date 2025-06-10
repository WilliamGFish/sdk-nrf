/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_TYPES_H__
#define DECT_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h> // For k_timer, k_msgq, k_mutex
#include <net/net_buf.h> // For struct net_buf
#include <net/net_pkt.h> // For struct net_pkt

// --- General Definitions ---
#define AES_KEY_LEN 16                       /**< AES encryption key length */
#define DLC_MAX_SEQ_NUM 256                  /**< Max sequence number for DLC (0-255, 8-bit) */
#define RTT_ALPHA_SHIFT 3                    /**< Alpha factor for SRTT (1/2^3 = 1/8) */
#define RTT_BETA_SHIFT 2                     /**< Beta factor for RTTVAR (1/2^2 = 1/4) */
#define RTT_K_FACTOR 2                       /**< K factor for RTO calculation */
#define MAC_ADDRESS_LEN 4                    /**< Length of MAC address (Long RD ID) */
#define LONG_RD_ID_LEN_BYTES 4               /**< Length of Long RD ID in bytes */
#define SHORT_RD_ID_LEN_BYTES 2              /**< Length of Short RD ID in bytes */
#define SECURITY_NONCE_LEN 16                /**< Length of security nonces in bytes */
#define MAC_MIC_LEN 8                        /**< Length of MAC Message Integrity Code (MIC) in bytes */
#define DLC_CRC_LEN_BYTES 2                  /**< Length of DLC CRC in bytes */
#define DLC_DATA_HDR_LEN_BYTES 2             /**< Length of DLC Data PDU header (Sequence, Window) */
#define DLC_ACK_HDR_LEN_BYTES 2              /**< Length of DLC ACK PDU header (ACK, Window) */
#define DLC_ARQ_TX_BUFFER_SIZE 16            /**< Number of entries in DLC ARQ TX buffer */
#define DLC_ARQ_RX_BUFFER_SIZE 16            /**< Number of entries in DLC ARQ RX buffer */
#define DLC_TX_WINDOW_SIZE 8                 /**< Max number of unacknowledged TX PDUs */
#define DLC_RX_WINDOW_SIZE 8                 /**< Max number of out-of-order RX PDUs accepted */
#define DLC_RX_WINDOW_SIZE_SHIFT 3           /**< Shift value for RX window size (2^3 = 8) */
#define DLC_RX_WINDOW_SIZE_UNIT (1 << DLC_RX_WINDOW_SIZE_SHIFT) /**< Unit size for RX window */
#define DLC_SEQ_NUM_MASK 0xFF                /**< Mask for 8-bit sequence number */
#define DLC_ACK_BIT_MASK 0x80                /**< Mask for ACK bit in DLC ACK header (if used) */
#define MAC_MAX_SDU_SIZE 256                 /**< Maximum SDU size at MAC layer (payload only) */
#define MAX_DECT_CHANNELS 10                 /**< Maximum number of DECT channels (0-9) */
#define MAX_PEERS 10                         /**< Maximum number of peers to track */
#define MAX_ROUTING_ENTRIES 20               /**< Maximum number of entries in routing table */
#define SHORT_RD_ID_BROADCAST 0xFFFF         /**< Broadcast Short RD ID */
#define HPC_LEN_BYTES 4                      /**< Length of HPC in bytes */
#define PSN_LEN_BYTES 2                      /**< Length of PSN in bytes */
#define LBT_STATUS_CHANNEL_FREE 0x01         /**< LBT status: channel free */
#define LBT_STATUS_CHANNEL_BUSY 0x00         /**< LBT status: channel busy */
#define DECT_NR_PLUS_IPV6_MTU 1280           /**< Standard IPv6 MTU for DECT NR+ link */
#define MAX_FRAGMENT_HDR_SIZE 4              /**< Max bytes for fragmentation header */
#define MAX_FRAGMENTS_PER_SDU 16             /**< Max number of fragments per SDU */
#define CVG_REASSEMBLY_TIMEOUT_MS 5000       /**< Reassembly timeout for CVG fragments */
#define MAC_IE_MAX_DATA_LEN 253              /**< Max data length for an Information Element */
#define MAC_HEADER_LEN_TYPE_1 1              /**< Length of MAC Header Type 1 (Control PDUs) */
#define MAC_HEADER_LEN_TYPE_2 4              /**< Length of MAC Header Type 2 (Data PDUs) */

// --- Helper Macro for Message Queue Puts ---
/**
 * @brief Macro to safely put a message into a Zephyr message queue,
 * handling queue full scenarios by unreferencing a buffer and
 * incrementing a statistics counter.
 *
 * @param msgq_ptr Pointer to the k_msgq structure.
 * @param msg_ptr Pointer to the message to put.
 * @param timeout Timeout for putting the message (e.g., K_NO_WAIT).
 * @param error_code The DECT_ERROR_ code to use if the put fails.
 * @param error_desc A string literal describing the error.
 * @param buf_to_unref Optional: A net_buf pointer to unreference if the put fails.
 * Pass NULL if no net_buf needs to be unreferenced.
 * @param stat_counter Optional: A global statistic counter to increment on failure.
 * Pass NULL if no stat needs to be incremented.
 * @return The return code of k_msgq_put (0 on success, or -ENOMEM/-EAGAIN on failure).
 */
#define DECT_MSGQ_PUT_OR_DROP(msgq_ptr, msg_ptr, timeout, error_code, error_desc, buf_to_unref, stat_counter) \
	({ \
		int __ret = k_msgq_put(msgq_ptr, msg_ptr, timeout); \
		if (__ret != 0) { \
			DECT_ERROR_HANDLER(error_code, error_desc); \
			if (buf_to_unref) { \
				net_buf_unref(buf_to_unref); \
			} \
			if (stat_counter) { \
				STATS_INC_GLOBAL(*stat_counter, 1); \
			} \
		} \
		__ret; \
	})


// --- Enums ---

/**
 * @brief DECT NR+ MAC roles.
 */
typedef enum {
	MAC_ROLE_FP, /**< Fixed Part (Base Station) */
	MAC_ROLE_PP, /**< Portable Part (Handset/End Device) */
} mac_role_t;

/**
 * @brief DECT NR+ MAC association states.
 */
typedef enum {
	MAC_ASSOC_STATE_IDLE,          /**< Not associated. */
	MAC_ASSOC_STATE_SCANNING,      /**< Portable Part scanning for Fixed Parts. */
	MAC_ASSOC_STATE_ASSOCIATING,   /**< Association procedure in progress. */
	MAC_ASSOC_STATE_ASSOCIATED,    /**< Successfully associated with a Fixed Part. */
	MAC_ASSOC_STATE_DISCONNECTING, /**< Disassociation procedure in progress. */
} mac_assoc_state_t;

/**
 * @brief DECT NR+ MAC synchronization states.
 */
typedef enum {
	MAC_SYNC_STATE_UNSYNCHRONIZED, /**< Not synchronized with any FP. */
	MAC_SYNC_STATE_SYNCHRONIZING,  /**< Attempting to synchronize. */
	MAC_SYNC_STATE_SYNCHRONIZED,   /**< Synchronized with an FP. */
	MAC_SYNC_STATE_LOST,           /**< Synchronization lost. */
} mac_sync_state_t;

/**
 * @brief MAC PDU header types.
 */
typedef enum {
	MAC_HEADER_TYPE_1_CONTROL = 0x01, /**< MAC Control PDU (e.g., Association, Security, Beacon) */
	MAC_HEADER_TYPE_2_DATA = 0x02,    /**< MAC Data PDU (e.g., carrying DLC data) */
	// Add other MAC Header Types as per specification
} mac_header_type_t;

/**
 * @brief MAC Control PDU types.
 */
typedef enum {
	MAC_CONTROL_TYPE_RESERVED = 0x00,
	MAC_CONTROL_TYPE_BEACON = 0x01,         /**< Beacon PDU (Part 4, 5.4.3.1.2) */
	MAC_CONTROL_TYPE_ASSOC_REQ = 0x02,      /**< Association Request (Part 4, 5.4.3.2.2) */
	MAC_CONTROL_TYPE_ASSOC_RESP = 0x03,     /**< Association Response (Part 4, 5.4.3.2.3) */
	MAC_CONTROL_TYPE_SECURITY_CHALLENGE = 0x04, /**< Security Challenge (Part 4, 5.4.3.3.2) */
	MAC_CONTROL_TYPE_SECURITY_RESPONSE = 0x05,  /**< Security Response (Part 4, 5.4.3.3.3) */
	MAC_CONTROL_TYPE_HANDOVER_REQ = 0x06,       /**< Handover Request */
	MAC_CONTROL_TYPE_HANDOVER_RESP = 0x07,      /**< Handover Response */
	MAC_CONTROL_TYPE_DISCONNECT = 0x08,     /**< Disconnect PDU */
	// Add other MAC Control PDU types as per specification
} mac_control_type_t;

/**
 * @brief Reasons for MAC link failure/disconnection.
 */
typedef enum {
	MAC_LINK_FAILURE_REASON_UNKNOWN,
	MAC_LINK_FAILURE_REASON_SYNC_LOSS,
	MAC_LINK_FAILURE_REASON_DISASSOCIATED,
	MAC_LINK_FAILURE_REASON_HANDOVER_FAILED,
	MAC_LINK_FAILURE_REASON_SECURITY_FAILED,
	MAC_LINK_FAILURE_REASON_PEER_TIMEOUT,
	// Add other reasons
} mac_link_failure_reason_t;


/**
 * @brief DLC PDU types.
 */
typedef enum {
	DLC_PDU_TYPE_DATA = 0x00,   /**< Data PDU (carries CVG/Routing data) */
	DLC_PDU_TYPE_ACK = 0x01,    /**< Acknowledgment PDU */
	DLC_PDU_TYPE_CONTROL = 0x02, /**< DLC Control PDU (e.g., Flow Control) */
	DLC_PDU_TYPE_ROUTING = 0x03, /**< Routing PDU (e.g., RREQ, RREP, RERR) */
	DLC_PDU_TYPE_BEACON = 0x04, /**< Beacon PDU (passed through from BCC) */
	// Add other DLC PDU types as per specification
} dlc_pdu_type_t;


/**
 * @brief Quality of Service (QoS) priorities.
 */
typedef enum {
	QOS_PRIORITY_LOW,    /**< Low priority, best effort. */
	QOS_PRIORITY_NORMAL, /**< Normal priority. */
	QOS_PRIORITY_HIGH,   /**< High priority, for time-sensitive data. */
	QOS_PRIORITY_CRITICAL, /**< Critical priority, for control/signaling. */
} qos_priority_t;

/**
 * @brief Channel status types.
 */
typedef enum {
	CHANNEL_STATUS_UNKNOWN,       /**< Channel status is unknown. */
	CHANNEL_STATUS_GOOD,          /**< Channel is good for communication. */
	CHANNEL_STATUS_BUSY,          /**< Channel is currently busy (e.g., LBT failure). */
	CHANNEL_STATUS_BAD_QUALITY,   /**< Channel has poor quality (e.g., high FER, low RSSI). */
	CHANNEL_STATUS_BLACKLISTED,   /**< Channel is temporarily or permanently blacklisted. */
	CHANNEL_STATUS_WHITELISTED,   /**< Channel is whitelisted (preferred). */
	CHANNEL_STATUS_IN_USE,        /**< Channel is currently active. */
} channel_status_t;

/**
 * @brief Device power modes.
 */
typedef enum {
	POWER_MODE_DEACTIVATED,         /**< Modem/Radio is completely off. */
	POWER_MODE_ACTIVE,              /**< Full power, ready for immediate TX/RX. */
	POWER_MODE_IDLE,                /**< Low power, but quickly transition to active. */
	POWER_MODE_DEEP_SLEEP,          /**< Deepest sleep, longest wake-up time. */
	POWER_MODE_STANDBY_LBT,         /**< Standby with Listen-Before-Talk enabled. */
	POWER_MODE_STANDBY_NO_LBT,      /**< Standby without LBT. */
} power_mode_t;

/**
 * @brief Reason for a power mode change request.
 */
typedef enum {
	POWER_CHANGE_REASON_IDLE_TIMEOUT,     /**< Inactivity timeout. */
	POWER_CHANGE_REASON_ACTIVITY_DETECTED,/**< Activity detected (RX/TX). */
	POWER_CHANGE_REASON_APPLICATION_REQ,  /**< Application explicitly requested. */
	POWER_CHANGE_REASON_ASSOC_STATE,      /**< Association state change. */
	POWER_CHANGE_REASON_SCANNING,         /**< Channel scanning. */
	POWER_CHANGE_REASON_HANDOVER,         /**< Handover procedure. */
	POWER_CHANGE_REASON_INIT,             /**< Initial power state. */
	POWER_CHANGE_REASON_DEINIT,           /**< De-initialization. */
} power_change_reason_t;

/**
 * @brief Security authentication states for a peer.
 */
typedef enum {
	SECURITY_AUTH_STATE_NONE,           /**< No security established. */
	SECURITY_AUTH_STATE_HANDSHAKE_INIT, /**< Handshake initiated (challenge sent). */
	SECURITY_AUTH_STATE_HANDSHAKE_RESP, /**< Handshake response received. */
	SECURITY_AUTH_STATE_AUTHENTICATED,  /**< Authenticated and session key derived. */
	SECURITY_AUTH_STATE_FAILED,         /**< Security handshake failed. */
} security_auth_state_t;

/**
 * @brief Current phase of a MAC Handover procedure.
 */
typedef enum {
	HANDOVER_PHASE_IDLE,                 /**< No handover in progress. */
	HANDOVER_PHASE_INITIATED,            /**< Handover request sent/received. */
	HANDOVER_PHASE_SYNC_LOSS_DETECTED,   /**< PP detected sync loss and initiated handover. */
	HANDOVER_PHASE_RESPONSE_AWAIT,       /**< Waiting for handover response from target FP. */
	HANDOVER_PHASE_COMPLETED_FP,         /**< FP side of handover completed. */
	HANDOVER_PHASE_COMPLETED_PP,         /**< PP side of handover completed. */
	HANDOVER_PHASE_FAILED,               /**< Handover failed. */
} mac_handover_phase_t;


/**
 * @brief Routing PDU types (AODV-like).
 */
typedef enum {
	ROUTING_PDU_TYPE_RREQ, /**< Route Request */
	ROUTING_PDU_TYPE_RREP, /**< Route Reply */
	ROUTING_PDU_TYPE_RERR, /**< Route Error */
	// Add other routing types if needed (e.g., RREP_ACK)
} routing_pdu_type_t;

/**
 * @brief CVG service types.
 */
typedef enum {
	CVG_SERVICE_TYPE_DATA,      /**< Regular data service (e.g., IPv6 payload) */
	CVG_SERVICE_TYPE_MOBILITY,  /**< Mobility-related control messages */
	CVG_SERVICE_TYPE_ACK,       /**< Acknowledgment for CVG layer (if any, separate from DLC ARQ) */
	CVG_SERVICE_TYPE_CONTROL,   /**< Generic control messages for CVG layer */
} cvg_service_type_t;

// --- Structs ---

/**
 * @brief MAC Information Element (IE) structure.
 * Used for including variable-length information in MAC PDUs (e.g., Beacons).
 */
typedef struct {
	uint8_t type; /**< IE Type */
	uint8_t len;  /**< IE Length (number of data bytes) */
	const uint8_t *data; /**< Pointer to IE data */
} mac_ie_t;

// KEEEP FOR REFEERENCE
// /**
//  * @brief PHY RX packet structure.
//  * Contains the received data buffer and associated metadata from the PHY layer.
//  */
// typedef struct {
// 	struct net_buf *data_buf; /**< Net buffer containing the received PHY payload. */
// 	int8_t rssi; /**< Received Signal Strength Indicator in dBm. */
// 	uint8_t channel; /**< Channel ID on which the packet was received. */
// 	bool crc_ok; /**< True if PHY CRC check passed. */
// 	uint16_t src_short_rd_id; /**< Short RD ID of the sender. */
// 	uint32_t hpc; /**< Half-Permanent Counter for encryption context. */
// 	uint16_t psn; /**< Packet Sequence Number for encryption context. */
// } nrf9161_dect_rx_packet_t;

/**
 * @brief MAC transmit PDU entry.
 * Used for tracking outstanding MAC PDUs sent to the PHY, primarily for HARQ.
 */
typedef struct {
	uint16_t dest_short_rd_id; /**< Destination Short RD ID. */
	struct net_buf *mac_pdu_buf; /**< The net_buf containing the MAC PDU payload. */
	uint32_t dlc_seq_num; /**< DLC sequence number of the payload in this MAC PDU. */
	uint32_t harq_transaction_id; /**< Unique ID for the HARQ transaction. */
	uint8_t retransmission_count; /**< Number of retransmissions so far. */
	// Add a k_timer if per-PDU MAC layer timers are needed for HARQ
	// struct k_timer tx_timer;
	uint64_t next_tx_time_modem_units; /**< Next scheduled TX time in modem units */
	bool is_retransmission; /**< Flag to indicate if this is a retransmission. */
} mac_tx_pdu_entry_t;

/**
 * @brief MAC context structure.
 * Holds the current state and configuration of the MAC layer.
 */
typedef struct {
	mac_role_t device_role;        /**< Configured device role (FP/PP). */
	mac_assoc_state_t assoc_state; /**< Current association state. */
	mac_sync_state_t sync_state;   /**< Current synchronization state. */
	uint16_t local_short_rd_id;    /**< Our own Short RD ID. */
	uint8_t mac_address[LONG_RD_ID_LEN_BYTES]; /**< Our own Long RD ID (MAC address). */
	uint16_t associated_fp_short_rd_id; /**< Short RD ID of associated FP (if PP). */
	uint16_t associated_pp_short_rd_id; /**< Short RD ID of associated PP (if FP). */
	uint32_t current_hpc;          /**< Current Half-Permanent Counter for crypto. */
	uint16_t current_psn;          /**< Current Packet Sequence Number for crypto. */
	struct net_if *net_if_ptr;     /**< Pointer to Zephyr net_if for this DECT interface. */
	// Timers for MAC procedures
	struct k_timer assoc_timer;    /**< Timer for association attempts. */
	struct k_timer sync_timer;     /**< Timer for synchronization maintenance (PP). */
	// Message queues for inter-layer communication
	struct k_msgq mac_tx_msgq;     /**< From DLC/Security to MAC. */
	struct k_msgq mac_rx_msgq;     /**< From PHY to MAC. */
	// HARQ related
	struct k_fifo mac_outstanding_tx_fifo; /**< FIFO for tracking outstanding TX PDUs for HARQ. */
	// Mobility related
	mac_handover_phase_t current_handover_phase; /**< Current phase of any active handover. */
	uint16_t target_fp_for_handover;             /**< Short RD ID of the target FP during handover. */
	struct k_timer handover_timer;               /**< Timer for handover process. */
	uint8_t handover_retries_count;              /**< Retries for current handover attempt. */
	// For FP: list of potential FP candidates (e.g., for PP to handover to)
	// For PP: list of scanned FP candidates for reselection/handover
	dect_fp_candidate_t fp_candidates[MAX_PEERS]; /**< Scanned FP candidates (for PP) / Known FPs (for FP). */
	uint8_t num_fp_candidates;                   /**< Number of active FP candidates. */
	uint64_t last_scan_attempt_ms;               /**< Timestamp of last channel scan attempt (for PP). */

	K_MUTEX_DEFINE(mutex); /**< Mutex to protect MAC context access. */
} dect_mac_context_t;

/**
 * @brief DLC ARQ transmit buffer entry.
 * Stores information about a PDU awaiting acknowledgment.
 */
typedef struct {
	uint32_t seq_num;            /**< Sequence number of the transmitted PDU. */
	struct net_buf *dlc_pdu_buf; /**< The net_buf containing the DLC PDU payload. */
	uint8_t retransmission_count; /**< Number of retransmissions for this PDU. */
	uint64_t last_tx_time_ms;    /**< Timestamp of the last transmission attempt. */
	uint32_t rto;                /**< Retransmission Timeout for this PDU. */
	uint32_t harq_transaction_id; /**< HARQ transaction ID from MAC layer. */
	cvg_service_type_t service_type; /**< Service type of the original SDU (for context). */
	bool encrypted;              /**< True if the PDU is encrypted. */
	uint16_t dest_short_rd_id;   /**< Destination Short RD ID for this PDU. */
	bool is_routing_pdu;         /**< True if this is a routing PDU. */
} dlc_arq_tx_buffer_entry_t;

/**
 * @brief DLC ARQ receive buffer entry.
 * Stores out-of-order received PDUs for reordering.
 */
typedef struct {
	uint32_t seq_num;            /**< Sequence number of the received PDU. */
	struct net_buf *dlc_pdu_buf; /**< The net_buf containing the DLC PDU payload. */
	uint32_t harq_transaction_id; /**< HARQ transaction ID from MAC layer (for consistency). */
	cvg_service_type_t service_type; /**< Service type of the original SDU (for context). */
	bool encrypted;              /**< True if the PDU was encrypted. */
	bool valid;                  /**< True if this entry holds a valid received PDU. */
} dlc_arq_rx_buffer_entry_t;


/**
 * @brief DLC context structure.
 * Holds the current state and configuration of the DLC layer.
 */
typedef struct {
	uint32_t next_tx_seq_num;  /**< Next sequence number to use for transmission. */
	uint32_t next_rx_seq_num;  /**< Next expected sequence number for reception. */
	uint32_t current_rtt;      /**< Current Round Trip Time estimate (ms). */
	uint32_t rtt_var;          /**< Round Trip Time Variation estimate (ms). */
	uint32_t rto;              /**< Retransmission Timeout (ms). */
	uint16_t peer_advertised_tx_window_size; /**< Peer's advertised TX window size. */
	uint16_t peer_advertised_rx_window_size; /**< Peer's advertised RX window size. */
	dlc_arq_tx_buffer_entry_t tx_buffer[DLC_ARQ_TX_BUFFER_SIZE]; /**< ARQ TX buffer. */
	dlc_arq_rx_buffer_entry_t rx_buffer[DLC_ARQ_RX_BUFFER_SIZE]; /**< ARQ RX buffer. */
	struct k_timer retransmission_timer; /**< Timer for retransmissions. */
	struct k_timer ack_delay_timer;      /**< Timer for delayed ACKs. */
	bool ack_pending;                    /**< Flag: an ACK needs to be sent. */
	uint8_t ack_seq_num;                 /**< Sequence number to acknowledge. */

	K_MUTEX_DEFINE(mutex); /**< Mutex to protect DLC context access. */
} dect_dlc_context_t;

/**
 * @brief DLC TX message format.
 * Used for messages from CVG/Routing to DLC layer.
 */
typedef struct {
	uint16_t dest_short_rd_id; /**< Destination Short RD ID. */
	struct net_buf *dlc_pdu_buf; /**< The net_buf containing the SDU to be sent as DLC payload. */
	cvg_service_type_t service_type; /**< Service type of the original SDU. */
	qos_priority_t qos_priority; /**< QoS priority for this message. */
} dlc_tx_msg_t;

/**
 * @brief DLC RX message format.
 * Used for messages from MAC to DLC layer.
 */
typedef struct {
	uint16_t src_short_rd_id; /**< Source Short RD ID. */
	struct net_buf *dlc_pdu_buf; /**< The net_buf containing the DLC PDU payload. */
	int8_t rssi; /**< RSSI of the received packet. */
	uint32_t hpc; /**< Half-Permanent Counter from MAC. */
	uint16_t psn; /**< Packet Sequence Number from MAC. */
	dlc_pdu_type_t dlc_pdu_type; /**< Type of DLC PDU. */
} dlc_rx_msg_t;


/**
 * @brief CVG transmit SDU entry.
 * Used for messages from application to CVG layer.
 */
typedef struct {
	struct net_pkt *pkt;        /**< The network packet (e.g., IPv6) to be sent. */
	cvg_service_type_t service_type; /**< Type of service for this SDU. */
	uint64_t next_tx_time_ms;   /**< Next scheduled transmit time for this SDU. */
	// Add other fields relevant for CVG TX (e.g., QoS)
} cvg_tx_sdu_entry_t;

/**
 * @brief CVG receive SDU reassembly context.
 * Stores fragments as they arrive for reassembly.
 */
typedef struct {
	uint16_t src_short_rd_id;   /**< Source Short RD ID of the SDU. */
	uint16_t datagram_size;     /**< Total size of the original unfragmented SDU. */
	uint16_t datagram_tag;      /**< Unique identifier for the fragmented SDU. */
	uint16_t current_length;    /**< Current accumulated length of reassembled data. */
	uint8_t fragment_mask;      /**< Bitmask to track received fragments. */
	uint64_t last_rx_time_ms;   /**< Timestamp of the last received fragment. */
	struct net_pkt *pkt;        /**< The net_pkt being reassembled. */
	uint8_t first_hpc;          /**< HPC from the first fragment. */
	uint16_t first_psn;         /**< PSN from the first fragment. */
	// Add other fields as needed for reassembly (e.g., offset, next expected fragment)
} cvg_rx_sdu_reassembly_t;

/**
 * @brief CVG context structure.
 * Holds the current state and configuration of the CVG layer.
 */
typedef struct {
	uint16_t next_datagram_tag; /**< Next datagram tag to use for fragmentation. */
	cvg_rx_sdu_reassembly_t rx_reassembly_sessions[MAX_PEERS]; /**< Per-peer reassembly contexts. */
	struct k_timer reassembly_timeout_timer; /**< Timer for reassembly timeouts. */
	K_MUTEX_DEFINE(mutex); /**< Mutex to protect CVG context access. */
} dect_cvg_context_t;


/**
 * @brief Channel quality information structure.
 */
typedef struct {
	uint8_t channel_id;      /**< The ID of the channel (0-MAX_DECT_CHANNELS-1). */
	int8_t rssi_avg;         /**< Average RSSI in dBm. */
	uint8_t fer_avg;         /**< Average Frame Error Rate (0-100%). */
	uint32_t last_scan_time_ms; /**< Last time this channel was scanned/updated. */
	channel_status_t status; /**< Current status of the channel. */
} channel_quality_info_t;

/**
 * @brief Channel Manager context structure.
 */
typedef struct {
	channel_quality_info_t channel_info[MAX_DECT_CHANNELS]; /**< Array of channel quality information. */
	uint8_t current_active_channel;                         /**< The currently active channel ID. */
	K_MUTEX_DEFINE(mutex);                                  /**< Mutex to protect context access. */
} dect_channel_mgr_context_t;

/**
 * @brief Power Manager context structure.
 */
typedef struct {
	power_mode_t current_power_mode;    /**< Current power mode of the device. */
	power_mode_t requested_power_mode;  /**< Power mode requested by a module. */
	power_change_reason_t change_reason;/**< Reason for the last power mode change. */
	uint64_t last_activity_time_ms;     /**< Timestamp of the last detected activity. */
	struct k_timer inactivity_timer;    /**< Timer for inactivity detection. */
	struct k_timer transition_delay_timer; /**< Timer for power mode transition delays. */
	bool inactivity_timer_active;       /**< Flag indicating if inactivity timer is running. */
	bool transition_in_progress;        /**< Flag indicating a power mode transition is ongoing. */
	uint32_t lbt_failures_in_current_mode; /**< Number of LBT failures in current power mode. */
	uint32_t last_lbt_success_time_ms;  /**< Timestamp of the last successful LBT. */

	K_MUTEX_DEFINE(mutex); /**< Mutex to protect Power Manager context access. */
} dect_power_mgr_context_t;


/**
 * @brief Crypto context structure.
 * Stores the device pointer and potentially the loaded keys.
 */
typedef struct {
	const struct device *crypto_dev; /**< Pointer to the crypto device structure. */
	uint8_t session_key[AES_KEY_LEN];/**< Current session key. */
	bool session_key_valid;          /**< True if session key is valid. */
	K_MUTEX_DEFINE(mutex);           /**< Mutex to protect crypto context. */
} dect_crypto_context_t;

/**
 * @brief DECT NR+ security context structure.
 */
typedef struct {
	security_auth_state_t auth_state; /**< Current authentication state with peer. */
	uint16_t peer_short_rd_id;        /**< Short RD ID of the peer in current handshake. */
	uint8_t local_nonce[SECURITY_NONCE_LEN]; /**< Our nonce for the current handshake. */
	uint8_t peer_nonce[SECURITY_NONCE_LEN];  /**< Peer's nonce received in handshake. */
	uint32_t current_hpc_rx;        /**< Current HPC received from peer. */
	uint16_t current_psn_rx;        /**< Current PSN received from peer. */
	struct k_timer handshake_timer;   /**< Timer for security handshake timeout. */
	K_MUTEX_DEFINE(mutex);            /**< Mutex to protect security context access. */
} dect_security_context_t;


/**
 * @brief Routing table entry.
 */
typedef struct {
	uint16_t dest_short_rd_id; /**< Destination Short RD ID. */
	uint16_t next_hop_short_rd_id; /**< Next hop Short RD ID to reach destination. */
	uint8_t hop_count;             /**< Number of hops to destination. */
	uint32_t dest_sequence_number; /**< Destination sequence number (for AODV). */
	uint64_t last_active_time_ms;  /**< Last time route was used/updated. */
	uint32_t route_lifetime_ms;    /**< How long route is valid for. */
	bool is_valid;                 /**< True if route is currently valid. */
} routing_table_entry_t;

/**
 * @brief Routing context structure.
 */
typedef struct {
	routing_table_entry_t routing_table[MAX_ROUTING_ENTRIES]; /**< Array of routing table entries. */
	uint8_t num_routing_entries;   /**< Current number of entries in the routing table. */
	uint32_t route_sequence_number; /**< Our own route sequence number. */
	uint32_t rreq_id_counter;       /**< Counter for RREQ IDs. */
	struct k_timer route_expiry_timer; /**< Timer for periodically checking route expiry. */
	K_MUTEX_DEFINE(mutex);         /**< Mutex to protect routing context access. */
} dect_routing_context_t;


/**
 * @brief DECT PHY information structure.
 * Stores details about discovered Fixed Parts during scanning (for Portable Parts).
 */
typedef struct {
	uint16_t short_rd_id; /**< Short RD ID of the Fixed Part. */
	uint8_t long_rd_id[LONG_RD_ID_LEN_BYTES]; /**< Long RD ID (MAC address) of the Fixed Part. */
	int8_t rssi; /**< Received Signal Strength Indicator from beacon. */
	uint8_t channel; /**< Channel on which the FP was detected. */
	uint32_t current_hpc; /**< Half-Permanent Counter from the FP's beacon. */
	uint16_t current_psn; /**< Packet Sequence Number from the FP's beacon. */
	uint64_t last_seen_ms; /**< Timestamp of the last received beacon from this FP. */
	// Add other FP capabilities advertised in beacon IEs
} dect_fp_candidate_t;


// --- In-line functions (if any) ---

/**
 * @brief Checks if a sequence number is greater than or equal to another, handling wrap-around.
 * Useful for sliding window protocols.
 *
 * @param s1 Sequence number 1.
 * @param s2 Sequence number 2.
 * @return True if s1 >= s2, considering wrap-around.
 */
static inline bool SEQ_NUM_IS_GREATER_EQUAL(uint8_t s1, uint8_t s2)
{
	return ((s1 - s2) & (DLC_MAX_SEQ_NUM >> 1)) < (DLC_MAX_SEQ_NUM >> 1);
}

#endif /* DECT_TYPES_H__ */

/* End of File
 * Last Amended: 2025-06-09 17:00 BST: Added tx_drops_no_mem and rx_drops_no_mem to dect_stats_t.
 * Last Amended: 2025-06-09 17:45 BST: Added CVG-specific drop statistics (cvg_tx_drops, cvg_rx_drops, cvg_frag_drops, cvg_reassembly_drops).
 * Last Amended: 2025-06-09 17:50 BST: Added DECT_MSGQ_PUT_OR_DROP macro for consistent message queue error handling.
 */
