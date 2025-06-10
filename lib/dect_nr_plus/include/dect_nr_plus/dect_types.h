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
#define SECURITY_NONCE_LEN 8                 /**< Length of security nonce (bytes) */
#define MAC_MIC_LEN 8                        /**< Length of MAC Message Integrity Code (bytes) */

#define MAX_DECT_CHANNELS 10                 /**< Total number of DECT NR+ channels (0-9) */
#define MAX_PEERS 5                          /**< Maximum number of concurrent peers/associations */
#define MAX_MULTICAST_MEMBERS 5              /**< Maximum number of multicast group members */
#define MAX_ROUTING_ENTRIES 10               /**< Maximum entries in the routing table */
#define MAX_FRAGMENTS_PER_SDU 16             /**< Max number of fragments for a single SDU */

// Max PDU sizes based on typical DECT NR+ MAC payload (excluding MAC/PHY headers)
// Assuming a maximum DLC payload size of 1500 bytes for IP MTU compatibility
// minus DLC header (e.g., 4 bytes) and CRC (2 bytes).
// Note: This needs to align with underlying PHY/MAC capabilities.
#define MAC_MAX_PDU_SIZE 1500                /**< Max MAC PDU payload size (effectively DLC SDU size) */
#define DLC_DATA_HDR_LEN_BYTES 4             /**< Example DLC Data PDU header length */
#define DLC_CONTROL_HDR_LEN_BYTES 2          /**< Example DLC Control PDU header length */
#define DLC_CRC_LEN_BYTES 2                  /**< DLC CRC length */
#define DLC_ACK_HDR_LEN_BYTES 2              /**< DLC ACK PDU header length (seq + window) */


// Service Type definitions
#define CVG_SERVICE_TYPE_DATA 0x01           /**< CVG service type for data */
#define CVG_SERVICE_TYPE_CONTROL 0x02        /**< CVG service type for control messages */

// Fixed Short RD IDs
#define SHORT_RD_ID_BROADCAST 0xFFFF         /**< Broadcast Short RD ID */
#define SHORT_RD_ID_MULTICAST_DEFAULT 0xFFFE /**< Default multicast Short RD ID */

// Thread Stack Sizes (moved from config, should be in Kconfig)
#ifndef CONFIG_DECT_NR_PLUS_MAC_STACK_SIZE
#define CONFIG_DECT_NR_PLUS_MAC_STACK_SIZE 2048
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_STACK_SIZE
#define CONFIG_DECT_NR_PLUS_DLC_STACK_SIZE 2048
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_THREAD_STACK_SIZE // Updated for combined CVG thread
// Combined stack size of previous TX and RX threads
#define CONFIG_DECT_NR_PLUS_CVG_THREAD_STACK_SIZE (2048 + 2048)
#endif
#ifndef CONFIG_DECT_NR_PLUS_ROUTING_STACK_SIZE
#define CONFIG_DECT_NR_PLUS_ROUTING_STACK_SIZE 2048
#endif

// Message Queue Sizes (moved from config, should be in Kconfig)
#ifndef CONFIG_DECT_NR_PLUS_MAC_TX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_MAC_TX_QUEUE_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_RX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_MAC_RX_QUEUE_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_TX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_DLC_TX_QUEUE_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_RX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_DLC_RX_QUEUE_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_TX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_CVG_TX_QUEUE_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_RX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_CVG_RX_QUEUE_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_ROUTING_TX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_ROUTING_TX_QUEUE_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_ROUTING_RX_QUEUE_COUNT
#define CONFIG_DECT_NR_PLUS_ROUTING_RX_QUEUE_COUNT 10
#endif

// Net Buffer Pool Sizes (moved from config, should be in Kconfig)
#ifndef CONFIG_DECT_NR_PLUS_MAC_TX_BUF_COUNT
#define CONFIG_DECT_NR_PLUS_MAC_TX_BUF_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE
#define CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE 2048
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_RX_BUF_COUNT
#define CONFIG_DECT_NR_PLUS_MAC_RX_BUF_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_RX_BUF_SIZE
#define CONFIG_DECT_NR_PLUS_MAC_RX_BUF_SIZE 2048
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_TX_BUF_COUNT
#define CONFIG_DECT_NR_PLUS_DLC_TX_BUF_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_TX_BUF_SIZE
#define CONFIG_DECT_NR_PLUS_DLC_TX_BUF_SIZE 2048
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_RX_BUF_COUNT
#define CONFIG_DECT_NR_PLUS_DLC_RX_BUF_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_RX_BUF_SIZE
#define CONFIG_DECT_NR_PLUS_DLC_RX_BUF_SIZE 2048
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_TX_BUF_COUNT
#define CONFIG_DECT_NR_PLUS_CVG_TX_BUF_COUNT 10
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_TX_BUF_SIZE
#define CONFIG_DECT_NR_PLUS_CVG_TX_BUF_SIZE 2048
#endif

// Default timeout values (should be in Kconfig)
#ifndef CONFIG_DECT_NR_PLUS_CHANNEL_SCAN_DURATION_MS
#define CONFIG_DECT_NR_PLUS_CHANNEL_SCAN_DURATION_MS 500
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE
#define CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE 1280 // Default MTU for 6LoWPAN is 1280, typically smaller due to L2 overhead
#endif
#ifndef CONFIG_DECT_NR_PLUS_CHANNEL_RESELECTION_INTERVAL_MS
#define CONFIG_DECT_NR_PLUS_CHANNEL_RESELECTION_INTERVAL_MS 60000 // 1 minute
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_ASSOC_RETRY_TIMEOUT_MS
#define CONFIG_DECT_NR_PLUS_MAC_ASSOC_RETRY_TIMEOUT_MS 5000 // 5 seconds
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_SYNC_RETRY_TIMEOUT_MS
#define CONFIG_DECT_NR_PLUS_MAC_SYNC_RETRY_TIMEOUT_MS 2000 // 2 seconds
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_MS
#define CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_MS 200 // Initial RTT for DLC
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_VAR_MS
#define CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_VAR_MS 50 // Initial RTT Variation
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTO_MS
#define CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTO_MS 400 // Initial Retransmission Timeout (should be > RTT)
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_ACK_DELAY_MS
#define CONFIG_DECT_NR_PLUS_DLC_ACK_DELAY_MS 20 // 20ms delayed ACK
#endif
#ifndef CONFIG_DECT_NR_PLUS_POWER_MODE_IDLE_TIMEOUT_MS
#define CONFIG_DECT_NR_PLUS_POWER_MODE_IDLE_TIMEOUT_MS 30000 // 30 seconds
#endif
#ifndef CONFIG_DECT_NR_PLUS_POWER_MODE_DEEP_SLEEP_TIMEOUT_MS
#define CONFIG_DECT_NR_PLUS_POWER_MODE_DEEP_SLEEP_TIMEOUT_MS 300000 // 5 minutes
#endif
#ifndef CONFIG_DECT_NR_PLUS_POWER_MODE_TRANSITION_DELAY_MS
#define CONFIG_DECT_NR_PLUS_POWER_MODE_TRANSITION_DELAY_MS 10 // 10ms for mode change
#endif
#ifndef CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS
#define CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS 600000 // 10 minutes
#endif
#ifndef CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_DISCOVERY_RETRIES
#define CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_DISCOVERY_RETRIES 3
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_TX_SLOT_DURATION_US
#define CONFIG_DECT_NR_PLUS_MAC_TX_SLOT_DURATION_US 2000 // Example: 2ms for a TX slot
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_RX_SLOT_DURATION_US
#define CONFIG_DECT_NR_PLUS_MAC_RX_SLOT_DURATION_US 2000 // Example: 2ms for a RX slot
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAC_MAX_RETRANSMISSIONS
#define CONFIG_DECT_NR_PLUS_MAC_MAX_RETRANSMISSIONS 3 // Max HARQ retransmissions
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE
#define CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE 8 // Max DLC TX window size
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE
#define CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE 8 // Max DLC RX window size
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES
#define CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES 5 // Max DLC retransmission retries
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_MIN_RTO_MS
#define CONFIG_DECT_NR_PLUS_DLC_MIN_RTO_MS 100 // Minimum RTO
#endif
#ifndef CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS
#define CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS 2000 // Maximum RTO
#endif
#ifndef CONFIG_DECT_NR_PLUS_MAX_PEERS
#define CONFIG_DECT_NR_PLUS_MAX_PEERS 5 // Max number of peers for stat tracking and reassembly
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_TIMEOUT_MS
#define CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_TIMEOUT_MS 60000 // 60 seconds (as per RFC recommendation)
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_MAX_FRAGMENTS
#define CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_MAX_FRAGMENTS 16 // Max fragments for one SDU
#endif
#ifndef CONFIG_DECT_NR_PLUS_CVG_THREAD_PRIORITY // Added for combined CVG thread
#define CONFIG_DECT_NR_PLUS_CVG_THREAD_PRIORITY 7
#endif


// --- Enums ---

/**
 * @brief Device roles.
 */
typedef enum {
	MAC_ROLE_FP, /**< Fixed Part (Base Station) */
	MAC_ROLE_PP, /**< Portable Part (Handset) */
} mac_role_t;

/**
 * @brief MAC Association states.
 */
typedef enum {
	MAC_ASSOC_STATE_IDLE,           /**< Not associated */
	MAC_ASSOC_STATE_ASSOCIATING,    /**< Attempting to associate */
	MAC_ASSOC_STATE_ASSOCIATED,     /**< Associated with a Fixed Part */
	MAC_ASSOC_STATE_DISASSOCIATING, /**< Releasing association */
} mac_assoc_state_t;

/**
 * @brief MAC Synchronization states.
 */
typedef enum {
	MAC_SYNC_STATE_IDLE,            /**< Not synchronized */
	MAC_SYNC_STATE_SYNCHRONIZING,   /**< Attempting to synchronize */
	MAC_SYNC_STATE_SYNCHRONIZED,    /**< Synchronized with a Fixed Part */
	MAC_SYNC_STATE_LOST,            /**< Synchronization lost */
} mac_sync_state_t;

/**
 * @brief MAC Header Types.
 */
typedef enum {
	MAC_HEADER_TYPE_1_DATA = 0x01,  /**< Type 1 Header for data (unicast/multicast) */
	MAC_HEADER_TYPE_1_CONTROL = 0x02, /**< Type 1 Header for control (unicast/multicast) */
	MAC_HEADER_TYPE_2_DATA = 0x03,  /**< Type 2 Header for data (broadcast) */
	MAC_HEADER_TYPE_2_CONTROL = 0x04, /**< Type 2 Header for control (broadcast) */
} mac_header_type_t;

/**
 * @brief MAC Control PDU Types.
 * These are values that would be encoded in the MAC header for control PDUs.
 */
typedef enum {
	MAC_CONTROL_TYPE_RESERVED = 0x00,
	MAC_CONTROL_TYPE_BEACON = 0x01,         /**< Beacon PDU (FP only) */
	MAC_CONTROL_TYPE_ASSOC_REQ = 0x02,      /**< Association Request PDU (PP to FP) */
	MAC_CONTROL_TYPE_ASSOC_RESP = 0x03,     /**< Association Response PDU (FP to PP) */
	MAC_CONTROL_TYPE_DISASSOC_REQ = 0x04,   /**< Disassociation Request PDU */
	MAC_CONTROL_TYPE_SECURITY_CHALLENGE = 0x05, /**< Security Challenge PDU */
	MAC_CONTROL_TYPE_SECURITY_RESPONSE = 0x06,  /**< Security Response PDU */
	MAC_CONTROL_TYPE_SECURITY_CONFIRM = 0x07,   /**< Security Confirmation PDU */
	MAC_CONTROL_TYPE_HANDOVER_REQUEST = 0x08,   /**< Handover Request (PP to FP) */
	MAC_CONTROL_TYPE_HANDOVER_RESPONSE = 0x09,  /**< Handover Response (FP to PP) */
	MAC_CONTROL_TYPE_HANDOVER_COMPLETE = 0x0A,  /**< Handover Complete (PP to FP) */
	MAC_CONTROL_TYPE_RESOURCE_REQUEST = 0x0B, /**< Resource Request (for specific time slots) */
	MAC_CONTROL_TYPE_RESOURCE_GRANT = 0x0C,   /**< Resource Grant */
	MAC_CONTROL_TYPE_RESOURCE_RELEASE = 0x0D, /**< Resource Release */
	// ... add more as needed
} mac_control_pdu_type_t;

/**
 * @brief MAC link failure reasons.
 */
typedef enum {
	MAC_LINK_FAILURE_REASON_NONE,
	MAC_LINK_FAILURE_REASON_INACTIVITY,      /**< Link lost due to inactivity timeout */
	MAC_LINK_FAILURE_REASON_DISASSOCIATED,   /**< Explicit disassociation */
	MAC_LINK_FAILURE_REASON_SECURITY_FAILED, /**< Security handshake failure */
	MAC_LINK_FAILURE_REASON_HANDOVER_FAILED, /**< Handover procedure failed */
	MAC_LINK_FAILURE_REASON_CHANNEL_QUALITY, /**< Channel quality degraded below threshold */
	MAC_LINK_FAILURE_REASON_PHY_ERROR,       /**< Underlying PHY error */
} mac_link_failure_reason_t;

/**
 * @brief DLC PDU Types.
 */
typedef enum {
	DLC_PDU_TYPE_DATA,         /**< Data PDU (carrying application/routing data) */
	DLC_PDU_TYPE_ACK,          /**< ACK PDU for ARQ (changed from ACK_NACK for clarity) */
	DLC_PDU_TYPE_NACK,         /**< NACK PDU for ARQ */
	DLC_PDU_TYPE_FLOW_CONTROL, /**< Flow Control PDU (window advertisement) */
	DLC_PDU_TYPE_CONNECT,      /**< Connection establishment PDU */
	DLC_PDU_TYPE_RELEASE,      /**< Connection release PDU */
	DLC_PDU_TYPE_ROUTING,      /**< Routing control PDU (e.g., RREQ, RREP, RERR) */
	DLC_PDU_TYPE_BEACON,       /**< Beacon PDU (can be passed up for some info) */
	// ... add more as needed
} dlc_pdu_type_t;

/**
 * @brief CVG Service Types.
 */
typedef enum {
	CVG_SERVICE_TYPE_UNKNOWN = 0x00,
	CVG_SERVICE_TYPE_DATA = 0x01,    /**< Data packet (IPv6, general application data) */
	CVG_SERVICE_TYPE_CONTROL = 0x02,   /**< CVG layer control messages (e.g. for connection setup) */
} cvg_service_type_t;

/**
 * @brief QoS Priority levels.
 */
typedef enum {
	QOS_PRIORITY_LOW,    /**< Best effort, lowest priority */
	QOS_PRIORITY_NORMAL, /**< Normal priority for general data */
	QOS_PRIORITY_HIGH,   /**< High priority for time-sensitive data */
	QOS_PRIORITY_CRITICAL, /**< Critical priority for control/signaling */
} qos_priority_t;

/**
 * @brief Power management modes.
 */
typedef enum {
	POWER_MODE_DEACTIVATED, /**< Device is powered off or fully deactivated. */
	POWER_MODE_ACTIVE,      /**< Device is fully active, ready for immediate TX/RX. */
	POWER_MODE_IDLE,        /**< Device is in a low-power idle state, but can quickly wake up. */
	POWER_MODE_DEEP_SLEEP,  /**< Device is in a deep sleep state, longer wake-up time. */
	POWER_MODE_STANDBY_LBT, /**< Device is in standby, performing LBT periodically. */
} power_mode_t;

/**
 * @brief Reasons for power mode change requests.
 */
typedef enum {
	POWER_CHANGE_REASON_INIT,         /**< Initial power-on/activation. */
	POWER_CHANGE_REASON_INACTIVITY,   /**< System inactivity detected. */
	POWER_CHANGE_REASON_ACTIVITY,     /**< Activity detected (TX/RX). */
	POWER_CHANGE_REASON_REQUEST,      /**< Explicit request from application/stack layer. */
	POWER_CHANGE_REASON_SYNC,         /**< Entering/exiting synchronization. */
	POWER_CHANGE_REASON_LBT_REQUIRED, /**< LBT is required, so enter standby_LBT. */
} power_change_reason_t;


/**
 * @brief Security authentication states.
 */
typedef enum {
	SECURITY_AUTH_STATE_NONE,           /**< No security established */
	SECURITY_AUTH_STATE_CHALLENGE_SENT, /**< Security Challenge sent, awaiting response */
	SECURITY_AUTH_STATE_RESPONSE_RCVD,  /**< Security Response received, awaiting confirm */
	SECURITY_AUTH_STATE_ESTABLISHED,    /**< Security established with peer */
} security_auth_state_t;

/**
 * @brief Channel status for Channel Manager.
 */
typedef enum {
	CHANNEL_STATUS_UNKNOWN,       /**< Channel status is unknown. */
	CHANNEL_STATUS_GOOD,          /**< Channel quality is good. */
	CHANNEL_STATUS_POOR,          /**< Channel quality is poor. */
	CHANNEL_STATUS_BLACKLISTED,   /**< Channel is explicitly blacklisted. */
	CHANNEL_STATUS_WHITELISTED,   /**< Channel is explicitly whitelisted. */
	CHANNEL_STATUS_BLOCKED_BY_WHITELIST, /**< Channel is not whitelisted, and whitelisting is active. */
} channel_status_t;

/**
 * @brief Routing PDU Types for AODV.
 */
typedef enum {
	ROUTING_PDU_TYPE_RREQ, /**< Route Request */
	ROUTING_PDU_TYPE_RREP, /**< Route Reply */
	ROUTING_PDU_TYPE_RERR, /**< Route Error */
	ROUTING_PDU_TYPE_DATA_FORWARD, /**< Data packet being forwarded by routing */
} routing_pdu_type_t;

/**
 * @brief PHY HARQ Feedback types.
 */
typedef enum {
	HARQ_FEEDBACK_NONE = 0, /**< No feedback yet or N/A */
	HARQ_FEEDBACK_ACK = 1,  /**< Positive acknowledgement */
	HARQ_FEEDBACK_NACK = 2, /**< Negative acknowledgement */
} harq_feedback_t;

/**
 * @brief MAC TX entry states for HARQ.
 */
typedef enum {
	MAC_TX_STATE_PENDING,       /**< PDU queued, awaiting first transmission */
	MAC_TX_STATE_TRANSMITTING,  /**< PDU sent, awaiting HARQ feedback */
	MAC_TX_STATE_RETRANSMITTING,/**< PDU retransmitted, awaiting HARQ feedback */
	MAC_TX_STATE_COMPLETED,     /**< PDU successfully transmitted (ACKed) */
	MAC_TX_STATE_FAILED,        /**< PDU transmission failed (max retries exceeded, NACKed) */
	MAC_TX_STATE_CANCELED,      /**< PDU transmission canceled (e.g., higher layer request) */
} mac_tx_state_t;

// --- Structures ---

/**
 * @brief Structure for Information Elements (IEs) in MAC PDUs.
 */
typedef struct {
	uint8_t id;    /**< IE Identifier */
	uint8_t len;   /**< Length of IE data */
	const uint8_t *data; /**< Pointer to IE data */
} mac_ie_t;

/**
 * @brief Structure to store channel quality information.
 */
typedef struct {
	int8_t rssi;            /**< Latest RSSI measurement in dBm. */
	uint8_t lqi;            /**< Latest Link Quality Indicator. */
	uint16_t fer_x100;      /**< Latest Frame Error Rate (FER) scaled by 100. */
	uint64_t last_updated_ms; /**< Timestamp of last quality update. */
	channel_status_t status; /**< Current status of the channel. */
} channel_quality_info_t;

/**
 * @brief MAC context structure.
 */
typedef struct {
	mac_role_t role;                        /**< Current device role (FP/PP). */
	mac_assoc_state_t assoc_state;          /**< Current association state. */
	mac_sync_state_t sync_state;            /**< Current synchronization state. */
	uint16_t local_short_rd_id;             /**< Our own Short RD ID. */
	uint8_t local_long_rd_id[LONG_RD_ID_LEN_BYTES]; /**< Our own Long RD ID. */
	uint16_t associated_fp_short_rd_id;     /**< Short RD ID of the associated Fixed Part (if PP). */
	uint64_t current_modem_time;            /**< Current modem time for scheduling. */
	struct k_timer association_timer;       /**< Timer for association process. */
	struct k_timer sync_timer;              /**< Timer for synchronization process. */
	struct k_timer inactivity_timer;        /**< Timer for inactivity detection. */
	struct k_timer resource_req_timer;      /**< Timer for resource requests. */
	struct k_timer handover_timer;          /**< Timer for handover process. */
	K_MUTEX_DEFINE(mutex);                  /**< Mutex to protect context access. */
	struct net_if *net_if_ptr;              /**< Pointer to the Zephyr network interface. */
	uint16_t fp_candidate_list[MAX_PEERS];  /**< List of detected FP candidates. */
	uint8_t num_fp_candidates;              /**< Number of active FP candidates. */
	uint16_t associated_peers[MAX_PEERS];   /**< Short RD IDs of currently associated peers. */
	uint8_t num_associated_peers;           /**< Number of associated peers. */
	uint16_t multicast_members[MAX_MULTICAST_MEMBERS]; /**< List of multicast group members. */
	uint8_t num_multicast_members;          /**< Number of active multicast members. */
	uint16_t associated_pp_short_rd_id; /**< Short RD ID of associated PP (if FP). */ // Added for FP role
} dect_mac_context_t;

/**
 * @brief Message structure for data from MAC to DLC.
 */
typedef struct {
	uint16_t src_short_rd_id;       /**< Source Short RD ID. */
	struct net_buf *dlc_pdu_buf;    /**< Pointer to the received DLC PDU buffer (owned by DLC). */
	int8_t rssi;                    /**< RSSI of the received frame. */
	uint32_t hpc;                   /**< Half-Permanent Counter from MAC. */
	uint16_t psn;                   /**< Packet Sequence Number from MAC. */
	dlc_pdu_type_t dlc_pdu_type;    /**< Type of the DLC PDU received. */
} dlc_rx_msg_t;

/**
 * @brief Message structure for data from CVG/Routing to DLC.
 */
typedef struct {
	uint16_t dest_short_rd_id;      /**< Destination Short RD ID. */
	struct net_buf *dlc_pdu_buf;    /**< Pointer to the SDU buffer (owned by DLC). */
	cvg_service_type_t service_type;/**< CVG service type. */
	qos_priority_t qos_priority;    /**< QoS priority. */
} dlc_tx_msg_t;


/**
 * @brief DLC context structure.
 */
typedef struct {
	uint8_t next_tx_seq_num;                /**< Next sequence number for outgoing data. */
	uint8_t next_rx_seq_num;                /**< Next expected sequence number for incoming data. */
	bool ack_pending;                       /**< True if an ACK needs to be sent. */
	uint8_t ack_seq_num;                    /**< Sequence number to acknowledge. */
	struct k_timer retransmission_timer;    /**< Timer for ARQ retransmissions. */
	struct k_timer ack_delay_timer;         /**< Timer for delayed ACKs. */
	struct k_timer conn_timeout_timer;      /**< Timer for connection establishment timeout. */
	struct k_timer release_timeout_timer;   /**< Timer for connection release timeout. */
	K_MUTEX_DEFINE(mutex);                  /**< Mutex to protect context access. */
	uint32_t current_rtt;                   /**< Current Smoothed Round Trip Time (SRTT). */
	uint32_t rtt_var;                       /**< Round Trip Time Variation. */
	uint32_t rto;                           /**< Retransmission Timeout. */
	// ARQ buffers for reliable delivery
	struct dlc_tx_entry {
		sys_snode_t node;             /**< Node for k_fifo */
		struct net_buf *dlc_pdu_buf;  /**< Pointer to the DLC PDU buffer (owned by DLC). */
		uint16_t dest_short_rd_id;    /**< Destination Short RD ID. */
		uint8_t seq_num;              /**< DLC Sequence Number. */
		uint8_t retransmission_count; /**< Number of transmission attempts. */
		uint32_t last_tx_time_ms;     /**< Timestamp of last transmission. */
		bool acknowledged;            /**< True if this PDU has been acknowledged. */
		qos_priority_t qos_priority;  /**< QoS priority for this PDU. */
		// bool is_fragment;          /**< True if this DLC PDU is an IPv6 fragment (handled in CVG) */
		uint32_t harq_transaction_id; /**< HARQ transaction ID from MAC. */
		uint32_t rto;                 /**< Current RTO for this specific entry. */
		cvg_service_type_t service_type; /**< Service type of the PDU. */
		bool is_routing_pdu;          /**< True if this is a routing PDU. */
		bool encrypted;               /**< True if this PDU was sent encrypted. */
	} tx_buffer[CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE];

	struct dlc_rx_entry {
		bool valid;                   /**< True if this entry holds a valid received PDU. */
		uint8_t seq_num;              /**< DLC Sequence Number. */
		struct net_buf *dlc_pdu_buf;  /**< Pointer to the received DLC PDU buffer. */
		uint16_t src_short_rd_id;     /**< Source Short RD ID. */
		cvg_service_type_t service_type; /**< Service type of the PDU. */
		uint32_t hpc;                 /**< HPC at receive. */
		uint16_t psn;                 /**< PSN at receive. */
		bool encrypted;               /**< True if the PDU was encrypted. */
	} rx_buffer[CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE];

	uint8_t peer_advertised_tx_window_size; /**< Peer's advertised TX window size (our RX window). */
	uint8_t peer_advertised_rx_window_size; /**< Peer's advertised RX window size (their RX window). */
} dect_dlc_context_t;

/**
 * @brief Reassembly session for incoming fragmented IPv6 packets.
 */
typedef struct cvg_rx_sdu_reassembly_t {
	struct net_pkt *pkt; // The reassembled net_pkt (or first fragment)
	uint32_t datagram_tag; // IPv6 Fragmentation Header Identification
	uint16_t datagram_size; // Total length of the original datagram (discovered from last fragment)
	uint16_t current_length; // Current length of reassembled data
	uint32_t fragment_mask; // Bitmask of received fragments (max MAX_FRAGMENTS_PER_SDU bits)
	uint16_t src_short_rd_id; // Source of the fragmented SDU
	uint32_t first_hpc; // HPC of the first fragment for consistency
	uint16_t first_psn; // PSN of the first fragment for consistency
	uint64_t last_rx_time_ms; // Timestamp of the last received fragment for this session
} cvg_rx_sdu_reassembly_t;

/**
 * @brief CVG context structure.
 */
typedef struct {
	uint32_t next_datagram_tag; /**< Next datagram tag to use for outgoing fragmented SDUs. */
	struct k_timer reassembly_timeout_timer; /**< Timer for SDU reassembly timeout. */
	K_MUTEX_DEFINE(mutex); /**< Mutex to protect context access. */
	struct net_if *net_if_ptr; /**< Pointer to the Zephyr network interface. */

	cvg_rx_sdu_reassembly_t rx_reassembly_sessions[MAX_PEERS]; // One reassembly session per peer
} dect_cvg_context_t;

/**
 * @brief Structure for queueing net_pkts from higher layers to CVG TX thread.
 * This wraps the net_pkt with destination and QoS information.
 */
typedef struct {
	struct net_pkt *pkt;          /**< Pointer to the net_pkt to be sent. */
	uint16_t dest_short_rd_id;    /**< Destination Short RD ID (resolved by application/routing). */
	qos_priority_t qos_priority;  /**< QoS priority for this packet. */
} cvg_tx_queue_entry_t;


/**
 * @brief Routing table entry.
 */
typedef struct {
	bool is_valid;                   /**< True if the route entry is valid. */
	uint16_t dest_short_rd_id;       /**< Destination Short RD ID. */
	uint16_t next_hop_short_rd_id;   /**< Next hop Short RD ID for this destination. */
	uint8_t hop_count;               /**< Number of hops to the destination. */
	uint32_t route_sequence_number;  /**< Destination sequence number (for AODV). */
	uint64_t last_active_time_ms;    /**< Timestamp of last activity for this route. */
	uint32_t route_lifetime_ms;      /**< Lifetime of this route entry. */
} routing_entry_t;

/**
 * @brief Routing context structure.
 */
typedef struct {
	routing_entry_t routing_table[MAX_ROUTING_ENTRIES]; /**< Array of routing table entries. */
	uint8_t num_routing_entries;                        /**< Current number of valid routing entries. */
	uint32_t route_sequence_number;                    /**< Our own route sequence number. */
	uint32_t rreq_id_counter;                          /**< Counter for Route Request IDs. */
	K_MUTEX_DEFINE(mutex);                              /**< Mutex to protect context access. */
	struct k_timer route_cleanup_timer;                 /**< Timer for periodically cleaning up expired routes. */
	struct k_timer rreq_timeout_timer;                  /**< Timer for RREQ timeouts. */
} dect_routing_context_t;


/**
 * @brief Security context structure.
 */
typedef struct {
	uint16_t peer_short_rd_id;             /**< Short RD ID of the peer we are securing. */
	security_auth_state_t auth_state;      /**< Current authentication state. */
	uint8_t local_nonce[SECURITY_NONCE_LEN]; /**< Our generated nonce. */
	uint8_t peer_nonce[SECURITY_NONCE_LEN];  /**< Peer's received nonce. */
	uint8_t session_key[AES_KEY_LEN];      /**< Derived session key. */
	bool session_key_valid;                /**< True if session key is valid. */
	struct k_timer security_timeout_timer; /**< Timer for security handshake timeouts. */
	K_MUTEX_DEFINE(mutex);                 /**< Mutex to protect context access. */
} dect_security_context_t;

/**
 * @brief Power Manager context structure.
 */
typedef struct {
	power_mode_t current_power_mode;      /**< The current power mode of the device. */
	power_mode_t requested_power_mode;    /**< The power mode requested by a module. */
	power_change_reason_t change_reason;  /**< The reason for the last power mode change. */
	uint64_t last_activity_time_ms;       /**< Timestamp of the last detected activity. */
	struct k_timer inactivity_timer;      /**< Timer to detect prolonged inactivity. */
	struct k_timer transition_delay_timer;/**< Timer for delaying power mode transitions. */
	bool transition_in_progress;          /**< Flag indicating an ongoing power mode transition. */
	K_MUTEX_DEFINE(mutex);                /**< Mutex to protect context access. */
	// State machine for power manager
	uint8_t state; // Could use enum power_mgr_state_t;
} dect_power_mgr_context_t;


/**
 * @brief Structure to hold common PHY-related information for TX/RX operations.
 */
typedef struct {
	nrf_modem_dect_phy_tx_type_t tx_type;    /**< Type of TX operation (e.g., PCC, PDC). */
	uint8_t tx_channel;                      /**< Channel ID for TX. */
	uint32_t start_time_us;                  /**< Absolute start time in modem units. */
	uint32_t duration_us;                    /**< Duration of TX/RX window in modem units. */
	// Add other common parameters as needed
} phy_op_params_t;


/**
 * @brief MAC Information Element for beacon content.
 * (Part 4, Clause 5.4.3.2.1, Table 5.4.3.2.1-1: Information Element types)
 */
typedef struct {
	uint8_t ie_type; /**< Type of the Information Element (e.g., System Info, Capability) */
	uint8_t ie_length; /**< Length of the IE payload in bytes */
	uint8_t ie_data[32]; /**< Placeholder for IE data, actual size depends on IE type */
} mac_ie_info_t;

/**
 * @brief MAC TX PDU entry for outstanding transmissions (for HARQ and retransmissions).
 */
typedef struct {
	sys_snode_t node;             /**< Node for k_fifo */
	struct net_buf *mac_pdu_buf;  /**< Pointer to the net_buf containing the complete MAC PDU. */
	uint16_t dest_short_rd_id;    /**< Destination Short RD ID. */
	mac_header_type_t mac_hdr_type;/**< MAC header type (Type 1 or Type 2). */
	dlc_pdu_type_t dlc_pdu_type;  /**< The type of DLC PDU (for statistics, etc.). */
	uint8_t dlc_seq_num;          /**< DLC sequence number of the transmitted PDU. */
	uint32_t harq_transaction_id; /**< The HARQ transaction ID associated with the transmission. */
	uint32_t current_hpc;         /**< HPC for this PDU. */
	uint16_t current_psn;         /**< PSN for this PDU. */
	bool encrypted;               /**< True if this PDU should be encrypted. */
	uint8_t tx_attempts;          /**< Number of transmission attempts for HARQ. */
	mac_tx_state_t state;         /**< Current state of the transmission entry. */
	uint32_t next_tx_time_ms;     /**< Earliest time this PDU can be transmitted (for scheduling). */
	void *phy_op_handle;          /**< Handle returned by PHY operation (e.g., for cancellation). */
} mac_tx_pdu_entry_t;


/**
 * @brief DECT NR+ overall statistics structure.
 */
typedef struct {
	uint32_t tx_frames;         /**< Total frames transmitted. */
	uint32_t rx_frames;         /**< Total frames received. */
	uint32_t tx_data_bytes;     /**< Total application data bytes transmitted. */
	uint32_t rx_data_bytes;     /**< Total application data bytes received. */

	// Layer-specific drops
	uint32_t tx_drops_no_mem;   /**< TX drops due to no memory (general). */
	uint32_t rx_drops_no_mem;   /**< RX drops due to no memory (general). */
	uint32_t tx_drops_queue_full; /**< TX drops due to message queue full. */
	uint32_t rx_drops_queue_full; /**< RX drops due to message queue full. */

	// MAC layer specific
	uint32_t mac_mic_failures;  /**< MAC MIC verification failures. */
	uint32_t mac_crc_errors;    /**< MAC CRC errors. */
	uint32_t mac_tx_drops;      /**< MAC TX drops (e.g., scheduling failed, no resources). */
	uint32_t mac_rx_drops;      /**< MAC RX drops (e.g., invalid header, unknown PDU type). */
	uint32_t mac_association_attempts; /**< Number of association attempts. */
	uint32_t mac_association_success; /**< Number of successful associations. */
	uint32_t mac_association_failures; /**< Number of association failures. */
	uint32_t mac_sync_attempts; /**< Number of synchronization attempts. */
	uint32_t mac_sync_success;  /**< Number of successful synchronizations. */
	uint32_t mac_sync_failures; /**< Number of synchronization failures. */
	uint32_t mac_handover_requests_tx; /**< Number of handover requests sent. */
	uint32_t mac_handover_responses_rx; /**< Number of handover responses received. */
	uint32_t mac_handover_success; /**< Number of successful handovers. */
	uint32_t mac_handover_failures; /**< Number of handover failures. */

	// DLC layer specific
	uint32_t dlc_crc_errors;    /**< DLC CRC errors. */
	uint32_t dlc_tx_drops;      /**< DLC TX drops (e.g., flow control, no ARQ buffer). */
	uint32_t dlc_rx_drops;      /**< DLC RX drops (e.g., invalid sequence, bad PDU type). */
	uint32_t dlc_retransmissions; /**< Number of DLC retransmissions. */
	uint32_t dlc_acks_tx;       /**< Number of ACKs transmitted. */
	uint32_t dlc_acks_rx;       /**< Number of ACKs received. */
	uint32_t dlc_nacks_tx;      /**< Number of NACKs transmitted. */
	uint32_t dlc_nacks_rx;      /**< Number of NACKs received. */
	uint32_t dlc_window_full_blocks; /**< Times TX was blocked by flow control window. */

	// CVG layer specific
	uint32_t cvg_tx_drops;      /**< CVG TX drops (e.g., queue full, fragmentation failed). */
	uint32_t cvg_rx_drops;      /**< CVG RX drops (e.g., invalid service type, queue full). */
	uint32_t cvg_frag_tx;       /**< Number of fragmented IP packets transmitted. */
	uint32_t cvg_frag_rx;       /**< Number of IP fragments received. */
	uint32_t cvg_frag_drops;    /**< Fragments dropped due to internal CVG issues. */
	uint32_t cvg_reassembly_success; /**< Number of successfully reassembled SDUs. */
	uint32_t cvg_reassembly_failures; /**< Number of reassembly failures (e.g., timeout, corrupt, missing fragments). */
	uint32_t cvg_reassembly_drops; /**< Fragments dropped during reassembly process. */
	uint32_t sixlo_compression_success; /**< Number of successful 6LoWPAN compressions. */
	uint32_t sixlo_compression_failures; /**< Number of 6LoWPAN compression failures. */
	uint32_t sixlo_decompression_success; /**< Number of successful 6LoWPAN decompresions. */
	uint32_t sixlo_decompression_failures; /**< Number of 6LoWPAN decompression failures. */

	// Routing layer specific
	uint32_t routing_tx_drops;  /**< Routing TX drops (e.g., no route). */
	uint32_t routing_rx_drops;  /**< Routing RX drops (e.g., invalid PDU, malformed). */
	uint32_t routing_route_discoveries; /**< Number of route discovery initiated. */
	uint32_t routing_route_success; /**< Number of successful route discoveries. */
	uint32_t routing_route_failures; /**< Number of failed route discoveries. */

	// Security layer specific
	uint32_t security_handshakes_initiated; /**< Number of security handshakes initiated. */
	uint32_t security_handshakes_processed; /**< Number of security handshakes processed. */
	uint32_t security_handshakes_success; /**< Number of successful security handshakes. */
	uint32_t security_handshakes_failures; /**< Number of failed security handshakes. */
	uint32_t security_tx_drops; /**< Security PDU TX drops. */
	uint32_t security_rx_drops; /**< Security PDU RX drops. */

	// Channel Manager specific
	uint32_t channel_reselection_attempts; /**< Number of channel reselection attempts. */
	uint32_t channel_reselection_success; /**< Number of successful channel reselections. */
	uint32_t channel_mgr_tx_drops; /**< Channel Manager related TX drops (e.g., phy set channel fail). */
	uint32_t channel_mgr_rx_drops; /**< Channel Manager related RX drops (e.g., phy scan fail). */
	uint32_t channel_blacklist_updates; /**< Number of times channel blacklist was updated. */
	uint32_t channel_whitelist_updates; /**< Number of times channel whitelist was updated. */

	// Power Manager specific
	uint32_t power_mode_changes; /**< Number of power mode transitions. */
	uint32_t power_idle_entries; /**< Number of times entered idle mode. */
	uint32_t power_deep_sleep_entries; /**< Number of times entered deep sleep mode. */
	uint32_t power_standby_lbt_entries; /**< Number of times entered standby with LBT. */

	// Broadcast Control (BCC) specific
	uint32_t bcc_beacons_tx; /**< Number of beacons transmitted. */
	uint32_t bcc_beacon_ie_errors; /**< Number of errors in beacon IE processing. */

	// Application-level stats (optional, depends on app interaction)
	uint32_t tx_app_data_requests; /**< Number of times application requested to send data. */

	// Add more specific stats as needed for detailed debugging and monitoring
	K_MUTEX_DEFINE(mutex); /**< Mutex to protect statistics access. */
} dect_stats_t;


/**
 * @brief Information about a detected Fixed Part candidate (for Portable Parts).
 */
typedef struct dect_fp_candidate_t {
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
 * Last Amended: 2025-06-05 15:30 BST: Updated dect_config.h for Mobility.
 * - Added `enable_mobility_support` flag.
 * - Added `t_mac_handover_timeout_ms` for handover negotiation timeout.
 * - Added `mac_max_handover_retries` for handover retry attempts.
 * - Included `t_mac_sync_loss_timeout_ms` which was missing from previous prj.conf but was in `dect_types.h`.
 * Last Amended: 2025-06-10 16:30 BST: Updated dect_types.h for IPv6 Fragmentation/Reassembly and improved consistency.
 * - Added `cvg_rx_sdu_reassembly_t` struct to `dect_cvg_context_t` for reassembly session tracking.
 * - Added `cvg_tx_queue_entry_t` struct for passing `net_pkt`s to the CVG TX thread with destination/QoS info.
 * - Moved various `CONFIG_DECT_NR_PLUS_` definitions from comments to actual `#ifndef` blocks,
 * as these should ideally be defined in Kconfig but serve as reasonable defaults here.
 * (Note: These should be removed from here if properly defined in Kconfig files.)
 * - Added `associated_pp_short_rd_id` to `dect_mac_context_t` for FP role.
 * - Corrected `DLC_PDU_TYPE_ACK_NACK` to `DLC_PDU_TYPE_ACK` and added `DLC_PDU_TYPE_NACK` separately.
 * - Added `DLC_PDU_TYPE_BEACON` to `dlc_pdu_type_t` for completeness.
 * - Added `DLC_ACK_HDR_LEN_BYTES` define.
 * - Added `CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES`, `CONFIG_DECT_NR_PLUS_DLC_MIN_RTO_MS`, `CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS` defines.
 * Last Amended: 2025-06-10 17:25 BST: Updated dect_types.h to align Kconfig fallbacks with the single combined CVG thread.
 * - Replaced `CONFIG_DECT_NR_PLUS_CVG_RX_STACK_SIZE` with `CONFIG_DECT_NR_PLUS_CVG_THREAD_STACK_SIZE` (sum of TX+RX).
 * - Removed individual TX/RX thread priority defines and added `CONFIG_DECT_NR_PLUS_CVG_THREAD_PRIORITY`.
 * Last Amended: 2025-06-10 17:35 BST: Implemented IPv6 Fragment Header Logic recommendations.
 * - Increased `CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_TIMEOUT_MS` to 60000ms (60 seconds) for robustness.
 * - Added `cvg_reassembly_failures` to `dect_stats_t` for tracking specific reassembly failures.
 * Last Amended: 2025-06-10 17:50 BST: Confirmed full implementation of IPv6 Fragment Header Logic recommendations. No further code changes.
 */
