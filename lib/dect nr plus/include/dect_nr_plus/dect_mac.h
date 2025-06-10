/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_MAC_H__
#define DECT_MAC_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr.h>
#include <device.h> // For struct device
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For all MAC related enums and structs
#include <dect_nr_plus/dect_phy_nrf9161.h> // Include for nrf9161_dect_rx_packet_t, and now for direct PHY interaction
#include <nrf_modem_dect_phy.h> // For HARQ feedback types and PHY API
#include <net/net_buf.h> // For struct net_buf

/**
 * @brief Global MAC context instance.
 * Defined in dect_mac.c.
 */
extern dect_mac_context_t mac_ctx;

/* Net buffer pool for MAC transmit PDUs */
NET_BUF_POOL_DEFINE(mac_tx_net_buf_pool, CONFIG_DECT_NR_PLUS_MAC_TX_BUF_COUNT,
					CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE, 0, NULL);

/* Message queues for inter-layer communication */
extern struct k_msgq mac_rx_msgq; // From PHY to MAC
extern struct k_msgq mac_tx_msgq; // From DLC to MAC

/* New message queue for PHY events */
extern struct k_msgq mac_phy_event_msgq; // From PHY event handler to MAC thread

/**
 * @brief Structure to hold an outgoing MAC PDU awaiting transmission.
 */
typedef struct {
	sys_snode_t node;             /**< Node for k_queue/k_fifo. Must be first. */
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


#define MAX_OUTSTANDING_TX 10 /**< Maximum number of outstanding TX entries. */

/**
 * @brief Initializes the Medium Access Control (MAC) layer.
 * Sets up message queues, timers, and internal state.
 *
 * @param phy_dev Pointer to the physical layer device structure.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_mac_init(const struct device *phy_dev);

/**
 * @brief Thread entry point for the MAC layer.
 *
 * This thread is responsible for processing incoming messages from the PHY,
 * outgoing messages from the DLC, managing the MAC state, and scheduling
 * transmissions with the PHY.
 *
 * @param p1 Unused.
 * @param p2 Unused.
 * @param p3 Unused.
 */
void dect_mac_thread(void *p1, void *p2, void *p3);

/**
 * @brief Sends a PDU from the DLC layer to the MAC for transmission.
 * This function queues the PDU for the MAC thread to process and schedule.
 *
 * @param dest_short_rd_id The Short RD ID of the destination peer.
 * @param mac_pdu_buf Pointer to the net_buf containing the DLC PDU payload. MAC takes ownership.
 * @param dlc_pdu_type The type of DLC PDU (used for statistics and internal MAC logic).
 * @param mac_hdr_type The type of MAC header to use (e.g., MAC_HEADER_TYPE_1_DATA).
 * @param hpc The current Half-Slot Packet Counter for encryption.
 * @param psn The current Packet Sequence Number for encryption.
 * @param is_retransmission True if this is a retransmission (for HARQ).
 * @param harq_transaction_id The HARQ transaction ID associated with the transmission.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_mac_send_pdu_from_dlc(uint16_t dest_short_rd_id, struct net_buf *mac_pdu_buf,
					 dlc_pdu_type_t dlc_pdu_type, mac_header_type_t mac_hdr_type,
					 uint32_t hpc, uint16_t psn, bool is_retransmission,
					 uint32_t harq_transaction_id);


// /**
//  * @brief Sends a PDU from the DLC layer to the MAC for transmission.
//  * This function queues the PDU for the MAC thread to process and schedule.
//  *
//  * @param dlc_pdu_buf Pointer to the net_buf containing the DLC PDU payload.
//  * @param dest_short_rd_id The Short RD ID of the destination peer.
//  * @param mac_hdr_type The type of MAC header to use (e.g., MAC_HEADER_TYPE_1_DATA).
//  * @param current_hpc The current Half-Slot Packet Counter for encryption.
//  * @param current_psn The current Packet Sequence Number for encryption.
//  * @param encrypted True if the PDU should be encrypted and integrity protected.
//  * @param dlc_pdu_type The type of DLC PDU (used for statistics and internal MAC logic).
//  * @param dlc_seq_num The DLC sequence number of the PDU.
//  * @param is_retransmission True if this is a retransmission (for HARQ).
//  * @return DECT_STATUS_OK on success, or an error code.
//  */
// dect_status_t dect_mac_send_pdu_from_dlc(struct net_buf *dlc_pdu_buf,
// 					 uint16_t dest_short_rd_id,
// 					 mac_header_type_t mac_hdr_type,
// 					 uint32_t current_hpc, uint16_t current_psn,
// 					 bool encrypted, dlc_pdu_type_t dlc_pdu_type,
// 					 uint8_t dlc_seq_num,
// 					 bool is_retransmission);

/**
 * @brief Notifies the DLC layer about the completion status of a MAC transmission.
 * This is crucial for HARQ-enabled transmissions to update the DLC's ARQ state.
 *
 * @param dlc_seq_num The DLC sequence number of the transmitted PDU.
 * @param harq_transaction_id The HARQ transaction ID associated with the transmission.
 * @param status The status of the MAC transmission (DECT_STATUS_OK for success, or error code).
 */
void dlc_mac_tx_completion_notification(uint8_t dlc_seq_num, uint32_t harq_transaction_id, dect_status_t status);


/**
 * @brief Notifies the MAC layer that a security handshake or connection has been established.
 * This can trigger state changes or allow data transmission.
 *
 * @param peer_short_rd_id The Short RD ID of the peer with which security is established.
 */
void mac_dlc_security_established_notification(uint16_t peer_short_rd_id);

/**
 * @brief Notifies the MAC layer that a security handshake or connection has failed/disconnected.
 *
 * @param peer_short_rd_id The Short RD ID of the peer.
 */
void mac_dlc_security_failed_notification(uint16_t peer_short_rd_id);

/**
 * @brief Notifies the MAC layer of a link failure (e.g., due to prolonged inactivity,
 * excessive errors, or explicit disconnect from a higher layer).
 * This triggers cleanup of peer state and potential re-association.
 *
 * @param peer_short_rd_id The Short RD ID of the peer for which the link failed.
 * @param reason The reason for the link failure.
 */
void dlc_mac_link_failure_notification(uint16_t peer_short_rd_id, mac_link_failure_reason_t reason);

/**
 * @brief Handler for PHY layer events from the nRF9161 modem.
 * This function processes asynchronous events from the PHY, such as TX completion,
 * RX of PCC/PDC, and various errors.
 *
 * @param event Pointer to the PHY event structure.
 * @param event_data Pointer to the PHY event data.
 */
void dect_mac_phy_event_handler(nrf_modem_dect_phy_event_id_t event_id, const nrf_modem_dect_phy_event_data_t *event_data)

#endif /* DECT_MAC_H__ */

/* End of File
 * Last Amended: 2025-06-05 18:30 BST: Updated dect_mac.h
 * - Added `mac_tx_pdu_entry_t` structure for MAC internal transmit queue.
 * - Defined `mac_phy_event_msgq` for inter-thread communication of PHY events.
 * - Modified `mac_harq_process_t` in dect_types.h (implicitly through this change) to include a state field.
 * - Added `phy_op_handle` to `mac_tx_pdu_entry_t` to link MAC PDUs to PHY operations.
 * - Added `mac_pdu_type` and `is_retransmission` flags to `mac_tx_pdu_entry_t`.
 * - Added `tx_timer` and `next_tx_time_ms` to `mac_tx_pdu_entry_t` for scheduling.
 * - Updated `dect_mac_send_pdu_from_dlc` prototype to include `mac_pdu_type`.
 * - Added `dect_mac_phy_event_handler` prototype for the new PHY event processing.
 * - Updated `dlc_mac_tx_completion_notification` to include `retransmission_count` and
 * `phy_op_handle` for better HARQ state management.
 * Last Amended: 2025-06-09 13:09 BST:
 * - Removed unused `dect_mac_receive_from_phy` prototype.
 * - Updated `dect_mac_send_pdu_from_dlc` prototype to exactly match its implementation.
 * - Updated `dlc_mac_tx_completion_notification` prototype to include `dest_short_rd_id` as the first parameter.
 * - Updated `dlc_mac_disconnected_notification` prototype to include `mac_link_failure_reason_t reason`.
 * - Removed `mac_add_multicast_member`, `mac_remove_multicast_member`, `mac_is_multicast_member` prototypes as they are internal static functions.
 * Last Amended: 2025-06-09 13:30 BST:
 * - Updated `mac_tx_pdu_entry_t` to include `dlc_seq_num` and `sys_snode_t node` for queuing.
 * - Added `MAX_OUTSTANDING_TX` macro.
 * - Updated `dlc_mac_tx_completion_notification` prototype to match `dect_dlc.h` with `uint8_t dlc_seq_num`, `uint32_t harq_transaction_id`, and `dect_status_t status`.
 * - Updated `dect_mac_send_pdu_from_dlc` prototype to include `dlc_seq_num`.
 */
