/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_DLC_H__
#define DECT_DLC_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h>
#include <net/net_pkt.h> // For struct net_pkt
#include <net/net_buf.h> // For struct net_buf

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For dect_dlc_context_t, dlc_service_type_t, etc.

/**
 * @brief Global DLC context instance.
 * Defined in dect_dlc.c.
 */
extern dect_dlc_context_t dlc_ctx;

/* Message queues for inter-layer communication */
extern struct k_msgq dlc_rx_msgq; // From MAC to DLC
extern struct k_msgq dlc_tx_msgq; // From CVG/Routing to DLC

/**
 * @brief Initializes the Data Link Control (DLC) layer.
 * Sets up message queues, timers, and internal state.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_dlc_init(void);

/**
 * @brief Thread entry point for the DLC layer.
 * This thread is responsible for processing incoming and outgoing DLC messages,
 * managing ARQ, flow control, and interacting with the MAC and CVG layers.
 *
 * @param p1 Unused.
 * @param p2 Unused.
 * @param p3 Unused.
 */
void dect_dlc_thread(void *p1, void *p2, void *p3);

/**
 * @brief Sends data from the Convergence (CVG) layer to the DLC layer.
 * This function handles segmentation, ARQ, and flow control.
 *
 * @param data_buf Pointer to the net_buf containing the CVG SDU.
 * @param len Length of the CVG SDU.
 * @param dest_short_rd_id Destination Short RD ID.
 * @param qos_priority QoS priority for this data.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_send_data_from_cvg(struct net_buf *data_buf, size_t len,
                                     uint16_t dest_short_rd_id, qos_priority_t qos_priority);

/**
 * @brief Sends a routing PDU from the Routing layer to the DLC layer.
 * This function handles ARQ and flow control for routing messages.
 *
 * @param data_buf Pointer to the net_buf containing the routing PDU.
 * @param len Length of the routing PDU.
 * @param dest_short_rd_id Destination Short RD ID.
 * @param qos_priority QoS priority for this routing PDU.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_send_routing_pdu(struct net_buf *data_buf, size_t len,
                                   uint16_t dest_short_rd_id, qos_priority_t qos_priority);

/**
 * @brief Sends data forwarded by the Routing layer to the DLC layer.
 * This function handles ARQ and flow control for forwarded data.
 *
 * @param data_buf Pointer to the net_buf containing the data.
 * @param len Length of the data.
 * @param dest_short_rd_id Final destination Short RD ID.
 * @param next_hop_short_rd_id Next hop Short RD ID.
 * @param qos_priority QoS priority for this data.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_send_data_from_routing(struct net_buf *data_buf, size_t len,
                                         uint16_t dest_short_rd_id, uint16_t next_hop_short_rd_id,
                                         qos_priority_t qos_priority);

/**
 * @brief Receives data from the MAC layer and processes it.
 * This function is called by the MAC layer when a DLC PDU is received.
 * It handles decryption, CRC check, ARQ, and passes data to CVG/Routing.
 *
 * @param data_buf Pointer to the net_buf containing the DLC PDU payload.
 * @param len Length of the DLC PDU payload.
 * @param src_short_rd_id Source Short RD ID.
 * @param hpc Hyper Packet Counter.
 * @param psn Packet Sequence Number.
 * @param encrypted True if payload was encrypted.
 * @param dlc_pdu_type Type of DLC PDU.
 * @param dlc_seq_num DLC Sequence Number.
 * @param harq_transaction_id HARQ transaction ID from PHY.
 * @return DECT_STATUS_OK on successful processing, or an error code.
 */
dect_status_t dlc_receive_data_from_mac(struct net_buf *data_buf, size_t len,
                                        uint16_t src_short_rd_id, uint32_t hpc, uint16_t psn,
                                        bool encrypted, dlc_pdu_type_t dlc_pdu_type,
                                        uint8_t dlc_seq_num, uint8_t harq_transaction_id);

// /**
//  * @brief Notifies the DLC layer about the completion status of a MAC transmission.
//  * This is crucial for HARQ-enabled transmissions to update the DLC's ARQ state.
//  *
//  * @param dlc_seq_num The DLC sequence number of the transmitted PDU.
//  * @param harq_transaction_id The HARQ transaction ID associated with the transmission.
//  * @param status The status of the MAC transmission (DECT_STATUS_OK for success, or error code).
//  */
// void dlc_mac_tx_completion_notification(uint8_t dlc_seq_num, uint8_t harq_transaction_id, dect_status_t status);

/**
 * @brief Notifies the DLC layer of a MAC transmission completion.
 * This function is called by the MAC layer upon completion of a PHY transmission,
 * providing HARQ feedback and status.
 *
 * @param dest_short_rd_id The Short RD ID of the destination peer. // [FIX]: Added to match .c implementation.
 * @param harq_transaction_id HARQ transaction ID of the completed TX.
 * @param feedback HARQ feedback received (MAC_HARQ_FEEDBACK_ACK/NACK).
 * @param retransmission_count Number of retransmissions by PHY for this PDU.
 * @param phy_tx_status Status of the PHY transmission (DECT_STATUS_OK for success).
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_mac_tx_completion_notification(uint16_t dest_short_rd_id, uint32_t harq_transaction_id,
                                                 nrf_modem_dect_phy_harq_feedback_t feedback,
                                                 uint8_t retransmission_count, int phy_tx_status)
/**
 * @brief Initiates a DLC connection with a peer.
 *
 * @param peer_short_rd_id The Short RD ID of the peer to connect to.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_initiate_connection(uint16_t peer_short_rd_id);

/**
 * @brief Releases a DLC connection with a peer.
 *
 * @param peer_short_rd_id The Short RD ID of the peer to release connection with.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_release_connection(uint16_t peer_short_rd_id);

/**
 * @brief Notifies the DLC layer that a link failure has occurred.
 * This is typically called by the MAC layer.
 *
 * @param peer_short_rd_id The Short RD ID of the peer with whom the link failed.
 */
void dlc_mac_link_failure_notification(uint16_t peer_short_rd_id);

/**
 * @brief Sends an ACK/NACK PDU to the peer.
 * This function constructs and sends a DLC control PDU with ACK/NACK information.
 *
 * @param dest_short_rd_id Destination Short RD ID.
 * @param ack_num Cumulative ACK number.
 * @param nack_seq_nums Array of NACKed sequence numbers.
 * @param num_nacks Number of NACKed sequence numbers.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_send_ack_nack(uint16_t dest_short_rd_id, uint8_t ack_num,
                                const uint8_t *nack_seq_nums, uint8_t num_nacks);

/**
 * @brief Sends a Flow Control PDU to the peer.
 * This function advertises the receiver's window size.
 *
 * @param dest_short_rd_id Destination Short RD ID.
 * @param tx_window_size Our advertised TX window size.
 * @param rx_window_size Our advertised RX window size.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_send_flow_control_pdu(uint16_t dest_short_rd_id,
                                        uint8_t tx_window_size, uint8_t rx_window_size);

/**
 * @brief Timer handler for DLC retransmission timeout.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dlc_retransmission_timer_handler(struct k_timer *timer_id);

/**
 * @brief Timer handler for DLC connection timeout.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dlc_conn_timeout_handler(struct k_timer *timer_id);

/**
 * @brief Timer handler for DLC release timeout.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dlc_release_timeout_handler(struct k_timer *timer_id);

/**
 * @brief Timer handler for delayed ACK.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dlc_delayed_ack_timer_handler(struct k_timer *timer_id);

/**
 * @brief Updates the Retransmission Timeout (RTO) based on SRTT and RTTVAR.
 *
 * @param srtt Smoothed Round-Trip Time.
 * @param rttvar Round-Trip Time Variation.
 * @return The calculated RTO in milliseconds.
 */
uint32_t dlc_update_rto(uint32_t srtt, uint32_t rttvar);

#endif /* DECT_DLC_H__ */

/* End of File
 * Last Amended: 2025-06-04 14:00 BST: Updated dect_dlc.h
 * - Added `dlc_mac_tx_completion_notification` prototype to allow MAC to inform DLC about TX status.
 */


/* End of File
 * Last Amended: 2025-05-31 15:20 BST: Added initial function prototypes and footer.
 * Last Amended: 2025-06-02 16:10 BST: Added `dlc_send_routing_pdu` prototype.
 * Last Amended: 2025-06-02 18:40 BST: Updated `dect_dlc.h` for ARQ robustness, flow control, and delayed ACKs.
 * Added `dlc_allocate_buffers` prototype for dynamic buffer allocation.
 * Added `dlc_send_ack_nack` and `dlc_send_flow_control_pdu` prototypes.
 * Updated `dlc_send_data_to_dlc` signature to include `qos_priority` and `pdu_type`.
 * Added `dlc_process_arq_data` prototype for handling ARQ.
 * Added `dlc_retransmission_timer_handler` and `dlc_delayed_ack_timer_handler` prototypes.
 * Updated Doxygen comments for new and modified functions.
 */

/*
 * File Amendment History:
 * - 2025-05-31 15:20 BST: Initial version with basic DLC functions.
 * - 2025-05-31 16:10 BST: Added ARQ related functions and context.
 * - 2025-05-31 16:20 BST: Renamed `dlc_send_data_to_mac` to `dlc_send_data_from_cvg`
 * to clarify source.
 * - 2025-05-31 16:40 BST: No changes.
 * - 2025-05-31 17:00 BST: No changes.
 * - 2025-05-31 17:30 BST: Added `dlc_send_routing_pdu` for routing control messages.
 * Added `dlc_send_data_from_routing` for data packets forwarded by routing.
 * Updated `dlc_rx_msg_t` to include `dlc_pdu_type`.
 * Updated `dlc_receive_data_from_mac` signature to include `dlc_pdu_type`.
 * - 2025-06-02 12:07 BST: Added `peer_advertised_tx_window_size` and `peer_advertised_rx_window_size`
 * to `dect_dlc_context_t` for enhanced flow control. Updated `dlc_receive_data_from_mac`
 * to store these values, and `dlc_send_data_from_cvg` and `dlc_send_data_from_routing`
 * to use `effective_tx_window_size` based on peer's advertised RX window.
 */

/*
 * File Amendment History:
 * - 2025-05-31 15:20 BST: Updated function signatures to return dect_status_t for comprehensive error handling.
 * Added footer comment block.
 * - 2025-05-31 15:49 BST: Implemented IPv6 multicast and broadcast handling in cvg_send_ipv6_pkt.
 * Mapped IPv6 all-nodes multicast (ff02::1) to DECT NR+ broadcast (SHORT_RD_ID_BROADCAST).
 * Conceptualized mapping for other IPv6 multicast addresses to SHORT_RD_ID_MULTICAST_DEFAULT.
 * - 2025-05-31 16:10 BST: Added `k_timer` to `dlc_tx_buffer_entry_t` for per-PDU retransmission timers.
 */
