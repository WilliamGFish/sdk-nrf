/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_ROUTING_H__
#define DECT_ROUTING_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h> // For k_timer, k_msgq, k_mutex

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For dect_routing_context_t, routing_pdu_type_t, routing_rreq_pdu_t, etc.

/**
 * @brief Global Routing context instance.
 * Defined in dect_routing.c.
 */
extern dect_routing_context_t routing_ctx;

/* Message queues for inter-layer communication */
extern struct k_msgq routing_rx_msgq; // From DLC to Routing
extern struct k_msgq routing_tx_msgq; // From Routing to DLC

/**
 * @brief Initializes the DECT NR+ Routing layer.
 * Sets up routing table, timers, and internal state.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_routing_init(void);

/**
 * @brief Initiates a route discovery process to a destination.
 * This function is called by higher layers (e.g., CVG) when a packet needs
 * to be sent to a destination for which no route is known. It broadcasts
 * a Route Request (RREQ) PDU.
 *
 * @param dest_short_rd_id The Short RD ID of the destination peer.
 * @return DECT_STATUS_OK if route discovery initiated, or an error code.
 */
dect_status_t dect_routing_discover_route(uint16_t dest_short_rd_id);

// /**
//  * @brief Sends data through the Routing layer to a destination peer.
//  * This function is called by the CVG layer to send application data which
//  * may require routing. It will lookup a route or initiate route discovery.
//  *
//  * @param dest_short_rd_id The Short RD ID of the destination peer.
//  * @param data_buf Pointer to the net_buf containing the data to send.
//  * @param service_type The CVG service type for the data (e.g., IPv6).
//  * @return DECT_STATUS_OK on success, or an error code.
//  */
// dect_status_t dect_routing_send_data(uint16_t dest_short_rd_id, struct net_buf *data_buf, cvg_service_type_t service_type);

/**
 * @brief Sends data through the Routing layer to a destination peer.
 * This function is called by the CVG layer to send application data which
 * may require routing. It will lookup a route or initiate route discovery.
 *
 * @param dest_short_rd_id The Short RD ID of the destination peer.
 * @param data_buf Pointer to the net_buf containing the data to send.
 * @param qos_priority Quality of Service priority for the data. // [FIX]: Changed parameter type to match .c.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_routing_send_data(uint16_t dest_short_rd_id, struct net_buf *data_buf, qos_priority_t qos_priority);

// /**
//  * @brief Processes an incoming Routing PDU from the DLC layer.
//  * This function parses the received Routing PDU (RREQ, RREP, RERR) and
//  * updates the routing table accordingly.
//  *
//  * @param dlc_pdu_buf Pointer to the net_buf containing the DLC PDU.
//  * @param src_short_rd_id The Short RD ID of the source peer.
//  * @return DECT_STATUS_OK on success, or an error code.
//  */
// dect_status_t dect_routing_process_incoming_pdu(struct net_buf *dlc_pdu_buf, uint16_t src_short_rd_id);

/**
 * @brief Processes an incoming Routing PDU from the DLC layer.
 * This function parses the received Routing PDU (RREQ, RREP, RERR) and
 * updates the routing table accordingly.
 *
 * @param src_short_rd_id The Short RD ID of the source peer. // [FIX]: Reordered to match .c.
 * @param routing_pdu_buf Pointer to the net_buf containing the Routing PDU. // [FIX]: Renamed from dlc_pdu_buf and reordered to match .c.
 * @param hpc Half-Permanent Counter from MAC. // [FIX]: Added to match .c.
 * @param psn Packet Sequence Number from MAC. // [FIX]: Added to match .c.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_routing_process_incoming_pdu(uint16_t src_short_rd_id, struct net_buf *routing_pdu_buf,
                                                uint32_t hpc, uint16_t psn);

/**
 * @brief Notifies the Routing layer of a link failure.
 * This function is called by the DLC/MAC layer when a link to a next hop
 * fails, allowing the Routing layer to invalidate affected routes and
 * potentially initiate Route Error (RERR) messages.
 *
 * @param peer_short_rd_id The Short RD ID of the peer whose link failed.
 * @param reason The reason for the link failure.
 */
void dect_routing_link_failure_notification(uint16_t peer_short_rd_id, mac_link_failure_reason_t reason);

/**
 * @brief Timer handler for route discovery timeout.
 * This function is called when a route discovery process times out,
 * indicating that no route could be found within the allotted time.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dect_routing_route_discovery_timeout_handler(struct k_timer *timer_id);

/**
 * @brief Timer handler for route expiry cleanup.
 * This function periodically scans the routing table and removes expired routes.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dect_routing_route_expiry_handler(struct k_timer *timer_id);

/**
 * @brief Thread entry point for the Routing layer.
 *
 * This thread is responsible for processing incoming and outgoing routing messages,
 * managing the routing table, and interacting with the DLC layer.
 *
 * @param p1 Unused.
 * @param p2 Unused.
 * @param p3 Unused.
 */
void dect_routing_thread(void *p1, void *p2, void *p3);

#endif /* DECT_ROUTING_H__ */

/* End of File
 * Last Amended: 2025-05-31 15:20 BST: Added initial function prototypes and footer.
 * Last Amended: 2025-06-02 21:00 BST: Implemented Recommendation 14 for dect_routing.h.
 * Added `dect_routing_discover_route` prototype for initiating route discovery.
 * Added `dect_routing_send_data` prototype for sending data through the routing layer.
 * Added `dect_routing_process_incoming_pdu` prototype for processing incoming routing PDUs.
 * Added `dect_routing_link_failure_notification` for link failure notifications.
 * Updated `dect_routing_context_t` with new fields (`num_routing_entries`, `route_sequence_number`, `rreq_id_counter`).
 * Added `routing_pdu_type_t` enum for routing PDU types.
 * Added `routing_rreq_pdu_t`, `routing_rrep_pdu_t`, `routing_rerr_pdu_t` structures.
 * Added `routing_table_entry_t` for routing table entries.
 * Added `routing_rx_msgq` and `routing_tx_msgq` message queue externs.
 * Added `dect_routing_route_discovery_timeout_handler` and `dect_routing_route_expiry_handler` timer prototypes.
 * Added `dect_routing_thread` prototype.
 */
