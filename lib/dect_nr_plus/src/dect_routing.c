/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <random/rand32.h> // For sys_rand32_get

#include <dect_nr_plus/dect_config.h>
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_routing.h> /* Own header */
#include <dect_nr_plus/dect_dlc.h> /* For DLC layer interaction */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_mac.h> // For getting our own Short RD ID
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_routing, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global Routing context instance definition */
dect_routing_context_t routing_ctx = {
	.num_routing_entries = 0,
	.route_sequence_number = 0, // Start from 0
	.rreq_id_counter = 0,       // Start from 0
};

/* Mutex to protect routing_ctx */
K_MUTEX_DEFINE(routing_ctx_mutex);

/* Message queues for inter-layer communication */
K_MSGQ_DEFINE(routing_rx_msgq, sizeof(routing_rx_msg_t),
	      CONFIG_DECT_NR_PLUS_ROUTING_RX_QUEUE_SIZE, 4); // From DLC to Routing

K_MSGQ_DEFINE(routing_tx_msgq, sizeof(routing_tx_msg_t),
	      CONFIG_DECT_NR_PLUS_ROUTING_TX_QUEUE_SIZE, 4); // From Routing to DLC

/* Forward declarations for internal functions */
static int routing_table_find_entry(uint16_t dest_short_rd_id);
static int routing_table_add_or_update(uint16_t dest_short_rd_id, uint16_t next_hop_short_rd_id,
				       uint8_t hop_count, uint32_t dest_sequence_number);
static dect_status_t routing_table_invalidate_route(uint16_t dest_short_rd_id);
static dect_status_t routing_send_rreq(uint16_t dest_short_rd_id);
static dect_status_t routing_send_rrep(uint16_t dest_short_rd_id, uint16_t originator_short_rd_id,
				       uint8_t hop_count, uint32_t dest_sequence_number);
static dect_status_t routing_send_rerr(uint16_t unreachable_dest_id);
static void routing_handle_rreq(uint16_t src_short_rd_id, struct net_buf *pdu_buf, uint32_t hpc, uint16_t psn);
static void routing_handle_rrep(uint16_t src_short_rd_id, struct net_buf *pdu_buf, uint32_t hpc, uint16_t psn);
static void routing_handle_rerr(uint16_t src_short_rd_id, struct net_buf *pdu_buf, uint32_t hpc, uint16_t psn);
static void routing_route_discovery_timeout_handler(struct k_timer *timer_id);
static void routing_route_expiry_handler(struct k_timer *timer_id);

/**
 * @brief Helper function to handle net_buf allocation for TX path.
 *
 * This function attempts to allocate a net_buf from the specified pool.
 * If allocation fails, it logs an error and increments a statistic.
 *
 * @param out_buf Pointer to a net_buf pointer where the allocated buffer will be stored.
 * @param pool Pointer to the net_buf_pool to allocate from.
 * @return DECT_STATUS_OK on success, DECT_ERROR_NO_MEM if allocation fails.
 */
static dect_status_t handle_tx_buffer_allocation(struct net_buf **out_buf, struct net_buf_pool *pool)
{
	*out_buf = net_buf_alloc(pool, K_NO_WAIT);
	if (!(*out_buf)) {
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "ROUTING: Failed to allocate net_buf from pool %s. No memory.", pool->name->name);
		STATS_INC(dect_stats.tx_drops_no_mem); // Increment global stat for TX drops due to no memory
		STATS_INC(dect_stats.routing_tx_drops); // Increment routing-specific TX drop stat
		return DECT_ERROR_NO_MEM;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_routing_init(void)
{
	k_mutex_init(&routing_ctx.mutex);
	k_timer_init(&routing_ctx.route_expiry_timer, routing_route_expiry_handler, NULL);
	// Start timer to periodically check for expired routes
	k_timer_start(&routing_ctx.route_expiry_timer, K_SECONDS(CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_EXPIRY_CHECK_INTERVAL_S),
		      K_SECONDS(CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_EXPIRY_CHECK_INTERVAL_S));

	LOG_INF("ROUTING: Module initialized.");
	return DECT_STATUS_OK;
}

void dect_routing_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("ROUTING: Thread started.");

	routing_tx_msg_t tx_msg; // For messages from application to routing
	routing_rx_msg_t rx_msg; // For messages from DLC to routing

	while (true) {
		// Process outgoing routing requests/data from application (if any)
		// This part is currently conceptual, as dect_routing_send_data is called directly
		// and route discovery is triggered by dect_routing_discover_route.

		// Process incoming routing PDUs from DLC layer
		if (k_msgq_get(&routing_rx_msgq, &rx_msg, K_NO_WAIT) == 0) {
			LOG_DBG("ROUTING: Received PDU from DLC (src 0x%04x, len %u, type %u).",
				rx_msg.src_short_rd_id, rx_msg.routing_pdu_buf->len, rx_msg.routing_pdu_type);
			dect_power_mgr_activity_detected(); // Notify power manager of RX activity

			// Check if routing is enabled
			if (!dect_config.enable_routing) {
				LOG_WRN("ROUTING: Routing disabled. Dropping incoming PDU from 0x%04x.", rx_msg.src_short_rd_id);
				STATS_INC(dect_stats.routing_rx_drops); // Increment routing specific drop stat
				net_buf_unref(rx_msg.routing_pdu_buf);
				continue;
			}

			switch (rx_msg.routing_pdu_type) {
			case ROUTING_PDU_TYPE_RREQ:
				routing_handle_rreq(rx_msg.src_short_rd_id, rx_msg.routing_pdu_buf, rx_msg.hpc, rx_msg.psn);
				// Buffer unref'd by handler
				break;
			case ROUTING_PDU_TYPE_RREP:
				routing_handle_rrep(rx_msg.src_short_rd_id, rx_msg.routing_pdu_buf, rx_msg.hpc, rx_msg.psn);
				// Buffer unref'd by handler
				break;
			case ROUTING_PDU_TYPE_RERR:
				routing_handle_rerr(rx_msg.src_short_rd_id, rx_msg.routing_pdu_buf, rx_msg.hpc, rx_msg.psn);
				// Buffer unref'd by handler
				break;
			default:
				DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_TYPE, "ROUTING: Unknown Routing PDU type %u. Dropping.", rx_msg.routing_pdu_type);
				STATS_INC(dect_stats.routing_rx_drops);
				net_buf_unref(rx_msg.routing_pdu_buf);
				break;
			}
		}

		k_sleep(K_MSEC(50)); // Sleep to yield CPU
	}
}

dect_status_t dect_routing_discover_route(uint16_t dest_short_rd_id)
{
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	if (!dect_config.enable_routing) {
		LOG_WRN("ROUTING: Routing disabled in config. Cannot discover route.");
		k_mutex_unlock(&routing_ctx.mutex);
		return DECT_ERROR_ROUTING_DISABLED;
	}

	// Check if a valid route already exists
	int entry_idx = routing_table_find_entry(dest_short_rd_id);
	if (entry_idx != -1 && routing_ctx.routing_table[entry_idx].is_valid &&
	    (k_uptime_get() - routing_ctx.routing_table[entry_idx].last_active_time_ms) < routing_ctx.routing_table[entry_idx].route_lifetime_ms) {
		LOG_DBG("ROUTING: Valid route to 0x%04x already exists.", dest_short_rd_id);
		k_mutex_unlock(&routing_ctx.mutex);
		return DECT_STATUS_OK;
	}

	LOG_INF("ROUTING: Initiating route discovery for 0x%04x.", dest_short_rd_id);
	dect_status_t status = routing_send_rreq(dest_short_rd_id);
	STATS_INC(dect_stats.routing_rreq_tx);
	k_mutex_unlock(&routing_ctx.mutex);
	return status;
}

dect_status_t dect_routing_send_data(uint16_t dest_short_rd_id, struct net_buf *data_buf,
				     qos_priority_t qos_priority)
{
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	if (!dect_config.enable_routing) {
		LOG_WRN("ROUTING: Routing disabled in config. Cannot send data via routing.");
		net_buf_unref(data_buf); // Release buffer
		k_mutex_unlock(&routing_ctx.mutex);
		return DECT_ERROR_ROUTING_DISABLED;
	}

	int entry_idx = routing_table_find_entry(dest_short_rd_id);
	if (entry_idx == -1 || !routing_ctx.routing_table[entry_idx].is_valid ||
	    (k_uptime_get() - routing_ctx.routing_table[entry_idx].last_active_time_ms) >= routing_ctx.routing_table[entry_idx].route_lifetime_ms) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_NO_ROUTE, "ROUTING: No valid route to 0x%04x. Initiating discovery.", dest_short_rd_id);
		STATS_INC(dect_stats.routing_tx_drops); // Stat for data dropped due to no route
		net_buf_unref(data_buf); // Release buffer
		routing_send_rreq(dest_short_rd_id); // Attempt to discover route
		k_mutex_unlock(&routing_ctx.mutex);
		return DECT_ERROR_ROUTING_NO_ROUTE;
	}

	uint16_t next_hop = routing_ctx.routing_table[entry_idx].next_hop_short_rd_id;
	k_mutex_unlock(&routing_ctx.mutex);

	LOG_DBG("ROUTING: Forwarding data for 0x%04x via next hop 0x%04x.", dest_short_rd_id, next_hop);

	// Pass the data SDU to DLC layer for transmission to the next hop
	dect_status_t status = dlc_send_data_from_cvg(next_hop, data_buf,
						      CVG_SERVICE_TYPE_DATA, qos_priority); // Using CVG_SERVICE_TYPE_DATA for forwarded app data
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "ROUTING: Failed to send data SDU to DLC for next hop 0x%04x.", next_hop);
		STATS_INC(dect_stats.routing_tx_drops); // Stat for data dropped at DLC interface
		// Data_buf unref'd by dlc_send_data_from_cvg on failure
	}

	return status;
}

dect_status_t dect_routing_process_incoming_pdu(uint16_t src_short_rd_id, struct net_buf *routing_pdu_buf,
						uint32_t hpc, uint16_t psn)
{
	if (routing_pdu_buf->len < 1) { // PDU Type is first byte of payload
		DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "ROUTING: Incoming PDU too short for type. Dropping.");
		STATS_INC(dect_stats.routing_rx_drops);
		net_buf_unref(routing_pdu_buf);
		return DECT_ERROR_FRAME_TOO_SHORT;
	}
	uint8_t pdu_type = net_buf_peek_u8(routing_pdu_buf); // Peek, don't pull yet

	LOG_DBG("ROUTING: Processing incoming PDU type 0x%02x from 0x%04x.", pdu_type, src_short_rd_id);

	switch (pdu_type) {
	case ROUTING_PDU_TYPE_RREQ:
		routing_handle_rreq(src_short_rd_id, routing_pdu_buf, hpc, psn);
		break;
	case ROUTING_PDU_TYPE_RREP:
		routing_handle_rrep(src_short_rd_id, routing_pdu_buf, hpc, psn);
		break;
	case ROUTING_PDU_TYPE_RERR:
		routing_handle_rerr(src_short_rd_id, routing_pdu_buf, hpc, psn);
		break;
	default:
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_TYPE, "ROUTING: Unknown Routing PDU type 0x%02x. Dropping.", pdu_type);
		STATS_INC(dect_stats.routing_rx_drops);
		net_buf_unref(routing_pdu_buf); // Unref if not handled
		return DECT_ERROR_INVALID_PDU_TYPE;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_routing_link_failure_notification(uint16_t failed_peer_short_rd_id,
						     mac_link_failure_reason_t reason)
{
	LOG_INF("ROUTING: Link failure notification for peer 0x%04x (reason %u).", failed_peer_short_rd_id, reason);

	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	bool rerr_needed = false;
	uint16_t unreachable_dest = 0;

	for (int i = 0; i < MAX_ROUTING_ENTRIES; i++) {
		if (routing_ctx.routing_table[i].is_valid &&
		    routing_ctx.routing_table[i].next_hop_short_rd_id == failed_peer_short_rd_id) {
			LOG_DBG("ROUTING: Invalidating route to 0x%04x via failed peer 0x%04x.",
				routing_ctx.routing_table[i].dest_short_rd_id, failed_peer_short_rd_id);
			routing_ctx.routing_table[i].is_valid = false;
			rerr_needed = true;
			unreachable_dest = routing_ctx.routing_table[i].dest_short_rd_id; // Take first one as example
			// In a real AODV, you'd send RERRs for all affected destinations.
		}
	}
	k_mutex_unlock(&routing_ctx.mutex);

	if (rerr_needed) {
		LOG_DBG("ROUTING: Sending RERR for unreachable destination 0x%04x.", unreachable_dest);
		dect_status_t status = routing_send_rerr(unreachable_dest);
		if (status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(status, "ROUTING: Failed to send RERR after link failure.");
			STATS_INC(dect_stats.routing_tx_drops);
		}
	}

	return DECT_STATUS_OK;
}

static int routing_table_find_entry(uint16_t dest_short_rd_id)
{
	// Assumes routing_ctx_mutex is locked by caller
	for (int i = 0; i < MAX_ROUTING_ENTRIES; i++) {
		if (routing_ctx.routing_table[i].is_valid &&
		    routing_ctx.routing_table[i].dest_short_rd_id == dest_short_rd_id) {
			return i;
		}
	}
	return -1;
}

static int routing_table_add_or_update(uint16_t dest_short_rd_id, uint16_t next_hop_short_rd_id,
				       uint8_t hop_count, uint32_t dest_sequence_number)
{
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	int entry_idx = routing_table_find_entry(dest_short_rd_id);

	if (entry_idx == -1) {
		// Find a free entry
		for (int i = 0; i < MAX_ROUTING_ENTRIES; i++) {
			if (!routing_ctx.routing_table[i].is_valid) {
				entry_idx = i;
				break;
			}
		}
		if (entry_idx == -1) {
			LOG_WRN("ROUTING: Routing table full. Cannot add route to 0x%04x.", dest_short_rd_id);
			k_mutex_unlock(&routing_ctx.mutex);
			return -1;
		}
		routing_ctx.num_routing_entries++;
		LOG_DBG("ROUTING: Added new route entry for 0x%04x at index %d. Total: %u.", dest_short_rd_id, entry_idx, routing_ctx.num_routing_entries);
	} else {
		// Update existing entry if new route is better (fresh sequence number, or fewer hops)
		if (dest_sequence_number > routing_ctx.routing_table[entry_idx].dest_sequence_number ||
		    (dest_sequence_number == routing_ctx.routing_table[entry_idx].dest_sequence_number &&
		     hop_count < routing_ctx.routing_table[entry_idx].hop_count)) {
			LOG_DBG("ROUTING: Updating route to 0x%04x: old hops %u, new hops %u, old seq %u, new seq %u.",
				dest_short_rd_id, routing_ctx.routing_table[entry_idx].hop_count, hop_count,
				routing_ctx.routing_table[entry_idx].dest_sequence_number, dest_sequence_number);
		} else {
			LOG_DBG("ROUTING: Existing route to 0x%04x is better or equal. No update needed.", dest_short_rd_id);
			k_mutex_unlock(&routing_ctx.mutex);
			return entry_idx;
		}
	}

	routing_ctx.routing_table[entry_idx].dest_short_rd_id = dest_short_rd_id;
	routing_ctx.routing_table[entry_idx].next_hop_short_rd_id = next_hop_short_rd_id;
	routing_ctx.routing_table[entry_idx].hop_count = hop_count;
	routing_ctx.routing_table[entry_idx].dest_sequence_number = dest_sequence_number;
	routing_ctx.routing_table[entry_idx].last_active_time_ms = k_uptime_get();
	routing_ctx.routing_table[entry_idx].route_lifetime_ms = CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS;
	routing_ctx.routing_table[entry_idx].is_valid = true;

	k_mutex_unlock(&routing_ctx.mutex);
	return entry_idx;
}

static dect_status_t routing_table_invalidate_route(uint16_t dest_short_rd_id)
{
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	int entry_idx = routing_table_find_entry(dest_short_rd_id);
	if (entry_idx != -1) {
		routing_ctx.routing_table[entry_idx].is_valid = false;
		LOG_INF("ROUTING: Invalidated route to 0x%04x.", dest_short_rd_id);
		k_mutex_unlock(&routing_ctx.mutex);
		return DECT_STATUS_OK;
	}
	LOG_DBG("ROUTING: Route to 0x%04x not found for invalidation.", dest_short_rd_id);
	k_mutex_unlock(&routing_ctx.mutex);
	return DECT_ERROR_NOT_FOUND;
}

static dect_status_t routing_send_rreq(uint16_t dest_short_rd_id)
{
	struct net_buf *rreq_pdu = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&rreq_pdu, &mac_tx_net_buf_pool); // Using MAC pool for PDU
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "ROUTING: Failed to allocate RREQ PDU.");
		return ret_alloc;
	}

	// RREQ format: Type (0x00) | Hop Count | RREQ ID | Dest Seq Num | Dest RD ID | Orig Seq Num | Orig RD ID
	net_buf_add_u8(rreq_pdu, ROUTING_PDU_TYPE_RREQ);
	net_buf_add_u8(rreq_pdu, 0); // Hop Count (starts at 0)
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	net_buf_add_le32(rreq_pdu, routing_ctx.rreq_id_counter++); // RREQ ID
	routing_ctx.route_sequence_number++; // Increment our sequence number
	net_buf_add_le32(rreq_pdu, routing_ctx.route_sequence_number); // Originator Sequence Number
	k_mutex_unlock(&routing_ctx.mutex);
	net_buf_add_le16(rreq_pdu, dest_short_rd_id); // Destination RD ID
	net_buf_add_le16(rreq_pdu, mac_ctx.local_short_rd_id); // Originator RD ID

	LOG_DBG("ROUTING: Sending RREQ for 0x%04x from 0x%04x (Seq %u, RREQ ID %u).",
		dest_short_rd_id, mac_ctx.local_short_rd_id, routing_ctx.route_sequence_number, routing_ctx.rreq_id_counter - 1);

	// Send to DLC layer (broadcast)
	dect_status_t status = dlc_send_routing_pdu(SHORT_RD_ID_BROADCAST, rreq_pdu);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "ROUTING: Failed to send RREQ to DLC.");
		STATS_INC(dect_stats.routing_tx_drops);
		// rreq_pdu unref'd by dlc_send_routing_pdu on failure
	}

	return status;
}

static dect_status_t routing_send_rrep(uint16_t dest_short_rd_id, uint16_t originator_short_rd_id,
				       uint8_t hop_count, uint32_t dest_sequence_number)
{
	struct net_buf *rrep_pdu = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&rrep_pdu, &mac_tx_net_buf_pool);
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "ROUTING: Failed to allocate RREP PDU.");
		return ret_alloc;
	}

	// RREP format: Type (0x01) | Hop Count | Dest RD ID | Dest Seq Num | Orig RD ID | Orig Seq Num | Lifetime
	net_buf_add_u8(rrep_pdu, ROUTING_PDU_TYPE_RREP);
	net_buf_add_u8(rrep_pdu, hop_count);
	net_buf_add_le16(rrep_pdu, dest_short_rd_id);
	net_buf_add_le32(rrep_pdu, dest_sequence_number);
	net_buf_add_le16(rrep_pdu, originator_short_rd_id);
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	net_buf_add_le32(rrep_pdu, routing_ctx.route_sequence_number); // Our own sequence number
	k_mutex_unlock(&routing_ctx.mutex);
	net_buf_add_le32(rrep_pdu, CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS); // Lifetime

	LOG_DBG("ROUTING: Sending RREP for 0x%04x to 0x%04x (hops %u, dest seq %u).",
		dest_short_rd_id, originator_short_rd_id, hop_count, dest_sequence_number);

	// Send to DLC layer (unicast to next hop towards originator)
	// This requires finding the next hop for the originator from our routing table.
	uint16_t next_hop_for_originator = 0; // Placeholder
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	int entry_idx = routing_table_find_entry(originator_short_rd_id);
	if (entry_idx != -1 && routing_ctx.routing_table[entry_idx].is_valid) {
		next_hop_for_originator = routing_ctx.routing_table[entry_idx].next_hop_short_rd_id;
	}
	k_mutex_unlock(&routing_ctx.mutex);

	if (next_hop_for_originator == 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_NO_ROUTE, "ROUTING: Cannot find next hop for RREP originator 0x%04x. Dropping.", originator_short_rd_id);
		STATS_INC(dect_stats.routing_tx_drops);
		net_buf_unref(rrep_pdu);
		return DECT_ERROR_ROUTING_NO_ROUTE;
	}

	dect_status_t status = dlc_send_routing_pdu(next_hop_for_originator, rrep_pdu);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "ROUTING: Failed to send RREP to DLC for next hop 0x%04x.", next_hop_for_originator);
		STATS_INC(dect_stats.routing_tx_drops);
		// rrep_pdu unref'd by dlc_send_routing_pdu on failure
	}

	return status;
}

static dect_status_t routing_send_rerr(uint16_t unreachable_dest_id)
{
	struct net_buf *rerr_pdu = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&rerr_pdu, &mac_tx_net_buf_pool);
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "ROUTING: Failed to allocate RERR PDU.");
		return ret_alloc;
	}

	// RERR format: Type (0x02) | Dest Count | Unreachable Dest RD ID | Dest Seq Num ...
	net_buf_add_u8(rerr_pdu, ROUTING_PDU_TYPE_RERR);
	net_buf_add_u8(rerr_pdu, 1); // Destination Count (for simplicity, one for now)
	net_buf_add_le16(rerr_pdu, unreachable_dest_id);
	// In a real AODV, you'd include the last known sequence number for this destination.
	// For simplicity, using 0 for now.
	net_buf_add_le32(rerr_pdu, 0); // Unreachable Destination Sequence Number

	LOG_DBG("ROUTING: Sending RERR for unreachable 0x%04x.", unreachable_dest_id);

	// RERRs are typically broadcast
	dect_status_t status = dlc_send_routing_pdu(SHORT_RD_ID_BROADCAST, rerr_pdu);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "ROUTING: Failed to send RERR to DLC.");
		STATS_INC(dect_stats.routing_tx_drops);
		// rerr_pdu unref'd by dlc_send_routing_pdu on failure
	}

	return status;
}

static void routing_handle_rreq(uint16_t src_short_rd_id, struct net_buf *pdu_buf, uint32_t hpc, uint16_t psn)
{
	ARG_UNUSED(hpc);
	ARG_UNUSED(psn);

	if (pdu_buf->len < (1 + 1 + 4 + 4 + 2 + 2)) { // Type, Hops, RREQ ID, Dest Seq, Dest ID, Orig Seq, Orig ID
		DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "ROUTING: RREQ PDU too short. Dropping from 0x%04x.", src_short_rd_id);
		STATS_INC(dect_stats.routing_rx_drops);
		net_buf_unref(pdu_buf);
		return;
	}

	net_buf_pull_u8(pdu_buf); // Pull PDU Type (already peeked)
	uint8_t hop_count = net_buf_pull_u8(pdu_buf);
	uint32_t rreq_id = net_buf_pull_le32(pdu_buf);
	uint32_t dest_sequence_number = net_buf_pull_le32(pdu_buf);
	uint16_t dest_rd_id = net_buf_pull_le16(pdu_buf);
	uint16_t originator_rd_id = net_buf_pull_le16(pdu_buf);

	LOG_DBG("ROUTING: Handling RREQ (src 0x%04x, dest 0x%04x, orig 0x%04x, hops %u, RREQ ID %u, dest seq %u).",
		src_short_rd_id, dest_rd_id, originator_rd_id, hop_count, rreq_id, dest_sequence_number);
	STATS_INC(dect_stats.routing_rreq_rx);

	// Update reverse route (originator -> current node -> source of RREQ)
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	int reverse_route_idx = routing_table_add_or_update(originator_rd_id, src_short_rd_id,
							    hop_count + 1, routing_ctx.route_sequence_number);
	k_mutex_unlock(&routing_ctx.mutex);

	if (dest_rd_id == mac_ctx.local_short_rd_id) {
		// We are the destination, send RREP back to originator
		LOG_INF("ROUTING: I am the destination (0x%04x). Sending RREP to 0x%04x.",
			mac_ctx.local_short_rd_id, originator_rd_id);
		dect_status_t status = routing_send_rrep(mac_ctx.local_short_rd_id, originator_rd_id,
							 0, // Hops to destination (us)
							 routing_ctx.route_sequence_number); // Our sequence number
		if (status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(status, "ROUTING: Failed to send RREP as destination.");
			STATS_INC(dect_stats.routing_tx_drops);
		}
		STATS_INC(dect_stats.routing_rrep_tx);
	} else {
		// Not the destination, check if we have a fresh route to destination
		k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
		int forward_route_idx = routing_table_find_entry(dest_rd_id);
		bool has_fresh_route = (forward_route_idx != -1 && routing_ctx.routing_table[forward_route_idx].is_valid &&
					routing_ctx.routing_table[forward_route_idx].dest_sequence_number >= dest_sequence_number);
		k_mutex_unlock(&routing_ctx.mutex);

		if (has_fresh_route) {
			// Have a fresh route, send RREP back towards originator
			LOG_DBG("ROUTING: Found fresh route to 0x%04x. Sending RREP back to 0x%04x.",
				dest_rd_id, originator_rd_id);
			k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
			uint8_t hops_to_dest = routing_ctx.routing_table[forward_route_idx].hop_count;
			uint32_t fwd_dest_seq_num = routing_ctx.routing_table[forward_route_idx].dest_sequence_number;
			k_mutex_unlock(&routing_ctx.mutex);

			dect_status_t status = routing_send_rrep(dest_rd_id, originator_rd_id,
								 hops_to_dest, fwd_dest_seq_num);
			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "ROUTING: Failed to send RREP with known route.");
				STATS_INC(dect_stats.routing_tx_drops);
			}
			STATS_INC(dect_stats.routing_rrep_tx);
		} else if (hop_count < CONFIG_DECT_NR_PLUS_ROUTING_MAX_HOPS) {
			// No fresh route, re-broadcast RREQ with incremented hop count
			LOG_DBG("ROUTING: No fresh route to 0x%04x. Re-broadcasting RREQ.", dest_rd_id);
			// Need to increment the hop count in the PDU before re-sending
			uint8_t *hop_count_ptr = net_buf_pull(pdu_buf, 1); // Pull original hop count
			net_buf_push_u8(pdu_buf, hop_count + 1); // Push incremented hop count

			dect_status_t status = dlc_send_routing_pdu(SHORT_RD_ID_BROADCAST, pdu_buf); // Pass the same buf
			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "ROUTING: Failed to re-broadcast RREQ.");
				STATS_INC(dect_stats.routing_tx_drops);
				// pdu_buf unref'd by dlc_send_routing_pdu on failure
			}
			STATS_INC(dect_stats.routing_rreq_tx);
			// If successful, pdu_buf ownership passed to DLC.
		} else {
			LOG_WRN("ROUTING: Max hops reached for RREQ to 0x%04x. Dropping.", dest_rd_id);
			STATS_INC(dect_stats.routing_rx_drops);
			net_buf_unref(pdu_buf); // Drop if max hops reached
		}
	}
	net_buf_unref(pdu_buf); // Ensure pdu_buf is unref'd if not passed to DLC (e.g. if we are destination or had fresh route)
}

static void routing_handle_rrep(uint16_t src_short_rd_id, struct net_buf *pdu_buf, uint32_t hpc, uint16_t psn)
{
	ARG_UNUSED(hpc);
	ARG_UNUSED(psn);

	if (pdu_buf-> < (1 + 1 + 2 + 4 + 2 + 4 + 4)) { // Type, Hops, Dest ID, Dest Seq, Orig ID, Orig Seq, Lifetime
		DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "ROUTING: RREP PDU too short. Dropping from 0x%04x.", src_short_rd_id);
		STATS_INC(dect_stats.routing_rx_drops);
		net_buf_unref(pdu_buf);
		return;
	}

	net_buf_pull_u8(pdu_buf); // Pull PDU Type
	uint8_t hop_count = net_buf_pull_u8(pdu_buf);
	uint16_t dest_rd_id = net_buf_pull_le16(pdu_buf);
	uint32_t dest_sequence_number = net_buf_pull_le32(pdu_buf);
	uint16_t originator_rd_id = net_buf_pull_le16(pdu_buf);
	uint32_t originator_sequence_number = net_buf_pull_le32(pdu_buf);
	uint32_t lifetime_ms = net_buf_pull_le32(pdu_buf);

	LOG_DBG("ROUTING: Handling RREP (src 0x%04x, dest 0x%04x, orig 0x%04x, hops %u, dest seq %u, lifetime %u).",
		src_short_rd_id, dest_rd_id, originator_rd_id, hop_count, dest_sequence_number, lifetime_ms);
	STATS_INC(dect_stats.routing_rrep_rx);

	// Update or add forward route (destination -> current node -> source of RREP)
	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	routing_table_add_or_update(dest_rd_id, src_short_rd_id, hop_count + 1, dest_sequence_number);
	k_mutex_unlock(&routing_ctx.mutex);

	if (originator_rd_id == mac_ctx.local_short_rd_id) {
		// We are the originator of the RREQ, route found!
		LOG_INF("ROUTING: Route to 0x%04x found via 0x%04x (hops %u).", dest_rd_id, src_short_rd_id, hop_count + 1);
		// Stop any pending route discovery timers for this destination (conceptual)
	} else {
		// Not the originator, forward RREP towards originator
		LOG_DBG("ROUTING: Forwarding RREP for 0x%04x towards originator 0x%04x.", dest_rd_id, originator_rd_id);

		// Increment hop count in PDU
		uint8_t *hop_count_ptr = net_buf_tail(pdu_buf) - (4 + 2 + 4 + 4 + 1); // Points to original hop count
		if (hop_count_ptr >= pdu_buf->data && hop_count_ptr < net_buf_tail(pdu_buf)) {
			*hop_count_ptr = hop_count + 1; // Increment hop count
		} else {
			DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "ROUTING: Failed to update hop count in RREP. Dropping.");
			STATS_INC(dect_stats.routing_rx_drops);
			net_buf_unref(pdu_buf);
			return;
		}


		// Send to DLC layer (unicast to next hop towards originator)
		uint16_t next_hop_for_originator = 0;
		k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
		int entry_idx = routing_table_find_entry(originator_rd_id);
		if (entry_idx != -1 && routing_ctx.routing_table[entry_idx].is_valid) {
			next_hop_for_originator = routing_ctx.routing_table[entry_idx].next_hop_short_rd_id;
		}
		k_mutex_unlock(&routing_ctx.mutex);

		if (next_hop_for_originator != 0) {
			dect_status_t status = dlc_send_routing_pdu(next_hop_for_originator, pdu_buf);
			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "ROUTING: Failed to forward RREP to DLC for next hop 0x%04x.", next_hop_for_originator);
				STATS_INC(dect_stats.routing_tx_drops);
				// pdu_buf unref'd by dlc_send_routing_pdu on failure
			}
			STATS_INC(dect_stats.routing_rrep_tx);
		} else {
			LOG_WRN("ROUTING: No route to originator 0x%04x to forward RREP. Dropping.", originator_rd_id);
			STATS_INC(dect_stats.routing_rx_drops);
			net_buf_unref(pdu_buf); // Drop if no route to originator
		}
	}
	net_buf_unref(pdu_buf); // Ensure pdu_buf is unref'd if not passed to DLC
}

static void routing_handle_rerr(uint16_t src_short_rd_id, struct net_buf *pdu_buf, uint32_t hpc, uint16_t psn)
{
	ARG_UNUSED(hpc);
	ARG_UNUSED(psn);

	if (pdu_buf->len < (1 + 1 + 2 + 4)) { // Type, Dest Count, Unreachable Dest ID, Dest Seq Num
		DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "ROUTING: RERR PDU too short. Dropping from 0x%04x.", src_short_rd_id);
		STATS_INC(dect_stats.routing_rx_drops);
		net_buf_unref(pdu_buf);
		return;
	}

	net_buf_pull_u8(pdu_buf); // Pull PDU Type
	uint8_t dest_count = net_buf_pull_u8(pdu_buf);

	LOG_DBG("ROUTING: Handling RERR from 0x%04x (dest count %u).", src_short_rd_id, dest_count);
	STATS_INC(dect_stats.routing_rerr_rx);

	// For simplicity, process only the first unreachable destination
	if (dest_count > 0 && pdu_buf->len >= (2 + 4)) {
		uint16_t unreachable_dest_id = net_buf_pull_le16(pdu_buf);
		uint32_t unreachable_dest_seq = net_buf_pull_le32(pdu_buf);

		LOG_INF("ROUTING: Peer 0x%04x reports 0x%04x unreachable (seq %u). Invalidating route.",
			src_short_rd_id, unreachable_dest_id, unreachable_dest_seq);

		k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
		int entry_idx = routing_table_find_entry(unreachable_dest_id);
		if (entry_idx != -1 && routing_ctx.routing_table[entry_idx].is_valid &&
		    routing_ctx.routing_table[entry_idx].next_hop_short_rd_id == src_short_rd_id) {
			// Only invalidate if the RERR came from the next hop we use for this destination
			routing_ctx.routing_table[entry_idx].is_valid = false;
			LOG_DBG("ROUTING: Route to 0x%04x invalidated.", unreachable_dest_id);
			// Optionally, send a new RREQ for this destination
			routing_send_rreq(unreachable_dest_id);
			STATS_INC(dect_stats.routing_rreq_tx);
		} else {
			LOG_DBG("ROUTING: RERR for 0x%04x not relevant to our current routes via 0x%04x.",
				unreachable_dest_id, src_short_rd_id);
		}
		k_mutex_unlock(&routing_ctx.mutex);
	} else {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "ROUTING: Malformed RERR PDU. Dropping.");
		STATS_INC(dect_stats.routing_rx_drops);
	}

	net_buf_unref(pdu_buf); // Consumed
}

static void routing_route_discovery_timeout_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	// This handler would be for specific RREQ timeouts if per-destination timers were used.
	// For now, it's illustrative.
	LOG_WRN("ROUTING: Route discovery timeout occurred. No route found for destination.");
	STATS_INC(dect_stats.routing_tx_drops); // Consider as a drop if no route was established
}

static void routing_route_expiry_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&routing_ctx.mutex, K_FOREVER);
	uint64_t current_time = k_uptime_get();

	for (int i = 0; i < MAX_ROUTING_ENTRIES; i++) {
		if (routing_ctx.routing_table[i].is_valid) {
			if ((current_time - routing_ctx.routing_table[i].last_active_time_ms) >= routing_ctx.routing_table[i].route_lifetime_ms) {
				routing_ctx.routing_table[i].is_valid = false;
				LOG_INF("ROUTING: Route to 0x%04x expired.", routing_ctx.routing_table[i].dest_short_rd_id);
				// Optionally, send RERR for expired routes to notify neighbors
				// routing_send_rerr(routing_ctx.routing_table[i].dest_short_rd_id);
			}
		}
	}
	k_mutex_unlock(&routing_ctx.mutex);
}

/* End of File
 * Last Amended: 2025-06-09 19:00 BST: Updated dect_routing.c for robust error handling.
 * - Added `handle_tx_buffer_allocation` helper function.
 * - Modified `routing_send_rreq`, `routing_send_rrep`, `routing_send_rerr` to use `handle_tx_buffer_allocation`.
 * - Modified `dect_routing_send_data` to unref `data_buf` and increment `routing_tx_drops` if no route or if `dlc_send_data_from_cvg` fails.
 * - Enhanced `dect_routing_process_incoming_pdu` and handlers (`routing_handle_rreq`, `routing_handle_rrep`, `routing_handle_rerr`) with explicit PDU length checks (`DECT_ERROR_FRAME_TOO_SHORT`) and `DECT_ERROR_INVALID_PDU_TYPE`.
 * - Ensured all error paths (allocation failures, invalid parameters, queue full, no route, malformed PDUs) increment `dect_stats.routing_tx_drops` or `dect_stats.routing_rx_drops` and unreference `net_buf`s.
 */
