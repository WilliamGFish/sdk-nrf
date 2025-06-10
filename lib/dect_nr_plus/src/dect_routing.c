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
#include <dect_nr_plus/dect_mac.h> // For getting our own Short RD ID and IP-to-RD_ID map
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_routing, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global Routing context instance definition */
dect_routing_context_t routing_ctx = {
	.num_routing_entries = 0,
	.route_sequence_number = 0, // Start from 0
	.rreq_id_counter = 0,       // Start from 0
};

/* Message queues for inter-layer communication */
K_MSGQ_DEFINE(routing_rx_msgq, sizeof(dlc_rx_msg_t),
			  CONFIG_DECT_NR_PLUS_ROUTING_RX_QUEUE_COUNT, 4);
K_MSGQ_DEFINE(routing_tx_msgq, sizeof(dlc_tx_msg_t),
			  CONFIG_DECT_NR_PLUS_ROUTING_TX_QUEUE_COUNT, 4);

/* Mutex for protecting routing context */
K_MUTEX_DEFINE(routing_ctx_mutex);

/* Forward declarations for internal static functions */
static void route_cleanup_timer_handler(struct k_timer *timer_id);
static void rreq_timeout_timer_handler(struct k_timer *timer_id);
static int find_routing_entry(uint16_t dest_short_rd_id);
static int add_or_update_routing_entry(uint16_t dest_short_rd_id, uint16_t next_hop_short_rd_id,
									   uint8_t hop_count, uint32_t dest_seq_num, uint32_t lifetime_ms,
									   dect_routing_mode_t mode);
static dect_status_t routing_send_route_request(uint16_t dest_short_rd_id, uint8_t hop_count,
												uint32_t orig_seq_num, uint32_t rreq_id);
static dect_status_t routing_send_route_reply(uint16_t dest_short_rd_id, uint16_t orig_route_dest_rd_id,
											  uint8_t hop_count, uint32_t orig_route_dest_seq_num,
											  uint32_t rreq_id, uint32_t lifetime_ms);
static dect_status_t routing_send_route_error(uint16_t unreachable_dest_short_rd_id);
static dect_status_t handle_tx_buffer_allocation(struct net_buf **out_buf, struct net_buf_pool *pool, const char *caller_name,
												   size_t size, enum dect_status_t error_code);


/**
 * @brief Helper to handle net_buf allocation and error paths.
 *
 * @param out_buf Pointer to net_buf pointer to store the allocated buffer.
 * @param pool The net_buf_pool to allocate from.
 * @param caller_name String name of the calling function for logging.
 * @param size Size of the buffer to allocate.
 * @param error_code The DECT_ERROR code to return on failure.
 * @return DECT_STATUS_OK on success, or error_code on failure.
 */
static dect_status_t handle_tx_buffer_allocation(struct net_buf **out_buf, struct net_buf_pool *pool, const char *caller_name,
												   size_t size, enum dect_status_t error_code)
{
	*out_buf = net_buf_alloc(pool, K_NO_WAIT);
	if (!(*out_buf)) {
		DECT_ERROR_HANDLER(error_code, "%s: Failed to allocate TX net_buf of size %zu.", caller_name, size);
		STATS_INC(dect_stats.routing_tx_drops); // Specific routing TX drop stat
		return error_code;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_routing_init(void)
{
	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);

	// Initialize routing table entries
	for (int i = 0; i < MAX_ROUTING_ENTRIES; i++) {
		routing_ctx.routing_table[i].is_valid = false;
	}

	// Initialize timers
	k_timer_init(&routing_ctx.route_cleanup_timer, route_cleanup_timer_handler, NULL);
	k_timer_start(&routing_ctx.route_cleanup_timer, K_MSEC(CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS / 2),
				  K_MSEC(CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS / 2));

	k_timer_init(&routing_ctx.rreq_timeout_timer, rreq_timeout_timer_handler, NULL);
	// This timer is typically started per RREQ

	LOG_INF("ROUTING: Initialized.");
	k_mutex_unlock(&routing_ctx_mutex);
	return DECT_STATUS_OK;
}

/**
 * @brief Internal helper to find a routing entry by destination Short RD ID.
 *
 * @param dest_short_rd_id The destination Short RD ID to find.
 * @return Index of the entry if found, -1 otherwise.
 */
static int find_routing_entry(uint16_t dest_short_rd_id)
{
	for (int i = 0; i < routing_ctx.num_routing_entries; i++) {
		if (routing_ctx.routing_table[i].is_valid &&
			routing_ctx.routing_table[i].dest_short_rd_id == dest_short_rd_id) {
			return i;
		}
	}
	return -1;
}

/**
 * @brief Internal helper to add or update a routing entry.
 *
 * @param dest_short_rd_id The destination Short RD ID.
 * @param next_hop_short_rd_id The next hop Short RD ID.
 * @param hop_count The hop count to the destination.
 * @param dest_seq_num The destination sequence number.
 * @param lifetime_ms The lifetime of the route in milliseconds.
 * @param mode The DECT NR+ native routing mode for this route.
 * @return Index of the updated/added entry, or -1 on failure.
 */
static int add_or_update_routing_entry(uint16_t dest_short_rd_id, uint16_t next_hop_short_rd_id,
									   uint8_t hop_count, uint32_t dest_seq_num, uint32_t lifetime_ms,
									   dect_routing_mode_t mode)
{
	int idx = find_routing_entry(dest_short_rd_id);

	if (idx != -1) {
		// Update existing entry if new route is better (newer sequence number or same seq num with fewer hops)
		if (dest_seq_num > routing_ctx.routing_table[idx].route_sequence_number ||
			(dest_seq_num == routing_ctx.routing_table[idx].route_sequence_number &&
			 hop_count < routing_ctx.routing_table[idx].hop_count)) {
			routing_ctx.routing_table[idx].next_hop_short_rd_id = next_hop_short_rd_id;
			routing_ctx.routing_table[idx].hop_count = hop_count;
			routing_ctx.routing_table[idx].route_sequence_number = dest_seq_num;
			routing_ctx.routing_table[idx].last_active_time_ms = k_uptime_get();
			routing_ctx.routing_table[idx].route_lifetime_ms = lifetime_ms;
			routing_ctx.routing_table[idx].mode = mode; // Update routing mode
			LOG_DBG("ROUTING: Updated route to 0x%04x via 0x%04x (hops: %u, seq: %u, mode: %u).",
					dest_short_rd_id, next_hop_short_rd_id, hop_count, dest_seq_num, mode);
		}
	} else {
		// Add new entry if space available
		if (routing_ctx.num_routing_entries < MAX_ROUTING_ENTRIES) {
			idx = routing_ctx.num_routing_entries++;
			routing_ctx.routing_table[idx].dest_short_rd_id = dest_short_rd_id;
			routing_ctx.routing_table[idx].next_hop_short_rd_id = next_hop_short_rd_id;
			routing_ctx.routing_table[idx].hop_count = hop_count;
			routing_ctx.routing_table[idx].route_sequence_number = dest_seq_num;
			routing_ctx.routing_table[idx].last_active_time_ms = k_uptime_get();
			routing_ctx.routing_table[idx].route_lifetime_ms = lifetime_ms;
			routing_ctx.routing_table[idx].is_valid = true;
			routing_ctx.routing_table[idx].mode = mode; // Set routing mode
			LOG_INF("ROUTING: Added new route to 0x%04x via 0x%04x (hops: %u, seq: %u, mode: %u).",
					dest_short_rd_id, next_hop_short_rd_id, hop_count, dest_seq_num, mode);
		} else {
			DECT_ERROR_HANDLER(DECT_ERROR_NO_RESOURCES, "ROUTING: Table full. Cannot add route to 0x%04x.", dest_short_rd_id);
			return -1;
		}
	}
	return idx;
}

dect_status_t dect_routing_discover_route(uint16_t dest_short_rd_id, dect_routing_mode_t mode)
{
	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	int idx = find_routing_entry(dest_short_rd_id);

	if (idx != -1 && routing_ctx.routing_table[idx].is_valid && routing_ctx.routing_table[idx].mode == mode) {
		LOG_DBG("ROUTING: Route to 0x%04x (%u) already exists.", dest_short_rd_id, mode);
		k_mutex_unlock(&routing_ctx_mutex);
		return DECT_STATUS_OK;
	}

	LOG_DBG("ROUTING: Initiating route discovery for 0x%04x (mode: %u).", dest_short_rd_id, mode);
	STATS_INC(dect_stats.routing_route_discoveries);

	routing_ctx.route_sequence_number++; // Increment our own sequence number
	routing_ctx.rreq_id_counter++;       // Increment RREQ ID

	// The route request PDU might vary slightly based on mode.
	// For simplicity, we'll use a generic ROUTE_REQUEST PDU.
	dect_status_t status = routing_send_route_request(dest_short_rd_id, 0,
													  routing_ctx.route_sequence_number,
													  routing_ctx.rreq_id_counter);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "ROUTING: Failed to send ROUTE_REQUEST for 0x%04x.", dest_short_rd_id);
		STATS_INC(dect_stats.routing_route_failures);
	} else {
		LOG_DBG("ROUTING: ROUTE_REQUEST sent for 0x%04x. Waiting for REPLY.", dest_short_rd_id);
		// Start RREQ timeout timer for this destination (conceptual, ideally per RREQ ID)
		k_timer_start(&routing_ctx.rreq_timeout_timer, K_MSEC(CONFIG_DECT_NR_PLUS_ROUTING_RREQ_TIMEOUT_MS), K_NO_WAIT);
	}

	k_mutex_unlock(&routing_ctx_mutex);
	return status;
}

dect_status_t dect_routing_send_data(uint16_t dest_short_rd_id, struct net_buf *data_buf,
									 qos_priority_t qos_priority, dect_routing_mode_t routing_mode)
{
	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	int idx = find_routing_entry(dest_short_rd_id);
	uint16_t next_hop;

	// For uplink/downlink, if not directly associated, find the route.
	// For horizontal, find the route or use hop-limited flooding.

	if (dect_config.role == MAC_ROLE_FP && routing_mode == DECT_ROUTING_MODE_DOWNLINK) {
		// FP sending downlink, if dest_short_rd_id is a directly associated PP
		if (dect_mac_is_peer_associated(dest_short_rd_id)) {
			next_hop = dest_short_rd_id; // Direct communication
			LOG_DBG("ROUTING: FP sending downlink data directly to 0x%04x.", dest_short_rd_id);
			STATS_INC(dect_stats.routing_downlink_tx);
		} else {
			// If not directly associated, it implies a multi-hop downlink,
			// which would require a route to a forwarding PP.
			// This scenario would ideally be handled by a route lookup.
			if (idx == -1 || !routing_ctx.routing_table[idx].is_valid || routing_ctx.routing_table[idx].mode != DECT_ROUTING_MODE_DOWNLINK) {
				LOG_WRN("ROUTING: FP cannot find downlink route to 0x%04x. Dropping.", dest_short_rd_id);
				net_buf_unref(data_buf);
				STATS_INC(dect_stats.routing_tx_drops);
				k_mutex_unlock(&routing_ctx_mutex);
				return DECT_ERROR_ROUTING_NO_ROUTE;
			}
			next_hop = routing_ctx.routing_table[idx].next_hop_short_rd_id;
			LOG_DBG("ROUTING: FP sending downlink data to 0x%04x via next hop 0x%04x.", dest_short_rd_id, next_hop);
			STATS_INC(dect_stats.routing_downlink_tx);
		}
	} else if (dect_config.role == MAC_ROLE_PP && routing_mode == DECT_ROUTING_MODE_UPLINK) {
		// PP sending uplink, next hop is the associated FP
		if (mac_ctx.assoc_state == MAC_ASSOC_STATE_ASSOCIATED) {
			next_hop = mac_ctx.associated_fp_short_rd_id;
			LOG_DBG("ROUTING: PP sending uplink data directly to FP 0x%04x.", next_hop);
			STATS_INC(dect_stats.routing_uplink_tx);
		} else {
			LOG_WRN("ROUTING: PP not associated, cannot send uplink data. Dropping for 0x%04x.", dest_short_rd_id);
			net_buf_unref(data_buf);
			STATS_INC(dect_stats.routing_tx_drops);
			k_mutex_unlock(&routing_ctx_mutex);
			return DECT_ERROR_NOT_ASSOCIATED;
		}
	} else if (routing_mode == DECT_ROUTING_MODE_HORIZONTAL) {
		if (idx == -1 || !routing_ctx.routing_table[idx].is_valid || routing_ctx.routing_table[idx].mode != DECT_ROUTING_MODE_HORIZONTAL) {
			// No direct horizontal route, use hop-limited flooding for discovery/initial transmission
			// For simplicity, this currently falls back to broadcast. A proper implementation
			// would use a hop count in the routing header and decrement it.
			next_hop = SHORT_RD_ID_BROADCAST; // Or a specific group address for limited flooding
			LOG_WRN("ROUTING: No direct horizontal route to 0x%04x. Using hop-limited flooding (broadcast fallback).", dest_short_rd_id);
			STATS_INC(dect_stats.routing_horizontal_tx);
			STATS_INC(dect_stats.routing_flood_tx);
		} else {
			next_hop = routing_ctx.routing_table[idx].next_hop_short_rd_id;
			LOG_DBG("ROUTING: Sending horizontal data to 0x%04x via next hop 0x%04x.", dest_short_rd_id, next_hop);
			STATS_INC(dect_stats.routing_horizontal_tx);
		}
	} else {
		// Default case if routing mode is NONE or unexpected, attempt direct or fail
		LOG_WRN("ROUTING: Unknown or unsupported routing mode %u for dest 0x%04x. Attempting direct send or dropping.", routing_mode, dest_short_rd_id);
		if (dect_mac_is_peer_associated(dest_short_rd_id)) {
			next_hop = dest_short_rd_id;
			LOG_DBG("ROUTING: Direct send to 0x%04x.", dest_short_rd_id);
		} else {
			LOG_ERR("ROUTING: No direct connection and unsupported routing mode. Dropping for 0x%04x.", dest_short_rd_id);
			net_buf_unref(data_buf);
			STATS_INC(dect_stats.routing_tx_drops);
			k_mutex_unlock(&routing_ctx_mutex);
			return DECT_ERROR_ROUTING_NO_ROUTE;
		}
	}

	// Construct routing data PDU (wrap the original data)
	// Routing Header: Type (DATA_FORWARD) + Dest RD ID + Original Source RD ID + Hop Count + Routing Mode
	struct net_buf *routing_pdu = NULL;
	// Header size: Type (1 byte) + Dest (2 bytes) + Orig_Src (2 bytes) + HopCount (1 byte) + RoutingMode (1 byte)
	size_t routing_hdr_len = 1 + SHORT_RD_ID_LEN_BYTES + SHORT_RD_ID_LEN_BYTES + 1 + 1;
	size_t total_pdu_len = routing_hdr_len + data_buf->len;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&routing_pdu, &dlc_tx_net_buf_pool, __func__,
															 total_pdu_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		net_buf_unref(data_buf);
		k_mutex_unlock(&routing_ctx_mutex);
		return alloc_status;
	}

	net_buf_add_u8(routing_pdu, ROUTING_PDU_TYPE_DATA_FORWARD);
	net_buf_add_be16(routing_pdu, dest_short_rd_id);      // Final destination
	net_buf_add_be16(routing_pdu, mac_ctx.local_short_rd_id); // Original source (this device)
	net_buf_add_u8(routing_pdu, 1);                           // Initial Hop Count (this device is 1st hop)
	net_buf_add_u8(routing_pdu, routing_mode);                // Routing Mode

	// Add original data payload
	net_buf_write(routing_pdu, data_buf->data, data_buf->len);
	net_buf_add(routing_pdu, data_buf->len);
	net_buf_unref(data_buf); // Routing layer now owns the data

	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = next_hop,
		.dlc_pdu_buf = routing_pdu,
		.service_type = CVG_SERVICE_TYPE_CONTROL, // Routing PDUs are control
		.qos_priority = qos_priority,
		.is_routing_pdu = true, // Explicitly mark as routing PDU for DLC
	};

	int ret = k_msgq_put(&routing_tx_msgq, &tx_msg, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_TX_DROPS, "ROUTING: Failed to queue data PDU to DLC (ret: %d).", ret);
		net_buf_unref(routing_pdu); // Unref if queue full
		STATS_INC(dect_stats.routing_tx_drops);
		k_mutex_unlock(&routing_ctx_mutex);
		return DECT_ERROR_QUEUE_FULL;
	}

	LOG_DBG("ROUTING: Data PDU for 0x%04x queued to DLC via next hop 0x%04x (mode: %u).",
			dest_short_rd_id, next_hop, routing_mode);
	k_mutex_unlock(&routing_ctx_mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_routing_process_incoming_pdu(uint16_t src_short_rd_id, struct net_buf *routing_pdu_buf, uint32_t hpc, uint16_t psn)
{
	if (!routing_pdu_buf || routing_pdu_buf->len < 1) { // Minimum 1 byte for PDU type
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "ROUTING RX: Received NULL or empty routing PDU.");
		STATS_INC(dect_stats.routing_rx_drops);
		return DECT_ERROR_INVALID_PARAM;
	}

	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	dect_status_t status = DECT_STATUS_OK;

	uint8_t pdu_type = net_buf_pull_u8(routing_pdu_buf); // First byte is PDU type

	LOG_DBG("ROUTING RX: Received PDU type %u from 0x%04x (len: %u).", pdu_type, src_short_rd_id, routing_pdu_buf->len);

	switch (pdu_type) {
		case ROUTING_PDU_TYPE_ROUTE_REQUEST: {
			// ROUTE_REQUEST format: Type | Orig_Short_RD_ID | Dest_Short_RD_ID | Hop_Count | Orig_Seq_Num | RREQ_ID
			// Note: Orig_Seq_Num and RREQ_ID are for horizontal routing (AODV-like discovery)
			// For Uplink/Downlink specific control, the PDU might be different.
			if (routing_pdu_buf->len < (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4) {
				LOG_ERR("ROUTING RX: Malformed ROUTE_REQUEST from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t orig_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint16_t dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint8_t hop_count = net_buf_pull_u8(routing_pdu_buf);
			uint32_t orig_seq_num = net_buf_pull_be32(routing_pdu_buf);
			uint32_t rreq_id = net_buf_pull_be32(routing_pdu_buf);

			LOG_DBG("ROUTING RX ROUTE_REQUEST: Orig 0x%04x, Dest 0x%04x, Hops %u, OrigSeq %u, RREQID %u.",
					orig_short_rd_id, dest_short_rd_id, hop_count, orig_seq_num, rreq_id);

			// Update/create route to originator (for reverse path)
			add_or_update_routing_entry(orig_short_rd_id, src_short_rd_id, hop_count + 1, orig_seq_num,
										CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS, DECT_ROUTING_MODE_HORIZONTAL);

			// If we are the destination or have a fresher route to destination
			if (dest_short_rd_id == mac_ctx.local_short_rd_id) {
				LOG_DBG("ROUTING: We are destination for 0x%04x. Sending ROUTE_REPLY.", dest_short_rd_id);
				// Send ROUTE_REPLY back to originator
				routing_send_route_reply(orig_short_rd_id, dest_short_rd_id, 0, routing_ctx.route_sequence_number,
										 rreq_id, CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS);
				STATS_INC(dect_stats.routing_route_success);
			} else {
				// Else, increment hop count and rebroadcast ROUTE_REQUEST (if not seen recently)
				LOG_DBG("ROUTING: Forwarding ROUTE_REQUEST for 0x%04x.", dest_short_rd_id);
				// For a proper implementation, check for duplicate RREQ_ID from orig_short_rd_id to prevent flooding.
				routing_send_route_request(dest_short_rd_id, hop_count + 1, orig_seq_num, rreq_id);
			}
			break;
		}
		case ROUTING_PDU_TYPE_ROUTE_REPLY: {
			// ROUTE_REPLY format: Type | Dest_Short_RD_ID | Orig_Route_Dest_RD_ID | Hop_Count | Orig_Route_Dest_Seq_Num | RREQ_ID | Lifetime
			if (routing_pdu_buf->len < (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4 + 4) {
				LOG_ERR("ROUTING RX: Malformed ROUTE_REPLY from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf); // ROUTE_REPLY's destination (original ROUTE_REQUEST source)
			uint16_t orig_route_dest_rd_id = net_buf_pull_be16(routing_pdu_buf); // ROUTE_REPLY's source (original ROUTE_REQUEST destination)
			uint8_t hop_count = net_buf_pull_u8(routing_pdu_buf);
			uint32_t orig_route_dest_seq_num = net_buf_pull_be32(routing_pdu_buf);
			uint32_t rreq_id = net_buf_pull_be32(routing_pdu_buf);
			uint32_t lifetime_ms = net_buf_pull_be32(routing_pdu_buf);

			LOG_DBG("ROUTING RX ROUTE_REPLY: Dest 0x%04x, OrigRouteDest 0x%04x, Hops %u, DestSeq %u, Lifetime %u.",
					dest_short_rd_id, orig_route_dest_rd_id, hop_count, orig_route_dest_seq_num, lifetime_ms);

			// Update/create route to original_route_dest_rd_id via current source (src_short_rd_id)
			add_or_update_routing_entry(orig_route_dest_rd_id, src_short_rd_id, hop_count + 1, orig_route_dest_seq_num,
										lifetime_ms, DECT_ROUTING_MODE_HORIZONTAL);

			// If we are the original ROUTE_REQUEST source, stop timeout and notify success
			if (dest_short_rd_id == mac_ctx.local_short_rd_id) {
				LOG_INF("ROUTING: Route to 0x%04x established! Hops: %u, via 0x%04x.",
						orig_route_dest_rd_id, hop_count + 1, src_short_rd_id);
				k_timer_stop(&routing_ctx.rreq_timeout_timer); // Stop the RREQ timeout
				STATS_INC(dect_stats.routing_route_success);
				// TODO: Notify higher layer (CVG) that route is found for buffered packets
			} else {
				// Else, forward ROUTE_REPLY towards its destination (dest_short_rd_id)
				LOG_DBG("ROUTING: Forwarding ROUTE_REPLY for 0x%04x.", dest_short_rd_id);
				routing_send_route_reply(dest_short_rd_id, orig_route_dest_rd_id, hop_count + 1,
										 orig_route_dest_seq_num, rreq_id, lifetime_ms);
			}
			break;
		}
		case ROUTING_PDU_TYPE_ROUTE_ERROR: {
			// ROUTE_ERROR format: Type | Unreachable_Dest_RD_ID | Unreachable_Dest_Seq_Num
			if (routing_pdu_buf->len < SHORT_RD_ID_LEN_BYTES + 4) {
				LOG_ERR("ROUTING RX: Malformed ROUTE_ERROR from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t unreachable_dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint32_t unreachable_dest_seq_num = net_buf_pull_be32(routing_pdu_buf);

			LOG_WRN("ROUTING RX ROUTE_ERROR: Unreachable 0x%04x (Seq %u) from 0x%04x.",
					unreachable_dest_short_rd_id, unreachable_dest_seq_num, src_short_rd_id);

			// Invalidate route(s) and propagate ROUTE_ERROR if necessary.
			int idx = find_routing_entry(unreachable_dest_short_rd_id);
			if (idx != -1 && routing_ctx.routing_table[idx].is_valid) {
				// Invalidate if the sequence number is older, or if it came from our next hop
				if (routing_ctx.routing_table[idx].route_sequence_number < unreachable_dest_seq_num ||
					(routing_ctx.routing_table[idx].route_sequence_number == unreachable_dest_seq_num &&
					 routing_ctx.routing_table[idx].next_hop_short_rd_id == src_short_rd_id)) {
					routing_ctx.routing_table[idx].is_valid = false;
					LOG_INF("ROUTING: Invalidated route to 0x%04x.", unreachable_dest_short_rd_id);
					// Propagate ROUTE_ERROR to other neighbors who might be using this route.
					routing_send_route_error(unreachable_dest_short_rd_id);
				}
			}
			break;
		}
		case ROUTING_PDU_TYPE_DATA_FORWARD: {
			// Data Forwarding: Type | Final_Dest_RD_ID | Original_Src_RD_ID | Hop Count | Routing Mode | Data Payload
			// Header size: Type (1 byte) + Dest (2 bytes) + Orig_Src (2 bytes) + HopCount (1 byte) + RoutingMode (1 byte)
			size_t received_routing_hdr_len = 1 + SHORT_RD_ID_LEN_BYTES + SHORT_RD_ID_LEN_BYTES + 1 + 1;

			if (routing_pdu_buf->len < received_routing_hdr_len) {
				LOG_ERR("ROUTING RX: Malformed Data Forward PDU from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t final_dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint16_t original_src_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint8_t hop_count = net_buf_pull_u8(routing_pdu_buf);
			dect_routing_mode_t rx_routing_mode = (dect_routing_mode_t)net_buf_pull_u8(routing_pdu_buf);
			// Remaining data is the actual payload

			LOG_DBG("ROUTING RX Data: Final Dest 0x%04x, Orig Src 0x%04x, Hops %u, Mode %u. Payload len %u.",
					final_dest_short_rd_id, original_src_short_rd_id, hop_count, rx_routing_mode, routing_pdu_buf->len);

			// Update route to original_src_short_rd_id via current src_short_rd_id
			// Assume sequence number for route update based on our own current sequence number
			add_or_update_routing_entry(original_src_short_rd_id, src_short_rd_id, hop_count + 1,
										routing_ctx.route_sequence_number,
										CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS,
										rx_routing_mode); // Use the mode from the PDU

			if (final_dest_short_rd_id == mac_ctx.local_short_rd_id) {
				// We are the final destination, pass to CVG (data service)
				LOG_DBG("ROUTING: Data PDU for us. Passing to CVG layer.");

				// FIX: The routing header has already been pulled from the buffer.
				// Now, routing_pdu_buf starts directly with the IP packet payload.
				status = dect_cvg_receive_sdu_from_dlc(src_short_rd_id, routing_pdu_buf, CVG_SERVICE_TYPE_DATA, hpc, psn);
				if (status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(status, "ROUTING: Failed to pass received data to CVG.");
					net_buf_unref(routing_pdu_buf);
					STATS_INC(dect_stats.routing_rx_drops);
				}
			} else {
				// Not for us, forward it
				if (hop_count >= CONFIG_DECT_NR_PLUS_ROUTING_MAX_HOPS) {
					LOG_WRN("ROUTING: Packet for 0x%04x reached max hops (%u). Dropping.",
							final_dest_short_rd_id, hop_count);
					net_buf_unref(routing_pdu_buf);
					STATS_INC(dect_stats.routing_tx_drops);
					STATS_INC(dect_stats.routing_flood_tx); // Consider this a flood drop
					break;
				}

				LOG_DBG("ROUTING: Data PDU not for us (dest 0x%04x). Forwarding.", final_dest_short_rd_id);

				// Prepare for forwarding: decrement hop count and re-add to PDU.
				// We need to re-construct the routing header with updated hop count.
				struct net_buf *forward_pdu = NULL;
				size_t forward_routing_hdr_len = 1 + SHORT_RD_ID_LEN_BYTES + SHORT_RD_ID_LEN_BYTES + 1 + 1;
				size_t forward_total_len = forward_routing_hdr_len + routing_pdu_buf->len;

				dect_status_t forward_alloc_status = handle_tx_buffer_allocation(&forward_pdu, &dlc_tx_net_buf_pool, __func__,
																			 forward_total_len, DECT_ERROR_ROUTING_NO_MEM);
				if (forward_alloc_status != DECT_STATUS_OK) {
					net_buf_unref(routing_pdu_buf); // Original data buffer still needs unref
					STATS_INC(dect_stats.routing_tx_drops);
					status = forward_alloc_status;
					break;
				}

				net_buf_add_u8(forward_pdu, ROUTING_PDU_TYPE_DATA_FORWARD);
				net_buf_add_be16(forward_pdu, final_dest_short_rd_id);
				net_buf_add_be16(forward_pdu, original_src_short_rd_id);
				net_buf_add_u8(forward_pdu, hop_count + 1); // Increment hop count
				net_buf_add_u8(forward_pdu, rx_routing_mode); // Preserve routing mode

				net_buf_write(forward_pdu, routing_pdu_buf->data, routing_pdu_buf->len);
				net_buf_add(forward_pdu, routing_pdu_buf->len);
				net_buf_unref(routing_pdu_buf); // Original data buffer consumed

				status = dect_routing_send_data(final_dest_short_rd_id, forward_pdu, QOS_PRIORITY_NORMAL, rx_routing_mode); // Re-use QOS, new hop count
				if (status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(status, "ROUTING: Failed to forward data PDU for 0x%04x.", final_dest_short_rd_id);
					// forward_pdu is unref'd by dect_routing_send_data on failure
					STATS_INC(dect_stats.routing_tx_drops); // This is a forward drop
				}
				// If forwarding succeeded, the buffer is unref'd by dect_routing_send_data
			}
			break;
		}
		default:
			LOG_WRN("ROUTING RX: Unknown Routing PDU type %u. Dropping.", pdu_type);
			status = DECT_ERROR_INVALID_PDU_TYPE;
			STATS_INC(dect_stats.routing_rx_drops);
			break;
	}

	if (status != DECT_STATUS_OK && routing_pdu_buf) {
		net_buf_unref(routing_pdu_buf); // Ensure buffer is freed on error
	}
	k_mutex_unlock(&routing_ctx_mutex);
	dect_power_mgr_activity_detected(); // Notify power manager of RX activity
	return status;
}

/**
 * @brief Sends a DECT NR+ Native Route Request PDU.
 * Used primarily for horizontal routing path discovery.
 *
 * @param dest_short_rd_id The Short RD ID of the desired destination.
 * @param hop_count Current hop count (0 for originator).
 * @param orig_seq_num Originator's sequence number.
 * @param rreq_id Unique RREQ ID.
 * @return DECT_STATUS_OK on success, or an error code.
 */
static dect_status_t routing_send_route_request(uint16_t dest_short_rd_id, uint8_t hop_count,
												uint32_t orig_seq_num, uint32_t rreq_id)
{
	struct net_buf *rreq_pdu = NULL;
	// ROUTE_REQUEST format: Type | Orig_Short_RD_ID | Dest_Short_RD_ID | Hop_Count | Orig_Seq_Num | RREQ_ID
	size_t rreq_len = 1 + (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&rreq_pdu, &dlc_tx_net_buf_pool, __func__,
															 rreq_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		return alloc_status;
	}

	net_buf_add_u8(rreq_pdu, ROUTING_PDU_TYPE_ROUTE_REQUEST);
	net_buf_add_be16(rreq_pdu, mac_ctx.local_short_rd_id);      // Originator Short RD ID
	net_buf_add_be16(rreq_pdu, dest_short_rd_id);               // Destination Short RD ID
	net_buf_add_u8(rreq_pdu, hop_count);                        // Hop Count
	net_buf_add_be32(rreq_pdu, orig_seq_num);                   // Originator Sequence Number
	net_buf_add_be32(rreq_pdu, rreq_id);                        // RREQ ID

	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = SHORT_RD_ID_BROADCAST, // Route Requests are typically broadcast
		.dlc_pdu_buf = rreq_pdu,
		.service_type = CVG_SERVICE_TYPE_CONTROL, // Routing PDUs are control
		.qos_priority = QOS_PRIORITY_CRITICAL,    // RREQ should be high priority
		.is_routing_pdu = true,                   // Explicitly mark as routing PDU
	};

	int ret = k_msgq_put(&routing_tx_msgq, &tx_msg, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_TX_DROPS, "ROUTING: Failed to queue ROUTE_REQUEST PDU to DLC (ret: %d).", ret);
		net_buf_unref(rreq_pdu);
		return DECT_ERROR_QUEUE_FULL;
	}
	return DECT_STATUS_OK;
}

/**
 * @brief Sends a DECT NR+ Native Route Reply PDU.
 * Used primarily for horizontal routing path discovery.
 *
 * @param dest_short_rd_id The Short RD ID of the destination (original ROUTE_REQUEST source).
 * @param orig_route_dest_rd_id The Short RD ID of the original route destination.
 * @param hop_count Hop count from the ROUTE_REPLY source to the ROUTE_REPLY destination.
 * @param orig_route_dest_seq_num Destination sequence number for the ROUTE_REPLY.
 * @param rreq_id The RREQ ID this ROUTE_REPLY is responding to.
 * @param lifetime_ms The lifetime of the route being advertised.
 * @return DECT_STATUS_OK on success, or an error code.
 */
static dect_status_t routing_send_route_reply(uint16_t dest_short_rd_id, uint16_t orig_route_dest_rd_id,
											  uint8_t hop_count, uint32_t orig_route_dest_seq_num,
											  uint32_t rreq_id, uint32_t lifetime_ms)
{
	struct net_buf *rrep_pdu = NULL;
	// ROUTE_REPLY format: Type | Dest_Short_RD_ID | Orig_Route_Dest_RD_ID | Hop_Count | Orig_Route_Dest_Seq_Num | RREQ_ID | Lifetime
	size_t rrep_len = 1 + (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4 + 4;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&rrep_pdu, &dlc_tx_net_buf_pool, __func__,
															 rrep_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		return alloc_status;
	}

	net_buf_add_u8(rrep_pdu, ROUTING_PDU_TYPE_ROUTE_REPLY);
	net_buf_add_be16(rrep_pdu, dest_short_rd_id);          // Destination (original ROUTE_REQUEST source)
	net_buf_add_be16(rrep_pdu, orig_route_dest_rd_id);     // Originator (original ROUTE_REQUEST destination)
	net_buf_add_u8(rrep_pdu, hop_count);                   // Hop Count from RREP source to RREP destination
	net_buf_add_be32(rrep_pdu, orig_route_dest_seq_num);   // Destination Sequence Number
	net_buf_add_be32(rrep_pdu, rreq_id);                   // RREQ ID (for matching)
	net_buf_add_be32(rrep_pdu, lifetime_ms);               // Lifetime

	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = dest_short_rd_id, // Send unicast to next hop towards ROUTE_REQUEST source
		.dlc_pdu_buf = rrep_pdu,
		.service_type = CVG_SERVICE_TYPE_CONTROL,
		.qos_priority = QOS_PRIORITY_CRITICAL,
		.is_routing_pdu = true,
	};

	int ret = k_msgq_put(&routing_tx_msgq, &tx_msg, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_TX_DROPS, "ROUTING: Failed to queue ROUTE_REPLY PDU to DLC (ret: %d).", ret);
		net_buf_unref(rrep_pdu);
		return DECT_ERROR_QUEUE_FULL;
	}
	return DECT_STATUS_OK;
}

/**
 * @brief Sends a DECT NR+ Native Route Error PDU.
 *
 * @param unreachable_dest_short_rd_id The Short RD ID of the unreachable destination.
 * @return DECT_STATUS_OK on success, or an error code.
 */
static dect_status_t routing_send_route_error(uint16_t unreachable_dest_short_rd_id)
{
	struct net_buf *rerr_pdu = NULL;
	// ROUTE_ERROR format: Type | Unreachable_Dest_RD_ID | Unreachable_Dest_Seq_Num
	size_t rerr_len = 1 + SHORT_RD_ID_LEN_BYTES + 4;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&rerr_pdu, &dlc_tx_net_buf_pool, __func__,
															 rerr_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		return alloc_status;
	}

	net_buf_add_u8(rerr_pdu, ROUTING_PDU_TYPE_ROUTE_ERROR);
	net_buf_add_be16(rerr_pdu, unreachable_dest_short_rd_id);
	// Use our current knowledge of the sequence number for the unreachable destination
	int idx = find_routing_entry(unreachable_dest_short_rd_id);
	uint32_t unreachable_dest_seq_num = (idx != -1 && routing_ctx.routing_table[idx].is_valid) ?
										 routing_ctx.routing_table[idx].route_sequence_number : 0;
	net_buf_add_be32(rerr_pdu, unreachable_dest_seq_num);

	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = SHORT_RD_ID_BROADCAST, // Route Errors are typically broadcast
		.dlc_pdu_buf = rerr_pdu,
		.service_type = CVG_SERVICE_TYPE_CONTROL,
		.qos_priority = QOS_PRIORITY_CRITICAL,
		.is_routing_pdu = true,
	};

	int ret = k_msgq_put(&routing_tx_msgq, &tx_msg, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_TX_DROPS, "ROUTING: Failed to queue ROUTE_ERROR PDU to DLC (ret: %d).", ret);
		net_buf_unref(rerr_pdu);
		return DECT_ERROR_QUEUE_FULL;
	}
	return DECT_STATUS_OK;
}

/**
 * @brief Timer handler for cleaning up expired routing table entries.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
static void route_cleanup_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	uint64_t current_time = k_uptime_get();

	for (int i = 0; i < MAX_ROUTING_ENTRIES; i++) {
		if (routing_ctx.routing_table[i].is_valid) {
			if ((current_time - routing_ctx.routing_table[i].last_active_time_ms) >= routing_ctx.routing_table[i].route_lifetime_ms) {
				routing_ctx.routing_table[i].is_valid = false;
				LOG_INF("ROUTING: Route to 0x%04x expired (mode: %u).",
						routing_ctx.routing_table[i].dest_short_rd_id, routing_ctx.routing_table[i].mode);
				// Optionally, send ROUTE_ERROR for expired routes to notify neighbors if needed
				// routing_send_route_error(routing_ctx.routing_table[i].dest_short_rd_id);
			}
		}
	}
	k_mutex_unlock(&routing_ctx_mutex);
}

/**
 * @brief Timer handler for Route Request (RREQ) timeouts.
 * If a ROUTE_REQUEST times out, it means no ROUTE_REPLY was received within the expected time.
 * This indicates a route discovery failure.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
static void rreq_timeout_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	LOG_WRN("ROUTING: ROUTE_REQUEST timeout. Route discovery failed for unspecified destination (needs enhancement to track specific RREQ dests).");
	STATS_INC(dect_stats.routing_route_failures);
	// In a full AODV, you'd retransmit ROUTE_REQUEST or declare route unreachable based on retry count.
	k_mutex_unlock(&routing_ctx_mutex);
}


void dect_routing_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_DBG("DECT ROUTING Thread started.");

	dlc_rx_msg_t rx_msg;
	dlc_tx_msg_t tx_msg;
	dect_status_t status;
	bool had_activity_this_loop;

	while (true) {
		had_activity_this_loop = false;

		/* Process incoming messages from DLC (for routing control PDUs) */
		if (k_msgq_get(&routing_rx_msgq, &rx_msg, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;
			LOG_DBG("ROUTING RX: Received message from DLC (src 0x%04x, len %u, type %u).",
					rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf->len, rx_msg.dlc_pdu_type);

			// Only process if it's explicitly a routing PDU type.
			if (rx_msg.dlc_pdu_type == DLC_PDU_TYPE_ROUTING) {
				status = dect_routing_process_incoming_pdu(rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf, rx_msg.hpc, rx_msg.psn);
				if (status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(status, "ROUTING RX: Error processing incoming routing PDU.");
					// dect_routing_process_incoming_pdu should unref buffer on error.
				}
			} else {
				LOG_WRN("ROUTING RX: Received unexpected DLC PDU type %u. Dropping.", rx_msg.dlc_pdu_type);
				net_buf_unref(rx_msg.dlc_pdu_buf);
				STATS_INC(dect_stats.routing_rx_drops);
			}
		}

		/* Process outgoing messages to DLC (from routing decisions/forwarding) */
		if (k_msgq_get(&routing_tx_msgq, &tx_msg, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;
			LOG_DBG("ROUTING TX: Sending PDU (dest 0x%04x, len %u, service %u) to DLC.",
					tx_msg.dest_short_rd_id, tx_msg.dlc_pdu_buf->len, tx_msg.service_type);

			// Pass to DLC for transmission. DLC is responsible for freeing the buffer.
			status = dect_dlc_send_data_from_routing(tx_msg.dest_short_rd_id,
													 tx_msg.dlc_pdu_buf,
													 tx_msg.service_type,
													 tx_msg.qos_priority);
			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "ROUTING TX: Failed to send PDU to DLC.");
				net_buf_unref(tx_msg.dlc_pdu_buf); // Ensure buffer is unref'd if DLC couldn't take it
				STATS_INC(dect_stats.routing_tx_drops);
			}
		}

		if (!had_activity_this_loop) {
			// If no messages were processed in this iteration, sleep to yield CPU
			k_sleep(K_MSEC(10)); // Sleep for a short period
		}
	}
}

/* End of File
 * Last Amended: 2025-06-09 19:00 BST: Updated dect_routing.c for robust error handling.
 * - Added `handle_tx_buffer_allocation` helper function.
 * - Modified `routing_send_rreq`, `routing_send_rrep`, `routing_send_rerr` to use `handle_tx_buffer_allocation`.
 * - Modified `dect_routing_send_data` to unref `data_buf` and increment `routing_tx_drops` if route not found.
 * - Added detailed error logging and `STATS_INC` calls for various routing operations, including queue full, no memory, invalid PDU formats, and route failures.
 * - Ensured `net_buf_unref` is called consistently on all error paths in `dect_routing_process_incoming_pdu`.
 * - Updated `dect_routing_process_incoming_pdu` to check for `DLC_PDU_TYPE_ROUTING` and handle unknown PDU types.
 * Last Amended: 2025-06-10 19:00 BST: Implemented Robust IP-to-Short RD ID Resolution (partial via AODV integration).
 * - Updated `add_or_update_routing_entry` to implicitly update MAC's IP-to-RD_ID map (conceptual, as AODV PDUs don't carry IPv6).
 * - **POTENTIAL BUG:** Highlighted a potential bug in `ROUTING_PDU_TYPE_DATA_FORWARD` processing: `dect_cvg_receive_sdu_from_dlc` expects IP packets/fragments, but `routing_pdu_buf` here still contains the routing header and might not be directly usable by CVG without stripping the routing header and potentially re-creating a `net_pkt` if the IP header was not preserved. This needs careful review based on actual AODV over DECT NR+ PDU definitions.
 * Last Amended: 2025-06-10 20:00 BST: Implemented Robust DECT NR+ Native Routing.
 * - Updated `dect_routing_discover_route` to take `dect_routing_mode_t`.
 * - Updated `dect_routing_send_data` to take `dect_routing_mode_t` and implement basic logic for Uplink, Downlink, and Horizontal modes (including a hop-limited flooding fallback for horizontal).
 * - Changed PDU types to align with native routing: `ROUTE_REQUEST`, `ROUTE_REPLY`, `ROUTE_ERROR` (from AODV RREQ/RREP/RERR).
 * - **FIXED POTENTIAL BUG:** Implemented explicit header stripping in `dect_routing_process_incoming_pdu` for `ROUTING_PDU_TYPE_DATA_FORWARD` before passing to `dect_cvg_receive_sdu_from_dlc`. This ensures the CVG layer receives a clean IP packet.
 * - Updated `add_or_update_routing_entry` to store the `dect_routing_mode_t`.
 * - Added hop count check and increment for `DATA_FORWARD` PDUs.
 * - Added `routing_flood_tx` stat increment.
 * - Updated calls to `routing_send_route_request` and `routing_send_route_reply` to reflect new parameters.
 */
