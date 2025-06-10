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
									   uint8_t hop_count, uint32_t dest_seq_num, uint32_t lifetime_ms);
static dect_status_t routing_send_rreq(uint16_t dest_short_rd_id);
static dect_status_t routing_send_rrep(uint16_t dest_short_rd_id, uint16_t src_short_rd_id,
									   uint8_t hop_count, uint32_t dest_seq_num, uint32_t rreq_id);
static dect_status_t routing_send_rerr(uint16_t unreachable_dest_short_rd_id);
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
 * @return Index of the updated/added entry, or -1 on failure.
 */
static int add_or_update_routing_entry(uint16_t dest_short_rd_id, uint16_t next_hop_short_rd_id,
									   uint8_t hop_count, uint32_t dest_seq_num, uint32_t lifetime_ms)
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
			LOG_DBG("ROUTING: Updated route to 0x%04x via 0x%04x (hops: %u, seq: %u).",
					dest_short_rd_id, next_hop_short_rd_id, hop_count, dest_seq_num);

			// If the destination is an IPv6 peer we know, update the MAC's IPv6-to-RD_ID map
			// This is a simplification; ideally, the routing protocol would carry IPv6 info.
			// For now, we update it if the Short RD ID already exists in the MAC's map.
			// Alternatively, if the AODV layer exchanged IPv6 addresses, we'd add new entries.
			// Given the current MAC IP-to-RD_ID mapping is direct, this might not be fully coherent
			// without extending AODV PDUs to carry IPv6 info.
			// This needs further refinement if AODV is truly to manage IPv6 mapping.
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
			LOG_INF("ROUTING: Added new route to 0x%04x via 0x%04x (hops: %u, seq: %u).",
					dest_short_rd_id, next_hop_short_rd_id, hop_count, dest_seq_num);
		} else {
			DECT_ERROR_HANDLER(DECT_ERROR_NO_RESOURCES, "ROUTING: Table full. Cannot add route to 0x%04x.", dest_short_rd_id);
			return -1;
		}
	}
	return idx;
}

dect_status_t dect_routing_discover_route(uint16_t dest_short_rd_id)
{
	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	int idx = find_routing_entry(dest_short_rd_id);

	if (idx != -1 && routing_ctx.routing_table[idx].is_valid) {
		LOG_DBG("ROUTING: Route to 0x%04x already exists.", dest_short_rd_id);
		k_mutex_unlock(&routing_ctx_mutex);
		return DECT_STATUS_OK;
	}

	LOG_DBG("ROUTING: Initiating route discovery for 0x%04x.", dest_short_rd_id);
	STATS_INC(dect_stats.routing_route_discoveries);

	routing_ctx.route_sequence_number++; // Increment our own sequence number
	routing_ctx.rreq_id_counter++;       // Increment RREQ ID

	dect_status_t status = routing_send_rreq(dest_short_rd_id);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "ROUTING: Failed to send RREQ for 0x%04x.", dest_short_rd_id);
		STATS_INC(dect_stats.routing_route_failures);
	} else {
		LOG_DBG("ROUTING: RREQ sent for 0x%04x. Waiting for RREP.", dest_short_rd_id);
		// Start RREQ timeout timer for this destination
		k_timer_start(&routing_ctx.rreq_timeout_timer, K_MSEC(CONFIG_DECT_NR_PLUS_ROUTING_RREQ_TIMEOUT_MS), K_NO_WAIT);
	}

	k_mutex_unlock(&routing_ctx_mutex);
	return status;
}

dect_status_t dect_routing_send_data(uint16_t dest_short_rd_id, struct net_buf *data_buf, qos_priority_t qos_priority)
{
	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	int idx = find_routing_entry(dest_short_rd_id);

	if (idx == -1 || !routing_ctx.routing_table[idx].is_valid) {
		LOG_WRN("ROUTING: No route to 0x%04x. Initiating discovery (or dropping).", dest_short_rd_id);
		// For a full AODV implementation, initiate route discovery here and buffer the packet
		// For now, if no route, drop the packet.
		net_buf_unref(data_buf); // Free the buffer as it's dropped
		STATS_INC(dect_stats.routing_tx_drops);
		k_mutex_unlock(&routing_ctx_mutex);
		return DECT_ERROR_ROUTING_NO_ROUTE;
	}

	uint16_t next_hop = routing_ctx.routing_table[idx].next_hop_short_rd_id;
	LOG_DBG("ROUTING: Forwarding data for 0x%04x via 0x%04x.", dest_short_rd_id, next_hop);

	// Construct routing data PDU (wrap the original data)
	// Routing Header: Type (DATA_FORWARD) + Dest RD ID + Original Source RD ID + Hop Count + Seq Num
	// This would need to be defined carefully based on AODV PDU format in ETSI spec.
	// For simplicity, we'll just prepend the type and the final destination.
	struct net_buf *routing_pdu = NULL;
	size_t routing_hdr_len = 1 + SHORT_RD_ID_LEN_BYTES + SHORT_RD_ID_LEN_BYTES; // Type + Dest + Orig_Src
	size_t total_pdu_len = routing_hdr_len + data_buf->len;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&routing_pdu, &dlc_tx_net_buf_pool, __func__,
															 total_pdu_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		net_buf_unref(data_buf);
		k_mutex_unlock(&routing_ctx_mutex);
		return alloc_status;
	}

	net_buf_add_u8(routing_pdu, ROUTING_PDU_TYPE_DATA_FORWARD);
	net_buf_add_be16(routing_pdu, dest_short_rd_id); // Final destination
	net_buf_add_be16(routing_pdu, mac_ctx.local_short_rd_id); // Original source (this device)

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

	LOG_DBG("ROUTING: Data PDU for 0x%04x queued to DLC via next hop 0x%04x.", dest_short_rd_id, next_hop);
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
		case ROUTING_PDU_TYPE_RREQ: {
			// RREQ format: Type | Orig_Short_RD_ID | Dest_Short_RD_ID | Hop_Count | Orig_Seq_Num | RREQ_ID | Dest_Seq_Num
			if (routing_pdu_buf->len < (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4) { // Simplified sizes
				LOG_ERR("ROUTING RX: Malformed RREQ from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t orig_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint16_t dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint8_t hop_count = net_buf_pull_u8(routing_pdu_buf);
			uint32_t orig_seq_num = net_buf_pull_be32(routing_pdu_buf);
			uint32_t rreq_id = net_buf_pull_be32(routing_pdu_buf);
			uint32_t dest_seq_num = net_buf_pull_be32(routing_pdu_buf);

			LOG_DBG("ROUTING RX RREQ: Orig 0x%04x, Dest 0x%04x, Hops %u, OrigSeq %u, RREQID %u, DestSeq %u.",
					orig_short_rd_id, dest_short_rd_id, hop_count, orig_seq_num, rreq_id, dest_seq_num);

			// AODV processing logic (simplified):
			// 1. Update/create route to originator
			add_or_update_routing_entry(orig_short_rd_id, src_short_rd_id, hop_count + 1, orig_seq_num, CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS);

			// 2. If we are the destination or have a fresher route to destination
			if (dest_short_rd_id == mac_ctx.local_short_rd_id ||
				(find_routing_entry(dest_short_rd_id) != -1 &&
				 routing_ctx.routing_table[find_routing_entry(dest_short_rd_id)].route_sequence_number >= dest_seq_num)) {
				// Send RREP back to originator
				LOG_DBG("ROUTING: We are destination or have fresher route for 0x%04x. Sending RREP.", dest_short_rd_id);
				routing_send_rrep(orig_short_rd_id, dest_short_rd_id, 0, routing_ctx.route_sequence_number, rreq_id);
				STATS_INC(dect_stats.routing_route_success);
			} else if (dest_short_rd_id == SHORT_RD_ID_BROADCAST) {
				// Treat as broadcast route request (e.g. for neighbor discovery type messages)
				LOG_DBG("ROUTING: Received broadcast RREQ. No RREP generated for broadcast.");
			} else {
				// Else, increment hop count and rebroadcast RREQ (if not seen recently)
				LOG_DBG("ROUTING: Forwarding RREQ for 0x%04x.", dest_short_rd_id);
				// A proper AODV would track seen RREQ IDs to prevent loops.
				// For simplicity, just re-send if not destination.
				routing_send_rreq(dest_short_rd_id); // Re-broadcasts the request
			}
			break;
		}
		case ROUTING_PDU_TYPE_RREP: {
			// RREP format: Type | Dest_Short_RD_ID | Orig_Short_RD_ID | Hop_Count | Dest_Seq_Num | RREQ_ID | Lifetime
			if (routing_pdu_buf->len < (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4) { // Simplified sizes
				LOG_ERR("ROUTING RX: Malformed RREP from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf); // RREP's destination (original RREQ source)
			uint16_t orig_short_rd_id = net_buf_pull_be16(routing_pdu_buf); // RREP's source (original RREQ dest)
			uint8_t hop_count = net_buf_pull_u8(routing_pdu_buf);
			uint32_t dest_seq_num = net_buf_pull_be32(routing_pdu_buf);
			uint32_t rreq_id = net_buf_pull_be32(routing_pdu_buf); // Not strictly needed for processing, but for matching
			uint32_t lifetime_ms = net_buf_pull_be32(routing_pdu_buf);

			LOG_DBG("ROUTING RX RREP: Dest 0x%04x, Orig 0x%04x, Hops %u, DestSeq %u, Lifetime %u.",
					dest_short_rd_id, orig_short_rd_id, hop_count, dest_seq_num, lifetime_ms);

			// AODV processing logic (simplified):
			// 1. Update/create route to destination (orig_short_rd_id) via current source (src_short_rd_id)
			add_or_update_routing_entry(orig_short_rd_id, src_short_rd_id, hop_count + 1, dest_seq_num, lifetime_ms);

			// 2. If we are the original RREQ source, stop timeout and notify success
			if (dest_short_rd_id == mac_ctx.local_short_rd_id) {
				LOG_INF("ROUTING: Route to 0x%04x established! Hops: %u, via 0x%04x.",
						orig_short_rd_id, hop_count + 1, src_short_rd_id);
				k_timer_stop(&routing_ctx.rreq_timeout_timer); // Stop the RREQ timeout
				STATS_INC(dect_stats.routing_route_success);
				// TODO: Notify higher layer (CVG) that route is found for buffered packets
			} else {
				// 3. Else, forward RREP towards its destination (dest_short_rd_id)
				LOG_DBG("ROUTING: Forwarding RREP for 0x%04x.", dest_short_rd_id);
				routing_send_rrep(dest_short_rd_id, orig_short_rd_id, hop_count + 1, dest_seq_num, rreq_id);
			}
			break;
		}
		case ROUTING_PDU_TYPE_RERR: {
			// RERR format: Type | Unreachable_Dest_RD_ID | Unreachable_Dest_Seq_Num
			if (routing_pdu_buf->len < SHORT_RD_ID_LEN_BYTES + 4) { // Simplified sizes
				LOG_ERR("ROUTING RX: Malformed RERR from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t unreachable_dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint32_t unreachable_dest_seq_num = net_buf_pull_be32(routing_pdu_buf);

			LOG_WRN("ROUTING RX RERR: Unreachable 0x%04x (Seq %u) from 0x%04x.",
					unreachable_dest_short_rd_id, unreachable_dest_seq_num, src_short_rd_id);

			// AODV processing logic (simplified):
			// Invalidate route(s) and propagate RERR if necessary.
			int idx = find_routing_entry(unreachable_dest_short_rd_id);
			if (idx != -1 && routing_ctx.routing_table[idx].is_valid) {
				if (routing_ctx.routing_table[idx].route_sequence_number < unreachable_dest_seq_num ||
					(routing_ctx.routing_table[idx].route_sequence_number == unreachable_dest_seq_num &&
					 routing_ctx.routing_table[idx].next_hop_short_rd_id == src_short_rd_id)) { // If it came from our next hop
					routing_ctx.routing_table[idx].is_valid = false;
					LOG_INF("ROUTING: Invalidated route to 0x%04x.", unreachable_dest_short_rd_id);
					// Propagate RERR to other neighbors who might be using this route.
					routing_send_rerr(unreachable_dest_short_rd_id);
				}
			}
			break;
		}
		case ROUTING_PDU_TYPE_DATA_FORWARD: {
			// Data Forwarding: Type | Final_Dest_RD_ID | Original_Src_RD_ID | Data Payload
			if (routing_pdu_buf->len < (SHORT_RD_ID_LEN_BYTES * 2)) {
				LOG_ERR("ROUTING RX: Malformed Data Forward PDU from 0x%04x. Dropping.", src_short_rd_id);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				STATS_INC(dect_stats.routing_rx_drops);
				break;
			}
			uint16_t final_dest_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			uint16_t original_src_short_rd_id = net_buf_pull_be16(routing_pdu_buf);
			// Remaining data is the actual payload

			LOG_DBG("ROUTING RX Data: Final Dest 0x%04x, Orig Src 0x%04x. Payload len %u.",
					final_dest_short_rd_id, original_src_short_rd_id, routing_pdu_buf->len);

			// Update route to original_src_short_rd_id via current src_short_rd_id
			// This updates the reverse path. We don't have hop count here directly unless included.
			// For now, assume a hop count of 1.
			add_or_update_routing_entry(original_src_short_rd_id, src_short_rd_id, 1, routing_ctx.route_sequence_number, CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS);

			if (final_dest_short_rd_id == mac_ctx.local_short_rd_id) {
				// We are the final destination, pass to CVG (data service)
				LOG_DBG("ROUTING: Data PDU for us. Passing to CVG layer.");
				// Pass to CVG. The CVG layer expects net_pkt, not net_buf directly, and handles IP.
				// This requires some re-packaging. For now, we'll pass the remaining net_buf.
				// BUG: dect_cvg_receive_sdu_from_dlc expects dlc_pdu_type, not a raw routing PDU type.
				// It expects the original IP packet. This needs to be correctly extracted.
				// The current dect_cvg_receive_sdu_from_dlc handles IP fragmentation.
				// If this data_buf contains a full IP packet (or fragment), it should be passed to CVG with CVG_SERVICE_TYPE_DATA.
				// This is a potential bug or mismatch.
				status = dect_cvg_receive_sdu_from_dlc(src_short_rd_id, routing_pdu_buf, CVG_SERVICE_TYPE_DATA, hpc, psn);
				if (status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(status, "ROUTING: Failed to pass received data to CVG.");
					net_buf_unref(routing_pdu_buf);
					STATS_INC(dect_stats.routing_rx_drops);
				}
			} else {
				// Not for us, forward it
				LOG_DBG("ROUTING: Data PDU not for us (dest 0x%04x). Forwarding.", final_dest_short_rd_id);
				dect_status_t forward_status = dect_routing_send_data(final_dest_short_rd_id, routing_pdu_buf, QOS_PRIORITY_NORMAL); // Re-use QOS
				if (forward_status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(forward_status, "ROUTING: Failed to forward data PDU for 0x%04x.", final_dest_short_rd_id);
					net_buf_unref(routing_pdu_buf); // Ensure buffer is unref'd if forwarding fails
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
 * @brief Sends an AODV Route Request (RREQ) PDU.
 *
 * @param dest_short_rd_id The Short RD ID of the desired destination.
 * @return DECT_STATUS_OK on success, or an error code.
 */
static dect_status_t routing_send_rreq(uint16_t dest_short_rd_id)
{
	struct net_buf *rreq_pdu = NULL;
	// RREQ format: Type | Orig_Short_RD_ID | Dest_Short_RD_ID | Hop_Count | Orig_Seq_Num | RREQ_ID | Dest_Seq_Num
	size_t rreq_len = 1 + (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4 + 4;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&rreq_pdu, &dlc_tx_net_buf_pool, __func__,
															 rreq_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		return alloc_status;
	}

	net_buf_add_u8(rreq_pdu, ROUTING_PDU_TYPE_RREQ);
	net_buf_add_be16(rreq_pdu, mac_ctx.local_short_rd_id);      // Originator Short RD ID
	net_buf_add_be16(rreq_pdu, dest_short_rd_id);             // Destination Short RD ID
	net_buf_add_u8(rreq_pdu, 0);                                  // Hop Count (starts at 0 from originator)
	net_buf_add_be32(rreq_pdu, routing_ctx.route_sequence_number); // Originator Sequence Number
	net_buf_add_be32(rreq_pdu, routing_ctx.rreq_id_counter);     // RREQ ID
	net_buf_add_be32(rreq_pdu, 0); // Destination Sequence Number (unknown, set to 0 initially)

	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = SHORT_RD_ID_BROADCAST, // RREQ is broadcast
		.dlc_pdu_buf = rreq_pdu,
		.service_type = CVG_SERVICE_TYPE_CONTROL, // Routing PDUs are control
		.qos_priority = QOS_PRIORITY_CRITICAL,    // RREQ should be high priority
		.is_routing_pdu = true,                   // Explicitly mark as routing PDU
	};

	int ret = k_msgq_put(&routing_tx_msgq, &tx_msg, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_TX_DROPS, "ROUTING: Failed to queue RREQ PDU to DLC (ret: %d).", ret);
		net_buf_unref(rreq_pdu);
		return DECT_ERROR_QUEUE_FULL;
	}
	return DECT_STATUS_OK;
}

/**
 * @brief Sends an AODV Route Reply (RREP) PDU.
 *
 * @param dest_short_rd_id The Short RD ID of the destination (original RREQ source).
 * @param src_short_rd_id The Short RD ID of the source (original RREQ destination).
 * @param hop_count Hop count from the RREP source to the RREP destination.
 * @param dest_seq_num Destination sequence number for the RREP.
 * @param rreq_id The RREQ ID this RREP is responding to.
 * @return DECT_STATUS_OK on success, or an error code.
 */
static dect_status_t routing_send_rrep(uint16_t dest_short_rd_id, uint16_t orig_rreq_dest_rd_id,
									   uint8_t hop_count, uint32_t orig_rreq_dest_seq_num, uint32_t rreq_id)
{
	struct net_buf *rrep_pdu = NULL;
	// RREP format: Type | Dest_Short_RD_ID | Orig_Short_RD_ID | Hop_Count | Dest_Seq_Num | RREQ_ID | Lifetime
	size_t rrep_len = 1 + (SHORT_RD_ID_LEN_BYTES * 2) + 1 + 4 + 4 + 4;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&rrep_pdu, &dlc_tx_net_buf_pool, __func__,
															 rrep_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		return alloc_status;
	}

	net_buf_add_u8(rrep_pdu, ROUTING_PDU_TYPE_RREP);
	net_buf_add_be16(rrep_pdu, dest_short_rd_id);          // Destination (original RREQ source)
	net_buf_add_be16(rrep_pdu, orig_rreq_dest_rd_id);      // Originator (original RREQ destination)
	net_buf_add_u8(rrep_pdu, hop_count);                   // Hop Count from RREP source to RREP destination
	net_buf_add_be32(rrep_pdu, orig_rreq_dest_seq_num);    // Destination Sequence Number
	net_buf_add_be32(rrep_pdu, rreq_id);                   // RREQ ID (for matching)
	net_buf_add_be32(rrep_pdu, CONFIG_DECT_NR_PLUS_ROUTING_ROUTE_LIFETIME_MS); // Lifetime

	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = dest_short_rd_id, // Send unicast to next hop towards RREQ source
		.dlc_pdu_buf = rrep_pdu,
		.service_type = CVG_SERVICE_TYPE_CONTROL,
		.qos_priority = QOS_PRIORITY_CRITICAL,
		.is_routing_pdu = true,
	};

	int ret = k_msgq_put(&routing_tx_msgq, &tx_msg, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_TX_DROPS, "ROUTING: Failed to queue RREP PDU to DLC (ret: %d).", ret);
		net_buf_unref(rrep_pdu);
		return DECT_ERROR_QUEUE_FULL;
	}
	return DECT_STATUS_OK;
}

/**
 * @brief Sends an AODV Route Error (RERR) PDU.
 *
 * @param unreachable_dest_short_rd_id The Short RD ID of the unreachable destination.
 * @return DECT_STATUS_OK on success, or an error code.
 */
static dect_status_t routing_send_rerr(uint16_t unreachable_dest_short_rd_id)
{
	struct net_buf *rerr_pdu = NULL;
	// RERR format: Type | Unreachable_Dest_RD_ID | Unreachable_Dest_Seq_Num
	size_t rerr_len = 1 + SHORT_RD_ID_LEN_BYTES + 4;

	dect_status_t alloc_status = handle_tx_buffer_allocation(&rerr_pdu, &dlc_tx_net_buf_pool, __func__,
															 rerr_len, DECT_ERROR_ROUTING_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		return alloc_status;
	}

	net_buf_add_u8(rerr_pdu, ROUTING_PDU_TYPE_RERR);
	net_buf_add_be16(rerr_pdu, unreachable_dest_short_rd_id);
	// Use our current knowledge of the sequence number for the unreachable destination
	int idx = find_routing_entry(unreachable_dest_short_rd_id);
	uint32_t unreachable_dest_seq_num = (idx != -1 && routing_ctx.routing_table[idx].is_valid) ?
										 routing_ctx.routing_table[idx].route_sequence_number : 0;
	net_buf_add_be32(rerr_pdu, unreachable_dest_seq_num);

	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = SHORT_RD_ID_BROADCAST, // RERR is broadcast
		.dlc_pdu_buf = rerr_pdu,
		.service_type = CVG_SERVICE_TYPE_CONTROL,
		.qos_priority = QOS_PRIORITY_CRITICAL,
		.is_routing_pdu = true,
	};

	int ret = k_msgq_put(&routing_tx_msgq, &tx_msg, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_TX_DROPS, "ROUTING: Failed to queue RERR PDU to DLC (ret: %d).", ret);
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
				LOG_INF("ROUTING: Route to 0x%04x expired.", routing_ctx.routing_table[i].dest_short_rd_id);
				// Optionally, send RERR for expired routes to notify neighbors
				// routing_send_rerr(routing_ctx.routing_table[i].dest_short_rd_id);
			}
		}
	}
	k_mutex_unlock(&routing_ctx_mutex);
}

/**
 * @brief Timer handler for RREQ timeouts.
 * If a RREQ times out, it means no RREP was received within the expected time.
 * This indicates a route discovery failure.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
static void rreq_timeout_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	k_mutex_lock(&routing_ctx_mutex, K_FOREVER);
	LOG_WRN("ROUTING: RREQ timeout. Route discovery failed for unspecifed destination (needs enhancement to track specific RREQ dests).");
	STATS_INC(dect_stats.routing_route_failures);
	// In a full AODV, you'd retransmit RREQ or declare route unreachable based on retry count.
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
			// The `dect_dlc.c` should classify `DLC_PDU_TYPE_ROUTING` and forward it here.
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
 * Last Amended: 2025-05-31 15:20 BST: Added initial function prototypes and footer.
 * Last Amended: 2025-06-02 21:00 BST: Implemented Recommendation 14 for dect_routing.h.
 * Added `dect_routing_discover_route` prototype for initiating route discovery.
 * Added `dect_routing_send_data` prototype for sending data through the routing layer.
 * Added `dect_routing_process_incoming_pdu` prototype for processing incoming routing PDUs.
 * Added `dect_routing_link_failure_notification` for link failure notifications.
 * Updated `dect_routing_context_t` with new fields (`num_routing_entries`, `route_sequence_number`, `rreq_id_counter`).
 * Added `routing_pdu_type_t` enum for routing PDU types.
 * Added `routing_rreq_pdu_t`, `routing_rrep_pdu_t`, `routing_rerr_pdu_t` structs.
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
 */
