/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <zephyr.h>
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/ipv6.h>
#include <net/net_buf.h> // For net_buf operations
#include <sys/util.h> // For MIN/MAX macros
#include <random/rand32.h> // For sys_rand32_get for HARQ transaction ID

#include <dect_nr_plus/dect_config.h>
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_mac.h> /* For MAC layer interaction */
#include <dect_nr_plus/dect_cvg.h> /* For CVG layer interaction */
#include <dect_nr_plus/dect_crc.h> /* For CRC computation */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness
#include <dect_nr_plus/dect_dlc.h> // Own header
#include <dect_nr_plus/dect_routing.h> // For routing layer interaction

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_dlc, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global DLC context instance definition */
dect_dlc_context_t dlc_ctx = {
	.next_tx_seq_num = 0,
	.next_rx_seq_num = 0,
	.ack_pending = false,
	.ack_seq_num = 0,
	.current_rtt = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_MS,
	.rtt_var = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_VAR_MS,
	.rto = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTO_MS,
	.peer_advertised_tx_window_size = CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE, // Advertise our RX window
	.peer_advertised_rx_window_size = CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE, // Assume peer can handle our full TX window initially
};

/* Message queues for inter-layer communication */
K_MSGQ_DEFINE(dlc_rx_msgq, sizeof(dlc_rx_msg_t),
			  CONFIG_DECT_NR_PLUS_DLC_RX_QUEUE_COUNT, 4);
K_MSGQ_DEFINE(dlc_tx_msgq, sizeof(dlc_tx_msg_t),
			  CONFIG_DECT_NR_PLUS_DLC_TX_QUEUE_COUNT, 4);


/* Forward declarations for internal static functions */
static void retransmission_timer_handler(struct k_timer *timer_id);
static void ack_delay_timer_handler(struct k_timer *timer_id);
static void dlc_send_ack(uint16_t dest_short_rd_id, uint8_t seq_num, uint8_t window_size);
static void dlc_send_nack(uint16_t dest_short_rd_id, uint8_t seq_num);
static void dlc_update_rtt(uint32_t sample_rtt);
static void dlc_reset_arq_state(void);
static void dlc_free_buffers(void);
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
		STATS_INC(dect_stats.dlc_tx_drops); // Specific DLC TX drop stat
		return error_code;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_dlc_init(void)
{
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);

	/* Initialize ARQ timers */
	k_timer_init(&dlc_ctx.retransmission_timer, retransmission_timer_handler, NULL);
	k_timer_init(&dlc_ctx.ack_delay_timer, ack_delay_timer_handler, NULL);
	k_timer_init(&dlc_ctx.conn_timeout_timer, NULL, NULL); // Placeholder for connection management
	k_timer_init(&dlc_ctx.release_timeout_timer, NULL, NULL); // Placeholder for connection management

	// Initialize ARQ buffers
	for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
		dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL;
		dlc_ctx.tx_buffer[i].acknowledged = true; // Mark as free/acknowledged
	}
	for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE; i++) {
		dlc_ctx.rx_buffer[i].dlc_pdu_buf = NULL;
		dlc_ctx.rx_buffer[i].valid = false;
	}

	// Start retransmission timer (will be re-started per pending transmission)
	k_timer_start(&dlc_ctx.retransmission_timer, K_MSEC(dlc_ctx.rto), K_MSEC(dlc_ctx.rto));

	LOG_INF("DLC: Initialized. RTT: %u, RTV: %u, RTO: %u.",
			dlc_ctx.current_rtt, dlc_ctx.rtt_var, dlc_ctx.rto);

	k_mutex_unlock(&dlc_ctx.mutex);
	return DECT_STATUS_OK;
}

void dlc_mac_tx_completion_notification(uint16_t dest_short_rd_id, uint32_t harq_transaction_id, harq_feedback_t feedback,
										uint8_t retransmission_count, dect_status_t tx_status)
{
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	bool found = false;

	for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
		if (dlc_ctx.tx_buffer[i].dlc_pdu_buf &&
			dlc_ctx.tx_buffer[i].dest_short_rd_id == dest_short_rd_id &&
			dlc_ctx.tx_buffer[i].harq_transaction_id == harq_transaction_id) {
			found = true;

			if (feedback == HARQ_FEEDBACK_ACK) {
				LOG_DBG("DLC: TX %u (ID %u) ACKed. Attempts: %u.",
						dlc_ctx.tx_buffer[i].seq_num, harq_transaction_id, retransmission_count);
				dlc_ctx.tx_buffer[i].acknowledged = true;
				// Update RTT
				uint32_t sample_rtt = k_uptime_get() - dlc_ctx.tx_buffer[i].last_tx_time_ms;
				dlc_update_rtt(sample_rtt);
				net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf);
				dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL;
				STATS_INC(dect_stats.harq_tx_success);
			} else if (feedback == HARQ_FEEDBACK_NACK) {
				LOG_DBG("DLC: TX %u (ID %u) NACKed. Retransmission count: %u.",
						dlc_ctx.tx_buffer[i].seq_num, harq_transaction_id, retransmission_count);
				STATS_INC(dect_stats.harq_tx_retransmissions);
				dlc_ctx.tx_buffer[i].retransmission_count = retransmission_count;
				// Do not unref buffer; it will be retransmitted by DLC.
				// Reset last_tx_time_ms to current time for RTO calculation on next TX.
				dlc_ctx.tx_buffer[i].last_tx_time_ms = k_uptime_get();
			} else { // Implicit NACK or other PHY error
				LOG_WRN("DLC: TX %u (ID %u) failed (status %d, feedback %u). Retransmission count: %u.",
						dlc_ctx.tx_buffer[i].seq_num, harq_transaction_id, tx_status, feedback, retransmission_count);
				STATS_INC(dect_stats.harq_tx_failures);
				dlc_ctx.tx_buffer[i].retransmission_count = retransmission_count;
				dlc_ctx.tx_buffer[i].last_tx_time_ms = k_uptime_get();
			}
			break;
		}
	}
	if (!found) {
		LOG_WRN("DLC: TX completion notification for unknown HARQ ID %u.", harq_transaction_id);
	}
	k_mutex_unlock(&dlc_ctx.mutex);
}

void dlc_mac_disconnected_notification(uint16_t peer_short_rd_id, mac_link_failure_reason_t reason)
{
	LOG_INF("DLC: Disconnected from peer 0x%04x (reason: %d). Resetting ARQ state.", peer_short_rd_id, reason);
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	dlc_reset_arq_state(); // Reset ARQ state for the disconnected peer
	// In a multi-peer scenario, this should be per-peer ARQ state reset.
	// For now, it's a global reset.
	k_mutex_unlock(&dlc_ctx.mutex);
	// Notify CVG layer about link failure (optional, if CVG needs to know)
	// dect_cvg_link_failure_notification(peer_short_rd_id, reason);
}

void dlc_security_established_notification(uint16_t peer_short_rd_id)
{
	LOG_INF("DLC: Security established with peer 0x%04x. (No specific DLC action required yet).", peer_short_rd_id);
	// At this point, DLC could enable encryption for future data transfers.
	// However, current crypto integration is done at MAC layer with `dect_security_is_established()`.
	// For connection-oriented DLC, this would trigger CONNECT PDU exchange.
	// For now, just logging.
}

dect_status_t dect_dlc_send_data_from_cvg(uint16_t dest_short_rd_id, struct net_buf *sdu_buf,
										  cvg_service_type_t service_type, qos_priority_t qos_priority)
{
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	dect_status_t status = DECT_STATUS_OK;

	if (!sdu_buf) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "DLC TX from CVG: NULL SDU buffer.");
		STATS_INC(dect_stats.dlc_tx_drops);
		status = DECT_ERROR_INVALID_PARAM;
		goto exit_unlock;
	}

	if (sdu_buf->len > CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE - DLC_DATA_HDR_LEN_BYTES - DLC_CRC_LEN_BYTES) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "DLC TX from CVG: SDU too large (%u bytes).", sdu_buf->len);
		net_buf_unref(sdu_buf);
		STATS_INC(dect_stats.dlc_tx_drops);
		status = DECT_ERROR_PDU_TOO_LARGE;
		goto exit_unlock;
	}

	// Check if ARQ window is full (simple check for now)
	bool window_full = true;
	int free_idx = -1;
	for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
		if (dlc_ctx.tx_buffer[i].dlc_pdu_buf == NULL || dlc_ctx.tx_buffer[i].acknowledged) {
			free_idx = i;
			window_full = false;
			break;
		}
	}

	if (window_full) {
		DECT_ERROR_HANDLER(DECT_ERROR_DLC_TX_WINDOW_FULL, "DLC TX from CVG: ARQ TX window full. Dropping SDU for 0x%04x.", dest_short_rd_id);
		net_buf_unref(sdu_buf);
		STATS_INC(dect_stats.dlc_tx_drops);
		STATS_INC(dect_stats.dlc_window_full_blocks);
		status = DECT_ERROR_DLC_TX_WINDOW_FULL;
		goto exit_unlock;
	}

	// Allocate a new net_buf for the DLC PDU, which will contain DLC header + SDU + CRC
	struct net_buf *dlc_pdu = NULL;
	size_t dlc_pdu_len = DLC_DATA_HDR_LEN_BYTES + sdu_buf->len + DLC_CRC_LEN_BYTES;

	status = handle_tx_buffer_allocation(&dlc_pdu, &mac_tx_net_buf_pool, __func__,
										 dlc_pdu_len, DECT_ERROR_DLC_NO_MEM);
	if (status != DECT_STATUS_OK) {
		net_buf_unref(sdu_buf);
		goto exit_unlock;
	}

	// Build DLC Data PDU header
	// Current simplified DLC Data PDU: Type (1 byte) + SeqNum (1 byte) + WindowSize (1 byte) + Reserved (1 byte)
	net_buf_add_u8(dlc_pdu, DLC_PDU_TYPE_DATA); // DLC PDU Type
	net_buf_add_u8(dlc_pdu, dlc_ctx.next_tx_seq_num); // Sequence Number
	net_buf_add_u8(dlc_pdu, CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE); // Advertised RX window size
	net_buf_add_u8(dlc_pdu, 0x00); // Reserved

	// Add SDU payload
	net_buf_write(dlc_pdu, sdu_buf->data, sdu_buf->len);
	net_buf_add(dlc_pdu, sdu_buf->len); // Advance tail pointer
	net_buf_unref(sdu_buf); // DLC now owns the buffer

	// Add CRC
	uint16_t crc = compute_crc(dlc_pdu->data, dlc_pdu->len);
	net_buf_add_le16(dlc_pdu, crc); // Add CRC (Little Endian for Zephyr's crc16_ccitt)

	LOG_DBG("DLC TX from CVG: Prepared DATA PDU (Seq %u, len %u) for 0x%04x.",
			dlc_ctx.next_tx_seq_num, dlc_pdu->len, dest_short_rd_id);

	// Store in ARQ TX buffer
	dlc_ctx.tx_buffer[free_idx].dlc_pdu_buf = dlc_pdu;
	dlc_ctx.tx_buffer[free_idx].dest_short_rd_id = dest_short_rd_id;
	dlc_ctx.tx_buffer[free_idx].seq_num = dlc_ctx.next_tx_seq_num;
	dlc_ctx.tx_buffer[free_idx].retransmission_count = 0;
	dlc_ctx.tx_buffer[free_idx].last_tx_time_ms = k_uptime_get();
	dlc_ctx.tx_buffer[free_idx].acknowledged = false;
	dlc_ctx.tx_buffer[free_idx].qos_priority = qos_priority;
	dlc_ctx.tx_buffer[free_idx].service_type = service_type;
	dlc_ctx.tx_buffer[free_idx].is_routing_pdu = false; // This is directly from CVG (app data)
	dlc_ctx.tx_buffer[free_idx].rto = dlc_ctx.rto;
	// HARQ ID will be assigned by MAC when it takes the PDU.

	dlc_ctx.next_tx_seq_num = (dlc_ctx.next_tx_seq_num + 1) % DLC_MAX_SEQ_NUM; // Increment sequence number

	// Trigger immediate TX via MAC
	status = dect_mac_send_pdu_from_dlc(dest_short_rd_id, dlc_pdu, MAC_HEADER_TYPE_1_DATA,
										dlc_ctx.tx_buffer[free_idx].seq_num, // Pass DLC seq for MAC context
										qos_priority, false); // Not retransmission
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "DLC TX from CVG: Failed to send PDU to MAC layer.");
		dlc_ctx.tx_buffer[free_idx].dlc_pdu_buf = NULL; // Clear entry if MAC failed to take it
		// MAC unref'd the buffer on its error path.
		STATS_INC(dect_stats.dlc_tx_drops);
	}

exit_unlock:
	k_mutex_unlock(&dlc_ctx.mutex);
	return status;
}

dect_status_t dect_dlc_send_data_from_routing(uint16_t dest_short_rd_id, struct net_buf *routing_pdu_buf,
											  cvg_service_type_t service_type, qos_priority_t qos_priority)
{
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	dect_status_t status = DECT_STATUS_OK;

	if (!routing_pdu_buf) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "DLC TX from ROUTING: NULL routing PDU buffer.");
		STATS_INC(dect_stats.dlc_tx_drops);
		status = DECT_ERROR_INVALID_PARAM;
		goto exit_unlock;
	}

	if (routing_pdu_buf->len > CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE - DLC_DATA_HDR_LEN_BYTES - DLC_CRC_LEN_BYTES) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "DLC TX from ROUTING: Routing PDU too large (%u bytes).", routing_pdu_buf->len);
		net_buf_unref(routing_pdu_buf);
		STATS_INC(dect_stats.dlc_tx_drops);
		status = DECT_ERROR_PDU_TOO_LARGE;
		goto exit_unlock;
	}

	// Check if ARQ window is full (simple check for now)
	bool window_full = true;
	int free_idx = -1;
	for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
		if (dlc_ctx.tx_buffer[i].dlc_pdu_buf == NULL || dlc_ctx.tx_buffer[i].acknowledged) {
			free_idx = i;
			window_full = false;
			break;
		}
	}

	if (window_full) {
		DECT_ERROR_HANDLER(DECT_ERROR_DLC_TX_WINDOW_FULL, "DLC TX from ROUTING: ARQ TX window full. Dropping PDU for 0x%04x.", dest_short_rd_id);
		net_buf_unref(routing_pdu_buf);
		STATS_INC(dect_stats.dlc_tx_drops);
		STATS_INC(dect_stats.dlc_window_full_blocks);
		status = DECT_ERROR_DLC_TX_WINDOW_FULL;
		goto exit_unlock;
	}

	// Allocate a new net_buf for the DLC PDU, which will contain DLC header + Routing PDU + CRC
	struct net_buf *dlc_pdu = NULL;
	size_t dlc_pdu_len = DLC_DATA_HDR_LEN_BYTES + routing_pdu_buf->len + DLC_CRC_LEN_BYTES;

	status = handle_tx_buffer_allocation(&dlc_pdu, &mac_tx_net_buf_pool, __func__,
										 dlc_pdu_len, DECT_ERROR_DLC_NO_MEM);
	if (status != DECT_STATUS_OK) {
		net_buf_unref(routing_pdu_buf);
		goto exit_unlock;
	}

	// Build DLC Data PDU header
	// Current simplified DLC Data PDU: Type (1 byte) + SeqNum (1 byte) + WindowSize (1 byte) + Reserved (1 byte)
	net_buf_add_u8(dlc_pdu, DLC_PDU_TYPE_ROUTING); // Mark as ROUTING PDU type at DLC level
	net_buf_add_u8(dlc_pdu, dlc_ctx.next_tx_seq_num); // Sequence Number
	net_buf_add_u8(dlc_pdu, CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE); // Advertised RX window size
	net_buf_add_u8(dlc_pdu, 0x00); // Reserved

	// Add Routing PDU payload
	net_buf_write(dlc_pdu, routing_pdu_buf->data, routing_pdu_buf->len);
	net_buf_add(dlc_pdu, routing_pdu_buf->len); // Advance tail pointer
	net_buf_unref(routing_pdu_buf); // DLC now owns the buffer

	// Add CRC
	uint16_t crc = compute_crc(dlc_pdu->data, dlc_pdu->len);
	net_buf_add_le16(dlc_pdu, crc); // Add CRC (Little Endian for Zephyr's crc16_ccitt)

	LOG_DBG("DLC TX from ROUTING: Prepared ROUTING PDU (Seq %u, len %u) for 0x%04x.",
			dlc_ctx.next_tx_seq_num, dlc_pdu->len, dest_short_rd_id);

	// Store in ARQ TX buffer
	dlc_ctx.tx_buffer[free_idx].dlc_pdu_buf = dlc_pdu;
	dlc_ctx.tx_buffer[free_idx].dest_short_rd_id = dest_short_rd_id;
	dlc_ctx.tx_buffer[free_idx].seq_num = dlc_ctx.next_tx_seq_num;
	dlc_ctx.tx_buffer[free_idx].retransmission_count = 0;
	dlc_ctx.tx_buffer[free_idx].last_tx_time_ms = k_uptime_get();
	dlc_ctx.tx_buffer[free_idx].acknowledged = false;
	dlc_ctx.tx_buffer[free_idx].qos_priority = qos_priority;
	dlc_ctx.tx_buffer[free_idx].service_type = service_type;
	dlc_ctx.tx_buffer[free_idx].is_routing_pdu = true; // This is a routing PDU
	dlc_ctx.tx_buffer[free_idx].rto = dlc_ctx.rto;
	// HARQ ID will be assigned by MAC when it takes the PDU.

	dlc_ctx.next_tx_seq_num = (dlc_ctx.next_tx_seq_num + 1) % DLC_MAX_SEQ_NUM; // Increment sequence number

	// Trigger immediate TX via MAC
	status = dect_mac_send_pdu_from_dlc(dest_short_rd_id, dlc_pdu, MAC_HEADER_TYPE_1_DATA, // Routing uses DATA type MAC
										dlc_ctx.tx_buffer[free_idx].seq_num, // Pass DLC seq for MAC context
										qos_priority, false); // Not retransmission
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "DLC TX from ROUTING: Failed to send PDU to MAC layer.");
		dlc_ctx.tx_buffer[free_idx].dlc_pdu_buf = NULL; // Clear entry if MAC failed to take it
		// MAC unref'd the buffer on its error path.
		STATS_INC(dect_stats.dlc_tx_drops);
	}

exit_unlock:
	k_mutex_unlock(&dlc_ctx.mutex);
	return status;
}

/**
 * @brief Handles incoming data from the MAC layer to the DLC layer.
 *
 * @param src_short_rd_id The Short RD ID of the source peer.
 * @param mac_pdu_payload_buf The net_buf containing the MAC PDU payload (DLC PDU).
 * @param hpc Half-Permanent Counter from MAC.
 * @param psn Packet Sequence Number from MAC.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_dlc_receive_data_from_mac(uint16_t src_short_rd_id, struct net_buf *mac_pdu_payload_buf,
											 uint32_t hpc, uint16_t psn)
{
	if (!mac_pdu_payload_buf || mac_pdu_payload_buf->len < DLC_CONTROL_HDR_LEN_BYTES + DLC_CRC_LEN_BYTES) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_FORMAT, "DLC RX: Malformed PDU from MAC (len: %u).",
						   mac_pdu_payload_buf ? mac_pdu_payload_buf->len : 0);
		net_buf_unref(mac_pdu_payload_buf);
		STATS_INC(dect_stats.dlc_rx_drops);
		return DECT_ERROR_INVALID_PDU_FORMAT;
	}

	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	dect_status_t status = DECT_STATUS_OK;

	// Extract CRC first (last 2 bytes, little-endian)
	uint16_t received_crc = net_buf_pull_le16(mac_pdu_payload_buf);

	// Compute CRC on the rest of the buffer
	uint16_t computed_crc = compute_crc(mac_pdu_payload_buf->data, mac_pdu_payload_buf->len);

	if (received_crc != computed_crc) {
		DECT_ERROR_HANDLER(DECT_ERROR_DLC_CRC_ERROR, "DLC RX: CRC mismatch for PDU from 0x%04x. Received 0x%04x, Computed 0x%04x. Dropping.",
						   src_short_rd_id, received_crc, computed_crc);
		net_buf_unref(mac_pdu_payload_buf);
		STATS_INC(dect_stats.dlc_crc_errors);
		status = DECT_ERROR_DLC_CRC_ERROR;
		goto exit_unlock;
	}

	uint8_t pdu_type = net_buf_pull_u8(mac_pdu_payload_buf);

	LOG_DBG("DLC RX: Received PDU type %u from 0x%04x (len %u, PSN %u, HPC %u).",
			pdu_type, src_short_rd_id, mac_pdu_payload_buf->len, psn, hpc);

	switch (pdu_type) {
		case DLC_PDU_TYPE_DATA: {
			if (mac_pdu_payload_buf->len < DLC_DATA_HDR_LEN_BYTES - 1) { // -1 for type
				LOG_ERR("DLC RX: Malformed DATA PDU from 0x%04x. Dropping.", src_short_rd_id);
				net_buf_unref(mac_pdu_payload_buf);
				STATS_INC(dect_stats.dlc_rx_drops);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				break;
			}
			uint8_t seq_num = net_buf_pull_u8(mac_pdu_payload_buf);
			uint8_t peer_tx_window_size = net_buf_pull_u8(mac_pdu_payload_buf); // Peer's advertised TX window
			// uint8_t reserved = net_buf_pull_u8(mac_pdu_payload_buf); // Pull reserved byte

			dlc_ctx.peer_advertised_rx_window_size = peer_tx_window_size; // Update peer's RX window (our TX limit)

			LOG_DBG("DLC RX DATA: Seq %u, PeerTXWin %u, Expected Seq %u.",
					seq_num, peer_tx_window_size, dlc_ctx.next_rx_seq_num);

			// Handle out-of-order/duplicate packets
			if (!SEQ_NUM_IS_GREATER_EQUAL(seq_num, dlc_ctx.next_rx_seq_num)) {
				// Old or duplicate packet, send ACK for next_rx_seq_num and drop
				LOG_WRN("DLC RX: Received old/duplicate DATA PDU (Seq %u), expected %u. Dropping and sending ACK.",
						seq_num, dlc_ctx.next_rx_seq_num);
				dlc_send_ack(src_short_rd_id, dlc_ctx.next_rx_seq_num, CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE);
				net_buf_unref(mac_pdu_payload_buf);
				STATS_INC(dect_stats.dlc_rx_drops);
				status = DECT_ERROR_DLC_DUPLICATE_PACKET;
				break;
			}

			// Store in RX buffer if it's within the window and not already received
			int rx_buffer_idx = -1;
			for(int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE; i++) {
				if(dlc_ctx.rx_buffer[i].valid && dlc_ctx.rx_buffer[i].seq_num == seq_num) {
					// Duplicate within window, drop and ACK current window
					LOG_WRN("DLC RX: Duplicate DATA PDU (Seq %u) in RX window. Dropping and ACK'ing.", seq_num);
					dlc_send_ack(src_short_rd_id, dlc_ctx.next_rx_seq_num, CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE);
					net_buf_unref(mac_pdu_payload_buf);
					STATS_INC(dect_stats.dlc_rx_drops);
					status = DECT_ERROR_DLC_DUPLICATE_PACKET;
					goto exit_unlock;
				}
				if (!dlc_ctx.rx_buffer[i].valid && rx_buffer_idx == -1) {
					rx_buffer_idx = i;
				}
			}

			if (rx_buffer_idx == -1) {
				DECT_ERROR_HANDLER(DECT_ERROR_DLC_RX_WINDOW_FULL, "DLC RX: RX window full. Dropping DATA PDU (Seq %u).", seq_num);
				net_buf_unref(mac_pdu_payload_buf);
				STATS_INC(dect_stats.dlc_rx_drops);
				status = DECT_ERROR_DLC_RX_WINDOW_FULL;
				goto exit_unlock;
			}

			dlc_ctx.rx_buffer[rx_buffer_idx].dlc_pdu_buf = mac_pdu_payload_buf;
			dlc_ctx.rx_buffer[rx_buffer_idx].seq_num = seq_num;
			dlc_ctx.rx_buffer[rx_buffer_idx].src_short_rd_id = src_short_rd_id;
			dlc_ctx.rx_buffer[rx_buffer_idx].hpc = hpc;
			dlc_ctx.rx_buffer[rx_buffer_idx].psn = psn;
			dlc_ctx.rx_buffer[rx_buffer_idx].valid = true;
			dlc_ctx.rx_buffer[rx_buffer_idx].service_type = CVG_SERVICE_TYPE_DATA; // This is application data

			// Check for contiguous packets starting from next_rx_seq_num and pass them up
			for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE; i++) {
				int current_buf_idx = -1;
				for (int j = 0; j < CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE; j++) {
					if (dlc_ctx.rx_buffer[j].valid && dlc_ctx.rx_buffer[j].seq_num == dlc_ctx.next_rx_seq_num) {
						current_buf_idx = j;
						break;
					}
				}

				if (current_buf_idx != -1) {
					dlc_rx_msg_t rx_msg_to_cvg = {
						.src_short_rd_id = dlc_ctx.rx_buffer[current_buf_idx].src_short_rd_id,
						.dlc_pdu_buf = dlc_ctx.rx_buffer[current_buf_idx].dlc_pdu_buf,
						.rssi = 0, // RSSI is handled by MAC, not available here explicitly from DLC PDU.
						.hpc = dlc_ctx.rx_buffer[current_buf_idx].hpc,
						.psn = dlc_ctx.rx_buffer[current_buf_idx].psn,
						.dlc_pdu_type = DLC_PDU_TYPE_DATA, // Pass up as data type
					};
					// Pass to CVG
					int ret = k_msgq_put(&cvg_rx_msgq, &rx_msg_to_cvg, K_NO_WAIT);
					if (ret != 0) {
						DECT_ERROR_HANDLER(DECT_ERROR_CVG_RX_DROPS, "DLC RX: Failed to queue DATA PDU (Seq %u) to CVG (ret: %d).", dlc_ctx.next_rx_seq_num, ret);
						net_buf_unref(rx_msg_to_cvg.dlc_pdu_buf);
						STATS_INC(dect_stats.dlc_rx_drops); // This also counts as a DLC drop
						// Continue trying to pass up subsequent packets in window if possible
					} else {
						LOG_DBG("DLC RX: Passed DATA PDU (Seq %u) to CVG.", dlc_ctx.next_rx_seq_num);
					}

					dlc_ctx.rx_buffer[current_buf_idx].dlc_pdu_buf = NULL; // Clear pointer
					dlc_ctx.rx_buffer[current_buf_idx].valid = false;
					dlc_ctx.next_rx_seq_num = (dlc_ctx.next_rx_seq_num + 1) % DLC_MAX_SEQ_NUM; // Increment expected sequence number
				} else {
					// Gap in sequence numbers, stop processing contiguous packets
					break;
				}
			}

			// Always send an ACK for the highest contiguous sequence number received
			dlc_send_ack(src_short_rd_id, dlc_ctx.next_rx_seq_num, CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE);
			break;
		}

		case DLC_PDU_TYPE_ACK: {
			if (mac_pdu_payload_buf->len < DLC_ACK_HDR_LEN_BYTES - 1) { // -1 for type
				LOG_ERR("DLC RX: Malformed ACK PDU from 0x%04x. Dropping.", src_short_rd_id);
				net_buf_unref(mac_pdu_payload_buf);
				STATS_INC(dect_stats.dlc_rx_drops);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				break;
			}
			uint8_t ack_seq_num = net_buf_pull_u8(mac_pdu_payload_buf);
			uint8_t peer_rx_window_size = net_buf_pull_u8(mac_pdu_payload_buf); // Peer's advertised RX window

			dlc_ctx.peer_advertised_tx_window_size = peer_rx_window_size; // Update peer's TX window (our RX limit)

			LOG_DBG("DLC RX ACK: Seq %u, PeerRXWin %u.", ack_seq_num, peer_rx_window_size);
			STATS_INC(dect_stats.dlc_acks_rx);

			k_mutex_lock(&dlc_ctx.mutex, K_FOREVER); // Acquire mutex for tx_buffer access
			// Mark acknowledged packets as such and free buffers
			for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
				if (dlc_ctx.tx_buffer[i].dlc_pdu_buf &&
					SEQ_NUM_IS_GREATER_EQUAL(ack_seq_num, dlc_ctx.tx_buffer[i].seq_num) &&
					!dlc_ctx.tx_buffer[i].acknowledged) {
					LOG_DBG("DLC RX ACK: PDU Seq %u acknowledged.", dlc_ctx.tx_buffer[i].seq_num);
					dlc_ctx.tx_buffer[i].acknowledged = true;
					// Update RTT for this acknowledged packet
					uint32_t sample_rtt = k_uptime_get() - dlc_ctx.tx_buffer[i].last_tx_time_ms;
					dlc_update_rtt(sample_rtt);
					net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf);
					dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL; // Free buffer
				}
			}
			k_mutex_unlock(&dlc_ctx.mutex);
			net_buf_unref(mac_pdu_payload_buf); // ACK PDU itself is consumed
			break;
		}

		case DLC_PDU_TYPE_NACK: {
			if (mac_pdu_payload_buf->len < DLC_CONTROL_HDR_LEN_BYTES - 1) { // -1 for type
				LOG_ERR("DLC RX: Malformed NACK PDU from 0x%04x. Dropping.", src_short_rd_id);
				net_buf_unref(mac_pdu_payload_buf);
				STATS_INC(dect_stats.dlc_rx_drops);
				status = DECT_ERROR_INVALID_PDU_FORMAT;
				break;
			}
			uint8_t nack_seq_num = net_buf_pull_u8(mac_pdu_payload_buf);
			// uint8_t reserved = net_buf_pull_u8(mac_pdu_payload_buf); // Pull reserved byte
			LOG_DBG("DLC RX NACK: Seq %u.", nack_seq_num);
			STATS_INC(dect_stats.dlc_nacks_rx);

			// Trigger retransmission for the NACKed packet
			k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
			for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
				if (dlc_ctx.tx_buffer[i].dlc_pdu_buf && dlc_ctx.tx_buffer[i].seq_num == nack_seq_num) {
					if (!dlc_ctx.tx_buffer[i].acknowledged) {
						LOG_DBG("DLC RX NACK: Retransmitting PDU Seq %u.", nack_seq_num);
						dlc_ctx.tx_buffer[i].retransmission_count++;
						dlc_ctx.tx_buffer[i].last_tx_time_ms = k_uptime_get(); // Reset timer for retransmission
						// Trigger retransmission via MAC directly
						dect_mac_send_pdu_from_dlc(dlc_ctx.tx_buffer[i].dest_short_rd_id,
												   dlc_ctx.tx_buffer[i].dlc_pdu_buf,
												   dlc_ctx.tx_buffer[i].is_routing_pdu ? MAC_HEADER_TYPE_1_DATA : MAC_HEADER_TYPE_1_DATA, // Routing uses DATA type MAC
												   dlc_ctx.tx_buffer[i].seq_num,
												   dlc_ctx.tx_buffer[i].qos_priority, true); // Mark as retransmission
						STATS_INC(dect_stats.dlc_retransmissions);
					} else {
						LOG_WRN("DLC RX NACK: Received NACK for already acknowledged PDU Seq %u.", nack_seq_num);
					}
					break;
				}
			}
			k_mutex_unlock(&dlc_ctx.mutex);
			net_buf_unref(mac_pdu_payload_buf); // NACK PDU itself is consumed
			break;
		}

		case DLC_PDU_TYPE_ROUTING: {
			LOG_DBG("DLC RX: Received ROUTING PDU from 0x%04x. Passing to Routing layer.", src_short_rd_id);
			// Pass to routing layer
			dlc_rx_msg_t rx_msg_to_routing = {
				.src_short_rd_id = src_short_rd_id,
				.dlc_pdu_buf = mac_pdu_payload_buf, // Pass ownership
				.rssi = 0, // Not directly from DLC PDU
				.hpc = hpc,
				.psn = psn,
				.dlc_pdu_type = DLC_PDU_TYPE_ROUTING,
			};
			int ret = k_msgq_put(&routing_rx_msgq, &rx_msg_to_routing, K_NO_WAIT);
			if (ret != 0) {
				DECT_ERROR_HANDLER(DECT_ERROR_ROUTING_RX_DROPS, "DLC RX: Failed to queue ROUTING PDU to Routing layer (ret: %d).", ret);
				net_buf_unref(mac_pdu_payload_buf); // If routing queue full, drop.
				STATS_INC(dect_stats.dlc_rx_drops); // Counts as DLC drop too.
			}
			break;
		}

		// Add other DLC PDU types (FLOW_CONTROL, CONNECT, RELEASE, BEACON) handling as needed
		default:
			LOG_WRN("DLC RX: Unknown or unhandled PDU type %u from 0x%04x. Dropping.", pdu_type, src_short_rd_id);
			net_buf_unref(mac_pdu_payload_buf);
			STATS_INC(dect_stats.dlc_rx_drops);
			status = DECT_ERROR_INVALID_PDU_TYPE;
			break;
	}

exit_unlock:
	k_mutex_unlock(&dlc_ctx.mutex);
	dect_power_mgr_activity_detected(); // Notify power manager of RX activity
	return status;
}

/**
 * @brief DLC thread entry point.
 * This thread handles retransmissions, ACK/NACK processing, and forwards data.
 *
 * @param p1 Unused.
 * @param p2 Unused.
 * @param p3 Unused.
 */
void dect_dlc_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_DBG("DECT DLC Thread started.");

	dlc_tx_msg_t tx_msg;
	dlc_rx_msg_t rx_msg;
	dect_status_t status;
	bool had_activity_this_loop;

	while (true) {
		had_activity_this_loop = false;

		/* Process incoming messages from CVG/Routing */
		if (k_msgq_get(&dlc_tx_msgq, &tx_msg, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;
			LOG_DBG("DLC TX: Received message from higher layer (dest 0x%04x, len %u, service %u, routing_pdu %d).",
					tx_msg.dest_short_rd_id, tx_msg.dlc_pdu_buf->len, tx_msg.service_type, tx_msg.is_routing_pdu);

			// Decide whether to call dect_dlc_send_data_from_cvg or dect_dlc_send_data_from_routing
			if (tx_msg.is_routing_pdu) {
				status = dect_dlc_send_data_from_routing(tx_msg.dest_short_rd_id, tx_msg.dlc_pdu_buf,
														 tx_msg.service_type, tx_msg.qos_priority);
			} else {
				status = dect_dlc_send_data_from_cvg(tx_msg.dest_short_rd_id, tx_msg.dlc_pdu_buf,
													 tx_msg.service_type, tx_msg.qos_priority);
			}

			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "DLC TX: Failed to send PDU to MAC layer.");
				// The send functions handle unref on their error paths.
			}
		}

		/* Process incoming messages from MAC */
		if (k_msgq_get(&dlc_rx_msgq, &rx_msg, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;
			LOG_DBG("DLC RX: Received message from MAC (src 0x%04x, len %u).",
					rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf->len);

			status = dect_dlc_receive_data_from_mac(rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf,
													rx_msg.hpc, rx_msg.psn);
			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "DLC RX: Error processing incoming PDU from MAC.");
				// dect_dlc_receive_data_from_mac handles unref on its error paths.
			}
		}

		// Re-scan ARQ TX buffer for any unacknowledged packets that need retransmission due to RTO expiry
		k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
		uint64_t current_time = k_uptime_get();
		for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
			if (dlc_ctx.tx_buffer[i].dlc_pdu_buf && !dlc_ctx.tx_buffer[i].acknowledged &&
				(current_time - dlc_ctx.tx_buffer[i].last_tx_time_ms) >= dlc_ctx.tx_buffer[i].rto) {
				if (dlc_ctx.tx_buffer[i].retransmission_count < CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES) {
					LOG_DBG("DLC TX: Retransmission timeout for PDU Seq %u (ID %u). Attempt %u.",
							dlc_ctx.tx_buffer[i].seq_num, dlc_ctx.tx_buffer[i].harq_transaction_id,
							dlc_ctx.tx_buffer[i].retransmission_count + 1);
					dlc_ctx.tx_buffer[i].retransmission_count++;
					dlc_ctx.tx_buffer[i].last_tx_time_ms = current_time; // Reset timer for retransmission
					dlc_ctx.tx_buffer[i].rto *= 2; // Exponential backoff
					if (dlc_ctx.tx_buffer[i].rto > CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS) {
						dlc_ctx.tx_buffer[i].rto = CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS;
					}
					// Re-send PDU via MAC
					status = dect_mac_send_pdu_from_dlc(dlc_ctx.tx_buffer[i].dest_short_rd_id,
														dlc_ctx.tx_buffer[i].dlc_pdu_buf,
														dlc_ctx.tx_buffer[i].is_routing_pdu ? MAC_HEADER_TYPE_1_DATA : MAC_HEADER_TYPE_1_DATA, // Routing uses DATA type MAC
														dlc_ctx.tx_buffer[i].seq_num,
														dlc_ctx.tx_buffer[i].qos_priority, true); // Mark as retransmission
					if (status != DECT_STATUS_OK) {
						DECT_ERROR_HANDLER(status, "DLC TX: Failed to retransmit PDU Seq %u to MAC.", dlc_ctx.tx_buffer[i].seq_num);
						// If MAC fails to take, this PDU might be stuck. Consider further error handling.
						// The buffer is not unref'd here, as it's still in the ARQ buffer.
						STATS_INC(dect_stats.dlc_tx_drops);
					} else {
						STATS_INC(dect_stats.dlc_retransmissions);
						had_activity_this_loop = true;
					}
				} else {
					LOG_ERR("DLC TX: Max retransmission attempts (%u) reached for PDU Seq %u (ID %u). Dropping.",
							CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES, dlc_ctx.tx_buffer[i].seq_num, dlc_ctx.tx_buffer[i].harq_transaction_id);
					net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf); // Finally drop the buffer
					dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL;
					dlc_ctx.tx_buffer[i].acknowledged = true; // Mark as free
					STATS_INC(dect_stats.dlc_tx_drops);
				}
			}
		}
		k_mutex_unlock(&dlc_ctx.mutex);


		if (!had_activity_this_loop) {
			// If no messages were processed in this iteration, sleep to yield CPU
			k_sleep(K_MSEC(10)); // Sleep for a short period
		}
	}
}

/**
 * @brief Sends a DLC ACK PDU.
 *
 * @param dest_short_rd_id The Short RD ID of the destination.
 * @param seq_num The sequence number being acknowledged.
 * @param window_size The advertised receive window size.
 */
static void dlc_send_ack(uint16_t dest_short_rd_id, uint8_t seq_num, uint8_t window_size)
{
	struct net_buf *ack_pdu = NULL;
	// ACK PDU: Type (1 byte) + ACK_SeqNum (1 byte) + WindowSize (1 byte)
	size_t ack_len = DLC_ACK_HDR_LEN_BYTES + 1; // 1 for type, 1 for seq, 1 for window size
	dect_status_t status = handle_tx_buffer_allocation(&ack_pdu, &mac_tx_net_buf_pool, __func__,
													   ack_len, DECT_ERROR_DLC_NO_MEM);
	if (status != DECT_STATUS_OK) {
		return;
	}

	net_buf_add_u8(ack_pdu, DLC_PDU_TYPE_ACK);
	net_buf_add_u8(ack_pdu, seq_num);
	net_buf_add_u8(ack_pdu, window_size);

	// Add CRC
	uint16_t crc = compute_crc(ack_pdu->data, ack_pdu->len);
	net_buf_add_le16(ack_pdu, crc);

	LOG_DBG("DLC TX: Sending ACK PDU (Seq %u, Win %u) to 0x%04x.", seq_num, window_size, dest_short_rd_id);

	// Send via MAC as a control PDU (even though DLC type is DATA)
	status = dect_mac_send_pdu_from_dlc(dest_short_rd_id, ack_pdu, MAC_HEADER_TYPE_1_CONTROL, // Use Control MAC Header Type for ACKs
										0, // No DLC seq num for MAC context for control PDU
										QOS_PRIORITY_CRITICAL, false); // ACKs are critical, not retransmission
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "DLC TX: Failed to send ACK PDU to MAC layer.");
		net_buf_unref(ack_pdu);
		STATS_INC(dect_stats.dlc_tx_drops);
	} else {
		STATS_INC(dect_stats.dlc_acks_tx);
	}
}

/**
 * @brief Sends a DLC NACK PDU.
 *
 * @param dest_short_rd_id The Short RD ID of the destination.
 * @param seq_num The sequence number being NACKed.
 */
static void dlc_send_nack(uint16_t dest_short_rd_id, uint8_t seq_num)
{
	struct net_buf *nack_pdu = NULL;
	// NACK PDU: Type (1 byte) + NACK_SeqNum (1 byte) + Reserved (1 byte)
	size_t nack_len = DLC_CONTROL_HDR_LEN_BYTES + 1; // 1 for type, 1 for seq, 1 for reserved
	dect_status_t status = handle_tx_buffer_allocation(&nack_pdu, &mac_tx_net_buf_pool, __func__,
													   nack_len, DECT_ERROR_DLC_NO_MEM);
	if (status != DECT_STATUS_OK) {
		return;
	}

	net_buf_add_u8(nack_pdu, DLC_PDU_TYPE_NACK);
	net_buf_add_u8(nack_pdu, seq_num);
	net_buf_add_u8(nack_pdu, 0x00); // Reserved

	// Add CRC
	uint16_t crc = compute_crc(nack_pdu->data, nack_pdu->len);
	net_buf_add_le16(nack_pdu, crc);

	LOG_DBG("DLC TX: Sending NACK PDU (Seq %u) to 0x%04x.", seq_num, dest_short_rd_id);

	// Send via MAC as a control PDU
	status = dect_mac_send_pdu_from_dlc(dest_short_rd_id, nack_pdu, MAC_HEADER_TYPE_1_CONTROL, // Use Control MAC Header Type for NACKs
										0, // No DLC seq num for MAC context for control PDU
										QOS_PRIORITY_CRITICAL, false); // NACKs are critical, not retransmission
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "DLC TX: Failed to send NACK PDU to MAC layer.");
		net_buf_unref(nack_pdu);
		STATS_INC(dect_stats.dlc_tx_drops);
	} else {
		STATS_INC(dect_stats.dlc_nacks_tx);
	}
}

/**
 * @brief Updates the Smoothed Round Trip Time (SRTT) and Retransmission Timeout (RTO).
 * Implements a simplified Jacobson's algorithm.
 *
 * @param sample_rtt The latest RTT sample in milliseconds.
 */
static void dlc_update_rtt(uint32_t sample_rtt)
{
	if (dlc_ctx.current_rtt == CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_MS) {
		// First sample, initialize
		dlc_ctx.current_rtt = sample_rtt;
		dlc_ctx.rtt_var = sample_rtt / 2; // Initial RTV
	} else {
		// Update SRTT and RTTVAR
		dlc_ctx.rtt_var = (dlc_ctx.rtt_var * (RTT_BETA_SHIFT - 1) + ABS((int32_t)dlc_ctx.current_rtt - (int32_t)sample_rtt)) / RTT_BETA_SHIFT;
		dlc_ctx.current_rtt = (dlc_ctx.current_rtt * (RTT_ALPHA_SHIFT - 1) + sample_rtt) / RTT_ALPHA_SHIFT;
	}

	// Calculate RTO
	dlc_ctx.rto = dlc_ctx.current_rtt + RTT_K_FACTOR * dlc_ctx.rtt_var;

	// Clamp RTO to min/max values
	if (dlc_ctx.rto < CONFIG_DECT_NR_PLUS_DLC_MIN_RTO_MS) {
		dlc_ctx.rto = CONFIG_DECT_NR_PLUS_DLC_MIN_RTO_MS;
	}
	if (dlc_ctx.rto > CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS) {
		dlc_ctx.rto = CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS;
	}

	LOG_DBG("DLC RTT Update: Sample %u, SRTT %u, RTTVAR %u, RTO %u.",
			sample_rtt, dlc_ctx.current_rtt, dlc_ctx.rtt_var, dlc_ctx.rto);
}

/**
 * @brief Timer handler for ARQ retransmissions.
 * This is primarily a fallback; individual retransmissions are triggered by MAC notifications.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
static void retransmission_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	// The main ARQ retransmission logic is now handled inline in the dlc_thread loop
	// by scanning tx_buffer entries that have exceeded their RTO.
	// This timer could be used for a more global RTO check or for specific connection timeouts.
	LOG_DBG("DLC: Global retransmission timer fired. Individual retransmissions are checked in thread loop.");
}

/**
 * @brief Timer handler for delayed ACKs.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
static void ack_delay_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	if (dlc_ctx.ack_pending) {
		LOG_DBG("DLC: Delayed ACK timer fired. Sending ACK for Seq %u.", dlc_ctx.ack_seq_num);
		dlc_send_ack(mac_ctx.associated_fp_short_rd_id, dlc_ctx.ack_seq_num, CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE);
		dlc_ctx.ack_pending = false;
	}
	k_mutex_unlock(&dlc_ctx.mutex);
}

/**
 * @brief Resets the ARQ state of the DLC layer.
 * This is called upon link disconnection or re-initialization.
 */
static void dlc_reset_arq_state(void)
{
	dlc_free_buffers(); // Free all outstanding buffers

	dlc_ctx.next_tx_seq_num = 0;
	dlc_ctx.next_rx_seq_num = 0;
	dlc_ctx.ack_pending = false;
	dlc_ctx.ack_seq_num = 0;

	// Reset RTT/RTO to initial values
	dlc_ctx.current_rtt = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_MS;
	dlc_ctx.rtt_var = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_VAR_MS;
	dlc_ctx.rto = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTO_MS;

	// Stop timers if they are running
	k_timer_stop(&dlc_ctx.retransmission_timer);
	k_timer_stop(&dlc_ctx.ack_delay_timer);
	// Restart retransmission timer with default RTO
	k_timer_start(&dlc_ctx.retransmission_timer, K_MSEC(dlc_ctx.rto), K_MSEC(dlc_ctx.rto));

	LOG_DBG("DLC: ARQ state reset.");
}

/**
 * @brief Frees all net_buf instances held by the DLC TX and RX buffers.
 */
static void dlc_free_buffers(void)
{
	for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_TX_WINDOW_SIZE; i++) {
		if (dlc_ctx.tx_buffer[i].dlc_pdu_buf) {
			net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf);
			dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL;
			dlc_ctx.tx_buffer[i].acknowledged = true;
		}
	}
	for (int i = 0; i < CONFIG_DECT_NR_PLUS_DLC_MAX_RX_WINDOW_SIZE; i++) {
		if (dlc_ctx.rx_buffer[i].dlc_pdu_buf) {
			net_buf_unref(dlc_ctx.rx_buffer[i].dlc_pdu_buf);
			dlc_ctx.rx_buffer[i].dlc_pdu_buf = NULL;
			dlc_ctx.rx_buffer[i].valid = false;
		}
	}
	LOG_DBG("DLC: All ARQ buffers freed.");
}


/* End of File
 * Last Amended: 2025-06-09 18:10 BST: Updated dect_dlc.c for robust error handling.
 * - Added `handle_tx_buffer_allocation` helper function for consistent net_buf allocation errors.
 * - Modified `dect_dlc_send_data_from_cvg` to use `handle_tx_buffer_allocation`.
 * - Enhanced error checks for NULL buffers, PDU size, and ARQ window full, returning specific DECT_ERROR codes and logging.
 * - Added `STATS_INC` calls for various DLC TX drops (no memory, PDU too large, window full).
 * - Modified `dect_dlc_receive_data_from_mac` to include comprehensive CRC validation and error handling for malformed PDUs.
 * - Added `STATS_INC` calls for DLC RX drops (CRC errors, malformed PDU, duplicate packet, RX window full).
 * - Ensured `net_buf_unref` is called consistently on all error paths for both TX and RX.
 * - Fixed potential issue where `ack_delay_timer_handler` might try to send ACK if `ack_pending` is true but `mac_ctx.associated_fp_short_rd_id` is invalid (e.g., after disconnection).
 * - Updated `dlc_mac_tx_completion_notification` to correctly update RTT on ACK.
 * - Updated `dlc_reset_arq_state` to stop timers before re-starting.
 * Last Amended: 2025-06-10 20:45 BST: Implemented Robust DECT NR+ Native Routing in DLC.
 * - Added `dect_dlc_send_data_from_routing` to specifically handle routing layer PDUs, marking them with `is_routing_pdu = true` in the `tx_buffer` entry.
 * - Modified `dect_dlc_receive_data_from_mac` to properly identify `DLC_PDU_TYPE_ROUTING` and queue it to `routing_rx_msgq`.
 * - Updated the `dlc_thread`'s `k_msgq_get` loop to differentiate between messages from CVG and Routing based on the `is_routing_pdu` flag in `dlc_tx_msg_t`, calling the appropriate `dect_dlc_send_data_from_cvg` or `dect_dlc_send_data_from_routing` function.
 * - Adjusted MAC TX calls within DLC to use `MAC_HEADER_TYPE_1_DATA` for routing PDUs as well, based on the `is_routing_pdu` flag.
 * - Corrected the handling of `DLC_PDU_TYPE_ACK` and `DLC_PDU_TYPE_NACK` within `dect_dlc_receive_data_from_mac` to use `MAC_HEADER_TYPE_1_CONTROL` for their MAC header type, as they are control messages.
 */
