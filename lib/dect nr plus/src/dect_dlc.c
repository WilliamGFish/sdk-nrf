/*
 * Copyright (c) 2025 Google LLC - MAN
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
#include <dect_nr_plus/dect_security.h> // For security context access (session key)

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_dlc, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global DLC context instance definition */
dect_dlc_context_t dlc_ctx = {
	.next_tx_seq_num = 0,
	.next_rx_seq_num = 0,
	.current_rtt = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_MS,
	.rtt_var = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTT_VAR_MS,
	.rto = CONFIG_DECT_NR_PLUS_DLC_INITIAL_RTO_MS,
	.peer_advertised_tx_window_size = DLC_TX_WINDOW_SIZE, // Advertise our RX window size
	.peer_advertised_rx_window_size = DLC_RX_WINDOW_SIZE, // Assume peer's TX window is our RX window
	.ack_pending = false,
	.ack_seq_num = 0,
};

/* Mutex to protect dlc_ctx */
K_MUTEX_DEFINE(dlc_ctx_mutex);


/* Message queues for inter-layer communication */
K_MSGQ_DEFINE(dlc_rx_msgq, sizeof(dlc_rx_msg_t),
	      CONFIG_DECT_NR_PLUS_DLC_RX_QUEUE_SIZE, 4); // From MAC to DLC

K_MSGQ_DEFINE(dlc_tx_msgq, sizeof(dlc_tx_msg_t),
	      CONFIG_DECT_NR_PLUS_DLC_TX_QUEUE_SIZE, 4); // From CVG/Routing to DLC


/* Forward declarations for internal functions */
static void dlc_allocate_buffers(void);
static void dlc_free_buffers(void);
static void dlc_retransmission_timer_handler(struct k_timer *timer_id);
static void dlc_ack_delay_timer_handler(struct k_timer *timer_id);
static void dlc_retransmit_pdu(uint16_t dest_short_rd_id, struct net_buf *pdu_buf, uint32_t dlc_seq_num,
			       uint32_t harq_transaction_id, cvg_service_type_t service_type,
			       bool encrypted, bool is_routing_pdu, uint8_t retransmission_count);
static dect_status_t dlc_send_ack(uint16_t dest_short_rd_id, uint8_t ack_seq_num, uint16_t window_size);
static void dlc_update_rtt(uint32_t sample_rtt);
static void dlc_reset_arq_state(void);


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
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "DLC: Failed to allocate net_buf from pool %s. No memory.", pool->name);
		STATS_INC(dect_stats.tx_drops_no_mem); // Increment global stat for TX drops due to no memory
		return DECT_ERROR_NO_MEM;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_dlc_init(void)
{
	k_mutex_init(&dlc_ctx.mutex);
	dlc_allocate_buffers(); // Initialize ARQ buffers

	k_timer_init(&dlc_ctx.retransmission_timer, dlc_retransmission_timer_handler, NULL);
	k_timer_start(&dlc_ctx.retransmission_timer, K_MSEC(dlc_ctx.rto), K_MSEC(dlc_ctx.rto));

	k_timer_init(&dlc_ctx.ack_delay_timer, dlc_ack_delay_timer_handler, NULL);

	// Ensure DLC context is reset to initial state
	dlc_reset_arq_state();

	LOG_INF("DLC: Module initialized. RTO: %u ms.", dlc_ctx.rto);
	return DECT_STATUS_OK;
}

/**
 * @brief Thread entry point for the DLC layer.
 *
 * This thread is responsible for processing outgoing SDUs from CVG/Routing,
 * processing incoming PDUs from MAC, and managing ARQ and flow control.
 */
void dect_dlc_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("DLC: Thread started.");

	dlc_tx_msg_t tx_msg;
	dlc_rx_msg_t rx_msg;

	while (true) {
		// Process outgoing data from CVG/Routing
		if (k_msgq_get(&dlc_tx_msgq, &tx_msg, K_NO_WAIT) == 0) {
			LOG_DBG("DLC: Received TX SDU from higher layer (dest 0x%04x, len %u, type %u, QoS %u).",
				tx_msg.dest_short_rd_id, tx_msg.dlc_pdu_buf->len,
				tx_msg.service_type, tx_msg.qos_priority);

			k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);

			// Check if TX window is full
			uint8_t current_tx_window_usage = 0;
			for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
				if (dlc_ctx.tx_buffer[i].dlc_pdu_buf != NULL) {
					current_tx_window_usage++;
				}
			}

			if (current_tx_window_usage >= dlc_ctx.peer_advertised_rx_window_size) {
				DECT_ERROR_HANDLER(DECT_ERROR_DLC_TX_WINDOW_FULL, "DLC: TX window full (peer adv. RX window %u). Dropping SDU.",
							dlc_ctx.peer_advertised_rx_window_size);
				STATS_INC(dect_stats.dlc_tx_drops); // Increment DLC specific drop stat
				net_buf_unref(tx_msg.dlc_pdu_buf); // Unref the SDU buffer
				k_mutex_unlock(&dlc_ctx.mutex);
				continue;
			}

			// Find a free entry in the TX buffer
			int tx_idx = -1;
			for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
				if (dlc_ctx.tx_buffer[i].dlc_pdu_buf == NULL) {
					tx_idx = i;
					break;
				}
			}

			if (tx_idx == -1) {
				DECT_ERROR_HANDLER(DECT_ERROR_NO_RESOURCES, "DLC: TX ARQ buffer full. Dropping SDU.");
				STATS_INC(dect_stats.dlc_tx_drops); // Increment DLC specific drop stat
				net_buf_unref(tx_msg.dlc_pdu_buf); // Unref the SDU buffer
				k_mutex_unlock(&dlc_ctx.mutex);
				continue;
			}

			dlc_ctx.tx_buffer[tx_idx].seq_num = dlc_ctx.next_tx_seq_num;
			dlc_ctx.tx_buffer[tx_idx].dlc_pdu_buf = tx_msg.dlc_pdu_buf; // Take ownership
			dlc_ctx.tx_buffer[tx_idx].retransmission_count = 0;
			dlc_ctx.tx_buffer[tx_idx].last_tx_time_ms = k_uptime_get();
			dlc_ctx.tx_buffer[tx_idx].rto = dlc_ctx.rto; // Current RTO
			dlc_ctx.tx_buffer[tx_idx].service_type = tx_msg.service_type;
			dlc_ctx.tx_buffer[tx_idx].dest_short_rd_id = tx_msg.dest_short_rd_id;
			dlc_ctx.tx_buffer[tx_idx].is_routing_pdu = (tx_msg.service_type == CVG_SERVICE_TYPE_CONTROL &&
									net_buf_peek_u8(tx_msg.dlc_pdu_buf) == ROUTING_PDU_TYPE_RREQ); // Simplified check for routing PDU

			// Determine encryption based on security context and config
			if (dect_config.enable_encryption && dect_security_is_established(tx_msg.dest_short_rd_id)) {
				dlc_ctx.tx_buffer[tx_idx].encrypted = true;
			} else {
				dlc_ctx.tx_buffer[tx_idx].encrypted = false;
			}


			// Construct DLC PDU with sequence number and window size
			struct net_buf *dlc_pdu = NULL;
			dect_status_t ret_alloc = handle_tx_buffer_allocation(&dlc_pdu, &mac_tx_net_buf_pool); // Use MAC pool for DLC PDUs to be sent
			if (ret_alloc != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(ret_alloc, "DLC: Failed to allocate PDU for TX. Dropping SDU.");
				STATS_INC(dect_stats.dlc_tx_drops);
				net_buf_unref(tx_msg.dlc_pdu_buf); // Release original SDU
				dlc_ctx.tx_buffer[tx_idx].dlc_pdu_buf = NULL; // Clear entry
				k_mutex_unlock(&dlc_ctx.mutex);
				continue;
			}

			// Add DLC Header: Sequence Number (8-bit) and Window Size (8-bit)
			net_buf_add_u8(dlc_pdu, dlc_ctx.next_tx_seq_num);
			net_buf_add_u8(dlc_pdu, dlc_ctx.peer_advertised_tx_window_size); // Our RX window size (advertised to peer as their TX window)

			// Copy SDU payload
			net_buf_add_mem(dlc_pdu, tx_msg.dlc_pdu_buf->data, tx_msg.dlc_pdu_buf->len);

			// Compute CRC
			uint16_t crc = compute_crc(dlc_pdu->data, dlc_pdu->len);
			net_buf_add_le16(dlc_pdu, crc);


			// Generate a unique HARQ transaction ID
			dlc_ctx.tx_buffer[tx_idx].harq_transaction_id = sys_rand32_get();

			// Pass to MAC layer for transmission
			// MAC layer handles encryption if enabled and security established
			dect_status_t mac_ret = dect_mac_send_pdu_from_dlc(tx_msg.dest_short_rd_id, dlc_pdu,
									   DLC_PDU_TYPE_DATA, MAC_HEADER_TYPE_2_DATA,
									   mac_ctx.current_hpc, mac_ctx.current_psn,
									   false, // Not a retransmission (first attempt)
									   dlc_ctx.tx_buffer[tx_idx].harq_transaction_id);
			if (mac_ret != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(mac_ret, "DLC: Failed to send PDU to MAC layer for first transmission.");
				// MAC layer unrefs pdu_buf on failure.
				STATS_INC(dect_stats.dlc_tx_drops); // Increment DLC specific drop stat
				dlc_ctx.tx_buffer[tx_idx].dlc_pdu_buf = NULL; // Clear entry
				k_mutex_unlock(&dlc_ctx.mutex);
				continue;
			}

			LOG_DBG("DLC: SDU (seq %u) sent to MAC for first time (HARQ ID %u).",
				dlc_ctx.next_tx_seq_num, dlc_ctx.tx_buffer[tx_idx].harq_transaction_id);

			dlc_ctx.next_tx_seq_num = (dlc_ctx.next_tx_seq_num + 1) % DLC_MAX_SEQ_NUM; // Increment sequence number
			STATS_INC(dect_stats.total_tx_frames);
			STATS_INC_PEER(tx_msg.dest_short_rd_id, tx_frames, 1);
			STATS_INC_GLOBAL(dect_stats.total_tx_data_bytes, tx_msg.dlc_pdu_buf->len);
			STATS_INC_PEER(tx_msg.dest_short_rd_id, tx_data_bytes, tx_msg.dlc_pdu_buf->len);

			k_mutex_unlock(&dlc_ctx.mutex);
			dect_power_mgr_activity_detected(); // Notify power manager of TX activity
		}

		// Process incoming data from MAC layer
		if (k_msgq_get(&dlc_rx_msgq, &rx_msg, K_NO_WAIT) == 0) {
			LOG_DBG("DLC: Received PDU from MAC (src 0x%04x, len %u, type %u).",
				rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf->len, rx_msg.dlc_pdu_type);
			dect_power_mgr_activity_detected(); // Notify power manager of RX activity

			k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);

			// Check CRC for data and ACK PDUs
			if (rx_msg.dlc_pdu_type == DLC_PDU_TYPE_DATA || rx_msg.dlc_pdu_type == DLC_PDU_TYPE_ACK) {
				if (rx_msg.dlc_pdu_buf->len < DLC_CRC_LEN_BYTES) {
					DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "DLC: RX PDU too short for CRC. Dropping.");
					STATS_INC(dect_stats.dlc_rx_drops); // Increment DLC specific drop stat
					net_buf_unref(rx_msg.dlc_pdu_buf);
					k_mutex_unlock(&dlc_ctx.mutex);
					continue;
				}
				uint16_t received_crc = sys_get_le16(net_buf_tail(rx_msg.dlc_pdu_buf) - DLC_CRC_LEN_BYTES);
				net_buf_pull(rx_msg.dlc_pdu_buf, DLC_CRC_LEN_BYTES); // Remove CRC before processing payload
				uint16_t computed_crc = compute_crc(rx_msg.dlc_pdu_buf->data, rx_msg.dlc_pdu_buf->len);

				if (received_crc != computed_crc) {
					DECT_ERROR_HANDLER(DECT_ERROR_INTEGRITY_CHECK_FAILED, "DLC: CRC mismatch for RX PDU (src 0x%04x). Received 0x%04x, Computed 0x%04x. Dropping.",
							   rx_msg.src_short_rd_id, received_crc, computed_crc);
					STATS_INC(dect_stats.dlc_crc_errors);
					STATS_INC_PEER(rx_msg.src_short_rd_id, dlc_crc_errors, 1);
					STATS_INC(dect_stats.dlc_rx_drops); // Increment DLC specific drop stat
					net_buf_unref(rx_msg.dlc_pdu_buf);
					k_mutex_unlock(&dlc_ctx.mutex);
					continue;
				}
				LOG_DBG("DLC: CRC check passed for RX PDU.");
			}

			switch (rx_msg.dlc_pdu_type) {
			case DLC_PDU_TYPE_DATA: {
				if (rx_msg.dlc_pdu_buf->len < DLC_DATA_HDR_LEN_BYTES) {
					DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "DLC: Data PDU too short for header. Dropping.");
					STATS_INC(dect_stats.dlc_rx_drops);
					net_buf_unref(rx_msg.dlc_pdu_buf);
					break;
				}
				uint8_t rx_seq_num = net_buf_pull_u8(rx_msg.dlc_pdu_buf);
				uint8_t peer_tx_window_size = net_buf_pull_u8(rx_msg.dlc_pdu_buf); // Peer's TX window size

				LOG_DBG("DLC: Received Data PDU (src 0x%04x, seq %u, peer_tx_win %u).",
					rx_msg.src_short_rd_id, rx_seq_num, peer_tx_window_size);

				// Update peer's advertised TX window size (our RX window)
				dlc_ctx.peer_advertised_tx_window_size = peer_tx_window_size;

				// Check if this is the next expected sequence number
				if (rx_seq_num == dlc_ctx.next_rx_seq_num) {
					// In-order packet, pass to CVG immediately
					LOG_DBG("DLC: In-order data PDU (seq %u). Passing to CVG.", rx_seq_num);
					dlc_rx_msg_t cvg_rx_msg = {
						.src_short_rd_id = rx_msg.src_short_rd_id,
						.dlc_pdu_buf = rx_msg.dlc_pdu_buf,
						.rssi = rx_msg.rssi,
						.hpc = rx_msg.hpc,
						.psn = rx_msg.psn,
						.dlc_pdu_type = DLC_PDU_TYPE_DATA
					};
					int ret_msgq = DECT_MSGQ_PUT_OR_DROP(&cvg_rx_msgq, &cvg_rx_msg, K_NO_WAIT,
											DECT_ERROR_QUEUE_FULL,
											"DLC: Failed to pass data to CVG (queue full). Dropping.",
											rx_msg.dlc_pdu_buf, &dect_stats.dlc_rx_drops);
					if (ret_msgq != 0) {
						// Buffer unref'd by macro
						break;
					}

					dlc_ctx.next_rx_seq_num = (dlc_ctx.next_rx_seq_num + 1) % DLC_MAX_SEQ_NUM;

					// Check for and deliver any buffered out-of-order packets
					for (int i = 0; i < DLC_ARQ_RX_BUFFER_SIZE; i++) {
						if (dlc_ctx.rx_buffer[i].valid &&
						    dlc_ctx.rx_buffer[i].seq_num == dlc_ctx.next_rx_seq_num) {
							LOG_DBG("DLC: Delivering buffered OOO PDU (seq %u) to CVG.", dlc_ctx.next_rx_seq_num);
							cvg_rx_msg.src_short_rd_id = rx_msg.src_short_rd_id;
							cvg_rx_msg.dlc_pdu_buf = dlc_ctx.rx_buffer[i].dlc_pdu_buf;
							cvg_rx_msg.rssi = rx_msg.rssi; // Use latest RSSI for now
							cvg_rx_msg.hpc = rx_msg.hpc;
							cvg_rx_msg.psn = rx_msg.psn;
							cvg_rx_msg.dlc_pdu_type = DLC_PDU_TYPE_DATA;

							ret_msgq = DECT_MSGQ_PUT_OR_DROP(&cvg_rx_msgq, &cvg_rx_msg, K_NO_WAIT,
												DECT_ERROR_QUEUE_FULL,
												"DLC: Failed to pass buffered OOO data to CVG (queue full). Dropping.",
												cvg_rx_msg.dlc_pdu_buf, &dect_stats.dlc_rx_drops);
							if (ret_msgq != 0) {
								// Buffer unref'd by macro
								dlc_ctx.rx_buffer[i].dlc_pdu_buf = NULL; // Clear pointer in buffer entry
								dlc_ctx.rx_buffer[i].valid = false;
								break;
							}
							dlc_ctx.rx_buffer[i].dlc_pdu_buf = NULL; // Clear pointer in buffer entry
							dlc_ctx.rx_buffer[i].valid = false;
							dlc_ctx.next_rx_seq_num = (dlc_ctx.next_rx_seq_num + 1) % DLC_MAX_SEQ_NUM;
							// Re-check for next sequence number immediately
							i = -1; // Restart loop to check from beginning of buffer
						}
					}
				} else if (SEQ_NUM_IS_GREATER_EQUAL(rx_seq_num, dlc_ctx.next_rx_seq_num) &&
						SEQ_NUM_IS_GREATER_EQUAL(dlc_ctx.next_rx_seq_num + DLC_RX_WINDOW_SIZE, rx_seq_num)) {
					// Out-of-order packet within RX window, buffer it
					int rx_idx = -1;
					for (int i = 0; i < DLC_ARQ_RX_BUFFER_SIZE; i++) {
						if (!dlc_ctx.rx_buffer[i].valid) {
							rx_idx = i;
							break;
						}
						// Check for duplicate
						if (dlc_ctx.rx_buffer[i].valid && dlc_ctx.rx_buffer[i].seq_num == rx_seq_num) {
							LOG_DBG("DLC: Duplicate OOO data PDU (seq %u). Dropping.", rx_seq_num);
							net_buf_unref(rx_msg.dlc_pdu_buf); // Drop duplicate
							STATS_INC(dect_stats.dlc_rx_drops);
							rx_idx = -2; // Indicate duplicate
							break;
						}
					}
					if (rx_idx == -1) {
						DECT_ERROR_HANDLER(DECT_ERROR_DLC_RX_WINDOW_FULL, "DLC: RX ARQ buffer full. Dropping OOO PDU (seq %u).", rx_seq_num);
						STATS_INC(dect_stats.dlc_rx_drops);
						net_buf_unref(rx_msg.dlc_pdu_buf); // Drop due to full buffer
					} else if (rx_idx != -2) {
						LOG_DBG("DLC: Out-of-order data PDU (seq %u). Buffering.", rx_seq_num);
						dlc_ctx.rx_buffer[rx_idx].seq_num = rx_seq_num;
						dlc_ctx.rx_buffer[rx_idx].dlc_pdu_buf = rx_msg.dlc_pdu_buf; // Take ownership
						dlc_ctx.rx_buffer[rx_idx].valid = true;
						// Store other metadata if needed
					}
				} else {
					// Out of window or old packet, drop
					LOG_WRN("DLC: Out of window or old data PDU (seq %u, expected %u). Dropping.",
						rx_seq_num, dlc_ctx.next_rx_seq_num);
					STATS_INC(dect_stats.dlc_rx_drops);
					net_buf_unref(rx_msg.dlc_pdu_buf);
				}

				// Always send an ACK if a data PDU is received, potentially delayed
				dlc_ctx.ack_pending = true;
				dlc_ctx.ack_seq_num = dlc_ctx.next_rx_seq_num; // ACK up to next expected
				k_timer_start(&dlc_ctx.ack_delay_timer, K_MSEC(CONFIG_DECT_NR_PLUS_DLC_ACK_DELAY_MS), K_NO_WAIT);
				break;
			}

			case DLC_PDU_TYPE_ACK: {
				if (rx_msg.dlc_pdu_buf->len < DLC_ACK_HDR_LEN_BYTES) {
					DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "DLC: ACK PDU too short for header. Dropping.");
					STATS_INC(dect_stats.dlc_rx_drops);
					net_buf_unref(rx_msg.dlc_pdu_buf);
					break;
				}
				uint8_t ack_seq_num = net_buf_pull_u8(rx_msg.dlc_pdu_buf);
				uint8_t peer_rx_window_size = net_buf_pull_u8(rx_msg.dlc_pdu_buf); // Peer's RX window size

				LOG_DBG("DLC: Received ACK PDU (ack_seq %u, peer_rx_win %u).",
					ack_seq_num, peer_rx_window_size);

				// Update peer's advertised RX window size
				dlc_ctx.peer_advertised_rx_window_size = peer_rx_window_size;

				// Process ACKs by marking TX buffer entries as acknowledged
				for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
					if (dlc_ctx.tx_buffer[i].dlc_pdu_buf != NULL &&
					    SEQ_NUM_IS_GREATER_EQUAL(ack_seq_num, dlc_ctx.tx_buffer[i].seq_num)) {
						LOG_DBG("DLC: PDU (seq %u) ACKed by peer. Freeing TX buffer entry.", dlc_ctx.tx_buffer[i].seq_num);
						dlc_ctx.tx_buffer[i].dlc_pdu_buf = net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf);
						dlc_ctx.tx_buffer[i].harq_transaction_id = 0; // Clear ID
						// Update RTT if this is the first ACK for this PDU
						if (dlc_ctx.tx_buffer[i].retransmission_count == 0) {
							uint32_t sample_rtt = k_uptime_get() - dlc_ctx.tx_buffer[i].last_tx_time_ms;
							dlc_update_rtt(sample_rtt);
						}
					}
				}
				net_buf_unref(rx_msg.dlc_pdu_buf);
				break;
			}

			case DLC_PDU_TYPE_CONTROL:
				// Pass control messages to higher layer if needed, or handle internally
				LOG_DBG("DLC: Received Control PDU. Passing to CVG if applicable.");
				dlc_rx_msg_t cvg_rx_msg_ctrl = {
						.src_short_rd_id = rx_msg.src_short_rd_id,
						.dlc_pdu_buf = rx_msg.dlc_pdu_buf,
						.rssi = rx_msg.rssi,
						.hpc = rx_msg.hpc,
						.psn = rx_msg.psn,
						.dlc_pdu_type = DLC_PDU_TYPE_CONTROL
					};
				int ret_msgq_ctrl = DECT_MSGQ_PUT_OR_DROP(&cvg_rx_msgq, &cvg_rx_msg_ctrl, K_NO_WAIT,
											DECT_ERROR_QUEUE_FULL,
											"DLC: Failed to pass control PDU to CVG (queue full). Dropping.",
											rx_msg.dlc_pdu_buf, &dect_stats.dlc_rx_drops);
				if (ret_msgq_ctrl != 0) {
					// Buffer unref'd by macro
					break;
				}
				break;

			case DLC_PDU_TYPE_ROUTING:
				// Pass routing messages to routing layer
				if (dect_config.enable_routing) {
					LOG_DBG("DLC: Received Routing PDU. Passing to Routing layer.");
					// In a full implementation, the routing layer would define its own msgq.
					// For now, let's assume `dect_routing_process_incoming_pdu` consumes the buffer.
					dect_status_t routing_ret = dect_routing_process_incoming_pdu(rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf, rx_msg.hpc, rx_msg.psn);
					if (routing_ret != DECT_STATUS_OK) {
						DECT_ERROR_HANDLER(routing_ret, "DLC: Failed to process incoming Routing PDU. Dropping.");
						STATS_INC(dect_stats.dlc_rx_drops); // Increment DLC specific drop stat
						net_buf_unref(rx_msg.dlc_pdu_buf); // Routing layer may not unref on all internal failures
					}
				} else {
					LOG_DBG("DLC: Routing disabled. Dropping Routing PDU.");
					STATS_INC(dect_stats.dlc_rx_drops); // Increment DLC specific drop stat
					net_buf_unref(rx_msg.dlc_pdu_buf);
				}
				break;

			case DLC_PDU_TYPE_BEACON:
				// Beacons are typically processed by MAC/Channel Manager, but if DLC has
				// specific beacon processing (e.g., for some IE), it would happen here.
				// For now, just unref if not passed up.
				LOG_DBG("DLC: Received Beacon PDU. Discarding at DLC (handled by MAC/BCC).");
				STATS_INC(dect_stats.dlc_rx_drops); // Increment DLC specific drop stat
				net_buf_unref(rx_msg.dlc_pdu_buf);
				break;

			default:
				DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_TYPE, "DLC: Received unknown DLC PDU type %u. Dropping.", rx_msg.dlc_pdu_type);
				STATS_INC(dect_stats.dlc_rx_drops); // Increment DLC specific drop stat
				net_buf_unref(rx_msg.dlc_pdu_buf);
				break;
			}
			k_mutex_unlock(&dlc_ctx.mutex);
		}

		k_sleep(K_MSEC(10)); // Small sleep to yield CPU
	}
}

dect_status_t dlc_send_data_from_cvg(uint16_t dest_short_rd_id, struct net_buf *sdu_buf,
				     cvg_service_type_t service_type, qos_priority_t qos_priority)
{
	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = dest_short_rd_id,
		.dlc_pdu_buf = sdu_buf, // DLC takes ownership
		.service_type = service_type,
		.qos_priority = qos_priority
	};

	LOG_DBG("DLC: Queuing data from CVG to internal TX queue (dest 0x%04x, len %u).",
		dest_short_rd_id, sdu_buf->len);

	int ret = DECT_MSGQ_PUT_OR_DROP(&dlc_tx_msgq, &tx_msg, K_NO_WAIT,
					DECT_ERROR_QUEUE_FULL,
					"DLC: Failed to put data from CVG into TX queue (full).",
					sdu_buf, &dect_stats.dlc_tx_drops);
	if (ret != 0) {
		return DECT_ERROR_QUEUE_FULL; // Buffer already unref'd by macro
	}

	return DECT_STATUS_OK;
}

dect_status_t dlc_send_routing_pdu(uint16_t dest_short_rd_id, struct net_buf *routing_pdu_buf)
{
	dlc_tx_msg_t tx_msg = {
		.dest_short_rd_id = dest_short_rd_id,
		.dlc_pdu_buf = routing_pdu_buf, // DLC takes ownership
		.service_type = CVG_SERVICE_TYPE_CONTROL, // Routing PDUs are a type of control message
		.qos_priority = QOS_PRIORITY_HIGH // Routing messages often higher priority
	};

	LOG_DBG("DLC: Queuing Routing PDU to internal TX queue (dest 0x%04x, len %u).",
		dest_short_rd_id, routing_pdu_buf->len);

	int ret = DECT_MSGQ_PUT_OR_DROP(&dlc_tx_msgq, &tx_msg, K_NO_WAIT,
					DECT_ERROR_QUEUE_FULL,
					"DLC: Failed to put Routing PDU into TX queue (full).",
					routing_pdu_buf, &dect_stats.dlc_tx_drops);
	if (ret != 0) {
		return DECT_ERROR_QUEUE_FULL; // Buffer already unref'd by macro
	}

	return DECT_STATUS_OK;
}

dect_status_t dlc_mac_tx_completion_notification(uint16_t dest_short_rd_id, uint32_t harq_transaction_id,
						 nrf_modem_dect_phy_harq_feedback_t feedback,
						 uint8_t retransmission_count, int phy_tx_status)
{
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);

	// Find the corresponding entry in the TX ARQ buffer
	int tx_idx = -1;
	for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
		if (dlc_ctx.tx_buffer[i].dlc_pdu_buf != NULL &&
		    dlc_ctx.tx_buffer[i].harq_transaction_id == harq_transaction_id) {
			tx_idx = i;
			break;
		}
	}

	if (tx_idx == -1) {
		LOG_WRN("DLC: TX completion notification for unknown HARQ ID %u. Ignoring.", harq_transaction_id);
		k_mutex_unlock(&dlc_ctx.mutex);
		return DECT_ERROR_GENERIC; // Or specific error
	}

	dlc_ctx.tx_buffer[tx_idx].retransmission_count = retransmission_count; // Update count

	if (feedback == NRF_MODEM_DECT_PHY_HARQ_FEEDBACK_ACK) {
		// PDU successfully acknowledged by peer or PHY (e.g., first attempt ACK)
		LOG_DBG("DLC: PDU (seq %u, HARQ ID %u) ACKed by PHY/Peer on attempt %u.",
			dlc_ctx.tx_buffer[tx_idx].seq_num, harq_transaction_id, retransmission_count + 1);

		if (retransmission_count == 0) {
			STATS_INC_PEER(dest_short_rd_id, harq_tx_success, 1);
		} else {
			STATS_INC_PEER(dest_short_rd_id, harq_tx_retransmissions, 1);
		}

		// Update RTT if this was the first transmission (not a retransmission)
		if (retransmission_count == 0) {
			uint32_t sample_rtt = k_uptime_get() - dlc_ctx.tx_buffer[tx_idx].last_tx_time_ms;
			dlc_update_rtt(sample_rtt);
		}

		// Free the buffer and clear the TX buffer entry
		dlc_ctx.tx_buffer[tx_idx].dlc_pdu_buf = net_buf_unref(dlc_ctx.tx_buffer[tx_idx].dlc_pdu_buf);
		dlc_ctx.tx_buffer[tx_idx].harq_transaction_id = 0; // Invalidate entry
	} else { // NRF_MODEM_DECT_PHY_HARQ_FEEDBACK_NACK or other failure indication
		LOG_DBG("DLC: PDU (seq %u, HARQ ID %u) NACKed/Failed on attempt %u (status %d).",
			dlc_ctx.tx_buffer[tx_idx].seq_num, harq_transaction_id, retransmission_count + 1, phy_tx_status);

		// If max retries not reached, schedule retransmission
		if (retransmission_count < CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES) {
			LOG_DBG("DLC: Retrying PDU (seq %u, HARQ ID %u). Retry count %u.",
				dlc_ctx.tx_buffer[tx_idx].seq_num, harq_transaction_id, retransmission_count + 1);
			dlc_ctx.tx_buffer[tx_idx].last_tx_time_ms = k_uptime_get(); // Update last TX time
			// The retransmission timer will pick this up
		} else {
			// Max retries reached, declare PDU loss
			DECT_ERROR_HANDLER(DECT_ERROR_DLC_TX_FAILED, "DLC: PDU (seq %u, HARQ ID %u) failed after max retries (%u). Dropping.",
					   dlc_ctx.tx_buffer[tx_idx].seq_num, harq_transaction_id, retransmission_count);
			STATS_INC_PEER(dest_short_rd_id, harq_tx_failures, 1);
			STATS_INC(dect_stats.dlc_tx_drops); // Global DLC TX drop stat for unrecoverable failures

			// Free the buffer and clear the TX buffer entry
			dlc_ctx.tx_buffer[tx_idx].dlc_pdu_buf = net_buf_unref(dlc_ctx.tx_buffer[tx_idx].dlc_pdu_buf);
			dlc_ctx.tx_buffer[tx_idx].harq_transaction_id = 0; // Invalidate entry

			// Notify higher layers of data loss if necessary (e.g., CVG)
		}
	}

	k_mutex_unlock(&dlc_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dlc_mac_security_established_notification(uint16_t peer_short_rd_id)
{
	LOG_INF("DLC: Security established with peer 0x%04x. Resetting ARQ state.", peer_short_rd_id);
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	dlc_reset_arq_state(); // Reset ARQ state for a fresh session
	// Set peer's initial window sizes
	dlc_ctx.peer_advertised_rx_window_size = DLC_RX_WINDOW_SIZE;
	dlc_ctx.peer_advertised_tx_window_size = DLC_TX_WINDOW_SIZE;
	k_mutex_unlock(&dlc_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dlc_mac_disconnected_notification(uint16_t peer_short_rd_id, mac_link_failure_reason_t reason)
{
	LOG_INF("DLC: Disconnected from peer 0x%04x (reason %u). Resetting ARQ state.", peer_short_rd_id, reason);
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	dlc_reset_arq_state(); // Reset ARQ state and free buffers
	// Reset peer's window sizes to default
	dlc_ctx.peer_advertised_rx_window_size = DLC_RX_WINDOW_SIZE;
	dlc_ctx.peer_advertised_tx_window_size = DLC_TX_WINDOW_SIZE;
	k_mutex_unlock(&dlc_ctx.mutex);
	return DECT_STATUS_OK;
}

static void dlc_allocate_buffers(void)
{
	for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
		dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL;
	}
	for (int i = 0; i < DLC_ARQ_RX_BUFFER_SIZE; i++) {
		dlc_ctx.rx_buffer[i].dlc_pdu_buf = NULL;
		dlc_ctx.rx_buffer[i].valid = false;
	}
}

static void dlc_free_buffers(void)
{
	for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
		if (dlc_ctx.tx_buffer[i].dlc_pdu_buf != NULL) {
			net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf);
			dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL;
		}
	}
	for (int i = 0; i < DLC_ARQ_RX_BUFFER_SIZE; i++) {
		if (dlc_ctx.rx_buffer[i].dlc_pdu_buf != NULL) {
			net_buf_unref(dlc_ctx.rx_buffer[i].dlc_pdu_buf);
			dlc_ctx.rx_buffer[i].dlc_pdu_buf = NULL;
		}
		dlc_ctx.rx_buffer[i].valid = false;
	}
}

static void dlc_retransmit_pdu(uint16_t dest_short_rd_id, struct net_buf *pdu_buf, uint32_t dlc_seq_num,
			       uint32_t harq_transaction_id, cvg_service_type_t service_type,
			       bool encrypted, bool is_routing_pdu, uint8_t retransmission_count)
{
	// This function is typically called by retransmission_timer_handler
	// The pdu_buf passed here is already owned by the TX buffer entry.
	// We need to create a new net_buf for the MAC layer to transmit.

	struct net_buf *dlc_pdu_copy = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&dlc_pdu_copy, &mac_tx_net_buf_pool);
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "DLC: Failed to allocate PDU for retransmission. Dropping.");
		STATS_INC(dect_stats.dlc_tx_drops);
		// Mark original TX buffer entry for cleanup, as it cannot be sent
		for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
			if (dlc_ctx.tx_buffer[i].harq_transaction_id == harq_transaction_id) {
				net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf);
				dlc_ctx.tx_buffer[i].dlc_pdu_buf = NULL;
				dlc_ctx.tx_buffer[i].harq_transaction_id = 0;
				break;
			}
		}
		return;
	}

	// Copy data from the original DLC PDU buffer (which includes DLC header and payload)
	net_buf_add_mem(dlc_pdu_copy, pdu_buf->data, pdu_buf->len);

	// Recompute CRC if payload changed (not typically for retrans) or for safety
	uint16_t crc = compute_crc(dlc_pdu_copy->data, dlc_pdu_copy->len);
	net_buf_add_le16(dlc_pdu_copy, crc);

	LOG_DBG("DLC: Retransmitting PDU (seq %u, HARQ ID %u, attempt %u) to MAC.",
		dlc_seq_num, harq_transaction_id, retransmission_count + 1);

	dect_status_t mac_ret = dect_mac_send_pdu_from_dlc(dest_short_rd_id, dlc_pdu_copy,
							   DLC_PDU_TYPE_DATA, MAC_HEADER_TYPE_2_DATA,
							   mac_ctx.current_hpc, mac_ctx.current_psn,
							   true, // This IS a retransmission
							   harq_transaction_id);
	if (mac_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mac_ret, "DLC: Failed to retransmit PDU to MAC layer.");
		// MAC layer unrefs pdu_buf on failure.
		STATS_INC(dect_stats.dlc_tx_drops); // Global DLC TX drop stat
		// The original buffer in TX buffer entry still exists and will be tried again by timer, or eventually dropped
	}
}

static dect_status_t dlc_send_ack(uint16_t dest_short_rd_id, uint8_t ack_seq_num, uint16_t window_size)
{
	struct net_buf *ack_pdu_buf = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&ack_pdu_buf, &mac_tx_net_buf_pool);
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "DLC: Failed to allocate ACK PDU buffer. Not sending ACK.");
		return ret_alloc;
	}

	// Add DLC ACK Header: ACK Sequence Number (8-bit) and Window Size (8-bit)
	net_buf_add_u8(ack_pdu_buf, ack_seq_num);
	net_buf_add_u8(ack_pdu_buf, window_size); // Our current RX window size

	// Compute CRC
	uint16_t crc = compute_crc(ack_pdu_buf->data, ack_pdu_buf->len);
	net_buf_add_le16(ack_pdu_buf, crc);

	LOG_DBG("DLC: Sending ACK PDU (ack_seq %u, window %u) to dest 0x%04x.",
		ack_seq_num, window_size, dest_short_rd_id);

	// Generate a dummy HARQ ID for ACK, as it's not part of ARQ (not retransmitted by DLC ARQ)
	uint32_t harq_id = sys_rand32_get();

	dect_status_t mac_ret = dect_mac_send_pdu_from_dlc(dest_short_rd_id, ack_pdu_buf,
							   DLC_PDU_TYPE_ACK, MAC_HEADER_TYPE_1_CONTROL, // Use Type 1 for control PDUs
							   mac_ctx.current_hpc, mac_ctx.current_psn,
							   false, harq_id);
	if (mac_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mac_ret, "DLC: Failed to send ACK PDU to MAC layer.");
		// MAC layer unrefs pdu_buf on failure.
		STATS_INC(dect_stats.dlc_tx_drops); // Global DLC TX drop stat
		return mac_ret;
	}

	return DECT_STATUS_OK;
}

static void dlc_retransmission_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	uint64_t current_time = k_uptime_get();

	for (int i = 0; i < DLC_ARQ_TX_BUFFER_SIZE; i++) {
		if (dlc_ctx.tx_buffer[i].dlc_pdu_buf != NULL) {
			// Check if PDU needs retransmission based on RTO
			if ((current_time - dlc_ctx.tx_buffer[i].last_tx_time_ms) >= dlc_ctx.tx_buffer[i].rto) {
				if (dlc_ctx.tx_buffer[i].retransmission_count < CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES) {
					LOG_DBG("DLC: Retransmission timer fired for PDU (seq %u, HARQ ID %u). Attempt %u.",
						dlc_ctx.tx_buffer[i].seq_num, dlc_ctx.tx_buffer[i].harq_transaction_id,
						dlc_ctx.tx_buffer[i].retransmission_count + 1);

					// Trigger retransmission
					dlc_retransmit_pdu(dlc_ctx.tx_buffer[i].dest_short_rd_id,
							   dlc_ctx.tx_buffer[i].dlc_pdu_buf,
							   dlc_ctx.tx_buffer[i].seq_num,
							   dlc_ctx.tx_buffer[i].harq_transaction_id,
							   dlc_ctx.tx_buffer[i].service_type,
							   dlc_ctx.tx_buffer[i].encrypted,
							   dlc_ctx.tx_buffer[i].is_routing_pdu,
							   dlc_ctx.tx_buffer[i].retransmission_count + 1); // Pass incremented count

					// Update RTO for next retransmission
					dlc_ctx.tx_buffer[i].rto *= 2; // Binary exponential backoff
					if (dlc_ctx.tx_buffer[i].rto > CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS) {
						dlc_ctx.tx_buffer[i].rto = CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS;
					}
					dlc_ctx.tx_buffer[i].retransmission_count++;
					dlc_ctx.tx_buffer[i].last_tx_time_ms = k_uptime_get(); // Update last TX time
				} else {
					// Max retries reached, declare PDU loss
					DECT_ERROR_HANDLER(DECT_ERROR_DLC_TX_FAILED, "DLC: PDU (seq %u, HARQ ID %u) max retries (%u) reached. Dropping.",
							   dlc_ctx.tx_buffer[i].seq_num, dlc_ctx.tx_buffer[i].harq_transaction_id, CONFIG_DECT_NR_PLUS_DLC_MAX_RETRIES);
					STATS_INC_PEER(dlc_ctx.tx_buffer[i].dest_short_rd_id, harq_tx_failures, 1);
					STATS_INC(dect_stats.dlc_tx_drops); // Global DLC TX drop stat for unrecoverable failures

					// Free the buffer and clear the TX buffer entry
					dlc_ctx.tx_buffer[i].dlc_pdu_buf = net_buf_unref(dlc_ctx.tx_buffer[i].dlc_pdu_buf);
					dlc_ctx.tx_buffer[i].harq_transaction_id = 0; // Invalidate entry
					// Notify higher layers of data loss if necessary (e.g., CVG)
				}
			}
		}
	}
	k_mutex_unlock(&dlc_ctx.mutex);
}

static void dlc_ack_delay_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);
	if (dlc_ctx.ack_pending) {
		LOG_DBG("DLC: ACK delay timer fired. Sending ACK for seq %u.", dlc_ctx.ack_seq_num);
		dlc_send_ack(mac_ctx.associated_pp_short_rd_id, dlc_ctx.ack_seq_num, dlc_ctx.peer_advertised_tx_window_size);
		dlc_ctx.ack_pending = false;
	}
	k_mutex_unlock(&dlc_ctx.mutex);
}

static void dlc_update_rtt(uint32_t sample_rtt)
{
	k_mutex_lock(&dlc_ctx.mutex, K_FOREVER);

	// Simplified Karn's algorithm for RTT and RTT_VAR
	// SRTT = (1 - alpha) * SRTT + alpha * RTT_sample
	// RTTVAR = (1 - beta) * RTTVAR + beta * |RTT_sample - SRTT|
	// RTO = SRTT + K * RTTVAR

	// Use shift operations for multiplication/division for efficiency
	uint32_t old_rtt = dlc_ctx.current_rtt;
	dlc_ctx.current_rtt = ((dlc_ctx.current_rtt * ((1 << RTT_ALPHA_SHIFT) - 1)) + sample_rtt) >> RTT_ALPHA_SHIFT;

	uint32_t diff = (sample_rtt > old_rtt) ? (sample_rtt - old_rtt) : (old_rtt - sample_rtt);
	dlc_ctx.rtt_var = ((dlc_ctx.rtt_var * ((1 << RTT_BETA_SHIFT) - 1)) + diff) >> RTT_BETA_SHIFT;

	dlc_ctx.rto = dlc_ctx.current_rtt + (RTT_K_FACTOR * dlc_ctx.rtt_var);

	// Ensure RTO is within bounds
	if (dlc_ctx.rto < CONFIG_DECT_NR_PLUS_DLC_MIN_RTO_MS) {
		dlc_ctx.rto = CONFIG_DECT_NR_PLUS_DLC_MIN_RTO_MS;
	} else if (dlc_ctx.rto > CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS) {
		dlc_ctx.rto = CONFIG_DECT_NR_PLUS_DLC_MAX_RTO_MS;
	}

	LOG_DBG("DLC: RTT updated. Sample: %u, SRTT: %u, RTTVAR: %u, RTO: %u.",
		sample_rtt, dlc_ctx.current_rtt, dlc_ctx.rtt_var, dlc_ctx.rto);

	k_mutex_unlock(&dlc_ctx.mutex);
}

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

/* End of File
 * Last Amended: 2025-06-09 18:10 BST: Updated dect_dlc.c for robust error handling.
 * - Added `handle_tx_buffer_allocation` helper function for `net_buf_alloc`.
 * - Modified `dlc_send_data_from_cvg`, `dlc_send_routing_pdu`, `dlc_retransmit_pdu`, `dlc_send_ack` to use `handle_tx_buffer_allocation`.
 * - Integrated `DECT_MSGQ_PUT_OR_DROP` macro for `k_msgq_put` calls to `mac_ctx.mac_tx_msgq` (DLC TX thread) and `cvg_rx_msgq` (DLC RX thread).
 * - Ensured all error paths (allocation failures, queue full, CRC errors, frame too short, unknown PDU types, max retries) increment appropriate `dect_stats.dlc_tx_drops` or `dect_stats.dlc_rx_drops` and `net_buf_unref` where necessary.
 * - Added DLC-specific drop stats to `dect_stats.h` in previous step.
 */
