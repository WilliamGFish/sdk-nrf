/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <device.h>
#include <net/net_if.h> // For net_if_carrier_on/off
#include <net/net_core.h> // For net_if_ipv6_addr_add
#include <net/net_l2.h> // For NET_L2_GET_CTX
#include <random/rand32.h> // For sys_rand32_get for Short RD ID assignment

#include <dect_nr_plus/dect_config.h>
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_mac.h> /* Own header */
#include <dect_nr_plus/dect_dlc.h> /* For DLC layer interaction */
#include <dect_nr_plus/dect_cvg.h> // For dect_net_if access
#include <dect_nr_plus/dect_phy_nrf9161.h> /* For PHY layer interaction */
#include <dect_nr_plus/dect_crypto.h> /* For encryption/decryption */
#include <dect_nr_plus/dect_power_mgr.h> /* For power management awareness */
#include <dect_nr_plus/dect_stats.h> /* For updating statistics */
#include <dect_nr_plus/dect_security.h> /* For security context access (session key) */

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_mac, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global MAC context instance definition */
dect_mac_context_t mac_ctx = {
	.device_role = MAC_ROLE_FP, // Default role, overwritten by config
	.assoc_state = MAC_ASSOC_STATE_IDLE,
	.sync_state = MAC_SYNC_STATE_UNSYNCHRONIZED,
	.local_short_rd_id = 0, // Assigned during init or from config
	.current_hpc = 0,
	.current_psn = 0,
	.net_if_ptr = NULL,
	.associated_fp_short_rd_id = 0,
	.associated_pp_short_rd_id = 0, // Only for FP
	.current_handover_phase = HANDOVER_PHASE_IDLE,
	.target_fp_for_handover = 0,
	.handover_retries_count = 0,
	.num_fp_candidates = 0,
	.last_scan_attempt_ms = 0,
};

/* Mutex to protect mac_ctx */
K_MUTEX_DEFINE(mac_ctx_mutex);

/* Net buffer pool for MAC transmit PDUs */
NET_BUF_POOL_DEFINE(mac_tx_net_buf_pool, CONFIG_DECT_NR_PLUS_MAC_TX_BUF_COUNT,
					CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE, 0, NULL);

/* Net buffer pool for MAC receive PDUs from PHY */
NET_BUF_POOL_DEFINE(mac_rx_net_buf_pool, CONFIG_DECT_NR_PLUS_MAC_RX_BUF_COUNT,
					CONFIG_DECT_NR_PLUS_MAC_RX_BUF_SIZE, 0, NULL);

/* Message queue for MAC transmit requests from DLC/Security */
K_MSGQ_DEFINE(mac_tx_msgq, sizeof(mac_tx_msg_t),
	      CONFIG_DECT_NR_PLUS_MAC_TX_QUEUE_SIZE, 4);

/* Message queue for MAC receive indications from PHY */
K_MSGQ_DEFINE(mac_rx_msgq, sizeof(nrf9161_dect_rx_packet_t),
	      CONFIG_DECT_NR_PLUS_MAC_RX_QUEUE_SIZE, 4);

/* FIFO for tracking outstanding TX PDUs to ensure correct HARQ feedback mapping */
K_FIFO_DEFINE(mac_outstanding_tx_fifo);

/* Forward declarations for internal functions */
static void mac_association_timer_handler(struct k_timer *timer_id);
static void mac_sync_timer_handler(struct k_timer *timer_id);
static dect_status_t mac_process_mac_control_pdu(uint16_t src_short_rd_id, struct net_buf *mac_pdu_buf);
static int find_multicast_member(uint16_t short_rd_id);
static dect_status_t mac_add_multicast_member(uint16_t short_rd_id);
static dect_status_t mac_remove_multicast_member(uint16_t short_rd_id);
static bool mac_is_multicast_member(uint16_t short_rd_id);
static void mac_clear_outstanding_tx_fifo(void);

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
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "MAC: Failed to allocate net_buf from pool %s. No memory.", pool->name->name);
		STATS_INC(dect_stats.tx_drops_no_mem); // Increment global stat for TX drops due to no memory
		return DECT_ERROR_NO_MEM;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_mac_init(const struct device *phy_dev)
{
	k_mutex_init(&mac_ctx.mutex);

	// Initialize PHY layer callbacks
	nrf9161_dect_phy_init(phy_dev, dect_mac_phy_event_handler, dect_mac_phy_rx_packet_handler);

	// Set initial configuration from dect_config
	k_mutex_lock(&mac_ctx.mutex, K_FOREVER);
	memcpy(mac_ctx.mac_address, dect_config.mac_address, LONG_RD_ID_LEN_BYTES);
	mac_ctx.device_role = dect_config.device_role;

	// Assign Short RD ID (either from config or random)
	if (dect_config.short_rd_id == 0) {
		mac_ctx.local_short_rd_id = (uint16_t)sys_rand32_get(); // Assign random if 0 in config
		LOG_WRN("MAC: Short RD ID was 0 in config, assigned random 0x%04x.", mac_ctx.local_short_rd_id);
	} else {
		mac_ctx.local_short_rd_id = dect_config.short_rd_id;
	}
	k_mutex_unlock(&mac_ctx.mutex);

	k_timer_init(&mac_ctx.assoc_timer, mac_association_timer_handler, NULL);
	k_timer_init(&mac_ctx.sync_timer, mac_sync_timer_handler, NULL);
	k_timer_init(&mac_ctx.handover_timer, NULL, NULL); // Handover timer initialized, handler set during handover

	LOG_INF("MAC: Module initialized. Role: %s, Local Short RD ID: 0x%04x.",
		mac_ctx.device_role == MAC_ROLE_FP ? "Fixed Part" : "Portable Part",
		mac_ctx.local_short_rd_id);

	return DECT_STATUS_OK;
}

void dect_mac_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("MAC: Thread started.");

	mac_tx_msg_t tx_msg;
	nrf9161_dect_rx_packet_t rx_packet;

	while (true) {
		// Process outgoing MAC PDUs from DLC/Security layers
		if (k_msgq_get(&mac_tx_msgq, &tx_msg, K_NO_WAIT) == 0) {
			LOG_DBG("MAC: Received TX request from higher layer (dest 0x%04x, type %u, len %u).",
				tx_msg.dest_short_rd_id, tx_msg.mac_pdu_type, tx_msg.mac_pdu_buf->len);

			dect_power_mgr_activity_detected(); // Notify power manager of TX activity

			// Check if encryption is enabled and security is established for this peer
			bool encrypt_pdu = false;
			if (dect_config.enable_encryption && tx_msg.mac_pdu_type == MAC_HEADER_TYPE_2_DATA &&
			    dect_security_is_established(tx_msg.dest_short_rd_id)) {
				encrypt_pdu = true;
			} else if (tx_msg.mac_pdu_type == MAC_HEADER_TYPE_1_CONTROL &&
				   (tx_msg.control_type == MAC_CONTROL_TYPE_SECURITY_CHALLENGE ||
				    tx_msg.control_type == MAC_CONTROL_TYPE_SECURITY_RESPONSE)) {
				// Security PDUs are handled by the crypto layer, they are not encrypted by MAC as data
				// but rather contain cryptographic material directly.
				encrypt_pdu = false; // MAC does not encrypt security PDUs, crypto layer handles it.
			}


			struct net_buf *phy_payload = NULL;
			dect_status_t ret_alloc = handle_tx_buffer_allocation(&phy_payload, &mac_tx_net_buf_pool);
			if (ret_alloc != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(ret_alloc, "MAC: Failed to allocate PHY payload buffer for TX. Dropping PDU.");
				STATS_INC(dect_stats.mac_tx_drops); // Increment MAC specific drop stat
				net_buf_unref(tx_msg.mac_pdu_buf); // Unref original PDU buffer
				continue; // Or return, depending on context
			}

			// Prepend MAC Header
			if (tx_msg.mac_pdu_type == MAC_HEADER_TYPE_1_CONTROL) {
				if (tx_msg.dest_short_rd_id == SHORT_RD_ID_BROADCAST) {
					// Broadcast control PDU (e.g., Beacon)
					net_buf_add_u8(phy_payload, MAC_HEADER_TYPE_1_CONTROL);
					// For beacons, MAC_CONTROL_TYPE_BEACON is the first byte of payload
					// Already added in BCC, so just copy the rest of the PDU.
				} else {
					// Unicast control PDU
					net_buf_add_u8(phy_payload, MAC_HEADER_TYPE_1_CONTROL | (tx_msg.control_type << 4)); // Type and Control Type
					// No specific destination in header for Type 1, implicitly handled by PHY TX to short_rd_id
				}
			} else if (tx_msg.mac_pdu_type == MAC_HEADER_TYPE_2_DATA) {
				// MAC Data PDU (Type 2)
				net_buf_add_u8(phy_payload, MAC_HEADER_TYPE_2_DATA);
				net_buf_add_le16(phy_payload, tx_msg.dest_short_rd_id); // Destination Short RD ID
				net_buf_add_u8(phy_payload, 0); // Reserved byte, or for control flags
			} else {
				DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PHY_HDR_TYPE, "MAC: Unknown MAC PDU type %u. Dropping.", tx_msg.mac_pdu_type);
				STATS_INC(dect_stats.mac_tx_drops); // Increment MAC specific drop stat
				net_buf_unref(tx_msg.mac_pdu_buf);
				net_buf_unref(phy_payload); // Free allocated buffer
				continue;
			}

			// Copy original MAC PDU payload (from DLC/Security)
			net_buf_add_mem(phy_payload, tx_msg.mac_pdu_buf->data, tx_msg.mac_pdu_buf->len);

			net_buf_unref(tx_msg.mac_pdu_buf); // MAC layer has consumed original PDU buffer


			// Encrypt if required
			if (encrypt_pdu) {
				uint8_t *session_key = NULL;
				size_t session_key_len = 0;
				dect_status_t key_ret = dect_security_get_session_key(tx_msg.dest_short_rd_id, &session_key, &session_key_len);

				if (key_ret != DECT_STATUS_OK || session_key == NULL) {
					DECT_ERROR_HANDLER(DECT_ERROR_SECURITY_NOT_READY, "MAC: No session key for peer 0x%04x. Cannot encrypt data. Dropping.", tx_msg.dest_short_rd_id);
					STATS_INC(dect_stats.mac_tx_drops);
					net_buf_unref(phy_payload);
					continue;
				}

				size_t encrypted_len = phy_payload->len + MAC_MIC_LEN; // Original len + MIC
				if (encrypted_len > CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE) { // Check against max total size
					DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "MAC: Encrypted PDU too large. Dropping.");
					STATS_INC(dect_stats.mac_tx_drops);
					net_buf_unref(phy_payload);
					continue;
				}

				// Encryption needs to happen in-place or into a new buffer,
				// and will add the MIC.
				// For this example, assume dect_crypto_encrypt can expand buffer.
				// The buffer in phy_payload might need to be resized if MIC
				// is appended by the encryption function.
				// Alternatively, pre-allocate space for MIC at allocation.
				// Current implementation of dect_crypto_encrypt appends MIC, so pre-allocation needed.
				// This would ideally be handled by net_buf_alloc_len with needed_len.
				// Or, reallocate. For now, assuming phy_payload has enough trailing space.

				// Copy data to a temp buffer for encryption if in-place modification is tricky,
				// or ensure phy_payload has enough headroom.
				uint8_t temp_data[CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE];
				memcpy(temp_data, phy_payload->data, phy_payload->len);
				size_t original_len = phy_payload->len;
				net_buf_remove(phy_payload, original_len); // Clear current data in net_buf

				dect_status_t enc_ret = dect_crypto_encrypt(session_key, session_key_len,
								            temp_data, original_len,
								            tx_msg.hpc, tx_msg.psn,
								            net_buf_tail(phy_payload), &encrypted_len);
				if (enc_ret != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(enc_ret, "MAC: Encryption failed for PDU (dest 0x%04x). Dropping.", tx_msg.dest_short_rd_id);
					STATS_INC(dect_stats.mac_tx_drops);
					net_buf_unref(phy_payload);
					continue;
				}
				net_buf_add(phy_payload, encrypted_len); // Update net_buf length
				LOG_DBG("MAC: PDU encrypted, new length %u (incl. MIC).", encrypted_len);
			}

			// Store information about the outstanding TX for HARQ feedback
			mac_outstanding_tx_entry_t *out_tx_entry = k_malloc(sizeof(mac_outstanding_tx_entry_t));
			if (!out_tx_entry) {
				DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "MAC: Failed to allocate outstanding TX entry. Dropping PDU.");
				STATS_INC(dect_stats.mac_tx_drops);
				net_buf_unref(phy_payload);
				continue;
			}
			out_tx_entry->harq_transaction_id = tx_msg.harq_transaction_id;
			out_tx_entry->dlc_seq_num = tx_msg.dlc_seq_num; // Needed by DLC for ARQ
			out_tx_entry->dest_short_rd_id = tx_msg.dest_short_rd_id;
			out_tx_entry->retransmission_count = tx_msg.retransmission_count;
			k_fifo_put(&mac_outstanding_tx_fifo, out_tx_entry);

			// Transmit PDU via PHY layer
			dect_status_t phy_ret = nrf9161_dect_phy_transmit_receive(
							tx_msg.dest_short_rd_id, // Target for unicast, or SHORT_RD_ID_BROADCAST
							phy_payload,
							tx_msg.tx_slot_duration_us, // Provided by DLC/BCC
							mac_ctx.current_hpc, // HPC for TX synchronization
							mac_ctx.current_psn, // PSN for TX synchronization
							tx_msg.mac_pdu_type // Used to determine PHY header type
							);
			if (phy_ret != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(phy_ret, "MAC: Failed to send PDU to PHY layer (dest 0x%04x).", tx_msg.dest_short_rd_id);
				STATS_INC(dect_stats.mac_tx_drops); // Increment MAC specific drop stat
				net_buf_unref(phy_payload); // PHY might not unref on all failures
				// Remove from outstanding FIFO if PHY TX failed immediately
				k_free(k_fifo_get(&mac_outstanding_tx_fifo, K_NO_WAIT));
				continue;
			}
		}

		// Process incoming RX packets from PHY layer
		if (k_msgq_get(&mac_rx_msgq, &rx_packet, K_NO_WAIT) == 0) {
			LOG_DBG("MAC: Received RX packet from PHY (src 0x%04x, len %u, RSSI %d, CRC OK: %s).",
				rx_packet.src_short_rd_id, rx_packet.data_buf->len,
				rx_packet.rssi, rx_packet.crc_ok ? "true" : "false");

			dect_power_mgr_activity_detected(); // Notify power manager of RX activity

			if (!rx_packet.crc_ok) {
				DECT_ERROR_HANDLER(DECT_ERROR_PHY_CRC_FAILED, "MAC: RX packet CRC failed (src 0x%04x). Dropping.", rx_packet.src_short_rd_id);
				STATS_INC(dect_stats.mac_crc_errors);
				net_buf_unref(rx_packet.data_buf);
				STATS_INC(dect_stats.mac_rx_drops); // Increment MAC specific drop stat
				continue;
			}

			// Extract MAC Header Type
			if (rx_packet.data_buf->len < 1) {
				DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "MAC: RX PDU too short for header. Dropping.");
				net_buf_unref(rx_packet.data_buf);
				STATS_INC(dect_stats.mac_rx_drops);
				continue;
			}
			uint8_t mac_hdr_type_byte = net_buf_pull_u8(rx_packet.data_buf);
			mac_header_type_t mac_hdr_type = (mac_header_type_t)(mac_hdr_type_byte & 0x0F); // Lower 4 bits

			// Decrypt if necessary
			bool encrypted = false; // Need a way to tell if it was encrypted. PHY doesn't know.
							// This information should ideally be part of the PDU header or implicitly known.
							// For now, assume if data PDU and security established, it's encrypted.
			if (dect_config.enable_encryption && mac_hdr_type == MAC_HEADER_TYPE_2_DATA &&
			    dect_security_is_established(rx_packet.src_short_rd_id)) {
				encrypted = true;
			}

			if (encrypted) {
				uint8_t *session_key = NULL;
				size_t session_key_len = 0;
				dect_status_t key_ret = dect_security_get_session_key(rx_packet.src_short_rd_id, &session_key, &session_key_len);

				if (key_ret != DECT_STATUS_OK || session_key == NULL) {
					DECT_ERROR_HANDLER(DECT_ERROR_SECURITY_NOT_READY, "MAC: No session key for peer 0x%04x. Cannot decrypt data. Dropping.", rx_packet.src_short_rd_id);
					STATS_INC(dect_stats.mac_rx_drops);
					net_buf_unref(rx_packet.data_buf);
					continue;
				}

				// Decryption needs to happen in-place. MIC is at the end of data.
				size_t decrypted_len = rx_packet.data_buf->len; // Will be actual payload len after MIC check
				uint8_t temp_data[CONFIG_DECT_NR_PLUS_MAC_RX_BUF_SIZE]; // Temporary buffer for decryption
				if (decrypted_len > sizeof(temp_data)) {
					DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "MAC: Encrypted RX PDU too large for temp buffer. Dropping.");
					STATS_INC(dect_stats.mac_rx_drops);
					net_buf_unref(rx_packet.data_buf);
					continue;
				}
				memcpy(temp_data, rx_packet.data_buf->data, decrypted_len);

				dect_status_t dec_ret = dect_crypto_decrypt(session_key, session_key_len,
								            temp_data, decrypted_len, // Pass total encrypted data including MIC
								            rx_packet.hpc, rx_packet.psn,
								            net_buf_tail(rx_packet.data_buf), &decrypted_len); // Write decrypted to net_buf, update length

				if (dec_ret != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(dec_ret, "MAC: Decryption or MIC verification failed for RX PDU (src 0x%04x). Dropping.", rx_packet.src_short_rd_id);
					STATS_INC(dect_stats.mac_mic_failures);
					STATS_INC(dect_stats.mac_rx_drops);
					net_buf_unref(rx_packet.data_buf);
					continue;
				}
				// Adjust net_buf to reflect decrypted length (MIC removed)
				net_buf_remove(rx_packet.data_buf, rx_packet.data_buf->len - decrypted_len);
				LOG_DBG("MAC: PDU decrypted, new length %u (MIC removed).", decrypted_len);
			}

			// Process PDU based on type
			switch (mac_hdr_type) {
			case MAC_HEADER_TYPE_1_CONTROL: {
				if (rx_packet.data_buf->len < 1) { // Control type byte
					DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "MAC: Control PDU too short for type. Dropping.");
					net_buf_unref(rx_packet.data_buf);
					STATS_INC(dect_stats.mac_rx_drops);
					break;
				}
				uint8_t control_type = net_buf_pull_u8(rx_packet.data_buf);
				LOG_DBG("MAC: Received Control PDU (type 0x%02x) from 0x%04x.", control_type, rx_packet.src_short_rd_id);
				dect_status_t status = mac_process_mac_control_pdu(rx_packet.src_short_rd_id, rx_packet.data_buf); // PDU buffer is unref'd inside this function on success
				if (status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(status, "MAC: Failed to process control PDU (type 0x%02x).", control_type);
					// Buffer unref'd by mac_process_mac_control_pdu on specific failures, or here if not.
					if (status != DECT_ERROR_INVALID_PARAM) { // If not invalid param, it was likely consumed.
						net_buf_unref(rx_packet.data_buf); // Ensure unref if not consumed
					}
					STATS_INC(dect_stats.mac_rx_drops);
				}
				break;
			}
			case MAC_HEADER_TYPE_2_DATA: {
				if (rx_packet.data_buf->len < SHORT_RD_ID_LEN_BYTES + 1) { // Dest Short RD ID + Reserved
					DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "MAC: Data PDU too short for header. Dropping.");
					net_buf_unref(rx_packet.data_buf);
					STATS_INC(dect_stats.mac_rx_drops);
					break;
				}
				uint16_t dest_short_rd_id = net_buf_pull_le16(rx_packet.data_buf); // Destination Short RD ID
				net_buf_pull_u8(rx_packet.data_buf); // Reserved byte

				LOG_DBG("MAC: Received Data PDU (dest 0x%04x) from 0x%04x. Passing to DLC.",
					dest_short_rd_id, rx_packet.src_short_rd_id);

				// Only process if for us or broadcast
				if (dest_short_rd_id == mac_ctx.local_short_rd_id ||
				    dest_short_rd_id == SHORT_RD_ID_BROADCAST ||
					mac_is_multicast_member(dest_short_rd_id)) { // Check if multicast group member

					dlc_rx_msg_t dlc_msg = {
						.src_short_rd_id = rx_packet.src_short_rd_id,
						.dlc_pdu_buf = rx_packet.data_buf, // DLC takes ownership
						.rssi = rx_packet.rssi,
						.hpc = rx_packet.hpc,
						.psn = rx_packet.psn,
						.dlc_pdu_type = DLC_PDU_TYPE_DATA
					};
					int ret_msgq = DECT_MSGQ_PUT_OR_DROP(&dlc_rx_msgq, &dlc_msg, K_NO_WAIT,
											DECT_ERROR_QUEUE_FULL,
											"MAC: Failed to pass Data PDU to DLC (queue full). Dropping.",
											rx_packet.data_buf, &dect_stats.mac_rx_drops);
					if (ret_msgq != 0) {
						// Buffer unref'd by macro
						break;
					}
				} else {
					LOG_DBG("MAC: Data PDU (dest 0x%04x) not for us or multicast. Dropping.", dest_short_rd_id);
					net_buf_unref(rx_packet.data_buf);
					STATS_INC(dect_stats.mac_rx_drops);
				}
				break;
			}
			default:
				DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_TYPE, "MAC: Received unknown MAC PDU type 0x%02x. Dropping.", mac_hdr_type);
				net_buf_unref(rx_packet.data_buf);
				STATS_INC(dect_stats.mac_rx_drops);
				break;
			}
		}

		k_sleep(K_MSEC(10)); // Small sleep to yield CPU
	}
}

dect_status_t dect_mac_send_pdu_from_dlc(uint16_t dest_short_rd_id, struct net_buf *mac_pdu_buf,
					 dlc_pdu_type_t dlc_pdu_type, mac_header_type_t mac_hdr_type,
					 uint32_t hpc, uint16_t psn, bool is_retransmission, uint32_t harq_transaction_id)
{
	mac_tx_msg_t tx_msg = {
		.dest_short_rd_id = dest_short_rd_id,
		.mac_pdu_buf = mac_pdu_buf, // MAC takes ownership
		.dlc_pdu_type = dlc_pdu_type,
		.mac_pdu_type = mac_hdr_type,
		.hpc = hpc,
		.psn = psn,
		.is_retransmission = is_retransmission,
		.harq_transaction_id = harq_transaction_id,
		.tx_slot_duration_us = nrf9161_dect_phy_get_tx_slot_duration(), // Get from PHY
	};

	LOG_DBG("MAC: Queuing TX PDU from DLC (dest 0x%04x, DLC type %u, MAC type %u, len %u) to internal queue.",
		dest_short_rd_id, dlc_pdu_type, mac_hdr_type, mac_pdu_buf->len);

	int ret = DECT_MSGQ_PUT_OR_DROP(&mac_tx_msgq, &tx_msg, K_NO_WAIT,
					DECT_ERROR_QUEUE_FULL,
					"MAC: Failed to put TX PDU from DLC into queue (full).",
					mac_pdu_buf, &dect_stats.mac_tx_drops);
	if (ret != 0) {
		return DECT_ERROR_QUEUE_FULL; // Buffer already unref'd by macro
	}

	return DECT_STATUS_OK;
}

// PHY event handler, called by PHY layer when an event (e.g., TX complete) occurs
void dect_mac_phy_event_handler(nrf_modem_dect_phy_event_id_t event_id, const nrf_modem_dect_phy_event_data_t *event_data)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER); // Protect MAC context on callback

	switch (event_id) {
	case NRF_MODEM_DECT_PHY_EVT_COMPLETED: {
		const struct nrf_modem_dect_phy_completed_evt *completed_evt = &event_data->completed;
		LOG_DBG("MAC: PHY TX completed (handle %u, status %d).",
			completed_evt->handle, completed_evt->status);

		mac_outstanding_tx_entry_t *out_tx_entry = NULL;
		// Find the corresponding outstanding TX entry by HARQ handle (which is the HARQ ID)
		k_fifo_get_for_item(&mac_outstanding_tx_fifo, (void **)&out_tx_entry);

		if (out_tx_entry == NULL || out_tx_entry->harq_transaction_id != completed_evt->handle) {
			LOG_WRN("MAC: Received PHY TX completion for unknown/mismatched HARQ ID %u. Expected %u. Ignoring.",
				completed_evt->handle, out_tx_entry ? out_tx_entry->harq_transaction_id : 0);
			k_free(out_tx_entry); // Free if it was an unexpected item
			break;
		}

		// Notify DLC about TX completion
		dect_mac_tx_completion_notification(out_tx_entry->dest_short_rd_id,
							out_tx_entry->harq_transaction_id,
							completed_evt->feedback,
							out_tx_entry->retransmission_count, // Use DLC's retransmission count
							completed_evt->status);
		k_free(out_tx_entry); // Free the outstanding TX entry

		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_RADIO_MODE_SET:
		LOG_DBG("MAC: PHY Radio mode set successfully.");
		break;
	case NRF_MODEM_DECT_PHY_EVT_TIME:
		// Time updated by PHY, usually handled by PHY module itself.
		break;
	case NRF_MODEM_DECT_PHY_EVT_LBT:
		LOG_DBG("MAC: LBT event (status %u).", event_data->lbt.status);
		break;
	case NRF_MODEM_DECT_PHY_EVT_ERROR:
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_GENERIC, "MAC: PHY error event (%d).", event_data->error.status);
		// Potentially trigger MAC link failure if critical PHY error
		break;
	default:
		LOG_WRN("MAC: Unhandled PHY event ID %u.", event_id);
		break;
	}
	k_mutex_unlock(&mac_ctx_mutex);
}

// PHY RX packet handler, called by PHY layer when a packet is received
void dect_mac_phy_rx_packet_handler(const nrf9161_dect_rx_packet_t *rx_packet)
{
	LOG_DBG("MAC: Received raw RX packet from PHY (src 0x%04x, len %u, RSSI %d, CRC OK: %s).",
		rx_packet->src_short_rd_id, rx_packet->data_buf->len,
		rx_packet->rssi, rx_packet->crc_ok ? "true" : "false");

	// MAC takes ownership of the net_buf from PHY.
	// We need to make a copy for the message queue because rx_packet itself is temporary.
	struct net_buf *rx_packet_buf_copy = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&rx_packet_buf_copy, &mac_rx_net_buf_pool); // Use RX pool
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "MAC: Failed to allocate copy for RX packet. Dropping PHY RX packet.");
		// Original rx_packet->data_buf will be unref'd by PHY.
		// No need to unref rx_packet->data_buf here.
		STATS_INC(dect_stats.rx_drops_no_mem);
		return;
	}
	net_buf_add_mem(rx_packet_buf_copy, rx_packet->data_buf->data, rx_packet->data_buf->len);


	nrf9161_dect_rx_packet_t rx_packet_copy = *rx_packet; // Copy struct
	rx_packet_copy.data_buf = rx_packet_buf_copy; // Update with the new buffer

	// Put into MAC RX message queue for processing by MAC thread
	int ret_msgq = DECT_MSGQ_PUT_OR_DROP(&mac_rx_msgq, &rx_packet_copy, K_NO_WAIT,
					     DECT_ERROR_QUEUE_FULL,
					     "MAC: RX message queue full. Dropping RX packet from PHY.",
					     rx_packet_buf_copy, &dect_stats.mac_rx_drops); // Pass the copy buffer to unref
	if (ret_msgq != 0) {
		// Buffer unref'd by macro
		return;
	}
}


static dect_status_t mac_process_mac_control_pdu(uint16_t src_short_rd_id, struct net_buf *mac_pdu_buf)
{
	if (mac_pdu_buf->len < 1) { // Control Type is first byte of payload
		DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "MAC Control PDU too short for Control Type. Dropping.");
		STATS_INC(dect_stats.mac_rx_drops);
		net_buf_unref(mac_pdu_buf);
		return DECT_ERROR_FRAME_TOO_SHORT;
	}
	uint8_t control_type = net_buf_pull_u8(mac_pdu_buf);

	LOG_DBG("MAC: Processing Control PDU Type 0x%02x from 0x%04x.", control_type, src_short_rd_id);

	switch (control_type) {
	case MAC_CONTROL_TYPE_BEACON: {
		// Beacons are processed by Channel Manager and BCC. MAC forwards if needed.
		// For now, simple logging and passing relevant info.
		// Beacon format: Control Type (0x01) + [IEs] + CRC
		LOG_DBG("MAC: Received Beacon from 0x%04x (len %u).", src_short_rd_id, mac_pdu_buf->len);
		STATS_INC(dect_stats.bcc_beacons_rx);
		net_buf_unref(mac_pdu_buf); // Consumed
		// In a real system, you might parse IEs and update channel quality or FP lists
		break;
	}
	case MAC_CONTROL_TYPE_ASSOC_REQ: {
		// Only FP processes association requests
		if (mac_ctx.device_role == MAC_ROLE_FP) {
			LOG_INF("MAC FP: Received Association Request from PP 0x%04x.", src_short_rd_id);
			// Process association request (e.g., check capabilities, accept/reject)
			// For simplicity, always accept for now and send Assoc Response
			k_mutex_lock(&mac_ctx.mutex, K_FOREVER);
			mac_ctx.associated_pp_short_rd_id = src_short_rd_id;
			mac_ctx.assoc_state = MAC_ASSOC_STATE_ASSOCIATED;
			net_if_carrier_on(mac_ctx.net_if_ptr); // Bring up network carrier
			LOG_INF("MAC FP: Associated with PP 0x%04x. Carrier ON.", src_short_rd_id);
			k_mutex_unlock(&mac_ctx.mutex);

			// Send Association Response
			struct net_buf *resp_pdu = NULL;
			dect_status_t ret_alloc = handle_tx_buffer_allocation(&resp_pdu, &mac_tx_net_buf_pool);
			if (ret_alloc != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(ret_alloc, "MAC: Failed to allocate Assoc Resp PDU.");
				STATS_INC(dect_stats.mac_tx_drops);
				net_buf_unref(mac_pdu_buf); // Original Req PDU
				return ret_alloc;
			}
			net_buf_add_u8(resp_pdu, MAC_CONTROL_TYPE_ASSOC_RESP);
			// Add any response parameters (e.g., FP capabilities, assigned short RD ID if dynamic)
			// For now, no specific payload beyond type.
			uint16_t crc = compute_crc(resp_pdu->data, resp_pdu->len);
			net_buf_add_le16(resp_pdu, crc);

			dect_status_t tx_status = dect_mac_send_pdu_from_dlc(src_short_rd_id, resp_pdu,
									     DLC_PDU_TYPE_CONTROL, MAC_HEADER_TYPE_1_CONTROL,
									     mac_ctx.current_hpc, mac_ctx.current_psn,
									     false, sys_rand32_get());
			if (tx_status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(tx_status, "MAC FP: Failed to send Association Response.");
				STATS_INC(dect_stats.mac_tx_drops);
			}
		} else {
			LOG_WRN("MAC PP: Received Assoc Request (unexpected). Dropping.");
			STATS_INC(dect_stats.mac_rx_drops);
		}
		net_buf_unref(mac_pdu_buf); // Consumed
		break;
	}
	case MAC_CONTROL_TYPE_ASSOC_RESP: {
		// Only PP processes association responses
		if (mac_ctx.device_role == MAC_ROLE_PP) {
			LOG_INF("MAC PP: Received Association Response from FP 0x%04x.", src_short_rd_id);
			k_mutex_lock(&mac_ctx.mutex, K_FOREVER);
			if (mac_ctx.assoc_state == MAC_ASSOC_STATE_ASSOCIATING &&
			    mac_ctx.associated_fp_short_rd_id == src_short_rd_id) {
				mac_ctx.assoc_state = MAC_ASSOC_STATE_ASSOCIATED;
				net_if_carrier_on(mac_ctx.net_if_ptr); // Bring up network carrier
				k_timer_stop(&mac_ctx.assoc_timer); // Stop retransmission timer
				LOG_INF("MAC PP: Associated with FP 0x%04x. Carrier ON.", src_short_rd_id);

				// Initiate security handshake after association
				if (dect_config.enable_encryption) {
					dect_security_initiate_handshake(src_short_rd_id);
				}
			} else {
				LOG_WRN("MAC PP: Received unexpected Assoc Response (state %u, assoc_fp 0x%04x).",
					mac_ctx.assoc_state, mac_ctx.associated_fp_short_rd_id);
			}
			k_mutex_unlock(&mac_ctx.mutex);
		} else {
			LOG_WRN("MAC FP: Received Assoc Response (unexpected). Dropping.");
			STATS_INC(dect_stats.mac_rx_drops);
		}
		net_buf_unref(mac_pdu_buf); // Consumed
		break;
	}
	case MAC_CONTROL_TYPE_SECURITY_CHALLENGE: {
		LOG_DBG("MAC: Received Security Challenge PDU from 0x%04x.", src_short_rd_id);
		// Pass to Security layer for processing
		dect_status_t sec_status = dect_security_process_challenge(src_short_rd_id, rx_packet.hpc, rx_packet.psn, mac_pdu_buf);
		if (sec_status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(sec_status, "MAC: Failed to process Security Challenge.");
			// Buffer unref'd by security layer on failure
			STATS_INC(dect_stats.mac_rx_drops);
		}
		// mac_pdu_buf consumed by dect_security_process_challenge
		break;
	}
	case MAC_CONTROL_TYPE_SECURITY_RESPONSE: {
		LOG_DBG("MAC: Received Security Response PDU from 0x%04x.", src_short_rd_id);
		// Extract MIC from end of PDU
		if (mac_pdu_buf->len < SECURITY_NONCE_LEN + MAC_MIC_LEN) {
			DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "MAC: Security Response PDU too short. Dropping.");
			net_buf_unref(mac_pdu_buf);
			STATS_INC(dect_stats.mac_rx_drops);
			break;
		}
		uint8_t *response_nonce = net_buf_pull(mac_pdu_buf, SECURITY_NONCE_LEN);
		uint8_t *mic = net_buf_pull(mac_pdu_buf, MAC_MIC_LEN);

		dect_status_t sec_status = dect_security_process_response(src_short_rd_id, response_nonce, rx_packet.hpc, rx_packet.psn, mic);
		if (sec_status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(sec_status, "MAC: Failed to process Security Response.");
			// Buffer already unref'd by security layer on failure
			STATS_INC(dect_stats.mac_rx_drops);
		}
		net_buf_unref(mac_pdu_buf); // Consumed
		break;
	}
	case MAC_CONTROL_TYPE_DISCONNECT: {
		LOG_INF("MAC: Received Disconnect PDU from 0x%04x.", src_short_rd_id);
		// Handle disconnection (e.g., move to IDLE state, notify DLC)
		k_mutex_lock(&mac_ctx.mutex, K_FOREVER);
		if (mac_ctx.device_role == MAC_ROLE_FP && mac_ctx.associated_pp_short_rd_id == src_short_rd_id) {
			mac_ctx.associated_pp_short_rd_id = 0;
		} else if (mac_ctx.device_role == MAC_ROLE_PP && mac_ctx.associated_fp_short_rd_id == src_short_rd_id) {
			mac_ctx.associated_fp_short_rd_id = 0;
		}
		mac_ctx.assoc_state = MAC_ASSOC_STATE_IDLE;
		mac_ctx.sync_state = MAC_SYNC_STATE_UNSYNCHRONIZED;
		net_if_carrier_off(mac_ctx.net_if_ptr); // Bring down network carrier
		LOG_INF("MAC: Link with 0x%04x down. Carrier OFF.", src_short_rd_id);
		k_mutex_unlock(&mac_ctx.mutex);
		dlc_mac_disconnected_notification(src_short_rd_id, MAC_LINK_FAILURE_REASON_DISASSOCIATED);
		net_buf_unref(mac_pdu_buf); // Consumed
		break;
	}
	// Add other control PDU types (Handover, etc.)
	case MAC_CONTROL_TYPE_HANDOVER_REQ:
	case MAC_CONTROL_TYPE_HANDOVER_RESP:
		LOG_WRN("MAC: Handover PDU type 0x%02x received. Not fully implemented. Dropping.", control_type);
		STATS_INC(dect_stats.mac_rx_drops);
		net_buf_unref(mac_pdu_buf); // Drop unimplemented
		break;
	default:
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_TYPE, "MAC: Unknown Control PDU type 0x%02x. Dropping.", control_type);
		STATS_INC(dect_stats.mac_rx_drops);
		net_buf_unref(mac_pdu_buf);
		return DECT_ERROR_INVALID_PDU_TYPE; // Return error
	}
	return DECT_STATUS_OK;
}

// MAC callback for DLC when security is established.
// This allows MAC to update its state or notify peers.
dect_status_t mac_dlc_security_established_notification(uint16_t peer_short_rd_id)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	// No specific MAC state change needed here usually, as MAC relies on security layer
	// for session key management. This is mainly for logging/statistics.
	LOG_INF("MAC: Security established with peer 0x%04x.", peer_short_rd_id);
	// Could trigger a MAC control PDU to indicate secure link ready if needed.
	k_mutex_unlock(&mac_ctx_mutex);
	return DECT_STATUS_OK;
}

void dect_mac_tx_completion_notification(uint16_t dest_short_rd_id, uint32_t harq_transaction_id,
					 nrf_modem_dect_phy_harq_feedback_t feedback,
					 uint8_t retransmission_count, int phy_tx_status)
{
	// This function is called by PHY event handler, already holding mac_ctx_mutex.
	// No need to lock here.
	dlc_mac_tx_completion_notification(dest_short_rd_id, harq_transaction_id,
					   feedback, retransmission_count, phy_tx_status);
}

void dlc_mac_disconnected_notification(uint16_t peer_short_rd_id, mac_link_failure_reason_t reason)
{
	// This function is called by DLC, could be from its own mutex.
	// Needs to acquire mac_ctx_mutex.
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);

	LOG_INF("MAC: Link disconnected notification from DLC for peer 0x%04x (reason %u).", peer_short_rd_id, reason);

	if (mac_ctx.device_role == MAC_ROLE_FP && mac_ctx.associated_pp_short_rd_id == peer_short_rd_id) {
		mac_ctx.associated_pp_short_rd_id = 0;
		mac_ctx.assoc_state = MAC_ASSOC_STATE_IDLE;
		net_if_carrier_off(mac_ctx.net_if_ptr);
		LOG_DBG("MAC FP: Cleared association for 0x%04x.", peer_short_rd_id);
	} else if (mac_ctx.device_role == MAC_ROLE_PP && mac_ctx.associated_fp_short_rd_id == peer_short_rd_id) {
		mac_ctx.associated_fp_short_rd_id = 0;
		mac_ctx.assoc_state = MAC_ASSOC_STATE_IDLE;
		mac_ctx.sync_state = MAC_SYNC_STATE_UNSYNCHRONIZED;
		net_if_carrier_off(mac_ctx.net_if_ptr);
		// Restart scanning if PP
		k_timer_start(&mac_ctx.assoc_timer, K_MSEC(CONFIG_DECT_NR_PLUS_MAC_ASSOC_RETRY_TIMEOUT_MS), K_NO_WAIT);
		LOG_DBG("MAC PP: Cleared association for 0x%04x. Restarting association timer.", peer_short_rd_id);
	}

	// Also clear any outstanding TX entries for this peer in the FIFO
	mac_clear_outstanding_tx_fifo();

	k_mutex_unlock(&mac_ctx_mutex);
}

static void mac_association_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&mac_ctx.mutex, K_FOREVER);

	if (mac_ctx.device_role == MAC_ROLE_PP && mac_ctx.assoc_state != MAC_ASSOC_STATE_ASSOCIATED) {
		LOG_INF("MAC PP: Association timer fired. Attempting association...");

		// Scan for FPs and attempt association
		// In a real scenario, this would involve scanning and selecting an FP.
		// For now, if we have an initial channel, try to associate.
		if (dect_config.initial_channel != 0xFF) { // Assuming 0xFF means no initial channel
			LOG_DBG("MAC PP: Attempting association on channel %u.", dect_config.initial_channel);
			// Simulate sending an association request
			struct net_buf *assoc_req_pdu = NULL;
			dect_status_t ret_alloc = handle_tx_buffer_allocation(&assoc_req_pdu, &mac_tx_net_buf_pool);
			if (ret_alloc != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(ret_alloc, "MAC: Failed to allocate Assoc Req PDU.");
				STATS_INC(dect_stats.mac_tx_drops);
				k_mutex_unlock(&mac_ctx.mutex);
				return;
			}
			net_buf_add_u8(assoc_req_pdu, MAC_CONTROL_TYPE_ASSOC_REQ);
			// Add any request parameters (e.g., PP capabilities)
			uint16_t crc = compute_crc(assoc_req_pdu->data, assoc_req_pdu->len);
			net_buf_add_le16(assoc_req_pdu, crc);


			mac_ctx.assoc_state = MAC_ASSOC_STATE_ASSOCIATING; // Set state to associating
			mac_ctx.associated_fp_short_rd_id = SHORT_RD_ID_BROADCAST; // Initially unknown FP

			dect_status_t tx_status = dect_mac_send_pdu_from_dlc(SHORT_RD_ID_BROADCAST, assoc_req_pdu,
										     DLC_PDU_TYPE_CONTROL, MAC_HEADER_TYPE_1_CONTROL,
										     mac_ctx.current_hpc, mac_ctx.current_psn,
										     false, sys_rand32_get()); // Dummy HARQ ID for control
			if (tx_status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(tx_status, "MAC PP: Failed to send Association Request.");
				STATS_INC(dect_stats.mac_tx_drops);
				// MAC_ASSOC_STATE_ASSOCIATING might need to be reset if failed here.
				mac_ctx.assoc_state = MAC_ASSOC_STATE_IDLE;
			} else {
				LOG_DBG("MAC PP: Association Request sent.");
				// If sent successfully, restart timer for response
				k_timer_start(&mac_ctx.assoc_timer, K_MSEC(CONFIG_DECT_NR_PLUS_MAC_ASSOC_TIMEOUT_MS), K_NO_WAIT);
			}
		} else {
			LOG_WRN("MAC PP: No initial channel configured for association.");
		}
	}
	k_mutex_unlock(&mac_ctx.mutex);
}

static void mac_sync_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&mac_ctx.mutex, K_FOREVER);
	if (mac_ctx.device_role == MAC_ROLE_PP && mac_ctx.sync_state == MAC_SYNC_STATE_SYNCHRONIZED) {
		LOG_DBG("MAC PP: Sync timer fired. Checking synchronization status...");
		// In a real implementation, this would involve checking recent beacon reception
		// or PHY sync status. For now, simulate potential sync loss.
		// if (k_uptime_get() - mac_ctx.last_sync_time_ms > MAX_SYNC_LOSS_INTERVAL) {
		// mac_ctx.sync_state = MAC_SYNC_STATE_LOST;
		// dect_mac_link_failure_notification(mac_ctx.associated_fp_short_rd_id, MAC_LINK_FAILURE_REASON_SYNC_LOSS);
		// }
	}
	k_mutex_unlock(&mac_ctx.mutex);
}

static int find_multicast_member(uint16_t short_rd_id)
{
	// Assumes mac_ctx_mutex is already locked
	for (int i = 0; i < mac_ctx.num_multicast_members; i++) {
		if (mac_ctx.multicast_members[i] == short_rd_id) {
			return i;
		}
	}
	return -1;
}

static dect_status_t mac_add_multicast_member(uint16_t short_rd_id)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	if (mac_ctx.num_multicast_members >= CONFIG_DECT_NR_PLUS_MAC_MAX_MULTICAST_MEMBERS) {
		LOG_WRN("MAC: Max multicast members reached. Cannot add 0x%04x.", short_rd_id);
		k_mutex_unlock(&mac_ctx_mutex);
		return DECT_ERROR_NO_RESOURCES;
	}
	if (find_multicast_member(short_rd_id) != -1) {
		LOG_DBG("MAC: Multicast member 0x%04x already exists.", short_rd_id);
		k_mutex_unlock(&mac_ctx_mutex);
		return DECT_STATUS_OK;
	}
	mac_ctx.multicast_members[mac_ctx.num_multicast_members++] = short_rd_id;
	LOG_INF("MAC: Added multicast member 0x%04x. Total: %u.", short_rd_id, mac_ctx.num_multicast_members);
	k_mutex_unlock(&mac_ctx_mutex);
	return DECT_STATUS_OK;
}

static dect_status_t mac_remove_multicast_member(uint16_t short_rd_id)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	int idx = find_multicast_member(short_rd_id);
	if (idx != -1) {
		for (int i = idx; i < mac_ctx.num_multicast_members - 1; i++) {
			mac_ctx.multicast_members[i] = mac_ctx.multicast_members[i + 1];
		}
		mac_ctx.num_multicast_members--;
		LOG_INF("MAC: Removed multicast member 0x%04x. Total: %u.", short_rd_id, mac_ctx.num_multicast_members);
		k_mutex_unlock(&mac_ctx_mutex);
		return DECT_STATUS_OK;
	}
	LOG_WRN("MAC: Multicast member 0x%04x not found.", short_rd_id);
	k_mutex_unlock(&mac_ctx_mutex);
	return DECT_ERROR_NOT_FOUND;
}

static bool mac_is_multicast_member(uint16_t short_rd_id)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	bool is_member = false;
	for (int i = 0; i < mac_ctx.num_multicast_members; i++) {
		if (mac_ctx.multicast_members[i] == short_rd_id) {
			is_member = true;
			break;
		}
	}
	k_mutex_unlock(&mac_ctx_mutex);
	return is_member;
}

static void mac_clear_outstanding_tx_fifo(void)
{
	mac_outstanding_tx_entry_t *entry;
	while ((entry = k_fifo_get(&mac_outstanding_tx_fifo, K_NO_WAIT)) != NULL) {
		LOG_DBG("MAC: Clearing outstanding TX FIFO. Freeing HARQ ID %u.", entry->harq_transaction_id);
		k_free(entry);
	}
}

/* End of File
 * Last Amended: 2025-06-09 18:30 BST: Updated dect_mac.c for robust error handling.
 * - Added `mac_tx_drops` and `mac_rx_drops` stats to `dect_stats.h` in previous step.
 * - Added `handle_tx_buffer_allocation` helper function.
 * - Modified `dect_mac_thread` (TX path) to use `handle_tx_buffer_allocation` and `DECT_MSGQ_PUT_OR_DROP` for `mac_tx_msgq`.
 * - Modified `dect_mac_phy_rx_packet_handler` (RX path) to use `handle_tx_buffer_allocation` for internal buffer copy and `DECT_MSGQ_PUT_OR_DROP` for `mac_rx_msgq`.
 * - Enhanced error handling for encryption/decryption failures, PDU too large, unknown PDU types, and CRC failures with stat increments and buffer unreferencing.
 * - Updated `dect_mac_send_pdu_from_dlc` to use `DECT_MSGQ_PUT_OR_DROP`.
 * - Added `mac_clear_outstanding_tx_fifo` to clean up on link disconnect.
 */
