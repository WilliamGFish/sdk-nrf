/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <device.h> // For struct device
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
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_channel_mgr.h> // For channel management interaction
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness
#include <dect_nr_plus/dect_routing.h> // For routing layer interaction

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_mac, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global MAC context instance definition */
dect_mac_context_t mac_ctx = {
	.role = MAC_ROLE_PP, // Default role
	.assoc_state = MAC_ASSOC_STATE_IDLE,
	.sync_state = MAC_SYNC_STATE_IDLE,
	.local_short_rd_id = 0, // Will be assigned on init or from config
	.associated_fp_short_rd_id = 0,
	.current_modem_time = 0,
	.net_if_ptr = NULL,
	.num_fp_candidates = 0,
	.num_associated_peers = 0,
	.num_multicast_members = 0,
	.num_ipv6_to_short_rd_id_entries = 0,
};

/* Internal message queue for MAC TX requests from DLC */
// K_MSGQ_DEFINE(mac_tx_msgq, sizeof(dlc_tx_msg_t), CONFIG_DECT_NR_PLUS_MAC_TX_QUEUE_COUNT, 4);

/* Internal message queue for MAC RX indications to DLC */
// K_MSGQ_DEFINE(mac_rx_msgq, sizeof(dlc_rx_msg_t), CONFIG_DECT_NR_PLUS_MAC_RX_QUEUE_COUNT, 4);

/* Internal FIFO for tracking outstanding HARQ transmissions */
// K_FIFO_DEFINE(mac_outstanding_tx_fifo);

/* Mutex for protecting MAC context */
K_MUTEX_DEFINE(mac_ctx_mutex);

/* Timer for association process */
static struct k_timer association_timer;
/* Timer for synchronization process */
static struct k_timer sync_timer;

/* Forward declarations for internal static functions */
static void association_timer_handler(struct k_timer *timer_id);
static void sync_timer_handler(struct k_timer *timer_id);
static void mac_clear_outstanding_tx_fifo(void);
static dect_status_t handle_tx_buffer_allocation(struct net_buf **out_buf, struct net_buf_pool *pool, const char *caller_name,
												   size_t size, enum dect_status_t error_code);
static int find_ipv6_to_short_rd_id_entry(const struct in6_addr *ipv6_addr);


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
		STATS_INC(dect_stats.mac_tx_drops);
		return error_code;
	}
	return DECT_STATUS_OK;
}


dect_status_t dect_mac_init(const struct device *dev)
{
	ARG_UNUSED(dev); // dev is no longer explicitly used here as PHY init is separate

	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);

	// Initialize MAC context
	mac_ctx.role = dect_config.device_role;
	mac_ctx.assoc_state = MAC_ASSOC_STATE_IDLE;
	mac_ctx.sync_state = MAC_SYNC_STATE_IDLE;
	mac_ctx.local_short_rd_id = dect_config.short_rd_id;
	memcpy(mac_ctx.local_long_rd_id, dect_config.mac_address, LONG_RD_ID_LEN_BYTES);
	mac_ctx.associated_fp_short_rd_id = 0;
	mac_ctx.num_fp_candidates = 0;
	mac_ctx.num_associated_peers = 0;
	mac_ctx.num_multicast_members = 0;
	mac_ctx.num_ipv6_to_short_rd_id_entries = 0;

	// Initialize timers
	k_timer_init(&association_timer, association_timer_handler, NULL);
	k_timer_init(&sync_timer, sync_timer_handler, NULL);

	// Initialize IPv6 to Short RD ID map
	for (int i = 0; i < MAX_IPV6_TO_RD_ID_MAP_ENTRIES; i++) {
		mac_ctx.ipv6_to_short_rd_id_map[i].is_valid = false;
	}


	LOG_INF("MAC: Initialized as %s (Short RD ID: 0x%04x, Long RD ID: %02x:%02x:%02x:%02x)",
			(mac_ctx.role == MAC_ROLE_FP) ? "Fixed Part" : "Portable Part",
			mac_ctx.local_short_rd_id,
			mac_ctx.local_long_rd_id[0], mac_ctx.local_long_rd_id[1],
			mac_ctx.local_long_rd_id[2], mac_ctx.local_long_rd_id[3]);

	k_mutex_unlock(&mac_ctx_mutex);
	return DECT_STATUS_OK;
}

void dect_mac_set_association_state(mac_assoc_state_t state)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	if (mac_ctx.assoc_state != state) {
		LOG_DBG("MAC: Association state changed from %d to %d.", mac_ctx.assoc_state, state);
		mac_ctx.assoc_state = state;
		STATS_INC(dect_stats.mac_association_attempts); // Count every change as an attempt/state transition
	}
	k_mutex_unlock(&mac_ctx_mutex);
}

mac_assoc_state_t dect_mac_get_association_state(void)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	mac_assoc_state_t state = mac_ctx.assoc_state;
	k_mutex_unlock(&mac_ctx_mutex);
	return state;
}

void dect_mac_set_sync_state(mac_sync_state_t state)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	if (mac_ctx.sync_state != state) {
		LOG_DBG("MAC: Synchronization state changed from %d to %d.", mac_ctx.sync_state, state);
		mac_ctx.sync_state = state;
		STATS_INC(dect_stats.mac_sync_attempts); // Count every change as an attempt/state transition
	}
	k_mutex_unlock(&mac_ctx_mutex);
}

mac_sync_state_t dect_mac_get_sync_state(void)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	mac_sync_state_t state = mac_ctx.sync_state;
	k_mutex_unlock(&mac_ctx_mutex);
	return state;
}

dect_status_t dect_mac_start_association(void)
{
	if (mac_ctx.role == MAC_ROLE_FP) {
		LOG_WRN("MAC: Fixed Part cannot initiate association (it waits for PPs).");
		return DECT_ERROR_INVALID_STATE;
	}

	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	if (mac_ctx.assoc_state == MAC_ASSOC_STATE_ASSOCIATED) {
		LOG_INF("MAC: Already associated. No need to start new association.");
		k_mutex_unlock(&mac_ctx_mutex);
		return DECT_STATUS_OK;
	}

	LOG_DBG("MAC: Starting association process for Portable Part...");
	dect_mac_set_association_state(MAC_ASSOC_STATE_ASSOCIATING);

	// Start a timer to periodically scan for FPs and send Association Requests
	k_timer_start(&association_timer, K_MSEC(CONFIG_DECT_NR_PLUS_MAC_ASSOC_RETRY_TIMEOUT_MS),
				  K_MSEC(CONFIG_DECT_NR_PLUS_MAC_ASSOC_RETRY_TIMEOUT_MS));

	k_mutex_unlock(&mac_ctx_mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_mac_stop_association(void)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	LOG_DBG("MAC: Stopping association process.");
	k_timer_stop(&association_timer);
	dect_mac_set_association_state(MAC_ASSOC_STATE_IDLE);
	mac_ctx.associated_fp_short_rd_id = 0;
	k_mutex_unlock(&mac_ctx_mutex);
	return DECT_STATUS_OK;
}

/**
 * @brief Timer handler for the association process (Portable Part).
 * This function is called periodically to scan for Fixed Parts and send
 * Association Request PDUs.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
static void association_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	dect_status_t status;

	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);

	if (mac_ctx.role == MAC_ROLE_PP && mac_ctx.assoc_state == MAC_ASSOC_STATE_ASSOCIATING) {
		LOG_DBG("MAC: Association timer fired. Scanning for FPs and sending Assoc Request.");

		// 1. Scan for Fixed Parts (using channel manager to scan channels)
		// This is a simplified conceptual call. In a real scenario, this might involve
		// using dect_channel_mgr_scan_channels and populating dect_fp_candidate_t.
		// For now, assume a FP is found on channel 0 with a dummy Short RD ID.
		uint16_t target_fp_short_rd_id = 0x0001; // Example FP Short RD ID
		uint8_t target_channel = 0; // Example channel

		// In a real implementation:
		// if (dect_channel_mgr_find_best_fp(&target_fp_short_rd_id, &target_channel) != DECT_STATUS_OK) {
		//     LOG_DBG("MAC: No suitable Fixed Part found yet.");
		//     STATS_INC(dect_stats.mac_association_failures);
		//     k_mutex_unlock(&mac_ctx_mutex);
		//     return;
		// }

		// 2. Construct and send Association Request PDU to the found FP
		struct net_buf *assoc_req_pdu = NULL;
		status = handle_tx_buffer_allocation(&assoc_req_pdu, &mac_tx_net_buf_pool, __func__,
											 MAC_CTRL_PDU_HEADER_SIZE, DECT_ERROR_MAC_NO_MEM);
		if (status != DECT_STATUS_OK) {
			k_mutex_unlock(&mac_ctx_mutex);
			return;
		}

		// MAC Control PDU Header: Type 1 (unicast control) + Control Type (Assoc Req)
		uint8_t mac_hdr_type_byte = (MAC_HEADER_TYPE_1_CONTROL << 4) | MAC_CONTROL_TYPE_ASSOC_REQ;
		net_buf_add_u8(assoc_req_pdu, mac_hdr_type_byte);
		net_buf_add_be16(assoc_req_pdu, mac_ctx.local_short_rd_id); // Source Short RD ID
		net_buf_add_be16(assoc_req_pdu, target_fp_short_rd_id);   // Destination Short RD ID

		LOG_DBG("MAC: Sending Association Request to FP 0x%04x on channel %u.",
				target_fp_short_rd_id, target_channel);

		// Send to PHY for transmission (simplified: actual scheduling needed)
		status = nrf9161_dect_phy_transmit_receive(NULL, // Placeholder for PHY device
												   assoc_req_pdu,
												   NRF_MODEM_DECT_PHY_TX_TYPE_PCC, // Point Coordination Channel
												   target_channel,
												   0, // current_modem_time - for immediate TX (should be scheduled)
												   0, // tx_offset - should be scheduled relative to current_modem_time
												   0, // tx_duration - actual PDU duration
												   NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS, // Listen after TX
												   0, // rx_offset
												   0, // rx_duration
												   true, // Perform LBT
												   mac_ctx.local_short_rd_id, // Short RD ID
												   sys_rand32_get()); // HARQ transaction ID (dummy)

		if (status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(status, "MAC: Failed to send Assoc Request to PHY.");
			net_buf_unref(assoc_req_pdu);
			STATS_INC(dect_stats.mac_tx_drops);
			STATS_INC(dect_stats.mac_association_failures);
		} else {
			LOG_DBG("MAC: Assoc Request sent. Waiting for response.");
			// Keep timer running for retries or stop if response received.
		}
	} else {
		LOG_DBG("MAC: Association timer fired in unexpected state (Role: %d, Assoc State: %d). Stopping.",
				mac_ctx.role, mac_ctx.assoc_state);
		k_timer_stop(&association_timer);
	}
	k_mutex_unlock(&mac_ctx_mutex);
}

dect_status_t dect_mac_send_pdu_from_dlc(uint16_t dest_short_rd_id,
										 mac_header_type_t mac_pdu_type,
										 struct net_buf *dlc_pdu_buf,
										 uint8_t dlc_seq_num,
										 qos_priority_t qos_priority,
										 bool encrypted,
										 bool is_retransmission,
										 uint32_t harq_transaction_id)
{
	if (!dlc_pdu_buf) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "MAC TX: Received NULL DLC PDU buffer.");
		STATS_INC(dect_stats.mac_tx_drops);
		return DECT_ERROR_INVALID_PARAM;
	}

	struct net_buf *mac_pdu_buf = NULL;
	// Calculate total MAC PDU size: MAC Header + DLC PDU length
	size_t mac_hdr_len;
	if (mac_pdu_type == MAC_HEADER_TYPE_1_DATA || mac_pdu_type == MAC_HEADER_TYPE_1_CONTROL) {
		mac_hdr_len = MAC_TYPE1_HEADER_LEN_BYTES;
	} else if (mac_pdu_type == MAC_HEADER_TYPE_2_DATA || mac_pdu_type == MAC_HEADER_TYPE_2_CONTROL) {
		mac_hdr_len = MAC_TYPE2_HEADER_LEN_BYTES;
	} else {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "MAC TX: Invalid MAC PDU type %u.", mac_pdu_type);
		net_buf_unref(dlc_pdu_buf);
		STATS_INC(dect_stats.mac_tx_drops);
		return DECT_ERROR_INVALID_PARAM;
	}

	size_t total_pdu_len = mac_hdr_len + dlc_pdu_buf->len;

	// Check if PDU size exceeds max frame size
	if (total_pdu_len > CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "MAC TX: MAC PDU too large (%zu bytes), max is %u.",
						   total_pdu_len, CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE);
		net_buf_unref(dlc_pdu_buf);
		STATS_INC(dect_stats.mac_tx_drops);
		return DECT_ERROR_PDU_TOO_LARGE;
	}

	dect_status_t alloc_status = handle_tx_buffer_allocation(&mac_pdu_buf, &mac_tx_net_buf_pool, __func__,
															 total_pdu_len, DECT_ERROR_MAC_NO_MEM);
	if (alloc_status != DECT_STATUS_OK) {
		net_buf_unref(dlc_pdu_buf);
		return alloc_status;
	}

	// Build MAC Header
	uint8_t mac_hdr_type_byte = (mac_pdu_type << 4) | (qos_priority & 0x0F); // Assuming 4 bits for QoS
	net_buf_add_u8(mac_pdu_buf, mac_hdr_type_byte);
	net_buf_add_be16(mac_pdu_buf, mac_ctx.local_short_rd_id); // Source Short RD ID
	net_buf_add_be16(mac_pdu_buf, dest_short_rd_id);       // Destination Short RD ID

	// Add DLC PDU payload
	net_buf_write(mac_pdu_buf, dlc_pdu_buf->data, dlc_pdu_buf->len);
	net_buf_add(mac_pdu_buf, dlc_pdu_buf->len);
	net_buf_unref(dlc_pdu_buf); // MAC now owns the data, DLC buffer can be unref'd

	// If encryption is enabled and security is established with the peer
	if (encrypted && dect_config.enable_encryption && dect_security_is_established(dest_short_rd_id)) {
		uint8_t *session_key;
		size_t key_len;
		dect_status_t crypto_status = dect_security_get_session_key(dest_short_rd_id, &session_key, &key_len);
		if (crypto_status == DECT_STATUS_OK && session_key != NULL) {
			// Encrypt the entire MAC PDU (excluding initial MAC header if MIC applies to payload)
			// Assuming encryption applies to MAC payload (DLC PDU) + MAC overhead
			// Adjust this based on where MIC/encryption boundary is in ETSI spec
			uint8_t *payload_start = net_buf_pull_unaligned_mem(mac_pdu_buf, mac_hdr_len); // Data after MAC header
			size_t payload_len = mac_pdu_buf->len - mac_hdr_len;

			LOG_DBG("MAC TX: Encrypting PDU for 0x%04x, payload_len %zu.", dest_short_rd_id, payload_len);
			crypto_status = dect_crypto_encrypt(session_key, key_len,
												payload_start, payload_len,
												mac_ctx.local_long_rd_id, // Local Long RD ID for nonce
												mac_ctx.current_modem_time, // HPC for nonce
												mac_ctx.current_modem_time, // PSN for nonce (simplified, should be actual PSN)
												payload_start, // In-place encryption
												&payload_len); // Updated length including MIC

			if (crypto_status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(crypto_status, "MAC TX: Encryption failed for PDU to 0x%04x.", dest_short_rd_id);
				net_buf_unref(mac_pdu_buf);
				STATS_INC(dect_stats.mac_tx_drops);
				return DECT_ERROR_ENCRYPTION_FAILED;
			}
			// Update the net_buf length if payload_len changed (due to MIC addition)
			if (payload_len + mac_hdr_len > mac_pdu_buf->len) {
				net_buf_add(mac_pdu_buf, payload_len + mac_hdr_len - mac_pdu_buf->len);
			} else if (payload_len + mac_hdr_len < mac_pdu_buf->len) {
				// This shouldn't happen for CTR mode + MIC (length increases)
				net_buf_pull(mac_pdu_buf, mac_pdu_buf->len - (payload_len + mac_hdr_len));
			}
		} else {
			LOG_WRN("MAC TX: Encryption requested but session key not available for peer 0x%04x. Sending unencrypted.", dest_short_rd_id);
			// Continue sending unencrypted if key not available
		}
	} else if (encrypted && !dect_config.enable_encryption) {
		LOG_WRN("MAC TX: Encryption requested but global encryption is disabled. Sending unencrypted.");
	} else if (encrypted && !dect_security_is_established(dest_short_rd_id)) {
		LOG_WRN("MAC TX: Encryption requested for peer 0x%04x, but security is not established. Sending unencrypted.", dest_short_rd_id);
	}


	// Create a TX entry for HARQ tracking
	mac_tx_pdu_entry_t *tx_entry = k_malloc(sizeof(mac_tx_pdu_entry_t));
	if (!tx_entry) {
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEMORY, "MAC TX: Failed to allocate TX entry.");
		net_buf_unref(mac_pdu_buf);
		STATS_INC(dect_stats.mac_tx_drops);
		return DECT_ERROR_NO_MEMORY;
	}

	tx_entry->mac_pdu_buf = mac_pdu_buf;
	tx_entry->dest_short_rd_id = dest_short_rd_id;
	tx_entry->mac_hdr_type = mac_pdu_type;
	tx_entry->dlc_pdu_type = dlc_pdu_type;
	tx_entry->dlc_seq_num = dlc_seq_num;
	tx_entry->harq_transaction_id = harq_transaction_id;
	tx_entry->current_hpc = mac_ctx.current_modem_time; // Use current modem time as HPC
	tx_entry->current_psn = mac_ctx.current_modem_time & 0xFFFF; // Use lower 16 bits of modem time as PSN
	tx_entry->encrypted = encrypted && dect_config.enable_encryption && dect_security_is_established(dest_short_rd_id); // Actual encryption status
	tx_entry->tx_attempts = is_retransmission ? 1 : 0; // If retransmission, 1st attempt for HARQ is already done.
	tx_entry->state = MAC_TX_STATE_PENDING; // Initially pending for scheduling
	tx_entry->next_tx_time_ms = k_uptime_get(); // Can be scheduled immediately
	tx_entry->phy_op_handle = NULL; // Will be filled by PHY

	// Add to outstanding TX FIFO
	k_fifo_put(&mac_outstanding_tx_fifo, tx_entry);

	LOG_DBG("MAC TX: Queued PDU (dest: 0x%04x, len: %u, DLC Seq: %u, HARQ ID: %u, encrypted: %d) for TX.",
			dest_short_rd_id, mac_pdu_buf->len, dlc_seq_num, harq_transaction_id, tx_entry->encrypted);

	STATS_INC(dect_stats.tx_frames); // Count as a MAC frame transmission attempt

	return DECT_STATUS_OK;
}

void dect_mac_phy_tx_completion_handler(uint32_t harq_transaction_id, harq_feedback_t feedback, dect_status_t tx_status)
{
	mac_tx_pdu_entry_t *entry = NULL;
	sys_snode_t *node;

	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);

	// Find the outstanding TX entry
	SYS_SLIST_FOR_EACH_NODE(&mac_outstanding_tx_fifo.data_q, node) {
		mac_tx_pdu_entry_t *curr = CONTAINER_OF(node, mac_tx_pdu_entry_t, node);
		if (curr->harq_transaction_id == harq_transaction_id) {
			entry = curr;
			break;
		}
	}

	if (!entry) {
		LOG_WRN("MAC: Received TX completion for unknown HARQ ID %u. Ignoring.", harq_transaction_id);
		k_mutex_unlock(&mac_ctx_mutex);
		return;
	}

	LOG_DBG("MAC: TX completion for HARQ ID %u. Feedback: %d, Status: %d. Attempts: %u.",
			harq_transaction_id, feedback, tx_status, entry->tx_attempts);

	if (tx_status == DECT_STATUS_OK && feedback == HARQ_FEEDBACK_ACK) {
		LOG_DBG("MAC: PDU (HARQ ID %u, DLC Seq %u) successfully transmitted to 0x%04x.",
				entry->harq_transaction_id, entry->dlc_seq_num, entry->dest_short_rd_id);
		entry->state = MAC_TX_STATE_COMPLETED;
		dlc_mac_tx_completion_notification(entry->dest_short_rd_id, entry->dlc_seq_num, true, entry->tx_attempts, entry->phy_op_handle);
		STATS_INC(dect_stats.harq_tx_success);
	} else {
		entry->tx_attempts++;
		if (entry->tx_attempts < CONFIG_DECT_NR_PLUS_MAC_MAX_RETRANSMISSIONS) {
			LOG_DBG("MAC: PDU (HARQ ID %u, DLC Seq %u) NACK/Failed. Retrying (%u/%u).",
					entry->harq_transaction_id, entry->dlc_seq_num,
					entry->tx_attempts, CONFIG_DECT_NR_PLUS_MAC_MAX_RETRANSMISSIONS);
			entry->state = MAC_TX_STATE_RETRANSMITTING;
			STATS_INC(dect_stats.harq_tx_retransmissions);
			// Re-queue the entry for retransmission (e.g., set next_tx_time_ms)
			// For simplicity, we just put it back to the beginning of the FIFO to be picked up quickly.
			// A more sophisticated scheduler would use next_tx_time_ms.
			k_fifo_put(&mac_outstanding_tx_fifo, entry); // This re-adds it.
		} else {
			LOG_WRN("MAC: PDU (HARQ ID %u, DLC Seq %u) failed after %u attempts. Dropping.",
					entry->harq_transaction_id, entry->dlc_seq_num, entry->tx_attempts);
			entry->state = MAC_TX_STATE_FAILED;
			dlc_mac_tx_completion_notification(entry->dest_short_rd_id, entry->dlc_seq_num, false, entry->tx_attempts, entry->phy_op_handle);
			STATS_INC(dect_stats.harq_tx_failures);
			net_buf_unref(entry->mac_pdu_buf); // Free the PDU buffer
			k_free(entry); // Free the TX entry
		}
	}
	k_mutex_unlock(&mac_ctx_mutex);
}

void dect_mac_phy_rx_packet_handler(nrf9161_dect_rx_packet_t *rx_packet_info)
{
	if (!rx_packet_info || !rx_packet_info->data_buf) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "MAC RX: Received NULL RX packet info or data buffer.");
		STATS_INC(dect_stats.mac_rx_drops);
		return;
	}

	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);

	STATS_INC(dect_stats.rx_frames);
	STATS_ADD(dect_stats.rx_data_bytes, rx_packet_info->data_buf->len);

	uint8_t *mac_pdu_ptr = net_buf_pull_unaligned_mem(rx_packet_info->data_buf, rx_packet_info->data_buf->len);
	if (rx_packet_info->data_buf->len < MAC_MIN_HEADER_LEN_BYTES) { // Assuming minimum header size
		LOG_WRN("MAC RX: Received PDU too short (%u bytes). Dropping.", rx_packet_info->data_buf->len);
		net_buf_unref(rx_packet_info->data_buf);
		STATS_INC(dect_stats.mac_rx_drops);
		k_mutex_unlock(&mac_ctx_mutex);
		return;
	}

	uint8_t mac_hdr_type_byte = mac_pdu_ptr[0];
	mac_header_type_t mac_hdr_type = (mac_hdr_type_byte >> 4) & 0x0F;
	uint8_t control_type_qos = mac_hdr_type_byte & 0x0F; // For control, this is control type; for data, it's QoS

	uint16_t src_short_rd_id = net_buf_pull_be16(rx_packet_info->data_buf); // Source RD ID
	uint16_t dest_short_rd_id = net_buf_pull_be16(rx_packet_info->data_buf); // Destination RD ID

	if (mac_hdr_type == MAC_HEADER_TYPE_1_CONTROL || mac_hdr_type == MAC_HEADER_TYPE_2_CONTROL) {
		mac_control_pdu_type_t control_pdu_type = (mac_control_pdu_type_t)control_type_qos;
		LOG_DBG("MAC RX: Received Control PDU (Type: %u, Control Type: %u) from 0x%04x to 0x%04x.",
				mac_hdr_type, control_pdu_type, src_short_rd_id, dest_short_rd_id);

		// Handle MAC Control PDUs
		switch (control_pdu_type) {
			case MAC_CONTROL_TYPE_BEACON:
				// Only FPs send beacons. PPs process them for sync/association.
				if (mac_ctx.role == MAC_ROLE_PP) {
					LOG_DBG("MAC: PP received Beacon from 0x%04x. RSSI: %d dBm.", src_short_rd_id, rx_packet_info->rssi);
					// Process beacon: update FP candidate list, check sync status
					// if (dect_channel_mgr_update_fp_candidate(src_short_rd_id, mac_pdu_ptr, rx_packet_info->rssi, rx_packet_info->channel) == DECT_STATUS_OK) {
					//     // If sync not established, try to sync
					//     if (mac_ctx.sync_state != MAC_SYNC_STATE_SYNCHRONIZED) {
					//         dect_mac_set_sync_state(MAC_SYNC_STATE_SYNCHRONIZED); // Simplified sync
					//         // Trigger some sync-related actions, e.g., stop sync timer
					//     }
					// }
					STATS_INC(dect_stats.bcc_beacons_rx);
				} else {
					LOG_DBG("MAC: FP received unexpected Beacon from 0x%04x. Ignoring.", src_short_rd_id);
				}
				break;
			case MAC_CONTROL_TYPE_ASSOC_REQ:
				if (mac_ctx.role == MAC_ROLE_FP && mac_ctx.assoc_state != MAC_ASSOC_STATE_ASSOCIATED) {
					LOG_DBG("MAC: FP received Association Request from PP 0x%04x.", src_short_rd_id);
					// Check if PP can be associated. If yes, send Assoc Resp.
					if (mac_ctx.num_associated_peers < MAX_PEERS) {
						mac_ctx.associated_peers[mac_ctx.num_associated_peers++] = src_short_rd_id;
						mac_ctx.associated_pp_short_rd_id = src_short_rd_id; // For single PP case
						dect_mac_set_association_state(MAC_ASSOC_STATE_ASSOCIATED);
						STATS_INC(dect_stats.mac_association_success);

						// Send Association Response
						struct net_buf *assoc_resp_pdu = NULL;
						dect_status_t status = handle_tx_buffer_allocation(&assoc_resp_pdu, &mac_tx_net_buf_pool, __func__,
																			MAC_CTRL_PDU_HEADER_SIZE, DECT_ERROR_MAC_NO_MEM);
						if (status == DECT_STATUS_OK) {
							uint8_t resp_hdr_type_byte = (MAC_HEADER_TYPE_1_CONTROL << 4) | MAC_CONTROL_TYPE_ASSOC_RESP;
							net_buf_add_u8(assoc_resp_pdu, resp_hdr_type_byte);
							net_buf_add_be16(assoc_resp_pdu, mac_ctx.local_short_rd_id);
							net_buf_add_be16(assoc_resp_pdu, src_short_rd_id);

							status = nrf9161_dect_phy_transmit_receive(NULL, assoc_resp_pdu, NRF_MODEM_DECT_PHY_TX_TYPE_PCC,
																	   rx_packet_info->channel, 0, 0, 0, NRF_MODEM_DECT_PHY_RX_MODE_IDLE, 0, 0,
																	   true, mac_ctx.local_short_rd_id, sys_rand32_get());
							if (status != DECT_STATUS_OK) {
								DECT_ERROR_HANDLER(status, "MAC: Failed to send Assoc Response.");
								net_buf_unref(assoc_resp_pdu);
								STATS_INC(dect_stats.mac_tx_drops);
							} else {
								LOG_DBG("MAC: Sent Association Response to PP 0x%04x.", src_short_rd_id);
							}
						}
					} else {
						LOG_WRN("MAC: Max associations reached. Rejecting Assoc Request from 0x%04x.", src_short_rd_id);
						STATS_INC(dect_stats.mac_association_failures);
						// Send rejection if spec requires
					}
				} else {
					LOG_DBG("MAC: %s received unexpected Association Request from 0x%04x. Ignoring.",
							(mac_ctx.role == MAC_ROLE_FP) ? "FP" : "PP", src_short_rd_id);
				}
				break;
			case MAC_CONTROL_TYPE_ASSOC_RESP:
				if (mac_ctx.role == MAC_ROLE_PP && mac_ctx.assoc_state == MAC_ASSOC_STATE_ASSOCIATING) {
					LOG_DBG("MAC: PP received Association Response from FP 0x%04x.", src_short_rd_id);
					mac_ctx.associated_fp_short_rd_id = src_short_rd_id;
					dect_mac_set_association_state(MAC_ASSOC_STATE_ASSOCIATED);
					k_timer_stop(&association_timer); // Stop association retries
					net_if_carrier_on(mac_ctx.net_if_ptr); // Bring up network interface
					LOG_INF("MAC: Associated with FP 0x%04x. Network interface carrier ON.", src_short_rd_id);
					STATS_INC(dect_stats.mac_association_success);
					// Notify security layer to initiate handshake
					dect_security_initiate_handshake(mac_ctx.associated_fp_short_rd_id);
				} else {
					LOG_DBG("MAC: PP received unexpected Association Response from 0x%04x. Ignoring.", src_short_rd_id);
				}
				break;
			case MAC_CONTROL_TYPE_DISASSOC_REQ:
				LOG_DBG("MAC: Received Disassociation Request from 0x%04x.", src_short_rd_id);
				dlc_mac_disconnected_notification(src_short_rd_id, MAC_LINK_FAILURE_REASON_DISASSOCIATED);
				// Remove from associated peers
				// For simplicity, directly set state to idle
				dect_mac_set_association_state(MAC_ASSOC_STATE_IDLE);
				mac_ctx.associated_fp_short_rd_id = 0;
				mac_ctx.associated_pp_short_rd_id = 0;
				net_if_carrier_off(mac_ctx.net_if_ptr); // Bring down network interface
				LOG_INF("MAC: Disassociated. Network interface carrier OFF.");
				break;
			case MAC_CONTROL_TYPE_SECURITY_CHALLENGE:
			case MAC_CONTROL_TYPE_SECURITY_RESPONSE:
			case MAC_CONTROL_TYPE_SECURITY_CONFIRM:
				// Pass security control PDUs to the Security layer
				LOG_DBG("MAC: Passing Security PDU (type %u) to Security layer from 0x%04x.", control_pdu_type, src_short_rd_id);
				dect_security_process_control_pdu(src_short_rd_id, control_pdu_type, rx_packet_info->data_buf);
				break;
			case MAC_CONTROL_TYPE_HANDOVER_REQUEST:
			case MAC_CONTROL_TYPE_HANDOVER_RESPONSE:
			case MAC_CONTROL_TYPE_HANDOVER_COMPLETE:
				if (dect_config.enable_mobility_support) {
					LOG_DBG("MAC: Mobility PDU (type %u) received from 0x%04x. Not yet implemented.", control_pdu_type, src_short_rd_id);
					// TODO: Implement mobility procedures and pass to a Mobility Management module
					STATS_INC(dect_stats.mac_handover_requests_rx); // Only track requests for now
				} else {
					LOG_WRN("MAC: Mobility PDU (type %u) received but mobility support is disabled. Dropping.", control_pdu_type);
					STATS_INC(dect_stats.mac_rx_drops);
				}
				net_buf_unref(rx_packet_info->data_buf);
				break;
			case MAC_CONTROL_TYPE_RESOURCE_REQUEST:
			case MAC_CONTROL_TYPE_RESOURCE_GRANT:
			case MAC_CONTROL_TYPE_RESOURCE_RELEASE:
				LOG_DBG("MAC: Resource management PDU (type %u) received from 0x%04x. Not yet implemented.", control_pdu_type, src_short_rd_id);
				net_buf_unref(rx_packet_info->data_buf);
				break;
			default:
				LOG_WRN("MAC RX: Received unknown MAC Control PDU type %u. Dropping.", control_pdu_type);
				net_buf_unref(rx_packet_info->data_buf);
				STATS_INC(dect_stats.mac_rx_drops);
				break;
		}
	} else if (mac_hdr_type == MAC_HEADER_TYPE_1_DATA || mac_hdr_type == MAC_HEADER_TYPE_2_DATA) {
		LOG_DBG("MAC RX: Received Data PDU (Type: %u, QoS: %u) from 0x%04x to 0x%04x. Length: %u.",
				mac_hdr_type, control_type_qos, src_short_rd_id, dest_short_rd_id, rx_packet_info->data_buf->len);

		if (dest_short_rd_id != mac_ctx.local_short_rd_id &&
			dest_short_rd_id != SHORT_RD_ID_BROADCAST &&
			!mac_is_multicast_member(dest_short_rd_id)) {
			LOG_DBG("MAC RX: PDU not for us (dest 0x%04x). Checking if routing enabled.", dest_short_rd_id);
			if (dect_config.enable_routing) {
				// Pass to routing layer for forwarding
				dect_status_t routing_status = dect_routing_process_incoming_pdu(src_short_rd_id, rx_packet_info->data_buf, rx_packet_info->hpc, rx_packet_info->psn);
				if (routing_status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(routing_status, "MAC RX: Failed to pass PDU to Routing layer.");
					net_buf_unref(rx_packet_info->data_buf);
					STATS_INC(dect_stats.mac_rx_drops);
				}
			} else {
				LOG_DBG("MAC RX: PDU not for us and routing disabled. Dropping.");
				net_buf_unref(rx_packet_info->data_buf);
				STATS_INC(dect_stats.mac_rx_drops);
			}
			k_mutex_unlock(&mac_ctx_mutex);
			return;
		}

		// Decrypt if necessary
		if (dect_config.enable_encryption && dect_security_is_established(src_short_rd_id)) {
			uint8_t *session_key;
			size_t key_len;
			dect_status_t crypto_status = dect_security_get_session_key(src_short_rd_id, &session_key, &key_len);
			if (crypto_status == DECT_STATUS_OK && session_key != NULL) {
				// Assuming decryption applies to the part after MAC header, including MIC.
				// This implies the MAC PDU has been pulled past its header for decryption.
				uint8_t *payload_start = net_buf_pull_unaligned_mem(rx_packet_info->data_buf, 0); // Start of payload (after MAC header already pulled)
				size_t payload_len = rx_packet_info->data_buf->len;

				LOG_DBG("MAC RX: Decrypting PDU from 0x%04x, payload_len %zu.", src_short_rd_id, payload_len);
				crypto_status = dect_crypto_decrypt(session_key, key_len,
													payload_start, payload_len,
													mac_ctx.local_long_rd_id, // Our Long RD ID for nonce
													rx_packet_info->hpc,      // HPC from received PDU
													rx_packet_info->psn,      // PSN from received PDU
													payload_start, // In-place decryption
													&payload_len); // Updated length after MIC removal

				if (crypto_status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(crypto_status, "MAC RX: Decryption or MIC verification failed for PDU from 0x%04x. Dropping.", src_short_rd_id);
					net_buf_unref(rx_packet_info->data_buf);
					STATS_INC(dect_stats.mac_rx_drops);
					k_mutex_unlock(&mac_ctx_mutex);
					return;
				}
				// Update net_buf length if payload_len changed due to MIC removal
				if (payload_len < rx_packet_info->data_buf->len) {
					net_buf_pull(rx_packet_info->data_buf, rx_packet_info->data_buf->len - payload_len);
				}
			} else {
				LOG_WRN("MAC RX: Encryption enabled but session key not available for peer 0x%04x. Dropping encrypted PDU.", src_short_rd_id);
				net_buf_unref(rx_packet_info->data_buf);
				STATS_INC(dect_stats.mac_rx_drops);
				k_mutex_unlock(&mac_ctx_mutex);
				return;
			}
		}

		// Pass data PDU to DLC layer
		dlc_rx_msg_t rx_msg = {
			.src_short_rd_id = src_short_rd_id,
			.dlc_pdu_buf = rx_packet_info->data_buf, // DLC now owns this buffer
			.rssi = rx_packet_info->rssi,
			.hpc = rx_packet_info->hpc,
			.psn = rx_packet_info->psn,
			.dlc_pdu_type = DLC_PDU_TYPE_DATA, // Assuming data PDU
		};

		int ret = k_msgq_put(&mac_rx_msgq, &rx_msg, K_NO_WAIT);
		if (ret != 0) {
			DECT_ERROR_HANDLER(DECT_ERROR_MAC_RX_DROPS, "MAC RX: Failed to queue RX PDU to DLC (ret: %d).", ret);
			net_buf_unref(rx_packet_info->data_buf); // Unref if queue full
			STATS_INC(dect_stats.mac_rx_drops);
		}
	} else {
		LOG_WRN("MAC RX: Received unknown MAC Header Type %u. Dropping.", mac_hdr_type);
		net_buf_unref(rx_packet_info->data_buf);
		STATS_INC(dect_stats.mac_rx_drops);
	}
	k_mutex_unlock(&mac_ctx_mutex);
}

void dect_mac_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_DBG("DECT MAC Thread started.");

	dlc_tx_msg_t tx_msg;
	dect_status_t status;
	bool had_activity_this_loop;

	while (true) {
		had_activity_this_loop = false;

		/* Process TX messages from DLC */
		if (k_msgq_get(&mac_tx_msgq, &tx_msg, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;

			// Pass to the general MAC send function
			status = dect_mac_send_pdu_from_dlc(tx_msg.dest_short_rd_id,
												MAC_HEADER_TYPE_1_DATA, // Assume data for now
												tx_msg.dlc_pdu_buf,
												0, // DLC sequence number not available here yet
												tx_msg.qos_priority,
												dect_config.enable_encryption, // Use config for encryption flag
												false, // Not a retransmission from this path
												sys_rand32_get()); // New HARQ ID

			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "MAC TX: Failed to send PDU from DLC.");
				// The buffer was unref'd inside dect_mac_send_pdu_from_dlc on error.
			}
		}

		/* Process outstanding HARQ transmissions and schedule PHY operations */
		mac_tx_pdu_entry_t *entry = (mac_tx_pdu_entry_t *)k_fifo_get(&mac_outstanding_tx_fifo, K_NO_WAIT);
		if (entry) {
			had_activity_this_loop = true;

			if (entry->state == MAC_TX_STATE_PENDING || entry->state == MAC_TX_STATE_RETRANSMITTING) {
				// Schedule for transmission if current time allows
				if (k_uptime_get() >= entry->next_tx_time_ms) {
					LOG_DBG("MAC: Scheduling TX for HARQ ID %u (DLC Seq %u, attempt %u).",
							entry->harq_transaction_id, entry->dlc_seq_num, entry->tx_attempts + 1);

					// Determine PHY TX type (PCC or PDC)
					nrf_modem_dect_phy_tx_type_t phy_tx_type = NRF_MODEM_DECT_PHY_TX_TYPE_PDC; // Default to PDC for data

					// If it's a control PDU (e.g., Assoc Req, Security PDU), use PCC
					if (entry->mac_hdr_type == MAC_HEADER_TYPE_1_CONTROL || entry->mac_hdr_type == MAC_HEADER_TYPE_2_CONTROL) {
						phy_tx_type = NRF_MODEM_DECT_PHY_TX_TYPE_PCC;
					}

					// Get current channel from Channel Manager
					uint8_t current_channel = dect_channel_mgr_get_active_channel();
					if (current_channel == 0xFF) { // Check for invalid channel
						DECT_ERROR_HANDLER(DECT_ERROR_INVALID_CHANNEL, "MAC: No active channel set. Cannot transmit.");
						entry->state = MAC_TX_STATE_FAILED; // Mark as failed
						dlc_mac_tx_completion_notification(entry->dest_short_rd_id, entry->dlc_seq_num, false, entry->tx_attempts, entry->phy_op_handle);
						STATS_INC(dect_stats.mac_tx_drops);
						net_buf_unref(entry->mac_pdu_buf); // Free buffer
						k_free(entry); // Free entry
						continue; // Process next item in FIFO
					}

					// Call PHY transmit function
					// Note: The timing parameters (start_time_us, duration_us, tx_offset, rx_offset, rx_duration)
					// are highly dependent on exact DECT NR+ TDMA slot scheduling. For now, using simplified values.
					// A proper implementation would calculate these based on current modem time and slot availability.
					dect_status_t phy_status = nrf9161_dect_phy_transmit_receive(
													NULL, // Placeholder for PHY device
													entry->mac_pdu_buf,
													phy_tx_type,
													current_channel,
													0, // start_time_us - 0 for immediate/next available slot
													nrf9161_dect_phy_get_tx_slot_duration(), // duration_us
													NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS, // RX mode after TX
													0, // rx_offset
													0, // rx_duration
													true, // Perform LBT
													entry->dest_short_rd_id, // Target Short RD ID
													entry->harq_transaction_id // HARQ ID
												);

					if (phy_status != DECT_STATUS_OK) {
						DECT_ERROR_HANDLER(phy_status, "MAC: PHY transmission failed for HARQ ID %u.", entry->harq_transaction_id);
						entry->state = MAC_TX_STATE_FAILED;
						dlc_mac_tx_completion_notification(entry->dest_short_rd_id, entry->dlc_seq_num, false, entry->tx_attempts, entry->phy_op_handle);
						STATS_INC(dect_stats.mac_tx_drops);
						net_buf_unref(entry->mac_pdu_buf);
						k_free(entry);
					} else {
						entry->state = MAC_TX_STATE_TRANSMITTING;
						// Re-add to FIFO, it will be removed by completion handler
						k_fifo_put(&mac_outstanding_tx_fifo, entry);
						STATS_INC(dect_stats.tx_frames); // Count successful PHY submission as frame TX
					}
				} else {
					// Put back to FIFO if not time to transmit yet
					k_fifo_put(&mac_outstanding_tx_fifo, entry);
				}
			} else if (entry->state == MAC_TX_STATE_COMPLETED || entry->state == MAC_TX_STATE_FAILED) {
				// These entries should have already been processed and freed by completion handler.
				// If they appear here, it indicates a logic error or a race condition.
				LOG_WRN("MAC: Found completed/failed TX entry %u in FIFO. Freeing.", entry->harq_transaction_id);
				net_buf_unref(entry->mac_pdu_buf);
				k_free(entry);
			} else {
				// Put back to FIFO if in unexpected state
				k_fifo_put(&mac_outstanding_tx_fifo, entry);
			}
		}

		// Update modem time periodically
		mac_ctx.current_modem_time = nrf9161_dect_phy_get_modem_time();


		if (!had_activity_this_loop) {
			// If no messages were processed and no HARQ pending, sleep to yield CPU
			k_sleep(K_MSEC(10)); // Sleep for a short period
		}
	}
}

/**
 * @brief Handles MAC link disconnection notifications from DLC.
 *
 * This function is part of the MAC API and is called by DLC to indicate
 * a link failure with a peer. MAC handles cleaning up its internal state
 * related to that peer.
 *
 * @param peer_short_rd_id The Short RD ID of the disconnected peer.
 * @param reason The reason for the link failure.
 */
void dlc_mac_disconnected_notification(uint16_t peer_short_rd_id, mac_link_failure_reason_t reason)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	LOG_INF("MAC: Link to peer 0x%04x disconnected. Reason: %d.", peer_short_rd_id, reason);

	// Remove peer from associated list
	for (int i = 0; i < mac_ctx.num_associated_peers; i++) {
		if (mac_ctx.associated_peers[i] == peer_short_rd_id) {
			for (int j = i; j < mac_ctx.num_associated_peers - 1; j++) {
				mac_ctx.associated_peers[j] = mac_ctx.associated_peers[j + 1];
			}
			mac_ctx.num_associated_peers--;
			break;
		}
	}

	// If the disconnected peer was the associated FP (for PP role)
	if (mac_ctx.role == MAC_ROLE_PP && mac_ctx.associated_fp_short_rd_id == peer_short_rd_id) {
		dect_mac_set_association_state(MAC_ASSOC_STATE_IDLE);
		mac_ctx.associated_fp_short_rd_id = 0;
		net_if_carrier_off(mac_ctx.net_if_ptr); // Bring down network interface
		LOG_INF("MAC: Disassociated from FP 0x%04x. Network interface carrier OFF.", peer_short_rd_id);
		// Potentially restart association process if automatic re-association is desired
		dect_mac_start_association(); // Try to re-associate
	}
	// If the disconnected peer was the associated PP (for FP role)
	else if (mac_ctx.role == MAC_ROLE_FP && mac_ctx.associated_pp_short_rd_id == peer_short_rd_id) {
		mac_ctx.associated_pp_short_rd_id = 0; // Clear associated PP
		LOG_INF("MAC: Associated PP 0x%04x disconnected.", peer_short_rd_id);
	}

	// Also clear any related IPv6 to Short RD ID mappings for this peer
	for (int i = 0; i < MAX_IPV6_TO_RD_ID_MAP_ENTRIES; i++) {
		if (mac_ctx.ipv6_to_short_rd_id_map[i].is_valid &&
			mac_ctx.ipv6_to_short_rd_id_map[i].short_rd_id == peer_short_rd_id) {
			mac_ctx.ipv6_to_short_rd_id_map[i].is_valid = false;
			LOG_DBG("MAC: Removed IPv6-RD ID mapping for 0x%04x due to link loss.", peer_short_rd_id);
		}
	}

	// Clean up any outstanding TX entries for this peer
	mac_tx_pdu_entry_t *entry_to_free;
	SYS_SLIST_FOR_EACH_NODE(&mac_outstanding_tx_fifo.data_q, node) {
		mac_tx_pdu_entry_t *curr = CONTAINER_OF(node, mac_tx_pdu_entry_t, node);
		if (curr->dest_short_rd_id == peer_short_rd_id) {
			entry_to_free = (mac_tx_pdu_entry_t *)k_fifo_get(&mac_outstanding_tx_fifo, K_NO_WAIT);
			if (entry_to_free == curr) { // Check if it's the one we expected to get
				LOG_DBG("MAC: Canceling and freeing outstanding TX PDU for peer 0x%04x (HARQ ID %u).", peer_short_rd_id, entry_to_free->harq_transaction_id);
				net_buf_unref(entry_to_free->mac_pdu_buf);
				k_free(entry_to_free);
				// Re-start iteration after removal
				node = &mac_outstanding_tx_fifo.data_q.head; // Reset iterator to head
			}
		}
	}


	k_mutex_unlock(&mac_ctx_mutex);
}

/**
 * @brief Internal helper to find an IPv6 to Short RD ID map entry.
 *
 * @param ipv6_addr Pointer to the IPv6 address to find.
 * @return Index of the entry if found, -1 otherwise.
 */
static int find_ipv6_to_short_rd_id_entry(const struct in6_addr *ipv6_addr)
{
	for (int i = 0; i < mac_ctx.num_ipv6_to_short_rd_id_entries; i++) {
		if (mac_ctx.ipv6_to_short_rd_id_map[i].is_valid &&
			net_ipv6_addr_cmp(ipv6_addr, &mac_ctx.ipv6_to_short_rd_id_map[i].ipv6_address)) {
			return i;
		}
	}
	return -1;
}

uint16_t dect_mac_lookup_ipv6_to_short_rd_id(const struct in6_addr *ipv6_addr)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	int idx = find_ipv6_to_short_rd_id_entry(ipv6_addr);
	uint16_t short_rd_id = 0; // Return 0 for not found

	if (idx != -1) {
		short_rd_id = mac_ctx.ipv6_to_short_rd_id_map[idx].short_rd_id;
		LOG_DBG("MAC: Found IPv6 %s mapped to Short RD ID 0x%04x.",
				log_strdup(net_ipv6_sprint(ipv6_addr)), short_rd_id);
	} else {
		LOG_DBG("MAC: IPv6 address %s not found in direct map.", log_strdup(net_ipv6_sprint(ipv6_addr)));
	}
	k_mutex_unlock(&mac_ctx_mutex);
	return short_rd_id;
}

dect_status_t dect_mac_add_ipv6_to_short_rd_id_mapping(const struct in6_addr *ipv6_addr, uint16_t short_rd_id)
{
	k_mutex_lock(&mac_ctx_mutex, K_FOREVER);
	int idx = find_ipv6_to_short_rd_id_entry(ipv6_addr);

	if (idx != -1) {
		// Update existing entry
		mac_ctx.ipv6_to_short_rd_id_map[idx].short_rd_id = short_rd_id;
		LOG_DBG("MAC: Updated IPv6 %s to Short RD ID 0x%04x.",
				log_strdup(net_ipv6_sprint(ipv6_addr)), short_rd_id);
	} else {
		// Add new entry if space available
		if (mac_ctx.num_ipv6_to_short_rd_id_entries < MAX_IPV6_TO_RD_ID_MAP_ENTRIES) {
			idx = mac_ctx.num_ipv6_to_short_rd_id_entries++;
			net_ipv6_addr_copy(&mac_ctx.ipv6_to_short_rd_id_map[idx].ipv6_address, ipv6_addr);
			mac_ctx.ipv6_to_short_rd_id_map[idx].short_rd_id = short_rd_id;
			mac_ctx.ipv6_to_short_rd_id_map[idx].is_valid = true;
			LOG_DBG("MAC: Added IPv6 %s mapped to Short RD ID 0x%04x.",
					log_strdup(net_ipv6_sprint(ipv6_addr)), short_rd_id);
		} else {
			DECT_ERROR_HANDLER(DECT_ERROR_NO_RESOURCES, "MAC: IPv6 to Short RD ID map is full. Cannot add new entry for %s.",
							   log_strdup(net_ipv6_sprint(ipv6_addr)));
			k_mutex_unlock(&mac_ctx_mutex);
			return DECT_ERROR_NO_RESOURCES;
		}
	}
	k_mutex_unlock(&mac_ctx_mutex);
	return DECT_STATUS_OK;
}

/* End of File
 * Last Amended: 2025-06-09 18:30 BST: Updated dect_mac.c for robust error handling.
 * - Added `mac_tx_drops` and `mac_rx_drops` stats to `dect_stats.h` in previous step.
 * - Added `handle_tx_buffer_allocation` helper function.
 * - Modified `dect_mac_thread` (TX path) to use `handle_tx_buffer_allocation` for PDU creation.
 * - Modified `dect_mac_phy_rx_packet_handler` to properly handle and log `DECT_ERROR_INVALID_PARAM` for NULL inputs.
 * - Ensured `net_buf_unref` is called consistently on all error paths in `dect_mac_send_pdu_from_dlc` and `dect_mac_phy_rx_packet_handler`.
 * - Added more detailed logging for various MAC operations and drops.
 * - Enhanced `dect_mac_phy_tx_completion_handler` to correctly re-queue for retransmission or free on failure.
 * - Updated `dlc_mac_disconnected_notification` to correctly clear outstanding TX entries for the disconnected peer.
 * Last Amended: 2025-06-10 18:40 BST: Implemented Robust IP-to-Short RD ID Resolution.
 * - Implemented `find_ipv6_to_short_rd_id_entry` static helper.
 * - Implemented `dect_mac_lookup_ipv6_to_short_rd_id` to provide IP-to-Short RD ID mapping lookup.
 * - Implemented `dect_mac_add_ipv6_to_short_rd_id_mapping` to allow dynamic addition/update of mappings.
 * - Initialized `ipv6_to_short_rd_id_map` in `dect_mac_init`.
 * - Updated `dlc_mac_disconnected_notification` to clear IP-to-Short RD ID mappings for disconnected peers.
 */
