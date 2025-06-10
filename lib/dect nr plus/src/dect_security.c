/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <random/rand32.h> // For sys_rand_get for nonce generation
#include <drivers/entropy.h> // For crypto device entropy driver

#include <dect_nr_plus/dect_config.h>
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_security.h> /* Own header */
#include <dect_nr_plus/dect_crypto.h> /* For cryptographic operations */
#include <dect_nr_plus/dect_mac.h> /* For MAC layer interaction (sending control PDUs) */
#include <dect_nr_plus/dect_dlc.h> /* For DLC notification of security established */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_phy_nrf9161.h> // For nrf9161_dect_phy_get_tx_slot_duration

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_security, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global security context instance definition */
dect_security_context_t sec_ctx = {
	.auth_state = SECURITY_AUTH_STATE_NONE,
	.peer_short_rd_id = 0,
	.session_key_valid = false,
};

/* Mutex to protect sec_ctx */
K_MUTEX_DEFINE(sec_ctx_mutex);

/* Forward declarations for internal functions */
static void security_timeout_handler(struct k_timer *timer_id);

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
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "SEC: Failed to allocate net_buf from pool %s. No memory.", pool->name->name);
		STATS_INC(dect_stats.tx_drops_no_mem); // Increment global stat for TX drops due to no memory
		STATS_INC(dect_stats.security_tx_drops); // Increment security-specific TX drop stat
		return DECT_ERROR_NO_MEM;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_security_init(void)
{
	k_mutex_init(&sec_ctx.mutex);
	k_timer_init(&sec_ctx.handshake_timer, security_timeout_handler, NULL);
	LOG_INF("SEC: Module initialized.");
	return DECT_STATUS_OK;
}

dect_status_t dect_security_initiate_handshake(uint16_t peer_short_rd_id)
{
	k_mutex_lock(&sec_ctx.mutex, K_FOREVER);

	if (!dect_config.enable_encryption) {
		LOG_WRN("SEC: Encryption disabled in config. Not initiating handshake.");
		k_mutex_unlock(&sec_ctx.mutex);
		return DECT_ERROR_SECURITY_DISABLED;
	}

	if (sec_ctx.auth_state != SECURITY_AUTH_STATE_NONE && sec_ctx.auth_state != SECURITY_AUTH_STATE_FAILED) {
		LOG_WRN("SEC: Handshake already in progress or established with peer 0x%04x. State: %u.",
			peer_short_rd_id, sec_ctx.auth_state);
		k_mutex_unlock(&sec_ctx.mutex);
		return DECT_ERROR_INVALID_STATE;
	}

	sec_ctx.peer_short_rd_id = peer_short_rd_id;
	sec_ctx.auth_state = SECURITY_AUTH_STATE_HANDSHAKE_INIT;
	sec_ctx.session_key_valid = false;
	STATS_INC(dect_stats.security_handshakes_initiated);

	// Generate a local nonce
	// IMPORTANT: In a real system, this should use a Cryptographically Secure PRNG (CSPRNG)
	// (e.g., Zephyr's entropy driver if available on nRF9161, using `entropy_get_blocking`).
	// For this example, using sys_rand32_get as a placeholder.
	// Requires #include <drivers/entropy.h>
	// struct device *entropy_dev; initialized in dect_security_init
	// if (entropy_get_blocking(entropy_dev, sec_ctx.local_nonce, SECURITY_NONCE_LEN) != 0) {
	// 	DECT_ERROR_HANDLER(DECT_ERROR_SECURITY_FAILED, "SEC: Failed to get entropy for nonce.");
	// 	// Handle error, unref challenge_pdu, etc.
	// 	k_mutex_unlock(&sec_ctx.mutex);
	// 	return DECT_ERROR_SECURITY_FAILED;
	// }

	for (int i = 0; i < SECURITY_NONCE_LEN / sizeof(uint32_t); i++) {
		((uint32_t *)sec_ctx.local_nonce)[i] = sys_rand32_get();
	}
	LOG_HEXDUMP_DBG(sec_ctx.local_nonce, SECURITY_NONCE_LEN, "SEC: Generated local nonce:");

	// Construct Security Challenge PDU
	struct net_buf *challenge_pdu = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&challenge_pdu, &mac_tx_net_buf_pool);
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "SEC: Failed to allocate Challenge PDU.");
		k_mutex_unlock(&sec_ctx.mutex);
		return ret_alloc;
	}

	// Payload: Local Nonce (SECURITY_NONCE_LEN bytes)
	net_buf_add_mem(challenge_pdu, sec_ctx.local_nonce, SECURITY_NONCE_LEN);

	// Compute MIC over the challenge PDU payload (local nonce)
	// Key used for MIC on challenge is typically a pre-shared master key or device-specific key.
	// Here, we use the master_key (conceptual).
	uint8_t mic[MAC_MIC_LEN];
	dect_status_t mic_ret = dect_crypto_compute_mic(master_key, AES_KEY_LEN,
							challenge_pdu->data, challenge_pdu->len,
							mic, MAC_MIC_LEN);
	if (mic_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mic_ret, "SEC: Failed to compute MIC for Challenge PDU.");
		net_buf_unref(challenge_pdu);
		STATS_INC(dect_stats.security_tx_drops);
		k_mutex_unlock(&sec_ctx.mutex);
		return mic_ret;
	}
	net_buf_add_mem(challenge_pdu, mic, MAC_MIC_LEN); // Append MIC

	LOG_HEXDUMP_DBG(challenge_pdu->data, challenge_pdu->len, "SEC: Challenge PDU payload (Nonce+MIC):");

	// Send to MAC layer (Control PDU Type 1)
	dect_status_t mac_ret = dect_mac_send_pdu_from_dlc(peer_short_rd_id, challenge_pdu,
							   DLC_PDU_TYPE_CONTROL, MAC_HEADER_TYPE_1_CONTROL,
							   mac_ctx.current_hpc, mac_ctx.current_psn,
							   false, sys_rand32_get()); // Dummy HARQ ID for control
	if (mac_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mac_ret, "SEC: Failed to send Security Challenge PDU to MAC layer.");
		STATS_INC(dect_stats.security_tx_drops); // Buffer unref'd by MAC on failure
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		k_mutex_unlock(&sec_ctx.mutex);
		return mac_ret;
	}

	k_timer_start(&sec_ctx.handshake_timer, K_MSEC(CONFIG_DECT_NR_PLUS_SECURITY_HANDSHAKE_TIMEOUT_MS), K_NO_WAIT);

	LOG_INF("SEC: Security handshake initiated with peer 0x%04x.", peer_short_rd_id);
	k_mutex_unlock(&sec_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_security_process_challenge(uint16_t src_short_rd_id, uint32_t hpc, uint16_t psn, struct net_buf *mac_pdu_buf)
{
	k_mutex_lock(&sec_ctx.mutex, K_FOREVER);

	if (!dect_config.enable_encryption) {
		LOG_WRN("SEC: Encryption disabled. Ignoring Security Challenge from 0x%04x.", src_short_rd_id);
		net_buf_unref(mac_pdu_buf); // Release buffer
		k_mutex_unlock(&sec_ctx.mutex);
		return DECT_ERROR_SECURITY_DISABLED;
	}

	if (mac_pdu_buf->len < (SECURITY_NONCE_LEN + MAC_MIC_LEN)) {
		DECT_ERROR_HANDLER(DECT_ERROR_FRAME_TOO_SHORT, "SEC: Challenge PDU too short (%u bytes). Expected at least %u.",
				   mac_pdu_buf->len, (SECURITY_NONCE_LEN + MAC_MIC_LEN));
		STATS_INC(dect_stats.security_rx_drops);
		net_buf_unref(mac_pdu_buf);
		k_mutex_unlock(&sec_ctx.mutex);
		return DECT_ERROR_FRAME_TOO_SHORT;
	}

	uint8_t *peer_nonce_received = net_buf_pull(mac_pdu_buf, SECURITY_NONCE_LEN);
	uint8_t *received_mic = net_buf_pull(mac_pdu_buf, MAC_MIC_LEN);

	LOG_HEXDUMP_DBG(peer_nonce_received, SECURITY_NONCE_LEN, "SEC: Received peer nonce:");
	LOG_HEXDUMP_DBG(received_mic, MAC_MIC_LEN, "SEC: Received MIC:");

	// Verify MIC for the received challenge PDU (over the nonce part)
	dect_status_t mic_ret = dect_crypto_verify_mic(master_key, AES_KEY_LEN,
							peer_nonce_received, SECURITY_NONCE_LEN,
							received_mic, MAC_MIC_LEN);
	if (mic_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mic_ret, "SEC: MIC verification failed for Security Challenge from 0x%04x.", src_short_rd_id);
		STATS_INC(dect_stats.security_rx_drops);
		net_buf_unref(mac_pdu_buf); // Release buffer
		k_mutex_unlock(&sec_ctx.mutex);
		return mic_ret;
	}
	LOG_DBG("SEC: MIC verification passed for Security Challenge.");

	// Store peer's nonce and current HPC/PSN
	memcpy(sec_ctx.peer_nonce, peer_nonce_received, SECURITY_NONCE_LEN);
	sec_ctx.current_hpc_rx = hpc;
	sec_ctx.current_psn_rx = psn;
	sec_ctx.peer_short_rd_id = src_short_rd_id; // Set peer for this handshake

	// Generate our local nonce for the response
	// IMPORTANT: As above, use CSPRNG (e.g., entropy_get_blocking)
	// Requires #include <drivers/entropy.h>
	// Struct device *entropy_dev; initialized in dect_security_init
	// if (entropy_get_blocking(entropy_dev, sec_ctx.local_nonce, SECURITY_NONCE_LEN) != 0) {
	// 	DECT_ERROR_HANDLER(DECT_ERROR_SECURITY_FAILED, "SEC: Failed to get entropy for nonce.");
	// 	// Handle error, unref challenge_pdu, etc.
	// 	k_mutex_unlock(&sec_ctx.mutex);
	// 	return DECT_ERROR_SECURITY_FAILED;
	// }

	for (int i = 0; i < SECURITY_NONCE_LEN / sizeof(uint32_t); i++) {
		((uint32_t *)sec_ctx.local_nonce)[i] = sys_rand32_get();
	}
	LOG_HEXDUMP_DBG(sec_ctx.local_nonce, SECURITY_NONCE_LEN, "SEC: Generated local nonce for response:");

	// Derive session key
	dect_status_t key_ret = dect_crypto_derive_session_key(master_key, AES_KEY_LEN,
							       sec_ctx.local_nonce, sec_ctx.peer_nonce,
							       sec_ctx.session_key, AES_KEY_LEN);
	if (key_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(key_ret, "SEC: Failed to derive session key.");
		STATS_INC(dect_stats.security_rx_drops);
		net_buf_unref(mac_pdu_buf); // Release buffer
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		k_mutex_unlock(&sec_ctx.mutex);
		return key_ret;
	}
	sec_ctx.session_key_valid = true;
	LOG_DBG("SEC: Session key derived successfully.");
	LOG_HEXDUMP_DBG(sec_ctx.session_key, AES_KEY_LEN, "SEC: Derived session key:");


	// Construct Security Response PDU
	struct net_buf *response_pdu = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&response_pdu, &mac_tx_net_buf_pool);
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "SEC: Failed to allocate Response PDU.");
		net_buf_unref(mac_pdu_buf); // Release original buffer
		STATS_INC(dect_stats.security_tx_drops);
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		k_mutex_unlock(&sec_ctx.mutex);
		return ret_alloc;
	}

	// Payload: Our Local Nonce (SECURITY_NONCE_LEN bytes)
	net_buf_add_mem(response_pdu, sec_ctx.local_nonce, SECURITY_NONCE_LEN);

	// Compute MIC over the response PDU payload (our local nonce) using the derived session key
	uint8_t response_mic[MAC_MIC_LEN];
	mic_ret = dect_crypto_compute_mic(sec_ctx.session_key, AES_KEY_LEN,
							response_pdu->data, response_pdu->len,
							response_mic, MAC_MIC_LEN);
	if (mic_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mic_ret, "SEC: Failed to compute MIC for Response PDU.");
		net_buf_unref(response_pdu);
		net_buf_unref(mac_pdu_buf); // Release original buffer
		STATS_INC(dect_stats.security_tx_drops);
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		k_mutex_unlock(&sec_ctx.mutex);
		return mic_ret;
	}
	net_buf_add_mem(response_pdu, response_mic, MAC_MIC_LEN); // Append MIC

	LOG_HEXDUMP_DBG(response_pdu->data, response_pdu->len, "SEC: Response PDU payload (Nonce+MIC):");

	// Send to MAC layer (Control PDU Type 1)
	dect_status_t mac_ret = dect_mac_send_pdu_from_dlc(src_short_rd_id, response_pdu,
							   DLC_PDU_TYPE_CONTROL, MAC_HEADER_TYPE_1_CONTROL,
							   mac_ctx.current_hpc, mac_ctx.current_psn,
							   false, sys_rand32_get()); // Dummy HARQ ID for control
	if (mac_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mac_ret, "SEC: Failed to send Security Response PDU to MAC layer.");
		STATS_INC(dect_stats.security_tx_drops);
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		k_mutex_unlock(&sec_ctx.mutex);
		return mac_ret;
	}

	sec_ctx.auth_state = SECURITY_AUTH_STATE_AUTHENTICATED;
	STATS_INC(dect_stats.security_handshakes_processed);
	STATS_INC(dect_stats.security_handshakes_success);
	LOG_INF("SEC: Security handshake successfully processed with peer 0x%04x. Authenticated.", src_short_rd_id);

	// Notify DLC and MAC about security establishment
	dlc_mac_security_established_notification(src_short_rd_id);
	mac_dlc_security_established_notification(src_short_rd_id);

	net_buf_unref(mac_pdu_buf); // Release original buffer after successful processing
	k_mutex_unlock(&sec_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_security_process_response(uint16_t src_short_rd_id, const uint8_t *response_nonce,
                                             uint32_t hpc, uint16_t psn, const uint8_t *mic)
{
	k_mutex_lock(&sec_ctx.mutex, K_FOREVER);

	if (!dect_config.enable_encryption) {
		LOG_WRN("SEC: Encryption disabled. Ignoring Security Response from 0x%04x.", src_short_rd_id);
		k_mutex_unlock(&sec_ctx.mutex);
		return DECT_ERROR_SECURITY_DISABLED;
	}

	if (sec_ctx.auth_state != SECURITY_AUTH_STATE_HANDSHAKE_INIT || sec_ctx.peer_short_rd_id != src_short_rd_id) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_STATE, "SEC: Received Security Response from 0x%04x but no handshake in progress with this peer. Dropping.", src_short_rd_id);
		STATS_INC(dect_stats.security_rx_drops);
		k_mutex_unlock(&sec_ctx.mutex);
		return DECT_ERROR_INVALID_STATE;
	}

	// Store peer's nonce and current HPC/PSN
	memcpy(sec_ctx.peer_nonce, response_nonce, SECURITY_NONCE_LEN);
	sec_ctx.current_hpc_rx = hpc;
	sec_ctx.current_psn_rx = psn;

	LOG_HEXDUMP_DBG(response_nonce, SECURITY_NONCE_LEN, "SEC: Received peer nonce in response:");
	LOG_HEXDUMP_DBG(mic, MAC_MIC_LEN, "SEC: Received MIC in response:");

	// Derive session key
	dect_status_t key_ret = dect_crypto_derive_session_key(master_key, AES_KEY_LEN,
							       sec_ctx.local_nonce, sec_ctx.peer_nonce,
							       sec_ctx.session_key, AES_KEY_LEN);
	if (key_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(key_ret, "SEC: Failed to derive session key from response.");
		STATS_INC(dect_stats.security_rx_drops);
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		k_timer_stop(&sec_ctx.handshake_timer);
		dlc_mac_disconnected_notification(src_short_rd_id, MAC_LINK_FAILURE_REASON_SECURITY_FAILED);
		k_mutex_unlock(&sec_ctx.mutex);
		return key_ret;
	}
	sec_ctx.session_key_valid = true;
	LOG_DBG("SEC: Session key derived successfully from response.");
	LOG_HEXDUMP_DBG(sec_ctx.session_key, AES_KEY_LEN, "SEC: Derived session key:");

	// Verify MIC from the response PDU using the derived session key
	dect_status_t mic_ret = dect_crypto_verify_mic(sec_ctx.session_key, AES_KEY_LEN,
							(const uint8_t *)response_nonce, SECURITY_NONCE_LEN,
							mic, MAC_MIC_LEN);
	if (mic_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mic_ret, "SEC: MIC verification failed for Security Response from 0x%04x.", src_short_rd_id);
		STATS_INC(dect_stats.security_rx_drops);
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		k_timer_stop(&sec_ctx.handshake_timer);
		dlc_mac_disconnected_notification(src_short_rd_id, MAC_LINK_FAILURE_REASON_SECURITY_FAILED);
		k_mutex_unlock(&sec_ctx.mutex);
		return mic_ret;
	}
	LOG_DBG("SEC: MIC verification passed for Security Response.");

	sec_ctx.auth_state = SECURITY_AUTH_STATE_AUTHENTICATED;
	STATS_INC(dect_stats.security_handshakes_processed);
	STATS_INC(dect_stats.security_handshakes_success);
	k_timer_stop(&sec_ctx.handshake_timer);
	LOG_INF("SEC: Security handshake completed with peer 0x%04x. Authenticated.", src_short_rd_id);

	// Notify DLC and MAC about security establishment
	dlc_mac_security_established_notification(src_short_rd_id);
	mac_dlc_security_established_notification(src_short_rd_id);

	k_mutex_unlock(&sec_ctx.mutex);
	return DECT_STATUS_OK;
}

bool dect_security_is_established(uint16_t peer_short_rd_id)
{
	k_mutex_lock(&sec_ctx.mutex, K_FOREVER);
	bool established = (sec_ctx.auth_state == SECURITY_AUTH_STATE_AUTHENTICATED &&
			    sec_ctx.session_key_valid &&
			    sec_ctx.peer_short_rd_id == peer_short_rd_id);
	k_mutex_unlock(&sec_ctx.mutex);
	return established;
}

dect_status_t dect_security_get_session_key(uint16_t peer_short_rd_id, uint8_t **key_out, size_t *key_len_out)
{
	k_mutex_lock(&sec_ctx.mutex, K_FOREVER);
	if (dect_security_is_established(peer_short_rd_id)) {
		*key_out = sec_ctx.session_key;
		*key_len_out = AES_KEY_LEN;
		k_mutex_unlock(&sec_ctx.mutex);
		return DECT_STATUS_OK;
	}
	*key_out = NULL;
	*key_len_out = 0;
	k_mutex_unlock(&sec_ctx.mutex);
	return DECT_ERROR_SECURITY_NOT_READY;
}

static void security_timeout_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&sec_ctx.mutex, K_FOREVER);
	if (sec_ctx.auth_state == SECURITY_AUTH_STATE_HANDSHAKE_INIT) {
		DECT_ERROR_HANDLER(DECT_ERROR_SECURITY_HANDSHAKE_TIMEOUT, "SEC: Security handshake with 0x%04x timed out.", sec_ctx.peer_short_rd_id);
		STATS_INC(dect_stats.security_handshakes_failures);
		sec_ctx.auth_state = SECURITY_AUTH_STATE_FAILED;
		sec_ctx.session_key_valid = false;
		// Notify DLC/MAC about security failure/link disconnect
		dlc_mac_disconnected_notification(sec_ctx.peer_short_rd_id, MAC_LINK_FAILURE_REASON_SECURITY_FAILED);
	}
	k_mutex_unlock(&sec_ctx.mutex);
}

dect_status_t dect_security_rekey(uint16_t peer_short_rd_id)
{
	LOG_INF("SEC: Initiating re-keying process with peer 0x%04x.", peer_short_rd_id);
	// Reset current state for the peer
	k_mutex_lock(&sec_ctx.mutex, K_FOREVER);
	sec_ctx.auth_state = SECURITY_AUTH_STATE_NONE;
	sec_ctx.session_key_valid = false;
	k_mutex_unlock(&sec_ctx.mutex);

	// Trigger a new handshake
	return dect_security_initiate_handshake(peer_short_rd_id);
}

/* End of File
 * Last Amended: 2025-06-09 18:45 BST: Updated dect_security.c for robust error handling.
 * - Added `security_tx_drops` and `security_rx_drops` stats to `dect_stats.h` in previous step.
 * - Added `handle_tx_buffer_allocation` helper function.
 * - Modified `dect_security_initiate_handshake` and `dect_security_process_challenge` to use `handle_tx_buffer_allocation` for PDU creation.
 * - Enhanced `dect_security_process_challenge` and `dect_security_process_response` with explicit length checks for incoming PDUs to prevent `DECT_ERROR_FRAME_TOO_SHORT`.
 * - Ensured all error paths (allocation failures, MIC computation/verification failures, invalid state, queue full, frame too short) increment `dect_stats.security_tx_drops` or `dect_stats.security_rx_drops` and unreference `net_buf`s.
 * - Added `DECT_MSGQ_PUT_OR_DROP` implicitly via `dect_mac_send_pdu_from_dlc` which now handles drops.
 */
