/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_SECURITY_H__
#define DECT_SECURITY_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h> // For k_timer, k_mutex

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For dect_security_context_t, SECURITY_NONCE_LEN, MAC_MIC_LEN

/**
 * @brief Global security context instance.
 * Defined in dect_security.c.
 */
extern dect_security_context_t sec_ctx;

/**
 * @brief Initializes the DECT NR+ Security layer.
 * Loads the master key (conceptual) and sets up the initial state.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_security_init(void);

// /**
//  * @brief Initiates a security handshake with a peer.
//  * This function is typically called by the Fixed Part (FP) after association
//  * or by the Portable Part (PP) after receiving an Association Response.
//  * It generates a local nonce and sends a Security Challenge PDU.
//  *
//  * @param peer_short_rd_id The Short RD ID of the peer to initiate handshake with.
//  * @param peer_long_rd_id The Long RD ID of the peer.
//  * @return DECT_STATUS_OK on success, or an error code.
//  */
// dect_status_t dect_security_initiate_handshake(uint16_t peer_short_rd_id, const uint8_t *peer_long_rd_id);

/**
 * @brief Initiates a security handshake with a peer.
 * This function is typically called by the Fixed Part (FP) after association
 * or by the Portable Part (PP) after receiving an Association Response.
 * It generates a local nonce and sends a Security Challenge PDU.
 *
 * @param peer_short_rd_id The Short RD ID of the peer to initiate handshake with.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_security_initiate_handshake(uint16_t peer_short_rd_id);

// /**
//  * @brief Processes a received Security Challenge PDU.
//  * This function is called by the MAC layer when a Security Challenge PDU is received.
//  * It stores the peer's nonce, derives a session key (conceptual), computes a MIC,
//  * and sends a Security Response PDU.
//  *
//  * @param src_short_rd_id The Short RD ID of the sender of the challenge.
//  * @param challenge_nonce The nonce received in the challenge.
//  * @param hpc Hyper Packet Counter from the received challenge.
//  * @param psn Packet Sequence Number from the received challenge.
//  * @return DECT_STATUS_OK on success, or an error code.
//  */
// dect_status_t dect_security_process_challenge(uint16_t src_short_rd_id, const uint8_t *challenge_nonce,
//                                               uint32_t hpc, uint16_t psn);

/**
 * @brief Processes a received Security Challenge PDU.
 * This function is called by the MAC layer when a Security Challenge PDU is received.
 * It stores the peer's nonce, derives a session key (conceptual), computes a MIC,
 * and sends a Security Response PDU.
 *
 * @param src_short_rd_id The Short RD ID of the sender of the challenge.
 * @param hpc Hyper Packet Counter from the received challenge. // [FIX]: Reordered parameters.
 * @param psn Packet Sequence Number from the received challenge. // [FIX]: Reordered parameters.
 * @param mac_pdu_buf Pointer to the net_buf containing the MAC PDU (challenge data). // [FIX]: Changed type from `challenge_nonce` to `mac_pdu_buf` to match .c.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_security_process_challenge(uint16_t src_short_rd_id, uint32_t hpc, uint16_t psn, struct net_buf *mac_pdu_buf);

/**
 * @brief Processes a received Security Response PDU.
 * This function is called by the MAC layer when a Security Response PDU is received.
 * It verifies the MIC, derives the session key, and completes the handshake.
 *
 * @param src_short_rd_id The Short RD ID of the sender of the response.
 * @param response_nonce The nonce received in the response.
 * @param hpc Hyper Packet Counter from the received response.
 * @param psn Packet Sequence Number from the received response.
 * @param mic The Message Integrity Code received in the response.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_security_process_response(uint16_t src_short_rd_id, const uint8_t *response_nonce,
                                             uint32_t hpc, uint16_t psn, const uint8_t *mic);

/**
 * @brief Timer handler for security handshake timeout.
 * This function is called when the security handshake timer expires.
 * It handles retransmissions or declares handshake failure.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dect_security_timeout_handler(struct k_timer *timer_id);

/**
 * @brief Checks if security (session key) is established with a given peer.
 * // [FIX]: Added missing public function declaration.
 * @param peer_short_rd_id The Short RD ID of the peer to check.
 * @return True if security is established, false otherwise.
 */
bool dect_security_is_established(uint16_t peer_short_rd_id);

/**
 * @brief Retrieves the session key for a given peer.
 * // [FIX]: Added missing public function declaration.
 * @param peer_short_rd_id The Short RD ID of the peer.
 * @param key_out Pointer to a pointer that will be set to the session key.
 * @param key_len_out Pointer to a size_t that will store the key length.
 * @return DECT_STATUS_OK on success, or an error code if key not found/valid.
 */
dect_status_t dect_security_get_session_key(uint16_t peer_short_rd_id, uint8_t **key_out, size_t *key_len_out);

/**
 * @brief Initiates a re-keying process (conceptual).
 * This function would trigger a new security handshake to derive a fresh session key.
 *
 * @param peer_short_rd_id The Short RD ID of the peer to re-key with.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_security_rekey(uint16_t peer_short_rd_id);

#endif /* DECT_SECURITY_H__ */

/* End of File
 * Last Amended: 2025-05-31 15:20 BST: Added initial function prototypes and footer.
 * Last Amended: 2025-06-02 17:45 BST: Updated `dect_security.h` with enhanced security handshake prototypes.
 * Added `dect_security_initiate_handshake`, `dect_security_process_challenge`, `dect_security_process_response`, `dect_security_timeout_handler`, and `dect_security_rekey` prototypes.
 * Updated Doxygen comments for new and modified functions.
 */
