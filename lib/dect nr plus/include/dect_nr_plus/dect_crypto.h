/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_CRYPTO_H__
#define DECT_CRYPTO_H__

#include <stdint.h>
#include <stddef.h>
#include <device.h> // For struct device
#include <dect_nr_plus/dect_errors.h> // For dect_status_t
#include <dect_nr_plus/dect_types.h> // For dect_security_context_t, AES_KEY_LEN, SECURITY_NONCE_LEN, MAC_MIC_LEN

/**
 * @brief Initializes the crypto module.
 *
 * This function stores the crypto device pointer and conceptually loads
 * the AES key from a secure source.
 *
 * @param dev Pointer to the crypto device structure.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_init(const struct device *dev);

/**
 * @brief Derives a session key using HKDF (HMAC-based Key Derivation Function).
 *
 * This function takes a master key, nonces from both parties, and other context
 * to derive a cryptographically strong session key.
 *
 * @param master_key Pointer to the master key.
 * @param master_key_len Length of the master key.
 * @param local_nonce Pointer to the local nonce.
 * @param peer_nonce Pointer to the peer's nonce.
 * @param session_key_out Pointer to the buffer where the derived session key will be stored.
 * @param session_key_len Length of the desired session key.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_derive_session_key(const uint8_t *master_key_in, size_t master_key_len,
											 const uint8_t *local_nonce, const uint8_t *peer_nonce,
											 uint8_t *session_key_out, size_t session_key_len)

/**
 * @brief Generates a random nonce for security handshake.
 *
 * @param nonce_buffer Pointer to the buffer to store the generated nonce.
 * @param nonce_len Length of the nonce to generate.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_generate_nonce(uint8_t *nonce_buffer, size_t nonce_len);

/**
 * @brief Encrypts a data block using AES-128 in CTR mode.
 * The nonce is constructed from MAC address, HPC, and PSN to ensure uniqueness.
 * This function also calculates and appends the MIC.
 *
 * @param key Pointer to the AES key (session key).
 * @param key_len Length of the key (AES_KEY_LEN).
 * @param hpc Highest Packet Count (for nonce).
 * @param psn Packet Sequence Number (for nonce).
 * @param data Pointer to the data to encrypt (will be encrypted in-place).
 * @param data_len Length of the data.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_encrypt(const uint8_t *key, size_t key_len,
								  uint32_t hpc, uint16_t psn,
								  uint8_t *data, size_t data_len);

/**
 * @brief Decrypts a data block using AES-128 in CTR mode and verifies the MIC.
 *
 * @param key Pointer to the AES key (session key).
 * @param key_len Length of the key (AES_KEY_LEN).
 * @param hpc Highest Packet Count (for nonce).
 * @param psn Packet Sequence Number (for nonce).
 * @param data Pointer to the data to decrypt (including MIC at the end, will be decrypted in-place).
 * @param data_len Length of the encrypted data *including* the MIC.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_decrypt(const uint8_t *key, size_t key_len,
								  uint32_t hpc, uint16_t psn,
								  uint8_t *data, size_t data_len);

/**
 * @brief Computes the Message Integrity Code (MIC) for a given data block.
 * Uses AES-CMAC with the derived session key.
 *
 * @param key Pointer to the key used for MIC computation (session key).
 * @param key_len Length of the key.
 * @param data Pointer to the data for which to compute the MIC.
 * @param data_len Length of the data.
 * @param mic_out Pointer to the buffer where the computed MIC will be stored.
 * @param mic_len Length of the MIC to compute (should be MAC_MIC_LEN).
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_compute_mic(const uint8_t *key, size_t key_len,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t *mic_out, size_t mic_len);

/**
 * @brief Verifies the Message Integrity Code (MIC) for a given data block.
 * Uses AES-CMAC with the derived session key.
 *
 * @param key Pointer to the key used for MIC verification (session key).
 * @param key_len Length of the key.
 * @param data Pointer to the data for which to verify the MIC.
 * @param data_len Length of the data.
 * @param mic_received Pointer to the received MIC.
 * @param mic_len Length of the MIC.
 * @return DECT_STATUS_OK if MIC is valid, DECT_ERROR_SECURITY_MIC_MISMATCH otherwise.
 */
dect_status_t dect_crypto_verify_mic(const uint8_t *key, size_t key_len,
                                     const uint8_t *data, size_t data_len,
                                     const uint8_t *mic_received, size_t mic_len);

#endif /* DECT_CRYPTO_H__ */

/* End of File
 * Last Amended: 2025-06-09 13:00 BST: Updated dect_crypto.h to synchronize function prototypes
 * with the implementation in dect_crypto.c. Removed outdated `encrypt_data` and `decrypt_data`
 * and added `dect_crypto_encrypt` and `dect_crypto_decrypt` with correct parameters.
 * Last Amended: 2025-06-09 13:09 BST: Corrected prototype for `dect_crypto_generate_nonce`
 * to match its implementation.
 */
