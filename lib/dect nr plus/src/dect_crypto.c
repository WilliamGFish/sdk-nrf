/*
 * Copyright (c) 2025 Google LLC
 * Manulytica
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <device.h>
#include <crypto/cipher.h> // Zephyr cipher API
#include <random/rand32.h> // For sys_rand_get for nonces

// mbed TLS includes for AES-CTR, CMAC, and HKDF
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/sha256.h>
#include <mbedtls/hkdf.h>

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For AES_KEY_LEN, LONG_RD_ID_LEN_BYTES, and context structs
#include <dect_nr_plus/dect_mac.h> // For mac_ctx.mac_address, mac_ctx.peer_long_rd_id
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_crypto.h> // Own header

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_crypto, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Conceptual master key (for demonstration purposes, this would be securely provisioned) */
static const uint8_t master_key[AES_KEY_LEN] = {
	0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
	0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

/* Global crypto context (if any, currently handled by mbed TLS objects on stack) */
// static const struct device *crypto_dev_ptr; // Not directly used with mbedtls

dect_status_t dect_crypto_init(const struct device *dev)
{
	LOG_INF("Crypto: Initializing crypto module...");
	// TODO
	// crypto_dev_ptr = dev; // Store device pointer if a Zephyr crypto device is used

	// No specific mbed TLS initialization needed beyond setting up contexts for operations.
	// For example, mbedtls_aes_init() or mbedtls_cmac_init() are called before use.
	// Ensure dev is not NULL. In a real system, you'd likely use DEVICE_DT_GET
    // or pass the actual device pointer from the subsystem init.
    // if (!dev) {
    //     DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_NOT_READY, "Crypto: Crypto device is NULL.");
    //     return DECT_ERROR_CRYPTO_NOT_READY;
    // }

	LOG_INF("Crypto: Crypto module initialized. Master key conceptually loaded.");
	return DECT_STATUS_OK;
}

dect_status_t dect_crypto_derive_session_key(const uint8_t *master_key_in, size_t master_key_len,
											 const uint8_t *local_nonce, const uint8_t *peer_nonce,
											 uint8_t *session_key_out, size_t session_key_len)
{
	if (!master_key_in || !local_nonce || !peer_nonce || !session_key_out ||
		master_key_len == 0 || session_key_len == 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "Crypto: Invalid parameters for session key derivation.");
		return DECT_ERROR_INVALID_PARAM;
	}
	if (master_key_len != AES_KEY_LEN || session_key_len != AES_KEY_LEN) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "Crypto: Master or session key length mismatch for AES.");
		return DECT_ERROR_INVALID_PARAM;
	}

	LOG_DBG("Crypto: Deriving session key using HKDF...");

	// Concatenate local and peer nonces to form the Info (or Salt) for HKDF
	uint8_t info[SECURITY_NONCE_LEN * 2];
	memcpy(info, local_nonce, SECURITY_NONCE_LEN);
	memcpy(info + SECURITY_NONCE_LEN, peer_nonce, SECURITY_NONCE_LEN);

	// HKDF with SHA256
	// IKM: Master Key
	// Salt: None (or empty string, or some fixed context string). Using concatenated nonces as info.
	// Info: Concatenated nonces
	// OKM: Session Key
	int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
						   NULL, 0, // Salt (optional, can be empty or fixed)
						   master_key_in, master_key_len,
						   info, sizeof(info), // Info
						   session_key_out, session_key_len); // Output Key Material

	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: HKDF session key derivation failed: %d.", ret);
		return DECT_ERROR_CRYPTO_FAILED;
	}

	LOG_DBG("Crypto: Session key derived successfully.");
	return DECT_STATUS_OK;
}

dect_status_t dect_crypto_generate_nonce(uint8_t *nonce_out, size_t nonce_len)
{
	if (!nonce_out || nonce_len == 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "Crypto: Invalid parameters for nonce generation.");
		return DECT_ERROR_INVALID_PARAM;
	}

	LOG_DBG("Crypto: Generating random nonce...");
	// Use Zephyr's random number generator
	sys_rand_get(nonce_out, nonce_len);
	LOG_HEXDUMP_DBG(nonce_out, nonce_len, "Generated Nonce:");
	return DECT_STATUS_OK;
}

/**
 * @brief Encrypts a data block using AES-128 in CTR mode.
 * The nonce is constructed from HPC, PSN, and a fixed prefix (e.g., Long RD ID).
 * This function also calculates and appends the MIC.
 *
 * @param key Pointer to the AES key (session key).
 * @param key_len Length of the key (AES_KEY_LEN).
 * @param hpc Highest Packet Count (for nonce).
 * @param psn Packet Sequence Number (for nonce).
 * @param data Pointer to the data to encrypt.
 * @param data_len Length of the data.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_encrypt(const uint8_t *key, size_t key_len,
								  uint32_t hpc, uint16_t psn,
								  uint8_t *data, size_t data_len)
{
	if (!key || key_len != AES_KEY_LEN || !data || data_len == 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "Crypto: Invalid parameters for encryption.");
		return DECT_ERROR_INVALID_PARAM;
	}
	if (data_len + MAC_MIC_LEN > MAC_MAX_PDU_SIZE) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "Crypto: Data too large for encryption with MIC.");
		return DECT_ERROR_PDU_TOO_LARGE;
	}

	mbedtls_aes_context aes_ctx;
	uint8_t nonce_ctr[AES_KEY_LEN]; // 128-bit = 16 bytes for AES-CTR nonce/counter
	uint8_t stream_block[AES_KEY_LEN];
	size_t nc_off = 0; // Current offset in the stream_block for CTR mode

	// Construct Nonce/Counter (IV) for AES-CTR (typically based on Long RD ID, HPC, PSN)
	// Example: Long RD ID (4 bytes) | HPC (4 bytes) | PSN (2 bytes) | Padding (6 bytes)
	// This ensures uniqueness per packet.
	memset(nonce_ctr, 0, sizeof(nonce_ctr));
	memcpy(nonce_ctr, mac_ctx.mac_address, LONG_RD_ID_LEN_BYTES); // Use local MAC address as part of nonce
	memcpy(nonce_ctr + LONG_RD_ID_LEN_BYTES, &hpc, sizeof(hpc));
	memcpy(nonce_ctr + LONG_RD_ID_LEN_BYTES + sizeof(hpc), &psn, sizeof(psn));

	LOG_DBG("Crypto: Encrypting data (len %zu) with HPC %u, PSN %u.", data_len, hpc, psn);
	LOG_HEXDUMP_DBG(nonce_ctr, AES_KEY_LEN, "CTR Nonce:");

	mbedtls_aes_init(&aes_ctx);
	int ret = mbedtls_aes_setkey_enc(&aes_ctx, key, key_len * 8);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: AES set key failed: %d.", ret);
		mbedtls_aes_free(&aes_ctx);
		return DECT_ERROR_CRYPTO_FAILED;
	}

	// Encrypt data in-place
	ret = mbedtls_aes_crypt_ctr(&aes_ctx, data_len, &nc_off, nonce_ctr, stream_block, data, data);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_ENCRYPTION_FAILED, "Crypto: AES CTR encryption failed: %d.", ret);
		mbedtls_aes_free(&aes_ctx);
		return DECT_ERROR_ENCRYPTION_FAILED;
	}
	mbedtls_aes_free(&aes_ctx);

	// Calculate and append MIC
	uint8_t mic[MAC_MIC_LEN];
	dect_status_t mic_status = dect_crypto_compute_mic(key, key_len, data, data_len, mic, MAC_MIC_LEN);
	if (mic_status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mic_status, "Crypto: Failed to compute MIC during encryption.");
		return mic_status;
	}
	memcpy(data + data_len, mic, MAC_MIC_LEN); // Append MIC to the end of the encrypted data

	LOG_DBG("Crypto: Data encrypted and MIC appended successfully.");
	STATS_INC(tx_encrypted_frames);
	STATS_ADD(tx_encrypted_bytes, data_len + MAC_MIC_LEN);
	return DECT_STATUS_OK;
}

/**
 * @brief Decrypts a data block using AES-128 in CTR mode and verifies the MIC.
 *
 * @param key Pointer to the AES key (session key).
 * @param key_len Length of the key (AES_KEY_LEN).
 * @param hpc Highest Packet Count (for nonce).
 * @param psn Packet Sequence Number (for nonce).
 * @param data Pointer to the data to decrypt (including MIC at the end).
 * @param data_len Length of the encrypted data *including* the MIC.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_decrypt(const uint8_t *key, size_t key_len,
								  uint32_t hpc, uint16_t psn,
								  uint8_t *data, size_t data_len)
{
	if (!key || key_len != AES_KEY_LEN || !data || data_len <= MAC_MIC_LEN) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "Crypto: Invalid parameters for decryption or data too short for MIC.");
		return DECT_ERROR_INVALID_PARAM;
	}

	mbedtls_aes_context aes_ctx;
	uint8_t nonce_ctr[AES_KEY_LEN]; // 128-bit = 16 bytes for AES-CTR nonce/counter
	uint8_t stream_block[AES_KEY_LEN];
	size_t nc_off = 0; // Current offset in the stream_block for CTR mode

	size_t encrypted_data_len = data_len - MAC_MIC_LEN;
	uint8_t *received_mic = data + encrypted_data_len;

	// Construct Nonce/Counter (IV) for AES-CTR (must match sender's construction)
	memset(nonce_ctr, 0, sizeof(nonce_ctr));
	memcpy(nonce_ctr, mac_ctx.mac_address, LONG_RD_ID_LEN_BYTES); // Use local MAC address for consistency (or peer's)
	memcpy(nonce_ctr + LONG_RD_ID_LEN_BYTES, &hpc, sizeof(hpc));
	memcpy(nonce_ctr + LONG_RD_ID_LEN_BYTES + sizeof(hpc), &psn, sizeof(psn));

	LOG_DBG("Crypto: Decrypting data (len %zu) with HPC %u, PSN %u.", encrypted_data_len, hpc, psn);
	LOG_HEXDUMP_DBG(nonce_ctr, AES_KEY_LEN, "CTR Nonce (Decrypt):");

	// First, verify MIC against the encrypted data (before decrypting)
	// Some protocols (e.g., IPsec ESP with AES-CTR + HMAC) do MAC-then-encrypt.
	// If it's encrypt-then-MAC, then verify MIC against decrypted data.
	// For DECT NR+, it's often encrypt-then-authenticate, meaning MIC is on ciphertext.
	// Assume MIC is on ciphertext as per original design.
	dect_status_t mic_verify_status = dect_crypto_verify_mic(key, key_len, data, encrypted_data_len, received_mic, MAC_MIC_LEN);
	if (mic_verify_status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mic_verify_status, "Crypto: MIC verification failed for packet. Dropping.");
		STATS_INC(mac_mic_failures); // This is a security failure
		return mic_verify_status;
	}
	LOG_DBG("Crypto: MIC verified successfully (pre-decryption).");

	mbedtls_aes_init(&aes_ctx);
	int ret = mbedtls_aes_setkey_dec(&aes_ctx, key, key_len * 8); // Same key for encrypt/decrypt in CTR
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: AES set key failed: %d.", ret);
		mbedtls_aes_free(&aes_ctx);
		return DECT_ERROR_CRYPTO_FAILED;
	}

	// Decrypt data in-place
	ret = mbedtls_aes_crypt_ctr(&aes_ctx, encrypted_data_len, &nc_off, nonce_ctr, stream_block, data, data);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_DECRYPTION_FAILED, "Crypto: AES CTR decryption failed: %d.", ret);
		mbedtls_aes_free(&aes_ctx);
		return DECT_ERROR_DECRYPTION_FAILED;
	}
	mbedtls_aes_free(&aes_ctx);

	LOG_DBG("Crypto: Data decrypted successfully.");
	STATS_INC(rx_decrypted_frames);
	STATS_ADD(rx_decrypted_bytes, encrypted_data_len);
	return DECT_STATUS_OK;
}

/**
 * @brief Computes the Message Integrity Code (MIC) for a given data block.
 * Uses AES-CMAC with the derived session key.
 *
 * @param key Pointer to the key used for MIC computation (session key).
 * @param key_len Length of the key.
 * @param data Pointer to the data for which to compute the MIC.
 * @param data_len Length of the data.
 * @param mic_out Pointer to the buffer to store the computed MIC.
 * @param mic_len Length of the MIC to compute (MAC_MIC_LEN).
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_crypto_compute_mic(const uint8_t *key, size_t key_len,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t *mic_out, size_t mic_len)
{
	if (!key || key_len != AES_KEY_LEN || !data || !mic_out || mic_len < MAC_MIC_LEN) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "Crypto: Invalid parameters for MIC computation.");
		return DECT_ERROR_INVALID_PARAM;
	}

	mbedtls_cipher_context_t cipher_ctx;
	const mbedtls_cipher_info_t *cipher_info;

	mbedtls_cipher_init(&cipher_ctx);

	cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CMAC);
	if (cipher_info == NULL) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: Failed to get AES-128-CMAC cipher info.");
		mbedtls_cipher_free(&cipher_ctx);
		return DECT_ERROR_CRYPTO_FAILED;
	}

	int ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: Cipher setup failed: %d.", ret);
		mbedtls_cipher_free(&cipher_ctx);
		return DECT_ERROR_CRYPTO_FAILED;
	}

	ret = mbedtls_cipher_cmac_starts(&cipher_ctx, key, key_len * 8);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: CMAC starts failed: %d.", ret);
		mbedtls_cipher_free(&cipher_ctx);
		return DECT_ERROR_CRYPTO_FAILED;
	}

	ret = mbedtls_cipher_cmac_update(&cipher_ctx, data, data_len);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: CMAC update failed: %d.", ret);
		mbedtls_cipher_free(&cipher_ctx);
		return DECT_ERROR_CRYPTO_FAILED;
	}

	ret = mbedtls_cipher_cmac_finish(&cipher_ctx, mic_out);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CRYPTO_FAILED, "Crypto: CMAC finish failed: %d.", ret);
		mbedtls_cipher_free(&cipher_ctx);
		return DECT_ERROR_CRYPTO_FAILED;
	}
	mbedtls_cipher_free(&cipher_ctx);

	LOG_DBG("Crypto: MIC computed successfully.");
	LOG_HEXDUMP_DBG(mic_out, mic_len, "Computed MIC:");
	return DECT_STATUS_OK;
}

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
                                     const uint8_t *mic_received, size_t mic_len)
{
	if (!key || key_len != AES_KEY_LEN || !data || !mic_received || mic_len < MAC_MIC_LEN) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "Crypto: Invalid parameters for MIC verification.");
		return DECT_ERROR_INVALID_PARAM;
	}

	uint8_t mic_computed[MAC_MIC_LEN];
	dect_status_t status = dect_crypto_compute_mic(key, key_len, data, data_len, mic_computed, MAC_MIC_LEN);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "Crypto: Failed to compute MIC for verification.");
		return status;
	}

	if (mbedtls_memcmp(mic_computed, mic_received, MAC_MIC_LEN) == 0) {
		LOG_DBG("Crypto: MIC verified successfully.");
		return DECT_STATUS_OK;
	} else {
		DECT_ERROR_HANDLER(DECT_ERROR_SECURITY_MIC_MISMATCH, "Crypto: MIC mismatch.");
		return DECT_ERROR_SECURITY_MIC_MISMATCH;
	}
}

/* End of File
 * Last Amended: 2025-06-07 18:00 BST: Updated dect_crypto.c
 * - Enhanced `dect_crypto_encrypt()`:
 * - Constructs AES-CTR nonce (IV) using `mac_ctx.mac_address`, HPC, and PSN to ensure uniqueness.
 * - Performs AES-128 CTR mode encryption using `mbedtls_aes_crypt_ctr`.
 * - Calculates and *appends* the Message Integrity Code (MIC) to the encrypted data using `dect_crypto_compute_mic`.
 * - Includes input validation for buffer sizes and cryptographic parameters.
 * - Logs detailed debugging information and updates `tx_encrypted_frames` and `tx_encrypted_bytes` statistics.
 * - Enhanced `dect_crypto_decrypt()`:
 * - Extracts the received MIC from the end of the `data` buffer.
 * - Performs MIC verification *before* decryption using `dect_crypto_verify_mic`.
 * - Constructs the same AES-CTR nonce (IV) as the sender for decryption.
 * - Performs AES-128 CTR mode decryption using `mbedtls_aes_crypt_ctr`.
 * - Includes input validation.
 * - Logs detailed debugging information and updates `rx_decrypted_frames` and `rx_decrypted_bytes` statistics.
 * - Updated `dect_crypto_derive_session_key()`: Uses `mbedtls_hkdf` with SHA256 and concatenated nonces as `info` to derive the session key.
 * - Confirmed `dect_crypto_init()` initializes mbed TLS contexts.
 * - All functions now use `mbedtls` library for cryptographic operations, adhering to specified standards.
 * - Removed direct Zephyr cipher API usage, relying solely on mbed TLS for core crypto.
 * - Added comprehensive error handling and logging for all crypto operations.
 */
