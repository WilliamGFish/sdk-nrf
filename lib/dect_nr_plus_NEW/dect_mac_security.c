/* dect_mac/dect_mac_security.c */
#include <zephyr/logging/log.h>
#include <zephyr/crypto/crypto.h> // For Zephyr Crypto API
#include <zephyr/sys/byteorder.h> // For sys_put_be32, sys_cpu_to_be16, sys_be16_to_cpu etc.
#include <string.h>               // For memcpy, memset

#include "dect_mac_security.h"

LOG_MODULE_REGISTER(dect_mac_security, CONFIG_DECT_MAC_SECURITY_LOG_LEVEL);

// Global device handle for the Zephyr crypto driver.
// Ensure a PSA-based crypto driver is enabled, e.g., CONFIG_PSA_CRYPTO_DRIVER_CC3XX for nRF91.
// If using legacy crypto: DEVICE_DT_GET(DT_CHOSEN(zephyr_crypto_aes_ctr_cc3xx)) etc.
// For PSA, it's usually simpler as PSA API abstracts specific HW.
// However, direct Zephyr crypto API (cipher_begin_session) is used here, not PSA client API.
#if defined(CONFIG_CRYPTO_NRF_CC3XX_PSA) || defined(CONFIG_CRYPTO_MBEDTLS_PSA)
// If PSA is the backend for the legacy Zephyr crypto API
static const struct device *const g_crypto_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_crypto));
#else
// Fallback or specific non-PSA driver if needed
static const struct device *const g_crypto_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_crypto));
#endif


void security_build_iv(uint8_t *iv_out,
                       uint32_t transmitter_long_rd_id,
                       uint32_t receiver_long_rd_id,
                       uint32_t hpc,
                       uint16_t psn) // PSN is 12-bit
{
    if (!iv_out) {
        LOG_ERR("IV Build: Output buffer is NULL.");
        return;
    }
    // As per ETSI TS 103 636-4, Table 5.9.1.3-1
    // All fields are Big Endian in the IV.

    // Octets 0-3: Long RD ID of the transmitter
    sys_put_be32(transmitter_long_rd_id, &iv_out[0]);

    // Octets 4-7: Long RD ID of the receiver
    sys_put_be32(receiver_long_rd_id, &iv_out[4]);

    // Octets 8-11: Hyper Packet Counter (HPC)
    sys_put_be32(hpc, &iv_out[8]);

    // Octets 12-13: Packet Sequence Number (PSN) (12 MSBs) + Initial Counter Block (4 LSBs = 0)
    // PSN is 12 bits. It occupies bits 15-4 of this 16-bit field (0-indexed from MSB of the 16-bit field).
    // The 4 LSBs (bits 3-0) are part of the CTR mode's initial counter block, set to 0.
    uint16_t psn_field_value = (psn & 0x0FFF) << 4; // Shift PSN left by 4, LSBs become 0
    sys_put_be16(psn_field_value, &iv_out[12]);

    // Octets 14-15: Ciphering engine internal byte counter (for CTR mode).
    // Initialized to 0 for the first 16-byte block of the PDU.
    iv_out[14] = 0;
    iv_out[15] = 0;
}

int security_calculate_mic(const uint8_t *pdu_data_for_mic,
                           size_t pdu_data_len,
                           const uint8_t *integrity_key, /* 16 bytes */
                           uint8_t *mic_out_5_bytes)
{
    if (!pdu_data_for_mic || pdu_data_len == 0 || !integrity_key || !mic_out_5_bytes) {
        LOG_ERR("MIC Calc: Invalid parameters (NULL ptrs or zero len).");
        return -EINVAL;
    }
    if (!device_is_ready(g_crypto_dev)) {
        LOG_ERR("MIC Calc: Crypto device (%s) is not ready.", g_crypto_dev->name);
        return -ENODEV;
    }

    uint8_t full_mic_tag[16]; // AES-CMAC produces a 16-byte tag
    struct cipher_ctx crypto_session_ctx; // Zero-init not strictly necessary if all fields are set.
    int err;

    // Initialize context for CMAC
    crypto_session_ctx.keylen = 16; // AES-128
    crypto_session_ctx.key.bit_stream = (uint8_t *)integrity_key; // Use const_cast if key is truly const and API needs non-const
    crypto_session_ctx.flags = CAP_RAW_KEY; // Indicates key.bit_stream is the raw key material

    err = cipher_begin_session(g_crypto_dev, &crypto_session_ctx, CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_CMAC, CRYPTO_CIPHER_OP_MAC);
    if (err != 0) {
        LOG_ERR("MIC Calc: Failed to begin AES-CMAC session, err: %d", err);
        return err;
    }

    // According to Zephyr API, for CMAC, all data should be passed in one go if possible,
    // or using cipher_mac_update and then cipher_mac_final.
    // If cipher_mac_op is used, it combines update and final.
    // Let's use update + final for clarity.

    struct mac_params cmac_params;
    cmac_params.tag = full_mic_tag;
    cmac_params.tag_len = sizeof(full_mic_tag); // Size of buffer for the full tag

    err = cipher_mac_update(&crypto_session_ctx, pdu_data_for_mic, pdu_data_len);
    if (err != 0) {
        LOG_ERR("MIC Calc: Failed to perform AES-CMAC update, err: %d", err);
        cipher_free_session(g_crypto_dev, &crypto_session_ctx);
        return err;
    }

    err = cipher_mac_final(&crypto_session_ctx, &cmac_params);
    if (err != 0) {
        LOG_ERR("MIC Calc: Failed to finalize AES-CMAC, err: %d", err);
        cipher_free_session(g_crypto_dev, &crypto_session_ctx);
        return err;
    }

    cipher_free_session(g_crypto_dev, &crypto_session_ctx);

    // Truncate the full 16-byte MIC to the 5 bytes required by ETSI spec.
    memcpy(mic_out_5_bytes, full_mic_tag, 5);

    return 0;
}

int security_crypt_payload(uint8_t *payload_in_out,
                           size_t len,
                           const uint8_t *cipher_key, /* 16 bytes */
                           uint8_t *iv,               /* 16 bytes, will be modified by CTR op */
                           bool encrypt)
{
    if (!payload_in_out || (len > 0 && !iv) || !cipher_key) {
        LOG_ERR("Crypt: Invalid parameters (NULL ptrs).");
        return -EINVAL;
    }
    if (len == 0) {
        return 0; // Nothing to encrypt/decrypt
    }
    if (!device_is_ready(g_crypto_dev)) {
        LOG_ERR("Crypt: Crypto device (%s) is not ready.", g_crypto_dev->name);
        return -ENODEV;
    }

    struct cipher_ctx crypto_session_ctx;
    int err;
    enum cipher_operator op_mode = encrypt ? CRYPTO_CIPHER_OP_ENCRYPT : CRYPTO_CIPHER_OP_DECRYPT;

    crypto_session_ctx.keylen = 16; // AES-128
    crypto_session_ctx.key.bit_stream = (uint8_t *)cipher_key;
    crypto_session_ctx.flags = CAP_RAW_KEY | CAP_INPLACE_OPS; // Enable in-place operation

    err = cipher_begin_session(g_crypto_dev, &crypto_session_ctx, CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_CTR, op_mode);
    if (err != 0) {
        LOG_ERR("Crypt: Failed to begin AES-CTR session (op: %s), err: %d",
                encrypt ? "encrypt" : "decrypt", err);
        return err;
    }

    // Perform the CTR operation. The IV is passed and will be updated by the driver.
    // The `cipher_ctr_op` expects `in_buf` and `out_buf`. For in-place, they are the same.
    err = cipher_pkt_op(&crypto_session_ctx, &(struct cipher_pkt){
                                                .in_buf = payload_in_out,
                                                .in_len = len,
                                                .out_buf = payload_in_out, // In-place
                                                .out_buf_max = len
                                            },
                        iv); // Pass IV here for CTR mode

    if (err != 0) {
        LOG_ERR("Crypt: Failed to perform AES-CTR operation (op: %s), err: %d",
                encrypt ? "encrypt" : "decrypt", err);
        // No session to free explicitly if cipher_pkt_op was used, as it's stateless after begin_session
        // However, if begin_session was stateful, free it.
        // The Zephyr API implies begin_session creates context, so free is needed.
        cipher_free_session(g_crypto_dev, &crypto_session_ctx);
        return err;
    }

    // No explicit cipher_update_iv or cipher_final for pkt_op with CTR.
    // The IV is updated by the driver.
    cipher_free_session(g_crypto_dev, &crypto_session_ctx);

    return 0;
}

int security_derive_session_keys_from_psk(const uint8_t *master_key,
                                          uint8_t *out_session_integrity_key,
                                          uint8_t *out_session_cipher_key)
{
    if (!master_key || !out_session_integrity_key || !out_session_cipher_key) {
        return -EINVAL;
    }

    // VERY SIMPLISTIC "KDF" - DO NOT USE IN PRODUCTION
    // Integrity Key = Master Key
    memcpy(out_session_integrity_key, master_key, 16);

    // Cipher Key = Master Key XORed with a fixed pattern (e.g., 0xFF...)
    // This ensures integrity and cipher keys are different but easily derived.
    for (int i = 0; i < 16; i++) {
        out_session_cipher_key[i] = master_key[i] ^ 0xFF;
    }
    // LOG_WRN("SECURITY_KDF: Using INSECURE placeholder KDF for session keys from PSK.");
    return 0;
}