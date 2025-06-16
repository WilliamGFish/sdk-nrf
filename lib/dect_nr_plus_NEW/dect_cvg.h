/* dect_cvg/dect_cvg.h */
#ifndef DECT_CVG_H__
#define DECT_CVG_H__

#include <zephyr/kernel.h>
#include <stdint.h>
#include <stddef.h>

/**
 * @file dect_cvg.h
 * @brief Public API and definitions for the DECT NR+ Convergence (CVG) Layer.
 *
 * This layer sits between the application and the DLC layer, providing end-to-end
 * services. This initial implementation focuses on the transparent service type.
 * Based on ETSI TS 103 636-5, Clause 6.
 */

/**
 * @brief CVG Service Types. (ETSI TS 103 636-5, Table 6.2.2.1-1)
 *
 * Defines the services the CVG layer can provide to the application.
 */
typedef enum {
    /** Transparent, best-effort data transfer. No CVG-level sequencing or ARQ. */
    CVG_SERVICE_TYPE_0_TRANSPARENT,
    /** Simple sequence numbering for out-of-order detection and duplicate removal. */
    CVG_SERVICE_TYPE_1_SEQ_NUM,
    /** CVG-level segmentation and reassembly. */
    CVG_SERVICE_TYPE_2_SAR,
    /** Flow Control. */
    CVG_SERVICE_TYPE_3_FC,
    /** Flow Control and ARQ. */
    CVG_SERVICE_TYPE_4_FC_ARQ,
    CVG_SERVICE_TYPE_COUNT
} cvg_service_type_t;


/**
 * @name CVG Header Structures and Helpers
 * @{
 * Definitions for the CVG common header as per ETSI TS 103 636-5, Clause 6.3.2.
 */

/**
 * @brief CVG Header Length Extension field (CVG Ext).
 * (ETSI TS 103 636-5, Table 6.3.2-1, bits 7-6 of first octet).
 */
typedef enum {
    CVG_EXT_NO_LEN_FIELD    = 0b00,
    CVG_EXT_8BIT_LEN_FIELD  = 0b01,
    CVG_EXT_16BIT_LEN_FIELD = 0b10,
    CVG_EXT_RESERVED        = 0b11,
} cvg_header_ext_len_t;

/**
 * @brief CVG Header Format 2 Coding (F2C) field.
 * (ETSI TS 103 636-5, Table 6.3.2-3). Used when MT bit is 1.
 */
typedef enum {
    CVG_F2C_DATA_IE         = 0b00,
    CVG_F2C_ARQ_FEEDBACK_IE = 0b01,
    CVG_F2C_USE_IE_TYPE     = 0b10, // Indicates a second octet with CVG IE Type is present
    CVG_F2C_RESERVED        = 0b11,
} cvg_header_f2c_t;

/**
 * @brief CVG IE Type field values for Header Format 1 or Format 2 (with F2C=10).
 * (ETSI TS 103 636-5, Table 6.3.2-2, 5-bit field).
 */
typedef enum {
    CVG_IE_TYPE_EP_MUX          = 0b00000,
    CVG_IE_TYPE_DATA            = 0b00001,
    CVG_IE_TYPE_DATA_EP         = 0b00010,
    CVG_IE_TYPE_DATA_TRANSPARENT= 0b00011,
    CVG_IE_TYPE_SECURITY        = 0b00100,
    CVG_IE_TYPE_TX_SERVICES_CFG = 0b00101,
    CVG_IE_TYPE_ARQ_FEEDBACK    = 0b00110,
    CVG_IE_TYPE_ARQ_POLL        = 0b00111,
    CVG_IE_TYPE_FLOW_STATUS     = 0b01000,
} cvg_ie_type_t;

/**
 * @brief CVG Segmentation Indication (SI) field.
 * (ETSI TS 103 636-5, Table 6.3.4-1, part of the octet after CVG header in Data IE).
 */
typedef enum {
    CVG_SI_COMPLETE_SDU     = 0b00,
    CVG_SI_FIRST_SEGMENT    = 0b01,
    CVG_SI_LAST_SEGMENT     = 0b10,
    CVG_SI_MIDDLE_SEGMENT   = 0b11,
} cvg_segmentation_indication_t;

/**
 * @name CVG Information Element Structures
 * @{
 * Definitions for specific CVG IEs that follow the CVG Header.
 */

/**
 * @brief CVG Endpoint Mux IE structure. Fixed size.
 * (ETSI TS 103 636-5, Figure 6.3.3-1).
 * Used to select a specific data flow/endpoint.
 */
typedef struct {
    cvg_header_t header;
    uint16_t endpoint_mux_be; // Big Endian on air
} __attribute__((packed)) cvg_ie_ep_mux_t;


/**
 * @brief CVG Data IE "base" structure. Variable size.
 * (ETSI TS 103 636-5, Figure 6.3.4-1).
 * This struct represents the fields immediately following the CVG header.
 * Optional fields (SDU Length, Segmentation Offset) and the payload follow this base.
 */
typedef struct {
    uint8_t si_sli_resv_sn_msb;   // SI(2b)|SLI(1b)|Resv(1b)|SN(4b, msb)
    uint8_t sequence_number_lsb;  // SN(8b, lsb)
} __attribute__((packed)) cvg_ie_data_base_t;

// --- Helpers for cvg_ie_data_base_t ---
static inline void cvg_ie_data_base_set(cvg_ie_data_base_t *base, cvg_segmentation_indication_t si,
                                        bool sli, uint16_t sn_12bit) {
    base->si_sli_resv_sn_msb = (((uint8_t)si & 0x03) << 6) |
                               ((sli ? 1 : 0) << 5) |
                               (((uint8_t)(sn_12bit >> 8) & 0x0F)); // SN ms4b are in bits 3-0
    base->sequence_number_lsb = (uint8_t)(sn_12bit & 0xFF);
}
static inline cvg_segmentation_indication_t cvg_ie_data_base_get_si(const cvg_ie_data_base_t *base) {
    return (cvg_segmentation_indication_t)((base->si_sli_resv_sn_msb >> 6) & 0x03);
}
static inline bool cvg_ie_data_base_get_sli(const cvg_ie_data_base_t *base) {
    return (base->si_sli_resv_sn_msb >> 5) & 0x01;
}
static inline uint16_t cvg_ie_data_base_get_sn(const cvg_ie_data_base_t *base) {
    return (uint16_t)(((base->si_sli_resv_sn_msb & 0x0F) << 8) | base->sequence_number_lsb);
}


/**
 * @brief CVG Data EP IE "base" structure. Variable size.
 * (ETSI TS 103 636-5, Figure 6.3.5-1).
 * Combines an Endpoint Mux field with the Data IE fields.
 */
typedef struct {
    uint16_t endpoint_mux_be;
    cvg_ie_data_base_t data_base;
} __attribute__((packed)) cvg_ie_data_ep_base_t;


/** @} */

/**
 * @brief CVG Header base structure (first octet).
 * This represents the common first byte of any CVG IE.
 */
typedef struct {
    uint8_t ext_mt_f2c_or_type;
} __attribute__((packed)) cvg_header_t;

/**
 * @brief Initializes the CVG layer and all layers below it (DLC, MAC).
 *
 * This function orchestrates the startup of the DECT stack. It must be called
 * once by the application before any other CVG or DECT functions.
 * Internally, it will call initialization functions for DLC and MAC.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int dect_cvg_init(void);

/**
 * @brief Sends application data through the DECT stack.
 *
 * This function takes a raw application payload (SDU), wraps it in the appropriate
 * CVG headers and IEs based on the selected service, and passes it to the DLC layer
 * for transmission. This function is non-blocking and queues the data for sending
 * by a dedicated CVG TX thread.
 *
 * @param service The CVG service type to use for this data transmission.
 * @param app_sdu Pointer to the application data payload.
 * @param app_sdu_len Length of the data payload.
 * @return 0 if data was successfully queued for transmission.
 * @retval -ENOMEM If the TX queue is full.
 * @retval -EINVAL If parameters are invalid.
 * @retval -EMSGSIZE If the payload is too large for the transport buffer.
 */
int dect_cvg_send(cvg_service_type_t service, const uint8_t *app_sdu, size_t app_sdu_len);

/**
 * @brief Receives application data from the DECT stack.
 *
 * This function is blocking and retrieves a complete application payload (SDU) that
 * has been received and processed by the CVG layer.
 *
 * @param app_sdu_buf Buffer to store the incoming data payload.
 * @param len_inout Pointer to a size_t variable.
 *                  On input, it must contain the maximum size of `app_sdu_buf`.
 *                  On successful return, it will contain the actual length of the received payload.
 * @param timeout The maximum time to wait for incoming data. Use K_FOREVER to wait
 *                indefinitely, K_NO_WAIT for non-blocking.
 * @return 0 on success.
 * @retval -EINVAL If any pointer arguments are NULL.
 * @retval -EMSGSIZE If the provided `app_sdu_buf` is too small to hold the received
 *                   data. `*len_inout` will be updated with the required size.
 * @retval -EAGAIN If the operation timed out.
 */
int dect_cvg_receive(uint8_t *app_sdu_buf, size_t *len_inout, k_timeout_t timeout);


#endif /* DECT_CVG_H__ */