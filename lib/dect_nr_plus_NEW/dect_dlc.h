/* dect_dlc/dect_dlc.h */
#ifndef DECT_DLC_H__
#define DECT_DLC_H__

#include <zephyr/kernel.h> // For k_timeout_t
#include <stdint.h>        // For uintxx_t types
#include <stddef.h>        // For size_t
#include "dect_mac_sm.h"   // For dect_mac_role_t (used by dect_stack_init)

/**
 * @brief Defines the DLC service types available to the application.
 * Based on ETSI TS 103 636-5, Clause 4.3.1.1.
 */
typedef enum {
    /** Transparent, best-effort data transfer. Relies on MAC HARQ. No DLC segmentation. */
    DLC_SERVICE_TYPE_0_TRANSPARENT,
    /** Unreliable data transfer with Segmentation and Reassembly by DLC. No DLC ARQ. */
    DLC_SERVICE_TYPE_1_SEGMENTATION,
    /** Acknowledged data transfer with end-to-end retransmissions (ARQ) by DLC. No DLC segmentation. */
    DLC_SERVICE_TYPE_2_ARQ,
    /** Acknowledged data transfer with Segmentation, Reassembly, and ARQ by DLC. */
    DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ,
    DLC_SERVICE_TYPE_COUNT
} dlc_service_type_t;

/**
 * @brief DLC PDU IE Type field values relevant to data transfer.
 * (ETSI TS 103 636-5 Table 5.3.1-1, first 4 bits of DLC PDU).
 * These define the structure of the DLC PDU header.
 */
typedef enum {
    DLC_IE_TYPE_DATA_TYPE_0_WITH_ROUTING    = 0b0000, // DLC Svc Type 0, DLC SDU contains Routing Hdr + CVG PDU
    DLC_IE_TYPE_DATA_TYPE_0_NO_ROUTING      = 0b0001, // DLC Svc Type 0, DLC SDU contains CVG PDU directly
    DLC_IE_TYPE_DATA_TYPE_123_WITH_ROUTING  = 0b0010, // DLC Svc Types 1,2,3, DLC SDU contains Routing Hdr + CVG PDU
    DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING    = 0b0011, // DLC Svc Types 1,2,3, DLC SDU contains CVG PDU directly
    DLC_IE_TYPE_TIMERS_CONFIG_CTRL          = 0b0100, // DLC Timers configuration Control IE
    DLC_IE_TYPE_DATA_TYPE_0_EXT_HDR         = 0b0101, // Type 0 data followed by DLC Extension header
    DLC_IE_TYPE_DATA_TYPE_123_EXT_HDR       = 0b0110, // Type 1/2/3 data followed by DLC Extension header
    // 0b0111 to 0b1101 are Reserved
    DLC_IE_TYPE_ESCAPE                      = 0b1110,
    DLC_IE_TYPE_RESERVED_MAX                = 0b1111, // Also Reserved by ETSI for future use
} dlc_ie_type_val_t;

/**
 * @brief DLC Segmentation Indication (SI) field.
 * (ETSI TS 103 636-5 Table 5.3.3.1-1, bits 5-4 of first octet for Type 1/2/3 PDUs if IE Type uses 4 MSB).
 * Note: ETSI table uses bits 3-2. If IE Type is 4 bits, SI is bits 5-4.
 * Let's assume IE Type is indeed 4 bits, so SI is bits 5-4 (0-indexed from MSB: bit0=MSB).
 * Octet1: [IE Type (4b) | SI (2b) | SN_ms2b (2b)]
 */
typedef enum {
    DLC_SI_COMPLETE_SDU     = 0b00,
    DLC_SI_FIRST_SEGMENT    = 0b01,
    DLC_SI_LAST_SEGMENT     = 0b10,
    DLC_SI_MIDDLE_SEGMENT   = 0b11,
} dlc_segmentation_indication_t;

/**
 * @brief DLC Header for Type 0 (Transparent) PDUs.
 * Total 1 octet. (ETSI TS 103 636-5, Figure 5.3.2-1).
 * The DLC SDU (which is CVG PDU or CVG PDU + DLC Routing Header) immediately follows.
 */
typedef struct {
    uint8_t ie_type_val_reserved; // Bits 7-4: IE Type, Bits 3-0: Reserved
} __attribute__((packed)) dect_dlc_header_type0_t;

// Helper to set/get fields for dect_dlc_header_type0_t
static inline void dlc_hdr_type0_set(dect_dlc_header_type0_t *hdr, dlc_ie_type_val_t type) {
    hdr->ie_type_val_reserved = ((uint8_t)type & 0x0F) << 4; // Reserved bits are 0
}
static inline dlc_ie_type_val_t dlc_hdr_type0_get_type(const dect_dlc_header_type0_t *hdr) {
    return (dlc_ie_type_val_t)((hdr->ie_type_val_reserved >> 4) & 0x0F);
}


/**
 * @brief DLC Header for Type 1, 2, 3 PDUs (unsegmented: SI=00, or first segment: SI=01).
 * Total 2 octets. (ETSI TS 103 636-5, Figure 5.3.3.1-1).
 * The DLC SDU (or first segment of DLC SDU) immediately follows.
 * Octet 1: [IE Type (4b) | SI (2b) | SN_ms2b (2b)]
 * Octet 2: [SN_ls8b (8b)]
 */
typedef struct {
    uint8_t ie_type_si_sn_msb;
    uint8_t sequence_number_lsb;
} __attribute__((packed)) dect_dlc_header_type123_basic_t;

// Helpers for dect_dlc_header_type123_basic_t
static inline void dlc_hdr_t123_basic_set(dect_dlc_header_type123_basic_t *hdr, dlc_ie_type_val_t type,
                                         dlc_segmentation_indication_t si, uint16_t sn_10bit) {
    hdr->ie_type_si_sn_msb = (((uint8_t)type & 0x0F) << 4) |
                             (((uint8_t)si & 0x03) << 2) |
                             ((uint8_t)((sn_10bit >> 8) & 0x03));
    hdr->sequence_number_lsb = (uint8_t)(sn_10bit & 0xFF);
}
static inline dlc_ie_type_val_t dlc_hdr_t123_basic_get_type(const dect_dlc_header_type123_basic_t *hdr) {
    return (dlc_ie_type_val_t)((hdr->ie_type_si_sn_msb >> 4) & 0x0F);
}
static inline dlc_segmentation_indication_t dlc_hdr_t123_basic_get_si(const dect_dlc_header_type123_basic_t *hdr) {
    return (dlc_segmentation_indication_t)((hdr->ie_type_si_sn_msb >> 2) & 0x03);
}
static inline uint16_t dlc_hdr_t123_basic_get_sn(const dect_dlc_header_type123_basic_t *hdr) {
    return (uint16_t)(((hdr->ie_type_si_sn_msb & 0x03) << 8) | hdr->sequence_number_lsb);
}


/**
 * @brief DLC Header for Type 1 or Type 3 PDUs (middle segment: SI=11, or last segment: SI=10).
 * Total 4 octets. (ETSI TS 103 636-5, Figure 5.3.3.1-2).
 * The DLC SDU segment immediately follows.
 * Octets 3-4: Segmentation Offset (Big Endian on air)
 */
typedef struct {
    uint8_t ie_type_si_sn_msb;
    uint8_t sequence_number_lsb;
    uint16_t segmentation_offset_be; // Big Endian
} __attribute__((packed)) dect_dlc_header_type13_segmented_t;

// Helpers for dect_dlc_header_type13_segmented_t (setters similar to basic, plus offset)
static inline void dlc_hdr_t13_segmented_set(dect_dlc_header_type13_segmented_t *hdr, dlc_ie_type_val_t type,
                                            dlc_segmentation_indication_t si, uint16_t sn_10bit, uint16_t seg_offset) {
    hdr->ie_type_si_sn_msb = (((uint8_t)type & 0x0F) << 4) |
                             (((uint8_t)si & 0x03) << 2) |
                             ((uint8_t)((sn_10bit >> 8) & 0x03));
    hdr->sequence_number_lsb = (uint8_t)(sn_10bit & 0xFF);
    hdr->segmentation_offset_be = sys_cpu_to_be16(seg_offset);
}
// Getters for type, SI, SN are same as basic.
static inline uint16_t dlc_hdr_t13_segmented_get_offset(const dect_dlc_header_type13_segmented_t *hdr) {
    return sys_be16_to_cpu(hdr->segmentation_offset_be);
}


/**
 * @brief Initializes the entire DECT stack (DLC and MAC layers).
 *
 * This function handles provisioning the device's unique ID from hardware (if not provided by caller)
 * and setting up all underlying layers (MAC Core, MAC Data Path, MAC PHY Interface).
 * It must be called once at boot by the application before any other DECT functions.
 *
 * @param role The operational role for this device (PT or FT).
 * @param provisioned_long_rd_id The 32-bit Long RD ID for this device.
 *                               If 0, the stack will attempt to derive one from the hardware ID.
 *                               Must not be 0xFFFFFFFF (broadcast).
 * @return 0 on success, or a negative error code.
 */
int dect_stack_init(dect_mac_role_t role, uint32_t provisioned_long_rd_id);

/**
 * @brief Sends application data (which forms a CVG PDU payload from DLC's perspective)
 *        over the DECT link using a specific DLC service.
 *
 * This function will handle necessary DLC procedures, including prepending appropriate DLC headers
 * and potentially segmenting the data if the selected DLC service type involves
 * segmentation and the data is too large for a single MAC SDU (DLC PDU).
 * The data provided is considered the DLC SDU payload (e.g., a CVG PDU or an IP packet if CVG is bypassed).
 *
 * @param service The DLC service type to use for this data transmission.
 * @param dlc_sdu_payload Pointer to the application data payload (e.g., a CVG PDU).
 * @param dlc_sdu_payload_len Length of the data payload.
 * @return 0 on success (data queued to MAC).
 * @retval -EINVAL If service type is invalid, data is NULL, or length is invalid.
 * @retval -ENOMEM If a MAC SDU buffer cannot be allocated for transmission.
 * @retval -EMSGSIZE If dlc_sdu_payload is too large for an unsegmented service type,
 *                   or if segmentation is required but fails (e.g., too many segments).
 *                   (Currently, segmentation is a TODO).
 */
int dlc_send_data(dlc_service_type_t service, const uint8_t *dlc_sdu_payload, size_t dlc_sdu_payload_len);

/**
 * @brief Receives application data (CVG PDU payload from DLC's perspective) from the DECT stack.
 *
 * This function is blocking and should typically be called from a dedicated application thread
 * that processes incoming data. It retrieves a complete, reassembled Service Data Unit payload
 * (e.g., a CVG PDU) from the DLC layer, providing the data and its original DLC service type.
 *
 * @param service_type_out Pointer to store the DLC service type of the received data.
 * @param app_level_payload_buf Buffer to store the incoming data payload.
 * @param app_level_payload_len_inout Pointer to a size_t variable.
 *                                    On input, it must contain the maximum size of `app_level_payload_buf`.
 *                                    On successful return, it will contain the actual length of the received payload.
 * @param timeout The maximum time to wait for incoming data. Use K_FOREVER to wait
 *                indefinitely, K_NO_WAIT for non-blocking.
 * @return 0 on success.
 * @retval -EINVAL If any pointer arguments are NULL.
 * @retval -EMSGSIZE If the provided `app_level_payload_buf` is too small to hold the received
 *                   data. `*app_level_payload_len_inout` will be updated with the required size.
 * @retval -EAGAIN If the operation timed out (K_NO_WAIT and no data, or `timeout` expired).
 * @retval Other negative error codes for internal issues.
 */
int dlc_receive_data(dlc_service_type_t *service_type_out, uint8_t *app_level_payload_buf, size_t *app_level_payload_len_inout, k_timeout_t timeout);

#endif /* DECT_DLC_H__ */