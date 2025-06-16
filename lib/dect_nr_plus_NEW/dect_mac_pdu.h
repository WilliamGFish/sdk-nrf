/* dect_mac/dect_mac_pdu.h */
#ifndef DECT_MAC_PDU_H__
#define DECT_MAC_PDU_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h> // For size_t

// Include context types if they define structures used here (like IE field structs)
// This will pull in dect_mac_cluster_beacon_ie_fields_t, etc.
// Assumes dect_mac_context.h includes or defines dect_mac_context_types.h which has these.
// If not, they need to be defined here or in a specific dect_mac_pdu_types.h.
// For now, assume they become visible via dect_mac_context.h or a similar include path.
#include "dect_mac_context.h" // This should bring in the IE field structures

// --- MAC Header Type (First Octet of MAC PDU - ETSI TS 103 636-4, 6.3.2) ---
typedef enum {
    MAC_SECURITY_NONE           = 0b00,
    MAC_SECURITY_USED_NO_IE     = 0b01,
    MAC_SECURITY_USED_WITH_IE   = 0b10,
    MAC_SECURITY_RESERVED       = 0b11,
} dect_mac_security_mode_t;

typedef enum { // ETSI Table 6.3.2-2
    MAC_COMMON_HEADER_TYPE_DATA_PDU     = 0b0000,
    MAC_COMMON_HEADER_TYPE_BEACON       = 0b0001,
    MAC_COMMON_HEADER_TYPE_UNICAST      = 0b0010,
    MAC_COMMON_HEADER_TYPE_RD_BROADCAST = 0b0011,
    // 0b0100 to 0b1110 are Reserved or for specific control messages not detailed here yet
    MAC_COMMON_HEADER_TYPE_ESCAPE       = 0b1111,
} dect_mac_common_header_type_val_t;

typedef struct {
    dect_mac_common_header_type_val_t mac_header_type : 4;
    dect_mac_security_mode_t mac_security         : 2;
    uint8_t version                       : 2; // e.g., 00 for Release 2 of ETSI Part 4
} __attribute__((packed)) dect_mac_header_type_octet_t;


// --- MAC Common Headers (Follows MAC Header Type Octet - ETSI 6.3.3) ---
typedef struct { // ETSI 6.3.3.1 - DATA MAC PDU header
    uint8_t sequence_num_high : 4; // Bits 7-4 of first octet (PSN bits 11-8)
    bool reset_bit            : 1; // Bit 3
    uint8_t reserved          : 3; // Bits 2-0 (Set to 0)
    uint8_t sequence_num_low;      // Second octet (PSN bits 7-0)
} __attribute__((packed)) dect_mac_data_pdu_header_t;

typedef struct { // ETSI 6.3.3.2 - Beacon Header
    uint8_t network_id_ms24[3];          // Most significant 24 bits of Network ID (Big Endian on air)
    uint32_t transmitter_long_rd_id_be;  // Big Endian on air
} __attribute__((packed)) dect_mac_beacon_header_t;

typedef struct { // ETSI 6.3.3.3 - Unicast Header
    // First octet (PSN high bits + reset + reserved)
    uint8_t sequence_num_high_reset_rsv; // Combined for packing: SN_H(4b)|Reset(1b)|Rsv(3b)
    uint8_t sequence_num_low;            // PSN low 8 bits
    uint32_t receiver_long_rd_id_be;     // Big Endian on air
    uint32_t transmitter_long_rd_id_be;  // Big Endian on air
} __attribute__((packed)) dect_mac_unicast_header_t;

// Helper macro to set sequence_num_high_reset_rsv for Unicast/Data PDU headers
#define SET_SEQ_NUM_HIGH_RESET_RSV(psn_high_4b, reset_flag) \
    (((psn_high_4b) & 0x0F) << 4 | ((reset_flag) ? (1 << 3) : 0))

#define DECT_MAC_COMMON_HEADER_MIN_SIZE sizeof(dect_mac_data_pdu_header_t) // Smallest common header (DATA PDU)


// --- Information Element Types (MAC SDU Area Content - ETSI 6.3.4 & Table 6.3.4-2/3) ---
// (These defines are for the 6-bit IE Type field used with MAC_Ext 00, 01, 10)
#define IE_TYPE_PADDING                     0b000000
#define IE_TYPE_HIGHER_LAYER_SIG_FLOW_1     0b000001 // Example, to be mapped to actual DLC/CVG flows
#define IE_TYPE_HIGHER_LAYER_SIG_FLOW_2     0b000010
#define IE_TYPE_USER_DATA_FLOW_1            0b000011 // Example for User Data (DLC PDU)
#define IE_TYPE_USER_DATA_FLOW_2            0b000100
#define IE_TYPE_USER_DATA_FLOW_3            0b000101
#define IE_TYPE_USER_DATA_FLOW_4            0b000110
#define IE_TYPE_NETWORK_BEACON              0b001000 // Note: This is a MAC Message, not just an IE in SDU area. Beacon PDU has specific common header.
#define IE_TYPE_CLUSTER_BEACON              0b001001 // This IE is part of Beacon PDU's SDU Area
#define IE_TYPE_ASSOC_REQ                   0b001010
#define IE_TYPE_ASSOC_RESP                  0b001011
#define IE_TYPE_ASSOC_RELEASE               0b001100
#define IE_TYPE_RECONFIG_REQ                0b001101
#define IE_TYPE_RECONFIG_RESP               0b001110
#define IE_TYPE_ADDITIONAL_MAC_MSG          0b001111
#define IE_TYPE_MAC_SECURITY_INFO           0b010000
#define IE_TYPE_ROUTE_INFO                  0b010001
#define IE_TYPE_RES_ALLOC                   0b010010 // Resource Allocation IE
#define IE_TYPE_RACH_INFO                   0b010011 // Random Access Resource IE
#define IE_TYPE_RD_CAPABILITY               0b010100 // Radio Device Capability IE
#define IE_TYPE_NEIGHBOURING_INFO           0b010101
#define IE_TYPE_BROADCAST_IND               0b010110
#define IE_TYPE_GROUP_ASSIGNMENT            0b010111
#define IE_TYPE_LOAD_INFO                   0b011000
#define IE_TYPE_MEASUREMENT_REPORT          0b011001
#define IE_TYPE_SOURCE_ROUTING              0b011010
#define IE_TYPE_JOINING_BEACON_MSG          0b011011 // This is a MAC Message type, not just an IE in SDU area
#define IE_TYPE_JOINING_INFORMATION         0b011100
#define IE_TYPE_ESCAPE_TO_PROPRIETARY       0b111110 // 6-bit
#define IE_TYPE_EXTENSION                   0b111111 // 6-bit, indicates 1-byte extension for IE type

// Short IE Types (for MAC_Ext = 11, IE Type is 5 bits)
#define IE_TYPE_SHORT_PADDING               0b00000
#define IE_TYPE_SHORT_CONFIG_REQ            0b00001 // Payload 0 byte
#define IE_TYPE_SHORT_KEEP_ALIVE            0b00010 // Payload 0 byte
#define IE_TYPE_SHORT_MAC_SEC_INFO_HPC_REQ  0b10000 // Payload 0 byte

#define IE_TYPE_SHORT_RD_STATUS             0b00001 // Payload 1 byte
#define IE_TYPE_SHORT_RD_CAP_SHORT          0b00010 // Payload 1 byte
#define IE_TYPE_SHORT_ASSOC_CTRL            0b00011 // Payload 1 byte


// --- Information Element Structures (Payloads AFTER MAC Mux Header) ---
// These structs (dect_mac_assoc_req_ie_t, etc.) are defined in dect_mac_context.h (or types file)
// as they are also used by context and SMs.

// MAC Security Info IE Payload (ETSI 6.4.3.1) - This one is specific to PDU module
typedef struct {
    // Octet 0: Version (2b) | Key Index (3b) | Security IV Type (3b)
    uint8_t version_keyidx_secivtype;
    uint32_t hpc_be; // Hyper Packet Counter (Big Endian on air)
} __attribute__((packed)) dect_mac_security_info_ie_payload_t;

// Bitfield masks and shifts for dect_mac_security_info_ie_payload_t.version_keyidx_secivtype
#define MAC_SEC_IE_VERSION_SHIFT     6
#define MAC_SEC_IE_VERSION_MASK      (0x03 << MAC_SEC_IE_VERSION_SHIFT)
#define MAC_SEC_IE_KEYIDX_SHIFT      3
#define MAC_SEC_IE_KEYIDX_MASK       (0x07 << MAC_SEC_IE_KEYIDX_SHIFT)
#define MAC_SEC_IE_SECIVTYPE_SHIFT   0
#define MAC_SEC_IE_SECIVTYPE_MASK    (0x07 << MAC_SEC_IE_SECIVTYPE_SHIFT)

// Security IV Types for Mode 1 (ETSI Table 6.4.3.1-2)
#define SEC_IV_TYPE_MODE1_HPC_PROVIDED          0b000 // Current HPC is provided
#define SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE   0b001 // Request peer to send its HPC
#define SEC_IV_TYPE_MODE1_HPC_ONETIME_WITH_REQ  0b010 // One-time HPC with request (for stateless)


// --- PDU (De)Serialization Function Prototypes ---

/**
 * @brief Parses a MAC Multiplexing header.
 *
 * @param buf Pointer to the start of the MUX header.
 * @param len Remaining length of the buffer from `buf`.
 * @param out_ie_type_value Pointer to store the parsed IE Type (5 or 6 bit value).
 * @param out_ie_payload_len Pointer to store the parsed IE Payload length.
 *                           If MAC_Ext=00, this will be 0, and actual length is type-defined or to end of PDU.
 * @param out_ie_payload_ptr Pointer to be set to the start of the IE's payload.
 * @return Length of the parsed MUX header in bytes (1, 2, or 3), or negative error code.
 */
int parse_mac_mux_header(const uint8_t *buf, size_t len,
                         uint8_t *out_ie_type_value, uint16_t *out_ie_payload_len,
                         const uint8_t **out_ie_payload_ptr);

// Functions to build the SDU Area (concatenation of MUXed IEs)
int build_assoc_req_ies_area(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                             const dect_mac_assoc_req_ie_t *req_ie_fields,
                             const dect_mac_rd_capability_ie_t *cap_ie_fields);

int build_assoc_resp_sdu_area_content(uint8_t *target_sdu_area_buf, size_t target_sdu_area_max_len,
                                      const dect_mac_assoc_resp_ie_t *resp_fields,
                                      const dect_mac_rd_capability_ie_t *ft_cap_fields, // Can be NULL if NACK
                                      const dect_mac_resource_alloc_ie_fields_t *res_alloc_fields); // Can be NULL if NACK

int build_beacon_sdu_area_content(uint8_t *target_sdu_area_buf, size_t target_sdu_area_max_len,
                                  const dect_mac_cluster_beacon_ie_fields_t *cb_fields,
                                  const dect_mac_rach_info_ie_fields_t *rach_beacon_ie_fields);

int build_broadcast_indication_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                                        uint16_t paged_pt_short_id);
                                                                          
int build_keep_alive_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len);

int build_mac_security_info_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                                     uint8_t version, uint8_t key_index,
                                     uint8_t sec_iv_type, uint32_t hpc_val);

int build_user_data_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                             const uint8_t *dlc_pdu_data, uint16_t dlc_pdu_len,
                             uint8_t user_data_flow_ie_type); // e.g. IE_TYPE_USER_DATA_FLOW_1


// Functions to parse specific IE payloads (after MUX header is stripped)
int parse_cluster_beacon_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                    dect_mac_cluster_beacon_ie_fields_t *out_cb_fields);
int parse_rach_info_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                               dect_mac_rach_info_ie_fields_t *out_rach_fields);
int parse_assoc_req_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                               dect_mac_assoc_req_ie_t *out_req_fields);
int parse_assoc_resp_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                dect_mac_assoc_resp_ie_t *out_resp_fields);
int parse_rd_capability_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                   dect_mac_rd_capability_ie_t *out_cap_fields);
int parse_resource_alloc_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                    dect_mac_resource_alloc_ie_fields_t *out_ra_fields);
int parse_mac_security_info_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                       uint8_t *out_version, uint8_t *out_key_index,
                                       uint8_t *out_sec_iv_type, uint32_t *out_hpc_val);


#endif /* DECT_MAC_PDU_H__ */