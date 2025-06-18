/* dect_mac/dect_mac_pdu.c */

#include <string.h> // For memcpy, memset
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h> // For sys_put_be16, sys_get_be16, sys_put_be32, sys_be32_to_cpu
#include <zephyr/sys/util.h>     // For MIN, MAX, ARRAY_SIZE, WRITE_BIT, READ_BIT

#include "dect_mac_pdu.h"
#include "dect_mac_context.h" // For IE field structures like dect_mac_cluster_beacon_ie_fields_t

LOG_MODULE_REGISTER(dect_mac_pdu, CONFIG_DECT_MAC_PDU_LOG_LEVEL);

// --- Helper Functions for Bit Manipulation ---

// Writes num_bits from value (right-aligned) into buf at bit_offset.
// buf is an array of uint8_t. bit_offset is 0 for MSB of buf[0].
// Advances bit_offset by num_bits. Returns new bit_offset, or negative on error.
static int write_bits(uint8_t *buf, size_t buf_max_len_bytes, int current_bit_offset, uint32_t value, uint8_t num_bits) {
    if (num_bits == 0 || num_bits > 32) {
        LOG_ERR("PDU_WR_BITS: Invalid num_bits %u", num_bits);
        return -EINVAL;
    }
    if (((current_bit_offset + num_bits - 1) / 8) >= buf_max_len_bytes) {
        LOG_ERR("PDU_WR_BITS: Write exceeds buffer max_len %zu (offset %d, num_bits %u)",
                buf_max_len_bytes, current_bit_offset, num_bits);
        return -ENOMEM;
    }

    for (int i = 0; i < num_bits; i++) {
        // Extract bit from MSB side of value's relevant part
        bool bit_val = (value >> (num_bits - 1 - i)) & 0x01;
        // Calculate byte index and bit index within that byte (0=MSB)
        int byte_idx = (current_bit_offset + i) / 8;
        int bit_idx_in_byte = (current_bit_offset + i) % 8;

        WRITE_BIT(buf[byte_idx], 7 - bit_idx_in_byte, bit_val);
    }
    return current_bit_offset + num_bits;
}

// Reads num_bits from buf at bit_offset_ptr (0 for MSB of buf[0]).
// Advances *bit_offset_ptr by num_bits. Returns the read value (right-aligned).
// remaining_bits_ptr is decremented by num_bits. Returns 0 and logs error if not enough bits.
static uint32_t read_bits_adv(const uint8_t *buf, int *bit_offset_ptr, int *remaining_bits_ptr, uint8_t num_bits) {
    if (num_bits == 0 || num_bits > 32) {
        LOG_ERR("PDU_RD_BITS: Invalid num_bits %u", num_bits);
        if (remaining_bits_ptr) *remaining_bits_ptr = 0;
        return 0; // Or a specific error indicator if needed
    }
    if (*remaining_bits_ptr < num_bits) {
        LOG_ERR("PDU_RD_BITS: Not enough bits remaining (%d) to read %u bits at offset %d",
                *remaining_bits_ptr, num_bits, *bit_offset_ptr);
        *remaining_bits_ptr = 0;
        return 0;
    }

    uint32_t value = 0;
    for (int i = 0; i < num_bits; i++) {
        value <<= 1;
        int byte_idx = (*bit_offset_ptr + i) / 8;
        int bit_idx_in_byte = (*bit_offset_ptr + i) % 8;
        if (READ_BIT(buf[byte_idx], 7 - bit_idx_in_byte)) { // READ_BIT is 0-indexed from MSB
            value |= 1;
        }
    }
    *bit_offset_ptr += num_bits;
    *remaining_bits_ptr -= num_bits;
    return value;
}


// --- MAC MUX Header Functions ---
static int build_mac_mux_header_internal(uint8_t *buf, size_t buf_len,
                                         uint8_t ie_type_value, uint16_t ie_payload_len,
                                         uint8_t mac_ext_format_override)
{
    if (!buf) return -EINVAL;

    uint8_t mac_ext_bits;
    uint8_t ie_type_masked;
    int header_actual_len = 0;

    if (mac_ext_format_override == 0) { // Auto-detect
        // ETSI 6.3.4.1: value 11 for short IE (0 or 1 byte payload), otherwise 00,01,10
        if (ie_payload_len <= 1) mac_ext_bits = 0b11; // Short IE, payload 0 or 1 byte
        else if (ie_payload_len <= 255) mac_ext_bits = 0b01; // 8-bit length field
        else mac_ext_bits = 0b10; // 16-bit length field
        // Note: MAC_Ext=00 (no length field) is not auto-detected this way,
        // it must be explicitly requested if IE type defines fixed length.
        // For simplicity, auto-detect will always choose a length field if >1 byte.
        // To use MAC_Ext=00, mac_ext_format_override=1 must be used.
    } else {
        if (mac_ext_format_override < 1 || mac_ext_format_override > 4) return -EINVAL;
        mac_ext_bits = mac_ext_format_override - 1; // Map 1..4 to 0b00..0b11
    }

    if (mac_ext_bits == 0b11) { // Short IE format (MAC_Ext = 11), 5 LSB for IE Type
        if (buf_len < 1) return -ENOMEM;
        if (ie_payload_len > 1) { // Short IE can only have 0 or 1 byte payload
            LOG_ERR("MUX_BUILD: Short IE (MAC_Ext=11) requested for payload len %u (>1)", ie_payload_len);
            return -EINVAL;
        }
        ie_type_masked = ie_type_value & 0x1F; // Mask to 5 bits
        buf[0] = (mac_ext_bits << 6) | ((ie_payload_len & 0x01) << 5) | ie_type_masked;
        header_actual_len = 1;
    } else if (mac_ext_bits == 0b00) { // No length field (MAC_Ext = 00), 6 LSB for IE Type
        if (buf_len < 1) return -ENOMEM;
        ie_type_masked = ie_type_value & 0x3F; // Mask to 6 bits
        buf[0] = (mac_ext_bits << 6) | ie_type_masked;
        header_actual_len = 1;
    } else if (mac_ext_bits == 0b01) { // 8-bit length field (MAC_Ext = 01), 6 LSB for IE type
        if (buf_len < 2) return -ENOMEM;
        ie_type_masked = ie_type_value & 0x3F; // Mask to 6 bits
        buf[0] = (mac_ext_bits << 6) | ie_type_masked;
        buf[1] = (uint8_t)ie_payload_len;
        header_actual_len = 2;
    } else if (mac_ext_bits == 0b10) { // 16-bit length field (MAC_Ext = 10), 6 LSB for IE type
        if (buf_len < 3) return -ENOMEM;
        ie_type_masked = ie_type_value & 0x3F; // Mask to 6 bits
        buf[0] = (mac_ext_bits << 6) | ie_type_masked;
        sys_put_be16(ie_payload_len, &buf[1]);
        header_actual_len = 3;
    } else {
        return -EINVAL;
    }
    return header_actual_len;
}

int parse_mac_mux_header(const uint8_t *buf, size_t len,
                         uint8_t *out_ie_type_value, uint16_t *out_ie_payload_len,
                         const uint8_t **out_ie_payload_ptr)
{
    // Ensure it handles all mac_ext_bits cases (00, 01, 10, 11) correctly for length and IE type.
    if (!buf || len == 0 || !out_ie_type_value || !out_ie_payload_len || !out_ie_payload_ptr) {
        return -EINVAL;
    }
    uint8_t mac_ext_bits = (buf[0] >> 6) & 0x03;
    int parsed_header_len;

    if (mac_ext_bits == 0b11) {
        parsed_header_len = 1;
        if (len < parsed_header_len) return -EMSGSIZE;
        *out_ie_type_value = buf[0] & 0x1F;
        *out_ie_payload_len = (buf[0] >> 5) & 0x01;
    } else if (mac_ext_bits == 0b00) {
        parsed_header_len = 1;
        if (len < parsed_header_len) return -EMSGSIZE;
        *out_ie_type_value = buf[0] & 0x3F;
        *out_ie_payload_len = 0; // Length defined by type, or to end of PDU
    } else if (mac_ext_bits == 0b01) {
        parsed_header_len = 2;
        if (len < parsed_header_len) return -EMSGSIZE;
        *out_ie_type_value = buf[0] & 0x3F;
        *out_ie_payload_len = buf[1];
    } else if (mac_ext_bits == 0b10) {
        parsed_header_len = 3;
        if (len < parsed_header_len) return -EMSGSIZE;
        *out_ie_type_value = buf[0] & 0x3F;
        *out_ie_payload_len = sys_get_be16(&buf[1]);
    } else {
        return -EBADMSG; // Should not be reached
    }

    if (mac_ext_bits != 0b00) { // For MAC_Ext=00, payload length is implicit
        if (len < (size_t)parsed_header_len + *out_ie_payload_len) {
            LOG_WRN("MUX_PARSE: Declared payload len %u for IE type 0x%X (MAC_Ext 0x%02X) exceeds remaining buf len %zu (header len %d)",
                    *out_ie_payload_len, *out_ie_type_value, mac_ext_bits, len, parsed_header_len);
            return -EMSGSIZE;
        }
    }
    *out_ie_payload_ptr = buf + parsed_header_len;
    return parsed_header_len;
}


// --- IE Payload (De)Serializers ---
static int serialize_cluster_beacon_ie_payload(uint8_t *buf, size_t buf_max_len,
                                               const dect_mac_cluster_beacon_ie_fields_t *cb_fields)
{
    if (!buf || !cb_fields) {
        return -EINVAL;
    }

    memset(buf, 0, buf_max_len);
    int bit_offset = 0;
    int ret;

    // --- Octet 0 ---
    ret = write_bits(buf, buf_max_len, bit_offset, cb_fields->sfn, 8);
    if (ret < 0) return ret;
    bit_offset = ret;

    // --- Octet 1 ---
    uint8_t octet1 = 0;
    octet1 |= (cb_fields->tx_power_present & 0x01) << 7;
    octet1 |= (cb_fields->power_constraints_active & 0x01) << 6;
    octet1 |= (cb_fields->frame_offset_present & 0x01) << 5;
    octet1 |= (cb_fields->next_channel_present & 0x01) << 4;
    octet1 |= (cb_fields->time_to_next_present & 0x01) << 3;
    // Bits 2-0 are reserved
    ret = write_bits(buf, buf_max_len, bit_offset, octet1, 8);
    if (ret < 0) return ret;
    bit_offset = ret;

    // --- Octet 2 ---
    uint8_t octet2 = 0;
    octet2 |= (cb_fields->network_beacon_period_code & 0x0F) << 4;
    octet2 |= (cb_fields->cluster_beacon_period_code & 0x0F);
    ret = write_bits(buf, buf_max_len, bit_offset, octet2, 8);
    if (ret < 0) return ret;
    bit_offset = ret;

    // --- Octet 3 ---
    uint8_t octet3 = 0;
    octet3 |= (cb_fields->count_to_trigger_code & 0x07) << 5;
    octet3 |= (cb_fields->rel_quality_code & 0x07) << 2;
    octet3 |= (cb_fields->min_quality_code & 0x03);
    ret = write_bits(buf, buf_max_len, bit_offset, octet3, 8);
    if (ret < 0) return ret;
    bit_offset = ret;

    // --- Optional Fields ---
    if (cb_fields->tx_power_present) {
        ret = write_bits(buf, buf_max_len, bit_offset, cb_fields->clusters_max_tx_power_code, 8);
        if (ret < 0) return ret;
        bit_offset = ret;
    }

    if (cb_fields->frame_offset_present) {
        uint8_t fo_len_bits = cb_fields->frame_offset_is_16bit ? 16 : 8;
        ret = write_bits(buf, buf_max_len, bit_offset, cb_fields->frame_offset_value, fo_len_bits);
        if (ret < 0) return ret;
        bit_offset = ret;
    }

    if (cb_fields->next_channel_present) {
        ret = write_bits(buf, buf_max_len, bit_offset, cb_fields->next_cluster_channel_val, 16);
        if (ret < 0) return ret;
        bit_offset = ret;
    }

    if (cb_fields->time_to_next_present) {
        ret = write_bits(buf, buf_max_len, bit_offset, cb_fields->time_to_next_us, 32);
        if (ret < 0) return ret;
        bit_offset = ret;
    }

    // Return total length in bytes, rounded up
    return (bit_offset + 7) / 8;
}

int parse_cluster_beacon_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                    dect_mac_cluster_beacon_ie_fields_t *out_cb_fields)
{
    if (!ie_payload || !out_cb_fields) {
        return -EINVAL;
    }
    if (ie_payload_len < 4) { // Minimum length for the fixed part
        LOG_ERR("CB_PARSE: Payload too short (%u < 4) for Cluster Beacon IE.", ie_payload_len);
        return -EMSGSIZE;
    }

    memset(out_cb_fields, 0, sizeof(dect_mac_cluster_beacon_ie_fields_t));
    int bit_offset = 0;
    int remaining_bits = ie_payload_len * 8;

    // --- Octet 0: SFN ---
    out_cb_fields->sfn = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);

    // --- Octet 1: Control Flags ---
    uint8_t octet1 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_cb_fields->tx_power_present = (octet1 >> 7) & 0x01;
    out_cb_fields->power_constraints_active = (octet1 >> 6) & 0x01;
    out_cb_fields->frame_offset_present = (octet1 >> 5) & 0x01;
    out_cb_fields->next_channel_present = (octet1 >> 4) & 0x01;
    out_cb_fields->time_to_next_present = (octet1 >> 3) & 0x01;

    // --- Octet 2: Period Codes ---
    uint8_t octet2 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_cb_fields->network_beacon_period_code = (octet2 >> 4) & 0x0F;
    out_cb_fields->cluster_beacon_period_code = octet2 & 0x0F;

    // --- Octet 3: Quality & Trigger Codes ---
    uint8_t octet3 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_cb_fields->count_to_trigger_code = (octet3 >> 5) & 0x07;
    out_cb_fields->rel_quality_code = (octet3 >> 2) & 0x07;
    out_cb_fields->min_quality_code = octet3 & 0x03;

    // --- Optional Fields ---
    if (out_cb_fields->tx_power_present) {
        if (remaining_bits < 8) return -EMSGSIZE;
        out_cb_fields->clusters_max_tx_power_code = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    }

    if (out_cb_fields->frame_offset_present) {
        // The length of Frame offset depends on the numerology (mu) of the link, which isn't
        // known at this layer. We need a way to pass this info or make an assumption.
        // Assuming mu <= 4 (8-bit offset) for now. A TODO for full compliance.
        // TODO: Pass 'mu' to determine 8-bit or 16-bit Frame Offset field length.
        out_cb_fields->frame_offset_is_16bit = false; // Assumption
        uint8_t fo_len_bits = out_cb_fields->frame_offset_is_16bit ? 16 : 8;
        if (remaining_bits < fo_len_bits) return -EMSGSIZE;
        out_cb_fields->frame_offset_value = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, fo_len_bits);
    }

    if (out_cb_fields->next_channel_present) {
        if (remaining_bits < 16) return -EMSGSIZE;
        out_cb_fields->next_cluster_channel_val = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 16);
    }

    if (out_cb_fields->time_to_next_present) {
        if (remaining_bits < 32) return -EMSGSIZE;
        out_cb_fields->time_to_next_us = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 32);
    }

    return 0;
}


/**
 * @brief Serializes the payload of a RACH Info IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.3.4 & Table 6.4.3.4-1
 *
 * @param buf Buffer to write the serialized payload into.
 * @param buf_max_len Max length of the buffer in bytes.
 * @param rach_fields Pointer to the structure holding the RACH Info IE fields to be serialized.
 * @return Length of the serialized payload in bytes, or negative error code.
 */
static int serialize_rach_info_ie_payload(uint8_t *buf, size_t buf_max_len,
                                          const dect_mac_rach_info_ie_fields_t *rach_fields)
{
    if (!buf || !rach_fields) {
        LOG_ERR("RACH_SER: NULL input pointers.");
        return -EINVAL;
    }
    // Minimum size for mandatory fields (5 octets)
    if (buf_max_len < 5) {
        LOG_ERR("RACH_SER: Buffer too small (%zu bytes) for RACH IE mandatory part (5 bytes).", buf_max_len);
        return -ENOMEM;
    }
    if (rach_fields->mu_value_for_ft_beacon == 0 || rach_fields->mu_value_for_ft_beacon > 8) { // Basic validation for mu
        LOG_ERR("RACH_SER: Invalid mu_value_for_ft_beacon: %u. Assuming mu <= 4 for 8-bit start_subslot.", rach_fields->mu_value_for_ft_beacon);
        // Default to 8-bit if mu is invalid to prevent issues, or return error.
        // Forcing a default might be safer if caller doesn't populate mu correctly yet.
    }


    memset(buf, 0, buf_max_len); // Initialize buffer to ensure reserved bits are 0
    int bit_offset = 0;
    int ret;

    // Octet 0: Flags
    uint8_t flags_octet0 = 0;
    WRITE_BIT(flags_octet0, 6, rach_fields->repeat_type_is_subslots);
    WRITE_BIT(flags_octet0, 5, rach_fields->sfn_validity_present);
    WRITE_BIT(flags_octet0, 4, rach_fields->channel_field_present);
    WRITE_BIT(flags_octet0, 3, rach_fields->channel2_field_present);
    WRITE_BIT(flags_octet0, 2, rach_fields->max_len_type_is_slots);
    WRITE_BIT(flags_octet0, 1, rach_fields->dect_delay_for_response);
    // Bits 7 and 0 are reserved (set to 0 by memset)
    ret = write_bits(buf, buf_max_len, bit_offset, flags_octet0, 8);
    if (ret < 0) return ret;
    bit_offset = ret;

    // Octets 1-2 (conditionally 17 bits total):
    // Start Subslot (9 bits if mu > 4, else 8 bits), Length Type (1 bit), Length (7 bits)
    uint8_t start_subslot_num_bits = (rach_fields->mu_value_for_ft_beacon > 4 && rach_fields->mu_value_for_ft_beacon <= 8) ? 9 : 8;

    if (rach_fields->start_subslot_index >= (1U << start_subslot_num_bits)) {
         LOG_WRN("RACH_SER: Start subslot %u too large for %u bits (mu=%u). Clamping/Truncating.",
                rach_fields->start_subslot_index, start_subslot_num_bits, rach_fields->mu_value_for_ft_beacon);
        // Allow truncation for now, value will be masked by write_bits.
    }
    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->start_subslot_index, start_subslot_num_bits);
    if (ret < 0) { LOG_ERR("RACH_SER: Write StartSS failed: %d", ret); return ret; }
    bit_offset = ret;

    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->length_type_is_slots ? 1 : 0, 1);
    if (ret < 0) { LOG_ERR("RACH_SER: Write LenType failed: %d", ret); return ret; }
    bit_offset = ret;

    if (rach_fields->num_subslots_or_slots > 0x7F) {
        LOG_WRN("RACH_SER: num_subslots_or_slots %u exceeds 7-bit field. Clamping.", rach_fields->num_subslots_or_slots);
    }
    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->num_subslots_or_slots & 0x7F, 7);
    if (ret < 0) { LOG_ERR("RACH_SER: Write Length failed: %d", ret); return ret; }
    bit_offset = ret;

    // Byte index for Octet 3 depends on start_subslot_num_bits. write_bits handles bit_offset progression.
    // Octet related to 'Max RACH Length' (ETSI: Octet 3 if StartSS was 8bit, or part of Octet2+Octet3 if 9bit)
    if (rach_fields->max_rach_pdu_len_units > 0x7F) {
        LOG_WRN("RACH_SER: max_rach_pdu_len_units %u exceeds 7-bit field. Clamping.", rach_fields->max_rach_pdu_len_units);
    }
    uint8_t max_rach_len_octet = (rach_fields->max_rach_pdu_len_units & 0x7F) << 1; // Shift to MSB 7 bits, LSB is reserved (0)
    ret = write_bits(buf, buf_max_len, bit_offset, max_rach_len_octet, 8);
    if (ret < 0) { LOG_ERR("RACH_SER: Write MaxRACHLen failed: %d", ret); return ret; }
    bit_offset = ret;

    // Octet related to 'Cwmin_sig, Cwmax_sig, Repetition'
    uint8_t cw_rep_octet = ((rach_fields->cwmin_sig_code & 0x07) << 5) |
                             ((rach_fields->cwmax_sig_code & 0x07) << 2) |
                             (rach_fields->repetition_code & 0x03);
    ret = write_bits(buf, buf_max_len, bit_offset, cw_rep_octet, 8);
    if (ret < 0) { LOG_ERR("RACH_SER: Write CW/Rep failed: %d", ret); return ret; }
    bit_offset = ret;

    // Octet related to 'Response Window'
    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->response_window_subslots_val_minus_1, 8);
    if (ret < 0) { LOG_ERR("RACH_SER: Write RespWin failed: %d", ret); return ret; }
    bit_offset = ret;

    // --- Optional fields ---
    // Ensure byte alignment for the following fields if they are present, if not using write_bits for them.
    // write_bits handles unaligned writes for individual fields correctly.
    // If we were to switch to sys_put_be16 for Channel fields, alignment would be needed prior.

    if (rach_fields->sfn_validity_present) {
        // Ensure space for 2 bytes
        if (((bit_offset + 16 - 1) / 8) >= buf_max_len) { LOG_ERR("RACH_SER: No space for SFN/Validity."); return -ENOMEM; }
        ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->sfn_value, 8);
        if (ret < 0) { LOG_ERR("RACH_SER: Write SFNVal failed: %d", ret); return ret; }
        bit_offset = ret;
        ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->validity_frames, 8);
        if (ret < 0) { LOG_ERR("RACH_SER: Write Validity failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    if (rach_fields->channel_field_present) {
        // Channel (13 MSBs of 16-bit field), Reserved (3 LSBs)
        if (((bit_offset + 16 - 1) / 8) >= buf_max_len) { LOG_ERR("RACH_SER: No space for Channel."); return -ENOMEM; }
        uint16_t chan_field_on_air = (rach_fields->channel_abs_freq_num & 0x1FFF) << 3;
        // Use write_bits to handle potential unaligned bit_offset start for these 16 bits
        ret = write_bits(buf, buf_max_len, bit_offset, (chan_field_on_air >> 8) & 0xFF, 8); // MSByte
        if (ret < 0) { LOG_ERR("RACH_SER: Write Chan MSB failed: %d", ret); return ret; }
        bit_offset = ret;
        ret = write_bits(buf, buf_max_len, bit_offset, chan_field_on_air & 0xFF, 8);       // LSByte
        if (ret < 0) { LOG_ERR("RACH_SER: Write Chan LSB failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    if (rach_fields->channel2_field_present) {
        if (((bit_offset + 16 - 1) / 8) >= buf_max_len) { LOG_ERR("RACH_SER: No space for Channel2."); return -ENOMEM; }
        uint16_t chan2_field_on_air = (rach_fields->channel2_abs_freq_num & 0x1FFF) << 3;
        ret = write_bits(buf, buf_max_len, bit_offset, (chan2_field_on_air >> 8) & 0xFF, 8); // MSByte
        if (ret < 0) { LOG_ERR("RACH_SER: Write Chan2 MSB failed: %d", ret); return ret; }
        bit_offset = ret;
        ret = write_bits(buf, buf_max_len, bit_offset, chan2_field_on_air & 0xFF, 8);       // LSByte
        if (ret < 0) { LOG_ERR("RACH_SER: Write Chan2 LSB failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    return (bit_offset + 7) / 8; // Total bytes written
}


/**
 * @brief Deserializes the payload of a RACH Info IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.3.4 & Table 6.4.3.4-1
 *
 * @param ie_payload Pointer to the start of the RACH Info IE payload.
 * @param ie_payload_len Length of the IE payload in bytes.
 * @param out_rach_fields Pointer to the structure to store the deserialized fields.
 * @return 0 on success, or a negative error code on failure (e.g., -EMSGSIZE if payload too short).
 */

int parse_rach_info_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                               uint8_t mu_value_for_ft_beacon, /* New parameter */
                               dect_mac_rach_info_ie_fields_t *out_rach_fields)
{
    if (!ie_payload || !out_rach_fields) {
        LOG_ERR("RACH_PARSE: NULL input pointers.");
        return -EINVAL;
    }
    // Minimum size for mandatory fields is 5 octets
    if (ie_payload_len < 5) {
        LOG_ERR("RACH_PARSE: Payload too short (%u bytes) for RACH Info IE mandatory part (5 bytes).", ie_payload_len);
        return -EMSGSIZE;
    }
    if (mu_value_for_ft_beacon == 0 || mu_value_for_ft_beacon > 8) { // Basic validation for mu
        LOG_ERR("RACH_PARSE: Invalid mu_value_for_ft_beacon: %u. Assuming mu <= 4 for 8-bit start_subslot.", mu_value_for_ft_beacon);
    }

    memset(out_rach_fields, 0, sizeof(dect_mac_rach_info_ie_fields_t));
    out_rach_fields->mu_value_for_ft_beacon = mu_value_for_ft_beacon; // Store it

    int bit_offset = 0;
    int remaining_bits_from_len = ie_payload_len * 8;
    int *remaining_bits = &remaining_bits_from_len;

    // Octet 0: Flags
    if (*remaining_bits < 8) return -EMSGSIZE;
    uint8_t flags_octet0 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_rach_fields->repeat_type_is_subslots = (flags_octet0 >> 6) & 0x01;
    out_rach_fields->sfn_validity_present    = (flags_octet0 >> 5) & 0x01;
    out_rach_fields->channel_field_present   = (flags_octet0 >> 4) & 0x01;
    out_rach_fields->channel2_field_present  = (flags_octet0 >> 3) & 0x01;
    out_rach_fields->max_len_type_is_slots   = (flags_octet0 >> 2) & 0x01;
    out_rach_fields->dect_delay_for_response = (flags_octet0 >> 1) & 0x01;

    // Octets 1-2 (conditionally 17 bits): Start Subslot (9/8b), Length Type (1b), Length (7b)
    uint8_t start_subslot_num_bits = (mu_value_for_ft_beacon > 4 && mu_value_for_ft_beacon <= 8) ? 9 : 8;
    if (*remaining_bits < (start_subslot_num_bits + 1 + 7)) {
        LOG_ERR("RACH_PARSE: Not enough bits for StartSS/LenType/Len (%d needed).", start_subslot_num_bits + 1 + 7);
        return -EMSGSIZE;
    }
    out_rach_fields->start_subslot_index  = read_bits_adv(ie_payload, &bit_offset, remaining_bits, start_subslot_num_bits);
    out_rach_fields->length_type_is_slots = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 1);
    out_rach_fields->num_subslots_or_slots= read_bits_adv(ie_payload, &bit_offset, remaining_bits, 7);

    // Octet related to 'Max RACH Length'
    if (*remaining_bits < 8) { LOG_ERR("RACH_PARSE: Not enough bits for MaxRACHLen octet."); return -EMSGSIZE; }
    uint8_t max_rach_len_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_rach_fields->max_rach_pdu_len_units = (max_rach_len_octet >> 1) & 0x7F;

    // Octet related to 'Cwmin_sig, Cwmax_sig, Repetition'
    if (*remaining_bits < 8) { LOG_ERR("RACH_PARSE: Not enough bits for CW/Rep octet."); return -EMSGSIZE; }
    uint8_t cw_rep_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_rach_fields->cwmin_sig_code  = (cw_rep_octet >> 5) & 0x07;
    out_rach_fields->cwmax_sig_code  = (cw_rep_octet >> 2) & 0x07;
    out_rach_fields->repetition_code = cw_rep_octet & 0x03;

    // Octet related to 'Response Window'
    if (*remaining_bits < 8) { LOG_ERR("RACH_PARSE: Not enough bits for RespWin octet."); return -EMSGSIZE; }
    out_rach_fields->response_window_subslots_val_minus_1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);

    // --- Optional fields ---
    if (out_rach_fields->sfn_validity_present) {
        if (*remaining_bits < 16) { LOG_ERR("RACH_PARSE: Not enough bits for SFN/Validity fields."); return -EMSGSIZE; }
        out_rach_fields->sfn_value       = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        out_rach_fields->validity_frames = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    }

    if (out_rach_fields->channel_field_present) {
        if (*remaining_bits < 16) { LOG_ERR("RACH_PARSE: Not enough bits for Channel field."); return -EMSGSIZE; }
        uint8_t msb = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        uint8_t lsb = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        uint16_t chan_field_on_air = ((uint16_t)msb << 8) | lsb;
        out_rach_fields->channel_abs_freq_num = (chan_field_on_air >> 3) & 0x1FFF;
    }

    if (out_rach_fields->channel2_field_present) {
        if (*remaining_bits < 16) { LOG_ERR("RACH_PARSE: Not enough bits for Channel2 field."); return -EMSGSIZE; }
        uint8_t msb = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        uint8_t lsb = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        uint16_t chan2_field_on_air = ((uint16_t)msb << 8) | lsb;
        out_rach_fields->channel2_abs_freq_num = (chan2_field_on_air >> 3) & 0x1FFF;
    }

    if (*remaining_bits > 0 && *remaining_bits < 8) {
        LOG_WRN("RACH_PARSE: %d unparsed bits remain at the end of RACH IE payload (len %u).",
                *remaining_bits, ie_payload_len);
    } else if (*remaining_bits >= 8) {
         LOG_WRN("RACH_PARSE: %d unparsed bits (>=1 byte) remain at the end of RACH IE payload (len %u).",
                *remaining_bits, ie_payload_len);
    }

    return 0;
}


/**
 * @brief Serializes the payload of an Association Request IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.2.4 & Table 6.4.2.4-1
 * For this implements only the first mandatory octet.
 *
 * @param buf Buffer to write the serialized payload into.
 * @param buf_max_len Max length of the buffer in bytes.
 * @param req_fields Pointer to the structure holding the Association Request fields.
 * @return Length of the serialized payload in bytes (currently always 1), or negative error code.
 */

static int serialize_assoc_req_ie_payload(uint8_t *buf, size_t buf_max_len,
                                          const dect_mac_assoc_req_ie_t *req_fields)
{
    if (!buf || !req_fields) {
        LOG_ERR("ASSOC_REQ_SER: NULL input pointers.");
        return -EINVAL;
    }
    // Min 1 octet for mandatory part. Max is complex: 1 (flags) + 2 (HARQ) + ceil(6*6/8)=5 (FlowIDs) +
    // 1 (FT periods) + 2 (FT NextChan) + 4 (FT TimeToNext) approx = 1+2+5+1+2+4 = 15 bytes.
    if (buf_max_len < 1) {
        LOG_ERR("ASSOC_REQ_SER: Buffer too small (%zu bytes) for mandatory part (1 byte).", buf_max_len);
        return -ENOMEM;
    }

    memset(buf, 0, buf_max_len);
    int bit_offset = 0;
    int ret;

    // --- Octet 0: Flags and Basic Info ---
    uint8_t octet0 = 0;
    WRITE_BIT(octet0, 7, req_fields->power_const_active);
    WRITE_BIT(octet0, 6, req_fields->ft_mode_capable);
    if (req_fields->number_of_flows_val > MAX_FLOW_IDS_IN_ASSOC_REQ && req_fields->number_of_flows_val != 7) { /* 7 is special meaning */
        LOG_WRN("ASSOC_REQ_SER: NumFlows %u invalid for actual flow list. Clamping to 0 for list, or use 7 if all prev.", req_fields->number_of_flows_val);
        octet0 |= (0 << 3); // Default to 0 if invalid for list.
    } else {
        octet0 |= ((req_fields->number_of_flows_val & 0x07) << 3);
    }
    octet0 |= (req_fields->setup_cause_val & 0x07);
    ret = write_bits(buf, buf_max_len, bit_offset, octet0, 8);
    if (ret < 0) { LOG_ERR("ASSOC_REQ_SER: Write octet0 failed: %d", ret); return ret; }
    bit_offset = ret;

    // --- Conditional: HARQ Parameters (Octets 1 & 2) ---
    // Assuming harq_params_present flag in struct correctly indicates if these should be included.
    // ETSI implies these are typically present for initial association.
    if (req_fields->harq_params_present) {
        if (((bit_offset / 8) + 2) > buf_max_len) { LOG_ERR("ASSOC_REQ_SER: No space for HARQ params."); return -ENOMEM;}
        // Octet 1: HARQ Proc TX (3b), MAX HARQ RE-TX delay code (5b)
        uint8_t octet1_harq = ((req_fields->harq_processes_tx_val & 0x07) << 5) |
                               (req_fields->max_harq_re_tx_delay_code & 0x1F);
        ret = write_bits(buf, buf_max_len, bit_offset, octet1_harq, 8);
        if (ret < 0) { LOG_ERR("ASSOC_REQ_SER: Write HARQ Octet1 failed: %d", ret); return ret; }
        bit_offset = ret;

        // Octet 2: HARQ Proc RX (3b), MAX HARQ RE-RX delay code (5b)
        uint8_t octet2_harq = ((req_fields->harq_processes_rx_val & 0x07) << 5) |
                               (req_fields->max_harq_re_rx_delay_code & 0x1F);
        ret = write_bits(buf, buf_max_len, bit_offset, octet2_harq, 8);
        if (ret < 0) { LOG_ERR("ASSOC_REQ_SER: Write HARQ Octet2 failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    // --- Conditional: Flow IDs (Variable length) ---
    uint8_t num_flows_to_list = (req_fields->number_of_flows_val <= MAX_FLOW_IDS_IN_ASSOC_REQ) ? req_fields->number_of_flows_val : 0;
    if (num_flows_to_list > 0) {
        if (((bit_offset + (num_flows_to_list * 6) - 1) / 8) >= buf_max_len) { LOG_ERR("ASSOC_REQ_SER: No space for Flow IDs."); return -ENOMEM; }
        for (int i = 0; i < num_flows_to_list; i++) {
            if (req_fields->flow_ids[i] > 0x3F) { LOG_WRN("ASSOC_REQ_SER: FlowID %u > 6-bit. Clamping.", req_fields->flow_ids[i]); }
            ret = write_bits(buf, buf_max_len, bit_offset, req_fields->flow_ids[i] & 0x3F, 6);
            if (ret < 0) { LOG_ERR("ASSOC_REQ_SER: Write FlowID %d failed: %d", i, ret); return ret; }
            bit_offset = ret;
        }
        // Pad to next octet boundary if num_flows_to_list * 6 is not a multiple of 8
        if (bit_offset % 8 != 0) {
            int padding_bits = 8 - (bit_offset % 8);
            ret = write_bits(buf, buf_max_len, bit_offset, 0, (uint8_t)padding_bits); // Pad with 0s
            if (ret < 0) { LOG_ERR("ASSOC_REQ_SER: FlowID padding failed: %d", ret); return ret; }
            bit_offset = ret;
        }
    }

    // --- Conditional: FT Mode Parameters (if ft_mode_capable) ---
    if (req_fields->ft_mode_capable) {
        // These are flags for presence + values, similar to Cluster Beacon IE construction
        // For simplicity, let's assume if ft_mode_capable, PT provides its preferred periods.
        // And if it wants to suggest a next channel/time, those flags are set in req_fields.

        // Octet for Beacon Periods (if any present)
        if (req_fields->ft_net_beacon_period_present || req_fields->ft_cluster_beacon_period_present) {
            if (((bit_offset / 8) + 1) > buf_max_len) { LOG_ERR("ASSOC_REQ_SER: No space for FT Beacon Periods."); return -ENOMEM; }
            uint8_t ft_periods_octet = 0;
            // Assuming codes are already validated to be 4-bit
            if (req_fields->ft_net_beacon_period_present) ft_periods_octet |= (req_fields->ft_network_beacon_period_code & 0x0F) << 4;
            if (req_fields->ft_cluster_beacon_period_present) ft_periods_octet |= (req_fields->ft_cluster_beacon_period_code & 0x0F);
            ret = write_bits(buf, buf_max_len, bit_offset, ft_periods_octet, 8);
            if (ret < 0) { LOG_ERR("ASSOC_REQ_SER: Write FT Periods failed: %d", ret); return ret; }
            bit_offset = ret;
        }

        // Octet for FT Param Presence Flags
        // Bit 7: Next Cluster Channel present, Bit 6: Time To Next present, Bit 5: Current Cluster Channel present (omitting for now)
        if (req_fields->ft_next_channel_present || req_fields->ft_time_to_next_present) {
            if (((bit_offset / 8) + 1) > buf_max_len) { LOG_ERR("ASSOC_REQ_SER: No space for FT Param Flags."); return -ENOMEM; }
            uint8_t ft_param_flags_octet = 0;
            WRITE_BIT(ft_param_flags_octet, 7, req_fields->ft_next_channel_present);
            WRITE_BIT(ft_param_flags_octet, 6, req_fields->ft_time_to_next_present);
            // Other bits reserved
            ret = write_bits(buf, buf_max_len, bit_offset, ft_param_flags_octet, 8);
            if (ret < 0) { LOG_ERR("ASSOC_REQ_SER: Write FT Param Flags failed: %d", ret); return ret; }
            bit_offset = ret;

            if (req_fields->ft_next_channel_present) {
                if (((bit_offset + 16 - 1) / 8) >= buf_max_len) { LOG_ERR("ASSOC_REQ_SER: No space for FT Next Chan."); return -ENOMEM; }
                uint16_t chan_val = (req_fields->ft_next_cluster_channel_val & 0x1FFF) << 3;
                ret = write_bits(buf, buf_max_len, bit_offset, (chan_val >> 8) & 0xFF, 8);
                if (ret < 0) return ret; bit_offset = ret;
                ret = write_bits(buf, buf_max_len, bit_offset, chan_val & 0xFF, 8);
                if (ret < 0) return ret; bit_offset = ret;
            }
            if (req_fields->ft_time_to_next_present) {
                 if (((bit_offset + 32 - 1) / 8) >= buf_max_len) { LOG_ERR("ASSOC_REQ_SER: No space for FT TimeToNext."); return -ENOMEM; }
                uint32_t ttn_val = req_fields->ft_time_to_next_us_val;
                ret = write_bits(buf, buf_max_len, bit_offset, (ttn_val >> 24) & 0xFF, 8); if (ret < 0) return ret; bit_offset = ret;
                ret = write_bits(buf, buf_max_len, bit_offset, (ttn_val >> 16) & 0xFF, 8); if (ret < 0) return ret; bit_offset = ret;
                ret = write_bits(buf, buf_max_len, bit_offset, (ttn_val >> 8) & 0xFF, 8); if (ret < 0) return ret; bit_offset = ret;
                ret = write_bits(buf, buf_max_len, bit_offset, ttn_val & 0xFF, 8); if (ret < 0) return ret; bit_offset = ret;
            }
        }
    }
    return (bit_offset + 7) / 8;
}



/**
 * @brief Deserializes the payload of an Association Request IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.2.4 & Table 6.4.2.4-1
 * For (FT receiving), this implements parsing of the first mandatory octet.
 *
 * @param ie_payload Pointer to the start of the Association Request IE payload.
 * @param ie_payload_len Length of the IE payload in bytes.
 * @param out_req_fields Pointer to the structure to store the deserialized fields.
 * @return 0 on success, or a negative error code on failure (e.g., -EMSGSIZE if payload too short).
 */

int parse_assoc_req_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                               dect_mac_assoc_req_ie_t *out_req_fields)
{
    if (!ie_payload || !out_req_fields) {
        LOG_ERR("ASSOC_REQ_PARSE: NULL input pointers.");
        return -EINVAL;
    }
    if (ie_payload_len < 1) {
        LOG_ERR("ASSOC_REQ_PARSE: Payload too short (%u bytes) for mandatory part (1 byte).", ie_payload_len);
        return -EMSGSIZE;
    }
    memset(out_req_fields, 0, sizeof(dect_mac_assoc_req_ie_t));

    int bit_offset = 0;
    int remaining_bits_from_len = ie_payload_len * 8;
    int *remaining_bits = &remaining_bits_from_len;

    // Octet 0: Flags and Basic Info
    if (*remaining_bits < 8) return -EMSGSIZE;
    uint8_t octet0 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_req_fields->power_const_active  = (octet0 >> 7) & 0x01;
    out_req_fields->ft_mode_capable     = (octet0 >> 6) & 0x01;
    out_req_fields->number_of_flows_val = (octet0 >> 3) & 0x07;
    out_req_fields->setup_cause_val     = (dect_assoc_setup_cause_t)(octet0 & 0x07);

    // Conditional: HARQ Parameters (Octets 1 & 2)
    // ETSI Table implies these are present based on context (e.g. initial assoc)
    // rather than an explicit flag in Octet 0.
    // For robust parsing, check if enough bytes remain for them *if* they are expected.
    // Let's assume for an initial association (cause 0) or if NumFlows > 0, they are present.
    // This 'harq_params_present' should ideally be set by the SM based on setup_cause.
    // For now, we try to parse if bytes are available.
    if (*remaining_bits >= 16) { // Check if at least 2 more octets exist
        out_req_fields->harq_params_present = true; // Assume present if space allows
        uint8_t octet1_harq = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        out_req_fields->harq_processes_tx_val = (octet1_harq >> 5) & 0x07;
        out_req_fields->max_harq_re_tx_delay_code = octet1_harq & 0x1F;

        uint8_t octet2_harq = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        out_req_fields->harq_processes_rx_val = (octet2_harq >> 5) & 0x07;
        out_req_fields->max_harq_re_rx_delay_code = octet2_harq & 0x1F;
    } else {
        out_req_fields->harq_params_present = false;
    }

    // Conditional: Flow IDs
    uint8_t num_flows_to_parse = (out_req_fields->number_of_flows_val <= MAX_FLOW_IDS_IN_ASSOC_REQ) ? out_req_fields->number_of_flows_val : 0;
    if (num_flows_to_parse > 0) {
        if (*remaining_bits < (num_flows_to_parse * 6)) {
            LOG_ERR("ASSOC_REQ_PARSE: Not enough bits for %u Flow IDs.", num_flows_to_parse);
            // Mark as parsing failure or partial success
            return -EMSGSIZE;
        }
        for (int i = 0; i < num_flows_to_parse; i++) {
            out_req_fields->flow_ids[i] = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 6);
        }
        // Consume padding bits if any
        if (bit_offset % 8 != 0) {
            int padding_to_read = 8 - (bit_offset % 8);
            if (*remaining_bits < padding_to_read) { /* Error */ return -EMSGSIZE; }
            read_bits_adv(ie_payload, &bit_offset, remaining_bits, (uint8_t)padding_to_read);
        }
    }

    // Conditional: FT Mode Parameters
    if (out_req_fields->ft_mode_capable) {
        // Try to parse FT Beacon Periods octet (if present)
        if (*remaining_bits >= 8) {
            uint8_t ft_periods_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
            // Heuristic: If any period code is non-zero, assume the octet was intended for periods
            if ((ft_periods_octet >> 4) != 0 || (ft_periods_octet & 0x0F) != 0) {
                 out_req_fields->ft_net_beacon_period_present = ((ft_periods_octet >> 4) != 0); // Approximation
                 out_req_fields->ft_network_beacon_period_code = (ft_periods_octet >> 4) & 0x0F;
                 out_req_fields->ft_cluster_beacon_period_present = ((ft_periods_octet & 0x0F) != 0); // Approximation
                 out_req_fields->ft_cluster_beacon_period_code = ft_periods_octet & 0x0F;
            } else { // Octet was all zeros, might not have been periods octet, rewind conceptually
                bit_offset -= 8; *remaining_bits += 8; // "Unread" it if it was all zeros
            }
        }

        // Try to parse FT Param Presence Flags octet (if present)
        if (*remaining_bits >= 8) {
            uint8_t ft_param_flags_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
            out_req_fields->ft_next_channel_present = (ft_param_flags_octet >> 7) & 0x01;
            out_req_fields->ft_time_to_next_present = (ft_param_flags_octet >> 6) & 0x01;
            // Bit 5 for Current Cluster Channel present - not parsing this for now

            if (out_req_fields->ft_next_channel_present) {
                if (*remaining_bits < 16) { LOG_ERR("ASSOC_REQ_PARSE: No space for FT Next Chan."); return -EMSGSIZE;}
                uint8_t msb = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
                uint8_t lsb = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
                out_req_fields->ft_next_cluster_channel_val = ((uint16_t)msb << 8) | lsb;
                out_req_fields->ft_next_cluster_channel_val = (out_req_fields->ft_next_cluster_channel_val >> 3) & 0x1FFF;
            }
            if (out_req_fields->ft_time_to_next_present) {
                if (*remaining_bits < 32) { LOG_ERR("ASSOC_REQ_PARSE: No space for FT TimeToNext."); return -EMSGSIZE;}
                uint32_t ttn_val = 0;
                ttn_val |= ((uint32_t)read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8)) << 24;
                ttn_val |= ((uint32_t)read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8)) << 16;
                ttn_val |= ((uint32_t)read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8)) << 8;
                ttn_val |= read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
                out_req_fields->ft_time_to_next_us_val = ttn_val;
            }
        }
    }

    if (*remaining_bits >= 8) {
        LOG_WRN("ASSOC_REQ_PARSE: %d unparsed bits (>=1 byte) remain. Payload len %u.", *remaining_bits, ie_payload_len);
    } else if (*remaining_bits > 0) {
        LOG_WRN("ASSOC_REQ_PARSE: %d unparsed bits remain (padding or error). Payload len %u.", *remaining_bits, ie_payload_len);
    }

    return 0;
}


/**
 * @brief Serializes the payload of an RD Capability IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.3.5 & Table 6.4.3.5-1
 * This version serializes the mandatory summary octets (Octet 0 and Octet 1).
 * Serialization of detailed PHY capability sets (Octets 2+N*5) is a TODO.
 *
 * @param buf Buffer to write the serialized payload into.
 * @param buf_max_len Max length of the buffer in bytes.
 * @param cap_fields Pointer to the structure holding the RD Capability fields.
 * @return Length of the serialized payload in bytes (currently 2 for the summary),
 *         or negative error code.
 */

static int serialize_rd_capability_ie_payload(uint8_t *buf, size_t buf_max_len,
                                              const dect_mac_rd_capability_ie_t *cap_fields)
{
    if (!buf || !cap_fields) {
        LOG_ERR("RD_CAP_SER: NULL input pointers.");
        return -EINVAL;
    }
    size_t min_len_needed = 2; // Mandatory summary octets
    if (cap_fields->num_phy_capabilities >= 1) {
        min_len_needed += 5; // Add 5 bytes for the first PHY set
    }
    if (buf_max_len < min_len_needed) {
        LOG_ERR("RD_CAP_SER: Buffer too small (%zu bytes) for RD Cap IE (needs min %zu).", buf_max_len, min_len_needed);
        return -ENOMEM;
    }

    memset(buf, 0, buf_max_len);
    int bit_offset = 0;
    int ret;

    // Octet 0: Number of PHY Capabilities (3 MSB), Release (5 LSB)
    if (cap_fields->num_phy_capabilities > 0x07) LOG_WRN("RD_CAP_SER: num_phy_cap %u > 3bit. Clamping.", cap_fields->num_phy_capabilities);
    if (cap_fields->release_version > 0x1F) LOG_WRN("RD_CAP_SER: release_ver %u > 5bit. Clamping.", cap_fields->release_version);
    uint8_t octet0 = ((cap_fields->num_phy_capabilities & 0x07) << 5) |
                     (cap_fields->release_version & 0x1F);
    ret = write_bits(buf, buf_max_len, bit_offset, octet0, 8);
    if (ret < 0) { LOG_ERR("RD_CAP_SER: Write octet0 failed: %d", ret); return ret; }
    bit_offset = ret;

    // Octet 1: Flags
    uint8_t octet1 = 0;
    WRITE_BIT(octet1, 7, cap_fields->supports_group_assignment);
    WRITE_BIT(octet1, 6, cap_fields->supports_paging);
    if (cap_fields->operating_modes_code > 0x03) LOG_WRN("RD_CAP_SER: op_modes %u > 2bit. Clamping.", cap_fields->operating_modes_code);
    octet1 |= ((cap_fields->operating_modes_code & 0x03) << 4);
    WRITE_BIT(octet1, 3, cap_fields->supports_mesh);
    WRITE_BIT(octet1, 2, cap_fields->supports_sched_data);
    if (cap_fields->mac_security_modes_code > 0x03) LOG_WRN("RD_CAP_SER: mac_sec %u > 2bit. Clamping.", cap_fields->mac_security_modes_code);
    octet1 |= (cap_fields->mac_security_modes_code & 0x03);
    ret = write_bits(buf, buf_max_len, bit_offset, octet1, 8);
    if (ret < 0) { LOG_ERR("RD_CAP_SER: Write octet1 failed: %d", ret); return ret; }
    bit_offset = ret;

    // Conditional: First PHY Capability Set (Octets 2 to 6)
    if (cap_fields->num_phy_capabilities >= 1) {
        const dect_mac_phy_capability_set_t *phy_set0 = &cap_fields->phy_variants[0];
        uint8_t phy_octet;

        // Set Octet 0: DLC Svc (3b), RX Div (3b), Rsvd (2b)
        phy_octet = ((phy_set0->dlc_service_type_support_code & 0x07) << 5) |
                    ((phy_set0->rx_for_tx_diversity_code & 0x07) << 2); // Rsvd are 0
        ret = write_bits(buf, buf_max_len, bit_offset, phy_octet, 8); if (ret < 0) return ret; bit_offset = ret;

        // Set Octet 1: mu (3b), beta (4b), Rsvd (1b)
        phy_octet = ((phy_set0->mu_value & 0x07) << 5) |
                    ((phy_set0->beta_value & 0x0F) << 1); // Rsvd is 0
        ret = write_bits(buf, buf_max_len, bit_offset, phy_octet, 8); if (ret < 0) return ret; bit_offset = ret;

        // Set Octet 2: Max NSS (3b), Max MCS (4b), Rsvd (1b)
        phy_octet = ((phy_set0->max_nss_for_rx_code & 0x07) << 5) |
                    ((phy_set0->max_mcs_code & 0x0F) << 1); // Rsvd is 0
        ret = write_bits(buf, buf_max_len, bit_offset, phy_octet, 8); if (ret < 0) return ret; bit_offset = ret;

        // Set Octet 3: HARQ Buf (4b), Num HARQ Proc (2b), Rsvd (2b)
        phy_octet = ((phy_set0->harq_soft_buffer_size_code & 0x0F) << 4) |
                    ((phy_set0->num_harq_processes_code & 0x03) << 2); // Rsvd are 0
        ret = write_bits(buf, buf_max_len, bit_offset, phy_octet, 8); if (ret < 0) return ret; bit_offset = ret;

        // Set Octet 4: HARQ Delay (4b), D_Delay (1b), HalfDup (1b), Rsvd (2b)
        phy_octet = ((phy_set0->harq_feedback_delay_code & 0x0F) << 4) |
                    ((phy_set0->supports_dect_delay ? 1 : 0) << 3) |
                    ((phy_set0->supports_half_duplex ? 1 : 0) << 2); // Rsvd are 0
        ret = write_bits(buf, buf_max_len, bit_offset, phy_octet, 8); if (ret < 0) return ret; bit_offset = ret;
    }
    // TODO: Loop here if cap_fields->num_phy_capabilities > 1 and phy_variants was an array

    return (bit_offset + 7) / 8;
}





/**
 * @brief Deserializes the payload of an RD Capability IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.3.5 & Table 6.4.3.5-1
 * This version deserializes the mandatory summary octets (Octet 0 and Octet 1).
 * Deserialization of detailed PHY capability sets (Octets 2+N*5) is a TODO.
 *
 * @param ie_payload Pointer to the start of the RD Capability IE payload.
 * @param ie_payload_len Length of the IE payload in bytes.
 * @param out_cap_fields Pointer to the structure to store the deserialized fields.
 * @return 0 on success, or a negative error code on failure (e.g., -EMSGSIZE if payload too short).
 */

int parse_rd_capability_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                   dect_mac_rd_capability_ie_t *out_cap_fields)
{
    if (!ie_payload || !out_cap_fields) {
        LOG_ERR("RD_CAP_PARSE: NULL input pointers.");
        return -EINVAL;
    }
    if (ie_payload_len < 2) { // Min 2 octets for summary
        LOG_ERR("RD_CAP_PARSE: Payload too short (%u bytes) for mandatory part (2 bytes).", ie_payload_len);
        return -EMSGSIZE;
    }
    memset(out_cap_fields, 0, sizeof(dect_mac_rd_capability_ie_t));

    int bit_offset = 0;
    int remaining_bits_from_len = ie_payload_len * 8;
    int *remaining_bits = &remaining_bits_from_len;

    // Octet 0: Number of PHY Capabilities (3 MSB), Release (5 LSB)
    if (*remaining_bits < 8) return -EMSGSIZE;
    uint8_t octet0 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_cap_fields->num_phy_capabilities = (octet0 >> 5) & 0x07; // This is N-1 value
    out_cap_fields->release_version      = octet0 & 0x1F;

    // Octet 1: Flags
    if (*remaining_bits < 8) { LOG_ERR("RD_CAP_PARSE: Payload too short for Octet 1 flags."); return -EMSGSIZE; }
    uint8_t octet1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_cap_fields->supports_group_assignment = (octet1 >> 7) & 0x01;
    out_cap_fields->supports_paging           = (octet1 >> 6) & 0x01;
    out_cap_fields->operating_modes_code      = (octet1 >> 4) & 0x03;
    out_cap_fields->supports_mesh             = (octet1 >> 3) & 0x01;
    out_cap_fields->supports_sched_data       = (octet1 >> 2) & 0x01;
    out_cap_fields->mac_security_modes_code   = octet1 & 0x03;

    LOG_DBG("RD_CAP_PARSE: Summary: NumPHYAddSets:%u, RelVer:%u, GrpAs:%d Paging:%d OpM:0x%X Mesh:%d Sched:%d MACSec:0x%X",
            out_cap_fields->num_phy_capabilities, out_cap_fields->release_version,
            out_cap_fields->supports_group_assignment, out_cap_fields->supports_paging,
            out_cap_fields->operating_modes_code, out_cap_fields->supports_mesh,
            out_cap_fields->supports_sched_data, out_cap_fields->mac_security_modes_code);

    // Conditional: Parse first explicit PHY Capability Set if present
    // num_phy_capabilities field stores (N-1). If it's 0, N=1 (base set only, no 5-octet part).
    // If it's 1, N=2 (base + 1 explicit 5-octet set).
    if (out_cap_fields->num_phy_capabilities >= 1) { // At least one explicit 5-octet set follows
        if (*remaining_bits < (5 * 8)) {
            LOG_ERR("RD_CAP_PARSE: num_phy_cap >= 1, but not enough bits (%d) for one 5-octet set.", *remaining_bits);
            // Continue with summary, but phy_variants[0] will be zeroed.
            out_cap_fields->num_phy_capabilities = 0; // Indicate no valid explicit sets were parsed
            return 0; // Or -EMSGSIZE if strict
        }
        
        dect_mac_phy_capability_set_t *phy_set0 = &out_cap_fields->phy_variants[0];
        uint8_t phy_octet;

        // Set Octet 0 of 5-octet set: DLC Svc (3b), RX Div (3b), Rsvd (2b)
        phy_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        phy_set0->dlc_service_type_support_code = (phy_octet >> 5) & 0x07;
        phy_set0->rx_for_tx_diversity_code = (phy_octet >> 2) & 0x07;

        // Set Octet 1 of 5-octet set: mu (3b), beta (4b), Rsvd (1b)
        phy_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        phy_set0->mu_value = (phy_octet >> 5) & 0x07;   // This is the mu_code (0-7)
        phy_set0->beta_value = (phy_octet >> 1) & 0x0F; // This is the beta_code (0-15)

        // Set Octet 2 of 5-octet set: Max NSS (3b), Max MCS (4b), Rsvd (1b)
        phy_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        phy_set0->max_nss_for_rx_code = (phy_octet >> 5) & 0x07;
        phy_set0->max_mcs_code = (phy_octet >> 1) & 0x0F;

        // Set Octet 3 of 5-octet set: HARQ Buf (4b), Num HARQ Proc (2b), Rsvd (2b)
        phy_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        phy_set0->harq_soft_buffer_size_code = (phy_octet >> 4) & 0x0F;
        phy_set0->num_harq_processes_code = (phy_octet >> 2) & 0x03;

        // Set Octet 4 of 5-octet set: HARQ Delay (4b), D_Delay (1b), HalfDup (1b), Rsvd (2b)
        phy_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        phy_set0->harq_feedback_delay_code = (phy_octet >> 4) & 0x0F;
        phy_set0->supports_dect_delay = (phy_octet >> 3) & 0x01;
        phy_set0->supports_half_duplex = (phy_octet >> 2) & 0x01;

        LOG_DBG("RD_CAP_PARSE: Parsed PHY Set 0: mu_code=%u, beta_code=%u, max_mcs_code=%u, dlc_svc_code=%u",
                phy_set0->mu_value, phy_set0->beta_value, phy_set0->max_mcs_code, phy_set0->dlc_service_type_support_code);
        // TODO: Loop here to parse more sets if out_cap_fields->num_phy_capabilities > 1
        //       and if phy_variants was an array capable of holding more.
    } else {
        LOG_DBG("RD_CAP_PARSE: No explicit 5-octet PHY capability sets indicated (num_phy_capabilities field is 0).");
    }

    if (*remaining_bits >= 8) {
        LOG_WRN("RD_CAP_PARSE: %d unparsed bits (>=1 byte) remain. Payload len %u.", *remaining_bits, ie_payload_len);
    } else if (*remaining_bits > 0) {
        LOG_WRN("RD_CAP_PARSE: %d unparsed bits remain (padding or error). Payload len %u.", *remaining_bits, ie_payload_len);
    }

    return 0;
}





/**
 * @brief Serializes the payload of an Association Response IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.2.5 & Table 6.4.2.5-1
 * This version serializes the mandatory first octet, and the second octet if NACK.
 * Serialization of conditional fields for ACK (HARQ, Flows, Group) is a TODO.
 *
 * @param buf Buffer to write the serialized payload into.
 * @param buf_max_len Max length of the buffer in bytes.
 * @param resp_fields Pointer to the structure holding the Association Response fields.
 * @return Length of the serialized payload in bytes (1 if ACK and no optionals, 2 if NACK),
 *         or negative error code.
 */

int serialize_assoc_resp_ie_payload(uint8_t *buf, size_t buf_max_len,
                                      const dect_mac_assoc_resp_ie_t *resp_fields)
{
    if (!buf || !resp_fields) {
        LOG_ERR("ASSOC_RESP_SER: NULL input pointers.");
        return -EINVAL;
    }
    // Min 1 octet (ACK with no optionals) or 2 octets (NACK).
    size_t min_len_needed = resp_fields->ack_nack ? 1 : 2;
    if (buf_max_len < min_len_needed) {
        LOG_ERR("ASSOC_RESP_SER: Buffer too small (%zu bytes) for min Assoc Resp IE (needs %zu).", buf_max_len, min_len_needed);
        return -ENOMEM;
    }

    memset(buf, 0, buf_max_len);
    int bit_offset = 0;
    int ret;

    // --- Octet 0: Flags and Basic Info ---
    uint8_t octet0 = 0;
    WRITE_BIT(octet0, 7, resp_fields->ack_nack);
    WRITE_BIT(octet0, 6, resp_fields->harq_mod_present);
    if (resp_fields->number_of_flows_accepted > 0x07) {
        LOG_WRN("ASSOC_RESP_SER: NumFlowsAccepted %u invalid. Clamping to 7 (all).", resp_fields->number_of_flows_accepted);
        octet0 |= (0x07 << 3);
    } else {
        octet0 |= ((resp_fields->number_of_flows_accepted & 0x07) << 3);
    }
    WRITE_BIT(octet0, 2, resp_fields->group_assignment_active);
    // Bits 1-0 are reserved, implicitly 0 by memset then explicit ORing of higher bits.
    // Or, if resp_fields->reserved_3bits was used, it should be (resp_fields->reserved_3bits & 0x03)
    // For ETSI text (bits 1-0 reserved):
    // octet0 |= (0 & 0x03); // Explicitly setting reserved bits 1-0 to 0.

    ret = write_bits(buf, buf_max_len, bit_offset, octet0, 8);
    if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Write octet0 failed: %d", ret); return ret; }
    bit_offset = ret;

    // --- Conditional: Reject Cause & Timer (Octet 1, if NACK) ---
    if (!resp_fields->ack_nack) {
        if (((bit_offset / 8) + 1) > buf_max_len) { LOG_ERR("ASSOC_RESP_SER: No space for NACK details."); return -ENOMEM; }
        uint8_t octet1_reject = 0;
        if (resp_fields->reject_timer_code > 0x0F) LOG_WRN("ASSOC_RESP_SER: RejectTimerCode %u > 4bit. Clamping.", resp_fields->reject_timer_code);
        if (resp_fields->reject_cause >= 8) LOG_WRN("ASSOC_RESP_SER: RejectCause %u invalid. Clamping.", resp_fields->reject_cause); // Assuming enum 0-7 for cause

        octet1_reject |= (resp_fields->reject_timer_code & 0x0F) << 4;
        octet1_reject |= (resp_fields->reject_cause & 0x0F); // Assuming cause is also 4 bits effectively
        ret = write_bits(buf, buf_max_len, bit_offset, octet1_reject, 8);
        if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Write reject octet1 failed: %d", ret); return ret; }
        bit_offset = ret;
    } else { // --- Conditional fields for ACK ---
        // --- HARQ Parameters (Octets 2 & 3, if ack_nack = 1 AND harq_mod_present = 1) ---
        if (resp_fields->harq_mod_present) {
            if (((bit_offset / 8) + 2) > buf_max_len) { LOG_ERR("ASSOC_RESP_SER: No space for HARQ params."); return -ENOMEM; }
            uint8_t octet_harq_tx = ((resp_fields->harq_processes_tx_val_ft & 0x07) << 5) |
                                    (resp_fields->max_harq_re_tx_delay_code_ft & 0x1F);
            ret = write_bits(buf, buf_max_len, bit_offset, octet_harq_tx, 8);
            if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Write HARQ TX Octet failed: %d", ret); return ret; }
            bit_offset = ret;

            uint8_t octet_harq_rx = ((resp_fields->harq_processes_rx_val_ft & 0x07) << 5) |
                                    (resp_fields->max_harq_re_rx_delay_code_ft & 0x1F);
            ret = write_bits(buf, buf_max_len, bit_offset, octet_harq_rx, 8);
            if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Write HARQ RX Octet failed: %d", ret); return ret; }
            bit_offset = ret;
        }

        // --- Accepted Flow IDs (Variable length, if number_of_flows_accepted is 1-6) ---
        uint8_t num_flows_to_list_resp = (resp_fields->number_of_flows_accepted <= MAX_FLOW_IDS_IN_ASSOC_REQ) ? resp_fields->number_of_flows_accepted : 0;
        if (num_flows_to_list_resp > 0) {
            if (((bit_offset + (num_flows_to_list_resp * 6) - 1) / 8) >= buf_max_len) { LOG_ERR("ASSOC_RESP_SER: No space for Flow IDs."); return -ENOMEM; }
            for (int i = 0; i < num_flows_to_list_resp; i++) {
                if (resp_fields->accepted_flow_ids[i] > 0x3F) { LOG_WRN("ASSOC_RESP_SER: AcceptedFlowID %u > 6-bit. Clamping.", resp_fields->accepted_flow_ids[i]); }
                ret = write_bits(buf, buf_max_len, bit_offset, resp_fields->accepted_flow_ids[i] & 0x3F, 6);
                if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Write AcceptedFlowID %d failed: %d", i, ret); return ret; }
                bit_offset = ret;
            }
            if (bit_offset % 8 != 0) { // Pad to next octet boundary
                int padding_bits = 8 - (bit_offset % 8);
                ret = write_bits(buf, buf_max_len, bit_offset, 0, (uint8_t)padding_bits);
                if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: FlowID padding failed: %d", ret); return ret; }
                bit_offset = ret;
            }
        }

        // --- Group ID & Resource Tag (2 octets, if group_assignment_active = 1) ---
        if (resp_fields->group_assignment_active) {
            if (((bit_offset / 8) + 2) > buf_max_len) { LOG_ERR("ASSOC_RESP_SER: No space for GroupID/ResTag."); return -ENOMEM; }
            // Group ID: 7 MSB, 1 LSB Reserved
            uint8_t group_id_octet = (resp_fields->group_id_val & 0x7F) << 1;
            ret = write_bits(buf, buf_max_len, bit_offset, group_id_octet, 8);
            if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Write GroupID failed: %d", ret); return ret; }
            bit_offset = ret;

            // Resource Tag: 7 MSB, 1 LSB Reserved
            uint8_t res_tag_octet = (resp_fields->resource_tag_val & 0x7F) << 1;
            ret = write_bits(buf, buf_max_len, bit_offset, res_tag_octet, 8);
            if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Write ResourceTag failed: %d", ret); return ret; }
            bit_offset = ret;
        }
    }
    return (bit_offset + 7) / 8; // Total bytes written
}



/**
 * @brief Deserializes the payload of an Association Response IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.2.5 & Table 6.4.2.5-1
 * This version deserializes the mandatory first octet, and the second octet if NACK.
 * Deserialization of conditional fields for ACK (HARQ, Flows, Group) is a TODO.
 *
 * @param ie_payload Pointer to the start of the Association Response IE payload.
 * @param ie_payload_len Length of the IE payload in bytes.
 * @param out_resp_fields Pointer to the structure to store the deserialized fields.
 * @return 0 on success, or a negative error code on failure (e.g., -EMSGSIZE if payload too short).
 */

int parse_assoc_resp_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                dect_mac_assoc_resp_ie_t *out_resp_fields)
{
    if (!ie_payload || !out_resp_fields) {
        LOG_ERR("ASSOC_RESP_PARSE: NULL input pointers.");
        return -EINVAL;
    }
    if (ie_payload_len < 1) {
        LOG_ERR("ASSOC_RESP_PARSE: Payload too short (%u bytes) for mandatory part (1 byte).", ie_payload_len);
        return -EMSGSIZE;
    }
    memset(out_resp_fields, 0, sizeof(dect_mac_assoc_resp_ie_t));

    int bit_offset = 0;
    int remaining_bits_from_len = ie_payload_len * 8;
    int *remaining_bits = &remaining_bits_from_len;

    // Octet 0: Flags and Basic Info
    if (*remaining_bits < 8) return -EMSGSIZE;
    uint8_t octet0 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_resp_fields->ack_nack                 = (octet0 >> 7) & 0x01;
    out_resp_fields->harq_mod_present         = (octet0 >> 6) & 0x01;
    out_resp_fields->number_of_flows_accepted = (octet0 >> 3) & 0x07;
    out_resp_fields->group_assignment_active  = (octet0 >> 2) & 0x01;
    out_resp_fields->reserved_3bits           = octet0 & 0x03; // Store actual reserved bits (0-1 or 0-2 depending on interpretation)

    // Conditional: Reject Cause & Timer (Octet 1, if NACK)
    if (!out_resp_fields->ack_nack) {
        if (*remaining_bits < 8) {
            LOG_ERR("ASSOC_RESP_PARSE: NACK, but not enough bits for Reject Cause/Timer octet.");
            return -EMSGSIZE;
        }
        uint8_t octet1_reject = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
        out_resp_fields->reject_timer_code = (octet1_reject >> 4) & 0x0F;
        out_resp_fields->reject_cause      = (dect_assoc_reject_cause_t)(octet1_reject & 0x0F);
    } else { // Conditional fields for ACK
        // HARQ Parameters (Octets 2 & 3, if harq_mod_present = 1)
        if (out_resp_fields->harq_mod_present) {
            if (*remaining_bits < 16) { LOG_ERR("ASSOC_RESP_PARSE: harq_mod_present, but not enough bits for HARQ params."); return -EMSGSIZE; }
            uint8_t octet_harq_tx = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
            out_resp_fields->harq_processes_tx_val_ft = (octet_harq_tx >> 5) & 0x07;
            out_resp_fields->max_harq_re_tx_delay_code_ft = octet_harq_tx & 0x1F;

            uint8_t octet_harq_rx = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
            out_resp_fields->harq_processes_rx_val_ft = (octet_harq_rx >> 5) & 0x07;
            out_resp_fields->max_harq_re_rx_delay_code_ft = octet_harq_rx & 0x1F;
        }

        // Accepted Flow IDs (Variable length, if number_of_flows_accepted is 1-6)
        uint8_t num_flows_to_parse_resp = (out_resp_fields->number_of_flows_accepted <= MAX_FLOW_IDS_IN_ASSOC_REQ) ? out_resp_fields->number_of_flows_accepted : 0;
        if (num_flows_to_parse_resp > 0) {
            if (*remaining_bits < (num_flows_to_parse_resp * 6)) { LOG_ERR("ASSOC_RESP_PARSE: Not enough bits for %u AcceptedFlowIDs.", num_flows_to_parse_resp); return -EMSGSIZE; }
            for (int i = 0; i < num_flows_to_parse_resp; i++) {
                out_resp_fields->accepted_flow_ids[i] = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 6);
            }
            if (bit_offset % 8 != 0) { // Consume padding bits
                int padding_to_read = 8 - (bit_offset % 8);
                if (*remaining_bits < padding_to_read) { /* Error */ return -EMSGSIZE; }
                read_bits_adv(ie_payload, &bit_offset, remaining_bits, (uint8_t)padding_to_read);
            }
        }

        // Group ID & Resource Tag (2 octets, if group_assignment_active = 1)
        if (out_resp_fields->group_assignment_active) {
            if (*remaining_bits < 16) { LOG_ERR("ASSOC_RESP_PARSE: group_assignment_active, but not enough bits for GroupID/ResTag."); return -EMSGSIZE; }
            uint8_t group_id_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
            out_resp_fields->group_id_val = (group_id_octet >> 1) & 0x7F; // 7 MSBs

            uint8_t res_tag_octet = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
            out_resp_fields->resource_tag_val = (res_tag_octet >> 1) & 0x7F; // 7 MSBs
        }
    }

    if (*remaining_bits >= 8) {
        LOG_WRN("ASSOC_RESP_PARSE: %d unparsed bits (>=1 byte) remain. Payload len %u.", *remaining_bits, ie_payload_len);
    } else if (*remaining_bits > 0) {
        LOG_WRN("ASSOC_RESP_PARSE: %d unparsed bits remain (padding or error). Payload len %u.", *remaining_bits, ie_payload_len);
    }
    return 0;
}




/**
 * @brief Serializes the payload of a Resource Allocation IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.3.3 & Table 6.4.3.3-1
 *
 * @param buf Buffer to write the serialized payload into.
 * @param buf_max_len Max length of the buffer in bytes.
 * @param ra_fields Pointer to the structure holding the Resource Allocation fields.
 *                  The caller must correctly set resX_is_9bit_subslot flags based on the
 *                  target link's 'mu' value if 9-bit start_subslot is intended.
 * @return Length of the serialized payload in bytes, or negative error code.
 */

int serialize_resource_alloc_ie_payload(uint8_t *buf, size_t buf_max_len,
                                          const dect_mac_resource_alloc_ie_fields_t *ra_fields)
{
    if (!buf || !ra_fields) {
        LOG_ERR("RA_SER: NULL input pointers.");
        return -EINVAL;
    }

    size_t min_len_check = 1; 
    uint8_t res1_start_subslot_num_bits = 0; 

    if (ra_fields->alloc_type_val != RES_ALLOC_TYPE_RELEASE_ALL) {
        res1_start_subslot_num_bits = ra_fields->res1_is_9bit_subslot ? 9 : 8;
        min_len_check = 1 + 1 + ((res1_start_subslot_num_bits + 1 + 7 + 7) / 8); // BMP0(1)+BMP1(1)+Res1_fields(2 or 3)
        if (ra_fields->alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
             uint8_t res2_start_subslot_num_bits = ra_fields->res2_is_9bit_subslot ? 9 : 8;
             min_len_check += ((res2_start_subslot_num_bits + 1 + 7 + 7) / 8); // Add Res2_fields(2 or 3)
        }
    }
    if (buf_max_len < min_len_check) {
         LOG_ERR("RA_SER: buf_max_len %zu too small for ResAlloc IE (expected min ~%zu).", buf_max_len, min_len_check);
         return -ENOMEM;
    }

    memset(buf, 0, buf_max_len);
    int bit_offset = 0;
    int ret;

    // Octet 0 of Bitmap
    uint8_t bitmap_octet0 = 0;
    bitmap_octet0 |= ((uint8_t)ra_fields->alloc_type_val & 0x03) << 6;
    WRITE_BIT(bitmap_octet0, 5, ra_fields->add_allocation);
    WRITE_BIT(bitmap_octet0, 4, ra_fields->id_present);
    bitmap_octet0 |= ((uint8_t)ra_fields->repeat_val & 0x07) << 1;
    WRITE_BIT(bitmap_octet0, 0, ra_fields->sfn_present);
    ret = write_bits(buf, buf_max_len, bit_offset, bitmap_octet0, 8);
    if (ret < 0) { LOG_ERR("RA_SER: Write Bitmap0 failed: %d", ret); return ret; }
    bit_offset = ret;

    if (ra_fields->alloc_type_val == RES_ALLOC_TYPE_RELEASE_ALL) {
        return (bit_offset + 7) / 8;
    }

    // Octet 1 of Bitmap
    uint8_t bitmap_octet1 = 0;
    WRITE_BIT(bitmap_octet1, 7, ra_fields->channel_present);
    WRITE_BIT(bitmap_octet1, 6, ra_fields->rlf_present);
    // Bits 5-0 are reserved
    ret = write_bits(buf, buf_max_len, bit_offset, bitmap_octet1, 8);
    if (ret < 0) { LOG_ERR("RA_SER: Write Bitmap1 failed: %d", ret); return ret; }
    bit_offset = ret;

    // Resource 1 Fields
    // res1_start_subslot_num_bits was determined above based on ra_fields->res1_is_9bit_subslot
    if (ra_fields->start_subslot_val_res1 >= (1U << res1_start_subslot_num_bits)) {
        LOG_WRN("RA_SER: Res1 StartSS %u too large for %u bits. Truncating.",
                ra_fields->start_subslot_val_res1, res1_start_subslot_num_bits);
    }
    ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->start_subslot_val_res1, res1_start_subslot_num_bits);
    if (ret < 0) { LOG_ERR("RA_SER: Write Res1 StartSS failed: %d", ret); return ret; }
    bit_offset = ret;

    ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_type_is_slots_res1 ? 1 : 0, 1);
    if (ret < 0) { LOG_ERR("RA_SER: Write Res1 LenType failed: %d", ret); return ret; }
    bit_offset = ret;

    if (ra_fields->length_val_res1 > 0x7F) { LOG_WRN("RA_SER: Res1 LenVal %u > 7-bit. Clamping.", ra_fields->length_val_res1); }
    ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_val_res1 & 0x7F, 7);
    if (ret < 0) { LOG_ERR("RA_SER: Write Res1 Length failed: %d", ret); return ret; }
    bit_offset = ret;

    // Resource 2 Fields (if alloc_type is BIDIR)
    if (ra_fields->alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
        uint8_t res2_start_subslot_num_bits = ra_fields->res2_is_9bit_subslot ? 9 : 8;
        if (ra_fields->start_subslot_val_res2 >= (1U << res2_start_subslot_num_bits)) {
            LOG_WRN("RA_SER: Res2 StartSS %u too large for %u bits. Truncating.",
                    ra_fields->start_subslot_val_res2, res2_start_subslot_num_bits);
        }
        ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->start_subslot_val_res2, res2_start_subslot_num_bits);
        if (ret < 0) { LOG_ERR("RA_SER: Write Res2 StartSS failed: %d", ret); return ret; }
        bit_offset = ret;

        ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_type_is_slots_res2 ? 1 : 0, 1);
        if (ret < 0) { LOG_ERR("RA_SER: Write Res2 LenType failed: %d", ret); return ret; }
        bit_offset = ret;

        if (ra_fields->length_val_res2 > 0x7F) { LOG_WRN("RA_SER: Res2 LenVal %u > 7-bit. Clamping.", ra_fields->length_val_res2); }
        ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_val_res2 & 0x7F, 7);
        if (ret < 0) { LOG_ERR("RA_SER: Write Res2 Length failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    // Byte alignment padding before optional octet-aligned fields
    if (bit_offset % 8 != 0) {
        int padding_bits = 8 - (bit_offset % 8);
        ret = write_bits(buf, buf_max_len, bit_offset, 0, (uint8_t)padding_bits);
        if (ret < 0) { LOG_ERR("RA_SER: Padding failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    // --- Optional Fields (Byte Aligned) ---
    // Ensure buffer pointers and lengths are managed correctly from here.
    uint8_t *current_byte_ptr = buf + (bit_offset / 8);
    size_t remaining_byte_buf_len = buf_max_len - (bit_offset / 8);

    if (ra_fields->id_present) {
        if (remaining_byte_buf_len < 2) { LOG_ERR("RA_SER: No space for ShortRDID"); return -ENOMEM; }
        sys_put_be16(ra_fields->short_rd_id_val, current_byte_ptr);
        current_byte_ptr += 2; remaining_byte_buf_len -= 2; bit_offset += 16;
    }

    if (ra_fields->repeat_val != RES_ALLOC_REPEAT_SINGLE) {
        if (remaining_byte_buf_len < 2) { LOG_ERR("RA_SER: No space for Repetition/Validity"); return -ENOMEM; }
        *current_byte_ptr++ = ra_fields->repetition_value;
        *current_byte_ptr++ = ra_fields->validity_value;
        remaining_byte_buf_len -= 2; bit_offset += 16;
    }

    if (ra_fields->sfn_present) {
        if (remaining_byte_buf_len < 1) { LOG_ERR("RA_SER: No space for SFN value"); return -ENOMEM; }
        *current_byte_ptr++ = ra_fields->sfn_val;
        remaining_byte_buf_len -= 1; bit_offset += 8;
    }

    if (ra_fields->channel_present) {
        if (remaining_byte_buf_len < 2) { LOG_ERR("RA_SER: No space for Channel value"); return -ENOMEM; }
        uint16_t chan_field_on_air = (ra_fields->channel_val & 0x1FFF) << 3;
        sys_put_be16(chan_field_on_air, current_byte_ptr);
        current_byte_ptr += 2; remaining_byte_buf_len -= 2; bit_offset += 16;
    }

    if (ra_fields->rlf_present) {
        if (remaining_byte_buf_len < 1) { LOG_ERR("RA_SER: No space for RLF value"); return -ENOMEM; }
        *current_byte_ptr++ = (ra_fields->dect_sched_res_fail_timer_code & 0x0F) << 4;
        // remaining_byte_buf_len -= 1; // This was missing, but current_byte_ptr advanced
        bit_offset += 8;
    }

    return (bit_offset + 7) / 8; // Total bytes written
}


/**
 * @brief Deserializes the payload of a Resource Allocation IE.
 * Ref: ETSI TS 103 636-4, Clause 6.4.3.3 & Table 6.4.3.3-1
 *
 * @param ie_payload Pointer to the start of the Resource Allocation IE payload.
 * @param ie_payload_len Length of the IE payload in bytes.
 * @param out_ra_fields Pointer to the structure to store the deserialized fields.
 *                      The caller should pre-set out_ra_fields->resX_is_9bit_subslot based on 'mu'
 *                      if known, otherwise this parser assumes 8-bit for start_subslot fields
 *                      unless specific bitmap encoding for 9-bit MSBs were implemented and detected.
 * @return 0 on success, or a negative error code on failure (e.g., -EMSGSIZE if payload too short).
 */


int parse_resource_alloc_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                    uint8_t link_mu_value, /* New parameter */
                                    dect_mac_resource_alloc_ie_fields_t *out_ra_fields)
{
    if (!ie_payload || !out_ra_fields) {
        LOG_ERR("RA_PARSE: NULL input pointers.");
        return -EINVAL;
    }
    if (ie_payload_len < 1) {
        LOG_ERR("RA_PARSE: Payload too short (%u bytes) for Res Alloc IE base.", ie_payload_len);
        return -EMSGSIZE;
    }
    if (link_mu_value == 0 || link_mu_value > 8) {
        LOG_WRN("RA_PARSE: Invalid link_mu_value: %u. Assuming mu <= 4 for 8-bit start_subslot.", link_mu_value);
        link_mu_value = (link_mu_value == 0) ? 1 : (link_mu_value > 8 ? 1 : link_mu_value); // Sanitize
    }

    memset(out_ra_fields, 0, sizeof(dect_mac_resource_alloc_ie_fields_t));
    out_ra_fields->res1_is_9bit_subslot = (link_mu_value > 4); // True if mu > 4
    out_ra_fields->res2_is_9bit_subslot = (link_mu_value > 4); // True if mu > 4

    int bit_offset = 0;
    int remaining_bits_from_len = ie_payload_len * 8;
    int *remaining_bits = &remaining_bits_from_len;

    // Octet 0 of Bitmap
    if (*remaining_bits < 8) return -EMSGSIZE;
    uint8_t bitmap_octet0 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_ra_fields->alloc_type_val   = (dect_alloc_type_t)((bitmap_octet0 >> 6) & 0x03);
    out_ra_fields->add_allocation   = (bitmap_octet0 >> 5) & 0x01;
    out_ra_fields->id_present       = (bitmap_octet0 >> 4) & 0x01;
    out_ra_fields->repeat_val       = (dect_repeat_type_t)((bitmap_octet0 >> 1) & 0x07);
    out_ra_fields->sfn_present      = bitmap_octet0 & 0x01;

    LOG_DBG("RA_PARSE: BMP0: AllocType:%u Add:%d IDPres:%d Repeat:%u SFNPres:%d",
            out_ra_fields->alloc_type_val, out_ra_fields->add_allocation, out_ra_fields->id_present,
            out_ra_fields->repeat_val, out_ra_fields->sfn_present);

    if (out_ra_fields->alloc_type_val == RES_ALLOC_TYPE_RELEASE_ALL) {
        if (ie_payload_len != 1) {
            LOG_WRN("RA_PARSE: AllocType RELEASE_ALL but payload len is %u bytes (expected 1).", ie_payload_len);
        }
        return 0;
    }

    uint8_t res1_ss_bits = out_ra_fields->res1_is_9bit_subslot ? 9 : 8;
    int min_bits_needed_after_bmp0 = 8 + res1_ss_bits + 1 + 7; // BMP1 + Res1 fields
    if (out_ra_fields->alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
        uint8_t res2_ss_bits = out_ra_fields->res2_is_9bit_subslot ? 9 : 8;
        min_bits_needed_after_bmp0 += (res2_ss_bits + 1 + 7);
    }
    if (*remaining_bits < min_bits_needed_after_bmp0) {
        LOG_ERR("RA_PARSE: Not enough bits for Bitmap1 + mandatory Res fields (need %d, have %d).", min_bits_needed_after_bmp0, *remaining_bits);
        return -EMSGSIZE;
    }

    // Octet 1 of Bitmap
    uint8_t bitmap_octet1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_ra_fields->channel_present  = (bitmap_octet1 >> 7) & 0x01;
    out_ra_fields->rlf_present      = (bitmap_octet1 >> 6) & 0x01;
    // Bits 5-0 are reserved.

    // Resource 1 Fields
    out_ra_fields->start_subslot_val_res1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, res1_ss_bits);
    out_ra_fields->length_type_is_slots_res1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 1);
    out_ra_fields->length_val_res1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 7);

    // Resource 2 Fields (if alloc_type is BIDIR)
    if (out_ra_fields->alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
        uint8_t res2_ss_bits = out_ra_fields->res2_is_9bit_subslot ? 9 : 8;
        // No need to re-check remaining_bits here as it was part of min_bits_needed_after_bmp0
        out_ra_fields->start_subslot_val_res2 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, res2_ss_bits);
        out_ra_fields->length_type_is_slots_res2 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 1);
        out_ra_fields->length_val_res2 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 7);
    }

    // Optional Fields (these start after byte alignment)
    if (bit_offset % 8 != 0) {
        int padding_to_read = 8 - (bit_offset % 8);
        if (*remaining_bits < padding_to_read) { LOG_ERR("RA_PARSE: Not enough bits for alignment padding (%d needed, %d have).", padding_to_read, *remaining_bits); return -EMSGSIZE; }
        read_bits_adv(ie_payload, &bit_offset, remaining_bits, (uint8_t)padding_to_read);
    }

    const uint8_t *current_byte_ptr_opts = ie_payload + (bit_offset / 8);
    // Calculate remaining_byte_len_opts based on *remaining_bits* which is accurately tracked
    uint16_t remaining_byte_len_opts = (*remaining_bits) / 8;

    if (out_ra_fields->id_present) {
        if (remaining_byte_len_opts < 2) { LOG_ERR("RA_PARSE: Payload too short for ShortRDID."); return -EMSGSIZE; }
        out_ra_fields->short_rd_id_val = sys_get_be16(current_byte_ptr_opts);
        current_byte_ptr_opts += 2; remaining_byte_len_opts -= 2; *remaining_bits -= 16;
    }

    if (out_ra_fields->repeat_val != RES_ALLOC_REPEAT_SINGLE) {
        if (remaining_byte_len_opts < 2) { LOG_ERR("RA_PARSE: Payload too short for Repetition/Validity."); return -EMSGSIZE; }
        out_ra_fields->repetition_value = *current_byte_ptr_opts++;
        out_ra_fields->validity_value   = *current_byte_ptr_opts++;
        remaining_byte_len_opts -= 2; *remaining_bits -= 16;
    }

    if (out_ra_fields->sfn_present) {
        if (remaining_byte_len_opts < 1) { LOG_ERR("RA_PARSE: Payload too short for SFN value."); return -EMSGSIZE; }
        out_ra_fields->sfn_val = *current_byte_ptr_opts++;
        remaining_byte_len_opts -= 1; *remaining_bits -= 8;
    }

    if (out_ra_fields->channel_present) {
        if (remaining_byte_len_opts < 2) { LOG_ERR("RA_PARSE: Payload too short for Channel value."); return -EMSGSIZE; }
        uint16_t chan_field_on_air = sys_get_be16(current_byte_ptr_opts);
        current_byte_ptr_opts += 2; remaining_byte_len_opts -= 2; *remaining_bits -= 16;
        out_ra_fields->channel_val = (chan_field_on_air >> 3) & 0x1FFF;
    }

    if (out_ra_fields->rlf_present) {
        if (remaining_byte_len_opts < 1) { LOG_ERR("RA_PARSE: Payload too short for RLF value."); return -EMSGSIZE; }
        out_ra_fields->dect_sched_res_fail_timer_code = (*current_byte_ptr_opts++ >> 4) & 0x0F;
        // remaining_byte_len_opts -= 1; // This was correctly handled by current_byte_ptr_opts++
        *remaining_bits -= 8;
    }

    if (*remaining_bits > 0 && *remaining_bits < 8) {
        LOG_WRN("RA_PARSE: %d unparsed bits remain (padding or error at end). Payload len %u.",
                *remaining_bits, ie_payload_len);
    } else if (*remaining_bits >= 8) {
         LOG_WRN("RA_PARSE: %d unparsed bits (>=1 byte) remain. Payload len %u. Likely unparsed optional IEs or error.",
                *remaining_bits, ie_payload_len);
    }
    return 0;
}


// --- Functions to build SDU Area content (MUXed IEs) ---
/**
 * @brief Builds the MAC SDU Area content for an Association Request PDU.
 * This area will contain MUXed IEs: Association Request IE and RD Capability IE.
 *
 * @param target_ie_area_buf Buffer to write the SDU Area content into.
 * @param target_buf_max_len Maximum length of the `target_ie_area_buf`.
 * @param req_ie_fields Pointer to the structure holding the fields for the Association Request IE.
 * @param cap_ie_fields Pointer to the structure holding the fields for the RD Capability IE.
 * @return Total length of the built SDU Area in bytes, or a negative error code on failure.
 */
int build_assoc_req_ies_area(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                             const dect_mac_assoc_req_ie_t *req_ie_fields,
                             const dect_mac_rd_capability_ie_t *cap_ie_fields)
{
    if (!target_ie_area_buf || !req_ie_fields || !cap_ie_fields) {
        LOG_ERR("ASSOC_REQ_AREA: NULL input pointers.");
        return -EINVAL;
    }

    int current_offset_bytes = 0;
    int mux_hdr_len_bytes;
    int ie_payload_len_bytes;
    int ret;

    // Temporary buffer to hold the serialized payload of a single IE before MUX header is added.
    // Size generously for the largest of these two IEs (RD Capability can be larger).
    uint8_t temp_ie_payload_buf[64 + 5]; // Max RD cap summary (2) + ~12 sets * 5 bytes/set = ~62. Give some room.

    // 1. Serialize and MUX the Association Request IE
    ie_payload_len_bytes = serialize_assoc_req_ie_payload(temp_ie_payload_buf,
                                                          sizeof(temp_ie_payload_buf),
                                                          req_ie_fields);
    if (ie_payload_len_bytes < 0) {
        LOG_ERR("ASSOC_REQ_AREA: Failed to serialize Association Request IE payload: %d", ie_payload_len_bytes);
        return ie_payload_len_bytes;
    }

    mux_hdr_len_bytes = build_mac_mux_header_internal(target_ie_area_buf + current_offset_bytes,
                                               target_buf_max_len - current_offset_bytes,
                                               IE_TYPE_ASSOC_REQ, (uint16_t)ie_payload_len_bytes,
                                               0 /* auto-detect MAC_Ext format */);
    if (mux_hdr_len_bytes < 0) {
        LOG_ERR("ASSOC_REQ_AREA: Failed to build MUX header for Association Request IE: %d", mux_hdr_len_bytes);
        return mux_hdr_len_bytes;
    }
    current_offset_bytes += mux_hdr_len_bytes;

    if (current_offset_bytes + ie_payload_len_bytes > target_buf_max_len) {
        LOG_ERR("ASSOC_REQ_AREA: Buffer overflow when adding Association Request IE payload.");
        return -ENOMEM;
    }
    memcpy(target_ie_area_buf + current_offset_bytes, temp_ie_payload_buf, ie_payload_len_bytes);
    current_offset_bytes += ie_payload_len_bytes;
    LOG_DBG("ASSOC_REQ_AREA: Added MUXed AssocReqIE (MuxHdr %d, Pyld %d, Total %d bytes). Current offset %d.",
            mux_hdr_len_bytes, ie_payload_len_bytes, mux_hdr_len_bytes + ie_payload_len_bytes, current_offset_bytes);

    // 2. Serialize and MUX the RD Capability IE
    ie_payload_len_bytes = serialize_rd_capability_ie_payload(temp_ie_payload_buf,
                                                              sizeof(temp_ie_payload_buf),
                                                              cap_ie_fields);
    if (ie_payload_len_bytes < 0) {
        LOG_ERR("ASSOC_REQ_AREA: Failed to serialize RD Capability IE payload: %d", ie_payload_len_bytes);
        return ie_payload_len_bytes;
    }

    mux_hdr_len_bytes = build_mac_mux_header_internal(target_ie_area_buf + current_offset_bytes,
                                               target_buf_max_len - current_offset_bytes,
                                               IE_TYPE_RD_CAPABILITY, (uint16_t)ie_payload_len_bytes,
                                               0 /* auto-detect MAC_Ext format */);
    if (mux_hdr_len_bytes < 0) {
        LOG_ERR("ASSOC_REQ_AREA: Failed to build MUX header for RD Capability IE: %d", mux_hdr_len_bytes);
        return mux_hdr_len_bytes;
    }
    current_offset_bytes += mux_hdr_len_bytes;

    if (current_offset_bytes + ie_payload_len_bytes > target_buf_max_len) {
        LOG_ERR("ASSOC_REQ_AREA: Buffer overflow when adding RD Capability IE payload.");
        return -ENOMEM;
    }
    memcpy(target_ie_area_buf + current_offset_bytes, temp_ie_payload_buf, ie_payload_len_bytes);
    current_offset_bytes += ie_payload_len_bytes;
    LOG_DBG("ASSOC_REQ_AREA: Added MUXed RDCapIE (MuxHdr %d, Pyld %d, Total %d bytes). Current offset %d.",
            mux_hdr_len_bytes, ie_payload_len_bytes, mux_hdr_len_bytes + ie_payload_len_bytes, current_offset_bytes);

    // Add other optional IEs for Association Request if needed by iterating further.

    return current_offset_bytes; // Total length of the SDU Area written
}


/**
 * @brief Builds the MAC SDU Area content for an Association Response PDU.
 * This typically includes: Association Response IE, and if ACK, also FT's
 * RD Capability IE and a Resource Allocation IE.
 * Any MAC Security Info IE (if response is secured) should be prepended to the
 * target_sdu_area_buf by the caller *before* invoking this function, and
 * current_sdu_area_offset should reflect its length.
 *
 * @param target_sdu_area_buf Buffer to write the SDU Area content into (potentially after other IEs).
 * @param target_sdu_area_max_len Maximum total length of the `target_sdu_area_buf`.
 * @param initial_offset The offset in `target_sdu_area_buf` where these IEs should start being written.
 *                       This is used if, for example, a MAC Security Info IE has already been written.
 * @param resp_fields Pointer to the structure holding fields for the Association Response IE.
 * @param ft_cap_fields Pointer to FT's RD Capability IE fields. Only used if resp_fields->ack_nack is true. Can be NULL if NACK.
 * @param res_alloc_fields Pointer to Resource Allocation IE fields. Only used if resp_fields->ack_nack is true. Can be NULL if NACK.
 * @return Total length of the IEs written by *this function call* (excluding initial_offset),
 *         or a negative error code on failure.
 */
int build_assoc_resp_sdu_area_content(uint8_t *target_sdu_area_buf, size_t target_sdu_area_max_len,
                                      int initial_offset, /* Offset to start writing from */
                                      const dect_mac_assoc_resp_ie_t *resp_fields,
                                      const dect_mac_rd_capability_ie_t *ft_cap_fields,
                                      const dect_mac_resource_alloc_ie_fields_t *res_alloc_fields)
{
    if (!target_sdu_area_buf || !resp_fields) {
        LOG_ERR("ASSOC_RESP_AREA: NULL target_sdu_area_buf or resp_fields.");
        return -EINVAL;
    }
    if (resp_fields->ack_nack && (!ft_cap_fields || !res_alloc_fields)) {
        LOG_ERR("ASSOC_RESP_AREA: ACK response but ft_cap_fields or res_alloc_fields is NULL.");
        return -EINVAL;
    }
    if ((size_t)initial_offset >= target_sdu_area_max_len) {
        LOG_ERR("ASSOC_RESP_AREA: Initial offset %d >= max buffer len %zu.", initial_offset, target_sdu_area_max_len);
        return -ENOMEM;
    }

    int current_write_offset_in_buf = initial_offset; // Where to start writing in the target_sdu_area_buf
    int bytes_written_by_this_func = 0;
    int mux_hdr_len_bytes;
    int ie_payload_len_bytes;
    int ret;

    // Temporary buffer for individual IE payloads
    uint8_t temp_ie_payload_buf[128]; // Sufficient for these IEs (ResAlloc can be largest of these)

    // 1. Serialize and MUX the Association Response IE
    ie_payload_len_bytes = serialize_assoc_resp_ie_payload(temp_ie_payload_buf,
                                                           sizeof(temp_ie_payload_buf),
                                                           resp_fields);
    if (ie_payload_len_bytes < 0) {
        LOG_ERR("ASSOC_RESP_AREA: Failed to serialize Association Response IE payload: %d", ie_payload_len_bytes);
        return ie_payload_len_bytes;
    }

    mux_hdr_len_bytes = build_mac_mux_header_internal(target_sdu_area_buf + current_write_offset_in_buf,
                                               target_sdu_area_max_len - current_write_offset_in_buf,
                                               IE_TYPE_ASSOC_RESP, (uint16_t)ie_payload_len_bytes,
                                               0 /* auto-detect MAC_Ext */);
    if (mux_hdr_len_bytes < 0) {
        LOG_ERR("ASSOC_RESP_AREA: Failed to build MUX header for AssocResp IE: %d", mux_hdr_len_bytes);
        return mux_hdr_len_bytes;
    }
    current_write_offset_in_buf += mux_hdr_len_bytes;
    bytes_written_by_this_func += mux_hdr_len_bytes;

    if (current_write_offset_in_buf + ie_payload_len_bytes > target_sdu_area_max_len) {
        LOG_ERR("ASSOC_RESP_AREA: Buffer overflow for AssocResp IE payload.");
        return -ENOMEM;
    }
    memcpy(target_sdu_area_buf + current_write_offset_in_buf, temp_ie_payload_buf, ie_payload_len_bytes);
    current_write_offset_in_buf += ie_payload_len_bytes;
    bytes_written_by_this_func += ie_payload_len_bytes;
    LOG_DBG("ASSOC_RESP_AREA: Added MUXed AssocRespIE (MuxHdr %d, Pyld %d). Total written now: %d.",
            mux_hdr_len_bytes, ie_payload_len_bytes, bytes_written_by_this_func);

    // If Association was NACK'd (rejected), only the Association Response IE is sent.
    if (!resp_fields->ack_nack) {
        return bytes_written_by_this_func;
    }

    // If ACK, add FT's RD Capability IE and Resource Allocation IE
    if (ft_cap_fields) { // Should always be true if ack_nack is true due to initial check
        ie_payload_len_bytes = serialize_rd_capability_ie_payload(temp_ie_payload_buf,
                                                                  sizeof(temp_ie_payload_buf),
                                                                  ft_cap_fields);
        if (ie_payload_len_bytes < 0) { LOG_ERR("ASSOC_RESP_AREA: Serialize FT RD Cap IE failed: %d", ie_payload_len_bytes); return ie_payload_len_bytes; }

        mux_hdr_len_bytes = build_mac_mux_header_internal(target_sdu_area_buf + current_write_offset_in_buf,
                                                   target_sdu_area_max_len - current_write_offset_in_buf,
                                                   IE_TYPE_RD_CAPABILITY, (uint16_t)ie_payload_len_bytes, 0);
        if (mux_hdr_len_bytes < 0) { LOG_ERR("ASSOC_RESP_AREA: Build MUX for FT RD Cap IE failed: %d", mux_hdr_len_bytes); return mux_hdr_len_bytes; }
        current_write_offset_in_buf += mux_hdr_len_bytes;
        bytes_written_by_this_func += mux_hdr_len_bytes;

        if (current_write_offset_in_buf + ie_payload_len_bytes > target_sdu_area_max_len) { LOG_ERR("ASSOC_RESP_AREA: Overflow for FT RD Cap IE payload."); return -ENOMEM; }
        memcpy(target_sdu_area_buf + current_write_offset_in_buf, temp_ie_payload_buf, ie_payload_len_bytes);
        current_write_offset_in_buf += ie_payload_len_bytes;
        bytes_written_by_this_func += ie_payload_len_bytes;
        LOG_DBG("ASSOC_RESP_AREA: Added MUXed FT_RDCapIE (MuxHdr %d, Pyld %d). Total written now: %d.",
                mux_hdr_len_bytes, ie_payload_len_bytes, bytes_written_by_this_func);
    }

    if (res_alloc_fields) { // Should always be true if ack_nack is true
        ie_payload_len_bytes = serialize_resource_alloc_ie_payload(temp_ie_payload_buf,
                                                                   sizeof(temp_ie_payload_buf),
                                                                   res_alloc_fields);
        if (ie_payload_len_bytes < 0) { LOG_ERR("ASSOC_RESP_AREA: Serialize Res Alloc IE failed: %d", ie_payload_len_bytes); return ie_payload_len_bytes; }

        mux_hdr_len_bytes = build_mac_mux_header_internal(target_sdu_area_buf + current_write_offset_in_buf,
                                                   target_sdu_area_max_len - current_write_offset_in_buf,
                                                   IE_TYPE_RES_ALLOC, (uint16_t)ie_payload_len_bytes, 0);
        if (mux_hdr_len_bytes < 0) { LOG_ERR("ASSOC_RESP_AREA: Build MUX for Res Alloc IE failed: %d", mux_hdr_len_bytes); return mux_hdr_len_bytes; }
        current_write_offset_in_buf += mux_hdr_len_bytes;
        bytes_written_by_this_func += mux_hdr_len_bytes;

        if (current_write_offset_in_buf + ie_payload_len_bytes > target_sdu_area_max_len) { LOG_ERR("ASSOC_RESP_AREA: Overflow for Res Alloc IE payload."); return -ENOMEM; }
        memcpy(target_sdu_area_buf + current_write_offset_in_buf, temp_ie_payload_buf, ie_payload_len_bytes);
        // current_write_offset_in_buf += ie_payload_len_bytes; // Not needed if last IE
        bytes_written_by_this_func += ie_payload_len_bytes;
        LOG_DBG("ASSOC_RESP_AREA: Added MUXed ResAllocIE (MuxHdr %d, Pyld %d). Total written by func: %d.",
                 mux_hdr_len_bytes, ie_payload_len_bytes, bytes_written_by_this_func);
    }

    return bytes_written_by_this_func; // Total length of the IEs added by this function
}



/**
 * @brief Builds the MAC SDU Area content for a Beacon PDU.
 * This area will contain MUXed IEs: Cluster Beacon IE and RACH Information IE.
 * Optionally, other IEs like Route Info or Load Info can be added later.
 *
 * @param target_sdu_area_buf Buffer to write the SDU Area content into.
 * @param target_sdu_area_max_len Maximum length of the `target_sdu_area_buf`.
 * @param cb_fields Pointer to the structure holding fields for the Cluster Beacon IE.
 * @param rach_beacon_ie_fields Pointer to the structure holding fields for the RACH Info IE (as advertised in beacon).
 * @return Total length of the built SDU Area in bytes, or a negative error code on failure.
 */
int build_beacon_sdu_area_content(uint8_t *target_sdu_area_buf, size_t target_sdu_area_max_len,
                                  const dect_mac_cluster_beacon_ie_fields_t *cb_fields,
                                  const dect_mac_rach_info_ie_fields_t *rach_beacon_ie_fields)
{
    if (!target_sdu_area_buf || !cb_fields || !rach_beacon_ie_fields) {
        LOG_ERR("BEACON_SDU_AREA: NULL input pointers.");
        return -EINVAL;
    }

    int current_offset_bytes = 0;
    int mux_hdr_len_bytes;
    int ie_payload_len_bytes;
    int ret;

    // Temporary buffer for individual IE payloads.
    // Cluster Beacon IE can be ~15 bytes, RACH Info ~10-15 bytes.
    uint8_t temp_ie_payload_buf[40]; // Max size for one of these IEs.

    // 1. Serialize and MUX the Cluster Beacon IE
    ie_payload_len_bytes = serialize_cluster_beacon_ie_payload(temp_ie_payload_buf,
                                                               sizeof(temp_ie_payload_buf),
                                                               cb_fields);
    if (ie_payload_len_bytes < 0) {
        LOG_ERR("BEACON_SDU_AREA: Failed to serialize Cluster Beacon IE payload: %d", ie_payload_len_bytes);
        return ie_payload_len_bytes;
    }

    mux_hdr_len_bytes = build_mac_mux_header_internal(target_sdu_area_buf + current_offset_bytes,
                                               target_sdu_area_max_len - current_offset_bytes,
                                               IE_TYPE_CLUSTER_BEACON, (uint16_t)ie_payload_len_bytes,
                                               0 /* auto-detect MAC_Ext format */);
    if (mux_hdr_len_bytes < 0) {
        LOG_ERR("BEACON_SDU_AREA: Failed to build MUX header for Cluster Beacon IE: %d", mux_hdr_len_bytes);
        return mux_hdr_len_bytes;
    }
    current_offset_bytes += mux_hdr_len_bytes;

    if (current_offset_bytes + ie_payload_len_bytes > target_sdu_area_max_len) {
        LOG_ERR("BEACON_SDU_AREA: Buffer overflow when adding Cluster Beacon IE payload.");
        return -ENOMEM;
    }
    memcpy(target_sdu_area_buf + current_offset_bytes, temp_ie_payload_buf, ie_payload_len_bytes);
    current_offset_bytes += ie_payload_len_bytes;
    LOG_DBG("BEACON_SDU_AREA: Added MUXed ClusterBeaconIE (MuxHdr %d, Pyld %d). Offset %d.",
            mux_hdr_len_bytes, ie_payload_len_bytes, current_offset_bytes);


    // 2. Serialize and MUX the RACH Information IE
    ie_payload_len_bytes = serialize_rach_info_ie_payload(temp_ie_payload_buf,
                                                          sizeof(temp_ie_payload_buf),
                                                          rach_beacon_ie_fields);
    if (ie_payload_len_bytes < 0) {
        LOG_ERR("BEACON_SDU_AREA: Failed to serialize RACH Info IE payload: %d", ie_payload_len_bytes);
        return ie_payload_len_bytes;
    }

    mux_hdr_len_bytes = build_mac_mux_header_internal(target_sdu_area_buf + current_offset_bytes,
                                               target_sdu_area_max_len - current_offset_bytes,
                                               IE_TYPE_RACH_INFO, (uint16_t)ie_payload_len_bytes,
                                               0 /* auto-detect MAC_Ext format */);
    if (mux_hdr_len_bytes < 0) {
        LOG_ERR("BEACON_SDU_AREA: Failed to build MUX header for RACH Info IE: %d", mux_hdr_len_bytes);
        return mux_hdr_len_bytes;
    }
    current_offset_bytes += mux_hdr_len_bytes;

    if (current_offset_bytes + ie_payload_len_bytes > target_sdu_area_max_len) {
        LOG_ERR("BEACON_SDU_AREA: Buffer overflow when adding RACH Info IE payload.");
        return -ENOMEM;
    }
    memcpy(target_sdu_area_buf + current_offset_bytes, temp_ie_payload_buf, ie_payload_len_bytes);
    current_offset_bytes += ie_payload_len_bytes;
    LOG_DBG("BEACON_SDU_AREA: Added MUXed RACHInfoIE (MuxHdr %d, Pyld %d). Total SDU Area: %d.",
            mux_hdr_len_bytes, ie_payload_len_bytes, current_offset_bytes);

    // TODO: Optionally add Route Info IE if FT is part of a mesh network.
    // TODO: Optionally add Load Info IE.

    return current_offset_bytes; // Total length of the SDU Area written
}

int build_broadcast_indication_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                                        uint16_t paged_pt_short_id)
{
    // ETSI 6.4.3.7: The payload is a list of Short_RD-IDs.
    // For simplicity, we will page one PT at a time.
    uint8_t payload[2];
    sys_put_be16(paged_pt_short_id, payload);
    size_t payload_len = sizeof(payload);

    int mux_hdr_len = build_mac_mux_header_internal(target_ie_area_buf, target_buf_max_len,
                                                  IE_TYPE_BROADCAST_IND, payload_len, 0);
    if (mux_hdr_len < 0) {
        return mux_hdr_len;
    }
    if ((size_t)mux_hdr_len + payload_len > target_buf_max_len) {
        return -ENOMEM;
    }

    memcpy(target_ie_area_buf + mux_hdr_len, payload, payload_len);
    return mux_hdr_len + payload_len;
}

int build_keep_alive_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len) {
    // Short IE, 0 byte payload. MAC_Ext = 11 (override code 4), Length bit = 0.
    return build_mac_mux_header_internal(target_ie_area_buf, target_buf_max_len,
                                         IE_TYPE_SHORT_KEEP_ALIVE, 0, 4);
}

int build_mac_security_info_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                                     uint8_t version, uint8_t key_index,
                                     uint8_t sec_iv_type, uint32_t hpc_val)
{
    dect_mac_security_info_ie_payload_t payload;
    // Ensure version, key_index, sec_iv_type are within their bitfield limits before shifting
    payload.version_keyidx_secivtype = (((version & 0x03) << MAC_SEC_IE_VERSION_SHIFT) & MAC_SEC_IE_VERSION_MASK) |
                                     (((key_index & 0x07) << MAC_SEC_IE_KEYIDX_SHIFT) & MAC_SEC_IE_KEYIDX_MASK) |
                                     (((sec_iv_type & 0x07) << MAC_SEC_IE_SECIVTYPE_SHIFT) & MAC_SEC_IE_SECIVTYPE_MASK);
    payload.hpc_be = sys_cpu_to_be32(hpc_val);
    size_t payload_len = sizeof(payload); // Fixed length payload for this IE

    // MAC_Ext=01 (8-bit length) or 00 (fixed length by type) could be used.
    // Let's use 01 for clarity on length, even if fixed. Auto-detect (0) would pick 01.
    int mux_hdr_len = build_mac_mux_header_internal(target_ie_area_buf, target_buf_max_len,
                                                  IE_TYPE_MAC_SECURITY_INFO, (uint16_t)payload_len, 0);
    if (mux_hdr_len < 0) return mux_hdr_len;
    if ((size_t)mux_hdr_len + payload_len > target_buf_max_len) return -ENOMEM;

    memcpy(target_ie_area_buf + mux_hdr_len, &payload, payload_len);
    return mux_hdr_len + payload_len;
}

int parse_mac_security_info_ie_payload(const uint8_t *ie_payload, uint16_t ie_payload_len,
                                       uint8_t *out_version, uint8_t *out_key_index,
                                       uint8_t *out_sec_iv_type, uint32_t *out_hpc_val)
{
    if (!ie_payload || !out_version || !out_key_index || !out_sec_iv_type || !out_hpc_val) return -EINVAL;
    if (ie_payload_len < sizeof(dect_mac_security_info_ie_payload_t)) {
        LOG_ERR("SEC_IE_PARSE: Payload too short (%u bytes) for MAC Sec Info IE.", ie_payload_len);
        return -EMSGSIZE;
    }
    const dect_mac_security_info_ie_payload_t *p = (const dect_mac_security_info_ie_payload_t *)ie_payload;
    *out_version     = (p->version_keyidx_secivtype & MAC_SEC_IE_VERSION_MASK) >> MAC_SEC_IE_VERSION_SHIFT;
    *out_key_index   = (p->version_keyidx_secivtype & MAC_SEC_IE_KEYIDX_MASK) >> MAC_SEC_IE_KEYIDX_SHIFT;
    *out_sec_iv_type = (p->version_keyidx_secivtype & MAC_SEC_IE_SECIVTYPE_MASK) >> MAC_SEC_IE_SECIVTYPE_SHIFT;
    *out_hpc_val     = sys_be32_to_cpu(p->hpc_be);
    return 0;
}

int build_user_data_ie_muxed(uint8_t *target_ie_area_buf, size_t target_buf_max_len,
                             const uint8_t *dlc_pdu_data, uint16_t dlc_pdu_len,
                             uint8_t user_data_flow_ie_type)
{
    if (!target_ie_area_buf || (!dlc_pdu_data && dlc_pdu_len > 0) || dlc_pdu_len > UINT16_MAX) { // UINT16_MAX check from MUX header
        return -EINVAL;
    }
    // user_data_flow_ie_type should be one of IE_TYPE_USER_DATA_FLOW_X

    // Auto-detect MAC_Ext format based on dlc_pdu_len (0 for auto-detect)
    int mux_hdr_len = build_mac_mux_header_internal(target_ie_area_buf, target_buf_max_len,
                                                  user_data_flow_ie_type, dlc_pdu_len, 0);
    if (mux_hdr_len < 0) return mux_hdr_len;
    if ((size_t)mux_hdr_len + dlc_pdu_len > target_buf_max_len) return -ENOMEM;

    if (dlc_pdu_data && dlc_pdu_len > 0) {
        memcpy(target_ie_area_buf + mux_hdr_len, dlc_pdu_data, dlc_pdu_len);
    }
    return mux_hdr_len + dlc_pdu_len;
}