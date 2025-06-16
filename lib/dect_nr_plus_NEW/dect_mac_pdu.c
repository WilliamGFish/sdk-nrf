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

    memset(buf, 0, buf_max_len); // Initialize buffer to ensure reserved bits are 0
    int bit_offset = 0;
    int ret;

    // Octet 0: Flags
    // Bit 7: Reserved (0)
    // Bit 6: Repeat Type (0=frames, 1=subslots)
    // Bit 5: SFN Validity (0=not present, 1=present)
    // Bit 4: Channel Field (0=current, 1=specific channel field present)
    // Bit 3: Channel_2 Field (0=same as RACH, 1=specific channel_2 field present for response)
    // Bit 2: MAX Len type (0=subslots, 1=slots)
    // Bit 1: DECT_Delay (0=n+HARQ_delay+1, 1=0.5 frames after RACH TX start)
    // Bit 0: Reserved (0)
    uint8_t flags_octet0 = 0;
    WRITE_BIT(flags_octet0, 6, rach_fields->repeat_type_is_subslots);
    WRITE_BIT(flags_octet0, 5, rach_fields->sfn_validity_present);
    WRITE_BIT(flags_octet0, 4, rach_fields->channel_field_present);
    WRITE_BIT(flags_octet0, 3, rach_fields->channel2_field_present);
    WRITE_BIT(flags_octet0, 2, rach_fields->max_len_type_is_slots);
    WRITE_BIT(flags_octet0, 1, rach_fields->dect_delay_for_response);
    ret = write_bits(buf, buf_max_len, bit_offset, flags_octet0, 8);
    if (ret < 0) return ret;
    bit_offset = ret;

    // Octets 1-2 (actually 17 bits total):
    // Start Subslot (9 bits if mu > 4, else 8 bits), Length Type (1 bit), Length (7 bits)
    // TODO: Actual mu value for the FT needs to be known to select 8 or 9 bits for Start Subslot.
    // Assuming FT uses mu <= 4 for its beacon RACH info for wider compatibility, so 8 bits for Start Subslot.
    // If FT's mu (from its capabilities or system config) indicates 9 bits are needed:
    // uint8_t start_subslot_num_bits = (ctx->phy_caps_for_beacon.mu > 4) ? 9 : 8; // Example
    uint8_t start_subslot_num_bits = 8; // Simplification: Assume 8 bits for now
    if (rach_fields->start_subslot_index >= (1 << start_subslot_num_bits) && start_subslot_num_bits == 8) {
        // If it doesn't fit 8 bits, but we assumed 8, try 9 (if this was a dynamic check)
        // For now, we stick to the assumption or it's an error in population.
         LOG_WRN("RACH_SER: Start subslot %u too large for %u bits. Truncating or error.",
                rach_fields->start_subslot_index, start_subslot_num_bits);
    }


    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->start_subslot_index, start_subslot_num_bits);
    if (ret < 0) return ret; bit_offset = ret;

    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->length_type_is_slots ? 1 : 0, 1);
    if (ret < 0) return ret; bit_offset = ret;

    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->num_subslots_or_slots & 0x7F, 7);
    if (ret < 0) return ret; bit_offset = ret;

    // Octet 3 (byte index depends on start_subslot_num_bits, write_bits handles this):
    // Max RACH Length (7 MSBs of this octet), Reserved (1 LSB)
    uint8_t max_rach_len_octet = (rach_fields->max_rach_pdu_len_units & 0x7F) << 1; // Shift to MSB, LSB is reserved (0)
    ret = write_bits(buf, buf_max_len, bit_offset, max_rach_len_octet, 8);
    if (ret < 0) return ret; bit_offset = ret;

    // Octet 4: Cwmin_sig (3 MSBs), Cwmax_sig (next 3 bits), Repetition (2 LSBs)
    uint8_t cw_rep_octet = ((rach_fields->cwmin_sig_code & 0x07) << 5) |
                             ((rach_fields->cwmax_sig_code & 0x07) << 2) |
                             (rach_fields->repetition_code & 0x03);
    ret = write_bits(buf, buf_max_len, bit_offset, cw_rep_octet, 8);
    if (ret < 0) return ret; bit_offset = ret;

    // Octet 5: Response Window (8 bits) - value is (actual subslots - 1)
    ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->response_window_subslots_val_minus_1, 8);
    if (ret < 0) return ret; bit_offset = ret;

    // --- Optional fields ---
    // Ensure byte alignment if next fields are written with sys_put_be16/32 directly.
    // write_bits handles unaligned writes correctly, so direct sys_put_be16 after write_bits is okay
    // if the total bits written by write_bits result in a byte-aligned offset.

    if (rach_fields->sfn_validity_present) {
        if (((bit_offset + 16 -1) / 8) >= buf_max_len) return -ENOMEM; // Check space for 2 bytes
        ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->sfn_value, 8);
        if (ret < 0) return ret; bit_offset = ret;
        ret = write_bits(buf, buf_max_len, bit_offset, rach_fields->validity_frames, 8);
        if (ret < 0) return ret; bit_offset = ret;
    }

    if (rach_fields->channel_field_present) {
        // Channel (13 MSBs of 16-bit field), Reserved (3 LSBs)
        if (((bit_offset + 16 -1) / 8) >= buf_max_len) return -ENOMEM;
        uint16_t chan_field_on_air = (rach_fields->channel_abs_freq_num & 0x1FFF) << 3; // Shift to MSBs, LSBs reserved (0)
        // write_bits can handle this, or direct sys_put_be16
        uint8_t *byte_ptr = buf + (bit_offset / 8); // Pointer to current byte
        if ( (bit_offset % 8) != 0) {
            LOG_ERR("RACH_SER: Unaligned bit_offset %d before writing Channel field with sys_put_be16. Use write_bits for multi-byte unaligned.", bit_offset);
            // Fallback to write_bits for safety if unaligned.
            ret = write_bits(buf, buf_max_len, bit_offset, (chan_field_on_air >> 8) & 0xFF, 8); // MSB of field
            if (ret < 0) return ret; bit_offset = ret;
            ret = write_bits(buf, buf_max_len, bit_offset, chan_field_on_air & 0xFF, 8);       // LSB of field
            if (ret < 0) return ret; bit_offset = ret;
        } else {
            sys_put_be16(chan_field_on_air, byte_ptr);
            bit_offset += 16;
        }
    }

    if (rach_fields->channel2_field_present) {
        if (((bit_offset + 16 -1) / 8) >= buf_max_len) return -ENOMEM;
        uint16_t chan2_field_on_air = (rach_fields->channel2_abs_freq_num & 0x1FFF) << 3;
        uint8_t *byte_ptr = buf + (bit_offset / 8);
        if ( (bit_offset % 8) != 0) {
             LOG_ERR("RACH_SER: Unaligned bit_offset %d before writing Channel2 field with sys_put_be16.", bit_offset);
            ret = write_bits(buf, buf_max_len, bit_offset, (chan2_field_on_air >> 8) & 0xFF, 8);
            if (ret < 0) return ret; bit_offset = ret;
            ret = write_bits(buf, buf_max_len, bit_offset, chan2_field_on_air & 0xFF, 8);
            if (ret < 0) return ret; bit_offset = ret;
        } else {
            sys_put_be16(chan2_field_on_air, byte_ptr);
            bit_offset += 16;
        }
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
    memset(out_rach_fields, 0, sizeof(dect_mac_rach_info_ie_fields_t));

    int bit_offset = 0;
    int remaining_bits = ie_payload_len * 8;

    // Octet 0: Flags
    if (remaining_bits < 8) return -EMSGSIZE;
    uint8_t flags_octet0 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_rach_fields->repeat_type_is_subslots = (flags_octet0 >> 6) & 0x01;
    out_rach_fields->sfn_validity_present    = (flags_octet0 >> 5) & 0x01;
    out_rach_fields->channel_field_present   = (flags_octet0 >> 4) & 0x01;
    out_rach_fields->channel2_field_present  = (flags_octet0 >> 3) & 0x01;
    out_rach_fields->max_len_type_is_slots   = (flags_octet0 >> 2) & 0x01;
    out_rach_fields->dect_delay_for_response = (flags_octet0 >> 1) & 0x01;
    // Bit 0 and 7 are reserved

    // Octets 1-2 (17 bits total usually): Start Subslot (9/8b), Length Type (1b), Length (7b)
    // TODO: Determine 8 or 9 bits for start_subslot based on sender's mu.
    //       For now, assume 8 bits as per serializer's simplification.
    //       A robust solution would need the sender's mu (from its RD Capability IE).
    uint8_t start_subslot_num_bits = 8; // Simplification: Assume 8 bits from sender for now
                                        // If it was 9, then (17-8)=9 bits read here, (16-9)=7 bits for next part
    if (remaining_bits < (start_subslot_num_bits + 1 + 7)) return -EMSGSIZE;
    out_rach_fields->start_subslot_index  = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, start_subslot_num_bits);
    out_rach_fields->length_type_is_slots = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 1);
    out_rach_fields->num_subslots_or_slots= read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 7);

    // Octet 3 (byte index depends on previous fields): Max RACH Length (7 MSBs), Reserved (1 LSB)
    if (remaining_bits < 8) return -EMSGSIZE;
    uint8_t max_rach_len_octet = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_rach_fields->max_rach_pdu_len_units = (max_rach_len_octet >> 1) & 0x7F;

    // Octet 4: Cwmin_sig (3 MSBs), Cwmax_sig (next 3 bits), Repetition (2 LSBs)
    if (remaining_bits < 8) return -EMSGSIZE;
    uint8_t cw_rep_octet = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_rach_fields->cwmin_sig_code  = (cw_rep_octet >> 5) & 0x07;
    out_rach_fields->cwmax_sig_code  = (cw_rep_octet >> 2) & 0x07;
    out_rach_fields->repetition_code = cw_rep_octet & 0x03;

    // Octet 5: Response Window (8 bits) - value is (actual subslots - 1)
    if (remaining_bits < 8) return -EMSGSIZE;
    out_rach_fields->response_window_subslots_val_minus_1 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);

    // --- Optional fields ---
    if (out_rach_fields->sfn_validity_present) {
        if (remaining_bits < 16) return -EMSGSIZE; // Need 2 bytes
        out_rach_fields->sfn_value       = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
        out_rach_fields->validity_frames = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    }

    if (out_rach_fields->channel_field_present) {
        if (remaining_bits < 16) return -EMSGSIZE; // Need 2 bytes
        // Ensure byte alignment for sys_get_be16 if bit_offset is not on a byte boundary.
        // read_bits_adv itself is bit-granular. If we read 16 bits with it:
        if ((bit_offset % 8) != 0) {
            LOG_WRN("RACH_PARSE: Unaligned bit_offset %d before reading Channel field. Reading bit-wise.", bit_offset);
            uint8_t msb = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
            uint8_t lsb = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
            uint16_t chan_field_on_air = ((uint16_t)msb << 8) | lsb;
            out_rach_fields->channel_abs_freq_num = (chan_field_on_air >> 3) & 0x1FFF;
        } else {
            const uint8_t *byte_ptr = ie_payload + (bit_offset / 8);
            uint16_t chan_field_on_air = sys_get_be16(byte_ptr);
            bit_offset += 16;
            remaining_bits -= 16;
            out_rach_fields->channel_abs_freq_num = (chan_field_on_air >> 3) & 0x1FFF;
        }
    }

    if (out_rach_fields->channel2_field_present) {
        if (remaining_bits < 16) return -EMSGSIZE;
        if ((bit_offset % 8) != 0) {
             LOG_WRN("RACH_PARSE: Unaligned bit_offset %d before reading Channel2 field. Reading bit-wise.", bit_offset);
            uint8_t msb = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
            uint8_t lsb = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
            uint16_t chan2_field_on_air = ((uint16_t)msb << 8) | lsb;
            out_rach_fields->channel2_abs_freq_num = (chan2_field_on_air >> 3) & 0x1FFF;
        } else {
            const uint8_t *byte_ptr = ie_payload + (bit_offset / 8);
            uint16_t chan2_field_on_air = sys_get_be16(byte_ptr);
            bit_offset += 16;
            remaining_bits -= 16; // Should be updated by read_bits_adv if used instead
            out_rach_fields->channel2_abs_freq_num = (chan2_field_on_air >> 3) & 0x1FFF;
        }
    }

    // Final check if we consumed an appropriate number of bytes based on flags
    // This is tricky because actual length depends on how many optional fields were present.
    // The `remaining_bits` check throughout helps catch overruns.
    // If remaining_bits > 0 after all expected optional fields are parsed, there might be more data than expected or parsing error.
    if (remaining_bits > 0 && remaining_bits < 8) { // Less than a full byte remaining typically indicates an issue or unparsed padding.
        LOG_WRN("RACH_PARSE: %d unparsed bits remain at the end of RACH IE payload (len %u).",
                remaining_bits, ie_payload_len);
    } else if (remaining_bits >= 8) {
         LOG_WRN("RACH_PARSE: %d unparsed bits (>=1 byte) remain at the end of RACH IE payload (len %u). Potentially more IEs or error.",
                remaining_bits, ie_payload_len);
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
    // Mandatory part is 1 octet.
    if (buf_max_len < 1) {
        LOG_ERR("ASSOC_REQ_SER: Buffer too small (%zu bytes) for Assoc Req IE mandatory part (1 byte).", buf_max_len);
        return -ENOMEM;
    }

    memset(buf, 0, buf_max_len); // Initialize buffer, ensures reserved bits are 0
    int bit_offset = 0;
    int ret;

    // --- Octet 0: Flags and Basic Info ---
    // Bit 7 (MSB): Power Const (0 = RD has no power constraints for this association)
    // Bit 6: FT Mode (0 = RD operates only in PT mode for this association)
    // Bit 5-3: Number of Flows (requested to be setup, 000 means 0 flows initially)
    // Bit 2-0: Setup Cause (e.g., 000 = initial association)

    uint8_t octet0 = 0;

    // Bit 7: Power Const
    if (req_fields->power_const_active) {
        WRITE_BIT(octet0, 7, 1);
    } // else it's 0 by memset

    // Bit 6: FT Mode
    if (req_fields->ft_mode_capable) {
        WRITE_BIT(octet0, 6, 1);
    } // else it's 0

    // Bits 5-3: Number of Flows
    if (req_fields->number_of_flows_val > 0x07) {
        LOG_WRN("ASSOC_REQ_SER: Number of flows %u exceeds 3-bit field. Clamping to 7.", req_fields->number_of_flows_val);
        octet0 |= (0x07 << 3);
    } else {
        octet0 |= ((req_fields->number_of_flows_val & 0x07) << 3);
    }

    // Bits 2-0: Setup Cause
    if (req_fields->setup_cause_val > 0x07) {
        LOG_WRN("ASSOC_REQ_SER: Setup cause %u exceeds 3-bit field. Using raw low 3 bits.", req_fields->setup_cause_val);
        octet0 |= (req_fields->setup_cause_val & 0x07);
    } else {
        octet0 |= (req_fields->setup_cause_val & 0x07);
    }

    ret = write_bits(buf, buf_max_len, bit_offset, octet0, 8);
    if (ret < 0) {
        LOG_ERR("ASSOC_REQ_SER: Failed to write octet0: %d", ret);
        return ret;
    }
    bit_offset = ret;

    // --- Conditional Fields (ETSI Table 6.4.2.4-1) ---
    // These are TODO for full implementation.
    // - HARQ Process TX (3b), MAX HARQ RE-TX (5b)
    // - HARQ Process RX (3b), MAX HARQ RE-RX (5b)
    // - Flow IDs (6b each, repeated 'Number of Flows' times if > 0)
    // - FT Mode specific parameters (if ft_mode_capable is true):
    //   - Network Beacon period (4b), Cluster Beacon period (4b)
    //   - Next Cluster Channel (1b flag + 13b value if flag is 1)
    //   - Time to next (1b flag + 32b value if flag is 1)
    //   - Current (1b flag + 13b value if flag is 1 and Next Cluster Channel is different)

    if (req_fields->number_of_flows_val > 0 || req_fields->ft_mode_capable) {
        LOG_WRN("ASSOC_REQ_SER: Conditional fields for Assoc Req IE (Flows, FT Params) are NOT YET SERIALIZED.");
        // For a fully compliant PDU, these would need to be serialized here if their flags/conditions are met.
        // This would increase the returned length.
    }

    // Return length in bytes (currently always 1 for this simplified version)
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
    // Mandatory part is 1 octet.
    if (ie_payload_len < 1) {
        LOG_ERR("ASSOC_REQ_PARSE: Payload too short (%u bytes) for Assoc Req IE mandatory part (1 byte).", ie_payload_len);
        return -EMSGSIZE;
    }
    memset(out_req_fields, 0, sizeof(dect_mac_assoc_req_ie_t));

    int bit_offset = 0;
    int remaining_bits = ie_payload_len * 8; // Track remaining bits for robust parsing

    // --- Octet 0: Flags and Basic Info ---
    // Bit 7 (MSB): Power Const
    // Bit 6: FT Mode
    // Bit 5-3: Number of Flows
    // Bit 2-0: Setup Cause
    if (remaining_bits < 8) return -EMSGSIZE; // Should be caught by ie_payload_len < 1
    uint8_t octet0 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);

    out_req_fields->power_const_active  = (octet0 >> 7) & 0x01;
    out_req_fields->ft_mode_capable     = (octet0 >> 6) & 0x01;
    out_req_fields->number_of_flows_val = (octet0 >> 3) & 0x07;
    out_req_fields->setup_cause_val     = octet0 & 0x07;

    LOG_DBG("ASSOC_REQ_PARSE: Parsed Octet0 -> PowerConst:%d, FTMode:%d, NumFlows:%d, Cause:%d",
            out_req_fields->power_const_active, out_req_fields->ft_mode_capable,
            out_req_fields->number_of_flows_val, out_req_fields->setup_cause_val);

    // --- Conditional Fields (ETSI Table 6.4.2.4-1) ---
    // These are TODO for full implementation.
    // The parser needs to check flags and `out_req_fields->number_of_flows_val`
    // to determine if and how many of these optional fields are present.
    // - HARQ Process TX (3b), MAX HARQ RE-TX (5b) -> Total 1 octet
    // - HARQ Process RX (3b), MAX HARQ RE-RX (5b) -> Total 1 octet
    // - Flow IDs (6b each, repeated 'Number of Flows' times if > 0) -> Variable length
    // - FT Mode specific parameters (if ft_mode_capable is true):
    //   - Network Beacon period (4b), Cluster Beacon period (4b) -> Total 1 octet
    //   - Next Cluster Channel Flag (1b)
    //     - Next Cluster Channel (13b + 3b reserved if flag=1) -> Total 2 octets
    //   - Time to next Flag (1b)
    //     - Time to next (32b if flag=1) -> Total 4 octets
    //   - Current Flag (1b)
    //     - Current Cluster Channel (13b + 3b reserved if flag=1 and NextChan flag was 1 and different) -> Total 2 octets

    if (remaining_bits >= 8) { // Check if there's at least one more byte
        LOG_WRN("ASSOC_REQ_PARSE: Conditional fields present in Assoc Req IE but NOT YET PARSED (remaining %d bits).", remaining_bits);
        // For a fully compliant parser, you would now check number_of_flows_val, ft_mode_capable,
        // and the flags for optional channel/time fields to parse the rest of the IE.
    }

    // For successfully parsing the first octet is sufficient to identify the request.
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
    // Mandatory part is 2 octets for the summary (Octet 0 & Octet 1).
    if (buf_max_len < 2) {
        LOG_ERR("RD_CAP_SER: Buffer too small (%zu bytes) for RD Cap IE mandatory part (2 bytes).", buf_max_len);
        return -ENOMEM;
    }

    memset(buf, 0, buf_max_len); // Initialize buffer, ensures reserved bits are 0
    int bit_offset = 0;
    int ret;

    // --- Octet 0: Number of PHY Capabilities (3 MSB), Release (5 LSB) ---
    // Number of PHY Capabilities: Indicates N-1 additional sets.
    // 000 means 1 set (the base set, often implied or described by subsequent summary fields).
    // 001 means 1 additional explicit PHY capability set follows (total 1+1=2 sets).
    // The `cap_fields->num_phy_capabilities` should hold the actual N-1 value for the field.
    if (cap_fields->num_phy_capabilities > 0x07) {
        LOG_WRN("RD_CAP_SER: num_phy_capabilities %u exceeds 3-bit field. Clamping.", cap_fields->num_phy_capabilities);
    }
    if (cap_fields->release_version > 0x1F) {
        LOG_WRN("RD_CAP_SER: release_version %u exceeds 5-bit field. Clamping.", cap_fields->release_version);
    }
    uint8_t octet0 = ((cap_fields->num_phy_capabilities & 0x07) << 5) |
                     (cap_fields->release_version & 0x1F);
    ret = write_bits(buf, buf_max_len, bit_offset, octet0, 8);
    if (ret < 0) { LOG_ERR("RD_CAP_SER: Failed to write octet0: %d", ret); return ret; }
    bit_offset = ret;

    // --- Octet 1: Flags ---
    // Bit 7 (MSB): Group Assignment support
    // Bit 6: Paging support
    // Bit 5-4: Operating Modes (00=PT, 01=FT, 10=Both, 11=Reserved)
    // Bit 3: Mesh support
    // Bit 2: Scheduled data transfer service support
    // Bit 1-0: MAC Security mode(s) supported (00=None, 01=Mode1, 10=Mode2(Rsvd), 11=Mode1&2(Rsvd))
    //          (ETSI Table 6.4.3.5-1 shows 2 bits for MAC Security)
    uint8_t octet1 = 0;
    WRITE_BIT(octet1, 7, cap_fields->supports_group_assignment);
    WRITE_BIT(octet1, 6, cap_fields->supports_paging);

    if (cap_fields->operating_modes_code > 0x03) {
        LOG_WRN("RD_CAP_SER: operating_modes_code %u exceeds 2-bit field. Clamping.", cap_fields->operating_modes_code);
    }
    octet1 |= ((cap_fields->operating_modes_code & 0x03) << 4);

    WRITE_BIT(octet1, 3, cap_fields->supports_mesh);
    WRITE_BIT(octet1, 2, cap_fields->supports_sched_data);

    if (cap_fields->mac_security_modes_code > 0x03) {
         LOG_WRN("RD_CAP_SER: mac_security_modes_code %u exceeds 2-bit field. Clamping.", cap_fields->mac_security_modes_code);
    }
    octet1 |= (cap_fields->mac_security_modes_code & 0x03);

    ret = write_bits(buf, buf_max_len, bit_offset, octet1, 8);
    if (ret < 0) { LOG_ERR("RD_CAP_SER: Failed to write octet1: %d", ret); return ret; }
    bit_offset = ret;

    // --- Conditional PHY Capability Sets (Octets 2 to (1 + N*5)) ---
    // N is (num_phy_capabilities field value + 1), but ETSI says num_phy_capabilities is N-1.
    // So, if num_phy_capabilities field is 'X', there are 'X' *additional* 5-octet sets following.
    // If num_phy_capabilities field is 0, no *additional* sets.
    // The fields in Octet 1 (like Schedul., MAC Security) and other implicit capabilities (like
    // support for HARQ based on HARQ process count IE, etc.) form the "base" capability set.
    // ETSI Annex A.2 describes some fields as "part of first set of PHY capabilities".

    // we only send the 2 summary octets.
    // A fully compliant device *must* send its actual PHY capabilities.
    if (cap_fields->num_phy_capabilities > 0) {
        LOG_WRN("RD_CAP_SER: Serialization of %u additional PHY capability set(s) (5 octets each) is NOT YET IMPLEMENTED.",
                cap_fields->num_phy_capabilities);
        // Here, you would loop cap_fields->num_phy_capabilities times:
        // For each set:
        //   - Get data from a corresponding struct (e.g., an array of PHY cap sets in dect_mac_rd_capability_ie_t)
        //   - Serialize 5 octets:
        //     - Octet 0: DLC Service Type (3b), RX for TX diversity (3b), Reserved (2b)
        //     - Octet 1: mu (3b), beta (4b), Reserved (1b)
        //     - Octet 2: Max NSS for RX (3b), Max MCS (4b), Reserved (1b)
        //     - Octet 3: HARQ soft buffer size code (4b), Num HARQ process code (2b), Reserved (2b)
        //     - Octet 4: HARQ feedback delay code (4b), D_Delay (1b), HalfDup (1b), Reserved (2b)
    }

    return (bit_offset + 7) / 8; // Bytes written (currently 2)
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
    // Mandatory part is 2 octets for the summary.
    if (ie_payload_len < 2) {
        LOG_ERR("RD_CAP_PARSE: Payload too short (%u bytes) for RD Cap IE mandatory part (2 bytes).", ie_payload_len);
        return -EMSGSIZE;
    }
    memset(out_cap_fields, 0, sizeof(dect_mac_rd_capability_ie_t));

    int bit_offset = 0;
    int remaining_bits = ie_payload_len * 8;

    // --- Octet 0: Number of PHY Capabilities (3 MSB), Release (5 LSB) ---
    if (remaining_bits < 8) return -EMSGSIZE; // Should be caught by ie_payload_len check
    uint8_t octet0 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_cap_fields->num_phy_capabilities = (octet0 >> 5) & 0x07; // N-1 value
    out_cap_fields->release_version      = octet0 & 0x1F;

    LOG_DBG("RD_CAP_PARSE: Octet0 -> NumPHYsets(N-1):%u, ReleaseVer:%u",
            out_cap_fields->num_phy_capabilities, out_cap_fields->release_version);

    // --- Octet 1: Flags ---
    // Bit 7 (MSB): Group Assignment support
    // Bit 6: Paging support
    // Bit 5-4: Operating Modes
    // Bit 3: Mesh support
    // Bit 2: Scheduled data transfer service support
    // Bit 1-0: MAC Security mode(s) supported
    if (remaining_bits < 8) {
        LOG_ERR("RD_CAP_PARSE: Payload too short for Octet 1 flags after reading Octet 0.");
        return -EMSGSIZE;
    }
    uint8_t octet1 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
    out_cap_fields->supports_group_assignment = (octet1 >> 7) & 0x01;
    out_cap_fields->supports_paging           = (octet1 >> 6) & 0x01;
    out_cap_fields->operating_modes_code      = (octet1 >> 4) & 0x03;
    out_cap_fields->supports_mesh             = (octet1 >> 3) & 0x01;
    out_cap_fields->supports_sched_data       = (octet1 >> 2) & 0x01;
    out_cap_fields->mac_security_modes_code   = octet1 & 0x03;

    LOG_DBG("RD_CAP_PARSE: Octet1 -> GrpAs:%d Paging:%d OpM:0x%X Mesh:%d Sched:%d MACSec:0x%X",
            out_cap_fields->supports_group_assignment, out_cap_fields->supports_paging,
            out_cap_fields->operating_modes_code, out_cap_fields->supports_mesh,
            out_cap_fields->supports_sched_data, out_cap_fields->mac_security_modes_code);

    // --- Conditional PHY Capability Sets (Octets 2 to (1 + N*5)) ---
    // N is the actual number of sets. num_phy_capabilities field stores (N-1).
    // So, if num_phy_capabilities field value is X, there are X *additional* 5-octet sets.
    // (If X=0, no additional sets beyond what's implied by summary/base PHY).

    uint8_t num_additional_phy_sets = out_cap_fields->num_phy_capabilities;
    if (num_additional_phy_sets > 0) {
        LOG_WRN("RD_CAP_PARSE: Deserialization of %u additional PHY capability set(s) (5 octets each) is NOT YET IMPLEMENTED.",
                num_additional_phy_sets);

        if (remaining_bits < (int)(num_additional_phy_sets * 5 * 8)) {
            LOG_ERR("RD_CAP_PARSE: Payload too short for %u declared additional PHY capability sets (need %u bits, have %d).",
                    num_additional_phy_sets, num_additional_phy_sets * 5 * 8, remaining_bits);
            // Proceed with parsed summary, but capabilities are incomplete.
            // Depending on strictness, could return -EMSGSIZE.
        } else {
            // Placeholder for loop to parse actual sets:
            // const uint8_t *phy_set_ptr = ie_payload + (bit_offset / 8);
            // for (int i = 0; i < num_additional_phy_sets; i++) {
            //     // Parse 5 octets from phy_set_ptr into a struct for PHY capabilities
            //     // e.g., out_cap_fields->phy_variants[i].dlc_service_type = (phy_set_ptr[0] >> 5) & 0x07;
            //     // ... and so on for all fields in the 5 octets ...
            //     phy_set_ptr += 5;
            //     bit_offset += (5*8);
            //     remaining_bits -= (5*8);
            // }
        }
    }

    // Check if we consumed an expected number of bytes if all fields were parsed.
    // For now, we only parsed 2 bytes.
    int expected_bytes_parsed = 2 + (num_additional_phy_sets * 5);
    if (ie_payload_len < (uint16_t)expected_bytes_parsed && num_additional_phy_sets > 0) {
        // This warning was already covered by remaining_bits check if it's critical.
    } else if ( (bit_offset / 8) != expected_bytes_parsed && num_additional_phy_sets > 0) {
        // Only log if we intended to parse more but didn't align.
        // If only summary is parsed, bit_offset/8 will be 2.
    }


    return 0; // Success for parsing the summary part
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
    // Mandatory part is 1 octet. If NACK, it's 2 octets.
    if (buf_max_len < 1) {
        LOG_ERR("ASSOC_RESP_SER: Buffer too small (%zu bytes) for Assoc Resp IE mandatory part (1 byte).", buf_max_len);
        return -ENOMEM;
    }
    if (!resp_fields->ack_nack && buf_max_len < 2) {
        LOG_ERR("ASSOC_RESP_SER: Buffer too small (%zu bytes) for NACK response (needs 2 bytes).", buf_max_len);
        return -ENOMEM;
    }


    memset(buf, 0, buf_max_len); // Initialize buffer, ensures reserved bits are 0
    int bit_offset = 0;
    int ret;

    // --- Octet 0: Flags and Basic Info ---
    // Bit 7 (MSB): ACK/NACK (1=ACK, 0=NACK)
    // Bit 6: HARQ mod present (0=HARQ params not present/accepted as is, 1=HARQ params follow)
    // Bit 5-3: Number of Flows accepted/indicated (000-110 for 0-6 flows, 111=all flows accepted)
    // Bit 2: Group (0=Group ID/Tag not present, 1=present)
    // Bit 1-0: Reserved (set to 0)

    uint8_t octet0 = 0;

    WRITE_BIT(octet0, 7, resp_fields->ack_nack);
    WRITE_BIT(octet0, 6, resp_fields->harq_mod_present); // this is usually false

    if (resp_fields->number_of_flows_accepted > 0x07) {
        LOG_WRN("ASSOC_RESP_SER: Number of flows accepted %u exceeds 3-bit field. Clamping to 7 (all).", resp_fields->number_of_flows_accepted);
        octet0 |= (0x07 << 3);
    } else {
        octet0 |= ((resp_fields->number_of_flows_accepted & 0x07) << 3);
    }

    WRITE_BIT(octet0, 2, resp_fields->group_assignment_active); // usually false

    // Bits 1-0 are reserved and should be 0 (achieved by initial memset and not setting them)
    // octet0 |= (resp_fields->reserved_2bits & 0x03); // If reserved_2bits was a field

    ret = write_bits(buf, buf_max_len, bit_offset, octet0, 8);
    if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Failed to write octet0: %d", ret); return ret; }
    bit_offset = ret;

    // --- Conditional Octet 1 (Only if NACK, i.e., ack_nack = 0) ---
    if (!resp_fields->ack_nack) {
        // Octet 1: Reject Timer (4 MSBs), Reject Cause (4 LSBs)
        if (((bit_offset / 8) + 1) > buf_max_len) { // Check if space for 1 more byte
             LOG_ERR("ASSOC_RESP_SER: Buffer too small for NACK details octet.");
             return -ENOMEM;
        }
        if (resp_fields->reject_timer_code > 0x0F) {
            LOG_WRN("ASSOC_RESP_SER: reject_timer_code %u exceeds 4-bit field. Clamping.", resp_fields->reject_timer_code);
        }
        if (resp_fields->reject_cause > 0x0F) { // dect_assoc_reject_cause_t should be < 16
            LOG_WRN("ASSOC_RESP_SER: reject_cause %u exceeds 4-bit field. Clamping.", resp_fields->reject_cause);
        }

        uint8_t octet1_reject = ((resp_fields->reject_timer_code & 0x0F) << 4) |
                                  (resp_fields->reject_cause & 0x0F);
        ret = write_bits(buf, buf_max_len, bit_offset, octet1_reject, 8);
        if (ret < 0) { LOG_ERR("ASSOC_RESP_SER: Failed to write reject octet1: %d", ret); return ret; }
        bit_offset = ret;
    } else { // ACK path
        // --- Conditional Fields for ACK (ETSI Table 6.4.2.5-1) ---
        // These are TODO for full implementation.
        if (resp_fields->harq_mod_present) {
            LOG_WRN("ASSOC_RESP_SER: HARQ Modification parameters present but NOT YET SERIALIZED.");
            // Serialize 2 octets for HARQ params
        }
        if (resp_fields->number_of_flows_accepted < 0x07 && resp_fields->number_of_flows_accepted > 0) {
            LOG_WRN("ASSOC_RESP_SER: List of %u accepted Flow IDs NOT YET SERIALIZED.", resp_fields->number_of_flows_accepted);
            // Serialize (N * 6 bits) for Flow IDs, padded to octet boundary.
        }
        if (resp_fields->group_assignment_active) {
            LOG_WRN("ASSOC_RESP_SER: Group ID and Resource Tag present but NOT YET SERIALIZED.");
            // Serialize 2 octets for Group ID and Resource Tag.
        }
    }

    // Return length in bytes
    return (bit_offset + 7) / 8;
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
    // Mandatory part is at least 1 octet.
    if (ie_payload_len < 1) {
        LOG_ERR("ASSOC_RESP_PARSE: Payload too short (%u bytes) for Assoc Resp IE base (min 1 byte).", ie_payload_len);
        return -EMSGSIZE;
    }
    memset(out_resp_fields, 0, sizeof(dect_mac_assoc_resp_ie_t));

    int bit_offset = 0;
    int remaining_bits = ie_payload_len * 8;

    // --- Octet 0: Flags and Basic Info ---
    // Bit 7 (MSB): ACK/NACK (1=ACK, 0=NACK)
    // Bit 6: HARQ mod present
    // Bit 5-3: Number of Flows accepted/indicated
    // Bit 2: Group
    // Bit 1-0: Reserved
    if (remaining_bits < 8) return -EMSGSIZE; // Should be caught by ie_payload_len check
    uint8_t octet0 = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);

    out_resp_fields->ack_nack                 = (octet0 >> 7) & 0x01;
    out_resp_fields->harq_mod_present         = (octet0 >> 6) & 0x01;
    out_resp_fields->number_of_flows_accepted = (octet0 >> 3) & 0x07;
    out_resp_fields->group_assignment_active  = (octet0 >> 2) & 0x01;
    out_resp_fields->reserved_3bits           = octet0 & 0x03; // Store reserved bits (bits 1-0 of octet 0)

    LOG_DBG("ASSOC_RESP_PARSE: Parsed Octet0 -> ACK:%d, HARQMod:%d, NumFlowsAcc:%d, GroupAct:%d, Rsvd:%u",
            out_resp_fields->ack_nack, out_resp_fields->harq_mod_present,
            out_resp_fields->number_of_flows_accepted, out_resp_fields->group_assignment_active,
            out_resp_fields->reserved_3bits);


    // --- Conditional Octet 1 (Only if NACK, i.e., ack_nack = 0) ---
    if (!out_resp_fields->ack_nack) {
        // Octet 1: Reject Timer (4 MSBs), Reject Cause (4 LSBs)
        if (remaining_bits < 8) {
            LOG_ERR("ASSOC_RESP_PARSE: NACK indicated, but payload too short for reject cause/timer octet (need %d more bits).", 8 - remaining_bits);
            return -EMSGSIZE;
        }
        uint8_t octet1_reject = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 8);
        out_resp_fields->reject_timer_code = (octet1_reject >> 4) & 0x0F;
        out_resp_fields->reject_cause      = (dect_assoc_reject_cause_t)(octet1_reject & 0x0F);
        LOG_INF("ASSOC_RESP_PARSE: NACK details -> RejectCause: %u, RejectTimerCode: %u",
                out_resp_fields->reject_cause, out_resp_fields->reject_timer_code);
    } else { // ACK path
        // --- Conditional Fields for ACK (ETSI Table 6.4.2.5-1) ---
        // These are TODO for full implementation.
        // The parser needs to check flags (harq_mod_present, group_assignment_active)
        // and number_of_flows_accepted to determine if these fields are present.

        if (out_resp_fields->harq_mod_present) {
            LOG_WRN("ASSOC_RESP_PARSE: ACK with HARQ Modification parameters present but NOT YET PARSED (remaining %d bits).", remaining_bits);
            // TODO: Parse 2 octets for HARQ params if remaining_bits >= 16
            // bit_offset = read_bits_adv(ie_payload, &bit_offset, &remaining_bits, 16); // Example
        }
        if (out_resp_fields->number_of_flows_accepted < 0x07 && out_resp_fields->number_of_flows_accepted > 0) {
            LOG_WRN("ASSOC_RESP_PARSE: ACK with %u accepted Flow IDs indicated but NOT YET PARSED (remaining %d bits).",
                    out_resp_fields->number_of_flows_accepted, remaining_bits);
            // TODO: Parse (N * 6 bits) for Flow IDs, handling padding.
        }
        if (out_resp_fields->group_assignment_active) {
            LOG_WRN("ASSOC_RESP_PARSE: ACK with Group ID and Resource Tag present but NOT YET PARSED (remaining %d bits).", remaining_bits);
            // TODO: Parse 2 octets for Group ID and Resource Tag if remaining_bits >= 16
        }
    }

    // Check if we consumed roughly what was expected.
    // This is difficult without parsing all conditional fields.
    if (remaining_bits >= 8) { // If a full byte or more remains after parsing known fields
        LOG_WRN("ASSOC_RESP_PARSE: %d unparsed bits (>=1 byte) remain at the end of Assoc Resp IE payload (len %u). Potentially unparsed conditional fields or error.",
                remaining_bits, ie_payload_len);
    }

    return 0; // Success for parsing the parts implemented
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

    size_t min_len_check = 1; // Min is 1 byte for RELEASE_ALL
    if (ra_fields->alloc_type_val != RES_ALLOC_TYPE_RELEASE_ALL) {
        // If not RELEASE_ALL, bitmap octet 1 + Res1 fields (2 octets if 8-bit start_subslot) are mandatory
        min_len_check = 1 + 1 + 2; // Bitmap0 + Bitmap1 + Res1_fields
    }
    if (buf_max_len < min_len_check) {
         LOG_ERR("RA_SER: buf_max_len %zu too small for min ResAlloc IE (expected ~%zu).", buf_max_len, min_len_check);
         return -ENOMEM;
    }

    memset(buf, 0, buf_max_len); // Initialize buffer (sets reserved bits to 0)
    int bit_offset = 0;
    int ret;

    // --- Octet 0 of Bitmap (Always present) ---
    // Bits 7-6 (MSB side): Alloc Type (ra_fields->alloc_type_val)
    // Bit 5: Add (ra_fields->add_allocation)
    // Bit 4: ID (ra_fields->id_present)
    // Bits 3-1: Repeat (ra_fields->repeat_val)
    // Bit 0 (LSB): SFN (ra_fields->sfn_present)
    uint8_t bitmap_octet0 = 0;
    bitmap_octet0 |= ((uint8_t)ra_fields->alloc_type_val & 0x03) << 6;
    WRITE_BIT(bitmap_octet0, 5, ra_fields->add_allocation);
    WRITE_BIT(bitmap_octet0, 4, ra_fields->id_present);
    bitmap_octet0 |= ((uint8_t)ra_fields->repeat_val & 0x07) << 1;
    WRITE_BIT(bitmap_octet0, 0, ra_fields->sfn_present);

    ret = write_bits(buf, buf_max_len, bit_offset, bitmap_octet0, 8);
    if (ret < 0) { LOG_ERR("RA_SER: Write Bitmap0 failed: %d", ret); return ret; }
    bit_offset = ret;

    // If Alloc Type is RELEASE_ALL, no more fields are present.
    if (ra_fields->alloc_type_val == RES_ALLOC_TYPE_RELEASE_ALL) {
        return (bit_offset + 7) / 8; // Should be 1 byte
    }

    // --- Octet 1 of Bitmap (Present if not RELEASE_ALL) ---
    // Bit 7: Channel (ra_fields->channel_present)
    // Bit 6: RLF (ra_fields->rlf_present)
    // Bits 5-0: Start subslot (MS 6 bits IF Res1 Start Subslot is 9-bit AND this bitmap format is used for it)
    //           OR Reserved (if Res1 Start Subslot is 8-bit, or fewer than 6 MSBs needed).
    // ETSI Figure 6.4.3.3-1 is a bit ambiguous on how the 9-bit start_subslot's MSBs are split
    // if other flags (Channel, RLF) are also in this octet.
    // For simplicity and more standard packing: Assume if Res1 Start Subslot is 9-bit,
    // those 9 bits are packed contiguously *after* the full 2-octet bitmap.
    // Thus, bits 5-0 of Bitmap Octet 1 are RESERVED here.
    uint8_t bitmap_octet1 = 0;
    WRITE_BIT(bitmap_octet1, 7, ra_fields->channel_present);
    WRITE_BIT(bitmap_octet1, 6, ra_fields->rlf_present);
    // Bits 5-0 are reserved, set to 0 by memset.

    ret = write_bits(buf, buf_max_len, bit_offset, bitmap_octet1, 8);
    if (ret < 0) { LOG_ERR("RA_SER: Write Bitmap1 failed: %d", ret); return ret; }
    bit_offset = ret;


    // --- Resource 1 Fields (Start Subslot, Length Type, Length) ---
    // Total 2 octets if Start Subslot is 8-bit.
    // If Start Subslot is 9-bit, then 9+1+7 = 17 bits, requiring careful packing or an extra byte.
    uint8_t res1_start_subslot_num_bits = ra_fields->res1_is_9bit_subslot ? 9 : 8;

    ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->start_subslot_val_res1, res1_start_subslot_num_bits);
    if (ret < 0) { LOG_ERR("RA_SER: Write Res1 StartSS failed: %d", ret); return ret; }
    bit_offset = ret;

    ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_type_is_slots_res1 ? 1 : 0, 1);
    if (ret < 0) { LOG_ERR("RA_SER: Write Res1 LenType failed: %d", ret); return ret; }
    bit_offset = ret;

    if ((ra_fields->length_val_res1 +1) == 0 || (ra_fields->length_val_res1 +1) > 128) { // length_val is N-1, actual length is val+1. Max 7 bits for val.
         LOG_ERR("RA_SER: Invalid Res1 Length value (N-1): %u", ra_fields->length_val_res1); return -EINVAL;
    }
    ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_val_res1 & 0x7F, 7);
    if (ret < 0) { LOG_ERR("RA_SER: Write Res1 Length failed: %d", ret); return ret; }
    bit_offset = ret;

    // After Res1 fields: (8+1+7 = 16 bits) or (9+1+7 = 17 bits)
    // If 17 bits, bit_offset is not byte aligned. The write_bits helper handles internal byte progression.

    // --- Resource 2 Fields (if alloc_type is BIDIR) ---
    if (ra_fields->alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
        uint8_t res2_start_subslot_num_bits = ra_fields->res2_is_9bit_subslot ? 9 : 8;

        ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->start_subslot_val_res2, res2_start_subslot_num_bits);
        if (ret < 0) { LOG_ERR("RA_SER: Write Res2 StartSS failed: %d", ret); return ret; }
        bit_offset = ret;

        ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_type_is_slots_res2 ? 1 : 0, 1);
        if (ret < 0) { LOG_ERR("RA_SER: Write Res2 LenType failed: %d", ret); return ret; }
        bit_offset = ret;

        if ((ra_fields->length_val_res2 +1) == 0 || (ra_fields->length_val_res2+1) > 128) {
             LOG_ERR("RA_SER: Invalid Res2 Length value (N-1): %u", ra_fields->length_val_res2); return -EINVAL;
        }
        ret = write_bits(buf, buf_max_len, bit_offset, ra_fields->length_val_res2 & 0x7F, 7);
        if (ret < 0) { LOG_ERR("RA_SER: Write Res2 Length failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    // --- Optional Fields based on Bitmap (these must follow byte alignment after packed bitfields) ---
    // Ensure byte alignment for the following fields if they are present.
    if (bit_offset % 8 != 0) {
        int padding_bits = 8 - (bit_offset % 8);
        LOG_DBG("RA_SER: Padding %d bits to byte align before optional fields (current offset %d).", padding_bits, bit_offset);
        ret = write_bits(buf, buf_max_len, bit_offset, 0, (uint8_t)padding_bits); // Pad with 0s
        if (ret < 0) { LOG_ERR("RA_SER: Padding failed: %d", ret); return ret; }
        bit_offset = ret;
    }

    uint8_t *current_byte_ptr = buf + (bit_offset / 8); // Start of byte-aligned optional fields
    size_t remaining_byte_buf_len = buf_max_len - (bit_offset / 8);

    if (ra_fields->id_present) {
        if (remaining_byte_buf_len < 2) { LOG_ERR("RA_SER: No space for ShortRDID"); return -ENOMEM; }
        sys_put_be16(ra_fields->short_rd_id_val, current_byte_ptr);
        current_byte_ptr += 2; remaining_byte_buf_len -= 2; bit_offset += 16;
    }

    if (ra_fields->repeat_val != RES_ALLOC_REPEAT_SINGLE) {
        if (remaining_byte_buf_len < 2) { LOG_ERR("RA_SER: No space for Repetition/Validity"); return -ENOMEM; }
        *current_byte_ptr++ = ra_fields->repetition_value; // Actual value (e.g. 1 for next, 2 for every 2nd)
        *current_byte_ptr++ = ra_fields->validity_value;   // 0xFF for permanent
        remaining_byte_buf_len -= 2; bit_offset += 16;
    }

    if (ra_fields->sfn_present) {
        if (remaining_byte_buf_len < 1) { LOG_ERR("RA_SER: No space for SFN value"); return -ENOMEM; }
        *current_byte_ptr++ = ra_fields->sfn_val;
        remaining_byte_buf_len -= 1; bit_offset += 8;
    }

    if (ra_fields->channel_present) {
        if (remaining_byte_buf_len < 2) { LOG_ERR("RA_SER: No space for Channel value"); return -ENOMEM; }
        // Channel is 13 bits (MSB), Reserved 3 LSBs
        uint16_t chan_field_on_air = (ra_fields->channel_val & 0x1FFF) << 3;
        sys_put_be16(chan_field_on_air, current_byte_ptr);
        current_byte_ptr += 2; remaining_byte_buf_len -= 2; bit_offset += 16;
    }

    if (ra_fields->rlf_present) {
        if (remaining_byte_buf_len < 1) { LOG_ERR("RA_SER: No space for RLF value"); return -ENOMEM; }
        // dectScheduledResourceFailure timer code (4 MSBs), Reserved (4 LSBs)
        *current_byte_ptr++ = (ra_fields->dect_sched_res_fail_timer_code & 0x0F) << 4;
        remaining_byte_buf_len -= 1; bit_offset += 8;
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
                                    dect_mac_resource_alloc_ie_fields_t *out_ra_fields)
{
    if (!ie_payload || !out_ra_fields) {
        LOG_ERR("RA_PARSE: NULL input pointers.");
        return -EINVAL;
    }
    if (ie_payload_len < 1) { // Min 1 byte for RELEASE_ALL
        LOG_ERR("RA_PARSE: Payload too short (%u bytes) for Res Alloc IE base.", ie_payload_len);
        return -EMSGSIZE;
    }
    memset(out_ra_fields, 0, sizeof(dect_mac_resource_alloc_ie_fields_t));

    int bit_offset = 0;
    int remaining_bits_from_len = ie_payload_len * 8;
    int *remaining_bits = &remaining_bits_from_len; // Use pointer for read_bits_adv

    // --- Octet 0 of Bitmap ---
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
        return 0; // No more fields
    }

    // Minimum length for non-RELEASE_ALL is 1 (bmp0) + 1 (bmp1) + 2 (Res1 fields) = 4 bytes
    if (ie_payload_len < 4 && !(out_ra_fields->res1_is_9bit_subslot && ie_payload_len <3 )) { // 9-bit with no Res2 might be 3 bytes + padding byte
         LOG_ERR("RA_PARSE: Payload too short (%u bytes) for non-RELEASE_ALL ResAlloc IE (min ~3-4 bytes).", ie_payload_len);
        return -EMSGSIZE;
    }


    // --- Octet 1 of Bitmap ---
    if (*remaining_bits < 8) return -EMSGSIZE;
    uint8_t bitmap_octet1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 8);
    out_ra_fields->channel_present  = (bitmap_octet1 >> 7) & 0x01;
    out_ra_fields->rlf_present      = (bitmap_octet1 >> 6) & 0x01;
    // Bits 5-0 could be MSBs of a 9-bit start_subslot_val_res1 if that encoding was used.
    // Current serializer packs 9-bit start subslot contiguously *after* bitmap.
    // So, here we assume bits 5-0 of bitmap_octet1 are reserved if that model is followed.
    uint8_t res1_start_msbs_in_bmp1 = bitmap_octet1 & 0x3F;
    LOG_DBG("RA_PARSE: BMP1: ChanPres:%d RLFPres:%d Rsvd/SS1Msb:0x%02X",
            out_ra_fields->channel_present, out_ra_fields->rlf_present, res1_start_msbs_in_bmp1);


    // --- Resource 1 Fields ---
    // Determine number of bits for start_subslot based on pre-set out_ra_fields->res1_is_9bit_subslot
    // (which should be set by caller based on 'mu' of the link context if known). Default to 8.
    uint8_t res1_start_subslot_num_bits = out_ra_fields->res1_is_9bit_subslot ? 9 : 8;

    if (*remaining_bits < (res1_start_subslot_num_bits + 1 + 7)) {LOG_ERR("RA_PARSE: Not enough bits for Res1 fields."); return -EMSGSIZE;}
    out_ra_fields->start_subslot_val_res1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, res1_start_subslot_num_bits);
    out_ra_fields->length_type_is_slots_res1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 1);
    out_ra_fields->length_val_res1 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 7);
    LOG_DBG("RA_PARSE: Res1: StartSS(%db):%u LenTypeSlots:%d LenVal:%u",
            res1_start_subslot_num_bits, out_ra_fields->start_subslot_val_res1,
            out_ra_fields->length_type_is_slots_res1, out_ra_fields->length_val_res1);


    // --- Resource 2 Fields (if alloc_type is BIDIR) ---
    if (out_ra_fields->alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
        uint8_t res2_start_subslot_num_bits = out_ra_fields->res2_is_9bit_subslot ? 9 : 8;
        if (*remaining_bits < (res2_start_subslot_num_bits + 1 + 7)) {LOG_ERR("RA_PARSE: Not enough bits for Res2 fields."); return -EMSGSIZE;}

        out_ra_fields->start_subslot_val_res2 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, res2_start_subslot_num_bits);
        out_ra_fields->length_type_is_slots_res2 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 1);
        out_ra_fields->length_val_res2 = read_bits_adv(ie_payload, &bit_offset, remaining_bits, 7);
        LOG_DBG("RA_PARSE: Res2: StartSS(%db):%u LenTypeSlots:%d LenVal:%u",
                res2_start_subslot_num_bits, out_ra_fields->start_subslot_val_res2,
                out_ra_fields->length_type_is_slots_res2, out_ra_fields->length_val_res2);
    }

    // --- Optional Fields (these start after byte alignment) ---
    if (bit_offset % 8 != 0) { // If current offset is not byte aligned
        int padding_to_read = 8 - (bit_offset % 8);
        if (*remaining_bits < padding_to_read) {LOG_ERR("RA_PARSE: Not enough bits for alignment padding."); return -EMSGSIZE;}
        read_bits_adv(ie_payload, &bit_offset, remaining_bits, (uint8_t)padding_to_read); // Consume padding
        LOG_DBG("RA_PARSE: Consumed %d padding bits to byte-align for optional fields.", padding_to_read);
    }

    const uint8_t *current_byte_ptr_opts = ie_payload + (bit_offset / 8);
    uint16_t remaining_byte_len_opts = (*remaining_bits) / 8;

    if (out_ra_fields->id_present) {
        if (remaining_byte_len_opts < 2) {LOG_ERR("RA_PARSE: Payload too short for ShortRDID."); return -EMSGSIZE;}
        out_ra_fields->short_rd_id_val = sys_get_be16(current_byte_ptr_opts);
        current_byte_ptr_opts += 2; remaining_byte_len_opts -= 2; bit_offset += 16; *remaining_bits -= 16;
        LOG_DBG("RA_PARSE: Opt ShortRDID: 0x%04X", out_ra_fields->short_rd_id_val);
    }

    if (out_ra_fields->repeat_val != RES_ALLOC_REPEAT_SINGLE) {
        if (remaining_byte_len_opts < 2) {LOG_ERR("RA_PARSE: Payload too short for Repetition/Validity."); return -EMSGSIZE;}
        out_ra_fields->repetition_value = *current_byte_ptr_opts++; bit_offset += 8; *remaining_bits -= 8;
        out_ra_fields->validity_value   = *current_byte_ptr_opts++; bit_offset += 8; *remaining_bits -= 8;
        remaining_byte_len_opts -= 2;
        LOG_DBG("RA_PARSE: Opt Repetition: %u, Validity: %u", out_ra_fields->repetition_value, out_ra_fields->validity_value);
    }

    if (out_ra_fields->sfn_present) {
        if (remaining_byte_len_opts < 1) {LOG_ERR("RA_PARSE: Payload too short for SFN value."); return -EMSGSIZE;}
        out_ra_fields->sfn_val = *current_byte_ptr_opts++;
        remaining_byte_len_opts -= 1; bit_offset += 8; *remaining_bits -= 8;
        LOG_DBG("RA_PARSE: Opt SFN Val: %u", out_ra_fields->sfn_val);
    }

    if (out_ra_fields->channel_present) {
        if (remaining_byte_len_opts < 2) {LOG_ERR("RA_PARSE: Payload too short for Channel value."); return -EMSGSIZE;}
        uint16_t chan_field_on_air = sys_get_be16(current_byte_ptr_opts);
        current_byte_ptr_opts += 2; remaining_byte_len_opts -= 2; bit_offset += 16; *remaining_bits -= 16;
        out_ra_fields->channel_val = (chan_field_on_air >> 3) & 0x1FFF; // Extract 13 MSBs
        LOG_DBG("RA_PARSE: Opt Channel Val: %u", out_ra_fields->channel_val);
    }

    if (out_ra_fields->rlf_present) {
        if (remaining_byte_len_opts < 1) {LOG_ERR("RA_PARSE: Payload too short for RLF value."); return -EMSGSIZE;}
        // RLF code is in 4 MSBs of the octet
        out_ra_fields->dect_sched_res_fail_timer_code = (*current_byte_ptr_opts++ >> 4) & 0x0F;
        remaining_byte_len_opts -= 1; bit_offset += 8; *remaining_bits -= 8; // Consumed full byte
        LOG_DBG("RA_PARSE: Opt RLF Code: %u", out_ra_fields->dect_sched_res_fail_timer_code);
    }

    if (*remaining_bits >= 8) { // If a full byte or more remains unparsed
        LOG_WRN("RA_PARSE: %d unparsed bits (>=1 byte) remain at the end of Res Alloc IE payload (len %u).",
                *remaining_bits, ie_payload_len);
    } else if (*remaining_bits > 0) { // Some bits, but less than a byte
         LOG_WRN("RA_PARSE: %d unparsed bits remain (less than 1 byte), possible padding or parse error. Payload len %u.",
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