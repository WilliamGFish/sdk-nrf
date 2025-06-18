/* dect_mac/dect_mac_phy_ctrl.c */
#include <zephyr/logging/log.h>
#include <zephyr/random/rand32.h>
#include <nrf_modem_dect_phy.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <zephyr/sys/util.h> // For ARRAY_SIZE, MIN, MAX

#include "dect_mac_phy_ctrl.h"
#include "dect_mac_core.h"      // For get_mac_context()
#include "dect_mac_context.h"   // For dect_mac_context_t and its members, config constants
#include "dect_mac_main_dispatcher.h" // For string utility functions (logging)
#include "dect_mac_pdu.h"       // For dect_mac_header_type_octet_t (though nrf_modem provides its own PCC structs)
#include "dect_mac_phy_tbs_tables.h" // Include the new header with TBS tables

LOG_MODULE_REGISTER(dect_mac_phy_ctrl, CONFIG_DECT_MAC_PHY_CTRL_LOG_LEVEL);


/**
 * @brief Calculates the duration of one subslot in modem time ticks for a given mu_code.
 *
 * A subslot is 5 OFDM symbols. Symbol duration depends on mu.
 * NRF_MODEM_DECT_SYMBOL_DURATION is assumed to be for mu=1 (code 0).
 * mu_actual = 2^mu_code. Symbol_duration_mu = Symbol_duration_mu1 / (2^(mu_code)).
 *
 * @param mu_code The mu code (0-7, where actual mu = 2^mu_code).
 *                Typical DECT NR+ uses mu_codes 0,1,2,3 for mu=1,2,4,8.
 * @return Subslot duration in modem ticks, or 0 if invalid mu_code or calculation error.
 */
static uint32_t get_subslot_duration_ticks_for_mu(uint8_t mu_code)
{
    if (mu_code > 7) { // mu=2^7 = 128 is likely too high, ETSI Table 4.3-1 goes up to mu=8 (code=3)
        LOG_ERR("PHY_TIMING: Invalid mu_code %u for subslot duration.", mu_code);
        return 0;
    }

    uint32_t base_symbol_duration_ticks = NRF_MODEM_DECT_SYMBOL_DURATION; // Ticks for mu=1 symbol
    uint32_t actual_symbol_duration_ticks = base_symbol_duration_ticks;

    if (mu_code > 0) { // For mu_code 0 (mu=1), actual_symbol_duration_ticks is base_symbol_duration_ticks
        actual_symbol_duration_ticks = base_symbol_duration_ticks / (1U << mu_code);
    }
    
    if (actual_symbol_duration_ticks == 0 && base_symbol_duration_ticks != 0) {
        // This implies mu_code was too large, leading to division to zero.
        LOG_ERR("PHY_TIMING: Calculated symbol duration is 0 for mu_code %u (base_sym_ticks %u).",
                mu_code, base_symbol_duration_ticks);
        return 0;
    }
    return actual_symbol_duration_ticks * 5; // 5 OFDM symbols per subslot
}

/**
 * @brief Gets the number of subslots per ETSI slot (0.41667 ms) for a given mu_code.
 *
 * ETSI TS 103 636-3, Table 4.3-1: N_slot_subslot
 * mu=1 (code 0) -> 2 subslots/slot
 * mu=2 (code 1) -> 4 subslots/slot
 * mu=4 (code 2) -> 8 subslots/slot
 * mu=8 (code 3) -> 16 subslots/slot
 *
 * @param mu_code The mu code (0-7).
 * @return Number of subslots per ETSI slot.
 */
static uint8_t get_subslots_per_etsi_slot_for_mu(uint8_t mu_code)
{
    if (mu_code > 3) { // ETSI Table 4.3-1 currently defines N_slot_subslot up to mu=8 (code=3)
        LOG_WRN("PHY_TIMING: mu_code %u > 3, N_slot_subslot may not be standard. Defaulting for mu=8.", mu_code);
        return 16; // Value for mu=8 (code=3)
    }
    // N_slot_subslot = 2 * (2^mu_code) = 2 * mu_actual
    // mu_code 0 (mu=1) -> 2 * 1 = 2
    // mu_code 1 (mu=2) -> 2 * 2 = 4
    // mu_code 2 (mu=4) -> 2 * 4 = 8
    // mu_code 3 (mu=8) -> 2 * 8 = 16
    return 2 * (1U << mu_code);
}


// Global buffer for constructing the PCC (Physical Control Channel header) to be sent to nRF PHY API.
// This buffer is filled before each TX operation.
static union nrf_modem_dect_phy_hdr g_phy_pcc_tx_constructor_buf;

// --- TBS Table Definitions ---
// ETSI TS 103 636-3 v2.1.1 Table 7.4.3-2: PDSCH Transport block size Tb(j) for µ=1, β=1
// Values are Tb(j) in BITS. Index j is number of subslots (1 to 16).
// Array index [j-1] corresponds to j subslots.
// Max j (number of subslots) is 16 (PCC packet_length field is 0-15, so N=1 to 16 subslots/slots)
#define MAX_PDSCH_SUB_SLOTS_CTRL 16 // Renamed to avoid conflict with any similar define in context.h
#define MAX_MCS_INDEX_SUPPORTED_CTRL 11 // Renamed

// TBS table for mu=1, beta=1
// Indexed as: tbs_mu1_beta1[MCS_INDEX][j-1_SUBOTS]
// TODO: Fully populate this table from ETSI TS 103 636-3 Table 7.4.3-2 for all MCS 0-11 and j=1 to 16.
//       Ensure accuracy, especially for any "---" (not supported) entries (use 0).
static const uint16_t tbs_mu1_beta1_ctrl[MAX_MCS_INDEX_SUPPORTED_CTRL + 1][MAX_PDSCH_SUB_SLOTS_CTRL] = {
    // MCS 0 (π/2-DBPSK, R=1/3)
    {136, 264, 400, 536, 664, 792, 920, 1064, 1192, 1320, 1448, 1576, 1704, 1864, 1992, 2120 /* Verify/Adjust j=16 */},
    // MCS 1 (QPSK, R=1/2)
    {296, 552, 824, 1096, 1352, 1608, 1864, 2104, 2360, 2616, 2872, 3128, 3384, 3704, 3960, 4216 /* Verify/Adjust j=16 */},
    // MCS 2 (QPSK, R=3/4)
    {456, 856, 1256, 1640, 2024, 2360, 2744, 3192, 3576, 3960, 4320, 4768, 5152, 5536, 5920 /* Verify/Adjust j=15,16 */},
    // MCS 3 (16QAM, R=1/2)
    {616, 1128, 1672, 2168, 2680, 3192, 3704, 4256, 4768, 5280, 5792, 6304, 6816, 7456, 7720 /* Verify/Adjust j=15,16 */},
    // MCS 4 (16QAM, R=3/4)
    {936, 1736, 2488, 3256, 4024, 4832, 5600, 6304, 7000, 7720, 8480, 9240, 10000, 10760, 11520, 12280 /* Verify/Adjust j=16 */},
    // MCS 5 to MCS 11 - TODO: Populate with actual values from ETSI Table 7.4.3-2
    // Using placeholder 0 for now for remaining MCS to allow compilation
    {0},{0},{0},{0},{0},{0},{0} // Placeholders for MCS 5, 6, 7, 8, 9, 10, 11
};
// --- End of TBS Table Definitions ---

// Global buffer for the MAC PDU's PDC part (MAC Common Hdr + MAC SDU Area + MIC if secured)
// to be sent to nRF PHY API's data field.
// Size is MAX_MAC_PDU_SIZE_FOR_PCC_CALC (e.g. 1637 bytes from dect_mac_context.h)
// which should be CONFIG_DECT_MAC_PDU_MAX_SIZE - 1 (excluding MAC Hdr Type octet).
static uint8_t g_phy_pdc_tx_constructor_buf_ctrl[MAX_MAC_PDU_SIZE_FOR_PCC_CALC];


// Simplified Tb(j) lookup for MCS0 (µ=1, β=1 assumed for this table)
// ETSI TS 103 636-3 v2.1.1 (2023-07) Table 7.4.3-1 for PDCCH (not PDSCH)
// Values are cumulative bits Tb(j) for j sub-slots.
static const uint16_t mcs0_mu1_beta1_cumulative_bits_pdcch_tb_j_ctrl[] = {
    // j=0  j=1   j=2   j=3   j=4   j=5   j=6   j=7
       0,  136,  264,  400,  536,  664,  792,  920,
    // j=8  j=9  j=10  j=11  j=12  j=13  j=14  j=15
    1064, 1192, 1320, 1448, 1576, 1704, 1864, 1992
};
#define MCS0_MU1_BETA1_TB_J_TABLE_SIZE_CTRL ARRAY_SIZE(mcs0_mu1_beta1_cumulative_bits_pdcch_tb_j_ctrl)

#define PCC_PACKET_LENGTH_FIELD_MAX_UNITS_CTRL 16 // Field value 15 represents 16 units
#define PCC_PACKET_LENGTH_FIELD_MAX_VALUE_CTRL (PCC_PACKET_LENGTH_FIELD_MAX_UNITS_CTRL - 1)



int dect_mac_phy_ctrl_start_rx(uint16_t carrier, uint32_t duration_modem_units,
                               enum nrf_modem_dect_phy_rx_mode mode,
                               uint32_t phy_op_handle, uint16_t expected_receiver_id,
                               pending_op_type_t op_type)
{
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->pending_op_type != PENDING_OP_NONE && ctx->pending_op_handle != phy_op_handle) {
        if (ctx->pending_op_type != op_type || ctx->pending_op_handle != phy_op_handle) {
            LOG_WRN("PHY_CTRL_RX: Cannot start RX op %s (H:%u), op %s (H:%u) already pending.",
                    dect_pending_op_to_str(op_type), phy_op_handle,
                    dect_pending_op_to_str(ctx->pending_op_type), ctx->pending_op_handle);
            return -EBUSY;
        }
    }
    ctx->pending_op_handle = phy_op_handle;
    ctx->pending_op_type = op_type;

    struct nrf_modem_dect_phy_rx_params rx_params = {
        .start_time = 0, // Default to immediate start for RX initiated by MAC logic
        .handle = phy_op_handle,
        .network_id = ctx->network_id_32bit,
        .mode = mode,
        .rssi_interval = NRF_MODEM_DECT_PHY_RSSI_INTERVAL_OFF, // Default, can be changed by caller if needed
        .link_id = NRF_MODEM_DECT_PHY_LINK_UNSPECIFIED, // TODO: Set if multi-link AFC is used
        .rssi_level = 0, // Auto AGC
        .carrier = carrier,
        .duration = duration_modem_units,
        .filter = {
            .short_network_id = (uint8_t)(ctx->network_id_32bit & 0xFF),
            .is_short_network_id_used = 1,
            // receiver_identity is BE format in nrf_modem_dect_phy.h, but spec uses LE for RD IDs.
            // Let's assume nrf_modem expects it in the format it would appear on air for PCC.
            // Short RD IDs are 16-bit.
            .receiver_identity = sys_cpu_to_be16(expected_receiver_id) // Ensure BE for filter match
        }
    };

    LOG_DBG("PHY_CTRL_RX: Starting RX. Hdl: %u, C: %u, Mode: %d, Dur: %u TU, RxID_Filter: 0x%04X, OpT: %s",
            phy_op_handle, carrier, mode, duration_modem_units,
            expected_receiver_id, dect_pending_op_to_str(op_type));

    int ret = nrf_modem_dect_phy_rx(&rx_params);
    if (ret != 0) {
        LOG_ERR("PHY_CTRL_RX: nrf_modem_dect_phy_rx() failed: %d. Hdl: %u, OpT: %s", ret, phy_op_handle, dect_pending_op_to_str(op_type));
        if (ctx->pending_op_handle == phy_op_handle && ctx->pending_op_type == op_type) {
            ctx->pending_op_type = PENDING_OP_NONE;
            ctx->pending_op_handle = 0;
        }
    }
    return ret;
}

int dect_mac_phy_ctrl_assemble_final_pdu(
    uint8_t *target_final_mac_pdu_buf,
    size_t target_buf_max_len,
    const dect_mac_header_type_octet_t *mac_hdr_type_octet, // Corrected type name
    const void *common_hdr_data,
    size_t common_hdr_len,
    const uint8_t *mac_sdu_area_data,
    size_t mac_sdu_area_len,
    uint16_t *out_assembled_pdu_len_cleartext)
{
    size_t current_offset = 0;

    if (!target_final_mac_pdu_buf || !mac_hdr_type_octet || !out_assembled_pdu_len_cleartext) {
        return -EINVAL;
    }
    // Validate conditional parameters
    if ((common_hdr_data == NULL && common_hdr_len > 0) || (common_hdr_data != NULL && common_hdr_len == 0)) {
        // Allow common_hdr_data to be NULL if common_hdr_len is 0 (e.g. no common header after type octet)
        if (common_hdr_data != NULL || common_hdr_len != 0) return -EINVAL;
    }
    if ((mac_sdu_area_data == NULL && mac_sdu_area_len > 0) || (mac_sdu_area_data != NULL && mac_sdu_area_len == 0)) {
        if (mac_sdu_area_data != NULL || mac_sdu_area_len != 0) return -EINVAL;
    }

    // 1. MAC Header Type (1 byte)
    if (target_buf_max_len < sizeof(dect_mac_header_type_octet_t)) return -ENOMEM;
    memcpy(target_final_mac_pdu_buf + current_offset, mac_hdr_type_octet, sizeof(dect_mac_header_type_octet_t));
    current_offset += sizeof(dect_mac_header_type_octet_t);

    // 2. MAC Common Header
    if (common_hdr_data && common_hdr_len > 0) {
        if (current_offset + common_hdr_len > target_buf_max_len) return -ENOMEM;
        memcpy(target_final_mac_pdu_buf + current_offset, common_hdr_data, common_hdr_len);
        current_offset += common_hdr_len;
    }

    // 3. MAC SDU Area (MUXed IEs or MUXed User Data SDU)
    if (mac_sdu_area_data && mac_sdu_area_len > 0) {
        if (current_offset + mac_sdu_area_len > target_buf_max_len) return -ENOMEM;
        memcpy(target_final_mac_pdu_buf + current_offset, mac_sdu_area_data, mac_sdu_area_len);
        current_offset += mac_sdu_area_len;
    }

    *out_assembled_pdu_len_cleartext = current_offset;
    return 0;
}



int dect_mac_phy_ctrl_start_tx_assembled(uint16_t carrier,
                                         const uint8_t *full_mac_pdu_to_send, uint16_t full_mac_pdu_len,
                                         uint16_t target_receiver_short_id, bool is_beacon,
                                         uint32_t phy_op_handle, pending_op_type_t op_type,
                                         bool use_lbt,
                                         uint64_t phy_op_target_start_time)
{
    dect_mac_context_t* ctx = get_mac_context();
    if (!ctx) { // Should ideally not happen if init order is correct
        LOG_ERR("PHY_CTRL_TX: MAC Context is NULL!");
        return -EFAULT;
    }

    if (ctx->pending_op_type != PENDING_OP_NONE && ctx->pending_op_handle != phy_op_handle) {
        if (ctx->pending_op_type != op_type || ctx->pending_op_handle != phy_op_handle) {
            LOG_WRN("PHY_CTRL_TX: Op %s (H:%u) busy with %s (H:%u). New TX for %s (H:%u) rejected.",
                    dect_pending_op_to_str(ctx->pending_op_type), ctx->pending_op_handle,
                    dect_pending_op_to_str(ctx->pending_op_type), ctx->pending_op_handle,
                    dect_pending_op_to_str(op_type), phy_op_handle);
            return -EBUSY;
        }
    }
    ctx->pending_op_handle = phy_op_handle;
    ctx->pending_op_type = op_type;

    if (full_mac_pdu_to_send == NULL || full_mac_pdu_len == 0 ||
        full_mac_pdu_len < sizeof(dect_mac_header_type_octet_t) ||
        full_mac_pdu_len > CONFIG_DECT_MAC_PDU_MAX_SIZE) {
        LOG_ERR("PHY_CTRL_TX: Invalid PDU or length: %p, len %u (min_hdr_type %zu, max_pdu %d)",
                full_mac_pdu_to_send, full_mac_pdu_len,
                sizeof(dect_mac_header_type_octet_t), CONFIG_DECT_MAC_PDU_MAX_SIZE);
        if (ctx->pending_op_handle == phy_op_handle) {ctx->pending_op_type = PENDING_OP_NONE; ctx->pending_op_handle = 0;}
        return -EINVAL;
    }

    const uint8_t *pdc_content_for_phy = full_mac_pdu_to_send + sizeof(dect_mac_header_type_octet_t);
    uint16_t pdc_content_len_for_phy = full_mac_pdu_len - sizeof(dect_mac_header_type_octet_t);

    if (pdc_content_len_for_phy > sizeof(g_phy_pdc_tx_constructor_buf_ctrl)) {
        LOG_ERR("PHY_CTRL_TX: Effective PDC content for PHY TX too large (%u > %zu)",
                pdc_content_len_for_phy, sizeof(g_phy_pdc_tx_constructor_buf_ctrl));
        if (ctx->pending_op_handle == phy_op_handle) {ctx->pending_op_type = PENDING_OP_NONE; ctx->pending_op_handle = 0;}
        return -ENOMEM;
    }
    if (pdc_content_len_for_phy > 0) {
        memcpy(g_phy_pdc_tx_constructor_buf_ctrl, pdc_content_for_phy, pdc_content_len_for_phy);
    }

    memset(&g_phy_pcc_tx_constructor_buf, 0, sizeof(g_phy_pcc_tx_constructor_buf));
    uint8_t pcc_nrf_phy_type_val;
    uint8_t calculated_pcc_packet_len_field;
    uint8_t mcs_to_use_for_pcc_calc;
    uint8_t calculated_pcc_pkt_len_type_field;

    mcs_to_use_for_pcc_calc = ctx->config.default_data_mcs_code;
    if (is_beacon) {
        mcs_to_use_for_pcc_calc = 0;
    }
    if (op_type == PENDING_OP_PT_RACH_ASSOC_REQ) {
        mcs_to_use_for_pcc_calc = 0;
    }

    // Use the device's own configured/operational mu and beta for its transmissions
    uint8_t own_mu_code = 0; // Default to mu-code 0 (actual mu=1)
    uint8_t own_beta_code = 0; // Default to beta-code 0 (actual beta=1)

    if (ctx->own_phy_params.is_valid) {
        own_mu_code = ctx->own_phy_params.mu;
        own_beta_code = ctx->own_phy_params.beta;
    } else {
        LOG_WRN("PHY_CTRL_TX: Own PHY params not marked valid in context. Using default mu_code=0, beta_code=0.");
        // Kconfig defaults would have been loaded into own_phy_params, but is_valid might be false if init failed.
        // Or, if own_phy_params is not fully initialized yet, use Kconfig defaults directly as ultimate fallback.
        own_mu_code = CONFIG_DECT_MAC_OWN_MU_CODE;
        own_beta_code = CONFIG_DECT_MAC_OWN_BETA_CODE;
    }
    // Sanitize codes just in case Kconfig allows out of typical range for DECT NR+
    if (own_mu_code > 7) { LOG_WRN("PHY_CTRL_TX: own_mu_code %u invalid, using 0.", own_mu_code); own_mu_code = 0; }
    if (own_beta_code > 15) { LOG_WRN("PHY_CTRL_TX: own_beta_code %u invalid, using 0.", own_beta_code); own_beta_code = 0; }


    dect_mac_phy_ctrl_calculate_pcc_params(pdc_content_len_for_phy,
                                           own_mu_code, own_beta_code,
                                           &calculated_pcc_packet_len_field,
                                           &mcs_to_use_for_pcc_calc,
                                           &calculated_pcc_pkt_len_type_field);

    if (is_beacon) {
        pcc_nrf_phy_type_val = 0; 
        struct nrf_modem_dect_phy_hdr_type_1 *pcc1 = &g_phy_pcc_tx_constructor_buf.hdr_type_1;
        pcc1->header_format = 0b000; 
        pcc1->packet_length_type = calculated_pcc_pkt_len_type_field; 
        pcc1->packet_length = calculated_pcc_packet_len_field;       
        pcc1->short_network_id = (uint8_t)(ctx->network_id_32bit & 0xFF);
        uint16_t be_tx_short_id = sys_cpu_to_be16(ctx->own_short_rd_id);
        pcc1->transmitter_id_hi = (uint8_t)(be_tx_short_id >> 8);
        pcc1->transmitter_id_lo = (uint8_t)(be_tx_short_id & 0xFF);
        pcc1->transmit_power = ctx->config.default_tx_power_code;
        pcc1->df_mcs = mcs_to_use_for_pcc_calc & 0x07; 
        pcc1->reserved = 0;
    } else { 
        pcc_nrf_phy_type_val = 1; 
        struct nrf_modem_dect_phy_hdr_type_2 *pcc2 = &g_phy_pcc_tx_constructor_buf.hdr_type_2;
        pcc2->header_format = 0b000; 
        pcc2->packet_length_type = calculated_pcc_pkt_len_type_field; 
        pcc2->packet_length = calculated_pcc_packet_len_field;       
        pcc2->short_network_id = (uint8_t)(ctx->network_id_32bit & 0xFF);
        uint16_t be_tx_short_id = sys_cpu_to_be16(ctx->own_short_rd_id);
        pcc2->transmitter_id_hi = (uint8_t)(be_tx_short_id >> 8);
        pcc2->transmitter_id_lo = (uint8_t)(be_tx_short_id & 0xFF);
        pcc2->transmit_power = ctx->config.default_tx_power_code;
        pcc2->df_mcs = mcs_to_use_for_pcc_calc & 0x0F; 

        uint16_t be_rx_short_id = sys_cpu_to_be16(target_receiver_short_id);
        pcc2->receiver_id_hi = (uint8_t)(be_rx_short_id >> 8);
        pcc2->receiver_id_lo = (uint8_t)(be_rx_short_id & 0xFF);
        pcc2->num_spatial_streams = 0; 

        bool is_harq_data_op = (op_type >= PENDING_OP_PT_DATA_TX_HARQ0 && op_type <= PENDING_OP_FT_DATA_TX_HARQ_MAX);
        if (is_harq_data_op) {
            int harq_idx_base = (op_type >= PENDING_OP_FT_DATA_TX_HARQ0) ? PENDING_OP_FT_DATA_TX_HARQ0 : PENDING_OP_PT_DATA_TX_HARQ0;
            int harq_idx = op_type - harq_idx_base;

            if (harq_idx >= 0 && harq_idx < MAX_HARQ_PROCESSES && ctx->harq_tx_processes[harq_idx].is_active) {
                 pcc2->df_harq_process_num = harq_idx & 0x07; 
                 pcc2->df_new_data_indication = (ctx->harq_tx_processes[harq_idx].tx_attempts == 1) ? 1 : 0; 
                 pcc2->df_redundancy_version = ctx->harq_tx_processes[harq_idx].redundancy_version & 0x03; 
            } else {
                LOG_WRN("PHY_CTRL_TX: HARQ op_type %s but no active/valid HARQ proc %d. Using default HARQ fields in PCC.",
                        dect_pending_op_to_str(op_type), harq_idx);
                pcc2->df_new_data_indication = 1; pcc2->df_redundancy_version = 0; pcc2->df_harq_process_num = 0;
            }
        } else { 
            pcc2->df_new_data_indication = 1; 
            pcc2->df_redundancy_version = 0;  
            pcc2->df_harq_process_num = 0;    
        }
        // Note: pcc2->feedback is populated by the caller (e.g., data_path) if feedback is to be sent.
        // If not pre-populated, it remains zeroed from memset.
    }

    struct nrf_modem_dect_phy_tx_params tx_params = {
        .start_time = phy_op_target_start_time,
        .handle = phy_op_handle,
        .network_id = ctx->network_id_32bit,
        .phy_type = pcc_nrf_phy_type_val,
        .lbt_rssi_threshold_max = use_lbt ? ctx->config.rssi_threshold_min_dbm : 0,
        .carrier = carrier,
        .lbt_period = use_lbt ? NRF_MODEM_DECT_LBT_PERIOD_MIN : 0,
        .phy_header = &g_phy_pcc_tx_constructor_buf,
        .bs_cqi = NRF_MODEM_DECT_PHY_BS_CQI_NOT_USED,
        .data = (pdc_content_len_for_phy > 0) ? g_phy_pdc_tx_constructor_buf_ctrl : NULL,
        .data_size = pdc_content_len_for_phy
    };

    LOG_DBG("PHY_CTRL_TX: Starting TX. Hdl:%u, C:%u, FullMACLen:%u (PDC:%u), OpT:%s, LBT:%d, PCC nRFType:%u, TargetStart:%llu, OwnMuCode:%u, OwnBetaCode:%u",
            phy_op_handle, carrier, full_mac_pdu_len, pdc_content_len_for_phy,
            dect_pending_op_to_str(op_type), use_lbt, pcc_nrf_phy_type_val,
            phy_op_target_start_time, own_mu_code, own_beta_code);

    int ret = nrf_modem_dect_phy_tx(&tx_params);
    if (ret != 0) {
        LOG_ERR("PHY_CTRL_TX: nrf_modem_dect_phy_tx() failed: %d. Hdl:%u, OpT:%s", ret, phy_op_handle, dect_pending_op_to_str(op_type));
        if (ctx->pending_op_handle == phy_op_handle && ctx->pending_op_type == op_type) {
            ctx->pending_op_type = PENDING_OP_NONE;
            ctx->pending_op_handle = 0;
        }
    }
    return ret;
}



int dect_mac_phy_ctrl_start_rssi_scan(uint16_t carrier, uint32_t duration_modem_units,
                                      enum nrf_modem_dect_phy_rssi_interval reporting_interval,
                                      uint32_t phy_op_handle, pending_op_type_t op_type) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->pending_op_type != PENDING_OP_NONE && ctx->pending_op_handle != phy_op_handle) {
         if (ctx->pending_op_type != op_type || ctx->pending_op_handle != phy_op_handle) {
            LOG_WRN("PHY_CTRL_RSSI: Op %s (H:%u) busy with %s (H:%u).",
                    dect_pending_op_to_str(op_type), phy_op_handle,
                    dect_pending_op_to_str(ctx->pending_op_type), ctx->pending_op_handle);
            return -EBUSY;
         }
    }
    ctx->pending_op_handle = phy_op_handle;
    ctx->pending_op_type = op_type;

    struct nrf_modem_dect_phy_rssi_params rssi_params = {
        .start_time = 0, // Immediate start for scans initiated by MAC logic
        .handle = phy_op_handle,
        .carrier = carrier,
        .duration = duration_modem_units,
        .reporting_interval = reporting_interval
    };
    LOG_DBG("PHY_CTRL_RSSI: Starting RSSI. Hdl: %u, C: %u, Dur: %u TU, RepInt: %d, OpT: %s",
            phy_op_handle, carrier, duration_modem_units, reporting_interval, dect_pending_op_to_str(op_type));

    int ret = nrf_modem_dect_phy_rssi(&rssi_params);
    if (ret != 0) {
        LOG_ERR("PHY_CTRL_RSSI: nrf_modem_dect_phy_rssi() failed: %d. Hdl: %u, OpT: %s", ret, phy_op_handle, dect_pending_op_to_str(op_type));
        if (ctx->pending_op_handle == phy_op_handle && ctx->pending_op_type == op_type) {
             ctx->pending_op_type = PENDING_OP_NONE;
             ctx->pending_op_handle = 0;
        }
    }
    return ret;
}

int dect_mac_phy_ctrl_cancel_op(uint32_t phy_op_handle) {
    LOG_INF("PHY_CTRL: Requesting cancel for PHY op handle %u", phy_op_handle);
    // The NRF_MODEM_DECT_PHY_EVT_COMPLETED for the cancelled op will clear pending_op_type.
    // NRF_MODEM_DECT_PHY_EVT_CANCELED confirms the cancel request itself.
    return nrf_modem_dect_phy_cancel(phy_op_handle);
}

pending_op_type_t dect_mac_phy_ctrl_handle_op_complete(const struct nrf_modem_dect_phy_op_complete_event *event) {
    dect_mac_context_t* ctx = get_mac_context();
    pending_op_type_t completed_type = PENDING_OP_NONE;

    if (event == NULL) {
        LOG_ERR("PHY_CTRL_OP_DONE: NULL event pointer.");
        return PENDING_OP_NONE;
    }

    // Check if this completion matches the MAC's currently tracked pending operation
    if (event->handle == ctx->pending_op_handle && ctx->pending_op_type != PENDING_OP_NONE) {
        completed_type = ctx->pending_op_type;
        LOG_INF("PHY_CTRL_OP_DONE: Matches pending op: Handle %u, Type %s, Err %d (%s)",
                event->handle, dect_pending_op_to_str(completed_type),
                event->err, nrf_modem_dect_phy_err_to_str(event->err));
        ctx->pending_op_type = PENDING_OP_NONE;
        ctx->pending_op_handle = 0; // Clear the global pending operation
    } else {
        // This can happen if:
        // 1. An operation completed that MAC wasn't specifically tracking with pending_op_handle (e.g., a multi-part op where only the first part was tracked).
        // 2. An operation was cancelled, and this is its completion event, but pending_op_handle was already cleared by a new op starting.
        // 3. A stale completion event for an old handle.
        if (ctx->pending_op_type == PENDING_OP_NONE && event->err == NRF_MODEM_DECT_PHY_ERR_OP_CANCELED) {
             LOG_DBG("PHY_CTRL_OP_DONE: Op CANCELED (Hdl %u), no specific MAC op was pending with this handle (or already cleared).", event->handle);
        } else if (event->err != NRF_MODEM_DECT_PHY_SUCCESS && event->err != NRF_MODEM_DECT_PHY_ERR_OP_CANCELED) {
            LOG_WRN("PHY_CTRL_OP_DONE: Error %d (%s) for unexpected/stale handle %u (current pending: Hdl %u, Type %s)",
                    event->err, nrf_modem_dect_phy_err_to_str(event->err),
                    event->handle, ctx->pending_op_handle, dect_pending_op_to_str(ctx->pending_op_type));
        } else { // Success or Canceled, but not matching current pending
             LOG_DBG("PHY_CTRL_OP_DONE: Success/Canceled for Hdl %u, but not matching current pending (Hdl %u, Type %s).",
                    event->handle, ctx->pending_op_handle, dect_pending_op_to_str(ctx->pending_op_type));
        }
    }
    return completed_type;
}

void dect_mac_phy_ctrl_calculate_pcc_params(size_t mac_pdc_payload_len_bytes,
                                           uint8_t mu, uint8_t beta, /* New parameters */
                                           uint8_t *out_packet_length_field,
                                           uint8_t *in_out_selected_mcs_field,
                                           uint8_t *out_packet_length_type_field)
{
    // This function remains critical and needs full implementation for all MCS/mu/beta.
    if (!out_packet_length_field || !in_out_selected_mcs_field || !out_packet_length_type_field) {
        LOG_ERR("PCC_CALC: NULL output pointers!");
        if(out_packet_length_field) *out_packet_length_field = 0;
        if(in_out_selected_mcs_field) *in_out_selected_mcs_field = 0; // Do not modify input if error
        if(out_packet_length_type_field) *out_packet_length_type_field = 0;
        return;
    }

    uint32_t pdc_payload_len_bits = (uint32_t)mac_pdc_payload_len_bytes * 8;
    uint8_t num_subslots_needed = 0; // Actual number of subslots (1-16)
    bool found_fit = false;
    uint8_t selected_mcs = *in_out_selected_mcs_field; // Use the input MCS





    const uint16_t (*selected_tbs_table)[TBS_MAX_SUB_SLOTS_J] = NULL;
    if (mu == 0 && beta == 0) { // Assuming mu_code 0 for mu=1, beta_code 0 for beta=1
        selected_tbs_table = tbs_single_slot_mu1_beta1; // From dect_mac_phy_tbs_tables.h
    } else {
        LOG_ERR("PCC_CALC: Unsupported mu_code=%u, beta_code=%u. Only mu_code=0, beta_code=0 (mu=1,beta=1) supported currently.", mu, beta);
        // Fallback to mu=1,beta=1 table if available, or error out
        selected_tbs_table = tbs_single_slot_mu1_beta1; // Use the only table we have for now
        if (!selected_tbs_table) { // Should not happen if header is included
             LOG_ERR("PCC_CALC: tbs_single_slot_mu1_beta1 table is NULL. Cannot proceed.");
            *out_packet_length_field = PCC_PACKET_LENGTH_FIELD_MAX_VALUE_CTRL; 
            *out_packet_length_type_field = 0; 
            return;
        }
        LOG_WRN("PCC_CALC: Using mu=1,beta=1 TBS as fallback.");
    }

    if (selected_mcs > TBS_MAX_MCS_INDEX) {
        LOG_ERR("PCC_CALC: Requested MCS %u is out of supported range (max %u). Clamping to max supported.",
                selected_mcs, TBS_MAX_MCS_INDEX);
        selected_mcs = TBS_MAX_MCS_INDEX;
        *in_out_selected_mcs_field = selected_mcs; 
    }



    if (mac_pdc_payload_len_bytes == 0) {
        // For a zero-byte PDC payload (e.g., MAC PDU with only PCC for ACK/NACK feedback),
        // ETSI implies minimum 1 subslot is used.
        num_subslots_needed = 1;
        found_fit = true;
    } else {


        for (uint8_t j_idx = 0; j_idx < TBS_MAX_SUB_SLOTS_J; j_idx++) { // New constant
            // Check if selected_tbs_table is valid before dereferencing
            if (!selected_tbs_table) { found_fit = false; break; } // Should have been caught earlier

            if (selected_tbs_table[selected_mcs][j_idx] == 0 && pdc_payload_len_bits > 0) {
                if (j_idx == TBS_MAX_SUB_SLOTS_J - 1 && !found_fit) {
                    LOG_WRN("PCC_CALC: TBS entry is 0 for MCS %u at max subslots (%u), payload %u bits. Likely too large or table incomplete.",
                            selected_mcs, j_idx + 1, pdc_payload_len_bits);
                }
                continue;
            }
            if (pdc_payload_len_bits <= selected_tbs_table[selected_mcs][j_idx]) {
                num_subslots_needed = j_idx + 1; 
                found_fit = true;
                break;
            }
        }


    }






    if (!found_fit) {
        LOG_ERR("PCC_CALC: Payload %zu bytes (%u bits) too large for MCS %u even at max %u subslots (TBS: %u bits). Clamping length.",
                mac_pdc_payload_len_bytes, pdc_payload_len_bits, selected_mcs, MAX_PDSCH_SUB_SLOTS_CTRL,
                selected_tbs_table[selected_mcs][MAX_PDSCH_SUB_SLOTS_CTRL - 1]);
        num_subslots_needed = MAX_PDSCH_SUB_SLOTS_CTRL;
        // TODO: Consider if *in_out_selected_mcs_field should be lowered and recalculation attempted.
        //       For now, we indicate failure by maxing out slots for the *current* MCS.
        //       The caller might need to then retry with a lower MCS.
    }

    *out_packet_length_type_field = 0; // 0 for subslots (PCC packet_length always refers to subslots for PDC)

    // PCC packet_length field is (N-1) coded, where N is number of subslots.
    if (num_subslots_needed > 0 && num_subslots_needed <= TBS_MAX_SUB_SLOTS_J) { // New constant
        *out_packet_length_field = num_subslots_needed - 1;
    } else if (num_subslots_needed == 0 && mac_pdc_payload_len_bytes > 0) { // Should be caught by found_fit
        LOG_ERR("PCC_CALC: Calculated 0 subslots for non-zero payload (%zu bytes). Defaulting to 1 subslot.", mac_pdc_payload_len_bytes);
        *out_packet_length_field = 0; // Represents 1 subslot
        num_subslots_needed = 1; 
    } else { 
        // This case implies num_subslots_needed > TBS_MAX_SUB_SLOTS_J (already clamped by found_fit logic)
        // or num_subslots_needed == 0 for zero payload (handled by initial if)
        // If num_subslots_needed was clamped to TBS_MAX_SUB_SLOTS_J, this is correct:
        *out_packet_length_field = TBS_MAX_SUB_SLOTS_J - 1; // Max field value for TBS_MAX_SUB_SLOTS_J
        // num_subslots_needed is already TBS_MAX_SUB_SLOTS_J if clamped.
    }


    LOG_DBG("PCC_CALC: Payload %zuB (%ub), mu %u, beta %u, MCS %u -> %u subslots (PCC len_f 0x%X, type %u)",
            mac_pdc_payload_len_bytes, pdc_payload_len_bits, mu, beta, selected_mcs,
            num_subslots_needed, *out_packet_length_field, *out_packet_length_type_field);
}


void dect_mac_phy_ctrl_init(void) {
    // Initialize global buffers if necessary (e.g., zero them out), though they are static.
    memset(&g_phy_pcc_tx_constructor_buf, 0, sizeof(g_phy_pcc_tx_constructor_buf));
    memset(g_phy_pdc_tx_constructor_buf_ctrl, 0, sizeof(g_phy_pdc_tx_constructor_buf_ctrl));
    LOG_INF("DECT MAC PHY Control initialized.");
    // Note: nrf_modem_dect_phy_init() is called by the application/main after nrf_modem_init()
    // and after dect_mac_phy_if_init() sets the event handler.
}