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

LOG_MODULE_REGISTER(dect_mac_phy_ctrl, CONFIG_DECT_MAC_PHY_CTRL_LOG_LEVEL);

// Global buffer for constructing the PCC (Physical Control Channel header) to be sent to nRF PHY API.
// This buffer is filled before each TX operation.
static union nrf_modem_dect_phy_hdr g_phy_pcc_tx_constructor_buf;

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


void dect_mac_phy_ctrl_init(void) {
    // Initialize global buffers if necessary (e.g., zero them out), though they are static.
    memset(&g_phy_pcc_tx_constructor_buf, 0, sizeof(g_phy_pcc_tx_constructor_buf));
    memset(g_phy_pdc_tx_constructor_buf_ctrl, 0, sizeof(g_phy_pdc_tx_constructor_buf_ctrl));
    LOG_INF("DECT MAC PHY Control initialized.");
    // Note: nrf_modem_dect_phy_init() is called by the application/main after nrf_modem_init()
    // and after dect_mac_phy_if_init() sets the event handler.
}

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
    if (ctx->pending_op_type != PENDING_OP_NONE && ctx->pending_op_handle != phy_op_handle) {
        if (ctx->pending_op_type != op_type || ctx->pending_op_handle != phy_op_handle) {
            LOG_WRN("PHY_CTRL_TX: Op %s (H:%u) busy with %s (H:%u).",
                    dect_pending_op_to_str(op_type), phy_op_handle,
                    dect_pending_op_to_str(ctx->pending_op_type), ctx->pending_op_handle);
            return -EBUSY;
        }
    }
    // If op_type and handle match, it might be an update to an existing pending op, allow.
    // Or, more strictly, no new op if any op is pending.
    // For simplicity, if an op is pending, only allow if it's the *same* op being rescheduled.
    // The pending_op_handle should be unique per call that intends to start a new PHY op.

    ctx->pending_op_handle = phy_op_handle;
    ctx->pending_op_type = op_type;

    if (full_mac_pdu_to_send == NULL || full_mac_pdu_len == 0 ||
        full_mac_pdu_len < sizeof(dect_mac_header_type_octet_t) || // Must have at least the type octet
        full_mac_pdu_len > CONFIG_DECT_MAC_PDU_MAX_SIZE) { // CONFIG_DECT_MAC_PDU_MAX_SIZE from Kconfig/api.h
        LOG_ERR("PHY_CTRL_TX: Invalid PDU or length: %p, %u", full_mac_pdu_to_send, full_mac_pdu_len);
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
    if (pdc_content_len_for_phy > 0) { // Only copy if there's actual PDC data
        memcpy(g_phy_pdc_tx_constructor_buf_ctrl, pdc_content_for_phy, pdc_content_len_for_phy);
    }


    memset(&g_phy_pcc_tx_constructor_buf, 0, sizeof(g_phy_pcc_tx_constructor_buf));
    uint8_t pcc_nrf_phy_type_val;
    uint8_t calculated_packet_len_val, selected_mcs_val, calculated_pkt_len_type_val;

    selected_mcs_val = ctx->config.default_data_mcs_code; // Base MCS
    if (is_beacon) { // Beacons should use a robust MCS, e.g., MCS0
        selected_mcs_val = 0; // Force MCS0 for beacons
    }
    // TODO: Allow op_type to influence selected_mcs_val (e.g. RACH might use robust MCS)

    dect_mac_phy_ctrl_calculate_pcc_params(pdc_content_len_for_phy,
                                           &calculated_packet_len_val,
                                           &selected_mcs_val, // Pass current selection, function will use/validate it
                                           &calculated_pkt_len_type_val);

    // Retrieve the MAC Header Type octet from the full PDU
    dect_mac_header_type_octet_t hdr_type_from_pdu;
    memcpy(&hdr_type_from_pdu, full_mac_pdu_to_send, sizeof(dect_mac_header_type_octet_t));


    if (is_beacon) {
        pcc_nrf_phy_type_val = 0; // nRF PHY Type 0 (ETSI PCC Type 1)
        struct nrf_modem_dect_phy_hdr_type_1 *pcc1 = &g_phy_pcc_tx_constructor_buf.hdr_type_1;
        pcc1->header_format = 0b000; // ETSI Figure 6.2.1-1: Bits are set to 000
        pcc1->packet_length_type = calculated_pkt_len_type_val;
        pcc1->packet_length = calculated_packet_len_val;
        pcc1->short_network_id = (uint8_t)(ctx->network_id_32bit & 0xFF);
        uint16_t be_tx_short_id = sys_cpu_to_be16(ctx->own_short_rd_id);
        pcc1->transmitter_id_hi = (uint8_t)(be_tx_short_id >> 8);
        pcc1->transmitter_id_lo = (uint8_t)(be_tx_short_id & 0xFF);
        pcc1->transmit_power = ctx->config.default_tx_power_code; // From MAC config
        pcc1->df_mcs = selected_mcs_val & 0x07; // 3 bits for Type 1 PCC's DF MCS
        pcc1->reserved = 0;
    } else { // Data or other control PDU
        pcc_nrf_phy_type_val = 1; // nRF PHY Type 1 (ETSI PCC Type 2)
        struct nrf_modem_dect_phy_hdr_type_2 *pcc2 = &g_phy_pcc_tx_constructor_buf.hdr_type_2;
        // Header format 000 = HARQ fields present, 001 = HARQ feedback not requested for this DF
        // This depends on whether this PDU *expects* a HARQ response from peer.
        // Assume for data PDUs, HARQ is generally used.
        pcc2->header_format = 0b000;
        pcc2->packet_length_type = calculated_pkt_len_type_val;
        pcc2->packet_length = calculated_packet_len_val;
        pcc2->short_network_id = (uint8_t)(ctx->network_id_32bit & 0xFF);
        uint16_t be_tx_short_id = sys_cpu_to_be16(ctx->own_short_rd_id);
        pcc2->transmitter_id_hi = (uint8_t)(be_tx_short_id >> 8);
        pcc2->transmitter_id_lo = (uint8_t)(be_tx_short_id & 0xFF);
        pcc2->transmit_power = ctx->config.default_tx_power_code;
        pcc2->df_mcs = selected_mcs_val & 0x0F; // 4 bits for Type 2 PCC's DF MCS

        uint16_t be_rx_short_id = sys_cpu_to_be16(target_receiver_short_id);
        pcc2->receiver_id_hi = (uint8_t)(be_rx_short_id >> 8);
        pcc2->receiver_id_lo = (uint8_t)(be_rx_short_id & 0xFF);
        pcc2->num_spatial_streams = 0; // Default: Single spatial stream

        bool is_harq_data_op = (op_type >= PENDING_OP_PT_DATA_TX_HARQ0 && op_type <= PENDING_OP_FT_DATA_TX_HARQ_MAX);
        if (is_harq_data_op) {
            int harq_idx_base = (op_type <= PENDING_OP_PT_DATA_TX_HARQ_MAX) ? PENDING_OP_PT_DATA_TX_HARQ0 : PENDING_OP_FT_DATA_TX_HARQ0;
            int harq_idx = op_type - harq_idx_base;
            if (harq_idx >=0 && harq_idx < MAX_HARQ_PROCESSES && ctx->harq_tx_processes[harq_idx].is_active) {
                 pcc2->df_harq_process_num = harq_idx & 0x07; // 3 bits
                 pcc2->df_new_data_indication = (ctx->harq_tx_processes[harq_idx].tx_attempts == 1) ? 1 : 0;
                 pcc2->df_redundancy_version = ctx->harq_tx_processes[harq_idx].redundancy_version & 0x03; // 2 bits
            } else {
                LOG_WRN("PHY_CTRL_TX: HARQ op_type %s but no active/valid HARQ proc %d. Using default HARQ fields.",
                        dect_pending_op_to_str(op_type), harq_idx);
                pcc2->df_new_data_indication = 1; pcc2->df_redundancy_version = 0; pcc2->df_harq_process_num = 0;
            }
        } else { // For other control messages (e.g., AssocReq, AssocResp, KeepAlive)
            pcc2->df_new_data_indication = 1; // Typically new data
            pcc2->df_redundancy_version = 0;  // RV0
            pcc2->df_harq_process_num = 0;    // Use a default process number or a dedicated one for control
        }
        // Populate pcc2->feedback if this TX PDU is also carrying HARQ feedback to the peer.
        // This is done in send_data_mac_sdu_via_phy_internal based on peer_info->pending_feedback_to_send
        // and passed in via phy_header parameter of nrf_modem_dect_phy_tx_params.
        // So, g_phy_pcc_tx_constructor_buf.hdr_type_2.feedback should already be populated by the caller if needed.
        // If not, ensure it's cleared here. For safety:
        // memset(&pcc2->feedback, 0, sizeof(pcc2->feedback)); // If caller doesn't set it, clear.
        // pcc2->feedback.format1.format = NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_NONE; // This is done by send_data_mac_sdu_via_phy_internal
    }

    struct nrf_modem_dect_phy_tx_params tx_params = {
        .start_time = phy_op_target_start_time,
        .handle = phy_op_handle,
        .network_id = ctx->network_id_32bit,
        .phy_type = pcc_nrf_phy_type_val,
        .lbt_rssi_threshold_max = use_lbt ? ctx->config.rssi_threshold_min_dbm : 0, // LBT if RSSI < threshold
        .carrier = carrier,
        .lbt_period = use_lbt ? NRF_MODEM_DECT_LBT_PERIOD_MIN : 0, // ETSI 5.3.3 needs at least this
                                                                  // TODO: Check if specific ops (RACH) need longer default LBT
        .phy_header = &g_phy_pcc_tx_constructor_buf, // Pointer to the globally constructed PCC
        .bs_cqi = NRF_MODEM_DECT_PHY_BS_CQI_NOT_USED, // For separate BS/CQI reporting packets, not this PDU's PCC
        .data = (pdc_content_len_for_phy > 0) ? g_phy_pdc_tx_constructor_buf_ctrl : NULL, // Pointer to global PDC data
        .data_size = pdc_content_len_for_phy
    };

    LOG_DBG("PHY_CTRL_TX: Starting TX. Hdl:%u, C:%u, FullMACLen:%u (PDC:%u), OpT:%s, LBT:%d, PCC nRFType:%u, TargetStart:%llu",
            phy_op_handle, carrier, full_mac_pdu_len, pdc_content_len_for_phy,
            dect_pending_op_to_str(op_type), use_lbt, pcc_nrf_phy_type_val,
            phy_op_target_start_time);

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
                                           uint8_t *out_packet_length_field,
                                           uint8_t *in_out_selected_mcs_field,
                                           uint8_t *out_packet_length_type_field)
{
    // This function remains critical and needs full implementation for all MCS/mu/beta.
    if (!out_packet_length_field || !in_out_selected_mcs_field || !out_packet_length_type_field) {
        LOG_ERR("PCC_CALC: NULL output pointers!");
        if(out_packet_length_field) *out_packet_length_field = 0;
        if(in_out_selected_mcs_field) *in_out_selected_mcs_field = 0;
        if(out_packet_length_type_field) *out_packet_length_type_field = 0;
        return;
    }
    uint32_t pdc_payload_len_bits = mac_pdc_payload_len_bytes * 8;
    uint8_t num_subslots_needed = 0;
    bool found_fit = false;

    if (*in_out_selected_mcs_field != 0) {
        LOG_WRN("PCC_CALC: Simplified! Only MCS0 supported. Forcing MCS0. Requested MCS %u ignored.", *in_out_selected_mcs_field);
        *in_out_selected_mcs_field = 0;
    }

    if (pdc_payload_len_bytes == 0) {
        num_subslots_needed = 1;
        found_fit = true;
    } else {
        for (uint8_t j = 1; j < MCS0_MU1_BETA1_TB_J_TABLE_SIZE_CTRL; j++) {
            if (pdc_payload_len_bits <= mcs0_mu1_beta1_cumulative_bits_pdcch_tb_j_ctrl[j]) {
                num_subslots_needed = j;
                found_fit = true;
                break;
            }
        }
    }

    if (!found_fit) {
        LOG_ERR("PCC_CALC: Payload %zu bytes too large for MCS0 max length. Clamping.", mac_pdc_payload_len_bytes);
        num_subslots_needed = MCS0_MU1_BETA1_TB_J_TABLE_SIZE_CTRL - 1;
    }

    *out_packet_length_type_field = 0; // 0 for subslots

    if (num_subslots_needed > PCC_PACKET_LENGTH_FIELD_MAX_UNITS_CTRL) {
        LOG_ERR("PCC_CALC: Needed %u subslots, PCC field max %u. Clamping.", num_subslots_needed, PCC_PACKET_LENGTH_FIELD_MAX_UNITS_CTRL);
        *out_packet_length_field = PCC_PACKET_LENGTH_FIELD_MAX_VALUE_CTRL;
    } else if (num_subslots_needed == 0 && mac_pdc_payload_len_bytes > 0) {
        LOG_ERR("PCC_CALC: Calculated 0 subslots for non-zero payload. Defaulting to 1.");
        *out_packet_length_field = 0; // 1 subslot
    } else {
        *out_packet_length_field = num_subslots_needed - 1; // N-1 coding
    }
    LOG_DBG("PCC_CALC: Payload %zuB (%ub), MCS %u -> %u subslots (PCC len_f 0x%X, type %u)",
            mac_pdc_payload_len_bytes, pdc_payload_len_bits, *in_out_selected_mcs_field,
            num_subslots_needed, *out_packet_length_field, *out_packet_length_type_field);
}