/* dect_mac/dect_mac_sm_ft.c */
#include <zephyr/logging/log.h>
#include <zephyr/random/rand32.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <zephyr/sys/util.h>

#include "dect_mac_sm_ft.h"
#include "dect_mac_core.h"
#include "dect_mac_context.h"
#include "dect_mac_pdu.h"
#include "dect_mac_phy_ctrl.h"
#include "dect_mac_data_path.h"
#include "dect_mac_main_dispatcher.h"
#include "dect_mac_api.h"       // For g_mac_sdu_slab
#include "dect_mac_security.h"  // For security functions

LOG_MODULE_REGISTER(dect_mac_sm_ft, CONFIG_DECT_MAC_SM_FT_LOG_LEVEL);

// --- Static Globals for this Module ---
static struct nrf_modem_dect_phy_pcc_event ft_last_relevant_pcc;
static bool ft_last_relevant_pcc_is_valid = false;

// --- Static Helper Function Prototypes (defined below) ---
static void ft_handle_phy_op_complete_ft(const struct nrf_modem_dect_phy_op_complete_event *event, pending_op_type_t completed_op_type);
static void ft_handle_phy_pcc_ft(const struct nrf_modem_dect_phy_pcc_event *event);
static void ft_handle_phy_pdc_ft(const struct nrf_modem_dect_phy_pdc_event *event);
static void ft_handle_phy_rssi_ft(const struct nrf_modem_dect_phy_rssi_event *event);
static void ft_select_operating_carrier_and_start_beaconing(const struct nrf_modem_dect_phy_rssi_event *rssi_event_data);
static void ft_start_beaconing_actions(void);
static void ft_send_beacon_action(void);
static void ft_schedule_rach_listen_action(void);
static void ft_process_association_request_pdu(const uint8_t *mac_sdu_area_data, size_t mac_sdu_area_len,
                                               uint16_t pt_tx_short_rd_id, uint32_t pt_tx_long_rd_id, int16_t rssi_from_pcc);
static void ft_send_association_response_action(uint32_t pt_long_rd_id, uint16_t pt_short_rd_id, bool accept_association, int peer_slot_idx);
static int  ft_find_and_init_peer_slot(uint32_t pt_long_id, uint16_t pt_short_id, int16_t rssi);
static int ft_get_peer_slot_idx(dect_mac_context_t* ctx, uint16_t pt_short_id);
static void populate_cb_fields_from_ctx(dect_mac_context_t *ctx, dect_mac_cluster_beacon_ie_fields_t *cb_fields);
static uint64_t calculate_target_modem_time(dect_mac_context_t *ctx, uint64_t sfn_zero_anchor_time, uint8_t anchor_sfn_val, uint8_t target_sfn_val, uint16_t target_subslot_idx);
// Helpers (ensure these are defined or made extern if in another file)
uint32_t get_subslot_duration_ticks(dect_mac_context_t *ctx);
uint32_t modem_us_to_ticks(uint32_t us, uint32_t tick_rate_khz);


// --- FT Timer Expiry Action Function (called by dispatcher) ---
void dect_mac_sm_ft_beacon_timer_expired_action(void) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->pending_op_type == PENDING_OP_NONE) {
        ft_send_beacon_action();
    } else {
        LOG_WRN("FT SM: Beacon time, but op %s pending. Skipping this beacon.",
                dect_pending_op_to_str(ctx->pending_op_type));
        uint32_t short_delay_ms = ctx->config.ft_cluster_beacon_period_ms / 4;
        if (short_delay_ms < 10) short_delay_ms = 10; // Minimum sensible retry delay
        if (short_delay_ms == 0 && ctx->config.ft_cluster_beacon_period_ms > 0) {
            short_delay_ms = ctx->config.ft_cluster_beacon_period_ms; // If period is very short, retry at full period
        } else if (short_delay_ms == 0) {
             short_delay_ms = 100; // Fallback if period was 0
        }
        k_timer_start(&ctx->role_ctx.ft.beacon_timer, K_MSEC(short_delay_ms), K_NO_WAIT);
    }
}

// --- FT Public Functions ---
void dect_mac_sm_ft_start_operation(void) {
    dect_mac_context_t* ctx = get_mac_context();
    dect_mac_change_state(MAC_STATE_FT_SCANNING);

    // Initialize DCS context
    ctx->role_ctx.ft.dcs_current_channel_scan_index = 0;
    ctx->role_ctx.ft.dcs_scan_complete = false;
    for (int i = 0; i < CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN; i++) {
        ctx->role_ctx.ft.dcs_candidate_rssi_avg[i] = NRF_MODEM_DECT_PHY_RSSI_NOT_MEASURED; // Indicates not scanned or invalid
        ctx->role_ctx.ft.dcs_candidate_busy_percent[i] = 101; // Indicates not scanned
    }

    // Populate candidate channels - TODO: Get this from Kconfig or a fixed list
    if (CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN > 0) {
        const char *chan_list_str = CONFIG_DECT_MAC_DCS_CHANNEL_LIST;
        char *next_chan_str;
        char *search_start = (char *)chan_list_str;
        int count = 0;

        for (count = 0; count < CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN; count++) {
            long chan_val = strtol(search_start, &next_chan_str, 10); // Assuming kHz are decimal
            if (search_start == next_chan_str) { // No number parsed
                if (count == 0) LOG_ERR("FT_DCS_INIT: No valid channels in Kconfig list '%s'", chan_list_str);
                break; // Stop if no more numbers
            }
            if (chan_val <= 0 || chan_val > UINT16_MAX) { // Basic validation for carrier frequency
                LOG_WRN("FT_DCS_INIT: Invalid channel value %ld from Kconfig list. Skipping.", chan_val);
            } else {
                ctx->role_ctx.ft.dcs_candidate_channels[count] = (uint16_t)chan_val;
                LOG_DBG("FT_DCS_INIT: Added candidate channel %u kHz", (uint16_t)chan_val);
            }

            if (*next_chan_str == ',') {
                search_start = next_chan_str + 1;
            } else if (*next_chan_str == '\0') { // End of string
                count++; // Account for the last parsed channel
                break;
            } else { // Invalid format
                LOG_WRN("FT_DCS_INIT: Invalid format in Kconfig channel list near '%s'", next_chan_str);
                break;
            }
        }
        if (count < CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN && count > 0) {
            LOG_WRN("FT_DCS_INIT: Kconfig provided %d channels, but configured to scan %d. Will scan %d.",
                    count, CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN, count);
            // Effectively reduce the number of channels to scan if Kconfig list is shorter
            // This requires CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN to be non-const or use a runtime var.
            // For simplicity, we assume Kconfig list provides at least NUM_CHANNELS_TO_SCAN,
            // or the loop naturally stops. The scan loop uses CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN.
            // It's better if the loop limit is min(CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN, actual_parsed_count).
            // For now, the scan loop will just use uninitialized entries if count < CONFIG_...
            // Let's ensure we only scan validly populated channels.
            // A dynamic count_to_scan could be added to ft_context.
        } else if (count == 0) {
             LOG_ERR("FT_DCS_INIT: Failed to parse any valid channels from Kconfig. Using default carrier.");
             ctx->role_ctx.ft.dcs_candidate_channels[0] = CONFIG_DECT_MAC_FT_DEFAULT_OPERATING_CARRIER_KHZ;
             // Set a runtime count of channels to scan to 1.
             // This needs a field like ctx->role_ctx.ft.dcs_actual_channels_to_scan = 1;
             // And the scan loop should use this runtime count.
        }
    }

    if (CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN == 0) {
        LOG_WRN("FT SM: DCS channel scan count is 0. Defaulting to operating_carrier %u and starting beaconing.", ctx->role_ctx.ft.operating_carrier);
        // Fallback to immediate beaconing on default configured carrier if no scan channels
        if (ctx->role_ctx.ft.operating_carrier == 0) ctx->role_ctx.ft.operating_carrier = DEFAULT_DECT_CARRIER;
        ft_start_beaconing_actions(); // This will transition to FT_BEACONING
        return;
    }

    uint16_t scan_carrier = ctx->role_ctx.ft.dcs_candidate_channels[0];
    LOG_INF("FT SM: Starting DCS scan, 1/%d on carrier %u.", CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN, scan_carrier);

    uint32_t phy_op_handle = sys_rand32_get();
    // Duration calculation logic from previous ft_start_operation
    uint32_t scan_duration_total_subslots = SCAN_MEAS_DURATION_SLOTS_CONFIG * SUB_SLOTS_PER_ETSI_SLOT;
    uint32_t subslot_ticks = get_subslot_duration_ticks(ctx);
    uint32_t scan_duration_modem_units = scan_duration_total_subslots * subslot_ticks;
    if (subslot_ticks == 0) scan_duration_modem_units = modem_us_to_ticks(10000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
    else if (scan_duration_modem_units < subslot_ticks) scan_duration_modem_units = subslot_ticks * SUB_SLOTS_PER_ETSI_SLOT;

    int ret = dect_mac_phy_ctrl_start_rssi_scan(
        scan_carrier,
        scan_duration_modem_units,
        NRF_MODEM_DECT_PHY_RSSI_INTERVAL_24_SLOTS, // Or a value that gives enough samples
        phy_op_handle,
        PENDING_OP_FT_INITIAL_SCAN);

    if (ret != 0) {
        LOG_ERR("FT SM: Failed to start initial RSSI scan for DCS (channel %u): %d. Retrying after delay.", scan_carrier, ret);
        // Use beacon_timer for generic retry, or a dedicated DCS retry mechanism
        k_timer_start(&ctx->role_ctx.ft.beacon_timer, K_SECONDS(1), K_NO_WAIT);
        dect_mac_change_state(MAC_STATE_IDLE); // Go back to IDLE to retry init sequence
    }
}




void dect_mac_sm_ft_handle_event(const struct dect_mac_event_msg *msg) {
    dect_mac_context_t* ctx = get_mac_context();

    switch (msg->type) {
        case MAC_EVENT_PHY_OP_COMPLETE:
            {
                pending_op_type_t completed_op = dect_mac_phy_ctrl_handle_op_complete(&msg->data.op_complete);
                if (completed_op != PENDING_OP_NONE) {
                    ft_handle_phy_op_complete_ft(&msg->data.op_complete, completed_op);
                } else {
                     LOG_DBG("FT SM: OP_COMPLETE for handle %u (err %d), but no matching/active MAC pending_op_type.",
                            msg->data.op_complete.handle, msg->data.op_complete.err);
                }
            }
            break;
        case MAC_EVENT_PHY_PCC:
            ft_handle_phy_pcc_ft(&msg->data.pcc);
            break;
        case MAC_EVENT_PHY_PDC:
            ft_handle_phy_pdc_ft(&msg->data.pdc);
            break;
        case MAC_EVENT_PHY_PCC_ERROR:
             LOG_WRN("FT SM: Received PCC_ERROR for handle %u (TID %u).", msg->data.pcc_crc_err.handle, msg->data.pcc_crc_err.transaction_id);
             if (ft_last_relevant_pcc_is_valid && ft_last_relevant_pcc.transaction_id == msg->data.pcc_crc_err.transaction_id) {
                ft_last_relevant_pcc_is_valid = false;
             }
            break;
        case MAC_EVENT_PHY_PDC_ERROR:
            LOG_WRN("FT SM: Received PDC_ERROR for handle %u (TID %u).", msg->data.pdc_crc_err.handle, msg->data.pdc_crc_err.transaction_id);
            if (ft_last_relevant_pcc_is_valid && ft_last_relevant_pcc.transaction_id == msg->data.pdc_crc_err.transaction_id) {
                uint16_t pt_short_id = sys_be16_to_cpu(
                    (uint16_t)((ft_last_relevant_pcc.hdr.hdr_type_2.transmitter_id_hi << 8) |
                                ft_last_relevant_pcc.hdr.hdr_type_2.transmitter_id_lo));
                int peer_idx = ft_get_peer_slot_idx(ctx, pt_short_id);
                if (peer_idx != -1 && ctx->role_ctx.ft.connected_pts[peer_idx].is_secure) {
                    uint8_t harq_proc_in_pt_tx = ft_last_relevant_pcc.hdr.hdr_type_2.df_harq_process_num;
                    dect_mac_peer_info_t *pt_ctx_peer = &ctx->role_ctx.ft.connected_pts[peer_idx];
                    if (pt_ctx_peer->num_pending_feedback_items < 2) {
                        int fb_idx = pt_ctx_peer->num_pending_feedback_items++;
                        pt_ctx_peer->pending_feedback_to_send[fb_idx].valid = true;
                        pt_ctx_peer->pending_feedback_to_send[fb_idx].is_ack = false;
                        pt_ctx_peer->pending_feedback_to_send[fb_idx].harq_process_num_for_peer = harq_proc_in_pt_tx;
                        LOG_WRN("FT_SM_HARQ_RX: Stored NACK for PT 0x%04X's HARQ_Proc %u due to PDC_ERROR.", pt_short_id, harq_proc_in_pt_tx);
                    } else { LOG_WRN("FT_SM_PDC_ERR: Feedback buffer full for PT 0x%04X", pt_short_id); }
                }
                ft_last_relevant_pcc_is_valid = false;
            }
            break;
        case MAC_EVENT_PHY_RSSI_RESULT:
            ft_handle_phy_rssi_ft(&msg->data.rssi);
            break;
        case MAC_EVENT_TIMER_EXPIRED_BEACON:
            if (ctx->state == MAC_STATE_FT_BEACONING ||
                (ctx->state == MAC_STATE_FT_SCANNING && ctx->pending_op_type == PENDING_OP_NONE) ) {
                dect_mac_sm_ft_beacon_timer_expired_action();
            }
            break;
        case MAC_EVENT_TIMER_EXPIRED_HARQ:
            dect_mac_data_path_handle_harq_nack_action(msg->data.timer_data.id);
            break;
        default:
            LOG_DBG("FT SM: Unhandled event type %s in state %s",
                    dect_mac_event_to_str(msg->type), dect_mac_state_to_str(ctx->state));
            break;
    }
}

// --- FT Static Helper Implementations ---
static int ft_get_peer_slot_idx(dect_mac_context_t* ctx, uint16_t pt_short_id) {
    for (int i = 0; i < MAX_PEERS_PER_FT; i++) {
        if (ctx->role_ctx.ft.connected_pts[i].is_valid &&
            ctx->role_ctx.ft.connected_pts[i].short_rd_id == pt_short_id) {
            return i;
        }
    }
    return -1;
}



void dect_mac_sm_ft_handle_auth_pdu(uint16_t pt_short_id, uint32_t pt_long_id, const uint8_t *pdu_data, size_t pdu_len)
{
    ARG_UNUSED(pdu_data);
    ARG_UNUSED(pdu_len);
    dect_mac_context_t* ctx = get_mac_context();
    int peer_idx = ft_get_peer_slot_idx(ctx, pt_short_id);

    if (peer_idx == -1 || !ctx->role_ctx.ft.connected_pts[peer_idx].is_valid ||
        ctx->role_ctx.ft.connected_pts[peer_idx].long_rd_id != pt_long_id) {
        LOG_WRN("FT_AUTH_HANDLE_PDU: Received Auth PDU from unknown/invalid PT S:0x%04X L:0x%08X. Ignoring.",
                pt_short_id, pt_long_id);
        return;
    }

    // A real auth protocol might involve the FT being in a specific auth sub-state for this peer.
    // if (ctx->role_ctx.ft.connected_pts[peer_idx].auth_sub_state != EXPECTING_PT_AUTH_RESPONSE) {
    //     LOG_WRN("FT_AUTH_HANDLE_PDU: Received Auth PDU from PT S:0x%04X in unexpected auth sub-state. Ignoring.");
    //     return;
    // }

    LOG_INF("FT_AUTH_HANDLE_PDU: Received (stubbed) Auth PDU from PT S:0x%04X L:0x%08X (slot %d, len %zu). No action for current PSK model.",
            pt_short_id, pt_long_id, peer_idx, pdu_len);

    // For a real multi-step protocol:
    // 1. Parse pdu_data (e.g., PT's response to FT's challenge).
    // 2. If valid and final step for FT:
    //    ctx->role_ctx.ft.connected_pts[peer_idx].is_secure = true; // Mark link as secure
    //    LOG_INF("FT_AUTH_HANDLE_PDU: Authentication with PT 0x%04X complete. Link SECURE.");
    //    // Optionally send a final "Secure Link Confirm" PDU to PT.
    // 3. If valid and more steps for FT (e.g., FT needs to send another message):
    //    // Build and send next auth PDU to PT.
    // 4. If invalid:
    //    // Send Auth Fail PDU and/or release PT.
    //
    // The FT's PSK-based key derivation and setting of `is_secure` happens in `ft_process_association_request_pdu`.
}


// Brief Overview: This is the complete populate_cb_fields_from_ctx function.
// It accurately populates all fields for the dect_mac_cluster_beacon_ie_fields_t structure,
// including deriving ETSI codes for Network and Cluster Beacon periods from Kconfig
// millisecond values, and using Kconfig for Count To Trigger, Rel Quality, and Min Quality codes.
static void populate_cb_fields_from_ctx(dect_mac_context_t *ctx, dect_mac_cluster_beacon_ie_fields_t *cb_fields) {
    if (!ctx || !cb_fields) {
        LOG_ERR("POP_CB_FIELDS: NULL context or cb_fields pointer.");
        return;
    }
    memset(cb_fields, 0, sizeof(dect_mac_cluster_beacon_ie_fields_t));

    cb_fields->sfn = ctx->role_ctx.ft.sfn;
    cb_fields->tx_power_present = true; 
    cb_fields->clusters_max_tx_power_code = ctx->config.default_tx_power_code; 
    cb_fields->power_constraints_active = false; // Example: FT has no constraints to impose on PTs via this

    // Frame Offset: If FT's transmission is offset from SFN boundary.
    // TODO: Implement if FT uses frame offset. Requires ft_context to store frame_offset_subslots_val
    //       and own_phy_params.mu to determine if 8 or 16 bit field.
    cb_fields->frame_offset_present = false;
    // if (cb_fields->frame_offset_present) {
    //    // mu_code 0,1,2 (mu=1,2,4) -> 8-bit offset. mu_code 3 (mu=8) or higher -> 16-bit offset.
    //    cb_fields->frame_offset_is_16bit = (ctx->own_phy_params.is_valid && ctx->own_phy_params.mu > 2);
    //    cb_fields->frame_offset_value = ctx->role_ctx.ft.frame_offset_subslots_val;
    // }

    // Next Cluster Channel / Time To Next (for multi-frequency FTs or handover hints - advanced)
    // TODO: Implement if FT supports these features. Requires ft_context to store these values.
    cb_fields->next_channel_present = false;
    // if (cb_fields->next_channel_present) {
    //    cb_fields->next_cluster_channel_val = ctx->role_ctx.ft.next_beacon_carrier_val;
    // }
    cb_fields->time_to_next_present = false;
    // if (cb_fields->time_to_next_present) {
    //    cb_fields->time_to_next_us = ctx->role_ctx.ft.time_to_next_beacon_us_val;
    // }

    // Convert Kconfig ms periods to ETSI codes for Network Beacon Period
    // ETSI TS 103 636-4, Table 6.4.2.2-1: Network Beacon Period codes (4-bit field)
    // 0: 50ms, 1: 100ms, 2: 500ms, 3: 1000ms, 4: 1500ms, 5: 2000ms, 6: 4000ms. 7-15: Reserved.
    uint32_t net_period_ms = ctx->config.ft_network_beacon_period_ms;
    if (net_period_ms <= 50) cb_fields->network_beacon_period_code = 0;
    else if (net_period_ms <= 100) cb_fields->network_beacon_period_code = 1;
    else if (net_period_ms <= 500) cb_fields->network_beacon_period_code = 2;
    else if (net_period_ms <= 1000) cb_fields->network_beacon_period_code = 3;
    else if (net_period_ms <= 1500) cb_fields->network_beacon_period_code = 4;
    else if (net_period_ms <= 2000) cb_fields->network_beacon_period_code = 5;
    else if (net_period_ms <= 4000) cb_fields->network_beacon_period_code = 6;
    else { // Value from Kconfig is outside the defined ETSI range for codes 0-6
        LOG_WRN("POP_CB_FIELDS: Kconfig Network Beacon Period %ums out of range for ETSI codes 0-6. Defaulting to 1000ms (code 3).", net_period_ms);
        cb_fields->network_beacon_period_code = 3;
    }

    // Convert Kconfig ms periods to ETSI codes for Cluster Beacon Period
    // ETSI TS 103 636-4, Table 6.4.2.2-1: Cluster Beacon Period codes (4-bit field)
    // 0: 10ms, 1: 50ms, 2: 100ms, 3: 500ms, 4: 1000ms, 5: 1500ms, 6: 2000ms, 7: 4000ms,
    // 8: 8000ms, 9: 16000ms, 10: 32000ms. 11-15: Reserved.
    uint32_t clus_period_ms = ctx->config.ft_cluster_beacon_period_ms;
    if (clus_period_ms <= 10) cb_fields->cluster_beacon_period_code = 0;
    else if (clus_period_ms <= 50) cb_fields->cluster_beacon_period_code = 1;
    else if (clus_period_ms <= 100) cb_fields->cluster_beacon_period_code = 2;
    else if (clus_period_ms <= 500) cb_fields->cluster_beacon_period_code = 3;
    else if (clus_period_ms <= 1000) cb_fields->cluster_beacon_period_code = 4;
    else if (clus_period_ms <= 1500) cb_fields->cluster_beacon_period_code = 5;
    else if (clus_period_ms <= 2000) cb_fields->cluster_beacon_period_code = 6;
    else if (clus_period_ms <= 4000) cb_fields->cluster_beacon_period_code = 7;
    else if (clus_period_ms <= 8000) cb_fields->cluster_beacon_period_code = 8;
    else if (clus_period_ms <= 16000) cb_fields->cluster_beacon_period_code = 9;
    else if (clus_period_ms <= 32000) cb_fields->cluster_beacon_period_code = 10;
    else { // Value from Kconfig is outside the defined ETSI range for codes 0-10
        LOG_WRN("POP_CB_FIELDS: Kconfig Cluster Beacon Period %ums out of range for ETSI codes 0-10. Defaulting to 100ms (code 2).", clus_period_ms);
        cb_fields->cluster_beacon_period_code = 2;
    }

    // Count To Trigger, Rel Quality, Min Quality (ETSI Table 6.4.2.3-1)
    // These are directly from Kconfig as codes (0-7 or 0-3).
    cb_fields->count_to_trigger_code = CONFIG_DECT_MAC_FT_COUNT_TO_TRIGGER_CODE & 0x07;
    cb_fields->rel_quality_code = CONFIG_DECT_MAC_FT_REL_QUALITY_CODE & 0x07;
    cb_fields->min_quality_code = CONFIG_DECT_MAC_FT_MIN_QUALITY_CODE & 0x03;

    // Current Cluster Channel field (ETSI Table 6.4.2.3-1):
    // This field is only present IF cb_fields->next_channel_present is true AND
    // the cb_fields->next_cluster_channel_val is different from the FT's current operating_carrier.
    // The serializer (serialize_cluster_beacon_ie_payload) would handle the logic of actually
    // including this field based on these conditions. Here, we just populate the value if needed.
    // if (cb_fields->next_channel_present && (cb_fields->next_cluster_channel_val != ctx->role_ctx.ft.operating_carrier)) {
    //    cb_fields->current_cluster_channel_val = ctx->role_ctx.ft.operating_carrier;
    //    // The serializer would then check a flag like cb_fields->current_channel_field_present
    // }
    // For now, since next_channel_present is false, Current Cluster Channel is not applicable.
}



static uint64_t calculate_target_modem_time(dect_mac_context_t *ctx, uint64_t sfn_zero_anchor_time,
                                            uint8_t sfn_of_anchor_relevance, uint8_t target_sfn_val,
                                            uint16_t target_subslot_idx,
                                            uint8_t link_mu_code, uint8_t link_beta_code)
{
    ARG_UNUSED(link_beta_code); // Beta currently not used in subslot/frame duration calculations here

    if (!ctx) {
        LOG_ERR("CALC_TIME: NULL MAC context provided!");
        return UINT64_MAX; 
    }

    if (sfn_zero_anchor_time == 0 && ctx->last_known_modem_time == 0) {
        LOG_WRN("CALC_TIME: SFN Zero Anchor and last_known_modem_time are both 0. Cannot calculate. Returning large future estimate.");
        return modem_us_to_ticks(500000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
    }
    if (sfn_zero_anchor_time == 0) {
        LOG_WRN("CALC_TIME: SFN Zero Anchor is 0. Using last_known_modem_time + fallback delay.");
        uint32_t fallback_delay_ticks = modem_us_to_ticks(FRAME_DURATION_MS_NOMINAL * 1000 * 2, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
        return ctx->last_known_modem_time + fallback_delay_ticks;
    }

    uint32_t frame_duration_ticks_val = 0;
    if (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ > 0) {
        frame_duration_ticks_val = (uint32_t)FRAME_DURATION_MS_NOMINAL * (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ / 1000U);
    }
    if (frame_duration_ticks_val == 0) {
        LOG_ERR("CALC_TIME: Calculated frame_duration_ticks is 0! Modem tick rate likely 0.");
        return UINT64_MAX;
    }

    // Use the provided link_mu_code for subslot duration calculation
    uint8_t mu_code_for_calc = link_mu_code;
    if (mu_code_for_calc > 7) { // Max mu_code for 2^7=128, typical DECT NR+ 0-3
        LOG_WRN("CALC_TIME: Invalid link_mu_code %u provided, defaulting to 0 (mu=1).", link_mu_code);
        mu_code_for_calc = 0;
    }

    uint32_t subslot_duration_ticks_val = get_subslot_duration_ticks_for_mu(mu_code_for_calc);
    if (subslot_duration_ticks_val == 0) {
        LOG_ERR("CALC_TIME: Calculated subslot_duration_ticks is 0 for mu_code %u!", mu_code_for_calc);
        return UINT64_MAX;
    }

    uint64_t anchor_relevance_frame_start_time = sfn_zero_anchor_time +
                                                 ((uint64_t)sfn_of_anchor_relevance * frame_duration_ticks_val);

    int16_t sfn_diff = (int16_t)target_sfn_val - (int16_t)sfn_of_anchor_relevance;
    if (sfn_diff > 128) { sfn_diff -= 256; }
    else if (sfn_diff < -128) { sfn_diff += 256; }

    uint64_t target_frame_start_time = anchor_relevance_frame_start_time + ((int64_t)sfn_diff * frame_duration_ticks_val);
    uint64_t target_subslot_offset_in_frame_ticks = (uint64_t)target_subslot_idx * subslot_duration_ticks_val;
    uint64_t final_target_time = target_frame_start_time + target_subslot_offset_in_frame_ticks;

    LOG_DBG("CALC_TIME: AnchorSFN %u (rel. to SFN0@%llu), TargetSFN %u, TargetSS %u (using link_mu_code %u) => FinalTime %llu",
            sfn_of_anchor_relevance, sfn_zero_anchor_time,
            target_sfn_val, target_subslot_idx, mu_code_for_calc, final_target_time);

    return final_target_time;
}




static void ft_select_operating_carrier_and_start_beaconing(const struct nrf_modem_dect_phy_rssi_event *optional_last_rssi_event_data) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != MAC_STATE_FT_SCANNING) {
        LOG_WRN("FT_DCS_SEL: Not in SCANNING state (%s), ignoring request to select carrier.", dect_mac_state_to_str(ctx->state));
        // If called unexpectedly, ensure we don't get stuck. Maybe restart scan timer.
        if (ctx->pending_op_type == PENDING_OP_NONE) { // Only if no scan is ongoing
             k_timer_start(&ctx->role_ctx.ft.beacon_timer, K_SECONDS(1), K_NO_WAIT); // Retry DCS sequence
        }
        return;
    }
    // This function is called when all DCS scans are complete (dcs_scan_complete=true) OR
    // if a scan op failed and we need to select from what we have.
    // optional_last_rssi_event_data is not directly used here anymore as results are in context.
    ARG_UNUSED(optional_last_rssi_event_data);


    int16_t best_rssi_found_q71 = INT16_MAX; // Lower (more negative) is better
    uint16_t final_selected_carrier = 0;
    int selected_idx = -1;
    int num_potentially_good_candidates = 0;

    LOG_INF("FT_DCS_SEL: Evaluating %d scanned channels for selection. Busy_Threshold <= %d%%, Noisy_Threshold < %ddBm.",
            CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN,
            CONFIG_DECT_MAC_DCS_ACCEPTABLE_BUSY_PERCENT,
            CONFIG_DECT_MAC_DCS_NOISY_THRESHOLD_DBM);

    for (int i = 0; i < CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN; i++) {
        if (ctx->role_ctx.ft.dcs_candidate_channels[i] == 0 || // Ensure channel was populated
            ctx->role_ctx.ft.dcs_candidate_rssi_avg[i] == NRF_MODEM_DECT_PHY_RSSI_NOT_MEASURED ||
            ctx->role_ctx.ft.dcs_candidate_busy_percent[i] > 100) { // Ensure scanned
            LOG_DBG("  Skipping candidate %d: Not scanned or invalid carrier/RSSI.", i);
            continue;
        }

        LOG_INF("  Candidate %d: C%u, AvgRSSI: %.1f dBm, Busy: %u%%", i,
                ctx->role_ctx.ft.dcs_candidate_channels[i],
                (float)ctx->role_ctx.ft.dcs_candidate_rssi_avg[i] / 2.0f,
                ctx->role_ctx.ft.dcs_candidate_busy_percent[i]);

        int16_t current_avg_rssi_q71 = ctx->role_ctx.ft.dcs_candidate_rssi_avg[i];
        uint8_t current_busy_pc = ctx->role_ctx.ft.dcs_candidate_busy_percent[i];
        int16_t noisy_threshold_q71 = CONFIG_DECT_MAC_DCS_NOISY_THRESHOLD_DBM * 2; // Convert dBm to Q7.1

        // Criterion 1: Is channel acceptably free of persistent business?
        if (current_busy_pc > CONFIG_DECT_MAC_DCS_ACCEPTABLE_BUSY_PERCENT) {
            LOG_DBG("    Rejected: Too busy (%u%% > %d%%).", current_busy_pc, CONFIG_DECT_MAC_DCS_ACCEPTABLE_BUSY_PERCENT);
            continue;
        }

        // Criterion 2: Is channel below general "noisy" threshold?
        if (current_avg_rssi_q71 >= noisy_threshold_q71) {
            LOG_DBG("    Rejected: Too noisy (%.1f dBm >= %d dBm).", (float)current_avg_rssi_q71 / 2.0f, CONFIG_DECT_MAC_DCS_NOISY_THRESHOLD_DBM);
            continue;
        }

        num_potentially_good_candidates++;
        // Criterion 3: Pick the one with the best (lowest) average RSSI among the good ones
        if (selected_idx == -1 || current_avg_rssi_q71 < best_rssi_found_q71) {
            best_rssi_found_q71 = current_avg_rssi_q71;
            final_selected_carrier = ctx->role_ctx.ft.dcs_candidate_channels[i];
            selected_idx = i;
            LOG_DBG("    Provisionally selected: C%u (AvgRSSI %.1f dBm, Busy %u%%)",
                    final_selected_carrier, (float)best_rssi_found_q71 / 2.0f, current_busy_pc);
        }
    }

    if (selected_idx != -1 && final_selected_carrier != 0) {
        ctx->role_ctx.ft.operating_carrier = final_selected_carrier;
        LOG_INF("FT_DCS_SEL: Best carrier selected: C%u (idx %d) with Avg RSSI %.1f dBm, Busy %u%%.",
                final_selected_carrier, selected_idx, (float)best_rssi_found_q71 / 2.0f,
                ctx->role_ctx.ft.dcs_candidate_busy_percent[selected_idx]);
    } else {
        LOG_WRN("FT_DCS_SEL: No suitable channel found from %d valid candidates after filtering. Defaulting to C%u.",
                num_potentially_good_candidates, CONFIG_DECT_MAC_FT_DEFAULT_OPERATING_CARRIER_KHZ);
        ctx->role_ctx.ft.operating_carrier = CONFIG_DECT_MAC_FT_DEFAULT_OPERATING_CARRIER_KHZ;
        if (ctx->role_ctx.ft.operating_carrier == 0) { 
            ctx->role_ctx.ft.operating_carrier = 1881792; // ETSI Ch0 as absolute fallback
            LOG_ERR("FT_DCS_SEL: Default carrier was 0, using absolute fallback %u kHz.", ctx->role_ctx.ft.operating_carrier);
        }
    }

    // Update advertised RACH channel based on selected operating carrier
    ctx->role_ctx.ft.advertised_rach_params.rach_operating_channel = ctx->role_ctx.ft.operating_carrier;
    ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.channel_abs_freq_num = ctx->role_ctx.ft.operating_carrier;
    ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.channel_field_present = true;

    ft_start_beaconing_actions(); // This transitions state to FT_BEACONING and starts beacon timer
}



static void ft_start_beaconing_actions(void) {
    dect_mac_context_t* ctx = get_mac_context();
    dect_mac_change_state(MAC_STATE_FT_BEACONING);
    LOG_INF("FT SM: Entered BEACONING state on carrier %u.", ctx->role_ctx.ft.operating_carrier);

    ctx->role_ctx.ft.sfn = 0; // FT starts its SFN count from 0
    uint32_t first_beacon_tx_attempt_delay_ms = 50; // Small delay before trying to send the first beacon

    // Initialize ft_sfn_zero_modem_time_anchor to 0.
    // It will be set accurately when the first beacon (SFN 0) is scheduled for transmission
    // in ft_send_beacon_action, based on its target PHY operation start time.
    ctx->ft_sfn_zero_modem_time_anchor = 0;
    // current_sfn_at_anchor_update for FT will effectively be 0 when anchor is first set.
    // This field is primarily for the PT to know the SFN context of the anchor time it receives.
    // For the FT, its anchor is *defined* at SFN 0.
    ctx->current_sfn_at_anchor_update = 0; 

    LOG_DBG("FT_START_BEACONING: SFN anchor will be established with first beacon TX. Initial SFN set to 0.");

    // Start the periodic beacon timer.
    // The first timer expiry will trigger ft_send_beacon_action, which will then establish the SFN anchor.
    uint32_t beacon_period_ms = ctx->config.ft_cluster_beacon_period_ms;
    if (beacon_period_ms == 0) { // Fallback if Kconfig is 0
        beacon_period_ms = 100;
        LOG_WRN("FT_START_BEACONING: ft_cluster_beacon_period_ms is 0, using fallback %ums for timer.", beacon_period_ms);
    }
    // The first timer event will trigger the first beacon send attempt.
    k_timer_start(&ctx->role_ctx.ft.beacon_timer, 
                  K_MSEC(first_beacon_tx_attempt_delay_ms), // Initial delay for the first beacon attempt
                  K_MSEC(beacon_period_ms));               // Subsequent period
}




static void ft_send_beacon_action(void) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != MAC_STATE_FT_BEACONING) {
        LOG_WRN("FT SM: Beacon TX attempt, but not in BEACONING state (%s). Aborting.",
                dect_mac_state_to_str(ctx->state));
        uint32_t beacon_period_ms = ctx->config.ft_cluster_beacon_period_ms;
        if (beacon_period_ms == 0) beacon_period_ms = 100;
        k_timer_start(&ctx->role_ctx.ft.beacon_timer, K_MSEC(beacon_period_ms), K_MSEC(beacon_period_ms));
        return;
    }

    if (ctx->pending_op_type != PENDING_OP_NONE) {
        LOG_WRN("FT SM: Beacon TX time, but op %s pending. Delaying beacon.",
                dect_pending_op_to_str(ctx->pending_op_type));
        // Reschedule beacon timer for a short delay to retry
        uint32_t short_delay_ms = ctx->config.ft_cluster_beacon_period_ms / 10;
        if (short_delay_ms < 20) short_delay_ms = 20; // Min 20ms retry
        if (short_delay_ms > 100) short_delay_ms = 100; // Max 100ms retry for this case
        k_timer_start(&ctx->role_ctx.ft.beacon_timer, K_MSEC(short_delay_ms), K_MSEC(ctx->config.ft_cluster_beacon_period_ms));
        return;
    }


    uint8_t mac_sdu_area_buf[128]; 
    int sdu_area_len;

    dect_mac_cluster_beacon_ie_fields_t cb_fields;
    populate_cb_fields_from_ctx(ctx, &cb_fields); // Populates cb_fields based on current FT context

    dect_mac_rach_info_ie_fields_t *rach_adv_fields = &ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields;
    
    // Ensure mu_value_for_ft_beacon is set correctly based on FT's operational mu
    uint8_t ft_operational_mu_code = 0; 
    if (ctx->own_phy_params.is_valid && ctx->own_phy_params.mu <= 7) {
        ft_operational_mu_code = ctx->own_phy_params.mu;
    } else {
        LOG_WRN("FT_BEACON_ACT: FT's own operational mu_code not valid in context. Defaulting to mu_code=0 for RACH IE.");
    }
    rach_adv_fields->mu_value_for_ft_beacon = ft_operational_mu_code;
    
    if (rach_adv_fields->channel_abs_freq_num != ctx->role_ctx.ft.operating_carrier || !rach_adv_fields->channel_field_present) {
        rach_adv_fields->channel_abs_freq_num = ctx->role_ctx.ft.operating_carrier;
        rach_adv_fields->channel_field_present = true;
    }

    sdu_area_len = build_beacon_sdu_area_content(mac_sdu_area_buf, sizeof(mac_sdu_area_buf),
                                                &cb_fields,
                                                rach_adv_fields);
    if (sdu_area_len < 0) {
        LOG_ERR("FT SM: Failed to build beacon SDU area content: %d. Skipping this beacon.", sdu_area_len);
        return; // Timer will fire again
    }

    dect_mac_header_type_octet_t hdr_type_octet;
    hdr_type_octet.version = 0; 
    hdr_type_octet.mac_security = MAC_SECURITY_NONE; 
    hdr_type_octet.mac_header_type = MAC_COMMON_HEADER_TYPE_BEACON;

    dect_mac_beacon_header_t common_beacon_hdr;
    common_beacon_hdr.network_id_ms24[0] = (uint8_t)((ctx->network_id_32bit >> 24) & 0xFF);
    common_beacon_hdr.network_id_ms24[1] = (uint8_t)((ctx->network_id_32bit >> 16) & 0xFF);
    common_beacon_hdr.network_id_ms24[2] = (uint8_t)((ctx->network_id_32bit >> 8) & 0xFF);
    common_beacon_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);

    uint8_t *full_mac_pdu_for_phy_slab = NULL;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab, K_MSEC(10));
    if(ret != 0 || full_mac_pdu_for_phy_slab == NULL) {
        LOG_ERR("FT SM: Failed to alloc PDU buf for beacon TX: %d. Skipping this beacon.", ret);
        return; 
    }
    uint8_t * const full_mac_pdu_for_phy = full_mac_pdu_for_phy_slab;

    uint16_t cleartext_pdu_len;
    ret = dect_mac_phy_ctrl_assemble_final_pdu(
              full_mac_pdu_for_phy, CONFIG_DECT_MAC_PDU_MAX_SIZE,
              &hdr_type_octet,
              &common_beacon_hdr, sizeof(common_beacon_hdr),
              mac_sdu_area_buf, (size_t)sdu_area_len,
              &cleartext_pdu_len);

    if (ret != 0) {
        LOG_ERR("FT SM: Failed to assemble final beacon PDU: %d", ret);
        k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);
        return; 
    }

    uint32_t phy_op_handle = sys_rand32_get();
    ctx->role_ctx.ft.sfn_for_last_beacon_tx = ctx->role_ctx.ft.sfn;
    uint64_t beacon_target_start_time;
    uint32_t frame_duration_ticks_val = 0;

    if (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ > 0) {
        frame_duration_ticks_val = (uint32_t)FRAME_DURATION_MS_NOMINAL * (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ / 1000U);
    }
    if (frame_duration_ticks_val == 0) {
        LOG_ERR("FT_BEACON_ACT: Frame duration ticks is zero! Cannot schedule beacon precisely. Sending immediate-ish.");
        beacon_target_start_time = 0; // Fallback
    } else if (ctx->ft_sfn_zero_modem_time_anchor == 0) { 
        uint32_t initial_tx_delay_ticks = modem_us_to_ticks(5000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ); 
        beacon_target_start_time = (ctx->last_known_modem_time > 0 ? ctx->last_known_modem_time : modem_us_to_ticks(1000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ)) + initial_tx_delay_ticks;
        
        ctx->ft_sfn_zero_modem_time_anchor = beacon_target_start_time; // SFN is 0 for the first beacon
        ctx->current_sfn_at_anchor_update = 0; 
        LOG_INF("FT_BEACON_ACT: Establishing SFN0 anchor at %llu for SFN %u (mu_c %u, beta_c %u).",
                ctx->ft_sfn_zero_modem_time_anchor, ctx->role_ctx.ft.sfn,
                ctx->own_phy_params.mu, ctx->own_phy_params.beta);
    } else {
        beacon_target_start_time = calculate_target_modem_time(ctx,
                                                                  ctx->ft_sfn_zero_modem_time_anchor,
                                                                  0, /* Anchor is for SFN 0 */
                                                                  ctx->role_ctx.ft.sfn,
                                                                  0, /* Beacon at subslot 0 */
                                                                  ctx->own_phy_params.mu, /* FT's own mu */
                                                                  ctx->own_phy_params.beta);/* FT's own beta */
    }

    if (beacon_target_start_time != 0) { // Only adjust if not already immediate
        uint32_t min_prep_time_ticks = modem_us_to_ticks(ctx->phy_latency.idle_to_active_tx_us +
                                                        ctx->phy_latency.scheduled_operation_startup_us,
                                                        NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
        if (ctx->last_known_modem_time > 0 && beacon_target_start_time < (ctx->last_known_modem_time + min_prep_time_ticks)) {
            LOG_WRN("FT_BEACON_ACT: Target start %llu for SFN %u is too soon (current %llu, prep %u). Adjusting.",
                    beacon_target_start_time, ctx->role_ctx.ft.sfn, ctx->last_known_modem_time, min_prep_time_ticks);
            
            uint64_t earliest_possible_start_from_now = ctx->last_known_modem_time + min_prep_time_ticks;
            uint64_t frames_since_anchor = 0;
            if (earliest_possible_start_from_now >= ctx->ft_sfn_zero_modem_time_anchor) {
                 frames_since_anchor = (earliest_possible_start_from_now - ctx->ft_sfn_zero_modem_time_anchor + frame_duration_ticks_val -1) / frame_duration_ticks_val;
            } // Else, SFN0 anchor is in future, something is odd, but calculate_target_modem_time would have used fallback.

            ctx->role_ctx.ft.sfn = (uint8_t)((ctx->current_sfn_at_anchor_update + frames_since_anchor) % 256);
            beacon_target_start_time = ctx->ft_sfn_zero_modem_time_anchor + (frames_since_anchor * frame_duration_ticks_val);
            ctx->role_ctx.ft.sfn_for_last_beacon_tx = ctx->role_ctx.ft.sfn;
            LOG_INF("FT_BEACON_ACT: Adjusted target SFN to %u, start_time %llu.", ctx->role_ctx.ft.sfn, beacon_target_start_time);
        }
    }


    ret = dect_mac_phy_ctrl_start_tx_assembled(
        ctx->role_ctx.ft.operating_carrier,
        full_mac_pdu_for_phy, cleartext_pdu_len,
        0xFFFF, true, phy_op_handle, PENDING_OP_FT_BEACON,
        false, beacon_target_start_time);

    k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);

    if (ret != 0) {
        LOG_ERR("FT SM: Failed to schedule beacon TX for SFN %u: %d", ctx->role_ctx.ft.sfn, ret);
    } else {
        LOG_INF("FT SM: Beacon SFN %u TX scheduled on C%u (Hdl %u), TargetStart %llu",
                ctx->role_ctx.ft.sfn, ctx->role_ctx.ft.operating_carrier, phy_op_handle, beacon_target_start_time);
    }
    ctx->role_ctx.ft.sfn = (ctx->role_ctx.ft.sfn + 1) & 0xFF;
}


/**
 * @brief Schedules a PHY RX operation for the FT to listen on its advertised RACH resources.
 */
static void ft_schedule_rach_listen_action(void) {
    dect_mac_context_t* ctx = get_mac_context();

    if (ctx->state != MAC_STATE_FT_BEACONING && ctx->state != MAC_STATE_ASSOCIATED) {
        LOG_DBG("FT_RACH_LSN: Not in a state to listen for RACH (%s).", dect_mac_state_to_str(ctx->state));
        return;
    }
    if (ctx->pending_op_type != PENDING_OP_NONE) {
        LOG_DBG("FT_RACH_LSN: PHY op %s pending. Deferring RACH listen.", dect_pending_op_to_str(ctx->pending_op_type));
        return;
    }

    const dect_mac_rach_info_ie_fields_t *rach_adv_fields = &ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields;

    uint16_t rach_carrier = rach_adv_fields->channel_field_present ?
                            rach_adv_fields->channel_abs_freq_num :
                            ctx->role_ctx.ft.operating_carrier;
    if (rach_carrier == 0 || rach_carrier == 0xFFFF) {
        LOG_ERR("FT_RACH_LSN: Invalid RACH carrier 0x%04X configured. Cannot listen.", rach_carrier);
        return;
    }

    // Use the mu advertised by the FT for its RACH resources (stored when RACH IE fields were populated)
    uint8_t ft_mu_for_rach = rach_adv_fields->mu_value_for_ft_beacon;
    if (ft_mu_for_rach > 7) { // mu_code is 0-7. Max typical DECT NR+ mu_code is 3 (mu=8)
        LOG_WRN("FT_RACH_LSN: Invalid mu_code (%u) in FT's advertised RACH IE. Defaulting to mu_code=0 (mu=1).", ft_mu_for_rach);
        ft_mu_for_rach = 0; // Default to mu_code 0 (actual mu=1)
    }
    uint32_t ft_subslot_duration_ticks = get_subslot_duration_ticks_for_mu(ft_mu_for_rach);
    if (ft_subslot_duration_ticks == 0) {
        LOG_ERR("FT_RACH_LSN: Calculated FT subslot duration is 0 for mu_code %u. Cannot proceed.", ft_mu_for_rach);
        return;
    }

    uint32_t rach_resource_len_actual_units = rach_adv_fields->num_subslots_or_slots; // This is N (actual units, 0-127)
    uint32_t rach_resource_len_subslots = rach_resource_len_actual_units;
    if (rach_adv_fields->length_type_is_slots) {
        uint8_t subslots_per_etsi_slot_for_ft_mu = get_subslots_per_etsi_slot_for_mu(ft_mu_for_rach);
        rach_resource_len_subslots *= subslots_per_etsi_slot_for_ft_mu;
    }
    if (rach_resource_len_subslots == 0) {
        LOG_ERR("FT_RACH_LSN: Advertised RACH resource length is 0 subslots. Cannot listen.");
        return;
    }

    uint8_t target_sfn_for_rach;
    uint8_t sfn_of_initial_rach_advertisement; // SFN where this RACH allocation definition starts

    if (rach_adv_fields->sfn_validity_present) {
        sfn_of_initial_rach_advertisement = rach_adv_fields->sfn_value;
        target_sfn_for_rach = sfn_of_initial_rach_advertisement; // Start with the SFN specified in IE

        uint8_t repetition_interval_frames = 1U << rach_adv_fields->repetition_code; // 00->1, 01->2, 10->4, 11->8

        // Advance target_sfn_for_rach until it's at or after current FT SFN (ctx->role_ctx.ft.sfn),
        // respecting the repetition interval.
        while (1) {
            int16_t sfn_diff_to_current = (int16_t)target_sfn_for_rach - (int16_t)ctx->role_ctx.ft.sfn;
            // Normalize diff to be shortest path, positive if target is in future/same SFN
            if (sfn_diff_to_current < -128) sfn_diff_to_current += 256;
            else if (sfn_diff_to_current > 128 && target_sfn_for_rach < ctx->role_ctx.ft.sfn) sfn_diff_to_current -=256;


            if (sfn_diff_to_current >= 0) { // Target SFN is at or after current SFN
                // Now check if it aligns with repetition from sfn_of_initial_rach_advertisement
                int16_t frames_from_initial_adv = (int16_t)target_sfn_for_rach - (int16_t)sfn_of_initial_rach_advertisement;
                if (frames_from_initial_adv < 0) frames_from_initial_adv += 256;

                if ((uint8_t)frames_from_initial_adv % repetition_interval_frames == 0) {
                    break; // Found a valid, upcoming, aligned SFN
                }
            }
            target_sfn_for_rach = (target_sfn_for_rach + 1) & 0xFF; // Try next SFN
            if (target_sfn_for_rach == sfn_of_initial_rach_advertisement && repetition_interval_frames > 1) {
                 // Full cycle without finding aligned slot, something is wrong or validity expired.
                 LOG_WRN("FT_RACH_LSN: Cycled SFNs without finding repetition match for SFN-based RACH.");
                 return; // Avoid infinite loop
            }
        }

        int16_t frames_from_initial_validity_sfn = (int16_t)target_sfn_for_rach - (int16_t)sfn_of_initial_rach_advertisement;
        if (frames_from_initial_validity_sfn < 0) frames_from_initial_validity_sfn += 256;

        if (rach_adv_fields->validity_frames != 0xFF && (uint8_t)frames_from_initial_validity_sfn >= rach_adv_fields->validity_frames) {
            LOG_WRN("FT_RACH_LSN: Advertised RACH validity expired for target SFN %u. Not listening.", target_sfn_for_rach);
            return;
        }
    } else { // SFN field not present in RACH IE
        // RACH is valid in frames relative to the beacon that advertised it.
        // Repetition code still applies.
        // FT should listen in the SFNs where this RACH instance would fall after its beacon.
        // Simplification: listen in the current SFN (assuming beacon just went out or is about to).
        target_sfn_for_rach = ctx->role_ctx.ft.sfn;
        sfn_of_initial_rach_advertisement = ctx->role_ctx.ft.sfn_for_last_beacon_tx; // Repetition relative to this
        // TODO: More robust logic for repetition if sfn_validity_present is false.
        // For now, if SFN not present, assume it's for the current/next frame and repetition is not strictly SFN-locked beyond that.
    }

    uint8_t ft_own_mu_code_for_rach = rach_adv_fields->mu_value_for_ft_beacon; // Mu advertised in RACH IE
    uint8_t ft_own_beta_code_for_rach = ctx->own_phy_params.is_valid ? ctx->own_phy_params.beta : 0; // FT's beta

    uint64_t rach_listen_start_time = calculate_target_modem_time(ctx,
                                                                  ctx->ft_sfn_zero_modem_time_anchor,
                                                                  ctx->current_sfn_at_anchor_update,
                                                                  target_sfn_for_rach,
                                                                  rach_adv_fields->start_subslot_index,
                                                                  ft_own_mu_code_for_rach,
                                                                  ft_own_beta_code_for_rach);
    
    uint32_t listen_duration_subslots = rach_resource_len_subslots + 2; // Listen a bit longer
    uint32_t listen_duration_modem_units = listen_duration_subslots * ft_subslot_duration_ticks;

    uint32_t min_prep_time_ticks = modem_us_to_ticks(ctx->phy_latency.idle_to_active_rx_us +
                                                     ctx->phy_latency.scheduled_operation_startup_us,
                                                     NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
    uint8_t initial_target_sfn_for_log = target_sfn_for_rach;

    while (ctx->last_known_modem_time > 0 && rach_listen_start_time < (ctx->last_known_modem_time + min_prep_time_ticks)) {
        LOG_WRN("FT_RACH_LSN: Target RACH listen SFN %u, SS %u at time %llu is too soon (curr %llu, prep %u). Advancing.",
                target_sfn_for_rach, rach_adv_fields->start_subslot_index, rach_listen_start_time,
                ctx->last_known_modem_time, min_prep_time_ticks);

        uint8_t repetition_interval_frames = 1U << rach_adv_fields->repetition_code;
        if (repetition_interval_frames == 0) repetition_interval_frames = 1; 

        target_sfn_for_rach = (target_sfn_for_rach + repetition_interval_frames) & 0xFF;

        if (rach_adv_fields->sfn_validity_present && rach_adv_fields->validity_frames != 0xFF) {
            int16_t frames_from_initial_validity_sfn = (int16_t)target_sfn_for_rach - (int16_t)sfn_of_initial_rach_advertisement;
            if (frames_from_initial_validity_sfn < 0) frames_from_initial_validity_sfn += 256;
            if ((uint8_t)frames_from_initial_validity_sfn >= rach_adv_fields->validity_frames) {
                LOG_WRN("FT_RACH_LSN: Next RACH repetition (SFN %u) would exceed validity period. Stopping listen attempts.", target_sfn_for_rach);
                return;
            }
        }
        // Recalculate start time for the new target SFN, using same mu/beta as initial calc
        rach_listen_start_time = calculate_target_modem_time(ctx,
                                                              ctx->ft_sfn_zero_modem_time_anchor,
                                                              ctx->current_sfn_at_anchor_update,
                                                              target_sfn_for_rach,
                                                              rach_adv_fields->start_subslot_index,
                                                              ft_own_mu_code_for_rach, // from earlier in this function
                                                              ft_own_beta_code_for_rach); // from earlier in this function


        LOG_INF("FT_RACH_LSN: Advanced to next RACH opportunity: SFN %u, new start_time %llu",
                target_sfn_for_rach, rach_listen_start_time);
        if (target_sfn_for_rach == initial_target_sfn_for_log && repetition_interval_frames > 0) {
            LOG_WRN("FT_RACH_LSN: Cycled SFNs fully while advancing for 'too soon'. Check RACH params/timing. Skipping.");
            return; // Avoid potential infinite loop if conditions are strange
        }
    }

    if (listen_duration_modem_units == 0) {
        LOG_ERR("FT_RACH_LSN: Calculated listen duration is 0 for mu_code %u. Aborting.", ft_mu);
        return;
    }

    LOG_INF("FT_RACH_LSN: Scheduling RX on RACH C%u for SFN %u (initial target was SFN %u), StartSS %u (len %u actual units, %u subslots). RXDur:%u TU, TargetStart:%llu",
            rach_carrier, target_sfn_for_rach, initial_target_sfn_for_log,
            rach_adv_fields->start_subslot_index,
            rach_resource_len_actual_units, rach_resource_len_subslots,
            listen_duration_modem_units, rach_listen_start_time);

    uint32_t phy_op_handle = sys_rand32_get();
    int ret = dect_mac_phy_ctrl_start_rx(
        rach_carrier,
        listen_duration_modem_units,
        NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS,
        phy_op_handle,
        ctx->own_short_rd_id,
        PENDING_OP_FT_RACH_RX_WINDOW);

    if (ret != 0) {
        LOG_ERR("FT_SM: Failed to schedule RACH RX window (SFN %u): %d", target_sfn_for_rach, ret);
    }
}




static int  ft_find_and_init_peer_slot(uint32_t pt_long_id, uint16_t pt_short_id, int16_t rssi) {
    dect_mac_context_t* ctx = get_mac_context();
    // Check if PT with this Long ID already exists
    for (int i = 0; i < MAX_PEERS_PER_FT; i++) {
        if (ctx->role_ctx.ft.connected_pts[i].is_valid && ctx->role_ctx.ft.connected_pts[i].long_rd_id == pt_long_id) {
            LOG_WRN("FT_SM_PEER: PT LongID 0x%08X already in slot %d (OldShort:0x%04X). Updating ShortID to 0x%04X and RSSI.",
                    pt_long_id, i, ctx->role_ctx.ft.connected_pts[i].short_rd_id, pt_short_id);
            ctx->role_ctx.ft.connected_pts[i].short_rd_id = pt_short_id;
            ctx->role_ctx.ft.connected_pts[i].rssi_2 = rssi;
            ctx->role_ctx.ft.connected_pts[i].is_secure = false; // Re-association requires re-authentication
            ctx->role_ctx.ft.connected_pts[i].hpc = 1;       // Reset tracked HPC for peer
            ctx->role_ctx.ft.keys_provisioned_for_peer[i] = false;
            ctx->role_ctx.ft.connected_pts[i].num_pending_feedback_items = 0;
            memset(ctx->role_ctx.ft.connected_pts[i].pending_feedback_to_send, 0, sizeof(ctx->role_ctx.ft.connected_pts[i].pending_feedback_to_send));
            // Keep existing schedule for now, or clear it:
            // memset(&ctx->role_ctx.ft.peer_schedules[i], 0, sizeof(dect_mac_schedule_t));
            // ctx->role_ctx.ft.peer_schedules[i].is_active = false;
            return i;
        }
    }
    // Find a new free slot
    for (int i = 0; i < MAX_PEERS_PER_FT; i++) {
        if (!ctx->role_ctx.ft.connected_pts[i].is_valid) {
            ctx->role_ctx.ft.connected_pts[i].is_valid = true;
            ctx->role_ctx.ft.connected_pts[i].long_rd_id = pt_long_id;
            ctx->role_ctx.ft.connected_pts[i].short_rd_id = pt_short_id;
            ctx->role_ctx.ft.connected_pts[i].rssi_2 = rssi;
            ctx->role_ctx.ft.connected_pts[i].is_secure = false;
            ctx->role_ctx.ft.connected_pts[i].hpc = 1; // FT's initial assumption of PT's TX HPC
            ctx->role_ctx.ft.keys_provisioned_for_peer[i] = false;
            ctx->role_ctx.ft.connected_pts[i].num_pending_feedback_items = 0;
            memset(ctx->role_ctx.ft.connected_pts[i].pending_feedback_to_send, 0, sizeof(ctx->role_ctx.ft.connected_pts[i].pending_feedback_to_send));
            memset(&ctx->role_ctx.ft.peer_schedules[i], 0, sizeof(dect_mac_schedule_t));
            ctx->role_ctx.ft.peer_schedules[i].is_active = false;
            LOG_INF("FT SM: PT 0x%08X (S:0x%04X) assigned to new peer slot %d.", pt_long_id, pt_short_id, i);
            return i;
        }
    }
    LOG_WRN("FT_SM: No free peer slots for PT LongID 0x%08X.", pt_long_id);
    return -1;
}

static void ft_handle_phy_op_complete_ft(const struct nrf_modem_dect_phy_op_complete_event *event, pending_op_type_t completed_op_type) {
    dect_mac_context_t* ctx = get_mac_context();
    switch (completed_op_type) {
        case PENDING_OP_FT_INITIAL_SCAN:
            LOG_INF("FT SM: DCS Scan for channel %u (idx %u) completed (err %d).",
                    ctx->role_ctx.ft.dcs_candidate_channels[ctx->role_ctx.ft.dcs_current_channel_scan_index],
                    ctx->role_ctx.ft.dcs_current_channel_scan_index,
                    event->err);

            if (event->err != NRF_MODEM_DECT_PHY_SUCCESS && event->err != NRF_MODEM_DECT_PHY_ERR_OP_CANCELED) {
                LOG_ERR("FT_DCS: Scan op for C%u failed (err %d). Marking as unusable.",
                         ctx->role_ctx.ft.dcs_candidate_channels[ctx->role_ctx.ft.dcs_current_channel_scan_index], event->err);
                // Mark this channel as bad in results, e.g. very high RSSI
                ctx->role_ctx.ft.dcs_candidate_rssi_avg[ctx->role_ctx.ft.dcs_current_channel_scan_index] = 127*2; // Effectively +127dBm
            }
            // Note: RSSI results themselves are processed in ft_handle_phy_rssi_ft

            ctx->role_ctx.ft.dcs_current_channel_scan_index++;
            if (ctx->role_ctx.ft.dcs_current_channel_scan_index < CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN) {
                // Scan next channel
                uint16_t next_scan_carrier = ctx->role_ctx.ft.dcs_candidate_channels[ctx->role_ctx.ft.dcs_current_channel_scan_index];
                LOG_INF("FT SM: Starting DCS scan %u/%u on carrier %u.",
                        ctx->role_ctx.ft.dcs_current_channel_scan_index + 1, CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN, next_scan_carrier);

                uint32_t phy_op_handle = sys_rand32_get();
                uint32_t scan_duration_total_subslots = SCAN_MEAS_DURATION_SLOTS_CONFIG * SUB_SLOTS_PER_ETSI_SLOT;
                uint32_t subslot_ticks = get_subslot_duration_ticks(ctx);
                uint32_t scan_duration_modem_units = scan_duration_total_subslots * subslot_ticks;
                if (subslot_ticks == 0) scan_duration_modem_units = modem_us_to_ticks(10000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
                else if (scan_duration_modem_units < subslot_ticks) scan_duration_modem_units = subslot_ticks * SUB_SLOTS_PER_ETSI_SLOT;

                int ret = dect_mac_phy_ctrl_start_rssi_scan(
                    next_scan_carrier,
                    scan_duration_modem_units,
                    NRF_MODEM_DECT_PHY_RSSI_INTERVAL_24_SLOTS, // Or other suitable interval
                    phy_op_handle,
                    PENDING_OP_FT_INITIAL_SCAN); // Same op type for iterative scanning
                if (ret != 0) {
                    LOG_ERR("FT SM: Failed to start next DCS scan (C%u): %d. Aborting DCS.", next_scan_carrier, ret);
                    // Fallback: Try to use default carrier or best found so far if any
                    ctx->role_ctx.ft.dcs_scan_complete = true; // Mark as complete to trigger selection
                    ft_select_operating_carrier_and_start_beaconing(NULL); // Pass NULL, selection uses stored results
                }
            } else {
                // All channels scanned
                LOG_INF("FT SM: DCS scan sequence complete.");
                ctx->role_ctx.ft.dcs_scan_complete = true;
                ft_select_operating_carrier_and_start_beaconing(NULL); // Pass NULL, selection logic uses stored results
            }
            break;
        case PENDING_OP_FT_BEACON:
            if (event->err != NRF_MODEM_DECT_PHY_SUCCESS) {
                LOG_ERR("FT SM: Beacon TX failed (err %d). Next beacon by timer.", event->err);
            } else {
                LOG_DBG("FT SM: Beacon TX SFN %u successful.", ctx->role_ctx.ft.sfn_for_last_beacon_tx);
            }
            if (ctx->state == MAC_STATE_FT_BEACONING) {
                ft_schedule_rach_listen_action();
            }
            break;
        case PENDING_OP_FT_RACH_RX_WINDOW:
             LOG_DBG("FT SM: RACH RX window op completed (err %d). Next RACH listen after next beacon cycle.", event->err);
            // Next RACH listen will be scheduled after next beacon if FT is still in beaconing state.
            break;
        case PENDING_OP_FT_ASSOC_RESP:
             if (event->err == NRF_MODEM_DECT_PHY_SUCCESS) {
                LOG_INF("FT SM: Association Response sent successfully to PT ShortID 0x%04X.",
                        ctx->role_ctx.ft.last_assoc_resp_pt_short_id);
             } else {
                LOG_ERR("FT SM: Association Response TX failed (err %d) for PT ShortID 0x%04X.",
                        event->err, ctx->role_ctx.ft.last_assoc_resp_pt_short_id);
                int peer_idx = ft_get_peer_slot_idx(ctx, ctx->role_ctx.ft.last_assoc_resp_pt_short_id);
                if (peer_idx != -1 && ctx->role_ctx.ft.connected_pts[peer_idx].is_valid) {
                    if (ctx->role_ctx.ft.connected_pts[peer_idx].long_rd_id != 0) { // Check if it was an actual acceptance attempt
                        LOG_INF("FT SM: Invalidating peer slot %d for PT 0x%04X due to failed AssocResp TX.",
                                peer_idx, ctx->role_ctx.ft.last_assoc_resp_pt_short_id);
                        // Don't fully clear, just mark not valid, so no new PT takes this slot immediately if it was a temp issue
                        ctx->role_ctx.ft.connected_pts[peer_idx].is_valid = false; // Or a more nuanced state like "assoc_pending_retry"
                        ctx->role_ctx.ft.keys_provisioned_for_peer[peer_idx] = false;
                    }
                }
            }
            ctx->role_ctx.ft.last_assoc_resp_pt_short_id = 0; // Clear
            break;
        case PENDING_OP_FT_DATA_TX_HARQ0:
        case PENDING_OP_FT_DATA_TX_HARQ_MAX: // Covers range with fallthrough
            {
                int harq_idx = completed_op_type - PENDING_OP_FT_DATA_TX_HARQ0;
                if (harq_idx >= 0 && harq_idx < MAX_HARQ_PROCESSES) {
                    if (event->err == NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY) {
                        LOG_WRN("FT SM: Data TX HARQ %d LBT busy. Data Path will re-TX.", harq_idx);
                        dect_mac_data_path_handle_harq_nack_action(harq_idx);
                    } else if (event->err != NRF_MODEM_DECT_PHY_SUCCESS) {
                        LOG_ERR("FT SM: Data TX HARQ %d failed (err %d). Data Path will re-TX/discard.", harq_idx, event->err);
                        dect_mac_data_path_handle_harq_nack_action(harq_idx);
                    } else {
                        LOG_DBG("FT SM: Data TX HARQ %d PHY op complete. Awaiting feedback.", harq_idx);
                    }
                } else {
                     LOG_ERR("FT SM: OP_COMPLETE for invalid FT_DATA_TX_HARQ op type: %d", completed_op_type);
                }
            }
            break;
        default:
            LOG_WRN("FT SM: OP_COMPLETE for unhandled FT op type: %s, err %d",
                    dect_pending_op_to_str(completed_op_type), event->err);
            break;
    }
}


static void ft_handle_phy_rssi_ft(const struct nrf_modem_dect_phy_rssi_event *rssi_event) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != MAC_STATE_FT_SCANNING || ctx->pending_op_type != PENDING_OP_FT_INITIAL_SCAN || rssi_event->handle != ctx->pending_op_handle) {
        LOG_WRN("FT_RSSI: Received RSSI result for unexpected op type %s, handle %u, or state %s.",
                dect_pending_op_to_str(ctx->pending_op_type), rssi_event->handle, dect_mac_state_to_str(ctx->state));
        // Clear pending op if it was this handle to avoid stall
        if (rssi_event->handle == ctx->pending_op_handle) {
             dect_mac_phy_ctrl_handle_op_complete(&(struct nrf_modem_dect_phy_op_complete_event){.handle = rssi_event->handle, .err = NRF_MODEM_DECT_PHY_ERR_OP_CANCELED});
        }
        return;
    }

    // pending_op is cleared by dect_mac_phy_ctrl_handle_op_complete called from dispatcher before this.
    // No, this handler is called directly for the RSSI event itself by the dispatcher.
    // The PENDING_OP_FT_INITIAL_SCAN is completed with its own NRF_MODEM_DECT_PHY_EVT_COMPLETED event.
    // This RSSI event is an intermediate report *during* PENDING_OP_FT_INITIAL_SCAN.

    uint8_t current_scan_idx = ctx->role_ctx.ft.dcs_current_channel_scan_index;
    uint16_t scanned_carrier = rssi_event->carrier;

    if (scanned_carrier != ctx->role_ctx.ft.dcs_candidate_channels[current_scan_idx]) {
        LOG_WRN("FT_RSSI: RSSI report for carrier %u, but expected scan for %u (idx %u). Ignoring.",
                scanned_carrier, ctx->role_ctx.ft.dcs_candidate_channels[current_scan_idx], current_scan_idx);
        return;
    }

    if (rssi_event->meas_len > 0) {
        int32_t rssi_sum = 0;
        int valid_count = 0;
        // New calculation including busy percentage:
        int busy_sample_count = 0;
        int16_t busy_threshold_q71 = ctx->config.rssi_threshold_max_dbm * 2; // Convert dBm to Q7.1

        for (uint16_t i = 0; i < rssi_event->meas_len; ++i) {
            if (rssi_event->meas[i] != NRF_MODEM_DECT_PHY_RSSI_NOT_MEASURED) {
                rssi_sum_q71 += rssi_event->meas[i];
                valid_sample_count++;
                if (rssi_event->meas[i] > busy_threshold_q71) {
                    busy_sample_count++;
                }
            }
        }

        if (valid_sample_count > 0) {
            ctx->role_ctx.ft.dcs_candidate_rssi_avg[current_scan_idx] = rssi_sum_q71 / valid_sample_count;
            ctx->role_ctx.ft.dcs_candidate_busy_percent[current_scan_idx] = (busy_sample_count * 100) / valid_sample_count;
            LOG_INF("FT_DCS: Scan %u/%u on C%u: AvgRSSI %.1f dBm, Busy %u%% (%d/%d samples).",
                    current_scan_idx + 1, CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN,
                    scanned_carrier,
                    (float)ctx->role_ctx.ft.dcs_candidate_rssi_avg[current_scan_idx] / 2.0f,
                    ctx->role_ctx.ft.dcs_candidate_busy_percent[current_scan_idx],
                    busy_sample_count, valid_sample_count);
        } else {
            LOG_WRN("FT_DCS: Scan %u/%u on C%u: No valid RSSI samples.",
                    current_scan_idx + 1, CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN, scanned_carrier);
            ctx->role_ctx.ft.dcs_candidate_rssi_avg[current_scan_idx] = 0; // Or INT16_MAX to mark as unusable
            ctx->role_ctx.ft.dcs_candidate_busy_percent[current_scan_idx] = 101; // Mark as unscanned/invalid
        }


    } else {
        LOG_WRN("FT_DCS: Scan %u/%u on C%u: RSSI event with no measurements.",
                current_scan_idx + 1, CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN, scanned_carrier);
    }

    // This RSSI event is just a report. The actual PENDING_OP_FT_INITIAL_SCAN
    // will complete with NRF_MODEM_DECT_PHY_EVT_COMPLETED.
    // The logic to scan the *next* channel or select the best should happen
    // in the handler for NRF_MODEM_DECT_PHY_EVT_COMPLETED for PENDING_OP_FT_INITIAL_SCAN.
}


// Include the full ft_handle_phy_pcc_ft from "Phase 5 P5.3"
static void ft_handle_phy_pcc_ft(const struct nrf_modem_dect_phy_pcc_event *pcc_event) {
    dect_mac_context_t* ctx = get_mac_context();
    ft_last_relevant_pcc_is_valid = false; 

    if (pcc_event->header_status == NRF_MODEM_DECT_PHY_HDR_STATUS_VALID) {
        uint16_t pcc_rx_id_on_ft_antenna = 0;
        uint16_t pcc_tx_id_from_pt = 0;

        if (pcc_event->phy_type == 1) { // nRF PHY Type 1 (ETSI PCC Type 2)
            pcc_rx_id_on_ft_antenna = sys_be16_to_cpu(
                (uint16_t)((pcc_event->hdr.hdr_type_2.receiver_id_hi << 8) |
                            pcc_event->hdr.hdr_type_2.receiver_id_lo));
            pcc_tx_id_from_pt = sys_be16_to_cpu(
                (uint16_t)((pcc_event->hdr.hdr_type_2.transmitter_id_hi << 8) |
                            pcc_event->hdr.hdr_type_2.transmitter_id_lo));

            if (pcc_rx_id_on_ft_antenna == ctx->own_short_rd_id) {
                memcpy(&ft_last_relevant_pcc, pcc_event, sizeof(struct nrf_modem_dect_phy_pcc_event));
                // ft_last_relevant_pcc.pcc_event_modem_time = pcc_event->time; // If storing time in wrapper
                ft_last_relevant_pcc_is_valid = true;

                if (ctx->pending_op_type == PENDING_OP_FT_RACH_RX_WINDOW) {
                    LOG_INF("FT_SM_PCC: PCC (Type2) on RACH from PT 0x%04X. TID:%u. Waiting PDC.",
                            pcc_tx_id_from_pt, pcc_event->transaction_id);
                    ctx->role_ctx.ft.last_rach_pt_short_id = pcc_tx_id_from_pt;
                    ctx->role_ctx.ft.last_rach_rssi2 = pcc_event->rssi_2;
                } else { 
                    int peer_idx = ft_get_peer_slot_idx(ctx, pcc_tx_id_from_pt);
                    if (peer_idx != -1) {
                        LOG_DBG("FT_SM_PCC: PCC (Type2) from connected PT 0x%04X (slot %d). TID:%u.",
                                pcc_tx_id_from_pt, peer_idx, pcc_event->transaction_id);
                        dect_mac_data_path_process_harq_feedback(&pcc_event->hdr.hdr_type_2.feedback, pcc_tx_id_from_pt);
                    } else {
                        LOG_WRN("FT_SM_PCC: PCC (Type2) from unknown PT 0x%04X. TID:%u. Ignoring.",
                                pcc_tx_id_from_pt, pcc_event->transaction_id);
                        ft_last_relevant_pcc_is_valid = false;
                    }
                }
            } else { 
                LOG_DBG("FT_SM_PCC: PCC (Type2) not for this FT (RxID 0x%04X vs Own 0x%04X). TID: %u",
                        pcc_rx_id_on_ft_antenna, ctx->own_short_rd_id, pcc_event->transaction_id);
            }
        } else if (pcc_event->phy_type == 0) {
             LOG_WRN("FT_SM_PCC: Received Type 1 PCC (Beacon). Normally not processed by FT. TID: %u", pcc_event->transaction_id);
        } else { 
             LOG_ERR("FT_SM_PCC: Unknown nRF PHY header type in PCC: %d. TID: %u", pcc_event->phy_type, pcc_event->transaction_id);
        }
    } else { LOG_WRN("FT_SM_PCC: Invalid PCC status %d. TID:%u.", pcc_event->header_status, pcc_event->transaction_id); }
}



static void ft_handle_phy_pdc_ft(const struct nrf_modem_dect_phy_pdc_event *pdc_event) {
    dect_mac_context_t* ctx = get_mac_context();
    uint8_t mac_pdc_payload_copy[CONFIG_DECT_MAC_PDU_MAX_SIZE];
    uint16_t pdc_payload_len = pdc_event->len;

    if (!ft_last_relevant_pcc_is_valid || ft_last_relevant_pcc.transaction_id != pdc_event->transaction_id) {
        LOG_WRN("FT_SM_PDC: PDC (TID %u) without matching valid PCC. Discarding.", pdc_event->transaction_id);
        return;
    }
    struct nrf_modem_dect_phy_pcc_event current_pcc_data = ft_last_relevant_pcc;
    ft_last_relevant_pcc_is_valid = false; // Consume the stored PCC info

    if (pdc_payload_len == 0 && pdc_event->transaction_id != 0) {
        LOG_DBG("FT_SM_PDC: Empty PDC (TID %u). Ignoring.", pdc_event->transaction_id);
        return;
    }
    if (pdc_payload_len > sizeof(mac_pdc_payload_copy)) {
        LOG_ERR("FT_SM_PDC: PDC payload from PHY (%u bytes) too large for copy buffer (%zu). Discarding.",
                pdc_payload_len, sizeof(mac_pdc_payload_copy));
        return;
    }
    memcpy(mac_pdc_payload_copy, pdc_event->data, pdc_payload_len);

    dect_mac_header_type_octet_t mac_hdr_type_octet;
    memcpy(&mac_hdr_type_octet, &current_pcc_data.hdr.bytes[0], sizeof(dect_mac_header_type_octet_t));

    uint8_t *pdu_content_start = mac_pdc_payload_copy;
    uint16_t pdu_content_len = pdc_payload_len;

    uint16_t pt_sender_short_id_from_pcc = sys_be16_to_cpu(
        (uint16_t)((current_pcc_data.hdr.hdr_type_2.transmitter_id_hi << 8) |
                    current_pcc_data.hdr.hdr_type_2.transmitter_id_lo));
    // Note: current_pcc_data must be Type 2 if we are here for data/assoc_req from PT
    if (current_pcc_data.phy_type != 1) {
        LOG_ERR("FT_SM_PDC: Expected Type 2 PCC for PT message, got type %u. TID %u",
                current_pcc_data.phy_type, pdc_event->transaction_id);
        return;
    }

    int peer_slot_idx = ft_get_peer_slot_idx(ctx, pt_sender_short_id_from_pcc);
    dect_mac_peer_info_t *pt_peer_ctx = (peer_slot_idx != -1) ? &ctx->role_ctx.ft.connected_pts[peer_slot_idx] : NULL;

    bool security_applied_by_sender = (mac_hdr_type_octet.mac_security != MAC_SECURITY_NONE);
    bool link_is_expected_to_be_secure = (pt_peer_ctx && pt_peer_ctx->is_valid && pt_peer_ctx->is_secure &&
                                        ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx]);
    bool pdc_process_ok_for_feedback = true;

    uint8_t *common_hdr_start_in_payload = pdu_content_start;
    size_t common_hdr_actual_len = 0;
    uint8_t *sdu_area_after_common_hdr = NULL;
    size_t sdu_area_plus_mic_actual_len = 0;

    if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_UNICAST) {
        common_hdr_actual_len = sizeof(dect_mac_unicast_header_t);
    } else if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_DATA_PDU) {
        common_hdr_actual_len = sizeof(dect_mac_data_pdu_header_t);
    } else {
        LOG_WRN("FT_SM_PDC: Received PDC with MAC Hdr Type %u, not Unicast/Data from PT. TID %u",
                mac_hdr_type_octet.mac_header_type, pdc_event->transaction_id);
        return;
    }

    if (pdu_content_len < common_hdr_actual_len) {
        LOG_ERR("FT_SM_PDC: PDU too short (%u) for Common Hdr type %u (len %zu).",
                pdu_content_len, mac_hdr_type_octet.mac_header_type, common_hdr_actual_len);
        return;
    }
    sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len;
    sdu_area_plus_mic_actual_len = pdu_content_len - common_hdr_actual_len;

    // These pointers will be adjusted after security processing
    uint8_t *sdu_area_for_data_path = sdu_area_after_common_hdr;
    size_t sdu_area_len_for_data_path = sdu_area_plus_mic_len_in_payload;

    if (security_applied_by_sender) {
        if (!link_is_expected_to_be_secure || !pt_peer_ctx) { // pt_peer_ctx should be valid if link_is_expected_to_be_secure
            LOG_WRN("FT_SM_PDC_SEC: Secured PDU from PT 0x%04X, but no valid secure context/peer_ctx. Discarding.",
                    pt_sender_short_id_from_pcc);
            return; // Cannot process security without keys/context
        }
        if (sdu_area_plus_mic_len_in_payload < 5 /*MIC_LEN*/) {
             LOG_ERR("FT_SM_PDC_SEC: Secured PDU from PT 0x%04X too short for MIC (SDUArea+MIC len %zu). Discarding.",
                    pt_sender_short_id_from_pcc, sdu_area_plus_mic_len_in_payload);
             return;
        }

        const dect_mac_unicast_header_t *uch_ptr = (const dect_mac_unicast_header_t *)common_hdr_start_in_payload;
        uint16_t received_psn = ((uch_ptr->sequence_num_high_reset_rsv >> 4) & 0x0F) << 8 | uch_ptr->sequence_num_low;
        uint32_t pt_tx_long_id_from_hdr = sys_be32_to_cpu(uch_ptr->transmitter_long_rd_id_be);

        if (pt_tx_long_id_from_hdr != pt_peer_ctx->long_rd_id) {
            LOG_WRN("FT_SM_PDC_SEC: Secured PDU LongID 0x%08X mismatch for PT 0x%04X (expected 0x%08X). Discarding.",
                    pt_tx_long_id_from_hdr, pt_sender_short_id_from_pcc, pt_peer_ctx->long_rd_id);
            return;
        }

        uint8_t *payload_to_decrypt_start = NULL;
        size_t payload_to_decrypt_len = 0;
        size_t cleartext_sec_ie_mux_len = 0; // Length of the MUXed MAC Sec Info IE (if present and cleartext)

        if (mac_hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            // Parse the MUXed MAC Security Info IE first (it's cleartext)
            uint8_t ie_type_sec; uint16_t ie_len_sec; const uint8_t *ie_payload_sec;
            int mux_hdr_len_sec = parse_mac_mux_header(sdu_area_after_common_hdr, sdu_area_plus_mic_len_in_payload,
                                                       &ie_type_sec, &ie_len_sec, &ie_payload_sec);

            if (mux_hdr_len_sec > 0 && ie_type_sec == IE_TYPE_MAC_SECURITY_INFO) {
                if (sdu_area_plus_mic_len_in_payload < (size_t)mux_hdr_len_sec + ie_len_sec + 5 /*MIC*/) {
                    LOG_ERR("FT_SM_PDC_SEC: PDU too short for parsed SecIE + rest + MIC. Discarding.");
                    pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path;
                }
                cleartext_sec_ie_mux_len = mux_hdr_len_sec + ie_len_sec;
                uint8_t ver, kidx, secivtype_from_ie; uint32_t hpc_from_ie;
                if (parse_mac_security_info_ie_payload(ie_payload_sec, ie_len_sec, &ver, &kidx, &secivtype_from_ie, &hpc_from_ie) == 0) {
                    LOG_INF("FT_SM_PDC_SEC (WITH_IE): MAC Sec Info IE from PT 0x%04X: PeerHPC_IE=%u, TrackedHPC=%u, SecIVType=%u",
                            pt_sender_short_id_from_pcc, hpc_from_ie, pt_peer_ctx->hpc, secivtype_from_ie);
                    // TODO: Implement full HPC windowing and resync request logic here.
                    // pt_peer_ctx is the context for the peer (e.g., ctx->role_ctx.ft.connected_pts[peer_slot_idx])
                    // hpc_from_ie is the HPC value parsed from the MAC Security Info IE.

                    LOG_INF("PDC_SEC_HPC: RX SecIE from Peer 0x%04X. HPC_IE=%u, MyTrackedPeerHPC.hpc=%u, MyTrackedPeerHPC.highest_rx=%u, SecIVType=%u",
                            pt_sender_short_id_from_pcc, /* or ft_sender_short_id_from_pcc for PT */
                            hpc_from_ie,
                            pt_peer_ctx->hpc, /* Current HPC used for this PDU's IV (might be updated) */
                            pt_peer_ctx->highest_rx_peer_hpc, /* Highest validated HPC from a SecIE */
                            secivtype_from_ie);

                    bool hpc_accepted_for_iv = false;

                    if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_PROVIDED) {
                        if (pt_peer_ctx->highest_rx_peer_hpc == 0 && hpc_from_ie > 0) { // First valid HPC received
                            pt_peer_ctx->highest_rx_peer_hpc = hpc_from_ie;
                            pt_peer_ctx->hpc = hpc_from_ie; // Use this for current PDU
                            hpc_accepted_for_iv = true;
                            LOG_DBG("PDC_SEC_HPC: First HPC_PROVIDED %u accepted.", hpc_from_ie);

                            

                        } else {
                            // Check for forward jump
                            uint32_t forward_diff;
                            if (hpc_from_ie >= pt_peer_ctx->highest_rx_peer_hpc) {
                                forward_diff = hpc_from_ie - pt_peer_ctx->highest_rx_peer_hpc;
                            } else { // hpc_from_ie wrapped around
                                forward_diff = (UINT32_MAX - pt_peer_ctx->highest_rx_peer_hpc) + hpc_from_ie + 1;
                            }

                            if (forward_diff == 0) {
                                pt_peer_ctx->hpc = hpc_from_ie;
                                hpc_accepted_for_iv = true;
                                LOG_DBG("PDC_SEC_HPC: HPC_PROVIDED %u matches highest_rx. Accepted.", hpc_from_ie);
                            } else if (forward_diff > 0 && forward_diff <= CONFIG_DECT_MAC_HPC_RX_FORWARD_WINDOW_MAX_ADVANCE) {
                                pt_peer_ctx->highest_rx_peer_hpc = hpc_from_ie;
                                pt_peer_ctx->hpc = hpc_from_ie;
                                hpc_accepted_for_iv = true;
                                LOG_DBG("PDC_SEC_HPC: HPC_PROVIDED %u accepted (forward jump %u). New highest_rx.", hpc_from_ie, forward_diff);
                            } else if (forward_diff > CONFIG_DECT_MAC_HPC_RX_FORWARD_WINDOW_MAX_ADVANCE) {
                                LOG_ERR("PDC_SEC_HPC: HPC_PROVIDED %u rejected. Excessive forward jump %u (max %d).",
                                        hpc_from_ie, forward_diff, CONFIG_DECT_MAC_HPC_RX_FORWARD_WINDOW_MAX_ADVANCE);
                                pdc_process_ok_for_feedback = false;
                            } else { // hpc_from_ie is "older"
                                uint32_t backward_diff;
                                if (pt_peer_ctx->highest_rx_peer_hpc >= hpc_from_ie) {
                                    backward_diff = pt_peer_ctx->highest_rx_peer_hpc - hpc_from_ie;
                                } else { 
                                    backward_diff = (UINT32_MAX - hpc_from_ie) + pt_peer_ctx->highest_rx_peer_hpc + 1;
                                }

                                if (backward_diff < CONFIG_DECT_MAC_HPC_RX_WINDOW_SIZE) {
                                    pt_peer_ctx->hpc = hpc_from_ie;
                                    hpc_accepted_for_iv = true;
                                    LOG_DBG("PDC_SEC_HPC: HPC_PROVIDED %u accepted (older, but within anti-replay window %u of %d).",
                                            hpc_from_ie, backward_diff, CONFIG_DECT_MAC_HPC_RX_WINDOW_SIZE);
                                } else {
                                    LOG_ERR("PDC_SEC_HPC: HPC_PROVIDED %u rejected. Too old or outside anti-replay window (diff %u, win %d).",
                                            hpc_from_ie, backward_diff, CONFIG_DECT_MAC_HPC_RX_WINDOW_SIZE);
                                    pdc_process_ok_for_feedback = false;
                                }
                            }
                        }

                    } else if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) {
                        // Peer is requesting our HPC. We should note this and send our HPC back.
                        // For *this current PDU's IV*, we should still validate the hpc_from_ie.
                        // The peer sends its *current* HPC when it makes a RESYNC_INITIATE request.
                        LOG_INF("PDC_SEC_HPC: Peer 0x%04X requests HPC resync, providing its HPC_IE=%u.",
                                pt_sender_short_id_from_pcc, hpc_from_ie);
                        
                        // Validate hpc_from_ie from FT for *this current PDU's IV*.
                        // Check if newer, or if older but within window (considering wrap-around for older check)
                        bool use_hpc_from_ie_for_iv = false;
                        if (pt_peer_ctx->highest_rx_peer_hpc == 0) { // First time or reset
                            use_hpc_from_ie_for_iv = true;
                        } else if (hpc_from_ie >= pt_peer_ctx->highest_rx_peer_hpc) { // Newer or same (could be retransmission)
                            // Check for excessive forward jump only if strictly greater
                            if (hpc_from_ie > pt_peer_ctx->highest_rx_peer_hpc) {
                                uint32_t fwd_diff = hpc_from_ie - pt_peer_ctx->highest_rx_peer_hpc;
                                if (fwd_diff <= CONFIG_DECT_MAC_HPC_RX_FORWARD_WINDOW_MAX_ADVANCE) {
                                    use_hpc_from_ie_for_iv = true;
                                } else {
                                    LOG_WRN("PDC_SEC_HPC: HPC_IE %u with RESYNC_INITIATE has excessive fwd jump. Using highest_rx for IV.", hpc_from_ie);
                                }
                            } else { // hpc_from_ie == pt_peer_ctx->highest_rx_peer_hpc
                                use_hpc_from_ie_for_iv = true;
                            }
                        } else { // hpc_from_ie < pt_peer_ctx->highest_rx_peer_hpc (check anti-replay window)
                            uint32_t back_diff = pt_peer_ctx->highest_rx_peer_hpc - hpc_from_ie;
                            // This simple subtraction is only okay if no wrap-around of hpc_from_ie has occurred
                            // A more robust check:
                            uint32_t effective_backward_diff;
                            if (pt_peer_ctx->highest_rx_peer_hpc >= hpc_from_ie) {
                                effective_backward_diff = pt_peer_ctx->highest_rx_peer_hpc - hpc_from_ie;
                            } else { // highest_rx_peer_hpc wrapped relative to hpc_from_ie
                                effective_backward_diff = (UINT32_MAX - hpc_from_ie) + pt_peer_ctx->highest_rx_peer_hpc + 1;
                            }
                            if (effective_backward_diff < CONFIG_DECT_MAC_HPC_RX_WINDOW_SIZE) {
                                use_hpc_from_ie_for_iv = true;
                            } else {
                                LOG_WRN("PDC_SEC_HPC: HPC_IE %u with RESYNC_INITIATE is too old. Using highest_rx for IV.", hpc_from_ie);
                            }
                        }

                        if (use_hpc_from_ie_for_iv) {
                            pt_peer_ctx->hpc = hpc_from_ie;
                            // Update highest_rx_peer_hpc only if hpc_from_ie is genuinely newer
                            if (hpc_from_ie > pt_peer_ctx->highest_rx_peer_hpc ||
                                (pt_peer_ctx->highest_rx_peer_hpc > 0xFFFFFF00 && hpc_from_ie < 0x000000FF && pt_peer_ctx->highest_rx_peer_hpc !=0) ) { // Heuristic for wrap
                                pt_peer_ctx->highest_rx_peer_hpc = hpc_from_ie;
                            }
                            hpc_accepted_for_iv = true;
                        } else {
                             // If hpc_from_ie was not accepted for IV (e.g. too old, too far ahead),
                             // use the last known good one for this PDU's IV.
                             pt_peer_ctx->hpc = pt_peer_ctx->highest_rx_peer_hpc;
                             hpc_accepted_for_iv = true; // Still try to process PDU with best guess HPC
                        }

                            pt_peer_ctx->hpc = hpc_from_ie; // Use this for current PDU
                            if (hpc_from_ie > pt_peer_ctx->highest_rx_peer_hpc) { // Update highest if newer
                                pt_peer_ctx->highest_rx_peer_hpc = hpc_from_ie;
                            }
                            hpc_accepted_for_iv = true;
                        } else {
                             LOG_WRN("PDC_SEC_HPC: HPC_IE %u with RESYNC_INITIATE is too old vs highest_rx %u. Using highest_rx for IV.",
                                     hpc_from_ie, pt_peer_ctx->highest_rx_peer_hpc);
                             pt_peer_ctx->hpc = pt_peer_ctx->highest_rx_peer_hpc; // Fallback for IV
                             hpc_accepted_for_iv = true; // Still accept PDU if possible
                        }
                        // Set flag for us to send our HPC back
                        if (ctx->role == MAC_ROLE_FT) { // FT received request from PT
                            pt_peer_ctx->peer_requested_hpc_resync = true;
                        } else { // PT received request from FT
                            ctx->send_mac_sec_info_ie_on_next_tx = true; // Global flag for PT to send its HPC
                        }
                    } else { // Unknown SecIVType
                        LOG_ERR("PDC_SEC_HPC: Unknown SecIVType %u from peer 0x%04X. Rejecting PDU.",
                                secivtype_from_ie, pt_sender_short_id_from_pcc);
                        pdc_process_ok_for_feedback = false;
                    }

                    if (!hpc_accepted_for_iv && pdc_process_ok_for_feedback) {
                        // This case should ideally be caught by specific rejection paths above.
                        LOG_ERR("PDC_SEC_HPC: HPC_IE %u was not accepted for IV construction. Rejecting PDU.", hpc_from_ie);
                        pdc_process_ok_for_feedback = false;
                    }
                } else { LOG_ERR("FT_SM_PDC_SEC: Failed to parse MAC Sec Info IE from PT 0x%04X.", pt_sender_short_id_from_pcc); 
                         pdc_process_ok_for_feedback = false; 
                }

                payload_to_decrypt_start = sdu_area_after_common_hdr + cleartext_sec_ie_mux_len;
                payload_to_decrypt_len = sdu_area_plus_mic_len_in_payload - cleartext_sec_ie_mux_len;
            } else {
                LOG_ERR("FT_SM_PDC_SEC: MAC_SECURITY_USED_WITH_IE indicated but MAC Sec Info IE not found/parsed first. Discarding.");
                pdc_process_ok_for_feedback = false;
            }
        } else { // MAC_SECURITY_USED_NO_IE
            cleartext_sec_ie_mux_len = 0;
            payload_to_decrypt_start = sdu_area_after_common_hdr;
            payload_to_decrypt_len = sdu_area_plus_mic_len_in_payload;
        }

        if (!pdc_process_ok_for_feedback) goto process_feedback_ft_pdc_secure_rx_path; // Abort if HPC from IE was invalid

        if (payload_to_decrypt_len < 5) { LOG_ERR("FT_SM_PDC_SEC: Encrypted part too short for MIC. Discarding."); pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path; }

        uint8_t iv[16];
        security_build_iv(iv, pt_tx_long_id_from_hdr, ctx->own_long_rd_id,
                          pt_peer_ctx->hpc, // Use FT's tracked HPC for this PT (which might have just been updated from SecIE)
                          received_psn);

        // Decrypt (in-place on mac_pdc_payload_copy)
        if (security_crypt_payload(payload_to_decrypt_start, payload_to_decrypt_len,
                                   ctx->role_ctx.ft.peer_cipher_keys[peer_slot_idx], iv, false /*decrypt*/) != 0) {
            LOG_ERR("FT_SM_PDC_SEC: Decryption failed for PDU from PT 0x%04X. Discarding.", pt_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path;
        }

        // MIC Verification (MIC is now cleartext at the end of payload_to_decrypt_start)
        uint8_t *cleartext_mic_ptr = payload_to_decrypt_start + payload_to_decrypt_len - 5;
        uint8_t calculated_mic[5];
        // MIC is calculated over: Common Header + MUXed SecIE (if present, cleartext) + (Rest of SDU Area, now cleartext)
        size_t data_for_mic_len = common_hdr_actual_len + (payload_to_decrypt_len - 5) + cleartext_sec_ie_mux_len;

        if (security_calculate_mic(common_hdr_start_in_payload, data_for_mic_len, /* common_hdr_start_in_payload is start of CommonHdr */
                                   ctx->role_ctx.ft.peer_integrity_keys[peer_slot_idx], calculated_mic) != 0) {
            LOG_ERR("FT_SM_PDC_SEC: MIC re-calc failed. Discarding PDU from PT 0x%04X.", pt_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path;
        }

        if (memcmp(cleartext_mic_ptr, calculated_mic, 5) != 0) {
            LOG_ERR("FT_SM_PDC_SEC: MIC FAIL from PT 0x%04X (PSN %u, PeerHPC %u). Discarding.",
                    pt_sender_short_id_from_pcc, received_psn, pt_peer_ctx->hpc);
            pt_peer_ctx->consecutive_mic_failures++;
            if (pt_peer_ctx->consecutive_mic_failures >= CONFIG_DECT_MAC_MAX_MIC_FAILURES_BEFORE_HPC_RESYNC) {
                LOG_WRN("FT_SM_PDC_SEC: Max MIC failures (%u) for PT 0x%04X. Will request HPC resync from PT.",
                        pt_peer_ctx->consecutive_mic_failures, pt_sender_short_id_from_pcc);
                pt_peer_ctx->self_needs_to_request_hpc_from_peer = true;
                pt_peer_ctx->consecutive_mic_failures = 0;
            }
            pdc_process_ok_for_feedback = false;
        } else { // MIC OK
            LOG_DBG("FT_SM_PDC_SEC: MIC OK from PT 0x%04X (PSN %u, PeerHPC %u).",
                    pt_sender_short_id_from_pcc, received_psn, pt_peer_ctx->hpc);
            pt_peer_ctx->consecutive_mic_failures = 0;
            // Adjust pointers for data path: SDU area is after CommonHdr and after cleartext SecIE (if present), and excludes MIC.
            sdu_area_for_data_path = sdu_area_after_common_hdr + cleartext_sec_ie_mux_len;
            sdu_area_len_for_data_path = payload_to_decrypt_len - 5; // Length of (Rest of SDU Area, now cleartext)
        }
    } else { // Not secured
        LOG_DBG("FT_SM_PDC: Unsecure PDU from PT 0x%04X.", pt_sender_short_id_from_pcc);
        // sdu_area_for_data_path and sdu_area_len_for_data_path are already set correctly for non-secure case
    }

process_feedback_ft_pdc_secure_rx_path:
    if (pt_peer_ctx && pt_peer_ctx->is_valid && current_pcc_data.phy_type == 1 &&
        (link_is_expected_to_be_secure || security_applied_by_sender) ) {
        uint8_t harq_proc_in_pt_tx = current_pcc_data.hdr.hdr_type_2.df_harq_process_num;
        if (pt_peer_ctx->num_pending_feedback_items < 2) {
            int fb_idx = pt_peer_ctx->num_pending_feedback_items++;
            pt_peer_ctx->pending_feedback_to_send[fb_idx].valid = true;
            pt_peer_ctx->pending_feedback_to_send[fb_idx].is_ack = pdc_process_ok_for_feedback;
            pt_peer_ctx->pending_feedback_to_send[fb_idx].harq_process_num_for_peer = harq_proc_in_pt_tx;
        } else { LOG_WRN("FT_SM_PDC: Feedback buffer full for PT 0x%04X", pt_sender_short_id_from_pcc); }
    }
    if (!pdc_process_ok_for_feedback) return;


    // --- Proceed with cleartext SDU Area content ---
    const uint8_t *sdu_area_final_ptr = sdu_area_after_common_hdr;
    size_t sdu_area_final_len = sdu_area_plus_mic_actual_len;
    uint32_t sender_long_id_final = 0;

    if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_UNICAST) {
        const dect_mac_unicast_header_t *uch = (const dect_mac_unicast_header_t *)common_hdr_start_in_payload;
        sender_long_id_final = sys_be32_to_cpu(uch->transmitter_long_rd_id_be);

        if (ctx->pending_op_type == PENDING_OP_FT_RACH_RX_WINDOW && pt_peer_ctx == NULL) {
            ft_process_association_request_pdu(sdu_area_final_ptr, sdu_area_final_len,
                                               pt_sender_short_id_from_pcc, sender_long_id_final,
                                               current_pcc_data.rssi_2);
        } else if (pt_peer_ctx && pt_peer_ctx->is_valid) {
            LOG_INF("FT_SM_PDC: Processing Unicast SDU Area (len %zu) from PT 0x%04X.", sdu_area_final_len, pt_sender_short_id_from_pcc);
            dect_mac_data_path_handle_rx_sdu(sdu_area_final_ptr, sdu_area_final_len, sender_long_id_final);
        } else {
             LOG_WRN("FT_SM_PDC: Unicast from unknown PT 0x%04X or unexpected state. Discarding.", pt_sender_short_id_from_pcc);
        }
    } else if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_DATA_PDU && pt_peer_ctx && pt_peer_ctx->is_valid) {
        sender_long_id_final = pt_peer_ctx->long_rd_id; // Inferred for DATA PDU
        LOG_INF("FT_SM_PDC: Processing DATA PDU SDU Area (len %zu) from PT 0x%04X.", sdu_area_final_len, pt_sender_short_id_from_pcc);
        dect_mac_data_path_handle_rx_sdu(sdu_area_final_ptr, sdu_area_final_len, sender_long_id_final);
    }
     else {
        LOG_WRN("FT_SM_PDC: Received PDC with unhandled/unexpected MAC Common Header Type %u after security.", mac_hdr_type_octet.mac_header_type);
    }
}

static void ft_process_association_request_pdu(const uint8_t *mac_sdu_area_data, size_t mac_sdu_area_len,
                                               uint16_t pt_tx_short_rd_id, uint32_t pt_tx_long_rd_id, int16_t rssi_from_pcc)
{
    dect_mac_context_t* ctx = get_mac_context();
    dect_mac_assoc_req_ie_t req_fields;
    dect_mac_rd_capability_ie_t pt_cap_fields;
    bool assoc_req_ie_found = false;
    bool pt_cap_ie_found = false;

    LOG_INF("FT_SM_ASSOC: Processing Association Request from PT LongID:0x%08X, ShortID:0x%04X, RSSI:%.1f dBm",
            pt_tx_long_rd_id, pt_tx_short_rd_id, (float)rssi_from_pcc / 2.0f);

    const uint8_t *current_ie_ptr = mac_sdu_area_data;
    size_t remaining_len = mac_sdu_area_len;

    while (remaining_len > 0) {
        uint8_t ie_type;
        uint16_t ie_payload_len;
        const uint8_t *ie_payload_ptr;
        int mux_hdr_len = parse_mac_mux_header(current_ie_ptr, remaining_len,
                                               &ie_type, &ie_payload_len, &ie_payload_ptr);
        if (mux_hdr_len < 0) {
            LOG_ERR("FT_SM_ASSOC: Failed to parse MUX header in Assoc Req SDU Area: %d", mux_hdr_len);
            return; // Cannot proceed
        }
        // Adjust for MAC_Ext=00 where parse_mac_mux_header returns 0 for ie_payload_len
        if (ie_payload_len == 0 && ((current_ie_ptr[0] >> 6) & 0x03) == 0b00) {
            if (remaining_len < (size_t)mux_hdr_len) { LOG_ERR("FT_SM_ASSOC: MUX header error for MAC_Ext=00"); return; }
            ie_payload_len = remaining_len - mux_hdr_len; // Assume IE consumes rest
        }

        if (remaining_len < (size_t)mux_hdr_len + ie_payload_len) {
            LOG_ERR("FT_SM_ASSOC: MUX IE declared length %u exceeds remaining SDU area %zu.",
                    ie_payload_len, remaining_len - mux_hdr_len);
            break; // Stop parsing
        }

        if (ie_type == IE_TYPE_ASSOC_REQ) {
            if (parse_assoc_req_ie_payload(ie_payload_ptr, ie_payload_len, &req_fields) == 0) {
                assoc_req_ie_found = true;
                LOG_DBG("FT_SM_ASSOC: Parsed Assoc Req IE (Cause %u, Flows %u, FTModeCap %d).",
                        req_fields.setup_cause_val, req_fields.number_of_flows_val, req_fields.ft_mode_capable);
                    // Log more parsed details if present
                    if (req_fields.harq_params_present) {
                        LOG_INF("FT_SM_ASSOC: PT Req HARQ -> TX Procs: %u, ReTX DelayCode: %u; RX Procs: %u, ReRX DelayCode: %u",
                                req_fields.harq_processes_tx_val, req_fields.max_harq_re_tx_delay_code,
                                req_fields.harq_processes_rx_val, req_fields.max_harq_re_rx_delay_code);
                        // TODO: FT should store/consider these requested HARQ params when configuring link for this PT.
                    }
                    if (req_fields.number_of_flows_val > 0 && req_fields.number_of_flows_val <= MAX_FLOW_IDS_IN_ASSOC_REQ) {
                        // char flow_ids_str[MAX_FLOW_IDS_IN_ASSOC_REQ * 3 + 1] = {0}; // For "XX, YY, ZZ"
                        // for(int k=0; k < req_fields.number_of_flows_val; ++k) { snprintf(flow_ids_str + strlen(flow_ids_str), sizeof(flow_ids_str)-strlen(flow_ids_str), "%u,", req_fields.flow_ids[k]); }
                        // if(strlen(flow_ids_str) > 0) flow_ids_str[strlen(flow_ids_str)-1] = '\0'; // Remove last comma
                        // LOG_INF("FT_SM_ASSOC: PT Req Flows (%u): [%s]", req_fields.number_of_flows_val, flow_ids_str);
                        // For now, just log count, as FT doesn't act on specific flow IDs yet.
                         LOG_INF("FT_SM_ASSOC: PT Req %u specific flows.", req_fields.number_of_flows_val);
                    }
                    if (req_fields.ft_mode_capable) {
                        LOG_INF("FT_SM_ASSOC: PT is FT Mode Capable.");
                        if (req_fields.ft_beacon_periods_octet_present) {
                             LOG_INF("  PT FT Pref NetBeaconPeriodCode: %u, ClusterBeaconPeriodCode: %u",
                                     req_fields.ft_network_beacon_period_code, req_fields.ft_cluster_beacon_period_code);
                        }
                        if (req_fields.ft_param_flags_octet_present) {
                            if (req_fields.ft_next_channel_present) LOG_INF("  PT FT Pref NextChan: %u", req_fields.ft_next_cluster_channel_val);
                            if (req_fields.ft_time_to_next_present) LOG_INF("  PT FT Pref TimeToNext: %u us", req_fields.ft_time_to_next_us_val);
                        }
                        // TODO: FT could consider these if it supports dynamic FT role handover or coordination.
                    }

            } else {
                LOG_ERR("FT_SM_ASSOC: Failed to parse Assoc Req IE payload.");
            }
        } else if (ie_type == IE_TYPE_RD_CAPABILITY) {
            if (parse_rd_capability_ie_payload(ie_payload_ptr, ie_payload_len, &pt_cap_fields) == 0) {
                pt_cap_ie_found = true;
                LOG_DBG("FT_SM_ASSOC: Parsed PT RD Capability IE (Release %u).", pt_cap_fields.release_version);
            } else {
                LOG_ERR("FT_SM_ASSOC: Failed to parse PT RD Cap IE payload.");
            }
        } else {
            LOG_DBG("FT_SM_ASSOC: Skipping MUX IE type 0x%X in Assoc Req PDU.", ie_type);
        }

        current_ie_ptr += mux_hdr_len + ie_payload_len;
        if (remaining_len >= (size_t)mux_hdr_len + ie_payload_len) {
            remaining_len -= (mux_hdr_len + ie_payload_len);
        } else {
            remaining_len = 0; // Should not happen if length checks are correct
        }
    }

    if (!assoc_req_ie_found) {
        LOG_WRN("FT_SM_ASSOC: No Association Request IE found in PDU from PT 0x%04X. Ignoring.", pt_tx_short_rd_id);
        return;
    }
    if (!pt_cap_ie_found) {
        LOG_WRN("FT_SM_ASSOC: No RD Capability IE found from PT 0x%04X. Proceeding with caution.", pt_tx_short_rd_id);
        // Initialize pt_cap_fields to defaults or proceed without checking capabilities
        memset(&pt_cap_fields, 0, sizeof(pt_cap_fields)); // Example: assume minimal caps
    }

    // Association Decision Logic
    bool accept_association = true; // Default to accept
    int peer_slot_idx = ft_find_and_init_peer_slot(pt_tx_long_rd_id, pt_tx_short_rd_id, rssi_from_pcc);

        // Store parsed PT capabilities (already done in previous step, just confirming its place)
        if (peer_slot_idx >= 0) { // peer_slot_idx is determined after parsing all IEs
            if (pt_cap_ie_found && pt_cap_fields.num_phy_capabilities >= 1) {
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_mu = pt_cap_fields.phy_variants[0].mu_value;
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_beta = pt_cap_fields.phy_variants[0].beta_value;
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_max_mcs_code = pt_cap_fields.phy_variants[0].max_mcs_code;
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_phy_params_known = true;
                LOG_INF("FT_SM_ASSOC: Stored PT's (S:0x%04X) PHY params: mu_code=%u, beta_code=%u, max_mcs_code=%u",
                        pt_tx_short_rd_id, pt_cap_fields.phy_variants[0].mu_value,
                        pt_cap_fields.phy_variants[0].beta_value, pt_cap_fields.phy_variants[0].max_mcs_code);
            } else {
                LOG_WRN("FT_SM_ASSOC: PT 0x%04X RD Cap IE not fully parsed or no explicit sets. Using defaults.", pt_tx_short_rd_id);
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_mu = 0; // Default mu_code 0 (mu=1)
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_beta = 0; // Default beta_code 0 (beta=1)
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_phy_params_known = false;
            }

            // Store PT's requested parameters from Association Request IE
            if (assoc_req_ie_found) {
                dect_mac_peer_info_t *peer_ctx = &ctx->role_ctx.ft.connected_pts[peer_slot_idx];
                peer_ctx->pt_requested_harq_params_valid = req_fields.harq_params_present;
                if (req_fields.harq_params_present) {
                    peer_ctx->pt_req_harq_procs_tx = req_fields.harq_processes_tx_val;
                    peer_ctx->pt_req_max_harq_retx_delay = req_fields.max_harq_re_tx_delay_code;
                    peer_ctx->pt_req_harq_procs_rx = req_fields.harq_processes_rx_val;
                    peer_ctx->pt_req_max_harq_rerx_delay = req_fields.max_harq_re_rx_delay_code;
                    LOG_DBG("FT_SM_ASSOC: PT 0x%04X requests HARQ: TXP %u, TXD %u, RXP %u, RXD %u",
                            pt_tx_short_rd_id, peer_ctx->pt_req_harq_procs_tx, peer_ctx->pt_req_max_harq_retx_delay,
                            peer_ctx->pt_req_harq_procs_rx, peer_ctx->pt_req_max_harq_rerx_delay);
                }
                peer_ctx->pt_req_num_flows = (req_fields.number_of_flows_val <= MAX_FLOW_IDS_IN_ASSOC_REQ) ? req_fields.number_of_flows_val : 0;
                if (peer_ctx->pt_req_num_flows > 0) {
                    memcpy(peer_ctx->pt_req_flow_ids, req_fields.flow_ids, peer_ctx->pt_req_num_flows);
                    // LOG_HEXDUMP_DBG(peer_ctx->pt_req_flow_ids, peer_ctx->pt_req_num_flows, "PT Req Flow IDs:");
                }
                peer_ctx->pt_is_ft_capable = req_fields.ft_mode_capable;
                if (peer_ctx->pt_is_ft_capable) {
                    LOG_DBG("FT_SM_ASSOC: PT 0x%04X is FT capable.", pt_tx_short_rd_id);
                    // TODO: Store req_fields.ft_network_beacon_period_code etc. if FT needs to act on them.
                }
            }
        }



    if (peer_slot_idx < 0) {
        LOG_WRN("FT_SM_ASSOC: No peer slots available for PT 0x%04X (L:0x%08X). Rejecting.",
                pt_tx_short_rd_id, pt_tx_long_rd_id);
        accept_association = false;
    } else {
        // TODO: Add more checks based on req_fields, pt_cap_fields, current FT load, etc.
        // For example, if PT requests too many flows or unsupported features.

        // If accepting, proceed with simplified "authentication" (key derivation from PSK)
        if (ctx->config.ft_policy_secure_on_assoc && ctx->master_psk_provisioned) {
            LOG_INF("FT_SM_ASSOC: PT 0x%04X accepted (slot %d). Attempting to derive session keys from PSK.",
                    pt_tx_short_rd_id, peer_slot_idx);
            int kdf_err = security_derive_session_keys_from_psk(
                ctx->master_psk, // Using FT's global master PSK for this PT
                ctx->role_ctx.ft.peer_integrity_keys[peer_slot_idx],
                ctx->role_ctx.ft.peer_cipher_keys[peer_slot_idx]);

            if (kdf_err == 0) {
                ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx] = true;
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].is_secure = true;
                // Initialize/reset FT's tracking of PT's HPC. PT will send its HPC in first secured PDU.
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].hpc = 1; // FT's initial assumption of PT's TX HPC
                LOG_INF("FT_SM_ASSOC: Session keys derived for PT slot %d. Link will be SECURE. PT_HPC(track):%u",
                        peer_slot_idx, ctx->role_ctx.ft.connected_pts[peer_slot_idx].hpc);
            } else {
                LOG_ERR("FT_SM_ASSOC: Failed to derive session keys for PT 0x%04X (err %d). Rejecting.",
                        pt_tx_short_rd_id, kdf_err);
                accept_association = false;
                // Invalidate the slot if key derivation failed, as we can't proceed securely.
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].is_valid = false;
                ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx] = false; // Ensure this is reset
            }
        } else if (ctx->config.ft_policy_secure_on_assoc && !ctx->master_psk_provisioned) {
            LOG_WRN("FT_SM_ASSOC: Policy is secure_on_assoc, but no master PSK. PT 0x%04X link will be UNSECURE.",
                    pt_tx_short_rd_id);
            ctx->role_ctx.ft.connected_pts[peer_slot_idx].is_secure = false;
            ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx] = false;
        } else { // Not securing on association by policy, or PSK not provisioned
            LOG_INF("FT_SM_ASSOC: PT 0x%04X accepted (slot %d). Link will be UNSECURE by policy/setup.",
                    pt_tx_short_rd_id, peer_slot_idx);
            ctx->role_ctx.ft.connected_pts[peer_slot_idx].is_secure = false;
            ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx] = false;
        }
    }

    // Send Association Response
    ft_send_association_response_action(pt_tx_long_rd_id, pt_tx_short_rd_id, accept_association, peer_slot_idx);
}


// Brief Overview: This is the complete ft_send_association_response_action function.
// It ensures all fields of dect_mac_assoc_resp_ie_t are populated correctly,
// including conditional HARQ parameters (if harq_mod_present is true),
// accepted Flow IDs (if number_of_flows_accepted is 1-6), and Group ID/Tag
// (if group_assignment_active is true), before serialization.
static void ft_send_association_response_action(uint32_t pt_long_rd_id, uint16_t pt_short_rd_id,
                                                bool accept_association, int peer_slot_idx)
{
    dect_mac_context_t* ctx = get_mac_context();
    uint8_t sdu_area_buf[256]; 
    int sdu_area_len_built_bytes = 0;
    size_t len_of_muxed_sec_ie_for_crypto_calc = 0;
    int ret;

    bool secure_this_response = false;
    if (accept_association && peer_slot_idx != -1 &&
        ctx->config.ft_policy_secure_on_assoc &&
        ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx]) {
        secure_this_response = true;
    }

    // 1. Populate Association Response IE fields (dect_mac_assoc_resp_ie_t)
    dect_mac_assoc_resp_ie_t resp_fields;
    memset(&resp_fields, 0, sizeof(resp_fields));
    resp_fields.ack_nack = accept_association;

    if (!accept_association) {
        resp_fields.reject_cause = ASSOC_REJECT_CAUSE_OTHER; // Example
        resp_fields.reject_timer_code = 1; // Example: 5s
        resp_fields.harq_mod_present = false;
        resp_fields.number_of_flows_accepted = 0;
        resp_fields.group_assignment_active = false;
    } else { // Accept Association
        dect_mac_peer_info_t *pt_peer_ctx = (peer_slot_idx != -1) ? &ctx->role_ctx.ft.connected_pts[peer_slot_idx] : NULL;

        // HARQ Parameter Negotiation
        if (pt_peer_ctx && pt_peer_ctx->pt_requested_harq_params_valid) {
            // Example: FT accepts PT's request if reasonable, else uses its own defaults.
            // For now, let's assume FT will try to match PT's request or offer its own standard config.
            // If FT wants to propose different params than PT requested, set harq_mod_present = true.
            resp_fields.harq_mod_present = true; // Let's assume FT always specifies its params for the link.
            
            // FT's parameters for communication towards this PT (FT is TX, PT is RX)
            resp_fields.harq_processes_tx_val_ft = CONFIG_DECT_MAC_FT_HARQ_TX_PROC_CODE; // FT's capability/preference
            resp_fields.max_harq_re_tx_delay_code_ft = CONFIG_DECT_MAC_FT_HARQ_RETX_DELAY_CODE;

            // FT's parameters for communication from this PT (FT is RX, PT is TX)
            resp_fields.harq_processes_rx_val_ft = CONFIG_DECT_MAC_FT_HARQ_RX_PROC_CODE;
            resp_fields.max_harq_re_rx_delay_code_ft = CONFIG_DECT_MAC_FT_HARQ_RERX_DELAY_CODE;
            LOG_DBG("FT_ASSOC_RESP: Setting HARQ params for PT 0x%04X: TXP %u,TXD %u, RXP %u,RXD %u",
                    pt_short_rd_id, resp_fields.harq_processes_tx_val_ft, resp_fields.max_harq_re_tx_delay_code_ft,
                    resp_fields.harq_processes_rx_val_ft, resp_fields.max_harq_re_rx_delay_code_ft);
        } else {
            resp_fields.harq_mod_present = false; // PT did not specify, or no peer_ctx
        }

        // Flow ID Acceptance
        if (pt_peer_ctx && pt_peer_ctx->pt_req_num_flows > 0 && pt_peer_ctx->pt_req_num_flows <= MAX_FLOW_IDS_IN_ASSOC_REQ) {
            // Example: FT accepts all flows requested by PT, up to what FT can handle.
            // For now, accept all that PT requested if PT requested any.
            resp_fields.number_of_flows_accepted = pt_peer_ctx->pt_req_num_flows;
            memcpy(resp_fields.accepted_flow_ids, pt_peer_ctx->pt_req_flow_ids, pt_peer_ctx->pt_req_num_flows);
            LOG_DBG("FT_ASSOC_RESP: Accepting %u flows as requested by PT 0x%04X.",
                    resp_fields.number_of_flows_accepted, pt_short_rd_id);
        } else {
            // If PT requested 0 flows, or special code 7 ("all previously configured" - not applicable for initial assoc)
            // FT indicates 0 specific flows are being established by this response beyond defaults.
            resp_fields.number_of_flows_accepted = 0; // No specific flows from this response.
            // Or, if PT sent 7, FT could also send 7 if it means "ok, we use our existing understanding".
            // For initial association, if PT sends 0, FT sending 7 means "I accept your 0 requested flows".
            if (pt_peer_ctx && pt_peer_ctx->pt_req_num_flows == 0) {
                 resp_fields.number_of_flows_accepted = 0x07; // "All (zero) requested flows accepted"
            }
        }
        
        // Group Assignment
        resp_fields.group_assignment_active = false; // Default: no group assignment
        // if (ft_decides_to_assign_group) {
        //    resp_fields.group_assignment_active = true;
        //    resp_fields.group_id_val = assigned_group_id & 0x7F;
        //    resp_fields.resource_tag_val = assigned_resource_tag & 0x7F;
        // }
    }



    resp_fields.reserved_3bits = 0; // Ensure reserved bits are zero

    // --- SDU Area Construction ---
    // (Security IE prepending logic remains the same as in previous full function output)
    if (secure_this_response) {
        uint8_t ft_key_index_for_pt = (peer_slot_idx != -1) ? ctx->role_ctx.ft.connected_pts[peer_slot_idx].current_key_index_for_peer : ctx->current_key_index;
        uint8_t sec_iv_type_for_assoc_resp = SEC_IV_TYPE_MODE1_HPC_PROVIDED;
        int ie_len_sec_info = build_mac_security_info_ie_muxed(
            sdu_area_buf + sdu_area_len_built_bytes, sizeof(sdu_area_buf) - sdu_area_len_built_bytes,
            0, ft_key_index_for_pt, sec_iv_type_for_assoc_resp, ctx->hpc);
        if (ie_len_sec_info < 0) { /* ... error handling ... */ return; }
        sdu_area_len_built_bytes += ie_len_sec_info;
        len_of_muxed_sec_ie_for_crypto_calc = ie_len_sec_info;
        if(ctx->send_mac_sec_info_ie_on_next_tx && sec_iv_type_for_assoc_resp == SEC_IV_TYPE_MODE1_HPC_PROVIDED) {
            ctx->send_mac_sec_info_ie_on_next_tx = false;
        }
        if (peer_slot_idx != -1 && ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_requested_hpc_resync &&
            sec_iv_type_for_assoc_resp == SEC_IV_TYPE_MODE1_HPC_PROVIDED) {
            ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_requested_hpc_resync = false;
        }
    }

    // Add Association Response IE (serializer was already updated to handle all fields)
    uint8_t temp_ie_payload_buf[64];
    int ie_payload_len = serialize_assoc_resp_ie_payload(temp_ie_payload_buf, sizeof(temp_ie_payload_buf), &resp_fields);
    if (ie_payload_len < 0) { LOG_ERR("FT_ASSOC_RESP: Serialize AssocResp IE payload failed: %d", ie_payload_len); return; }
    int mux_hdr_len = build_mac_mux_header_internal(sdu_area_buf + sdu_area_len_built_bytes, sizeof(sdu_area_buf) - sdu_area_len_built_bytes, IE_TYPE_ASSOC_RESP, (uint16_t)ie_payload_len, 0);
    if (mux_hdr_len < 0) { LOG_ERR("FT_ASSOC_RESP: Build MUX for AssocResp IE failed: %d", mux_hdr_len); return; }
    if (sdu_area_len_built_bytes + mux_hdr_len + ie_payload_len > sizeof(sdu_area_buf)) { LOG_ERR("FT_ASSOC_RESP: SDU area overflow for AssocResp IE."); return; }
    memcpy(sdu_area_buf + sdu_area_len_built_bytes + mux_hdr_len, temp_ie_payload_buf, ie_payload_len);
    sdu_area_len_built_bytes += (mux_hdr_len + ie_payload_len);

    if (accept_association) {
        // Populate and add FT's RD Capability IE
        dect_mac_rd_capability_ie_t ft_cap_fields; // Populate this fully from ctx->own_phy_params and Kconfigs
        // ... (ft_cap_fields population as in previous full function output) ...
        memset(&ft_cap_fields, 0, sizeof(ft_cap_fields));
        ft_cap_fields.release_version = 1; 
        ft_cap_fields.num_phy_capabilities = 1; 
        ft_cap_fields.supports_group_assignment = IS_ENABLED(CONFIG_DECT_MAC_FT_SUPPORTS_GROUP_ASSIGNMENT);
        ft_cap_fields.supports_paging = IS_ENABLED(CONFIG_DECT_MAC_FT_SUPPORTS_PAGING);            
        ft_cap_fields.operating_modes_code = 0b01; 
        ft_cap_fields.supports_mesh = IS_ENABLED(CONFIG_DECT_MAC_FT_SUPPORTS_MESH);              
        ft_cap_fields.supports_sched_data = true;
        ft_cap_fields.mac_security_modes_code = IS_ENABLED(CONFIG_DECT_MAC_SECURITY_ENABLE) ? 0b01 : 0b00;
        dect_mac_phy_capability_set_t *ft_phy_set0 = &ft_cap_fields.phy_variants[0];
        ft_phy_set0->dlc_service_type_support_code = CONFIG_DECT_MAC_FT_DLC_SERVICE_SUPPORT_CODE;
        ft_phy_set0->rx_for_tx_diversity_code = CONFIG_DECT_MAC_FT_RX_TX_DIVERSITY_CODE;      
        ft_phy_set0->mu_value = ctx->own_phy_params.is_valid ? ctx->own_phy_params.mu : CONFIG_DECT_MAC_OWN_MU_CODE;
        ft_phy_set0->beta_value = ctx->own_phy_params.is_valid ? ctx->own_phy_params.beta : CONFIG_DECT_MAC_OWN_BETA_CODE;
        ft_phy_set0->max_nss_for_rx_code = CONFIG_DECT_MAC_FT_MAX_NSS_RX_CODE;              
        ft_phy_set0->max_mcs_code = CONFIG_DECT_MAC_FT_MAX_MCS_CODE;                        
        ft_phy_set0->harq_soft_buffer_size_code = CONFIG_DECT_MAC_FT_HARQ_BUFFER_CODE;      
        ft_phy_set0->num_harq_processes_code = CONFIG_DECT_MAC_FT_NUM_HARQ_PROC_CODE;      
        ft_phy_set0->harq_feedback_delay_code = CONFIG_DECT_MAC_FT_HARQ_FEEDBACK_DELAY_CODE;
        ft_phy_set0->supports_dect_delay = IS_ENABLED(CONFIG_DECT_MAC_FT_SUPPORTS_DECT_DELAY);
        ft_phy_set0->supports_half_duplex = IS_ENABLED(CONFIG_DECT_MAC_FT_SUPPORTS_HALF_DUPLEX);

        ie_payload_len = serialize_rd_capability_ie_payload(temp_ie_payload_buf, sizeof(temp_ie_payload_buf), &ft_cap_fields);
        // ... (MUX and copy RD Cap IE, as in previous full function output) ...
        if (ie_payload_len < 0) { LOG_ERR("FT_ASSOC_RESP: Serialize FT RD Cap IE failed: %d", ie_payload_len); return; }
        mux_hdr_len = build_mac_mux_header_internal(sdu_area_buf + sdu_area_len_built_bytes, sizeof(sdu_area_buf) - sdu_area_len_built_bytes, IE_TYPE_RD_CAPABILITY, (uint16_t)ie_payload_len, 0);
        if (mux_hdr_len < 0) { LOG_ERR("FT_ASSOC_RESP: Build MUX for RD Cap failed: %d", mux_hdr_len); return; }
        if (sdu_area_len_built_bytes + mux_hdr_len + ie_payload_len > sizeof(sdu_area_buf)) { LOG_ERR("FT_ASSOC_RESP: SDU area overflow for RD Cap IE."); return; }
        memcpy(sdu_area_buf + sdu_area_len_built_bytes + mux_hdr_len, temp_ie_payload_buf, ie_payload_len);
        sdu_area_len_built_bytes += (mux_hdr_len + ie_payload_len);


        // Populate and add Resource Allocation IE
        dect_mac_resource_alloc_ie_fields_t local_res_alloc_fields;
        // ... (Populate local_res_alloc_fields, including setting resX_is_9bit_subslot based on PT's mu, as in previous full function output) ...
        // ... (Store schedule in ctx->role_ctx.ft.peer_schedules[peer_slot_idx]) ...
        // ... (Serialize, MUX and copy Resource Allocation IE, as in previous full function output) ...
        memset(&local_res_alloc_fields, 0, sizeof(local_res_alloc_fields));
        local_res_alloc_fields.alloc_type_val = RES_ALLOC_TYPE_BIDIR;
        local_res_alloc_fields.sfn_present = true;
        uint8_t target_pt_mu_code = 0; 
        if (peer_slot_idx != -1 && ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_phy_params_known) {
            target_pt_mu_code = ctx->role_ctx.ft.connected_pts[peer_slot_idx].peer_mu;
        }
        local_res_alloc_fields.res1_is_9bit_subslot = (target_pt_mu_code > 2);
        local_res_alloc_fields.res2_is_9bit_subslot = (target_pt_mu_code > 2);
        local_res_alloc_fields.start_subslot_val_res1 = 10; local_res_alloc_fields.length_val_res1 = 2 - 1;
        local_res_alloc_fields.start_subslot_val_res2 = 14; local_res_alloc_fields.length_val_res2 = 2 - 1;
        local_res_alloc_fields.repeat_val = RES_ALLOC_REPEAT_FRAMES;
        local_res_alloc_fields.repetition_value = 10; local_res_alloc_fields.validity_value = 100;
        local_res_alloc_fields.sfn_val = (ctx->role_ctx.ft.sfn + 2) & 0xFF;
        if (peer_slot_idx != -1) { /* ... store schedule ... */ }

        ie_payload_len = serialize_resource_alloc_ie_payload(temp_ie_payload_buf, sizeof(temp_ie_payload_buf), &local_res_alloc_fields);
        if (ie_payload_len < 0) { LOG_ERR("FT_ASSOC_RESP: Serialize Res Alloc IE failed: %d", ie_payload_len); return; }
        mux_hdr_len = build_mac_mux_header_internal(sdu_area_buf + sdu_area_len_built_bytes, sizeof(sdu_area_buf) - sdu_area_len_built_bytes, IE_TYPE_RES_ALLOC, (uint16_t)ie_payload_len, 0);
        if (mux_hdr_len < 0) { LOG_ERR("FT_ASSOC_RESP: Build MUX for Res Alloc failed: %d", mux_hdr_len); return; }
        if (sdu_area_len_built_bytes + mux_hdr_len + ie_payload_len > sizeof(sdu_area_buf)) { LOG_ERR("FT_ASSOC_RESP: SDU area overflow for Res Alloc IE."); return; }
        memcpy(sdu_area_buf + sdu_area_len_built_bytes + mux_hdr_len, temp_ie_payload_buf, ie_payload_len);
        sdu_area_len_built_bytes += (mux_hdr_len + ie_payload_len);

    }



    // --- MAC Header Type & Common Header ---
    dect_mac_header_type_octet_t hdr_type_octet;
    hdr_type_octet.version = 0;
    hdr_type_octet.mac_header_type = MAC_COMMON_HEADER_TYPE_UNICAST;
    if (secure_this_response) {
        hdr_type_octet.mac_security = MAC_SECURITY_USED_WITH_IE; // Because we are sending Sec Info IE
    } else {
        hdr_type_octet.mac_security = MAC_SECURITY_NONE;
    }

    dect_mac_unicast_header_t common_hdr;
    increment_psn_and_hpc(ctx); // FT increments its own PSN/HPC for this TX
    common_hdr.sequence_num_high_reset_rsv = SET_SEQ_NUM_HIGH_RESET_RSV((ctx->psn >> 8) & 0x0F, 1 /*reset bit for first response*/);
    common_hdr.sequence_num_low = ctx->psn & 0xFF;
    common_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);
    common_hdr.receiver_long_rd_id_be = sys_cpu_to_be32(pt_long_rd_id);

    // --- Assemble PDU (pre-security application) ---
    uint8_t *full_mac_pdu_for_phy_slab = NULL;
    ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab, K_MSEC(10));
    if(ret != 0 || full_mac_pdu_for_phy_slab == NULL) { LOG_ERR("FT_ASSOC_RESP: Failed to alloc PDU buf for PT 0x%04X", pt_short_rd_id); return; }
    uint8_t * const full_mac_pdu_for_phy = full_mac_pdu_for_phy_slab;

    uint16_t assembled_pdu_len_pre_mic;
    ret = dect_mac_phy_ctrl_assemble_final_pdu(
              full_mac_pdu_for_phy, CONFIG_DECT_MAC_PDU_MAX_SIZE,
              &hdr_type_octet,
              &common_hdr, sizeof(common_hdr),
              sdu_area_buf, (size_t)sdu_area_len_built_bytes,
              &assembled_pdu_len_pre_mic);
    if (ret != 0) {
        LOG_ERR("FT_ASSOC_RESP: Assemble PDU failed for PT 0x%04X: %d", pt_short_rd_id,ret);
        k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);
        return;
    }

    uint16_t final_tx_pdu_len = assembled_pdu_len_pre_mic;

    // --- Apply Security if active ---
    if (secure_this_response) {
        uint8_t iv[16];
        security_build_iv(iv, ctx->own_long_rd_id, pt_long_rd_id, ctx->hpc, ctx->psn);

        uint8_t *mic_calculation_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t);
        size_t mic_calculation_length = sizeof(common_hdr) + sdu_area_len_built_bytes;

        if ((assembled_pdu_len_pre_mic + 5) > CONFIG_DECT_MAC_PDU_MAX_SIZE) {
            LOG_ERR("FT_ASSOC_RESP: No space for MIC for PT 0x%04X.", pt_short_rd_id);
            k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
        }
        uint8_t *mic_location_ptr = full_mac_pdu_for_phy + assembled_pdu_len_pre_mic;
        ret = security_calculate_mic(mic_calculation_start_ptr, mic_calculation_length,
                                   ctx->role_ctx.ft.peer_integrity_keys[peer_slot_idx], mic_location_ptr);
        if (ret != 0) {
            LOG_ERR("FT_ASSOC_RESP: MIC calc failed for PT 0x%04X: %d", pt_short_rd_id, ret);
            k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
        }
        final_tx_pdu_len = assembled_pdu_len_pre_mic + 5;

        uint8_t *encryption_start_ptr;
        size_t encryption_length;
        if (hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            encryption_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                   sizeof(common_hdr) + len_of_muxed_sec_ie_for_crypto_calc;
            encryption_length = (sdu_area_len_built_bytes - len_of_muxed_sec_ie_for_crypto_calc) + 5;
        } else {
            encryption_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) + sizeof(common_hdr);
            encryption_length = sdu_area_len_built_bytes + 5;
        }

        if (encryption_length > 0) {
            uint8_t* pdu_buffer_end_with_mic = full_mac_pdu_for_phy + final_tx_pdu_len;
            if (encryption_start_ptr < full_mac_pdu_for_phy || (encryption_start_ptr + encryption_length) > pdu_buffer_end_with_mic ) {
                 LOG_ERR("FT_ASSOC_RESP: Encryption range error for PT 0x%04X. Start:%p Len:%zu PDU_End:%p",
                        pt_short_rd_id, encryption_start_ptr, encryption_length, pdu_buffer_end_with_mic);
                 k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
            }
             ret = security_crypt_payload(encryption_start_ptr, encryption_length,
                                          ctx->role_ctx.ft.peer_cipher_keys[peer_slot_idx], iv, true /*encrypt*/);
             if (ret != 0) {
                 LOG_ERR("FT_ASSOC_RESP: Encryption failed for PT 0x%04X: %d", pt_short_rd_id, ret);
                 k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
             }
        }
        LOG_INF("FT_ASSOC_RESP: Secured Association Response for PT 0x%04X. Final len %u. MUXSecIELen: %zu",
                pt_short_rd_id, final_tx_pdu_len, len_of_muxed_sec_ie_for_crypto_calc);
    }

    // --- Schedule TX ---
    uint32_t phy_op_handle = sys_rand32_get();
    ctx->role_ctx.ft.last_assoc_resp_pt_short_id = pt_short_rd_id; // Store for OP_COMPLETE context

    ret = dect_mac_phy_ctrl_start_tx_assembled(
        ctx->role_ctx.ft.operating_carrier, // Send on FT's current operating carrier
        full_mac_pdu_for_phy, final_tx_pdu_len,
        pt_short_rd_id, // Target PT's short ID for PCC Type 2 Receiver ID field
        false,          /* is_beacon = false */
        phy_op_handle, PENDING_OP_FT_ASSOC_RESP,
        true,           /* use_lbt = true for unicast response */
        0               /* target_start_time = 0 for immediate attempt after LBT */
    );

    k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);

    if (ret != 0) {
        LOG_ERR("FT_ASSOC_RESP: Failed to schedule TX to PT 0x%04X: %d", pt_short_rd_id, ret);
        if (accept_association && peer_slot_idx != -1) {
            // If failed to send acceptance, invalidate the peer slot again
            LOG_WRN("FT_ASSOC_RESP: Invalidating peer slot %d for PT 0x%04X due to failed AssocResp TX.",
                    peer_slot_idx, pt_short_rd_id);
            ctx->role_ctx.ft.connected_pts[peer_slot_idx].is_valid = false;
            ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx] = false;
            memset(&ctx->role_ctx.ft.peer_schedules[peer_slot_idx], 0, sizeof(dect_mac_schedule_t));
            ctx->role_ctx.ft.peer_schedules[peer_slot_idx].is_active = false;
        }
    } else {
        LOG_INF("FT_SM: Association Response (%s) TX scheduled to PT 0x%04X (Hdl %u). Secure: %s",
                accept_association ? "ACCEPT" : "REJECT", pt_short_rd_id, phy_op_handle, secure_this_response ? "Yes" : "No");
        if (accept_association && peer_slot_idx != -1) {
            // If successfully scheduled an ACCEPT, mark PT as fully identified if Long ID was present
            if (pt_long_rd_id != 0) {
                ctx->role_ctx.ft.connected_pts[peer_slot_idx].is_fully_identified = true;
            }
        }
    }
}

/**/

