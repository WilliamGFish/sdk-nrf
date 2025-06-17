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
    // Example:
    if (CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN > 0) ctx->role_ctx.ft.dcs_candidate_channels[0] = DEFAULT_DECT_CARRIER;
    if (CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN > 1) ctx->role_ctx.ft.dcs_candidate_channels[1] = DEFAULT_DECT_CARRIER + 1; // Example, ensure valid channel
    if (CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN > 2) ctx->role_ctx.ft.dcs_candidate_channels[2] = DEFAULT_DECT_CARRIER - 1; // Example, ensure valid channel
    // ... populate others if CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN is larger

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



static void populate_cb_fields_from_ctx(dect_mac_context_t *ctx, dect_mac_cluster_beacon_ie_fields_t *cb_fields) {
    memset(cb_fields, 0, sizeof(dect_mac_cluster_beacon_ie_fields_t));

    cb_fields->sfn = ctx->role_ctx.ft.sfn;
    cb_fields->tx_power_present = true; // FT should always advertise its max TX power for the cluster
    cb_fields->clusters_max_tx_power_code = ctx->config.default_tx_power_code; // Or a specific cluster max
    cb_fields->power_constraints_active = false; // Example: FT has no constraints to impose on PTs via this

    // Frame Offset: If FT's transmission is offset from SFN boundary. Assume 0 for now.
    cb_fields->frame_offset_present = false;
    // cb_fields->frame_offset_is_16bit = (ctx->phy_link_params.mu > 4); // Requires mu storage
    // cb_fields->frame_offset_value = ctx->role_ctx.ft.frame_offset_subslots; // If used

    // Next Cluster Channel / Time To Next (for multi-frequency FTs or handover hints - advanced)
    cb_fields->next_channel_present = false;
    cb_fields->time_to_next_present = false;
    // cb_fields->next_cluster_channel_val = ...;
    // cb_fields->time_to_next_us = ...;

    // Convert ms periods from Kconfig to ETSI codes
    // ETSI Table 6.4.2.2-1: Network Beacon Period
    // Codes: 0=50ms, 1=100ms, 2=500ms, 3=1000ms, 4=1500ms, 5=2000ms, 6=4000ms. Others reserved.
    // Mapping Kconfig to codes (example, needs full mapping based on ETSI codes)
    if (ctx->config.ft_network_beacon_period_ms <= 50) cb_fields->network_beacon_period_code = 0;
    else if (ctx->config.ft_network_beacon_period_ms <= 100) cb_fields->network_beacon_period_code = 1;
    else if (ctx->config.ft_network_beacon_period_ms <= 500) cb_fields->network_beacon_period_code = 2;
    else if (ctx->config.ft_network_beacon_period_ms <= 1000) cb_fields->network_beacon_period_code = 3;
    // ... add other mappings ...
    else cb_fields->network_beacon_period_code = 3; // Default to 1000ms code if no match

    // ETSI Table 6.4.2.2-1: Cluster Beacon Period
    // Codes: 0=10ms, 1=50ms, 2=100ms, ... 6=4000ms, 7=8000ms, 8=16000ms, 9=32000ms. Others reserved.
    if (ctx->config.ft_cluster_beacon_period_ms <= 10) cb_fields->cluster_beacon_period_code = 0;
    else if (ctx->config.ft_cluster_beacon_period_ms <= 50) cb_fields->cluster_beacon_period_code = 1;
    else if (ctx->config.ft_cluster_beacon_period_ms <= 100) cb_fields->cluster_beacon_period_code = 2;
    // ... add other mappings ...
    else cb_fields->cluster_beacon_period_code = 2; // Default to 100ms code

    // These are typically PT parameters, but FT can signal defaults/recommendations
    cb_fields->count_to_trigger_code = 7; // Example: 8 beacons (ETSI Table 6.4.2.3-1 maps codes)
    cb_fields->rel_quality_code = 2;      // Example: 6dB (codes 0-3 for 0,3,6,9 dB)
    cb_fields->min_quality_code = 1;      // Example: 3dB

    // Current Cluster Channel (ETSI Table 6.4.2.3-1): This field is only present IF Next Cluster Channel is present
    // AND the next channel is different from the current one.
    // Since we set next_channel_present = false, this field is implicitly not included
    // as per ETSI Figure 6.4.2.3-1.
    // If next_channel_present was true, logic to set current_cluster_channel_val would be here.
}






static uint64_t calculate_target_modem_time(dect_mac_context_t *ctx, uint64_t sfn_zero_anchor_time,
                                            uint8_t sfn_of_anchor_relevance, uint8_t target_sfn_val,
                                            uint16_t target_subslot_idx)
{
    if (sfn_zero_anchor_time == 0) {
        LOG_WRN("CALC_TIME: SFN Zero Anchor is 0. Cannot calculate precise target time.");
        // Return a time slightly in the future as a fallback.
        return ctx->last_known_modem_time +
               modem_us_to_ticks(FRAME_DURATION_MS_NOMINAL * 1000,
                                 NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
    }

    uint32_t frame_duration_ticks = (uint32_t)FRAME_DURATION_MS_NOMINAL *
                                    (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ / 1000U);
    uint32_t subslot_duration_ticks = get_subslot_duration_ticks(ctx);

    // Calculate the number of frames between the anchor's SFN and the target SFN,
    // correctly handling wraparound.
    int16_t sfn_diff = (int16_t)target_sfn_val - (int16_t)sfn_of_anchor_relevance;
    if (sfn_diff < -128) { // Target SFN has wrapped around relative to anchor SFN
        sfn_diff += 256;
    } else if (sfn_diff > 128) { // Anchor SFN has wrapped around relative to target SFN
        sfn_diff -= 256;
    }

    // The anchor relevance time is the modem time when SFN was sfn_of_anchor_relevance
    uint64_t anchor_relevance_time = sfn_zero_anchor_time +
                                     ((uint64_t)sfn_of_anchor_relevance * frame_duration_ticks);

    uint64_t target_frame_start_time = anchor_relevance_time +
                                       ((int64_t)sfn_diff * frame_duration_ticks);

    uint64_t target_subslot_offset_in_frame = (uint64_t)target_subslot_idx * subslot_duration_ticks;

    return target_frame_start_time + target_subslot_offset_in_frame;
}



static void ft_select_operating_carrier_and_start_beaconing(const struct nrf_modem_dect_phy_rssi_event *optional_last_rssi_event_data) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != MAC_STATE_FT_SCANNING) {
        LOG_WRN("FT_DCS_SEL: Not in SCANNING state (%s), ignoring request to select carrier.", dect_mac_state_to_str(ctx->state));
        return;
    }
    if (!ctx->role_ctx.ft.dcs_scan_complete && optional_last_rssi_event_data == NULL) {
        LOG_WRN("FT_DCS_SEL: Called to select carrier, but scan not marked complete and no final RSSI event given.");
        // This might happen if a scan op failed catastrophically.
        // Attempt to select based on whatever data is available.
    }


    // Select the best channel from ctx->role_ctx.ft.dcs_candidate_rssi_avg
    int16_t best_rssi = INT16_MAX; // Looking for the lowest (most negative) RSSI
    uint16_t selected_carrier = 0;
    int best_idx = -1;

    LOG_INF("FT_DCS_SEL: Selecting best carrier from %d candidates:", CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN);
    for (int i = 0; i < CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN; i++) {
        if (ctx->role_ctx.ft.dcs_candidate_rssi_avg[i] != NRF_MODEM_DECT_PHY_RSSI_NOT_MEASURED) { // Check if scanned
            LOG_DBG("  Candidate %d: C%u, AvgRSSI: %.1f dBm", i,
                    ctx->role_ctx.ft.dcs_candidate_channels[i],
                    (float)ctx->role_ctx.ft.dcs_candidate_rssi_avg[i] / 2.0f);
            // Simple selection: lowest average RSSI that is below a general "too noisy" threshold
            // TODO: Add busy_percent and other metrics to selection criteria.
            if (ctx->role_ctx.ft.dcs_candidate_rssi_avg[i] < best_rssi &&
                ctx->role_ctx.ft.dcs_candidate_rssi_avg[i] < (ctx->config.rssi_threshold_min_dbm * 2 + 20*2 /* e.g. -65dBm threshold */ ) ) {
                best_rssi = ctx->role_ctx.ft.dcs_candidate_rssi_avg[i];
                selected_carrier = ctx->role_ctx.ft.dcs_candidate_channels[i];
                best_idx = i;
            }
        }
    }

    if (best_idx != -1 && selected_carrier != 0) {
        ctx->role_ctx.ft.operating_carrier = selected_carrier;
        LOG_INF("FT_DCS_SEL: Best carrier selected: C%u (idx %d) with Avg RSSI %.1f dBm.",
                selected_carrier, best_idx, (float)best_rssi / 2.0f);
    } else {
        LOG_WRN("FT_DCS_SEL: No suitable quiet channel found from scan. Defaulting to C%u.", DEFAULT_DECT_CARRIER);
        ctx->role_ctx.ft.operating_carrier = DEFAULT_DECT_CARRIER;
    }

    // Update advertised RACH channel based on selected operating carrier
    ctx->role_ctx.ft.advertised_rach_params.rach_operating_channel = ctx->role_ctx.ft.operating_carrier;
    ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.channel_abs_freq_num = ctx->role_ctx.ft.operating_carrier;
    ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.channel_field_present = true; // Assuming RACH is on op channel

    ft_start_beaconing_actions(); // This transitions state and starts beacon timer
}


static void ft_start_beaconing_actions(void) {
    dect_mac_context_t* ctx = get_mac_context();
    dect_mac_change_state(MAC_STATE_FT_BEACONING);
    LOG_INF("FT SM: Entered BEACONING state on carrier %u.", ctx->role_ctx.ft.operating_carrier);

    ctx->role_ctx.ft.sfn = 0;
    uint32_t first_beacon_delay_ms = 50;
    uint64_t current_time_for_anchor = (ctx->last_known_modem_time == 0) ? modem_us_to_ticks(1000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ) : ctx->last_known_modem_time;
    ctx->ft_sfn_zero_modem_time_anchor = current_time_for_anchor + modem_us_to_ticks(first_beacon_delay_ms * 1000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
    ctx->current_sfn_at_anchor_update = 0;

    k_timer_start(&ctx->role_ctx.ft.beacon_timer, K_MSEC(first_beacon_delay_ms), K_MSEC(ctx->config.ft_cluster_beacon_period_ms));
}





static void ft_send_beacon_action(void) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != MAC_STATE_FT_BEACONING) {
        LOG_WRN("FT SM: Beacon TX attempt, but not in BEACONING state (%s). Aborting.",
                dect_mac_state_to_str(ctx->state));
        // Restart timer with a sensible period if it was stopped or for next attempt
        // Ensure ft_cluster_beacon_period_ms is not zero to avoid K_MSEC(0) which might be K_NO_WAIT
        uint32_t beacon_period_ms = ctx->config.ft_cluster_beacon_period_ms;
        if (beacon_period_ms == 0) {
            beacon_period_ms = 100; // Fallback default if config is 0
            LOG_WRN("FT_BEACON_ACT: ft_cluster_beacon_period_ms is 0, using fallback %ums", beacon_period_ms);
        }
        k_timer_start(&ctx->role_ctx.ft.beacon_timer, K_MSEC(beacon_period_ms), K_MSEC(beacon_period_ms));
        return;
    }

    uint8_t mac_sdu_area_buf[128]; // Sufficient for MUXed (Cluster Beacon IE + RACH Info IE)
    int sdu_area_len;

    dect_mac_cluster_beacon_ie_fields_t cb_fields;
    populate_cb_fields_from_ctx(ctx, &cb_fields); // Populates cb_fields based on current FT context

    // Pointer to the RACH Info IE fields that the FT will advertise.
    // This structure is part of the FT's context and should be updated by DCS/configuration.
    dect_mac_rach_info_ie_fields_t *rach_adv_fields = &ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields;
    
    // Ensure mu_value_for_ft_beacon is set correctly based on FT's operational mu.
    // This 'mu' should reflect the numerology the FT is currently operating with and advertising.
    // It should be stored in the MAC context, e.g., ctx->phy_link_params.mu (assuming such a field exists and is valid).
    // TODO: Ensure ctx->phy_link_params.mu (or equivalent for FT's own PHY config) is correctly initialized/updated.
    uint8_t ft_operational_mu = 1; // Default/Placeholder if not found in context for FT's own mu
    if (ctx->phy_link_params.is_valid && ctx->phy_link_params.mu > 0 && ctx->phy_link_params.mu <= 8) { // Example check
        ft_operational_mu = ctx->phy_link_params.mu;
    } else {
        LOG_WRN("FT_BEACON_ACT: FT operational mu not available or invalid in context (is_valid:%d, mu:%d). Defaulting to mu=1 for RACH IE.",
                ctx->phy_link_params.is_valid, ctx->phy_link_params.mu);
        // Consider if this warning should be an error or if defaulting is acceptable.
    }
    rach_adv_fields->mu_value_for_ft_beacon = ft_operational_mu;
    LOG_DBG("FT_BEACON_ACT: Setting RACH IE mu_value_for_ft_beacon to %u for beacon SFN %u",
            ft_operational_mu, ctx->role_ctx.ft.sfn);

    // Ensure other critical RACH params like operating channel are also up-to-date before serialization.
    // This should have been set by ft_select_operating_carrier_and_start_beaconing or similar config logic.
    if (rach_adv_fields->channel_abs_freq_num != ctx->role_ctx.ft.operating_carrier || !rach_adv_fields->channel_field_present) {
        LOG_INF("FT_BEACON_ACT: Updating RACH IE channel to current FT operating_carrier %u.", ctx->role_ctx.ft.operating_carrier);
        rach_adv_fields->channel_abs_freq_num = ctx->role_ctx.ft.operating_carrier;
        rach_adv_fields->channel_field_present = true; // RACH typically on op channel
    }
    // Other fields like start_subslot_index, num_subslots_or_slots, repetition_code, validity_frames,
    // response_window_subslots_val_minus_1, cwmin_sig_code, cwmax_sig_code, etc.,
    // are assumed to be correctly populated in ctx->role_ctx.ft.advertised_rach_params
    // by dect_mac_core_init or by the DCS logic (ft_select_operating_carrier_and_start_beaconing).

    sdu_area_len = build_beacon_sdu_area_content(mac_sdu_area_buf, sizeof(mac_sdu_area_buf),
                                                &cb_fields,
                                                rach_adv_fields); // Pass pointer to the (now updated) struct
    if (sdu_area_len < 0) {
        LOG_ERR("FT SM: Failed to build beacon SDU area content: %d", sdu_area_len);
        // Timer will fire again as it's periodic.
        return;
    }

    dect_mac_header_type_octet_t hdr_type_octet;
    hdr_type_octet.version = 0; // ETSI TS 103 636-4 Release 2
    hdr_type_octet.mac_security = MAC_SECURITY_NONE; // Beacons often unsecure for initial discovery
                                                    // TODO: Add logic for secured beacons if needed
    hdr_type_octet.mac_header_type = MAC_COMMON_HEADER_TYPE_BEACON;

    dect_mac_beacon_header_t common_beacon_hdr;
    // Network ID: MS24 bits from context, LSB part is in PHY Control Channel (PCC)
    common_beacon_hdr.network_id_ms24[0] = (uint8_t)((ctx->network_id_32bit >> 24) & 0xFF);
    common_beacon_hdr.network_id_ms24[1] = (uint8_t)((ctx->network_id_32bit >> 16) & 0xFF);
    common_beacon_hdr.network_id_ms24[2] = (uint8_t)((ctx->network_id_32bit >> 8) & 0xFF);
    common_beacon_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);

    uint8_t *full_mac_pdu_for_phy_slab = NULL;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab, K_MSEC(10)); // Timeout for buffer
    if(ret != 0 || full_mac_pdu_for_phy_slab == NULL) {
        LOG_ERR("FT SM: Failed to alloc PDU buf for beacon TX: %d. Skipping this beacon.", ret);
        return; // Timer will fire again
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
        return; // Timer will fire again
    }

    uint32_t phy_op_handle = sys_rand32_get();
    ctx->role_ctx.ft.sfn_for_last_beacon_tx = ctx->role_ctx.ft.sfn;

    // Calculate target start time for this beacon based on SFN
    uint64_t beacon_target_start_time = calculate_target_modem_time(ctx,
                                                                  ctx->ft_sfn_zero_modem_time_anchor,
                                                                  ctx->current_sfn_at_anchor_update, // SFN when anchor was set/updated
                                                                  ctx->role_ctx.ft.sfn, // Target SFN for this beacon
                                                                  0); // Beacons are at subslot 0 of the frame
    
    uint32_t min_prep_time_ticks = modem_us_to_ticks(ctx->phy_latency.idle_to_active_tx_us +
                                                     ctx->phy_latency.scheduled_operation_startup_us,
                                                     NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
    if (ctx->last_known_modem_time > 0 && beacon_target_start_time < (ctx->last_known_modem_time + min_prep_time_ticks)) {
        LOG_WRN("FT_BEACON_ACT: Target start %llu for SFN %u too soon (current %llu, prep %u). Sending immediate-ish.",
                beacon_target_start_time, ctx->role_ctx.ft.sfn, ctx->last_known_modem_time, min_prep_time_ticks);
        beacon_target_start_time = 0; // Request PHY to send as soon as possible
    }


    ret = dect_mac_phy_ctrl_start_tx_assembled(
        ctx->role_ctx.ft.operating_carrier,
        full_mac_pdu_for_phy, cleartext_pdu_len,
        0xFFFF, /* target_receiver_short_id for beacon is broadcast */
        true,   /* is_beacon = true */
        phy_op_handle, PENDING_OP_FT_BEACON,
        false,  /* use_lbt = false for beacons (typically on dedicated resources or FT manages CCA) */
        beacon_target_start_time);

    k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);

    if (ret != 0) {
        LOG_ERR("FT SM: Failed to schedule beacon TX for SFN %u: %d", ctx->role_ctx.ft.sfn, ret);
    } else {
        LOG_INF("FT SM: Beacon SFN %u TX scheduled on C%u (Hdl %u), TargetStart %llu",
                ctx->role_ctx.ft.sfn, ctx->role_ctx.ft.operating_carrier, phy_op_handle, beacon_target_start_time);
    }
    // Increment SFN for the next beacon period.
    ctx->role_ctx.ft.sfn = (ctx->role_ctx.ft.sfn + 1) & 0xFF;
    // The periodic timer will re-trigger ft_beacon_timer_expired_action for the next beacon.
}





static void ft_schedule_rach_listen_action(void) {
    dect_mac_context_t* ctx = get_mac_context();

    // Only listen for RACH if beaconing or has associated PTs (implies beaconing is active)
    if (ctx->state != MAC_STATE_FT_BEACONING && ctx->state != MAC_STATE_ASSOCIATED) {
        LOG_DBG("FT_RACH_LSN: Not in a state to listen for RACH (%s).", dect_mac_state_to_str(ctx->state));
        return;
    }
    if (ctx->pending_op_type != PENDING_OP_NONE) {
        LOG_DBG("FT_RACH_LSN: PHY op %s pending. Deferring RACH listen.", dect_pending_op_to_str(ctx->pending_op_type));
        return;
    }

    const dect_mac_rach_info_ie_fields_t *rach_adv_fields = &ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields;

    // 1. Determine the RACH operating carrier
    uint16_t rach_carrier = rach_adv_fields->channel_field_present ?
                            rach_adv_fields->channel_abs_freq_num :
                            ctx->role_ctx.ft.operating_carrier;
    if (rach_carrier == 0 || rach_carrier == 0xFFFF) {
        LOG_ERR("FT_RACH_LSN: Invalid RACH carrier 0x%04X configured. Cannot listen.", rach_carrier);
        return;
    }

    // 2. Calculate RACH resource length in subslots
    uint32_t rach_resource_len_subslots = rach_adv_fields->num_subslots_or_slots; // This is N (actual units)
    if (rach_adv_fields->length_type_is_slots) {
        // TODO: SUB_SLOTS_PER_ETSI_SLOT should be mu-dependent if ETSI slot definition varies with mu.
        // ETSI TS 103 636-3 Table 4.3-1: N_slot_symb varies (10,20,40,80). N_slot_subslot is N_slot_symb / 5.
        // So, yes, mu-dependent. For mu=1, N_slot_subslot = 10/5 = 2. For mu=2, 20/5=4.
        // Let's assume SUB_SLOTS_PER_ETSI_SLOT from context.h (e.g. 24) is for a specific mu, or we need better logic.
        // For now, using a fixed value, but this is a key point for mu-awareness.
        // ETSI 636-3, 4.4: "frame duration (10ms) and slot duration (0.41667ms)" - this implies fixed slot duration in time.
        // N_slot_subslot = T_slot / T_subslot. T_subslot = 5 * T_symb. T_symb depends on mu.
        // This implies SUB_SLOTS_PER_ETSI_SLOT is NOT fixed if T_slot_time is fixed.
        // However, Table 4.3-1 N_slot_subslot IS fixed for each mu.
        // Recheck: Slot is 0.41667ms. Subslot is 5 symbols.
        // mu=1, symb=41.6us, subslot=208.3us, slot/subslot = 0.41667ms / 0.20833ms = 2 subslots per slot.
        // mu=2, symb=20.8us, subslot=104.1us, slot/subslot = 0.41667ms / 0.1041us = 4 subslots per slot.
        // This means SUB_SLOTS_PER_ETSI_SLOT is indeed mu dependent.
        uint8_t subslots_per_etsi_slot_val = 2; // Default for mu=1
        uint8_t ft_mu = 1; // TODO: Get FT's actual operational mu
        if (ctx->phy_link_params.is_valid) ft_mu = ctx->phy_link_params.mu;
        if (ft_mu == 1) subslots_per_etsi_slot_val = 2;
        else if (ft_mu == 2) subslots_per_etsi_slot_val = 4;
        else if (ft_mu == 4) subslots_per_etsi_slot_val = 8;
        else if (ft_mu == 8) subslots_per_etsi_slot_val = 16;
        else {LOG_ERR("FT_RACH_LSN: Invalid mu %u for subslots_per_slot calc.", ft_mu); return;}

        rach_resource_len_subslots *= subslots_per_etsi_slot_val;
    }
    if (rach_resource_len_subslots == 0) {
        LOG_ERR("FT_RACH_LSN: Advertised RACH resource length is 0 subslots. Cannot listen.");
        return;
    }

    // 3. Determine Target SFN for the next RACH listen window
    uint8_t target_sfn_for_rach;
    uint8_t current_ft_sfn = ctx->role_ctx.ft.sfn; // The SFN for the *next* frame the FT will be involved in.

    if (rach_adv_fields->sfn_validity_present) {
        target_sfn_for_rach = rach_adv_fields->sfn_value;
        // Advance target_sfn_for_rach based on repetition until it's >= current_ft_sfn
        // And also check validity_frames.
        // Repetition code: 00=every frame, 01=every 2nd, 10=every 4th, 11=every 8th (from ETSI 6.4.3.4)
        uint8_t repetition_interval_frames = 1 << rach_adv_fields->repetition_code; // 1, 2, 4, 8

        int16_t sfn_diff_to_curr = (int16_t)target_sfn_for_rach - (int16_t)current_ft_sfn;
        if (sfn_diff_to_curr < 0) sfn_diff_to_curr += 256; // Handle SFN wrap for difference

        if (sfn_diff_to_curr > 0 && (sfn_diff_to_curr % repetition_interval_frames != 0) ) { // target is in future but not on repetition boundary
            target_sfn_for_rach = (current_ft_sfn + (repetition_interval_frames - (current_ft_sfn % repetition_interval_frames))) & 0xFF;
             if (target_sfn_for_rach < current_ft_sfn) target_sfn_for_rach += repetition_interval_frames; // Ensure it's future
             target_sfn_for_rach &= 0xFF;
        } else if (sfn_diff_to_curr < 0) { // Initial target_sfn_for_rach is in the past
            target_sfn_for_rach = (current_ft_sfn + (repetition_interval_frames - (current_ft_sfn % repetition_interval_frames))) & 0xFF;
             if (target_sfn_for_rach < current_ft_sfn) target_sfn_for_rach += repetition_interval_frames;
             target_sfn_for_rach &= 0xFF;
        }
        // Now target_sfn_for_rach is the next valid occurrence at or after current_ft_sfn.
        // Check validity period
        int16_t frames_from_initial_validity_sfn = (int16_t)target_sfn_for_rach - (int16_t)rach_adv_fields->sfn_value;
        if (frames_from_initial_validity_sfn < 0) frames_from_initial_validity_sfn += 256;
        if (rach_adv_fields->validity_frames != 0xFF && (uint8_t)frames_from_initial_validity_sfn >= rach_adv_fields->validity_frames) {
            LOG_WRN("FT_RACH_LSN: Advertised RACH validity expired (target SFN %u, initial SFN %u, validity %u frames). Not listening.",
                    target_sfn_for_rach, rach_adv_fields->sfn_value, rach_adv_fields->validity_frames);
            return;
        }
    } else {
        // If SFN not present, RACH is valid "now" (relative to beacon that advertised it).
        // The FT should listen in its SFN cycle immediately following the beacon for RACH.
        // Repetition implies it occurs every 'repetition_interval_frames' relative to beacon SFN.
        // This logic might need more careful thought if SFN is not present but repetition is.
        // For now, if SFN not present, assume listen in current_ft_sfn or next frame.
        target_sfn_for_rach = current_ft_sfn; // Listen in the SFN matching current beacon period
                                             // or sfn_for_last_beacon_tx if more appropriate.
    }


    // 4. Calculate RACH Listen Start Time using the SFN anchor
    uint64_t rach_listen_start_time = calculate_target_modem_time(ctx,
                                                                  ctx->ft_sfn_zero_modem_time_anchor,
                                                                  ctx->current_sfn_at_anchor_update,
                                                                  target_sfn_for_rach,
                                                                  rach_adv_fields->start_subslot_index);

    // 5. Calculate RACH Listen Duration in modem ticks
    // Listen for the RACH resource length plus a small margin (e.g., Max RACH PDU TX time from RACH IE)
    // Plus response window of PT, as PT might still be transmitting if FT is slow to respond.
    // For now, simple: advertised RACH length + small guard.
    uint32_t listen_duration_subslots = rach_resource_len_subslots + 2; // Listen a bit longer
    uint32_t listen_duration_modem_units = listen_duration_subslots * get_subslot_duration_ticks(ctx);

    // Check if calculated start time is too soon
    uint32_t min_prep_time_ticks = modem_us_to_ticks(ctx->phy_latency.idle_to_active_rx_us +
                                                     ctx->phy_latency.scheduled_operation_startup_us,
                                                     NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
    if (ctx->last_known_modem_time > 0 && rach_listen_start_time < (ctx->last_known_modem_time + min_prep_time_ticks)) {
        // Attempt to schedule for the *next* repetition cycle if this one is missed
        // This is complex due to repetition_code (frames vs subslots).
        // For now, if too soon, log and skip this listen opportunity.
        LOG_WRN("FT_RACH_LSN: Calculated start time %llu for SFN %u / SS %u too soon (current %llu, prep %u). Skipping this RACH opp.",
                rach_listen_start_time, target_sfn_for_rach, rach_adv_fields->start_subslot_index,
                ctx->last_known_modem_time, min_prep_time_ticks);
        return;
    }
    if (listen_duration_modem_units == 0) {
        LOG_ERR("FT_RACH_LSN: Calculated listen duration is 0. Aborting.");
        return;
    }

    LOG_INF("FT_RACH_LSN: Scheduling RX on RACH C%u for SFN %u, StartSS %u (len %u subslots). RXDur:%u TU, TargetStart:%llu",
            rach_carrier, target_sfn_for_rach, rach_adv_fields->start_subslot_index, rach_resource_len_subslots,
            listen_duration_modem_units, rach_listen_start_time);

    uint32_t phy_op_handle = sys_rand32_get();
    int ret = dect_mac_phy_ctrl_start_rx(
        rach_carrier,
        listen_duration_modem_units,
        NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS, // Listen for whole window for any RACH attempt
        phy_op_handle,
        ctx->own_short_rd_id, // Association Request is sent to FT's Short ID
        PENDING_OP_FT_RACH_RX_WINDOW);

    if (ret != 0) {
        LOG_ERR("FT_SM: Failed to schedule RACH RX window: %d", ret);
        // Could retry scheduling for next repetition based on repetition_code
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
        for (uint16_t i = 0; i < rssi_event->meas_len; ++i) {
            if (rssi_event->meas[i] != NRF_MODEM_DECT_PHY_RSSI_NOT_MEASURED) {
                rssi_sum += rssi_event->meas[i];
                valid_count++;
            }
        }
        if (valid_count > 0) {
            ctx->role_ctx.ft.dcs_candidate_rssi_avg[current_scan_idx] = rssi_sum / valid_count;
            LOG_INF("FT_DCS: Scan %u/%u on C%u: Avg RSSI %.1f dBm (%d valid samples).",
                    current_scan_idx + 1, CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN,
                    scanned_carrier, (float)ctx->role_ctx.ft.dcs_candidate_rssi_avg[current_scan_idx] / 2.0f,
                    valid_count);
            // TODO: Calculate busy percentage based on thresholds
            // ctx->role_ctx.ft.dcs_candidate_busy_percent[current_scan_idx] = calculated_busy_pc;
        } else {
            LOG_WRN("FT_DCS: Scan %u/%u on C%u: No valid RSSI samples.",
                    current_scan_idx + 1, CONFIG_DECT_MAC_DCS_NUM_CHANNELS_TO_SCAN, scanned_carrier);
            ctx->role_ctx.ft.dcs_candidate_rssi_avg[current_scan_idx] = 0; // Or some other marker for no valid data
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

    if (security_applied_by_sender) {
        if (!link_is_expected_to_be_secure) {
            LOG_WRN("FT_SM_PDC_SEC: Secured PDU from PT 0x%04X (slot %d), but link not marked secure. Discarding.",
                    pt_sender_short_id_from_pcc, peer_slot_idx);
            return;
        }
        if (sdu_area_plus_mic_actual_len < 5 /*MIC_LEN*/) {
             LOG_ERR("FT_SM_PDC_SEC: Secured PDU from PT 0x%04X too short for MIC. SDUArea+MIC len %zu. Discarding.",
                    pt_sender_short_id_from_pcc, sdu_area_plus_mic_actual_len);
             return;
        }

        const dect_mac_unicast_header_t *uch_ptr = (const dect_mac_unicast_header_t *)common_hdr_start_in_payload;
        uint16_t received_psn = ((uch_ptr->sequence_num_high_reset_rsv >> 4) & 0x0F) << 8 | uch_ptr->sequence_num_low;
        uint32_t pt_tx_long_id = sys_be32_to_cpu(uch_ptr->transmitter_long_rd_id_be);

        if (pt_tx_long_id != pt_peer_ctx->long_rd_id) {
            LOG_WRN("FT_SM_PDC_SEC: Secured PDU LongID 0x%08X mismatch for PT 0x%04X (expected 0x%08X). Discarding.",
                    pt_tx_long_id, pt_sender_short_id_from_pcc, pt_peer_ctx->long_rd_id);
            return;
        }

        uint8_t iv[16];
        security_build_iv(iv, pt_tx_long_id, ctx->own_long_rd_id,
                          pt_peer_ctx->hpc, // Use FT's tracked HPC for this PT
                          received_psn);

        uint8_t *part_to_decrypt_start;
        size_t part_to_decrypt_len;
        size_t muxed_sec_ie_total_len_parsed = 0;

        uint8_t *decryption_input_buffer_start; // Renamed for clarity
        size_t decryption_input_len;         // Renamed for clarity
        // size_t muxed_sec_ie_total_len_parsed = 0; // Already declared earlier

        if (mac_hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            // Common Header and MUXed MAC Sec Info IE are cleartext.
            // First, parse the cleartext MAC Sec Info IE from the start of the SDU Area.
            uint8_t ie_type; uint16_t ie_len; const uint8_t *ie_payload;
            int mux_hdr_len = parse_mac_mux_header(sdu_area_after_common_hdr, sdu_area_plus_mic_actual_len,
                                                   &ie_type, &ie_len, &ie_payload);

            if (mux_hdr_len > 0 && ie_type == IE_TYPE_MAC_SECURITY_INFO) {
                if (sdu_area_plus_mic_actual_len < (size_t)mux_hdr_len + ie_len + 5 /*min rest of SDU area + MIC*/) {
                    LOG_ERR("FT_SM_PDC_SEC: PDU too short for parsed SecIE + rest + MIC. Discarding.");
                    pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path;
                }
                muxed_sec_ie_total_len_parsed = mux_hdr_len + ie_len; // Store total length of MUXed SecIE
                uint8_t ver, kidx, secivtype_from_ie; uint32_t hpc_from_ie;
                if (parse_mac_security_info_ie_payload(ie_payload, ie_len, &ver, &kidx, &secivtype_from_ie, &hpc_from_ie) == 0) {
                    // ... (Full HPC windowing and resync request handling logic from previous step for SEC_IV_TYPE_MODE1_PROVIDED and SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) ...
                    // This block updates pt_peer_ctx->hpc and pt_peer_ctx->highest_rx_peer_hpc
                    // and may set pt_peer_ctx->peer_requested_hpc_resync or pdc_process_ok_for_feedback = false
                    LOG_INF("FT_SM_PDC_SEC (WITH_IE): MAC Sec Info IE from PT 0x%04X: PeerHPC_IE=%u, TrackedHPC=%u, SecIVType=%u",
                            pt_sender_short_id_from_pcc, hpc_from_ie, pt_peer_ctx->hpc, secivtype_from_ie);
                    // (Simplified: just showing the log, full window/resync logic goes here)
                    if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_PROVIDED) {
                        if (pt_peer_ctx->highest_rx_peer_hpc == 0 && hpc_from_ie > 0) {pt_peer_ctx->highest_rx_peer_hpc = hpc_from_ie; pt_peer_ctx->hpc = hpc_from_ie;}
                        else { /* ... window logic ... */ if (hpc_from_ie > pt_peer_ctx->highest_rx_peer_hpc /* simplified */) pt_peer_ctx->hpc = hpc_from_ie; }
                    } else if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) {
                        if (pt_peer_ctx->highest_rx_peer_hpc == 0 && hpc_from_ie > 0) {pt_peer_ctx->highest_rx_peer_hpc = hpc_from_ie; pt_peer_ctx->hpc = hpc_from_ie;}
                        else { /* ... window logic ... */ if (hpc_from_ie > pt_peer_ctx->highest_rx_peer_hpc /* simplified */) pt_peer_ctx->hpc = hpc_from_ie; }
                        pt_peer_ctx->peer_requested_hpc_resync = true;
                    }

                } else { LOG_ERR("FT_SM_PDC_SEC: Failed to parse MAC Sec Info IE from PT 0x%04X.", pt_sender_short_id_from_pcc); }
                
                decryption_input_buffer_start = sdu_area_after_common_hdr + muxed_sec_ie_total_len_parsed; // Decrypt part *after* SecIE
                decryption_input_len = sdu_area_plus_mic_actual_len - muxed_sec_ie_total_len_parsed;     // This is (Rest of SDU Area + MIC)
            } else {
                LOG_ERR("FT_SM_PDC_SEC: MAC_SECURITY_USED_WITH_IE indicated but MAC Sec Info IE not found/parsed first. Discarding.");
                pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path;
            }
        } else { // MAC_SECURITY_USED_NO_IE
            // Common Header is cleartext. Decrypt (SDU Area + MIC).
            decryption_input_buffer_start = sdu_area_after_common_hdr;      // Decryption starts *after* Common Header
            decryption_input_len = sdu_area_plus_mic_actual_len;         // Length of (SDU Area + MIC)
            muxed_sec_ie_total_len_parsed = 0; // No SecIE in this mode
        }


        if (!pdc_process_ok_for_feedback) goto process_feedback_ft_pdc_secure_rx_path;

        if (part_to_decrypt_len < 5) { LOG_ERR("FT_SM_PDC_SEC: Encrypted part too short for MIC. Discarding."); pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path; }
        if (security_crypt_payload(part_to_decrypt_start, part_to_decrypt_len,
                                   ctx->role_ctx.ft.peer_cipher_keys[peer_slot_idx], iv, false) != 0) {
            LOG_ERR("FT_SM_PDC_SEC: Decryption failed for PDU from PT 0x%04X. Discarding.", pt_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path;
        }

        uint8_t received_mic[5];
        memcpy(received_mic, part_to_decrypt_start + part_to_decrypt_len - 5, 5);
        uint8_t calculated_mic[5];
        if (security_calculate_mic(common_hdr_start_in_payload, pdu_content_len - 5,
                                   ctx->role_ctx.ft.peer_integrity_keys[peer_slot_idx], calculated_mic) != 0) {
            LOG_ERR("FT_SM_PDC_SEC: MIC re-calc failed. Discarding PDU from PT 0x%04X.", pt_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_ft_pdc_secure_rx_path;
        }
        if (memcmp(received_mic, calculated_mic, 5) != 0) {
            LOG_ERR("FT_SM_PDC_SEC: MIC FAIL from PT 0x%04X (PSN %u, PeerHPC %u). Discarding.",
                    pt_sender_short_id_from_pcc, received_psn, pt_peer_ctx->hpc);
            if (pt_peer_ctx) { // pt_peer_ctx should be valid if link_is_expected_to_be_secure was true
                pt_peer_ctx->consecutive_mic_failures++;
                if (pt_peer_ctx->consecutive_mic_failures >= MAX_MIC_FAILURES_BEFORE_HPC_RESYNC) {
                    LOG_WRN("FT_SM_PDC_SEC: Max MIC failures (%u) for PT 0x%04X. Will request HPC resync from PT.",
                            pt_peer_ctx->consecutive_mic_failures, pt_sender_short_id_from_pcc);
                    pt_peer_ctx->self_needs_to_request_hpc_from_peer = true; // FT will send RESYNC_INITIATE to this PT
                    pt_peer_ctx->consecutive_mic_failures = 0; // Reset counter after deciding to resync
                }
            }
            pdc_process_ok_for_feedback = false; // Signal to store NACK
            goto process_feedback_ft_pdc_secure_rx_path; // Go to store feedback, then return
        } else { // MIC OK
            LOG_DBG("FT_SM_PDC_SEC: MIC OK from PT 0x%04X (PSN %u, PeerHPC %u).",
                    pt_sender_short_id_from_pcc, received_psn, pt_peer_ctx->hpc);
            if(pt_peer_ctx) pt_peer_ctx->consecutive_mic_failures = 0; // Reset on successful MIC
        }

        // Adjust pointers to the SDU area content (after Common Hdr and potential SecIE, before MIC)
        if (mac_hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len + muxed_sec_ie_total_len_parsed;
            sdu_area_plus_mic_actual_len = pdu_content_len - common_hdr_actual_len - muxed_sec_ie_total_len_parsed - 5;
        } else { // MAC_SECURITY_USED_NO_IE
            sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len;
            sdu_area_plus_mic_actual_len = pdu_content_len - common_hdr_actual_len - 5;
        }
    } else { // Not secured
        LOG_DBG("FT_SM_PDC: Unsecure PDU from PT 0x%04X.", pt_sender_short_id_from_pcc);
        sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len;
        sdu_area_plus_mic_actual_len = pdu_content_len - common_hdr_actual_len;
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

static void ft_send_association_response_action(uint32_t pt_long_rd_id, uint16_t pt_short_rd_id,
                                                bool accept_association, int peer_slot_idx) // peer_slot_idx is valid if accept_association is true
{
    dect_mac_context_t* ctx = get_mac_context();
    uint8_t sdu_area_buf[256]; // Buffer for MUXed IEs. Max size for:
                               // [SecIE(6)] + [AssocResp(2-10)] + [RDCap(2-~60)] + [ResAlloc(4-~10)]
    int sdu_area_len_cleartext = 0;

    bool secure_this_response = false;
    if (accept_association && peer_slot_idx != -1 &&
        ctx->config.ft_policy_secure_on_assoc && // FT wants to secure this link
        ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx]) { // Keys were successfully derived
        secure_this_response = true;
    }

    // 1. Populate Association Response IE fields
    dect_mac_assoc_resp_ie_t resp_fields;
    memset(&resp_fields, 0, sizeof(resp_fields));
    resp_fields.ack_nack = accept_association;
    resp_fields.harq_mod_present = false; // Simplification for Phase 5
    resp_fields.number_of_flows_accepted = accept_association ? 0x07 : 0; // 7 = all requested flows accepted (0 for now)
    resp_fields.group_assignment_active = false; // Simplification
    resp_fields.reserved_3bits = 0;


    if (!accept_association) {
        resp_fields.reject_cause = ASSOC_REJECT_CAUSE_OTHER; // Example: Could be NO_RADIO_CAP, NO_HW_CAP etc.
        resp_fields.reject_timer_code = 1; // Example: 5s (ETSI Table 6.4.2.5-2 maps code 1 to 5s)
    }

    // 2. Populate FT's RD Capability IE fields (only if accepting)
    dect_mac_rd_capability_ie_t ft_cap_fields; // Sent if accept_association is true
    if (accept_association) {
        memset(&ft_cap_fields, 0, sizeof(ft_cap_fields));
        ft_cap_fields.num_phy_capabilities = 0;    // Minimal: 0 means 1 set described by common fields/PHY default
        ft_cap_fields.release_version = 1;         // DECT NR+ Release 2 (code 1)
        ft_cap_fields.supports_group_assignment = false; // Example
        ft_cap_fields.supports_paging = true;            // Example: FT supports paging PTs
        ft_cap_fields.operating_modes_code = 0b01;     // FT mode only
        ft_cap_fields.supports_mesh = false;           // Example
        ft_cap_fields.supports_sched_data = true;
        ft_cap_fields.mac_security_modes_code = secure_this_response ? 0b01 : 0b00; // Supports Mode 1 if link will be secure
    }

    // 3. Populate Resource Allocation IE fields (only if accepting)
    dect_mac_resource_alloc_ie_fields_t res_alloc_fields; // Sent if accept_association is true
    if (accept_association) {
        memset(&res_alloc_fields, 0, sizeof(res_alloc_fields));
        res_alloc_fields.alloc_type_val = RES_ALLOC_TYPE_BIDIR;
        res_alloc_fields.add_allocation = false; // New allocation
        res_alloc_fields.id_present = false;     // This response is unicast to the PT
        res_alloc_fields.repeat_val = RES_ALLOC_REPEAT_FRAMES;
        res_alloc_fields.sfn_present = true;
        res_alloc_fields.channel_present = false; // Use current FT operating carrier
        res_alloc_fields.rlf_present = false;     // No dectScheduledResourceFailure timer info for now

        // Example: Resource 1 (Downlink for PT)
        res_alloc_fields.res1_is_9bit_subslot = false; // Assume mu <= 4 for PT link initially
        res_alloc_fields.start_subslot_val_res1 = 10;  // Example: DL for PT starts at subslot 10
        res_alloc_fields.length_type_is_slots_res1 = false;
        res_alloc_fields.length_val_res1 = 2 - 1;      // 2 subslots long (N-1 coded)

        // Example: Resource 2 (Uplink from PT)
        res_alloc_fields.res2_is_9bit_subslot = false;
        res_alloc_fields.start_subslot_val_res2 = 14;  // Example: UL from PT starts at subslot 14
        res_alloc_fields.length_type_is_slots_res2 = false;
        res_alloc_fields.length_val_res2 = 2 - 1;      // 2 subslots long

        res_alloc_fields.repetition_value = 10; // Example: Repeat every 10 frames
        res_alloc_fields.validity_value = 100;  // Example: Valid for 100 frames
        uint8_t target_start_sfn = (ctx->role_ctx.ft.sfn + 2) & 0xFF; // Schedule starts in SFN+2 (example)
        res_alloc_fields.sfn_val = target_start_sfn;

        // FT also stores this schedule for the PT internally for its own scheduler
        if (peer_slot_idx != -1) {
            dect_mac_schedule_t *pt_sched_dl = &ctx->role_ctx.ft.peer_schedules[peer_slot_idx]; // Assuming one schedule for bi-dir
            pt_sched_dl->is_active = true;
            pt_sched_dl->alloc_type = RES_ALLOC_TYPE_DOWNLINK; // From FT's TX perspective
            pt_sched_dl->dl_start_subslot = res_alloc_fields.start_subslot_val_res1;
            pt_sched_dl->dl_duration_subslots = res_alloc_fields.length_val_res1 + 1;
            pt_sched_dl->dl_length_is_slots = res_alloc_fields.length_type_is_slots_res1;
            pt_sched_dl->ul_start_subslot = res_alloc_fields.start_subslot_val_res2; // Store UL info too
            pt_sched_dl->ul_duration_subslots = res_alloc_fields.length_val_res2 + 1;
            pt_sched_dl->ul_length_is_slots = res_alloc_fields.length_type_is_slots_res2;
            pt_sched_dl->repeat_type = res_alloc_fields.repeat_val;
            pt_sched_dl->repetition_value = res_alloc_fields.repetition_value;
            pt_sched_dl->validity_value = res_alloc_fields.validity_value;
            pt_sched_dl->channel = res_alloc_fields.channel_present ? res_alloc_fields.channel_val : ctx->role_ctx.ft.operating_carrier;
            pt_sched_dl->schedule_init_modem_time = ctx->last_known_modem_time;
            pt_sched_dl->sfn_of_initial_occurrence = target_start_sfn;
            pt_sched_dl->next_occurrence_modem_time = calculate_target_modem_time(ctx, ctx->ft_sfn_zero_modem_time_anchor, ctx->role_ctx.ft.sfn, target_start_sfn, res_alloc_fields.start_subslot_val_res1);
            update_next_occurrence(ctx, pt_sched_dl, ctx->last_known_modem_time);
        }
    }

    // --- SDU Area Construction ---
    int current_sdu_area_offset = 0;
    int ie_len_written_val; // Renamed to avoid conflict
    uint8_t temp_ie_payload_buf_resp[64]; // Temp buffer for individual IE payloads

    // Prepend MAC Security Info IE if this response is secured
    if (secure_this_response) {
        // FT sends its current TX HPC. This is the first time PT learns it for this session.
        ie_len_written_val = build_mac_security_info_ie_muxed(
            sdu_area_buf + current_sdu_area_offset, // sdu_area_buf is defined in the function
            sizeof(sdu_area_buf) - current_sdu_area_offset,
            0, ctx->current_key_index, // Version 0, FT's current key index for this PT link
            SEC_IV_TYPE_MODE1_HPC_PROVIDED,
            ctx->hpc); // FT's own current global TX HPC
        if (ie_len_written_val < 0) {
            LOG_ERR("FT_ASSOC_RESP: Failed to build MAC Sec Info IE for secure response: %d", ie_len_written_val);
            // Cannot send secured response without it, could send unsecure or fail fully.
            // For now, fail the operation.
            return;
        }
        current_sdu_area_offset += ie_len_written_val;
        len_of_muxed_sec_ie_for_crypto = ie_len_written_val; // Store length of MUXed SecIE
        LOG_DBG("FT_ASSOC_RESP: Including MAC Sec Info IE (FT_HPC: %u) in secure response.", ctx->hpc);
        // FT's global send_mac_sec_info_ie_on_next_tx is for its own HPC wrap,
        // this SecIE is specific to initiating security with this PT.
        // If global flag was also set, it effectively gets "consumed" by sending this.
        if(ctx->send_mac_sec_info_ie_on_next_tx) ctx->send_mac_sec_info_ie_on_next_tx = false;
    }

    // Add Association Response IE
    ie_len_written_val = serialize_assoc_resp_ie_payload(temp_ie_payload_buf_resp, sizeof(temp_ie_payload_buf_resp), &resp_fields);
    if (ie_len_written_val < 0) { LOG_ERR("FT_ASSOC_RESP: Serialize AssocResp IE failed: %d", ie_len_written_val); return; }
    int mux_hdr_len_val = build_mac_mux_header_internal(sdu_area_buf + current_sdu_area_offset, sizeof(sdu_area_buf) - current_sdu_area_offset, IE_TYPE_ASSOC_RESP, ie_len_written_val, 0);
    if (mux_hdr_len_val < 0) { LOG_ERR("FT_ASSOC_RESP: Build MUX for AssocResp IE failed: %d", mux_hdr_len_val); return; }
    current_sdu_area_offset += mux_hdr_len_val;
    if (current_sdu_area_offset + ie_len_written_val > sizeof(sdu_area_buf)) { LOG_ERR("FT_ASSOC_RESP: SDU area overflow for AssocResp IE."); return; }
    memcpy(sdu_area_buf + current_sdu_area_offset, temp_ie_payload_buf_resp, ie_len_written_val);
    current_sdu_area_offset += ie_len_written_val;

    if (accept_association) {
        // Add FT RD Capability IE
        ie_len_written_val = serialize_rd_capability_ie_payload(temp_ie_payload_buf_resp, sizeof(temp_ie_payload_buf_resp), &ft_cap_fields);
        if (ie_len_written_val < 0) { LOG_ERR("FT_ASSOC_RESP: Serialize FT RD Cap IE failed: %d", ie_len_written_val); return; }
        mux_hdr_len_val = build_mac_mux_header_internal(sdu_area_buf + current_sdu_area_offset, sizeof(sdu_area_buf) - current_sdu_area_offset, IE_TYPE_RD_CAPABILITY, ie_len_written_val, 0);
        if (mux_hdr_len_val < 0) { LOG_ERR("FT_ASSOC_RESP: Build MUX for RD Cap failed: %d", mux_hdr_len_val); return; }
        current_sdu_area_offset += mux_hdr_len_val;
        if (current_sdu_area_offset + ie_len_written_val > sizeof(sdu_area_buf)) { LOG_ERR("FT_ASSOC_RESP: SDU area overflow for RD Cap IE."); return; }
        memcpy(sdu_area_buf + current_sdu_area_offset, temp_ie_payload_buf_resp, ie_len_written_val);
        current_sdu_area_offset += ie_len_written_val;

        // Add Resource Allocation IE
        ie_len_written_val = serialize_resource_alloc_ie_payload(temp_ie_payload_buf_resp, sizeof(temp_ie_payload_buf_resp), &res_alloc_fields);
        if (ie_len_written_val < 0) { LOG_ERR("FT_ASSOC_RESP: Serialize Res Alloc IE failed: %d", ie_len_written_val); return; }
        mux_hdr_len_val = build_mac_mux_header_internal(sdu_area_buf + current_sdu_area_offset, sizeof(sdu_area_buf) - current_sdu_area_offset, IE_TYPE_RES_ALLOC, ie_len_written_val, 0);
        if (mux_hdr_len_val < 0) { LOG_ERR("FT_ASSOC_RESP: Build MUX for Res Alloc failed: %d", mux_hdr_len_val); return; }
        current_sdu_area_offset += mux_hdr_len_val;
        if (current_sdu_area_offset + ie_len_written_val > sizeof(sdu_area_buf)) { LOG_ERR("FT_ASSOC_RESP: SDU area overflow for Res Alloc IE."); return; }
        memcpy(sdu_area_buf + current_sdu_area_offset, temp_ie_payload_buf_resp, ie_len_written_val);
        current_sdu_area_offset += ie_len_written_val;
    }
    sdu_area_len_cleartext = current_sdu_area_offset;

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
    common_hdr.sequence_num_high_reset_rsv = SET_SEQ_NUM_HIGH_RESET_RSV((ctx->psn >> 8) & 0x0F, 1 /*reset*/);
    common_hdr.sequence_num_low = ctx->psn & 0xFF;
    common_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);
    common_hdr.receiver_long_rd_id_be = sys_cpu_to_be32(pt_long_rd_id);

    // --- Assemble PDU (pre-security application) ---
    uint8_t *full_mac_pdu_for_phy_slab = NULL;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab, K_NO_WAIT);
    if(ret != 0 || full_mac_pdu_for_phy_slab == NULL) { LOG_ERR("FT_ASSOC_RESP: Failed to alloc PDU buf for PT 0x%04X", pt_short_rd_id); return; }
    uint8_t * const full_mac_pdu_for_phy = full_mac_pdu_for_phy_slab;

    uint16_t assembled_pdu_len_pre_mic;
    ret = dect_mac_phy_ctrl_assemble_final_pdu(
              full_mac_pdu_for_phy, CONFIG_DECT_MAC_PDU_MAX_SIZE,
              &hdr_type_octet,
              &common_hdr, sizeof(common_hdr),
              sdu_area_buf, sdu_area_len_cleartext,
              &assembled_pdu_len_pre_mic);
    if (ret != 0) { LOG_ERR("FT_ASSOC_RESP: Assemble PDU failed for PT 0x%04X: %d", pt_short_rd_id,ret); k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return; }

    uint16_t final_tx_pdu_len = assembled_pdu_len_pre_mic;

    // --- Apply Security if active ---
    if (secure_this_response) {
        uint8_t iv[16];
        security_build_iv(iv, ctx->own_long_rd_id, pt_long_rd_id, ctx->hpc, ctx->psn);

        uint8_t *mic_calc_start = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t);
        size_t mic_calc_len = sizeof(common_hdr) + sdu_area_len_cleartext;

        if (assembled_pdu_len_pre_mic + 5 > CONFIG_DECT_MAC_PDU_MAX_SIZE) { LOG_ERR("FT_ASSOC_RESP: No space for MIC for PT 0x%04X.", pt_short_rd_id); k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return; }
        uint8_t *mic_location = full_mac_pdu_for_phy + assembled_pdu_len_pre_mic;
        ret = security_calculate_mic(mic_calc_start, mic_calc_len, ctx->role_ctx.ft.peer_integrity_keys[peer_slot_idx], mic_location);
        if (ret != 0) { LOG_ERR("FT_ASSOC_RESP: MIC calc failed for PT 0x%04X: %d", pt_short_rd_id, ret); k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return; }

        
        // Encryption: (Common Header and MUXed MAC Sec Info IE are cleartext)
        uint8_t *encrypt_start_ptr;
        size_t encrypt_len;
        size_t common_hdr_actual_len_assoc = sizeof(common_hdr);

        // len_of_muxed_sec_ie_for_crypto was calculated when SecIE was built
        encrypt_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                            common_hdr_actual_len_assoc + len_of_muxed_sec_ie_for_crypto;
        // Encrypt (Rest of SDU Area (AssocResp IE, RDCap IE, ResAlloc IE) + MIC)
        encrypt_len = (sdu_area_len_cleartext - len_of_muxed_sec_ie_for_crypto) + 5;
        // <<<< END OF THE SPECIFIC BLOCK YOU PROVIDED >>>>

        if (encrypt_len > 0) {
            uint8_t* pdu_buffer_end_assoc = full_mac_pdu_for_phy + assembled_pdu_len_pre_mic + 5;
            if ( (encrypt_start_ptr < full_mac_pdu_for_phy) || ((encrypt_start_ptr + encrypt_len) > pdu_buffer_end_assoc) ) {
                 LOG_ERR("FT_ASSOC_RESP: Encryption range error for PT 0x%04X. Start:%p Len:%zu End:%p PDU_End:%p",
                        pt_short_rd_id, encrypt_start_ptr, encrypt_len, encrypt_start_ptr + encrypt_len, pdu_buffer_end_assoc);
                 k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab); return;
            }
             ret = security_crypt_payload(encrypt_start_ptr, encrypt_len, ctx->role_ctx.ft.peer_cipher_keys[peer_slot_idx], iv, true);
             if (ret != 0) { LOG_ERR("FT_ASSOC_RESP: Encryption failed for PT 0x%04X: %d", pt_short_rd_id, ret); k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return; }
        }
        final_tx_pdu_len = assembled_pdu_len_pre_mic + 5;
        LOG_INF("FT_ASSOC_RESP: Secured Association Response for PT 0x%04X. Final len %u.", pt_short_rd_id, final_tx_pdu_len);
    }

    // --- Schedule TX ---
    uint32_t phy_op_handle = sys_rand32_get();
    ctx->role_ctx.ft.last_assoc_resp_pt_short_id = pt_short_rd_id;

    ret = dect_mac_phy_ctrl_start_tx_assembled(
        ctx->role_ctx.ft.operating_carrier,
        full_mac_pdu_for_phy, final_tx_pdu_len,
        pt_short_rd_id,
        false, /* is_beacon */
        phy_op_handle, PENDING_OP_FT_ASSOC_RESP,
        true, /* use_lbt for unicast response */
        0 /* target_start_time = 0 for immediate */
    );

    k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);

    if (ret != 0) {
        LOG_ERR("FT_ASSOC_RESP: Failed to schedule TX to PT 0x%04X: %d", pt_short_rd_id, ret);
        if (accept_association && peer_slot_idx != -1) {
            ctx->role_ctx.ft.connected_pts[peer_slot_idx].is_valid = false; // Failed to send acceptance
            ctx->role_ctx.ft.keys_provisioned_for_peer[peer_slot_idx] = false;
        }
    } else {
        LOG_INF("FT_SM: Association Response (%s) TX scheduled to PT 0x%04X (Hdl %u). Secure: %s",
                accept_association ? "ACCEPT" : "REJECT", pt_short_rd_id, phy_op_handle, secure_this_response ? "Yes" : "No");
    }
}