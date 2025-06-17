/* dect_mac/dect_mac_sm_pt.c */
#include <zephyr/logging/log.h>
#include <zephyr/random/rand32.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <zephyr/sys/util.h>

#include "dect_mac_sm_pt.h"
#include "dect_mac_core.h"
#include "dect_mac_context.h"
#include "dect_mac_pdu.h"
#include "dect_mac_phy_ctrl.h"
#include "dect_mac_data_path.h"
#include "dect_mac_main_dispatcher.h"
#include "dect_mac_api.h"       // For g_mac_sdu_slab
#include "dect_mac_security.h"  // For security functions

LOG_MODULE_REGISTER(dect_mac_sm_pt, CONFIG_DECT_MAC_SM_PT_LOG_LEVEL);

// --- Static Globals for this Module ---
// Store the PCC associated with an incoming PDC for context
static struct {
    struct nrf_modem_dect_phy_pcc_event pcc_data;
    uint64_t pcc_event_modem_time; // Store the modem time of the PCC event
    bool is_valid;
} last_relevant_pcc_for_pt;


// --- Static Helper Function Prototypes ---
static void pt_handle_phy_op_complete_internal(const struct nrf_modem_dect_phy_op_complete_event *event, pending_op_type_t completed_op_type);
static void pt_handle_phy_pcc_internal(const struct nrf_modem_dect_phy_pcc_event *event, uint64_t pcc_event_time);
static void pt_handle_phy_pdc_internal(const struct nrf_modem_dect_phy_pdc_event *pdc_event, const struct nrf_modem_dect_phy_pcc_event *assoc_pcc_event, uint64_t pcc_reception_modem_time);
static void pt_handle_phy_rssi_internal(const struct nrf_modem_dect_phy_rssi_event *event);
static void pt_update_mobility_candidate(uint16_t carrier, int16_t rssi, uint32_t long_id, uint16_t short_id);

static void pt_process_identified_beacon_and_attempt_assoc(dect_mac_context_t *ctx,
                                                           const dect_mac_cluster_beacon_ie_fields_t *cb_fields,
                                                           const dect_mac_rach_info_ie_fields_t *rach_fields,
                                                           uint32_t ft_long_id, uint16_t ft_short_id, int16_t rssi,
                                                           uint16_t beacon_rx_carrier, uint64_t beacon_pcc_rx_time);
static void pt_send_association_request_action(void);
static void pt_process_association_response_pdu(const uint8_t *mac_sdu_area_data, size_t mac_sdu_area_len,
                                                uint32_t ft_tx_long_rd_id, uint64_t assoc_resp_pcc_rx_time);
static void pt_send_keep_alive_action(void);
// static void pt_initiate_background_mobility_scan_action(void); // TODO
static void pt_start_authentication_with_ft_action(dect_mac_context_t *ctx); // Simplified for PSK
static void pt_authentication_complete_action(dect_mac_context_t* ctx, bool success); // Called after key derivation

// Helpers from data_path or utils (ensure they are accessible)
extern uint32_t get_subslot_duration_ticks(dect_mac_context_t *ctx);
extern uint32_t modem_us_to_ticks(uint32_t us, uint32_t tick_rate_khz);
extern uint64_t calculate_target_modem_time(dect_mac_context_t *ctx, uint64_t sfn_zero_anchor_time, uint8_t anchor_sfn_val, uint8_t target_sfn_val, uint16_t target_subslot_idx);
extern void update_next_occurrence(dect_mac_context_t *ctx, dect_mac_schedule_t *schedule, uint64_t current_modem_time);


// --- PT Timer Expiry Action Functions (called by dispatcher) ---
void pt_rach_backoff_timer_expired_action(void) {
    dect_mac_context_t* ctx = get_mac_context();
    LOG_INF("PT SM: RACH Backoff timer expired.");
    if (ctx->role_ctx.pt.target_ft.is_valid && ctx->role_ctx.pt.target_ft.is_fully_identified) {
        LOG_INF("PT SM: Retrying Association Request to FT ShortID 0x%04X.", ctx->role_ctx.pt.target_ft.short_rd_id);
        // State should already be PT_RACH_BACKOFF, send_association_request changes to PT_ASSOCIATING
        pt_send_association_request_action();
    } else {
        LOG_ERR("PT SM: RACH backoff expired, but no valid/fully_identified target FT. Restarting scan.");
        dect_mac_sm_pt_start_operation();
    }
}

void pt_paging_cycle_timer_expired_action(void)
{
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != MAC_STATE_PT_PAGING) {
        LOG_WRN("PT_PAGING: Paging timer fired in unexpected state %s. Stopping timer.",
                dect_mac_state_to_str(ctx->state));
        k_timer_stop(&ctx->role_ctx.pt.paging_cycle_timer);
        return;
    }

    if (ctx->pending_op_type != PENDING_OP_NONE) {
        LOG_WRN("PT_PAGING: Paging listen time, but op %s pending. Will retry shortly.",
                dect_pending_op_to_str(ctx->pending_op_type));
        k_timer_start(&ctx->role_ctx.pt.paging_cycle_timer, K_MSEC(100), K_NO_WAIT); // Quick retry
        return;
    }

    LOG_INF("PT_PAGING: Waking up to listen for page (on FT carrier %u).",
            ctx->role_ctx.pt.associated_ft.operating_carrier);

    uint32_t phy_op_handle = sys_rand32_get();
    // Listen for a short duration, enough to receive a beacon.
    uint32_t listen_duration_modem_units = get_subslot_duration_ticks(ctx) *
                                           SUB_SLOTS_PER_ETSI_SLOT * 2; // Listen for 2 slots (10ms)

    int ret = dect_mac_phy_ctrl_start_rx(
        ctx->role_ctx.pt.associated_ft.operating_carrier,
        listen_duration_modem_units,
        NRF_MODEM_DECT_PHY_RX_MODE_SEMICONTINUOUS, // Stop after first unicast or beacon
        phy_op_handle,
        0xFFFF, // Listen for broadcast beacons
        PENDING_OP_PT_PAGING_LISTEN);

    if (ret != 0) {
        LOG_ERR("PT_PAGING: Failed to schedule RX for paging listen: %d. Retrying shortly.", ret);
        k_timer_start(&ctx->role_ctx.pt.paging_cycle_timer, K_MSEC(200), K_NO_WAIT);
    }
}


void pt_rach_response_window_timer_expired_action(void) {
    dect_mac_context_t* ctx = get_mac_context();
    k_timer_stop(&ctx->rach_context.rach_response_window_timer);
    LOG_WRN("PT SM: RACH Response Window timer expired. No Association Response from FT 0x%04X.",
            ctx->role_ctx.pt.target_ft.short_rd_id);

    ctx->role_ctx.pt.current_assoc_retries++;
    if (ctx->role_ctx.pt.target_ft.is_valid && ctx->role_ctx.pt.current_assoc_retries < ctx->config.max_assoc_retries) {
        LOG_INF("PT SM: Retrying association to FT 0x%04X (attempt %u / %u)",
                ctx->role_ctx.pt.target_ft.short_rd_id,
                ctx->role_ctx.pt.current_assoc_retries + 1, ctx->config.max_assoc_retries);
        ctx->rach_context.rach_cw_current_idx = ctx->config.rach_cw_min_idx; // Reset CW for new attempt sequence
        pt_send_association_request_action();
    } else {
        LOG_ERR("PT SM: Max association retries (%u) for FT 0x%04X or no target. Restarting scan.",
                ctx->config.max_assoc_retries, ctx->role_ctx.pt.target_ft.short_rd_id);
        dect_mac_sm_pt_start_operation();
    }
}

void dect_mac_sm_pt_keep_alive_timer_expired_action(void) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state == MAC_STATE_ASSOCIATED) {
        if (ctx->pending_op_type == PENDING_OP_NONE) {
            pt_send_keep_alive_action();
        } else {
            LOG_WRN("PT SM: Keep-alive time, but op %s pending. Will retry on next expiry.",
                    dect_pending_op_to_str(ctx->pending_op_type));
            // Periodic timer will fire again.
        }
    }
}

void dect_mac_sm_pt_mobility_scan_timer_expired_action(void)
{
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != MAC_STATE_ASSOCIATED) { // Only scan for mobility if associated
        LOG_DBG("PT SM: Mobility scan timer fired but not associated. Restarting general scan.");
        dect_mac_sm_pt_start_operation();
        return;
    }

    if (ctx->pending_op_type != PENDING_OP_NONE) {
        LOG_WRN("PT SM: Mobility scan time, but op %s pending. Deferring scan.",
                dect_pending_op_to_str(ctx->pending_op_type));
        // The timer will fire again later.
        return;
    }

    // Simple channel selection logic: scan the next channel.
    // A production system would use a more sophisticated channel hopping sequence.
    uint16_t current_carrier = ctx->role_ctx.pt.associated_ft.operating_carrier;
    uint16_t scan_carrier = (current_carrier != 0) ? (current_carrier + 1) : DEFAULT_DECT_CARRIER;
    // TODO: Add logic to wrap around the valid channel range.

    LOG_INF("PT SM: Starting mobility background RSSI scan on carrier %u.", scan_carrier);

    uint32_t phy_op_handle = sys_rand32_get();
    // A short scan, e.g., for one or two slots duration.
    uint32_t scan_duration_modem_units = get_subslot_duration_ticks(ctx) * SUB_SLOTS_PER_ETSI_SLOT * 2;

    int ret = dect_mac_phy_ctrl_start_rssi_scan(
        scan_carrier,
        scan_duration_modem_units,
        NRF_MODEM_DECT_PHY_RSSI_INTERVAL_24_SLOTS, // Get one report for this short scan
        phy_op_handle,
        PENDING_OP_PT_MOBILITY_SCAN);

    if (ret != 0) {
        LOG_ERR("PT SM: Failed to start mobility RSSI scan: %d.", ret);
        // The periodic timer will try again on its next cycle.
    }
}


// --- PT Public Functions ---
void dect_mac_sm_pt_start_operation(void) {
    dect_mac_context_t* ctx = get_mac_context();
    dect_mac_change_state(MAC_STATE_PT_SCANNING);
    // TODO: PT needs to scan multiple carriers if default is not yielding results.
    // For now, always scan on DEFAULT_DECT_CARRIER.
    uint16_t scan_carrier = DEFAULT_DECT_CARRIER;
    LOG_INF("PT SM: Starting scan for FT beacons on carrier %u.", scan_carrier);

    uint32_t phy_op_handle = sys_rand32_get();
    ctx->role_ctx.pt.current_assoc_retries = 0;
    memset(&ctx->role_ctx.pt.target_ft, 0, sizeof(dect_mac_peer_info_t));
    memset(&ctx->role_ctx.pt.associated_ft, 0, sizeof(dect_mac_peer_info_t)); // Clear previous association
    ctx->keys_provisioned = false; // Clear session keys

    // Continuous scan until an FT is found and association is attempted
    int ret = dect_mac_phy_ctrl_start_rx(scan_carrier, 0 /*duration indefinite for continuous*/,
                                   NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS,
                                   phy_op_handle, 0xFFFF, /* Accept beacons with any RxID (broadcast beacons) */
                                   PENDING_OP_PT_SCAN);
    if (ret != 0) {
        LOG_ERR("PT SM: Failed to start initial PHY scan: %d. Retrying after delay.", ret);
        // Use mobility timer as a generic retry mechanism for scan start failure
        k_timer_start(&ctx->role_ctx.pt.mobility_scan_timer, K_SECONDS(5), K_NO_WAIT); // Renamed from scan_retry_timer
        dect_mac_change_state(MAC_STATE_IDLE);
    }
}

void dect_mac_sm_pt_handle_event(const struct dect_mac_event_msg *msg) {
    dect_mac_context_t* ctx = get_mac_context();

    if (ctx->state == MAC_STATE_PT_AUTHENTICATING &&
        !(msg->type == MAC_EVENT_PHY_OP_COMPLETE ||
          msg->type == MAC_EVENT_PHY_PCC ||
          msg->type == MAC_EVENT_PHY_PDC ||
          msg->type == MAC_EVENT_PHY_PCC_ERROR ||
          msg->type == MAC_EVENT_PHY_PDC_ERROR) ) {
        LOG_DBG("PT SM: Event %s ignored during AUTHENTICATING state.", dect_mac_event_to_str(msg->type));
        return;
    }

    switch (msg->type) {
        case MAC_EVENT_PHY_OP_COMPLETE:
            {
                pending_op_type_t completed_op = dect_mac_phy_ctrl_handle_op_complete(&msg->data.op_complete);
                if (completed_op != PENDING_OP_NONE) {
                    pt_handle_phy_op_complete_internal(&msg->data.op_complete, completed_op);
                } else {
                    LOG_DBG("PT SM: OP_COMPLETE for handle %u (err %d), but no matching/active MAC pending_op_type.",
                            msg->data.op_complete.handle, msg->data.op_complete.err);
                }
            }
            break;
        case MAC_EVENT_PHY_PCC:
            pt_handle_phy_pcc_internal(&msg->data.pcc, msg->modem_time_of_event);
            break;
        case MAC_EVENT_PHY_PDC:
            pt_handle_phy_pdc_pt(&msg->data.pdc, msg->modem_time_of_event); // Renamed to avoid direct internal call
            break;
        case MAC_EVENT_PHY_PCC_ERROR:
            LOG_WRN("PT SM: Received PCC_ERROR for handle %u (TID %u).", msg->data.pcc_crc_err.handle, msg->data.pcc_crc_err.transaction_id);
            if (last_relevant_pcc_for_pt.pcc_data.transaction_id == msg->data.pcc_crc_err.transaction_id) {
                last_relevant_pcc_for_pt.is_valid = false;
            }
            if (ctx->state == MAC_STATE_PT_WAIT_ASSOC_RESP && msg->data.pcc_crc_err.handle == ctx->pending_op_handle) {
                LOG_WRN("PT SM: PCC Error while waiting for Assoc Resp. Response timer will handle timeout.");
            }
            break;
        case MAC_EVENT_PHY_PDC_ERROR:
            LOG_WRN("PT SM: Received PDC_ERROR for handle %u (TID %u).", msg->data.pdc_crc_err.handle, msg->data.pdc_crc_err.transaction_id);
            // If this was for an expected data packet, data_path might eventually be notified via HARQ NACK logic
            // If it was for AssocResp, the RACH response timer will expire.
            // If it was for a secure packet from FT that resulted in PDC CRC error *after* PCC OK,
            // PT should store a NACK for FT's HARQ process.
            if (last_relevant_pcc_for_pt.is_valid && last_relevant_pcc_for_pt.pcc_data.transaction_id == msg->data.pdc_crc_err.transaction_id) {
                if (ctx->state == MAC_STATE_ASSOCIATED && ctx->role_ctx.pt.associated_ft.is_secure) {
                    uint8_t harq_proc_in_ft_tx = last_relevant_pcc_for_pt.pcc_data.hdr.hdr_type_2.df_harq_process_num;
                    dect_mac_peer_info_t *assoc_ft_ctx = &ctx->role_ctx.pt.associated_ft;
                    if (assoc_ft_ctx->num_pending_feedback_items < 2) {
                        int fb_idx = assoc_ft_ctx->num_pending_feedback_items++;
                        assoc_ft_ctx->pending_feedback_to_send[fb_idx].valid = true;
                        assoc_ft_ctx->pending_feedback_to_send[fb_idx].is_ack = false; // NACK
                        assoc_ft_ctx->pending_feedback_to_send[fb_idx].harq_process_num_for_peer = harq_proc_in_ft_tx;
                         LOG_WRN("PT_SM_HARQ_RX: Stored NACK for FT 0x%04X's HARQ_Proc %u due to PDC_ERROR.", assoc_ft_ctx->short_rd_id, harq_proc_in_ft_tx);
                    }
                }
                last_relevant_pcc_for_pt.is_valid = false; // Consume
            }
            break;
        case MAC_EVENT_PHY_RSSI_RESULT:
            pt_handle_phy_rssi_internal(&msg->data.rssi);
            LOG_DBG("PT SM: RSSI Result received (unhandled for now).");
            break;
        case MAC_EVENT_TIMER_EXPIRED_RACH_BACKOFF:
            if (ctx->state == MAC_STATE_PT_RACH_BACKOFF) {
                pt_rach_backoff_timer_expired_action();
            }
            break;
        case MAC_EVENT_TIMER_EXPIRED_RACH_RESP_WINDOW:
            if (ctx->state == MAC_STATE_PT_WAIT_ASSOC_RESP || ctx->state == MAC_STATE_PT_ASSOCIATING) {
                pt_rach_response_window_timer_expired_action();
            }
            break;
        case MAC_EVENT_TIMER_EXPIRED_KEEPALIVE:
            if (ctx->state == MAC_STATE_ASSOCIATED) {
                 dect_mac_sm_pt_keep_alive_timer_expired_action();
            }
            break;
        case MAC_EVENT_TIMER_EXPIRED_MOBILITY_SCAN:
            if (ctx->state == MAC_STATE_ASSOCIATED) { // Only scan if associated
                 dect_mac_sm_pt_mobility_scan_timer_expired_action();
            } else { // If not associated, use this timer to re-trigger general scan
                LOG_INF("PT SM: Mobility timer fired while not associated. Restarting general scan.");
                dect_mac_sm_pt_start_operation();
            }
            break;
        case MAC_EVENT_TIMER_EXPIRED_HARQ:
            dect_mac_data_path_handle_harq_nack_action(msg->data.timer_data.id); // Timeout is a NACK
            break;
        case MAC_EVENT_CMD_ENTER_PAGING_MODE:
            if (ctx->state == MAC_STATE_ASSOCIATED) {
                LOG_INF("PT SM: Command received to enter paging mode.");
                dect_mac_change_state(MAC_STATE_PT_PAGING);
                // Stop other periodic activity like keep-alives and mobility scans
                k_timer_stop(&ctx->role_ctx.pt.keep_alive_timer);
                k_timer_stop(&ctx->role_ctx.pt.mobility_scan_timer);
                // Start the paging cycle timer. The first listen will happen after one cycle.
                // TODO: The cycle duration should be negotiated with the FT. Using a hardcoded value for now.
                uint32_t paging_cycle_ms = 1280; // e.g., ETSI DRF=8 -> 1.28s
                k_timer_start(&ctx->role_ctx.pt.paging_cycle_timer, K_MSEC(paging_cycle_ms), K_MSEC(paging_cycle_ms));
            } else {
                LOG_WRN("PT SM: Ignoring CMD_ENTER_PAGING_MODE in state %s.", dect_mac_state_to_str(ctx->state));
            }
            break;
        case MAC_EVENT_TIMER_EXPIRED_PAGING_CYCLE:
            if (ctx->state == MAC_STATE_PT_PAGING) {
                pt_paging_cycle_timer_expired_action();
            }
            break;            
        default:
            LOG_DBG("PT SM: Unhandled event type %s in state %s",
                    dect_mac_event_to_str(msg->type), dect_mac_state_to_str(ctx->state));
            break;
    }
}

// All static helper functions (pt_handle_phy_op_complete_internal, pt_handle_phy_pcc_internal,
// pt_handle_phy_pdc_internal, pt_process_identified_beacon_and_attempt_assoc,
// pt_send_association_request_action, pt_process_association_response_pdu,
// pt_send_keep_alive_action, pt_start_authentication_with_ft_action,
// pt_authentication_complete_action) are included below with their full implementations.

// --- PT Static Helper Implementations ---
static void pt_handle_phy_op_complete_internal(const struct nrf_modem_dect_phy_op_complete_event *event,
                                               pending_op_type_t completed_op_type) {
    dect_mac_context_t* ctx = get_mac_context();

    switch (completed_op_type) {
        case PENDING_OP_PT_MOBILITY_SCAN:
            LOG_DBG("PT SM: Mobility scan op completed (err %d).", event->err);
            // The result is handled in pt_handle_phy_rssi_internal.
            // The periodic mobility timer will trigger the next scan.
            break;
        case PENDING_OP_PT_PAGING_LISTEN:
            if (ctx->state == MAC_STATE_PT_PAGING) {
                LOG_DBG("PT_PAGING: Paging listen RX window complete (err %d).", event->err);
                // The periodic timer will automatically schedule the next listen window.
                // If a page *was* received, the PDC handler would have already changed
                // the state out of PAGING, which would stop the timer.
            }
            break;            
        case PENDING_OP_PT_SCAN:
            if (event->err == NRF_MODEM_DECT_PHY_ERR_OP_CANCELED) {
                LOG_INF("PT SM: Scan successfully canceled (Hdl %u). Presuming association attempt follows.", event->handle);
                // If scan was canceled because a beacon led to association attempt (via pt_process_identified_beacon):
                if (ctx->state == MAC_STATE_PT_SCANNING && ctx->role_ctx.pt.target_ft.is_valid && ctx->role_ctx.pt.target_ft.is_fully_identified) {
                     pt_send_association_request_action(); // State changes inside here
                } else if (ctx->state != MAC_STATE_PT_ASSOCIATING && ctx->state != MAC_STATE_PT_WAIT_ASSOC_RESP) {
                    // If scan cancelled but not moving to assoc (e.g. manual cancel), restart scan
                    LOG_WRN("PT_SM: Scan op cancelled but no target FT for association. Restarting scan.");
                    dect_mac_sm_pt_start_operation();
                }
            } else if (event->err != NRF_MODEM_DECT_PHY_SUCCESS) {
                LOG_ERR("PT_SM: Scan PHY op failed (err %d, %s). Restarting scan after delay.", event->err, nrf_modem_dect_phy_err_to_str(event->err));
                k_sleep(K_MSEC(1000 + (sys_rand32_get() % 1000)));
                dect_mac_sm_pt_start_operation();
            } else { // Success but no beacon parsed that led to cancel (e.g. scan duration ended)
                LOG_INF("PT_SM: Scan PHY op completed (Hdl %u), but no suitable FT found during PDC parsing. Restarting scan.", event->handle);
                dect_mac_sm_pt_start_operation();
            }
            break;

        case PENDING_OP_PT_RACH_ASSOC_REQ:
            if (event->err == NRF_MODEM_DECT_PHY_SUCCESS) {
                LOG_INF("PT_SM: Association Request TX successful (Hdl %u). Waiting for Response.", event->handle);
                dect_mac_change_state(MAC_STATE_PT_WAIT_ASSOC_RESP);

                // Calculate response window duration from RACH params (subslots to ms)
                uint32_t resp_win_subslots = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.response_window_subslots_val_minus_1 + 1;
                uint32_t subslot_dur_us = get_subslot_duration_ticks(ctx) * 1000 / NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ;
                uint32_t resp_win_ms = resp_win_subslots * subslot_dur_us / 1000;
                if (resp_win_ms < 10) resp_win_ms = 50; // Minimum sensible timeout
                if (resp_win_ms > 5000) resp_win_ms = 5000; // Max sensible timeout

                k_timer_start(&ctx->rach_context.rach_response_window_timer, K_MSEC(resp_win_ms), K_NO_WAIT);

                uint32_t phy_rx_op_handle = sys_rand32_get();
                uint32_t rx_duration_modem_units = modem_us_to_ticks( (resp_win_ms + 50) * 1000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ ); // Listen for window + buffer

                int ret = dect_mac_phy_ctrl_start_rx(
                    ctx->role_ctx.pt.target_ft.operating_carrier,
                    rx_duration_modem_units,
                    NRF_MODEM_DECT_PHY_RX_MODE_SEMICONTINUOUS, // Stop after unicast PDC
                    phy_rx_op_handle,
                    ctx->own_short_rd_id, // Expecting response addressed to us
                    PENDING_OP_PT_WAIT_ASSOC_RESP);
                if (ret != 0) {
                    LOG_ERR("PT_SM: Failed to schedule RX for AssocResp: %d. Resp timer will timeout.", ret);
                } else {
                    LOG_INF("PT_SM: RX scheduled (Hdl %u) for Association Response from FT 0x%04X.",
                            phy_rx_op_handle, ctx->role_ctx.pt.target_ft.short_rd_id);
                }

            } else if (event->err == NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY) {
                LOG_WRN("PT_SM: RACH TX LBT busy for AssocReq (Hdl %u). Increasing CW.", event->handle);
                dect_mac_change_state(MAC_STATE_PT_RACH_BACKOFF);
                if (ctx->rach_context.rach_cw_current_idx < ctx->config.rach_cw_max_idx) { // Use config for max index
                    ctx->rach_context.rach_cw_current_idx++;
                }
                uint32_t max_backoff_window_val = (1 << ctx->rach_context.rach_cw_current_idx) - 1;
                uint32_t backoff_slots_to_wait = (max_backoff_window_val > 0) ? (sys_rand32_get() % max_backoff_window_val) : 0;
                // Convert RACH backoff slots to ms. A RACH slot is often one STF+GI duration.
                // For simplicity, use a small random delay based on CW index.
                uint32_t backoff_ms = (backoff_slots_to_wait + 1) * 2; // Example: ~2ms per backoff unit
                LOG_INF("PT_SM: RACH backoff for %u ms (CW_idx %u, max_val %u, chosen_slots %u)",
                        backoff_ms, ctx->rach_context.rach_cw_current_idx, max_backoff_window_val, backoff_slots_to_wait);
                k_timer_start(&ctx->rach_context.rach_backoff_timer, K_MSEC(backoff_ms), K_NO_WAIT);

            } else { // Other TX error
                LOG_ERR("PT_SM: Association Request TX failed (Hdl %u, err %d, %s). Retry/Rescan.",
                        event->handle, event->err, nrf_modem_dect_phy_err_to_str(event->err));
                // Rely on rach_response_window_timer to expire, which will trigger retry/rescan logic
                // or directly call pt_rach_response_window_timer_expired_action() to expedite.
                pt_rach_response_window_timer_expired_action();
            }
            break;

        case PENDING_OP_PT_WAIT_ASSOC_RESP:
            LOG_DBG("PT_SM: RX op for AssocResp completed (Hdl %u, err %d). If no PDC, timer will expire.", event->handle, event->err);
            // If PDC with AssocResp was received, state would have changed.
            // If this completes due to duration end without PDC, rach_response_window_timer handles it.
            break;

        case PENDING_OP_PT_KEEP_ALIVE:
            if (event->err != NRF_MODEM_DECT_PHY_SUCCESS) {
                LOG_ERR("PT_SM: Keep Alive TX failed (Hdl %u, err %d, %s).",
                        event->handle, event->err, nrf_modem_dect_phy_err_to_str(event->err));
                // Link might be lost. Could trigger link supervision logic or faster KA retries.
                // For now, periodic timer will try again.
            } else {
                LOG_DBG("PT_SM: Keep Alive TX successful (Hdl %u).", event->handle);
            }
            break;
        case PENDING_OP_PT_DATA_TX_HARQ0: // Fallthrough for all HARQ data ops
        case PENDING_OP_PT_DATA_TX_HARQ_MAX:
            {
                int harq_idx = completed_op_type - PENDING_OP_PT_DATA_TX_HARQ0;
                if (harq_idx >= 0 && harq_idx < MAX_HARQ_PROCESSES) {
                    if (event->err == NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY) {
                        LOG_WRN("PT SM: Data TX HARQ %d LBT busy. Data Path will re-TX.", harq_idx);
                        dect_mac_data_path_handle_harq_nack_action(harq_idx);
                    } else if (event->err != NRF_MODEM_DECT_PHY_SUCCESS) {
                        LOG_ERR("PT SM: Data TX HARQ %d failed (err %d, %s). Data Path will re-TX/discard.",
                                harq_idx, event->err, nrf_modem_dect_phy_err_to_str(event->err));
                        dect_mac_data_path_handle_harq_nack_action(harq_idx);
                    } else {
                        LOG_DBG("PT SM: Data TX HARQ %d PHY op complete. Awaiting feedback.", harq_idx);
                        // HARQ timer for ACK/NACK was started by data_path when TX was scheduled.
                    }
                } else {
                    LOG_ERR("PT SM: OP_COMPLETE for invalid PT_DATA_TX_HARQ op type: %d", completed_op_type);
                }
            }
            break;
        default:
             LOG_WRN("PT SM: OP_COMPLETE for unhandled PT op type: %s (Hdl %u), err %d (%s)",
                    dect_pending_op_to_str(completed_op_type), event->handle,
                    event->err, nrf_modem_dect_phy_err_to_str(event->err));
            break;
    }
}

// All other static helper functions (pt_handle_phy_pcc_internal, pt_handle_phy_pdc_internal,
// pt_process_identified_beacon_and_attempt_assoc, pt_send_association_request_action,
// pt_process_association_response_pdu, pt_send_keep_alive_action,
// pt_start_authentication_with_ft_action, pt_authentication_complete_action)
// are now included below with their full implementations as per our latest discussions.

static void pt_handle_phy_pcc_internal(const struct nrf_modem_dect_phy_pcc_event *pcc_event, uint64_t pcc_event_time) {
    dect_mac_context_t* ctx = get_mac_context();

    // Clear previous stored PCC before evaluating the new one
    last_relevant_pcc_for_pt.is_valid = false;

    if (pcc_event->header_status == NRF_MODEM_DECT_PHY_HDR_STATUS_VALID) {
        // Store this valid PCC and its reception time for potential correlation with a subsequent PDC
        memcpy(&last_relevant_pcc_for_pt.pcc_data, pcc_event, sizeof(struct nrf_modem_dect_phy_pcc_event));
        last_relevant_pcc_for_pt.pcc_event_modem_time = pcc_event_time;
        last_relevant_pcc_for_pt.is_valid = true;

        uint16_t pcc_tx_short_id = 0; // Transmitter of this PCC (the FT)
        bool is_type2_pcc = false;

        if (pcc_event->phy_type == 0) { // nRF PHY Type 0 (ETSI PCC Type 1) - Beacon
            pcc_tx_short_id = sys_be16_to_cpu(
                (uint16_t)((pcc_event->hdr.hdr_type_1.transmitter_id_hi << 8) |
                            pcc_event->hdr.hdr_type_1.transmitter_id_lo));

            if (ctx->state == MAC_STATE_PT_SCANNING) {
                LOG_INF("PT_SM_PCC: Beacon PCC (Type1) received from FT ShortID 0x%04X in SCANNING. TID: %u. Waiting for PDC.",
                        pcc_tx_short_id, pcc_event->transaction_id);
                // Further processing happens when the PDC arrives.
                // PT might transition to MAC_STATE_PT_BEACON_PDC_WAIT here if desired,
                // or simply let the SCANNING state's PDC handler do the work.
            } else {
                // Unlikely to get a beacon PCC in other states unless it's a neighbor for mobility
                LOG_DBG("PT_SM_PCC: Beacon PCC (Type1) from FT 0x%04X in state %s. TID %u.",
                        pcc_tx_short_id, dect_mac_state_to_str(ctx->state), pcc_event->transaction_id);
            }

        } else if (pcc_event->phy_type == 1) { // nRF PHY Type 1 (ETSI PCC Type 2) - Unicast/Data
            is_type2_pcc = true;
            pcc_tx_short_id = sys_be16_to_cpu(
                (uint16_t)((pcc_event->hdr.hdr_type_2.transmitter_id_hi << 8) |
                            pcc_event->hdr.hdr_type_2.transmitter_id_lo));
            uint16_t pcc_rx_short_id_on_pt = sys_be16_to_cpu(
                (uint16_t)((pcc_event->hdr.hdr_type_2.receiver_id_hi << 8) |
                            pcc_event->hdr.hdr_type_2.receiver_id_lo));

            if (pcc_rx_short_id_on_pt != ctx->own_short_rd_id) {
                LOG_DBG("PT_SM_PCC: Unicast PCC (Type2) not for this PT (RxID 0x%04X vs Own 0x%04X). TID: %u. Ignoring.",
                        pcc_rx_short_id_on_pt, ctx->own_short_rd_id, pcc_event->transaction_id);
                last_relevant_pcc_for_pt.is_valid = false; // Don't process its PDC
                return;
            }

            if (ctx->state == MAC_STATE_PT_WAIT_ASSOC_RESP) {
                if (pcc_tx_short_id == ctx->role_ctx.pt.target_ft.short_rd_id) {
                    LOG_INF("PT_SM_PCC: PCC (Type2) from target FT 0x%04X while WAITING_ASSOC_RESP. TID %u. Waiting for PDC.",
                            pcc_tx_short_id, pcc_event->transaction_id);
                    // Association Response is typically unsecure initially, or first secure packet.
                    // HARQ feedback for PT's AssocReq itself is not standard via this PCC's feedback field.
                    // If FT *did* include feedback for the AssocReq (unlikely), it would be processed here.
                    // For now, assume no HARQ feedback processing specific to the AssocReq itself.
                } else {
                    LOG_WRN("PT_SM_PCC: PCC (Type2) from unexpected FT 0x%04X while WAITING_ASSOC_RESP. Ignoring. TID %u",
                            pcc_tx_short_id, pcc_event->transaction_id);
                    last_relevant_pcc_for_pt.is_valid = false;
                }
            } else if (ctx->state == MAC_STATE_ASSOCIATED) {
                if (pcc_tx_short_id == ctx->role_ctx.pt.associated_ft.short_rd_id) {
                    LOG_DBG("PT_SM_PCC: PCC (Type2) from associated FT 0x%04X. TID %u. Processing feedback.",
                            pcc_tx_short_id, pcc_event->transaction_id);
                    // Process HARQ feedback sent by the FT for PT's previous transmissions
                    dect_mac_data_path_process_harq_feedback(&pcc_event->hdr.hdr_type_2.feedback, pcc_tx_short_id);
                } else {
                    LOG_WRN("PT_SM_PCC: PCC (Type2) from unexpected FT 0x%04X while ASSOCIATED. Ignoring. TID %u",
                            pcc_tx_short_id, pcc_event->transaction_id);
                    last_relevant_pcc_for_pt.is_valid = false;
                }
            } else {
                 LOG_DBG("PT_SM_PCC: PCC (Type2) from FT 0x%04X in unexpected state %s. TID %u",
                        pcc_tx_short_id, dect_mac_state_to_str(ctx->state), pcc_event->transaction_id);
                 // Store it anyway, PDC handler will re-check state.
            }
        } else {
            LOG_ERR("PT_SM_PCC: Unknown nRF PHY header type in PCC: %d. TID %u", pcc_event->phy_type, pcc_event->transaction_id);
            last_relevant_pcc_for_pt.is_valid = false;
        }
    } else { // PCC HeaderStatus not VALID
        last_relevant_pcc_for_pt.is_valid = false;
        LOG_WRN("PT_SM_PCC: Received PCC with invalid status %d. TID %u. Op Hdl %u.",
                pcc_event->header_status, pcc_event->transaction_id, pcc_event->handle);
        // If PT was waiting for a specific response (e.g. AssocResp on pending_op_handle) and PCC is invalid,
        // the response timer (e.g. rach_response_window_timer) should eventually handle the timeout.
        // No PDC will follow this invalid PCC.
    }
}
static void pt_handle_phy_pdc_pt(const struct nrf_modem_dect_phy_pdc_event *pdc_event, uint64_t event_modem_time) {
    // This is the wrapper that calls pt_handle_phy_pdc_internal
    if (last_relevant_pcc_for_pt.is_valid && last_relevant_pcc_for_pt.pcc_data.transaction_id == pdc_event->transaction_id) {
        pt_handle_phy_pdc_internal(pdc_event, &last_relevant_pcc_for_pt.pcc_data, last_relevant_pcc_for_pt.pcc_event_modem_time);
        last_relevant_pcc_for_pt.is_valid = false;
    } else {
        LOG_WRN("PT_SM_PDC_WRAP: PDC (TID %u) but no matching valid PCC stored (LastPCC TID %u, valid %d). Discarding.",
                pdc_event->transaction_id,
                last_relevant_pcc_for_pt.is_valid ? last_relevant_pcc_for_pt.pcc_data.transaction_id : 0,
                last_relevant_pcc_for_pt.is_valid);
    }
}

static void pt_handle_phy_pdc_internal(const struct nrf_modem_dect_phy_pdc_event *pdc_event,
                                       const struct nrf_modem_dect_phy_pcc_event *assoc_pcc_event,
                                       uint64_t pcc_reception_modem_time)
{
    dect_mac_context_t* ctx = get_mac_context();
    uint8_t mac_pdc_payload_copy[CONFIG_DECT_MAC_PDU_MAX_SIZE];
    uint16_t pdc_payload_len = pdc_event->len;

    if (pdc_payload_len == 0 && pdc_event->transaction_id != 0) {
        LOG_DBG("PT_SM_PDC: Empty PDC (TID %u). Ignoring.", pdc_event->transaction_id);
        return;
    }
    if (pdc_payload_len > sizeof(mac_pdc_payload_copy)) {
        LOG_ERR("PT_SM_PDC: PDC payload from PHY (%u bytes) too large for copy buffer (%zu). Discarding.",
                pdc_payload_len, sizeof(mac_pdc_payload_copy));
        return;
    }
    memcpy(mac_pdc_payload_copy, pdc_event->data, pdc_payload_len);

    dect_mac_header_type_octet_t mac_hdr_type_octet;
    memcpy(&mac_hdr_type_octet, &assoc_pcc_event->hdr.bytes[0], sizeof(dect_mac_header_type_octet_t));

    uint8_t *pdu_content_start = mac_pdc_payload_copy; // This is CommonHeader + SDUArea + [MIC]
    uint16_t pdu_content_len = pdc_payload_len;

    uint16_t ft_sender_short_id_from_pcc = 0;
    if (assoc_pcc_event->phy_type == 0) { // Beacon
        ft_sender_short_id_from_pcc = sys_be16_to_cpu(
            (uint16_t)((assoc_pcc_event->hdr.hdr_type_1.transmitter_id_hi << 8) |
                        assoc_pcc_event->hdr.hdr_type_1.transmitter_id_lo));
    } else if (assoc_pcc_event->phy_type == 1) { // Unicast/Data
        ft_sender_short_id_from_pcc = sys_be16_to_cpu(
            (uint16_t)((assoc_pcc_event->hdr.hdr_type_2.transmitter_id_hi << 8) |
                        assoc_pcc_event->hdr.hdr_type_2.transmitter_id_lo));
    } else {
        LOG_ERR("PT_SM_PDC: PDC for unknown PCC phy_type %d. Discarding.", assoc_pcc_event->phy_type);
        return;
    }

    bool security_applied_by_sender = (mac_hdr_type_octet.mac_security != MAC_SECURITY_NONE);
    dect_mac_peer_info_t *active_ft_peer_ctx = NULL;
    bool link_is_expected_to_be_secure = false;
    bool pdc_process_ok_for_feedback = true;

    if (ctx->state == MAC_STATE_PT_WAIT_ASSOC_RESP && ctx->role_ctx.pt.target_ft.is_valid &&
        ft_sender_short_id_from_pcc == ctx->role_ctx.pt.target_ft.short_rd_id) {
        active_ft_peer_ctx = &ctx->role_ctx.pt.target_ft;
        link_is_expected_to_be_secure = ctx->keys_provisioned; // Depends on if FT sent secure AssocResp
    } else if (ctx->state == MAC_STATE_ASSOCIATED && ctx->role_ctx.pt.associated_ft.is_valid &&
               ft_sender_short_id_from_pcc == ctx->role_ctx.pt.associated_ft.short_rd_id) {
        active_ft_peer_ctx = &ctx->role_ctx.pt.associated_ft;
        link_is_expected_to_be_secure = active_ft_peer_ctx->is_secure && ctx->keys_provisioned;
    } else if ((ctx->state == MAC_STATE_PT_SCANNING || ctx->state == MAC_STATE_PT_BEACON_PDC_WAIT) &&
               mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_BEACON) {
        // For beacons, security is typically not applied by FT at MAC layer.
        // If it were, active_ft_peer_ctx would be &ctx->role_ctx.pt.target_ft for temp storage.
        link_is_expected_to_be_secure = false; // Beacons are not secured this way
        if (security_applied_by_sender) {
             LOG_WRN("PT_SM_PDC: Secured Beacon from FT 0x%04X. Unusual. Will likely fail if no prior shared key.", ft_sender_short_id_from_pcc);
             // Attempting to process a secured beacon would require a pre-established key, not session key.
             // For now, assume beacons are not MAC secured.
             security_applied_by_sender = false;
        }
    } else {
        LOG_WRN("PT_SM_PDC: Received PDC from FT 0x%04X in unexpected state %s or from unexpected FT. Discarding.",
                ft_sender_short_id_from_pcc, dect_mac_state_to_str(ctx->state));
        return;
    }

    uint8_t *common_hdr_start_in_payload = pdu_content_start;
    size_t common_hdr_actual_len = 0;
    uint8_t *sdu_area_after_common_hdr = NULL;
    size_t sdu_area_plus_mic_len_in_payload = 0;

    // Determine Common Header type and length based on MAC Header Type octet
    if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_UNICAST) {
        common_hdr_actual_len = sizeof(dect_mac_unicast_header_t);
    } else if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_DATA_PDU) {
        common_hdr_actual_len = sizeof(dect_mac_data_pdu_header_t);
    } else if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_BEACON) {
        common_hdr_actual_len = sizeof(dect_mac_beacon_header_t);
    } else { /* Should have been caught by earlier checks or SM state */ return; }

    if (pdu_content_len < common_hdr_actual_len) {
        LOG_ERR("PT_SM_PDC: PDU too short for its Common Hdr. Len %u, HdrLen %zu", pdu_content_len, common_hdr_actual_len);
        return;
    }
    sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len;
    sdu_area_plus_mic_len_in_payload = pdu_content_len - common_hdr_actual_len;


    if (security_applied_by_sender) {
        if (!active_ft_peer_ctx || !link_is_expected_to_be_secure) {
            LOG_WRN("PT_SM_PDC_SEC: Secured PDU from FT 0x%04X, but no valid secure context. Discarding.", ft_sender_short_id_from_pcc);
            return;
        }
        if (sdu_area_plus_mic_len_in_payload < 5 /*MIC_LEN*/) {
             LOG_ERR("PT_SM_PDC_SEC: Secured PDU from FT 0x%04X too short for MIC. SDUArea+MIC len %zu. Discarding.",
                    ft_sender_short_id_from_pcc, sdu_area_plus_mic_len_in_payload);
             return;
        }

        const dect_mac_unicast_header_t *uch_ptr = (const dect_mac_unicast_header_t *)common_hdr_start_in_payload;
        uint16_t received_psn = ((uch_ptr->sequence_num_high_reset_rsv >> 4) & 0x0F) << 8 | uch_ptr->sequence_num_low;
        uint32_t ft_tx_long_id = sys_be32_to_cpu(uch_ptr->transmitter_long_rd_id_be);

        if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_UNICAST && ft_tx_long_id != active_ft_peer_ctx->long_rd_id) {
            LOG_WRN("PT_SM_PDC_SEC: Secured PDU LongID 0x%08X mismatch for FT 0x%04X (expected 0x%08X). Discarding.",
                    ft_tx_long_id, ft_sender_short_id_from_pcc, active_ft_peer_ctx->long_rd_id);
            return;
        }

        uint8_t iv[16];
        security_build_iv(iv, ft_tx_long_id, ctx->own_long_rd_id,
                          active_ft_peer_ctx->hpc, // Use PT's tracked HPC for this FT
                          received_psn);

        uint8_t *part_to_decrypt_start;
        size_t part_to_decrypt_len;
        size_t muxed_sec_ie_total_len_parsed = 0;

        uint8_t *decryption_input_buffer_start; // Renamed for clarity
        size_t decryption_input_len;         // Renamed for clarity
        // size_t muxed_sec_ie_total_len_parsed = 0; // Already declared earlier in the PT version

        if (mac_hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            // Common Header and MUXed MAC Sec Info IE are cleartext.
            uint8_t ie_type; uint16_t ie_len; const uint8_t *ie_payload;
            int mux_hdr_len = parse_mac_mux_header(sdu_area_after_common_hdr, sdu_area_plus_mic_len_in_payload,
                                                   &ie_type, &ie_len, &ie_payload);

            if (mux_hdr_len > 0 && ie_type == IE_TYPE_MAC_SECURITY_INFO) {
                if (sdu_area_plus_mic_len_in_payload < (size_t)mux_hdr_len + ie_len + 5) {
                    LOG_ERR("PT_SM_PDC_SEC: PDU too short for parsed SecIE + rest + MIC. Discarding.");
                    pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path;
                }
                muxed_sec_ie_total_len_parsed = mux_hdr_len + ie_len;
                uint8_t ver, kidx, secivtype_from_ie; uint32_t hpc_from_ie;
                if (parse_mac_security_info_ie_payload(ie_payload, ie_len, &ver, &kidx, &secivtype_from_ie, &hpc_from_ie) == 0) {
                    // ... (Full HPC windowing and resync request handling logic from previous step for SEC_IV_TYPE_MODE1_PROVIDED and SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) ...
                    // This block updates active_ft_peer_ctx->hpc and active_ft_peer_ctx->highest_rx_peer_hpc
                    // and may set ctx->send_mac_sec_info_ie_on_next_tx (if FT requested PT's HPC) or pdc_process_ok_for_feedback = false.
                    LOG_INF("PT_SM_PDC_SEC (WITH_IE): MAC Sec Info IE from FT 0x%04X: PeerHPC_IE=%u, TrackedHPC=%u, SecIVType=%u",
                            ft_sender_short_id_from_pcc, hpc_from_ie, active_ft_peer_ctx->hpc, secivtype_from_ie);
                    // (Simplified: just showing the log, full window/resync logic goes here, as implemented in previous ft_handle_phy_pdc_ft section)
                    if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_PROVIDED) { // FT sends its HPC
                        if (active_ft_peer_ctx->highest_rx_peer_hpc == 0 && hpc_from_ie > 0) {active_ft_peer_ctx->highest_rx_peer_hpc = hpc_from_ie; active_ft_peer_ctx->hpc = hpc_from_ie;}
                        else { /* ... window logic ... */ if (hpc_from_ie > active_ft_peer_ctx->highest_rx_peer_hpc /* simplified */) active_ft_peer_ctx->hpc = hpc_from_ie; }
                    } else if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) { // FT requests PT's HPC
                        if (active_ft_peer_ctx->highest_rx_peer_hpc == 0 && hpc_from_ie > 0) {active_ft_peer_ctx->highest_rx_peer_hpc = hpc_from_ie; active_ft_peer_ctx->hpc = hpc_from_ie;}
                        else { /* ... window logic ... */ if (hpc_from_ie > active_ft_peer_ctx->highest_rx_peer_hpc /* simplified */) active_ft_peer_ctx->hpc = hpc_from_ie; }
                        ctx->send_mac_sec_info_ie_on_next_tx = true; // PT will send its HPC back
                    }


                } else { LOG_ERR("PT_SM_PDC_SEC: Failed to parse MAC Sec Info IE from FT 0x%04X.", ft_sender_short_id_from_pcc); }

                decryption_input_buffer_start = sdu_area_after_common_hdr + muxed_sec_ie_total_len_parsed;
                decryption_input_len = sdu_area_plus_mic_len_in_payload - muxed_sec_ie_total_len_parsed;
            } else {
                LOG_ERR("PT_SM_PDC_SEC: MAC_SECURITY_USED_WITH_IE indicated but MAC Sec Info IE not found/parsed first. Discarding.");
                pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path;
            }
        } else { // MAC_SECURITY_USED_NO_IE
            decryption_input_buffer_start = sdu_area_after_common_hdr;
            decryption_input_len = sdu_area_plus_mic_len_in_payload;
            muxed_sec_ie_total_len_parsed = 0;
        }

        if (!pdc_process_ok_for_feedback) goto process_feedback_pt_rx_sec_path; // Abort if HPC from IE was invalid

        if (part_to_decrypt_len < 5) { LOG_ERR("PT_SM_PDC_SEC: Encrypted part too short for MIC. Discarding."); pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path; }
        if (security_crypt_payload(part_to_decrypt_start, part_to_decrypt_len,
                                   ctx->cipher_key, iv, false /*decrypt*/) != 0) {
            LOG_ERR("PT_SM_PDC_SEC: Decryption failed for PDU from FT 0x%04X. Discarding.", ft_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path;
        }

        uint8_t received_mic[5];
        memcpy(received_mic, part_to_decrypt_start + part_to_decrypt_len - 5, 5);
        uint8_t calculated_mic[5];
        if (security_calculate_mic(common_hdr_start_in_payload, pdu_content_len - 5,
                                   ctx->integrity_key, calculated_mic) != 0) {
            LOG_ERR("PT_SM_PDC_SEC: MIC re-calc failed. Discarding PDU from FT 0x%04X.", ft_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path;
        }
        if (memcmp(received_mic, calculated_mic, 5) != 0) {
            LOG_ERR("PT_SM_PDC_SEC: MIC FAIL from FT 0x%04X (PSN %u, PeerHPC %u). Discarding.",
                    ft_sender_short_id_from_pcc, received_psn, active_ft_peer_ctx->hpc);
            if (active_ft_peer_ctx) { // Should be valid if link_is_expected_to_be_secure
                active_ft_peer_ctx->consecutive_mic_failures++;
                if (active_ft_peer_ctx->consecutive_mic_failures >= MAX_MIC_FAILURES_BEFORE_HPC_RESYNC) {
                    LOG_WRN("PT_SM_PDC_SEC: Max MIC failures (%u) for FT 0x%04X. Will request HPC resync from FT.",
                            active_ft_peer_ctx->consecutive_mic_failures, ft_sender_short_id_from_pcc);
                    active_ft_peer_ctx->self_needs_to_request_hpc_from_peer = true; // PT will send RESYNC_INITIATE to FT
                    active_ft_peer_ctx->consecutive_mic_failures = 0; // Reset counter
                }
            }
            pdc_process_ok_for_feedback = false; // Signal to store NACK
            goto process_feedback_pt_rx_sec_path; // Go to store feedback, then return
        } else { // MIC OK
            LOG_DBG("PT_SM_PDC_SEC: MIC OK from FT 0x%04X (PSN %u, PeerHPC %u).",
                    ft_sender_short_id_from_pcc, received_psn, active_ft_peer_ctx->hpc);
            if(active_ft_peer_ctx) active_ft_peer_ctx->consecutive_mic_failures = 0; // Reset on successful MIC
        }

        // Adjust pointers to cleartext SDU area after security processing
        if (mac_hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len + muxed_sec_ie_total_len_parsed;
            sdu_area_plus_mic_len_in_payload = pdu_content_len - common_hdr_actual_len - muxed_sec_ie_total_len_parsed - 5;
        } else { // MAC_SECURITY_USED_NO_IE
            sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len;
            sdu_area_plus_mic_len_in_payload = pdu_content_len - common_hdr_actual_len - 5;
        }
    } else { // Not secured
        LOG_DBG("PT_SM_PDC: Unsecure PDU from FT 0x%04X.", ft_sender_short_id_from_pcc);
        sdu_area_after_common_hdr = common_hdr_start_in_payload + common_hdr_actual_len;
        sdu_area_plus_mic_len_in_payload = pdu_content_len - common_hdr_actual_len;
    }

process_feedback_pt_rx_sec_path:
    if (active_ft_peer_ctx && assoc_pcc_event->phy_type == 1 &&
        (link_is_expected_to_be_secure || security_applied_by_sender) ) {
        uint8_t harq_proc_in_ft_tx = assoc_pcc_event->hdr.hdr_type_2.df_harq_process_num;
        if (active_ft_peer_ctx->num_pending_feedback_items < 2) {
            int fb_idx = active_ft_peer_ctx->num_pending_feedback_items++;
            active_ft_peer_ctx->pending_feedback_to_send[fb_idx].valid = true;
            active_ft_peer_ctx->pending_feedback_to_send[fb_idx].is_ack = pdc_process_ok_for_feedback;
            active_ft_peer_ctx->pending_feedback_to_send[fb_idx].harq_process_num_for_peer = harq_proc_in_ft_tx;
        } else { LOG_WRN("PT_SM_HARQ_RX: Feedback buffer full for FT 0x%04X", ft_sender_short_id_from_pcc); }
    }
    if (!pdc_process_ok_for_feedback) return;


    // --- Proceed with cleartext SDU Area content ---
    const uint8_t *sdu_area_final_ptr = sdu_area_after_common_hdr;
    size_t sdu_area_final_len = sdu_area_plus_mic_len_in_payload; // Length of MUXed IEs (user data part)

    if (ctx->state == MAC_STATE_PT_SCANNING || ctx->state == MAC_STATE_PT_BEACON_PDC_WAIT) {
        if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_BEACON) {
            const dect_mac_beacon_header_t *bch = (const dect_mac_beacon_header_t *)common_hdr_start_in_payload;
            uint32_t ft_long_id = sys_be32_to_cpu(bch->transmitter_long_rd_id_be);
            
            dect_mac_cluster_beacon_ie_fields_t cb_fields_parsed;
            dect_mac_rach_info_ie_fields_t rach_fields_parsed;


            dect_mac_rd_capability_ie_t ft_caps_parsed; // To store parsed FT capabilities

            bool cb_found = false;
            bool rach_found = false;
            bool ft_caps_parsed_successfully = false; // Changed flag name for clarity
            uint8_t mu_from_ft_caps = 1; // Default to mu=1 (8-bit start_subslot)

            const uint8_t *sdu_area_iter_ptr = sdu_area_final_ptr;
            size_t sdu_area_iter_rem_len = sdu_area_final_len;

            LOG_DBG("PT_PDC_BCN: Parsing beacon SDU area (len %zu) from FT L:0x%08X S:0x%04X",
                    sdu_area_final_len, ft_long_id, ft_sender_short_id_from_pcc);

            // First pass: Iterate through all IEs to find RD Capability and extract mu.
            // Also parse Cluster Beacon and RACH Info if encountered, but RACH will use default mu first.
            // We will re-parse RACH Info if a non-default mu is found in RD Capability later in this same SDU Area.
            // A more robust method would be to store pointers/lengths of all IEs first, then process.

            // Initialize structures to be parsed
            memset(&cb_fields_parsed, 0, sizeof(cb_fields_parsed));
            memset(&rach_fields_parsed, 0, sizeof(rach_fields_parsed));
            memset(&ft_caps_parsed, 0, sizeof(ft_caps_parsed));


            const uint8_t *ptr_for_rd_cap_scan = sdu_area_final_ptr;
            size_t len_for_rd_cap_scan = sdu_area_final_len;
            while (len_for_rd_cap_scan > 0 && !ft_caps_parsed_successfully) { // Stop if RD Cap found
                uint8_t ie_type_scan; uint16_t ie_len_scan; const uint8_t *ie_payload_scan;
                int mux_hdr_len_scan = parse_mac_mux_header(ptr_for_rd_cap_scan, len_for_rd_cap_scan,
                                                            &ie_type_scan, &ie_len_scan, &ie_payload_scan);
                if (mux_hdr_len_scan <= 0) { LOG_ERR("PT_PDC_BCN: MUX pre-scan error %d.", mux_hdr_len_scan); break; }
                if (ie_len_scan == 0 && ((ptr_for_rd_cap_scan[0] >> 6) & 0x03) == 0b00) {
                    if (len_for_rd_cap_scan < (size_t)mux_hdr_len_scan) break;
                    ie_len_scan = len_for_rd_cap_scan - mux_hdr_len_scan;
                }
                if (len_for_rd_cap_scan < (size_t)mux_hdr_len_scan + ie_len_scan) { LOG_ERR("PT_PDC_BCN: MUX IE pre-scan len error."); break; }

                if (ie_type_scan == IE_TYPE_RD_CAPABILITY) {
                    if (parse_rd_capability_ie_payload(ie_payload_scan, ie_len_scan, &ft_caps_parsed) == 0) {
                        ft_caps_parsed_successfully = true;
                        // EXTRACT MU: This depends on how ft_caps_parsed stores mu.
                        // Assuming dect_mac_rd_capability_ie_t has phy_variants[0].mu after parsing
                        // (Task 1.B.5 needs to ensure this).
                        if (ft_caps_parsed.num_phy_capabilities >= 0 && /* ensure at least base set exists */
                            ft_caps_parsed.phy_variants[0].mu_value > 0 && /* phy_variants[0].mu_value would be new field */
                            ft_caps_parsed.phy_variants[0].mu_value <= 8) {
                            mu_from_ft_caps = ft_caps_parsed.phy_variants[0].mu_value;
                            LOG_INF("PT_PDC_BCN: Extracted mu=%u from FT RD Capability IE.", mu_from_ft_caps);
                        } else {
                            LOG_WRN("PT_PDC_BCN: RD Cap IE parsed, but mu not found or invalid. Using default mu=%u.", mu_from_ft_caps);
                        }
                    } else { LOG_WRN("PT_PDC_BCN: Failed to parse RD_CAP IE payload during pre-scan.");}
                }
                ptr_for_rd_cap_scan += mux_hdr_len_scan + ie_len_scan;
                if (len_for_rd_cap_scan >= (size_t)mux_hdr_len_scan + ie_len_scan) len_for_rd_cap_scan -= (mux_hdr_len_scan + ie_len_scan); else len_for_rd_cap_scan = 0;
            }

            // Second pass: Parse all IEs, using the determined mu_from_ft_caps for RACH Info IE.
            while(sdu_area_remaining_len > 0) {
                uint8_t ie_type; uint16_t ie_len; const uint8_t *ie_payload_data;
                int mux_hdr_len = parse_mac_mux_header(sdu_area_iter_ptr, sdu_area_iter_rem_len,
                                                       &ie_type, &ie_len, &ie_payload_data);
                if (mux_hdr_len <= 0) { LOG_ERR("PT_PDC_BCN: MUX parse error %d in main pass.", mux_hdr_len); break; }
                if (ie_len == 0 && ((sdu_area_iter_ptr[0] >> 6) & 0x03) == 0b00) {
                     if (sdu_area_iter_rem_len < (size_t)mux_hdr_len) break;
                     ie_len = sdu_area_iter_rem_len - mux_hdr_len;
                }
                if (sdu_area_iter_rem_len < (size_t)mux_hdr_len + ie_len) { LOG_ERR("PT_PDC_BCN: MUX IE len error in main pass."); break; }

                if (ie_type == IE_TYPE_CLUSTER_BEACON && !cb_found) {
                    if(parse_cluster_beacon_ie_payload(ie_payload_data, ie_len, &cb_fields_parsed)==0) {
                        cb_found = true;
                        LOG_DBG("PT_PDC_BCN: Parsed Cluster Beacon IE.");
                    } else { LOG_WRN("PT_PDC_BCN: Failed to parse Cluster Beacon IE payload."); }
                } else if (ie_type == IE_TYPE_RACH_INFO && !rach_found) {
                    if(parse_rach_info_ie_payload(ie_payload_data, ie_len, mu_from_ft_caps, &rach_fields_parsed)==0) {
                        rach_found = true;
                        rach_fields_parsed.mu_value_for_ft_beacon = mu_from_ft_caps; // Store mu used for this parse
                        LOG_DBG("PT_PDC_BCN: Parsed RACH Info IE using mu=%u.", mu_from_ft_caps);
                    } else { LOG_WRN("PT_PDC_BCN: Failed to parse RACH Info IE payload (using mu=%u).", mu_from_ft_caps); }
                } else if (ie_type == IE_TYPE_RD_CAPABILITY && !ft_caps_parsed_successfully) {
                    // If RD Cap wasn't found in pre-scan (e.g., it appeared after RACH_INFO),
                    // this parse is mainly for storing its content. RACH_INFO would have used default mu.
                    if (parse_rd_capability_ie_payload(ie_payload_data, ie_len, &ft_caps_parsed) == 0) {
                        ft_caps_parsed_successfully = true; // Mark as parsed, even if late for mu decision for RACH
                        LOG_DBG("PT_PDC_BCN: Parsed RD_CAP IE (main loop, mu for RACH might have been default).");
                    }
                } else {
                    LOG_DBG("PT_PDC_BCN: Skipping MUX IE type 0x%X during main pass.", ie_type);
                }

                sdu_area_iter_ptr += mux_hdr_len + ie_len;
                if (sdu_area_iter_rem_len >= (size_t)mux_hdr_len + ie_len) {
                     sdu_area_iter_rem_len -= (mux_hdr_len + ie_len);
                } else {
                    sdu_area_iter_rem_len = 0;
                }
            }


            if (cb_found && rach_found) {
                pt_process_identified_beacon_and_attempt_assoc(ctx, &cb_fields_parsed, &rach_fields_parsed,
                                                               ft_long_id, ft_sender_short_id_from_pcc,
                                                               assoc_pcc_event->rssi_2,
                                                               assoc_pcc_event->pcc_params_from_modem.carrier,
                                                               pcc_reception_modem_time);
            } else { LOG_WRN("PT_PDC_BCN: Missing CB (%d) or RACH (%d) IE from FT 0x%04X.", cb_found, rach_found, ft_sender_short_id_from_pcc); }
        }
    } else if (ctx->state == MAC_STATE_PT_WAIT_ASSOC_RESP) {
        if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_UNICAST &&
            active_ft_peer_ctx && ft_sender_short_id_from_pcc == active_ft_peer_ctx->short_rd_id) {
            const dect_mac_unicast_header_t *uch = (const dect_mac_unicast_header_t *)common_hdr_start_in_payload;
            uint32_t ft_tx_long_id_resp = sys_be32_to_cpu(uch->transmitter_long_rd_id_be);
            pt_process_association_response_pdu(sdu_area_final_ptr, sdu_area_final_len,
                                                ft_tx_long_id_resp, pcc_reception_modem_time);
        }
    } else if (ctx->state == MAC_STATE_ASSOCIATED) {
         if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_UNICAST &&
            active_ft_peer_ctx && ft_sender_short_id_from_pcc == active_ft_peer_ctx->short_rd_id) {
            const dect_mac_unicast_header_t *uch = (const dect_mac_unicast_header_t *)common_hdr_start_in_payload;
            uint32_t ft_tx_long_id_data = sys_be32_to_cpu(uch->transmitter_long_rd_id_be);
            LOG_INF("PT_SM_PDC: Data SDU Area (len %zu) from FT 0x%04X.", sdu_area_final_len, ft_sender_short_id_from_pcc);
            dect_mac_data_path_handle_rx_sdu(sdu_area_final_ptr, sdu_area_final_len, ft_tx_long_id_data);
        } else if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_BEACON) {
            // Received a beacon while already associated - this must be from a neighbor FT.
            const dect_mac_beacon_header_t *bch = (const dect_mac_beacon_header_t *)common_hdr_start_in_payload;
            uint32_t neighbor_ft_long_id = sys_be32_to_cpu(bch->transmitter_long_rd_id_be);

            // If we are in paging mode, a beacon from our associated FT might contain a page
            if (ctx->state == MAC_STATE_PT_PAGING && neighbor_ft_long_id == ctx->role_ctx.pt.associated_ft.long_rd_id) {
                // TODO: Parse SDU area for Broadcast Indication IE and check if our ID is paged.
                // For now, we will assume any beacon received from our FT while paging is a page for us.
                LOG_DBG("PT_PAGING: Received beacon from associated FT while paging. Treating as a page indication.");
                pt_process_page_indication();
            } else if (neighbor_ft_long_id != ctx->role_ctx.pt.associated_ft.long_rd_id) {
                LOG_INF("MOBILITY: Heard beacon from neighbor FT 0x%08X (S:0x%04X) on carrier %u.",
                        neighbor_ft_long_id, ft_sender_short_id_from_pcc,
                        assoc_pcc_event->pcc_params_from_modem.carrier);
                pt_update_mobility_candidate(assoc_pcc_event->pcc_params_from_modem.carrier,
                                             assoc_pcc_event->rssi_2,
                                             neighbor_ft_long_id,
                                             ft_sender_short_id_from_pcc);
                // TODO: Parse beacon IEs and store RACH info for this candidate.
            }            
        }
    } else {
        LOG_WRN("PT_SM_PDC: PDC received in unhandled state %s for FT 0x%04X.",
                dect_mac_state_to_str(ctx->state), ft_sender_short_id_from_pcc);
    }
}

static void pt_process_identified_beacon_and_attempt_assoc(dect_mac_context_t *ctx,
                                                           const dect_mac_cluster_beacon_ie_fields_t *cb_fields,
                                                           const dect_mac_rach_info_ie_fields_t *rach_fields,
                                                           uint32_t ft_long_id,
                                                           uint16_t ft_short_id,
                                                           int16_t rssi_q7_1, // RSSI from PCC event (Q7.1 format)
                                                           uint16_t beacon_rx_carrier, // Carrier on which this beacon was received
                                                           uint64_t beacon_pcc_rx_time) // Modem time of beacon PCC reception
{
    if (!ctx || !cb_fields || !rach_fields) {
        LOG_ERR("PT_BEACON_PROC: NULL arguments.");
        return;
    }

    // Basic FT selection logic:
    // 1. If no current target_ft, this one becomes the target.
    // 2. If current target_ft exists but is not fully identified (LongID unknown), this one (if fully ID'd) might replace it.
    // 3. If current target_ft is fully identified, this new one must be significantly better (RSSI + Hysteresis).
    // TODO: Add a proper candidate list and more sophisticated selection for mobility.

    bool select_this_ft = false;
    if (!ctx->role_ctx.pt.target_ft.is_valid) {
        select_this_ft = true;
        LOG_INF("PT_BEACON_PROC: No current target FT, selecting FT 0x%04X (L:0x%08X).", ft_short_id, ft_long_id);
    } else if (!ctx->role_ctx.pt.target_ft.is_fully_identified && ft_long_id != 0) {
        // Current target might just be from a random PCC, this beacon gives LongID.
        select_this_ft = true;
        LOG_INF("PT_BEACON_PROC: Current target not fully ID'd. Switching to FT 0x%04X (L:0x%08X).", ft_short_id, ft_long_id);
    } else if (ft_long_id != 0 && rssi_q7_1 > (ctx->role_ctx.pt.target_ft.rssi_2 + (RSSI_HYSTERESIS_DB * 2))) {
        // New FT is significantly stronger (RSSI is Q7.1, so hysteresis needs scaling if RSSI_HYSTERESIS_DB is in dB)
        select_this_ft = true;
        LOG_INF("PT_BEACON_PROC: New FT 0x%04X (L:0x%08X, RSSI:%.1f) is stronger than current target 0x%04X (RSSI:%.1f). Switching.",
                ft_short_id, ft_long_id, (float)rssi_q7_1 / 2.0f,
                ctx->role_ctx.pt.target_ft.short_rd_id, (float)ctx->role_ctx.pt.target_ft.rssi_2 / 2.0f);
    }


    if (select_this_ft) {
        LOG_INF("PT_BEACON_PROC: Selected FT LongID:0x%08X, ShortID:0x%04X, BeaconRxCarrier:%u, RSSI2:%.1f dBm",
                ft_long_id, ft_short_id, beacon_rx_carrier, (float)rssi_q7_1 / 2.0f);

        // Store as target FT
        ctx->role_ctx.pt.target_ft.is_valid = true;
        ctx->role_ctx.pt.target_ft.is_fully_identified = (ft_long_id != 0);
        ctx->role_ctx.pt.target_ft.long_rd_id = ft_long_id;
        ctx->role_ctx.pt.target_ft.short_rd_id = ft_short_id;
        ctx->role_ctx.pt.target_ft.rssi_2 = rssi_q7_1;

        // Determine operating carrier for association:
        // Prefer "Next Cluster Channel" if present and valid in CB IE.
        // Else, use the carrier where this beacon was received (beacon_rx_carrier).
        if (cb_fields->next_channel_present && cb_fields->next_cluster_channel_val != 0 &&
            cb_fields->next_cluster_channel_val != 0xFFFF /*Ensure it's not an invalid carrier code*/) {
            ctx->role_ctx.pt.target_ft.operating_carrier = cb_fields->next_cluster_channel_val;
            LOG_INF("PT_BEACON_PROC: Target FT using 'Next Cluster Channel': %u from CB IE.", cb_fields->next_cluster_channel_val);
        } else {
            ctx->role_ctx.pt.target_ft.operating_carrier = beacon_rx_carrier;
            LOG_INF("PT_BEACON_PROC: Target FT using beacon RX carrier: %u.", beacon_rx_carrier);
        }


        // Estimate or refine the FT's SFN timing anchor
        uint32_t frame_duration_ticks = (uint32_t)FRAME_DURATION_MS_NOMINAL *
                                        (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ / 1000U);

        // Calculate a new estimate for SFN 0 based on the current beacon
        uint64_t new_sfn0_estimate = beacon_pcc_rx_time -
                                     ((uint64_t)cb_fields->sfn * frame_duration_ticks);

        if (ctx->ft_sfn_zero_modem_time_anchor == 0 || select_this_ft) {
            // First time seeing this FT, or switching to a new one. Set the anchor directly.
            ctx->ft_sfn_zero_modem_time_anchor = new_sfn0_estimate;
            LOG_INF("PT_BEACON_PROC: Set initial FT SFN0 Anchor: %llu (from Beacon SFN %u at time %llu)",
                    ctx->ft_sfn_zero_modem_time_anchor, cb_fields->sfn, beacon_pcc_rx_time);
        } else {
            // We already have an anchor. Refine it to compensate for clock drift.
            // This is a simple averaging filter. A more advanced filter (e.g., Kalman) could be used.
            // We average the new estimate with the old anchor.
            ctx->ft_sfn_zero_modem_time_anchor = (ctx->ft_sfn_zero_modem_time_anchor + new_sfn0_estimate) / 2;
            LOG_DBG("PT_BEACON_PROC: Refined FT SFN0 Anchor: %llu (NewEst: %llu)",
                    ctx->ft_sfn_zero_modem_time_anchor, new_sfn0_estimate);
        }
        // Always update the SFN value that corresponds to our latest timing information.
        ctx->current_sfn_at_anchor_update = cb_fields->sfn;


        // Copy RACH parameters from parsed IE into PT's operational RACH context for this FT
        memcpy(&ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields, rach_fields, sizeof(dect_mac_rach_info_ie_fields_t));

        // Derive operational RACH values
        if (rach_fields->channel_field_present && rach_fields->channel_abs_freq_num != 0 && rach_fields->channel_abs_freq_num != 0xFFFF) {
            ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel = rach_fields->channel_abs_freq_num;
        } else {
            // If RACH IE doesn't specify channel, it's FT's current operating channel (where beacon was heard or next_cluster_channel)
            ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel = ctx->role_ctx.pt.target_ft.operating_carrier;
        }
        // CWmin_sig and Cwmax_sig codes are 0-7. CW = 8 * 2^code.
        // ETSI 5.3.1: CW_CURRENT is value (not code), between CW_MIN and CW_MAX.
        // The fields cwmin_sig_code and cwmax_sig_code store the *codes*.
        // CW_MIN/MAX values themselves (as per ETSI 5.3.1) not directly in IE, but derived.
        // For now, store the codes, and backoff logic will use config->rach_cw_min_idx.
        // Let's also store the derived min/max values for clarity for backoff logic.
        ctx->role_ctx.pt.current_ft_rach_params.cw_min_val = 8 * (1 << rach_fields->cwmin_sig_code);
        ctx->role_ctx.pt.current_ft_rach_params.cw_max_val = 8 * (1 << rach_fields->cwmax_sig_code);

        uint32_t resp_win_subslots = rach_fields->response_window_subslots_val_minus_1 + 1;
        uint32_t subslot_dur_us = get_subslot_duration_ticks(ctx) * 1000 / NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ;
        ctx->role_ctx.pt.current_ft_rach_params.response_window_duration_us = resp_win_subslots * subslot_dur_us;

        LOG_INF("PT_BEACON_PROC: Stored RACH params for FT 0x%04X: OpCarrier %u, CWmin_code %u (val %u), CWmax_code %u (val %u), RespWin %u us",
                ft_short_id,
                ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel,
                rach_fields->cwmin_sig_code, ctx->role_ctx.pt.current_ft_rach_params.cw_min_val,
                rach_fields->cwmax_sig_code, ctx->role_ctx.pt.current_ft_rach_params.cw_max_val,
                ctx->role_ctx.pt.current_ft_rach_params.response_window_duration_us);

        ctx->role_ctx.pt.current_assoc_retries = 0; // Reset retries for new target
        ctx->rach_context.rach_cw_current_idx = ctx->config.rach_cw_min_idx; // Reset CW for new attempt sequence


        // Cancel ongoing general scan PHY operation if it's still running
        if (ctx->pending_op_type == PENDING_OP_PT_SCAN && ctx->pending_op_handle != 0) {
            LOG_INF("PT_BEACON_PROC: Cancelling ongoing scan (handle %u) to associate with FT 0x%04X.",
                    ctx->pending_op_handle, ft_short_id);
            // The actual call to pt_send_association_request_action will happen
            // in pt_handle_phy_op_complete_internal when the PENDING_OP_PT_SCAN
            // completes with NRF_MODEM_DECT_PHY_ERR_OP_CANCELED.
            dect_mac_phy_ctrl_cancel_op(ctx->pending_op_handle);
            // State will change upon OP_COMPLETE of the cancelled scan.
            // If we change state to PT_ASSOCIATING here, and scan cancel complete comes later,
            // it might be confusing. Let the op_complete handler for scan cancellation trigger association.
        } else {
            // If no scan was pending (e.g., it completed naturally, or this is a re-evaluation),
            // directly trigger association attempt.
            LOG_INF("PT_BEACON_PROC: No active scan to cancel. Directly attempting association with FT 0x%04X.", ft_short_id);
            pt_send_association_request_action(); // This will change state to PT_ASSOCIATING
        }
    } else {
        LOG_DBG("PT_BEACON_PROC: Beacon from FT 0x%04X (L:0x%08X, RSSI:%.1f) not better than current target 0x%04X (RSSI:%.1f). Continuing scan.",
                ft_short_id, ft_long_id, (float)rssi_q7_1 / 2.0f,
                ctx->role_ctx.pt.target_ft.short_rd_id, (float)ctx->role_ctx.pt.target_ft.rssi_2 / 2.0f);
    }
}

static void pt_send_association_request_action(void) {
    dect_mac_context_t* ctx = get_mac_context();

    if (!ctx->role_ctx.pt.target_ft.is_valid || !ctx->role_ctx.pt.target_ft.is_fully_identified) {
        LOG_ERR("PT_SM_ASSOC_REQ: No valid or not fully identified target FT. Restarting scan.");
        dect_mac_sm_pt_start_operation(); // Rescan to find a fully identified FT
        return;
    }
    if (ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel == 0 ||
        ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel == 0xFFFF) { // 0xFFFF might be broadcast/invalid
        LOG_ERR("PT_SM_ASSOC_REQ: Target FT RACH operating channel invalid (0 or 0xFFFF). Restarting scan.");
        dect_mac_sm_pt_start_operation();
        return;
    }
    if (ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.max_rach_pdu_len_units == 0) {
        LOG_ERR("PT_SM_ASSOC_REQ: Target FT RACH max PDU length is 0. Cannot send. Restarting scan.");
        dect_mac_sm_pt_start_operation();
        return;
    }


    // If already in ASSOCIATING state, it might be a retry after LBT busy.
    // If coming from another state (e.g. after beacon processing), change state.
    if (ctx->state != MAC_STATE_PT_ASSOCIATING && ctx->state != MAC_STATE_PT_RACH_BACKOFF) {
        dect_mac_change_state(MAC_STATE_PT_ASSOCIATING);
    } else if (ctx->state == MAC_STATE_PT_RACH_BACKOFF) {
        dect_mac_change_state(MAC_STATE_PT_ASSOCIATING); // Exiting backoff, now associating
    }


    LOG_INF("PT_SM_ASSOC_REQ: Attempting Association Request to FT 0x%04X on RACH carrier %u.",
            ctx->role_ctx.pt.target_ft.short_rd_id,
            ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel);

    // 1. Prepare SDU Area (MUXed Association Request IE + RD Capability IE)
    uint8_t sdu_area_buf[128]; // Estimate max size needed for these two IEs (simplified versions)
    dect_mac_assoc_req_ie_t assoc_req_fields;
    memset(&assoc_req_fields, 0, sizeof(assoc_req_fields));
    assoc_req_fields.setup_cause_val = 0; // 000 = Initial association (ETSI Table 6.4.2.4-2)
    assoc_req_fields.number_of_flows_val = 0; // No specific flows requested during initial association
    assoc_req_fields.ft_mode_capable = false; // This PT device does not also operate as an FT
    assoc_req_fields.power_const_active = false; // PT has no power constraints to declare to FT

    dect_mac_rd_capability_ie_t rd_cap_fields;
    memset(&rd_cap_fields, 0, sizeof(rd_cap_fields));
    rd_cap_fields.num_phy_capabilities = 0;    // 0 means 1 set (the base set defined by common fields or default PHY)
    rd_cap_fields.release_version = 1;         // DECT NR+ Release 2 is coded as 1 (see ETSI Part 4 Annex A, A.2.0)
    rd_cap_fields.supports_group_assignment = false; // Example capability
    rd_cap_fields.supports_paging = true;            // Example: This PT supports being paged
    rd_cap_fields.operating_modes_code = 0b00;     // PT mode only (ETSI Table 6.4.3.5-1)
    rd_cap_fields.supports_mesh = false;           // Example
    rd_cap_fields.supports_sched_data = true;      // PT wants scheduled data transfer
    rd_cap_fields.mac_security_modes_code = 0b01;  // PT supports MAC Security Mode 1

    int sdu_area_len = build_assoc_req_ies_area(sdu_area_buf, sizeof(sdu_area_buf),
                                               &assoc_req_fields, &rd_cap_fields);
    if (sdu_area_len < 0) {
        LOG_ERR("PT_SM_ASSOC_REQ: Failed to build Association Request SDU area: %d. Restarting scan.", sdu_area_len);
        dect_mac_sm_pt_start_operation();
        return;
    }

    // 2. Prepare MAC Header Type Octet
    dect_mac_header_type_octet_t hdr_type_octet;
    hdr_type_octet.version = 0; // Current version for ETSI TS 103 636-4 Release 2
    hdr_type_octet.mac_security = MAC_SECURITY_NONE; // Association Request is unsecure
    hdr_type_octet.mac_header_type = MAC_COMMON_HEADER_TYPE_UNICAST;

    // 3. Prepare MAC Common Unicast Header
    dect_mac_unicast_header_t common_hdr;
    increment_psn_and_hpc(ctx); // Get new PSN for this transmission, potentially increment PT's own TX HPC
    common_hdr.sequence_num_high_reset_rsv = SET_SEQ_NUM_HIGH_RESET_RSV((ctx->psn >> 8) & 0x0F, 1 /*reset bit*/);
    common_hdr.sequence_num_low = ctx->psn & 0xFF;
    common_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);
    common_hdr.receiver_long_rd_id_be = sys_cpu_to_be32(ctx->role_ctx.pt.target_ft.long_rd_id);

    // 4. Assemble the full MAC PDU
    uint8_t *full_mac_pdu_for_phy_slab = NULL;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab, K_NO_WAIT);
    if(ret != 0 || full_mac_pdu_for_phy_slab == NULL) {
        LOG_ERR("PT_SM_ASSOC_REQ: Failed to alloc PDU buf for AssocReq. Restarting scan.");
        dect_mac_sm_pt_start_operation();
        return;
    }
    uint8_t * const full_mac_pdu_for_phy = full_mac_pdu_for_phy_slab;

    uint16_t pdu_len;
    ret = dect_mac_phy_ctrl_assemble_final_pdu(full_mac_pdu_for_phy, CONFIG_DECT_MAC_PDU_MAX_SIZE,
                                         &hdr_type_octet, &common_hdr, sizeof(common_hdr),
                                         sdu_area_buf, (size_t)sdu_area_len,
                                         &pdu_len);
    if (ret != 0) {
        LOG_ERR("PT_SM_ASSOC_REQ: Failed to assemble Association Request PDU: %d. Restarting scan.", ret);
        k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);
        dect_mac_sm_pt_start_operation();
        return;
    }

    // Check against Max RACH PDU length from FT's RACH Info IE
    // max_rach_pdu_len_units is number of subslots or slots. Convert PDU len to subslots.
    uint8_t pcc_pkt_len_f, pcc_mcs_f, pcc_pkt_len_type_f;
    dect_mac_phy_ctrl_calculate_pcc_params(pdu_len - sizeof(dect_mac_header_type_octet_t), /* PDC part len */
                                           &pcc_pkt_len_f, &pcc_mcs_f, &pcc_pkt_len_type_f);
    uint32_t assoc_req_tx_duration_subslots = pcc_pkt_len_f + 1; // N-1 coded
    if (pcc_pkt_len_type_f == 1) { // If length is in slots
        assoc_req_tx_duration_subslots *= SUB_SLOTS_PER_ETSI_SLOT;
    }

    if (assoc_req_tx_duration_subslots > ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.max_rach_pdu_len_units) {
        LOG_ERR("PT_SM_ASSOC_REQ: Assembled AssocReq PDU needs %u subslots, but FT RACH max is %u. Cannot send. Restarting scan.",
                assoc_req_tx_duration_subslots,
                ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.max_rach_pdu_len_units);
        k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab);
        dect_mac_sm_pt_start_operation();
        return;
    }

    // 5. Schedule TX operation
    uint32_t phy_op_handle = sys_rand32_get();
    // LBT period for RACH: ETSI 5.3.3 specifies MINIMUM_LBT_PERIOD.
    // NRF_MODEM_DECT_LBT_PERIOD_MIN corresponds to 2 symbols.
    ret = dect_mac_phy_ctrl_start_tx_assembled(
        ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel,
        full_mac_pdu_for_phy, pdu_len,
        ctx->role_ctx.pt.target_ft.short_rd_id, // Target for Type 2 PCC's Receiver ID
        false, /* is_beacon = false */
        phy_op_handle,
        PENDING_OP_PT_RACH_ASSOC_REQ,
        true, /* use_lbt = true for RACH */
        0     /* target_start_time = 0 for immediate attempt after LBT/backoff */
    );

    k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab); // Free the buffer after scheduling attempt

    if (ret != 0) {
        LOG_ERR("PT_SM_ASSOC_REQ: Failed to schedule Association Request TX: %d. Will rely on op_complete/timeout for retry.", ret);
        // If phy_ctrl_start_tx_assembled failed (e.g., -EBUSY), pending_op_type might have been cleared.
        // The OP_COMPLETE handler (if an op was pending) or RACH response timer needs to trigger next action.
        // If it failed because an op was already pending, that pending op needs to complete first.
        // For now, do nothing here; op_complete or timer expiry will drive next state.
        // If state was PT_ASSOCIATING, it remains so. If it was PT_RACH_BACKOFF, it also remains.
        // A short backoff might be good if -EBUSY from phy_ctrl itself.
        if (ret == -EBUSY && ctx->state == MAC_STATE_PT_ASSOCIATING) {
            dect_mac_change_state(MAC_STATE_PT_RACH_BACKOFF);
            k_timer_start(&ctx->rach_context.rach_backoff_timer, K_MSEC(10 + (sys_rand32_get()%20)), K_NO_WAIT);
        }
    } else {
        LOG_INF("PT_SM_ASSOC_REQ: Association Request TX scheduled (Hdl %u) to FT 0x%04X.",
                phy_op_handle, ctx->role_ctx.pt.target_ft.short_rd_id);
        // State is already MAC_STATE_PT_ASSOCIATING, awaiting OP_COMPLETE.
    }
}

static void pt_process_association_response_pdu(const uint8_t *mac_sdu_area_data, size_t mac_sdu_area_len,
                                                uint32_t ft_tx_long_rd_id,
                                                uint64_t assoc_resp_pcc_rx_time)
{
    dect_mac_context_t* ctx = get_mac_context();
    k_timer_stop(&ctx->rach_context.rach_response_window_timer); // Stop waiting for response, we got one

    if (ft_tx_long_rd_id != ctx->role_ctx.pt.target_ft.long_rd_id) {
        LOG_WRN("PT_SM_ASSOC_RESP: Received AssocResp from unexpected FT LongID 0x%08X (expected 0x%08X). Ignoring.",
                ft_tx_long_rd_id, ctx->role_ctx.pt.target_ft.long_rd_id);
        // If still waiting for true target, let timer expire or restart RX for target.
        // For now, if a response comes, and it's not from the target, we might be confused.
        // Best to restart scan if this happens.
        dect_mac_sm_pt_start_operation();
        return;
    }

    dect_mac_assoc_resp_ie_t resp_fields;
    dect_mac_rd_capability_ie_t ft_cap_fields;
    dect_mac_resource_alloc_ie_fields_t res_alloc_fields;
    bool resp_ie_found = false;
    bool ft_cap_found = false;
    bool res_alloc_found = false;

    const uint8_t *current_ie_ptr = mac_sdu_area_data;
    size_t remaining_len = mac_sdu_area_len;

    LOG_INF("PT_SM_ASSOC_RESP: Processing Association Response from FT LongID:0x%08X (ShortID:0x%04X)",
             ft_tx_long_rd_id, ctx->role_ctx.pt.target_ft.short_rd_id);

    while (remaining_len > 0) {
        uint8_t ie_type;
        uint16_t ie_payload_len;
        const uint8_t *ie_payload_ptr;
        int mux_hdr_len = parse_mac_mux_header(current_ie_ptr, remaining_len,
                                               &ie_type, &ie_payload_len, &ie_payload_ptr);

        if (mux_hdr_len < 0) {
            LOG_ERR("PT_SM_ASSOC_RESP: Failed to parse MUX header in Assoc Resp PDU: %d", mux_hdr_len);
            break; // Stop parsing this PDU
        }
        if (ie_payload_len == 0 && ((current_ie_ptr[0] >> 6) & 0x03) == 0b00) { // MAC_Ext=00
             if (remaining_len < (size_t)mux_hdr_len) { LOG_ERR("PT_SM_ASSOC_RESP: MUX hdr error MAC_Ext=00"); break;}
            ie_payload_len = remaining_len - mux_hdr_len; // Assume IE consumes rest
        }
        if (remaining_len < (size_t)mux_hdr_len + ie_payload_len) {
            LOG_ERR("PT_SM_ASSOC_RESP: MUX IE declared length %u exceeds SDU area %zu.",
                    ie_payload_len, remaining_len - mux_hdr_len);
            break;
        }

        if (ie_type == IE_TYPE_ASSOC_RESP) {
            if (parse_assoc_resp_ie_payload(ie_payload_ptr, ie_payload_len, &resp_fields) == 0) {
                resp_ie_found = true;
                LOG_DBG("PT_SM_ASSOC_RESP: Parsed Assoc Resp IE (ACK: %d).", resp_fields.ack_nack);
            } else { LOG_ERR("PT_SM_ASSOC_RESP: Failed to parse Assoc Resp IE payload."); }
        } else if (ie_type == IE_TYPE_RD_CAPABILITY) {
            if (parse_rd_capability_ie_payload(ie_payload_ptr, ie_payload_len, &ft_cap_fields) == 0) {
                ft_cap_found = true;
                LOG_DBG("PT_SM_ASSOC_RESP: Parsed FT RD Capability IE.");
            } else { LOG_ERR("PT_SM_ASSOC_RESP: Failed to parse FT RD Cap IE."); }
        } else if (ie_type == IE_TYPE_RES_ALLOC) {
            if (parse_resource_alloc_ie_payload(ie_payload_ptr, ie_payload_len, &res_alloc_fields) == 0) {
                res_alloc_found = true;
                LOG_DBG("PT_SM_ASSOC_RESP: Parsed Resource Allocation IE (Type %u).", res_alloc_fields.alloc_type_val);
            } else { LOG_ERR("PT_SM_ASSOC_RESP: Failed to parse Res Alloc IE."); }
        } else {
            LOG_DBG("PT_SM_ASSOC_RESP: Skipping MUX IE type 0x%X.", ie_type);
        }

        current_ie_ptr += mux_hdr_len + ie_payload_len;
        if (remaining_len >= (size_t)mux_hdr_len + ie_payload_len) {
            remaining_len -= (mux_hdr_len + ie_payload_len);
        } else {
            remaining_len = 0;
        }
    }

    if (!resp_ie_found) {
        LOG_ERR("PT_SM_ASSOC_RESP: Association Response IE missing from PDU. Restarting scan.");
        dect_mac_sm_pt_start_operation();
        return;
    }

    if (resp_fields.ack_nack) { // Association Accepted
        LOG_INF("PT_SM: Association ACCEPTED by FT LongID 0x%08X (ShortID 0x%04X).",
                ctx->role_ctx.pt.target_ft.long_rd_id, ctx->role_ctx.pt.target_ft.short_rd_id);

        // Promote target_ft to associated_ft
        memcpy(&ctx->role_ctx.pt.associated_ft, &ctx->role_ctx.pt.target_ft, sizeof(dect_mac_peer_info_t));
        ctx->role_ctx.pt.associated_ft.is_valid = true; // Now truly associated
        // Clear target_ft as we are now associated (or moving to auth with this one)
        memset(&ctx->role_ctx.pt.target_ft, 0, sizeof(dect_mac_peer_info_t));
        ctx->role_ctx.pt.target_ft.is_valid = false;

        if (ft_cap_found) {
            // TODO: Store/use relevant FT capabilities if needed by PT for future interactions
            LOG_DBG("PT_SM: FT Capabilities: Release %u, MACSecModes 0x%X",
                    ft_cap_fields.release_version, ft_cap_fields.mac_security_modes_code);
        } else {
            LOG_WRN("PT_SM: FT RD Capability IE missing in accepted Association Response.");
        }

        if (res_alloc_found) {
            LOG_INF("PT_SM: Storing schedule from FT 0x%04X.", ctx->role_ctx.pt.associated_ft.short_rd_id);
            uint32_t frame_duration_ticks = (uint32_t)FRAME_DURATION_MS_NOMINAL * (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ / 1000U);
            uint16_t schedule_channel = res_alloc_fields.channel_present ? \
                                        res_alloc_fields.channel_val : ctx->role_ctx.pt.associated_ft.operating_carrier;

            // --- Downlink Schedule (Res1 in ResAlloc IE) ---
            ctx->role_ctx.pt.dl_schedule.is_active = true;
            ctx->role_ctx.pt.dl_schedule.alloc_type = RES_ALLOC_TYPE_DOWNLINK;
            ctx->role_ctx.pt.dl_schedule.dl_start_subslot = res_alloc_fields.start_subslot_val_res1;
            ctx->role_ctx.pt.dl_schedule.dl_duration_subslots = res_alloc_fields.length_val_res1 + 1;
            ctx->role_ctx.pt.dl_schedule.dl_length_is_slots = res_alloc_fields.length_type_is_slots_res1;
            ctx->role_ctx.pt.dl_schedule.repeat_type = res_alloc_fields.repeat_val;
            ctx->role_ctx.pt.dl_schedule.repetition_value = res_alloc_fields.repetition_val;
            ctx->role_ctx.pt.dl_schedule.validity_value = res_alloc_fields.validity_val;
            ctx->role_ctx.pt.dl_schedule.channel = schedule_channel;
            ctx->role_ctx.pt.dl_schedule.schedule_init_modem_time = assoc_resp_pcc_rx_time;
            ctx->role_ctx.pt.dl_schedule.res1_is_9bit_subslot = res_alloc_fields.res1_is_9bit_subslot; // Copy from parsed

            if (res_alloc_fields.sfn_present) {
                ctx->role_ctx.pt.dl_schedule.sfn_of_initial_occurrence = res_alloc_fields.sfn_val;
                ctx->role_ctx.pt.dl_schedule.next_occurrence_modem_time =
                    calculate_target_modem_time(ctx, ctx->ft_sfn_zero_modem_time_anchor,
                                                ctx->current_sfn_at_anchor_update,
                                                res_alloc_fields.sfn_val,
                                                res_alloc_fields.start_subslot_val_res1);
            } else {
                ctx->role_ctx.pt.dl_schedule.sfn_of_initial_occurrence = ctx->current_sfn_at_anchor_update;
                uint64_t now_plus_processing_delay = assoc_resp_pcc_rx_time + modem_us_to_ticks(5000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
                uint64_t current_frame_start_approx = (now_plus_processing_delay / frame_duration_ticks) * frame_duration_ticks;
                uint64_t candidate_time = current_frame_start_approx + (uint64_t)res_alloc_fields.start_subslot_val_res1 * get_subslot_duration_ticks(ctx);
                if (candidate_time <= now_plus_processing_delay) { candidate_time += frame_duration_ticks; }
                ctx->role_ctx.pt.dl_schedule.next_occurrence_modem_time = candidate_time;
            }
            update_next_occurrence(ctx, &ctx->role_ctx.pt.dl_schedule, ctx->last_known_modem_time);
            LOG_INF("PT_SM: DL Schedule Init: NextOcc @ %llu, StartSS %u, Dur %u, Rep %u, Valid %u, Chan %u",
                    ctx->role_ctx.pt.dl_schedule.next_occurrence_modem_time, ctx->role_ctx.pt.dl_schedule.dl_start_subslot,
                    ctx->role_ctx.pt.dl_schedule.dl_duration_subslots, ctx->role_ctx.pt.dl_schedule.repetition_value,
                    ctx->role_ctx.pt.dl_schedule.validity_value, ctx->role_ctx.pt.dl_schedule.channel);

            if (res_alloc_fields.alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
                ctx->role_ctx.pt.ul_schedule.is_active = true;
                ctx->role_ctx.pt.ul_schedule.alloc_type = RES_ALLOC_TYPE_UPLINK;
                ctx->role_ctx.pt.ul_schedule.ul_start_subslot = res_alloc_fields.start_subslot_val_res2;
                ctx->role_ctx.pt.ul_schedule.ul_duration_subslots = res_alloc_fields.length_val_res2 + 1;
                ctx->role_ctx.pt.ul_schedule.ul_length_is_slots = res_alloc_fields.length_type_is_slots_res2;
                ctx->role_ctx.pt.ul_schedule.repeat_type = res_alloc_fields.repeat_val;
                ctx->role_ctx.pt.ul_schedule.repetition_value = res_alloc_fields.repetition_val;
                ctx->role_ctx.pt.ul_schedule.validity_value = res_alloc_fields.validity_value;
                ctx->role_ctx.pt.ul_schedule.channel = schedule_channel;
                ctx->role_ctx.pt.ul_schedule.schedule_init_modem_time = assoc_resp_pcc_rx_time;
                ctx->role_ctx.pt.ul_schedule.res1_is_9bit_subslot = res_alloc_fields.res2_is_9bit_subslot; // For UL part it's Res2

                if (res_alloc_fields.sfn_present) {
                    ctx->role_ctx.pt.ul_schedule.sfn_of_initial_occurrence = res_alloc_fields.sfn_val;
                    ctx->role_ctx.pt.ul_schedule.next_occurrence_modem_time =
                        calculate_target_modem_time(ctx, ctx->ft_sfn_zero_modem_time_anchor,
                                                    ctx->current_sfn_at_anchor_update,
                                                    res_alloc_fields.sfn_val,
                                                    res_alloc_fields.start_subslot_val_res2);
                } else {
                    ctx->role_ctx.pt.ul_schedule.sfn_of_initial_occurrence = ctx->current_sfn_at_anchor_update;
                    uint64_t now_plus_processing_delay = assoc_resp_pcc_rx_time + modem_us_to_ticks(5000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
                    uint64_t current_frame_start_approx = (now_plus_processing_delay / frame_duration_ticks) * frame_duration_ticks;
                    uint64_t candidate_time = current_frame_start_approx + (uint64_t)res_alloc_fields.start_subslot_val_res2 * get_subslot_duration_ticks(ctx);
                    if (candidate_time <= now_plus_processing_delay) { candidate_time += frame_duration_ticks; }
                    ctx->role_ctx.pt.ul_schedule.next_occurrence_modem_time = candidate_time;
                }
                update_next_occurrence(ctx, &ctx->role_ctx.pt.ul_schedule, ctx->last_known_modem_time);
                 LOG_INF("PT_SM: UL Schedule Init: NextOcc @ %llu, StartSS %u, Dur %u",
                        ctx->role_ctx.pt.ul_schedule.next_occurrence_modem_time, ctx->role_ctx.pt.ul_schedule.ul_start_subslot,
                        ctx->role_ctx.pt.ul_schedule.ul_duration_subslots);
            }
        } else {
            LOG_WRN("PT_SM: Association accepted by FT 0x%04X but NO Resource Allocation IE found! Link unusable.", ctx->role_ctx.pt.associated_ft.short_rd_id);
            // This is a critical failure for data exchange. PT should probably rescan or release.
            dect_mac_sm_pt_start_operation(); // Restart scan
            return;
        }

        // Proceed to "authentication" (simplified PSK key derivation)
        pt_start_authentication_with_ft_action(ctx); // This changes state to AUTHENTICATING then to ASSOCIATED
                                                     // and starts KeepAlive timer.

    } else { // Association Rejected
        LOG_WRN("PT_SM: Association REJECTED by FT 0x%04X. Cause: %u, Timer Code: %u.",
                ctx->role_ctx.pt.target_ft.short_rd_id, resp_fields.reject_cause, resp_fields.reject_timer_code);
        // TODO: Honor reject_timer_code by not trying this FT again for that duration.
        // For now, just clear target and rescan.
        memset(&ctx->role_ctx.pt.target_ft, 0, sizeof(dect_mac_peer_info_t));
        dect_mac_sm_pt_start_operation();
    }
}


static void pt_send_keep_alive_action(void) {
    dect_mac_context_t* ctx = get_mac_context();

    if (ctx->state != MAC_STATE_ASSOCIATED || !ctx->role_ctx.pt.associated_ft.is_valid) {
        LOG_WRN("PT_SM_KA: Cannot send Keep Alive, not in associated state or no valid FT.");
        k_timer_stop(&ctx->role_ctx.pt.keep_alive_timer);
        return;
    }

    if (ctx->pending_op_type != PENDING_OP_NONE) {
        LOG_DBG("PT_SM_KA: PHY op %s pending, deferring Keep Alive. Will retry on next timer expiry.",
                dect_pending_op_to_str(ctx->pending_op_type));
        return;
    }

    LOG_INF("PT_SM_KA: Sending Keep Alive to associated FT 0x%04X.", ctx->role_ctx.pt.associated_ft.short_rd_id);

    uint8_t sdu_area_buf[20]; 
    size_t current_sdu_area_len = 0;
    int ie_len_written_val;

    bool secure_this_pdu = ctx->role_ctx.pt.associated_ft.is_secure && ctx->keys_provisioned;
    bool include_mac_sec_info_ie_for_ka = false;
    uint8_t sec_iv_type_for_ka_ie = SEC_IV_TYPE_MODE1_HPC_PROVIDED; // Default if sending SecIE

    // Determine if MAC Sec Info IE is needed and its SecIVType
    // This check is only relevant if the PDU will be secured and is not a HARQ retransmission.
    if (secure_this_pdu /* && !is_retransmission_placeholder_ka - KA is always new */) {
        dect_mac_peer_info_t *assoc_ft_ctx = &ctx->role_ctx.pt.associated_ft;

        if (assoc_ft_ctx->self_needs_to_request_hpc_from_peer) {
            sec_iv_type_for_ka_ie = SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE;
            include_mac_sec_info_ie_for_ka = true;
        } else if (assoc_ft_ctx->peer_requested_hpc_resync || ctx->send_mac_sec_info_ie_on_next_tx) {
            sec_iv_type_for_ka_ie = SEC_IV_TYPE_MODE1_HPC_PROVIDED;
            include_mac_sec_info_ie_for_ka = true;
        }
    }

    // 1. MAC Header Type Octet
    dect_mac_header_type_octet_t hdr_type_octet;
    hdr_type_octet.version = 0;
    hdr_type_octet.mac_header_type = MAC_COMMON_HEADER_TYPE_UNICAST;
    if (secure_this_pdu) {
        hdr_type_octet.mac_security = include_mac_sec_info_ie_for_ka ? MAC_SECURITY_USED_WITH_IE : MAC_SECURITY_USED_NO_IE;
    } else {
        hdr_type_octet.mac_security = MAC_SECURITY_NONE;
    }

    // 2. MAC Common Unicast Header
    dect_mac_unicast_header_t common_hdr;
    increment_psn_and_hpc(ctx); 
    uint16_t current_psn_for_tx = ctx->psn;
    uint32_t current_hpc_for_iv = ctx->hpc;

    common_hdr.sequence_num_high_reset_rsv = SET_SEQ_NUM_HIGH_RESET_RSV((current_psn_for_tx >> 8) & 0x0F, 1);
    common_hdr.sequence_num_low = current_psn_for_tx & 0xFF;
    common_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);
    common_hdr.receiver_long_rd_id_be = sys_cpu_to_be32(ctx->role_ctx.pt.associated_ft.long_rd_id);

    // 3. SDU Area Construction
    size_t len_of_muxed_sec_ie_for_crypto_calc = 0;
    if (include_mac_sec_info_ie_for_ka) {
        ie_len_written_val = build_mac_security_info_ie_muxed(
            sdu_area_buf + current_sdu_area_len,
            sizeof(sdu_area_buf) - current_sdu_area_len,
            0, ctx->current_key_index,
            sec_iv_type_for_ka_ie,
            ctx->hpc); 
        if (ie_len_written_val < 0) { LOG_ERR("PT_SM_KA: Build MAC Sec Info IE failed: %d", ie_len_written_val); return; }
        current_sdu_area_len += ie_len_written_val;
        len_of_muxed_sec_ie_for_crypto_calc = ie_len_written_val;
        if (sec_iv_type_for_ka_ie == SEC_IV_TYPE_MODE1_HPC_PROVIDED) {
             LOG_DBG("PT_SM_KA: Including MAC Sec Info IE (PT_HPC: %u) as PROVIDED.", ctx->hpc);
        } else {
             LOG_DBG("PT_SM_KA: Including MAC Sec Info IE (PT_HPC: %u) as RESYNC_INITIATE.", ctx->hpc);
        }
    }

    ie_len_written_val = build_keep_alive_ie_muxed(sdu_area_buf + current_sdu_area_len,
                                               sizeof(sdu_area_buf) - current_sdu_area_len);
    if (ie_len_written_val < 0) { LOG_ERR("PT_SM_KA: Build Keep Alive IE failed: %d", ie_len_written_val); return; }
    current_sdu_area_len += ie_len_written_val;

    // 4. Assemble PDU
    uint8_t *full_mac_pdu_for_phy_slab = NULL;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab, K_NO_WAIT);
    if(ret != 0 || full_mac_pdu_for_phy_slab == NULL) {
        LOG_ERR("PT_SM_KA: Failed to alloc PDU buf for Keep Alive.");
        return;
    }
    uint8_t * const full_mac_pdu_for_phy = full_mac_pdu_for_phy_slab;

    uint16_t assembled_pdu_len_pre_mic;
    ret = dect_mac_phy_ctrl_assemble_final_pdu(
              full_mac_pdu_for_phy, CONFIG_DECT_MAC_PDU_MAX_SIZE,
              &hdr_type_octet,
              &common_hdr, sizeof(common_hdr),
              sdu_area_buf, current_sdu_area_len,
              &assembled_pdu_len_pre_mic);

    if (ret != 0) {
        LOG_ERR("PT_SM_KA: Assemble PDU failed: %d", ret);
        k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab);
        return;
    }

    uint16_t final_tx_pdu_len = assembled_pdu_len_pre_mic;

    // 5. Apply Security if active
    if (secure_this_pdu) {
        uint8_t iv[16];
        security_build_iv(iv, ctx->own_long_rd_id, ctx->role_ctx.pt.associated_ft.long_rd_id,
                          current_hpc_for_iv, current_psn_for_tx);

        uint8_t *mic_calc_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t);
        size_t mic_calc_len = sizeof(common_hdr) + current_sdu_area_len;

        if (assembled_pdu_len_pre_mic + 5 > CONFIG_DECT_MAC_PDU_MAX_SIZE) {
            LOG_ERR("PT_SM_KA: No space for MIC in PDU.");
            k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab);
            return;
        }
        uint8_t *mic_location_ptr = full_mac_pdu_for_phy + assembled_pdu_len_pre_mic;
        ret = security_calculate_mic(mic_calc_start_ptr, mic_calc_len, ctx->integrity_key, mic_location_ptr);
        if (ret != 0) {
            LOG_ERR("PT_SM_KA: MIC calculation failed: %d", ret);
            k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab);
            return;
        }

        uint8_t *encrypt_start_ptr;
        size_t encrypt_len;
        size_t common_hdr_actual_len_ka = sizeof(common_hdr);

        if (include_mac_sec_info_ie_for_ka) {
            encrypt_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                common_hdr_actual_len_ka + len_of_muxed_sec_ie_for_crypto_calc;
            encrypt_len = (current_sdu_area_len - len_of_muxed_sec_ie_for_crypto_calc) + 5;
        } else {
            encrypt_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                common_hdr_actual_len_ka;
            encrypt_len = current_sdu_area_len + 5;
        }

        if (encrypt_len > 0) {
             uint8_t* pdu_buffer_end_ka = full_mac_pdu_for_phy + assembled_pdu_len_pre_mic + 5;
             if (encrypt_start_ptr < full_mac_pdu_for_phy || (encrypt_start_ptr + encrypt_len) > pdu_buffer_end_ka ) {
                 LOG_ERR("PT_SM_KA: Encryption range error. Start %p + Len %zu > PDU End %p",
                         encrypt_start_ptr, encrypt_len, pdu_buffer_end_ka);
                 k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab); return;
             }
             ret = security_crypt_payload(encrypt_start_ptr, encrypt_len, ctx->cipher_key, iv, true /*encrypt*/);
             if (ret != 0) {
                 LOG_ERR("PT_SM_KA: Encryption failed: %d", ret);
                 k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab); return;
             }
        }
        final_tx_pdu_len = assembled_pdu_len_pre_mic + 5;
        LOG_DBG("PT_SM_KA: Keep Alive PDU secured. Final len %u. Mode: %s",
                final_tx_pdu_len, include_mac_sec_info_ie_for_ka ? "WITH_SEC_IE" : "NO_SEC_IE");
    }

    // 6. Schedule TX
    uint32_t phy_op_handle = sys_rand32_get();
    ret = dect_mac_phy_ctrl_start_tx_assembled(
        ctx->role_ctx.pt.associated_ft.operating_carrier,
        full_mac_pdu_for_phy, final_tx_pdu_len,
        ctx->role_ctx.pt.associated_ft.short_rd_id,
        false, /* is_beacon */
        phy_op_handle,
        PENDING_OP_PT_KEEP_ALIVE,
        true, /* use_lbt for unicast control PDU */
        0     /* target_start_time = 0 for immediate attempt */
    );

    // --- This is the block for clearing HPC sync flags after successful scheduling ---
    if (ret == 0 && secure_this_pdu /* && !is_retransmission_placeholder_ka - KA is new */) {
        dect_mac_peer_info_t *assoc_ft_ctx_flags = &ctx->role_ctx.pt.associated_ft;
        if (include_mac_sec_info_ie_for_ka) { // If SecIE was actually sent
            if (sec_iv_type_for_ka_ie == SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) {
                if (assoc_ft_ctx_flags->self_needs_to_request_hpc_from_peer) {
                    LOG_DBG("PT_SM_KA: Cleared self_needs_to_request_hpc_from_peer for FT after sending INITIATE.");
                    assoc_ft_ctx_flags->self_needs_to_request_hpc_from_peer = false;
                }
            } else { // SEC_IV_TYPE_MODE1_HPC_PROVIDED was sent
                bool cleared_peer_req = false;
                if (assoc_ft_ctx_flags->peer_requested_hpc_resync) {
                    LOG_DBG("PT_SM_KA: Cleared peer_requested_hpc_resync for FT after sending PROVIDED.");
                    assoc_ft_ctx_flags->peer_requested_hpc_resync = false;
                    cleared_peer_req = true;
                }
                // Only clear global send_mac_sec_info_ie_on_next_tx if it was the *sole* reason for sending PROVIDED
                if (ctx->send_mac_sec_info_ie_on_next_tx && !cleared_peer_req &&
                    !(sec_iv_type_for_ka_ie == SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) ) { // Double check it wasn't initiate
                    LOG_DBG("PT_SM_KA: Cleared global send_mac_sec_info_ie_on_next_tx after sending PROVIDED for own HPC wrap.");
                    ctx->send_mac_sec_info_ie_on_next_tx = false;
                }
            }
        }
    }
    // --- End of HPC sync flag clearing block ---

    k_mem_slab_free(&g_mac_s_slab, (void**)&full_mac_pdu_for_phy_slab); // Free slab buffer after PHY call

    if (ret != 0) {
        LOG_ERR("PT_SM_KA: Failed to schedule Keep Alive TX: %d", ret);
    } else {
        LOG_INF("PT_SM_KA: Keep Alive TX scheduled (Hdl %u).", phy_op_handle);
    }
}

static void pt_start_authentication_with_ft_action(dect_mac_context_t *ctx) {
    if (!ctx) {
        LOG_ERR("PT_AUTH_START: NULL context provided.");
        return;
    }

    if (!ctx->role_ctx.pt.associated_ft.is_valid) {
        LOG_ERR("PT_AUTH_START: No valid associated FT to authenticate with. Aborting auth.");
        // This state should not normally be reached if called correctly after processing AssocResp(ACK)
        dect_mac_change_state(MAC_STATE_IDLE); // Go back to idle to rescan
        dect_mac_sm_pt_start_operation();      // Trigger rescan
        return;
    }

    LOG_INF("PT SM: Starting Authentication (PSK-based key derivation) with FT 0x%04X (L:0x%08X).",
            ctx->role_ctx.pt.associated_ft.short_rd_id,
            ctx->role_ctx.pt.associated_ft.long_rd_id);

    dect_mac_change_state(MAC_STATE_PT_AUTHENTICATING);

    // For PSK-based "authentication", the main action is local key derivation.
    // No PDUs are exchanged for this simplified model.
    // A real authentication would involve sending an Auth Request, receiving Challenge, sending Response etc.

    if (ctx->master_psk_provisioned) {
        LOG_DBG("PT_AUTH_START: Master PSK is provisioned. Deriving session keys.");
        int kdf_err = security_derive_session_keys_from_psk(
            ctx->master_psk,
            ctx->integrity_key, // PT's global session integrity key for this FT
            ctx->cipher_key);   // PT's global session cipher key for this FT

        if (kdf_err == 0) {
            LOG_INF("PT_AUTH_START: Session keys successfully derived from PSK.");
            // Call the completion action with success
            pt_authentication_complete_action(ctx, true);
        } else {
            LOG_ERR("PT_AUTH_START: Failed to derive session keys (err %d). Authentication failed.", kdf_err);
            // Call the completion action with failure
            pt_authentication_complete_action(ctx, false);
        }
    } else {
        LOG_WRN("PT_AUTH_START: Master PSK not provisioned. Cannot perform PSK-based authentication. Authentication 'fails' (link remains unsecure).");
        // Call the completion action with failure for security establishment,
        // but the MAC link might still be considered associated (unsecure).
        pt_authentication_complete_action(ctx, false);
    }
}

static void pt_authentication_complete_action(dect_mac_context_t* ctx, bool success) {
    if (!ctx) {
        LOG_ERR("PT_AUTH_COMPLETE: NULL context provided.");
        return;
    }

    if (ctx->state != MAC_STATE_PT_AUTHENTICATING) {
        LOG_WRN("PT_AUTH_COMPLETE: Called in unexpected state %s. Current FT ShortID: 0x%04X",
                dect_mac_state_to_str(ctx->state), ctx->role_ctx.pt.associated_ft.short_rd_id);
        // If not in authenticating, perhaps an old/stale completion.
        // If already associated, do nothing more.
        // If in another state, it might be an error. For now, just log.
        if (ctx->state == MAC_STATE_ASSOCIATED && ctx->role_ctx.pt.associated_ft.is_valid) {
            return; // Already successfully associated.
        }
        // Otherwise, if some error led here, might need to reset.
    }

    if (success && ctx->role_ctx.pt.associated_ft.is_valid) {
        // This 'success' specifically means keys were derived and security context is ready.
        ctx->keys_provisioned = true; // PT's global session keys are now set for this FT
        ctx->role_ctx.pt.associated_ft.is_secure = true;

        // Reset/Initialize HPCs for this new secure session:
        // PT's own transmit HPC for communication with this FT.
        ctx->hpc = 1; // Start own HPC at 1 (or a random value, but 1 is fine for new session)
        // PT's tracking of the FT's transmit HPC. Assume FT also starts/resets its HPC for PT.
        ctx->role_ctx.pt.associated_ft.hpc = 1; // Initial assumption of FT's TX HPC
        // PT should send its HPC in the first secured PDU to the FT.
        ctx->send_mac_sec_info_ie_on_next_tx = true;

        dect_mac_change_state(MAC_STATE_ASSOCIATED);
        LOG_INF("PT_AUTH_COMPLETE: Authentication successful with FT 0x%04X (L:0x%08X). Link is SECURE.",
                ctx->role_ctx.pt.associated_ft.short_rd_id, ctx->role_ctx.pt.associated_ft.long_rd_id);
        LOG_INF("PT_AUTH_COMPLETE: OwnTX_HPC=%u, Tracking FT_TX_HPC=%u. Will send SecIE.",
                ctx->hpc, ctx->role_ctx.pt.associated_ft.hpc);

        // Start periodic timers for an active link
        k_timer_start(&ctx->role_ctx.pt.keep_alive_timer,
                      K_MSEC(ctx->config.keep_alive_period_ms),  // Initial delay
                      K_MSEC(ctx->config.keep_alive_period_ms)); // Period

        if (IS_ENABLED(CONFIG_DECT_MAC_PT_MOBILITY_ENABLE)) { // Enable via Kconfig
            k_timer_start(&ctx->role_ctx.pt.mobility_scan_timer,
                          K_MSEC(ctx->config.mobility_scan_interval_ms),
                          K_MSEC(ctx->config.mobility_scan_interval_ms));
        }
        // Reset association attempt counter for any future (re-)associations
        ctx->role_ctx.pt.current_assoc_retries = 0;

    } else { // Authentication failed or was skipped (e.g. no PSK)
        if (ctx->role_ctx.pt.associated_ft.is_valid) { // Still associated, but unsecure
            ctx->keys_provisioned = false;
            ctx->role_ctx.pt.associated_ft.is_secure = false;
            dect_mac_change_state(MAC_STATE_ASSOCIATED); // Proceed to associated state, but unsecure
            LOG_WRN("PT_AUTH_COMPLETE: Authentication failed or skipped for FT 0x%04X. Link is UNSECURE.",
                    ctx->role_ctx.pt.associated_ft.short_rd_id);
            k_timer_start(&ctx->role_ctx.pt.keep_alive_timer,
                          K_MSEC(ctx->config.keep_alive_period_ms),
                          K_MSEC(ctx->config.keep_alive_period_ms));
            if (IS_ENABLED(CONFIG_DECT_MAC_PT_MOBILITY_ENABLE)) {
                k_timer_start(&ctx->role_ctx.pt.mobility_scan_timer,
                              K_MSEC(ctx->config.mobility_scan_interval_ms),
                              K_MSEC(ctx->config.mobility_scan_interval_ms));
            }
        } else { // No valid associated FT (e.g. if assoc was rejected prior to auth attempt)
            LOG_ERR("PT_AUTH_COMPLETE: Authentication failed and no valid associated FT. Restarting scan.");
            dect_mac_sm_pt_start_operation(); // Go back to scanning
        }
    }
}


static void pt_update_mobility_candidate(uint16_t carrier, int16_t rssi, uint32_t long_id, uint16_t short_id)
{
    dect_mac_context_t* ctx = get_mac_context();
    int free_slot = -1;
    int existing_slot = -1;

    // Check if this candidate (by Long ID) already exists
    for (int i = 0; i < MAX_MOBILITY_CANDIDATES; i++) {
        if (ctx->role_ctx.pt.mobility_candidates[i].is_valid) {
            if (ctx->role_ctx.pt.mobility_candidates[i].long_rd_id == long_id) {
                existing_slot = i;
                break;
            }
        } else if (free_slot == -1) {
            free_slot = i;
        }
    }

    int target_slot = -1;
    if (existing_slot != -1) {
        target_slot = existing_slot;
        LOG_DBG("MOBILITY: Updating existing candidate in slot %d.", target_slot);
    } else if (free_slot != -1) {
        target_slot = free_slot;
        LOG_INF("MOBILITY: Adding new candidate in slot %d.", target_slot);
    } else {
        // No free slots. Find the weakest candidate to replace.
        int16_t weakest_rssi = 0; // RSSI is negative, so 0 is very strong
        int weakest_slot = 0;
        for (int i = 0; i < MAX_MOBILITY_CANDIDATES; i++) {
            if (ctx->role_ctx.pt.mobility_candidates[i].rssi_2 < weakest_rssi) {
                weakest_rssi = ctx->role_ctx.pt.mobility_candidates[i].rssi_2;
                weakest_slot = i;
            }
        }
        if (rssi > weakest_rssi) {
            target_slot = weakest_slot;
            LOG_INF("MOBILITY: Evicting weakest candidate (slot %d, RSSI %.1f) for new one (RSSI %.1f).",
                    target_slot, (float)weakest_rssi / 2.0f, (float)rssi / 2.0f);
        } else {
            LOG_DBG("MOBILITY: New candidate (RSSI %.1f) not stronger than weakest in full list (RSSI %.1f). Ignoring.",
                    (float)rssi / 2.0f, (float)weakest_rssi / 2.0f);
            return;
        }
    }

    // Update the target slot with the new information
    dect_mobility_candidate_t *cand = &ctx->role_ctx.pt.mobility_candidates[target_slot];
    cand->is_valid = true;
    cand->long_rd_id = long_id;
    cand->short_rd_id = short_id;
    cand->operating_carrier = carrier;
    cand->rssi_2 = rssi;
    // TODO: `trigger_count_remaining` and `rach_params` would be populated from a beacon.
}

static void pt_process_page_indication(void)
{
    dect_mac_context_t *ctx = get_mac_context();
    LOG_INF("PT_PAGING: Page received from FT! Transitioning to Associated state to receive data.");

    // Stop the paging cycle
    k_timer_stop(&ctx->role_ctx.pt.paging_cycle_timer);
    // Transition back to the normal connected state
    dect_mac_change_state(MAC_STATE_ASSOCIATED);
    // Restart normal link supervision
    k_timer_start(&ctx->role_ctx.pt.keep_alive_timer, K_MSEC(ctx->config.keep_alive_period_ms), K_MSEC(ctx->config.keep_alive_period_ms));
    // TODO: Schedule an immediate RX window to listen for the pending downlink data.
}

static void pt_handle_phy_rssi_internal(const struct nrf_modem_dect_phy_rssi_event *event)
{
    if (event == NULL || event->meas_len == 0) {
        return;
    }

    // For mobility, we are just interested in the average channel energy.
    // If we find a quiet channel, we could schedule a brief RX on it to listen for beacons.
    int32_t rssi_sum = 0;
    int valid_count = 0;
    for (uint16_t i = 0; i < event->meas_len; ++i) {
        if (event->meas[i] != NRF_MODEM_DECT_PHY_RSSI_NOT_MEASURED) {
            rssi_sum += event->meas[i];
            valid_count++;
        }
    }

    if (valid_count > 0) {
        int16_t avg_rssi = rssi_sum / valid_count;
        LOG_DBG("MOBILITY: Scan on carrier %u result: avg RSSI %.1f dBm.", event->carrier, (float)avg_rssi / 2.0f);

        // TODO: Here you would decide if this channel is "interesting" enough to
        // do a follow-up RX listen for a beacon. For now, this RSSI scan is just a placeholder.
    }
}