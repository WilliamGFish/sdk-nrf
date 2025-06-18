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

#ifndef HPC_RX_WINDOW_SIZE
#define HPC_RX_WINDOW_SIZE 64
#endif
#ifndef HPC_RX_FORWARD_WINDOW_MAX_ADVANCE
#define HPC_RX_FORWARD_WINDOW_MAX_ADVANCE 1024 // Allow a jump of up to 1024
#endif

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
    if (ctx->state != MAC_STATE_PT_WAIT_ASSOC_RESP && ctx->state != MAC_STATE_PT_ASSOCIATING) {
        LOG_WRN("PT_RACH_RESP_TIMEOUT: Timer expired in unexpected state %s. Ignoring.", dect_mac_state_to_str(ctx->state));
        return;
    }

    LOG_WRN("PT_RACH_RESP_TIMEOUT: No Association Response from FT 0x%04X (L:0x%08X).",
            ctx->role_ctx.pt.target_ft.short_rd_id, ctx->role_ctx.pt.target_ft.long_rd_id);

    ctx->role_ctx.pt.current_assoc_retries++;
    if (ctx->role_ctx.pt.target_ft.is_valid && // Still have a target
        ctx->role_ctx.pt.current_assoc_retries < ctx->config.max_assoc_retries) {

        LOG_INF("PT_RACH_RESP_TIMEOUT: Retrying association to FT 0x%04X (attempt %u / %u).",
                ctx->role_ctx.pt.target_ft.short_rd_id,
                ctx->role_ctx.pt.current_assoc_retries + 1, // +1 for display
                ctx->config.max_assoc_retries);

        // New CW handling for timeout (similar to LBT busy):
        uint8_t ft_cwmin_sig_code = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.cwmin_sig_code;
        uint8_t ft_cwmax_sig_code = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.cwmax_sig_code;

        if (ctx->rach_context.rach_cw_current_idx < ft_cwmin_sig_code) {
             ctx->rach_context.rach_cw_current_idx = ft_cwmin_sig_code;
        }
        if (ctx->rach_context.rach_cw_current_idx < ft_cwmax_sig_code) {
            ctx->rach_context.rach_cw_current_idx++;
            LOG_DBG("PT_RACH_RESP_TIMEOUT: Increased CW index to %u for next attempt.", ctx->rach_context.rach_cw_current_idx);
        } else {
            LOG_DBG("PT_RACH_RESP_TIMEOUT: CW index already at max (%u) from FT.", ft_cwmax_sig_code);
        }


        // If the next attempt is RACH, pt_send_association_request_action will handle LBT and potential further CW increase.
        // Directly call pt_send_association_request_action to re-attempt.
        // It will change state to PT_ASSOCIATING or PT_RACH_BACKOFF.
        pt_send_association_request_action();

    } else {
        LOG_ERR("PT_RACH_RESP_TIMEOUT: Max association retries (%u) for FT 0x%04X or no valid target. Restarting scan.",
                ctx->config.max_assoc_retries, ctx->role_ctx.pt.target_ft.short_rd_id);
        // Clear target FT info as we're giving up on this one
        memset(&ctx->role_ctx.pt.target_ft, 0, sizeof(dect_mac_peer_info_t));
        ctx->role_ctx.pt.target_ft.is_valid = false;
        dect_mac_sm_pt_start_operation(); // Restart scan to find a new FT
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

                // Use response window duration from parsed RACH params
                uint32_t resp_win_ms = ctx->role_ctx.pt.current_ft_rach_params.response_window_duration_us / 1000;
                if (resp_win_ms < 10) resp_win_ms = 50; // Minimum sensible timeout
                if (resp_win_ms == 0 && ctx->config.rach_response_window_ms > 0) { // Fallback if calc was 0
                    LOG_WRN("PT_SM_RACH_RESP_TMR: Calculated RespWin was 0us, using Kconfig default %ums", ctx->config.rach_response_window_ms);
                    resp_win_ms = ctx->config.rach_response_window_ms;
                } else if (resp_win_ms == 0) {
                    resp_win_ms = 200; // Absolute fallback
                }
                if (resp_win_ms > 5000) resp_win_ms = 5000; // Max sensible timeout

                LOG_DBG("PT_SM_RACH_RESP_TMR: Starting RACH response window timer for %u ms.", resp_win_ms);
                k_timer_start(&ctx->rach_context.rach_response_window_timer, K_MSEC(resp_win_ms), K_NO_WAIT);

                uint32_t phy_rx_op_handle = sys_rand32_get();
                // Listen duration should also be related to response_window_duration_us
                uint32_t rx_duration_modem_units = modem_us_to_ticks( (resp_win_ms + 50 /*margin*/) * 1000, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ );

                int ret = dect_mac_phy_ctrl_start_rx(
                    ctx->role_ctx.pt.target_ft.operating_carrier, // Response expected on FT's op carrier
                    rx_duration_modem_units,
                    NRF_MODEM_DECT_PHY_RX_MODE_SEMICONTINUOUS,
                    phy_rx_op_handle,
                    ctx->own_short_rd_id,
                    PENDING_OP_PT_WAIT_ASSOC_RESP);
                if (ret != 0) {
                    LOG_ERR("PT_SM: Failed to schedule RX for AssocResp: %d. Resp timer will timeout.", ret);
                } else {
                    LOG_INF("PT_SM: RX scheduled (Hdl %u) for Association Response from FT 0x%04X.",
                            phy_rx_op_handle, ctx->role_ctx.pt.target_ft.short_rd_id);
                }

            } else if (event->err == NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY) {
                LOG_WRN("PT_SM: RACH TX LBT busy for AssocReq (Hdl %u). Increasing CW and backing off.", event->handle);
                dect_mac_change_state(MAC_STATE_PT_RACH_BACKOFF);



                // Ensure current_assoc_retries is incremented for LBT busy as it's a failed attempt
                // Note: This might conflict if timeout also increments it. Typically, LBT busy is one type of failure.
                // Let's assume LBT busy also counts towards retries for *this specific FT target*.
                if (ctx->role_ctx.pt.current_assoc_retries < ctx->config.max_assoc_retries) {
                    // ctx->role_ctx.pt.current_assoc_retries++; // Incrementing here might be too aggressive if backoff is short.
                                                              // Let timeout handle retry count for simplicity for now.
                } else {
                    LOG_ERR("PT_SM_RACH_LBT_BUSY: Max association retries reached for FT 0x%04X after LBT busy. Restarting scan.",
                            ctx->role_ctx.pt.target_ft.short_rd_id);
                    dect_mac_sm_pt_start_operation();
                    return; // Do not proceed with backoff
                }

                // Use CW_MIN/MAX codes from parsed RACH params for this FT
                uint8_t ft_cwmin_sig_code = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.cwmin_sig_code;
                uint8_t ft_cwmax_sig_code = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.cwmax_sig_code;

                // If current CW index is below FT's min, reset to FT's min.
                // This can happen if CW was reset globally (e.g. after success with another FT).
                if (ctx->rach_context.rach_cw_current_idx < ft_cwmin_sig_code) {
                    ctx->rach_context.rach_cw_current_idx = ft_cwmin_sig_code;
                }

                // Double CW by incrementing index, up to FT's max.
                if (ctx->rach_context.rach_cw_current_idx < ft_cwmax_sig_code) {
                    ctx->rach_context.rach_cw_current_idx++;
                }
                // If already at max, it stays at max.

                // Calculate current CW value (CW_CURRENT from ETSI 5.3.1)
                // CW_Value = 8 * (2^CodeValue)
                uint16_t current_cw_value = 8 * (1U << ctx->rach_context.rach_cw_current_idx);

                // Ensure current_cw_value does not exceed the max value derived from ft_cwmax_sig_code.
                // (This should be inherently handled if rach_cw_current_idx is capped by ft_cwmax_sig_code)
                // uint16_t derived_ft_cw_max_val = ctx->role_ctx.pt.current_ft_rach_params.cw_max_val;
                // if (current_cw_value > derived_ft_cw_max_val && derived_ft_cw_max_val > 0) {
                //     current_cw_value = derived_ft_cw_max_val;
                // }
                // The derived cw_min_val and cw_max_val are already in current_ft_rach_params.
                if (current_cw_value < ctx->role_ctx.pt.current_ft_rach_params.cw_min_val) {
                    current_cw_value = ctx->role_ctx.pt.current_ft_rach_params.cw_min_val;
                }
                if (current_cw_value > ctx->role_ctx.pt.current_ft_rach_params.cw_max_val &&
                    ctx->role_ctx.pt.current_ft_rach_params.cw_max_val > 0 ) { // Check cw_max_val is not 0 due to bad code
                    current_cw_value = ctx->role_ctx.pt.current_ft_rach_params.cw_max_val;
                }


                uint32_t backoff_slots_to_wait = (current_cw_val > 0) ? (sys_rand32_get() % current_cw_val) : 0;

                // ETSI RACH slot duration = STF + GI.
                // STF = 7 or 9 symbols (N_rep * N_STF_symb_per_rep). GI duration also mu-dependent.
                // For simplicity, let's use a fixed small unit time per "RACH backoff slot", e.g. ~200us (1 subslot time for mu=1)
                // This needs to align with how contention slots are actually defined/perceived in the system.
                // NRF_MODEM_DECT_LBT_PERIOD_MIN is 2 symbols.

                // Use FT's mu (from its RACH IE) to determine subslot duration for backoff units
                uint8_t ft_mu_for_rach = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.mu_value_for_ft_beacon;
                if (ft_mu_for_rach == 0 || ft_mu_for_rach > 8) { // Sanitize from parsed IE
                    LOG_WRN("PT_RACH_BKOFF: Invalid mu %u from FT RACH IE for backoff timing, defaulting to mu=1.", ft_mu_for_rach);
                    ft_mu_for_rach = 1; // mu_code 0
                }
                uint32_t rach_contention_slot_ticks = get_subslot_duration_ticks_for_mu(ft_mu_for_rach);
                if (rach_contention_slot_ticks == 0) { // Fallback if helper returned error
                    LOG_ERR("PT_RACH_BKOFF: Failed to get subslot duration for FT mu_code %u. Using default backoff time.", ft_mu_for_rach);
                    rach_contention_slot_ticks = NRF_MODEM_DECT_LBT_PERIOD_MIN; // Fallback to a small unit
                }


                uint32_t backoff_duration_ticks = backoff_slots_to_wait * rach_contention_slot_ticks;
                uint32_t backoff_ms = (backoff_duration_ticks * 1000U) / NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ;
                if (backoff_ms == 0 && backoff_slots_to_wait > 0) backoff_ms = 1; // Ensure at least 1ms for very short tick counts
                if (backoff_ms == 0 && backoff_slots_to_wait == 0) backoff_ms = 2; // Min backoff even if 0 slots chosen

                LOG_INF("PT_SM: RACH backoff for %u ms (CW_idx %u -> val %u, chosen_units %u, unit_ticks %u)",
                        backoff_ms, ctx->rach_context.rach_cw_current_idx, current_cw_val,
                        backoff_slots_to_wait, rach_contention_slot_ticks);
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


        uint8_t *sdu_area_for_data_path = sdu_area_after_common_hdr;
    size_t sdu_area_len_for_data_path = sdu_area_plus_mic_len_in_payload;

    if (security_applied_by_sender) {
        if (!active_ft_peer_ctx || !link_is_expected_to_be_secure) {
            LOG_WRN("PT_SM_PDC_SEC: Secured PDU from FT 0x%04X, but no valid secure context. Discarding.", ft_sender_short_id_from_pcc);
            return;
        }
        if (sdu_area_plus_mic_len_in_payload < 5 /*MIC_LEN*/) {
             LOG_ERR("PT_SM_PDC_SEC: Secured PDU from FT 0x%04X too short for MIC (SDUArea+MIC len %zu). Discarding.",
                    ft_sender_short_id_from_pcc, sdu_area_plus_mic_len_in_payload);
             return;
        }

        const dect_mac_unicast_header_t *uch_ptr = (const dect_mac_unicast_header_t *)common_hdr_start_in_payload;
        uint16_t received_psn = ((uch_ptr->sequence_num_high_reset_rsv >> 4) & 0x0F) << 8 | uch_ptr->sequence_num_low;
        uint32_t ft_tx_long_id_from_hdr = sys_be32_to_cpu(uch_ptr->transmitter_long_rd_id_be);

        if (mac_hdr_type_octet.mac_header_type == MAC_COMMON_HEADER_TYPE_UNICAST && ft_tx_long_id_from_hdr != active_ft_peer_ctx->long_rd_id) {
            LOG_WRN("PT_SM_PDC_SEC: Secured PDU LongID 0x%08X mismatch for FT 0x%04X (expected 0x%08X). Discarding.",
                    ft_tx_long_id_from_hdr, ft_sender_short_id_from_pcc, active_ft_peer_ctx->long_rd_id);
            return;
        }
        // For MAC_COMMON_HEADER_TYPE_DATA_PDU, ft_tx_long_id_from_hdr is not present in header, use active_ft_peer_ctx->long_rd_id

        uint8_t *payload_to_decrypt_start = NULL;
        size_t payload_to_decrypt_len = 0;
        size_t cleartext_sec_ie_mux_len = 0;

        if (mac_hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            uint8_t ie_type_sec; uint16_t ie_len_sec; const uint8_t *ie_payload_sec;
            int mux_hdr_len_sec = parse_mac_mux_header(sdu_area_after_common_hdr, sdu_area_plus_mic_len_in_payload,
                                                       &ie_type_sec, &ie_len_sec, &ie_payload_sec);
            if (mux_hdr_len_sec > 0 && ie_type_sec == IE_TYPE_MAC_SECURITY_INFO) {
                if (sdu_area_plus_mic_len_in_payload < (size_t)mux_hdr_len_sec + ie_len_sec + 5) {
                    LOG_ERR("PT_SM_PDC_SEC: PDU too short for parsed SecIE + rest + MIC. Discarding.");
                    pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path;
                }
                cleartext_sec_ie_mux_len = mux_hdr_len_sec + ie_len_sec;
                uint8_t ver, kidx, secivtype_from_ie; uint32_t hpc_from_ie;
                if (parse_mac_security_info_ie_payload(ie_payload_sec, ie_len_sec, &ver, &kidx, &secivtype_from_ie, &hpc_from_ie) == 0) {
                    // active_ft_peer_ctx is the context for the peer FT.
                    // hpc_from_ie is the HPC value parsed from the MAC Security Info IE.

                    LOG_INF("PDC_SEC_HPC_PT: RX SecIE from FT 0x%04X. HPC_IE=%u, MyTrackedPeerHPC.hpc=%u, MyTrackedPeerHPC.highest_rx=%u, SecIVType=%u",
                            ft_sender_short_id_from_pcc,
                            hpc_from_ie,
                            active_ft_peer_ctx->hpc, /* Current HPC used for this PDU's IV (might be updated) */
                            active_ft_peer_ctx->highest_rx_peer_hpc, /* Highest validated HPC from a SecIE */
                            secivtype_from_ie);

                    bool hpc_accepted_for_iv = false;

                    if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_PROVIDED) {
                        if (active_ft_peer_ctx->highest_rx_peer_hpc == 0 && hpc_from_ie > 0) { // First valid HPC received
                            active_ft_peer_ctx->highest_rx_peer_hpc = hpc_from_ie;
                            active_ft_peer_ctx->hpc = hpc_from_ie; // Use this for current PDU
                            hpc_accepted_for_iv = true;
                            LOG_DBG("PDC_SEC_HPC_PT: First HPC_PROVIDED %u accepted.", hpc_from_ie);
                        } else {
                            uint32_t forward_diff;
                            if (hpc_from_ie >= active_ft_peer_ctx->highest_rx_peer_hpc) {
                                forward_diff = hpc_from_ie - active_ft_peer_ctx->highest_rx_peer_hpc;
                            } else { // hpc_from_ie wrapped around
                                forward_diff = (UINT32_MAX - active_ft_peer_ctx->highest_rx_peer_hpc) + hpc_from_ie + 1;
                            }

                            if (forward_diff == 0) { // Same as highest seen
                                active_ft_peer_ctx->hpc = hpc_from_ie;
                                hpc_accepted_for_iv = true;
                                LOG_DBG("PDC_SEC_HPC_PT: HPC_PROVIDED %u matches highest_rx. Accepted.", hpc_from_ie);
                            } else if (forward_diff > 0 && forward_diff <= HPC_RX_FORWARD_WINDOW_MAX_ADVANCE) {
                                active_ft_peer_ctx->highest_rx_peer_hpc = hpc_from_ie;
                                active_ft_peer_ctx->hpc = hpc_from_ie;
                                hpc_accepted_for_iv = true;
                                LOG_DBG("PDC_SEC_HPC_PT: HPC_PROVIDED %u accepted (forward jump %u). New highest_rx.", hpc_from_ie, forward_diff);
                            } else if (forward_diff > HPC_RX_FORWARD_WINDOW_MAX_ADVANCE) {
                                LOG_ERR("PDC_SEC_HPC_PT: HPC_PROVIDED %u rejected. Excessive forward jump %u (max %u).",
                                        hpc_from_ie, forward_diff, HPC_RX_FORWARD_WINDOW_MAX_ADVANCE);
                                pdc_process_ok_for_feedback = false;
                            } else { // hpc_from_ie is "older"
                                uint32_t backward_diff;
                                if (active_ft_peer_ctx->highest_rx_peer_hpc >= hpc_from_ie) {
                                    backward_diff = active_ft_peer_ctx->highest_rx_peer_hpc - hpc_from_ie;
                                } else { // highest_rx_peer_hpc wrapped relative to hpc_from_ie
                                    backward_diff = (UINT32_MAX - hpc_from_ie) + active_ft_peer_ctx->highest_rx_peer_hpc + 1;
                                }

                                if (backward_diff < HPC_RX_WINDOW_SIZE) {
                                    active_ft_peer_ctx->hpc = hpc_from_ie;
                                    hpc_accepted_for_iv = true;
                                    LOG_DBG("PDC_SEC_HPC_PT: HPC_PROVIDED %u accepted (older, but within anti-replay window %u).",
                                            hpc_from_ie, backward_diff);
                                } else {
                                    LOG_ERR("PDC_SEC_HPC_PT: HPC_PROVIDED %u rejected. Too old or outside anti-replay window (diff %u, win %u).",
                                            hpc_from_ie, backward_diff, HPC_RX_WINDOW_SIZE);
                                    pdc_process_ok_for_feedback = false;
                                }
                            }
                        }
                    } else if (secivtype_from_ie == SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE) {
                        // FT is requesting PT's HPC. PT should note this and send its HPC back.
                        LOG_INF("PDC_SEC_HPC_PT: FT 0x%04X requests PT's HPC, providing its HPC_IE=%u.",
                                ft_sender_short_id_from_pcc, hpc_from_ie);
                        // Validate hpc_from_ie from FT for *this current PDU's IV*.
                        if (active_ft_peer_ctx->highest_rx_peer_hpc == 0 || hpc_from_ie >= active_ft_peer_ctx->highest_rx_peer_hpc ||
                           (active_ft_peer_ctx->highest_rx_peer_hpc > hpc_from_ie && /* Check for wrap-around if hpc_from_ie is small */
                            (active_ft_peer_ctx->highest_rx_peer_hpc - hpc_from_ie < HPC_RX_WINDOW_SIZE)) ||
                           (hpc_from_ie < active_ft_peer_ctx->highest_rx_peer_hpc && /* Check for wrap-around if highest_rx_peer_hpc is small */
                            (UINT32_MAX - active_ft_peer_ctx->highest_rx_peer_hpc + hpc_from_ie + 1 < HPC_RX_WINDOW_SIZE)) ) {
                            active_ft_peer_ctx->hpc = hpc_from_ie;
                            if (hpc_from_ie > active_ft_peer_ctx->highest_rx_peer_hpc || /* Standard update or wrap-around new */
                                (active_ft_peer_ctx->highest_rx_peer_hpc > 0xFFFFFF00 && hpc_from_ie < 0x000000FF)) { // Heuristic for wrap
                                active_ft_peer_ctx->highest_rx_peer_hpc = hpc_from_ie;
                            }
                            hpc_accepted_for_iv = true;
                        } else {
                             LOG_WRN("PDC_SEC_HPC_PT: HPC_IE %u with RESYNC_INITIATE from FT is too old vs highest_rx %u. Using highest_rx for IV.",
                                     hpc_from_ie, active_ft_peer_ctx->highest_rx_peer_hpc);
                             active_ft_peer_ctx->hpc = active_ft_peer_ctx->highest_rx_peer_hpc; // Fallback for IV
                             hpc_accepted_for_iv = true; // Still accept PDU if possible
                        }
                        // Set flag for PT to send its HPC back to the FT
                        ctx->send_mac_sec_info_ie_on_next_tx = true;
                    } else { // Unknown SecIVType
                        LOG_ERR("PDC_SEC_HPC_PT: Unknown SecIVType %u from FT 0x%04X. Rejecting PDU.",
                                secivtype_from_ie, ft_sender_short_id_from_pcc);
                        pdc_process_ok_for_feedback = false;
                    }

                    if (!hpc_accepted_for_iv && pdc_process_ok_for_feedback) {
                        LOG_ERR("PDC_SEC_HPC_PT: HPC_IE %u was not accepted for IV construction. Rejecting PDU.", hpc_from_ie);
                        pdc_process_ok_for_feedback = false;
                    }

                } else { LOG_ERR("PT_SM_PDC_SEC: Failed to parse MAC Sec Info IE from FT 0x%04X.", ft_sender_short_id_from_pcc); 
                    pdc_process_ok_for_feedback = false; 
                }

                payload_to_decrypt_start = sdu_area_after_common_hdr + cleartext_sec_ie_mux_len;
                payload_to_decrypt_len = sdu_area_plus_mic_len_in_payload - cleartext_sec_ie_mux_len;
            } else {
                LOG_ERR("PT_SM_PDC_SEC: MAC_SECURITY_USED_WITH_IE indicated but MAC Sec Info IE not found/parsed first. Discarding.");
                pdc_process_ok_for_feedback = false;
            }
        } else { // MAC_SECURITY_USED_NO_IE
            cleartext_sec_ie_mux_len = 0;
            payload_to_decrypt_start = sdu_area_after_common_hdr;
            payload_to_decrypt_len = sdu_area_plus_mic_len_in_payload;
        }

        if (!pdc_process_ok_for_feedback) goto process_feedback_pt_rx_sec_path;

        if (payload_to_decrypt_len < 5) { LOG_ERR("PT_SM_PDC_SEC: Encrypted part too short for MIC. Discarding."); pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path; }

        uint8_t iv[16];
        security_build_iv(iv, active_ft_peer_ctx->long_rd_id, ctx->own_long_rd_id,
                          active_ft_peer_ctx->hpc, // Use PT's tracked HPC for this FT
                          received_psn);

        if (security_crypt_payload(payload_to_decrypt_start, payload_to_decrypt_len,
                                   ctx->cipher_key, iv, false /*decrypt*/) != 0) {
            LOG_ERR("PT_SM_PDC_SEC: Decryption failed for PDU from FT 0x%04X. Discarding.", ft_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path;
        }

        uint8_t *cleartext_mic_ptr = payload_to_decrypt_start + payload_to_decrypt_len - 5;
        uint8_t calculated_mic[5];
        size_t data_for_mic_len = common_hdr_actual_len + (payload_to_decrypt_len - 5) + cleartext_sec_ie_mux_len;

        if (security_calculate_mic(common_hdr_start_in_payload, data_for_mic_len,
                                   ctx->integrity_key, calculated_mic) != 0) {
            LOG_ERR("PT_SM_PDC_SEC: MIC re-calc failed. Discarding PDU from FT 0x%04X.", ft_sender_short_id_from_pcc);
            pdc_process_ok_for_feedback = false; goto process_feedback_pt_rx_sec_path;
        }

        if (memcmp(cleartext_mic_ptr, calculated_mic, 5) != 0) {
            LOG_ERR("PT_SM_PDC_SEC: MIC FAIL from FT 0x%04X (PSN %u, PeerHPC %u). Discarding.",
                    ft_sender_short_id_from_pcc, received_psn, active_ft_peer_ctx->hpc);
            active_ft_peer_ctx->consecutive_mic_failures++;
            if (active_ft_peer_ctx->consecutive_mic_failures >= MAX_MIC_FAILURES_BEFORE_HPC_RESYNC) {
                LOG_WRN("PT_SM_PDC_SEC: Max MIC failures (%u) for FT 0x%04X. Will request HPC resync from FT.",
                        active_ft_peer_ctx->consecutive_mic_failures, ft_sender_short_id_from_pcc);
                active_ft_peer_ctx->self_needs_to_request_hpc_from_peer = true;
                active_ft_peer_ctx->consecutive_mic_failures = 0;
            }
            pdc_process_ok_for_feedback = false;
        } else { // MIC OK
            LOG_DBG("PT_SM_PDC_SEC: MIC OK from FT 0x%04X (PSN %u, PeerHPC %u).",
                    ft_sender_short_id_from_pcc, received_psn, active_ft_peer_ctx->hpc);
            active_ft_peer_ctx->consecutive_mic_failures = 0;
            sdu_area_for_data_path = sdu_area_after_common_hdr + cleartext_sec_ie_mux_len;
            sdu_area_len_for_data_path = payload_to_decrypt_len - 5;
        }
    } else { // Not secured
        LOG_DBG("PT_SM_PDC: Unsecure PDU from FT 0x%04X.", ft_sender_short_id_from_pcc);
        // sdu_area_for_data_path and sdu_area_len_for_data_path are already set for non-secure
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


            dect_mac_rd_capability_ie_t ft_caps_parsed; 

            bool cb_found = false;
            bool rach_found = false;
            bool ft_caps_parsed_successfully = false; 
            uint8_t mu_code_from_ft_caps = 0; // Default to mu-code 0 (actual mu=1)

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

            // First pass: Iterate through all IEs to find RD Capability and extract mu_code.
            const uint8_t *scan_ptr = sdu_area_final_ptr;
            size_t scan_rem_len = sdu_area_final_len;
            while (scan_rem_len > 0 && !ft_caps_parsed_successfully) {
                uint8_t ie_type_scan; uint16_t ie_len_scan; const uint8_t *ie_payload_scan;
                int mux_hdr_len_scan = parse_mac_mux_header(scan_ptr, scan_rem_len, &ie_type_scan, &ie_len_scan, &ie_payload_scan);

                if (mux_hdr_len_scan <= 0) { LOG_ERR("PT_PDC_BCN: MUX pre-scan error %d.", mux_hdr_len_scan); break; }
                if (ie_len_scan == 0 && ((scan_ptr[0] >> 6) & 0x03) == 0b00) { /* MAC_Ext=00 */
                    if (scan_rem_len < (size_t)mux_hdr_len_scan) break;
                    ie_len_scan = scan_rem_len - mux_hdr_len_scan;
                }
                if (scan_rem_len < (size_t)mux_hdr_len_scan + ie_len_scan) { LOG_ERR("PT_PDC_BCN: MUX IE pre-scan len error."); break; }

                if (ie_type_scan == IE_TYPE_RD_CAPABILITY) {
                    if (parse_rd_capability_ie_payload(ie_payload_scan, ie_len_scan, &ft_caps_parsed) == 0) {
                        ft_caps_parsed_successfully = true;
                        if (ft_caps_parsed.num_phy_capabilities >= 1 && // num_phy_capabilities is N-1 value
                            ft_caps_parsed.phy_variants[0].mu_value <= 7) { // mu_code is 0-7
                            mu_code_from_ft_caps = ft_caps_parsed.phy_variants[0].mu_value;
                            LOG_INF("PT_PDC_BCN: Extracted mu_code=%u from FT RD Capability IE.", mu_code_from_ft_caps);
                        } else {
                            LOG_WRN("PT_PDC_BCN: RD Cap IE parsed, but no explicit PHY sets or mu_code invalid. Using default mu_code=%u.", mu_code_from_ft_caps);
                        }
                    } else { LOG_WRN("PT_PDC_BCN: Failed to parse RD_CAP IE payload during pre-scan.");}
                }
                scan_ptr += mux_hdr_len_scan + ie_len_scan;
                if (scan_rem_len >= (size_t)mux_hdr_len_scan + ie_len_scan) scan_rem_len -= (mux_hdr_len_scan + ie_len_scan); else scan_rem_len = 0;
            }

            // Second pass: Parse all IEs, using the determined mu_code_from_ft_caps for RACH Info IE.
            while(sdu_area_iter_rem_len > 0) {
                uint8_t ie_type; uint16_t ie_len; const uint8_t *ie_payload_data;
                int mux_hdr_len = parse_mac_mux_header(sdu_area_iter_ptr, sdu_area_iter_rem_len,
                                                       &ie_type, &ie_len, &ie_payload_data);
                if (mux_hdr_len <= 0) { LOG_ERR("PT_PDC_BCN: MUX parse error %d in main pass.", mux_hdr_len); break; }
                if (ie_len == 0 && ((sdu_area_iter_ptr[0] >> 6) & 0x03) == 0b00) { /* MAC_Ext=00 */
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
                    if(parse_rach_info_ie_payload(ie_payload_data, ie_len, mu_code_from_ft_caps, &rach_fields_parsed)==0) {
                        rach_found = true;
                        // The parser now stores the mu_code it used internally in rach_fields_parsed.mu_value_for_ft_beacon
                        LOG_DBG("PT_PDC_BCN: Parsed RACH Info IE using mu_code=%u.", mu_code_from_ft_caps);
                    } else { LOG_WRN("PT_PDC_BCN: Failed to parse RACH Info IE payload (using mu_code=%u).", mu_code_from_ft_caps); }
                } else if (ie_type == IE_TYPE_RD_CAPABILITY && !ft_caps_parsed_successfully) {
                    // If RD Cap wasn't found in pre-scan (e.g., it appeared after RACH_INFO), parse it here.
                    // The mu_code_from_ft_caps used for RACH_INFO would have been the default in this case.
                    if (parse_rd_capability_ie_payload(ie_payload_data, ie_len, &ft_caps_parsed) == 0) {
                        ft_caps_parsed_successfully = true;
                        LOG_DBG("PT_PDC_BCN: Parsed RD_CAP IE (main loop).");
                        // Optionally, re-parse RACH if mu was different and RACH was already parsed with default. (More complex)
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
        LOG_INF("PT_BEACON_PROC: Target FT operating_carrier set to: %u", ctx->role_ctx.pt.target_ft.operating_carrier);

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
        LOG_DBG("PT_BEACON_PROC: FT SFN0 Anchor: %llu (Beacon SFN %u @ %llu)",
                ctx->ft_sfn_zero_modem_time_anchor, cb_fields->sfn, beacon_pcc_rx_time);

        // Copy RACH parameters from parsed IE into PT's operational RACH context for this FT
        memcpy(&ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields,
               parsed_rach_ie_fields, sizeof(dect_mac_rach_info_ie_fields_t));

        // Derive RACH Operating Channel
        if (parsed_rach_ie_fields->channel_field_present &&
            parsed_rach_ie_fields->channel_abs_freq_num != 0 &&
            parsed_rach_ie_fields->channel_abs_freq_num != 0xFFFF) {
            ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel = parsed_rach_ie_fields->channel_abs_freq_num;
        } else {
            ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel = ctx->role_ctx.pt.target_ft.operating_carrier;
        }

        // Derive CW_MIN and CW_MAX values from codes (ETSI 5.3.1: CW_Value = 8 * 2^Code)
        if (parsed_rach_ie_fields->cwmin_sig_code <= 7) { // Code is 0-7
             ctx->role_ctx.pt.current_ft_rach_params.cw_min_val = 8 * (1U << parsed_rach_ie_fields->cwmin_sig_code);
        } else {
            LOG_WRN("PT_BEACON_PROC: Invalid cwmin_sig_code %u from FT. Using Kconfig default.", parsed_rach_ie_fields->cwmin_sig_code);
             ctx->role_ctx.pt.current_ft_rach_params.cw_min_val = 8 * (1U << ctx->config.rach_cw_min_idx); // Fallback
        }
        if (parsed_rach_ie_fields->cwmax_sig_code <= 7) { // Code is 0-7
            ctx->role_ctx.pt.current_ft_rach_params.cw_max_val = 8 * (1U << parsed_rach_ie_fields->cwmax_sig_code);
        } else {
            LOG_WRN("PT_BEACON_PROC: Invalid cwmax_sig_code %u from FT. Using Kconfig default.", parsed_rach_ie_fields->cwmax_sig_code);
            ctx->role_ctx.pt.current_ft_rach_params.cw_max_val = 8 * (1U << ctx->config.rach_cw_max_idx); // Fallback
        }

        // Calculate Response Window Duration in microseconds, now mu-aware
        uint32_t resp_win_subslots_actual = parsed_rach_ie_fields->response_window_subslots_val_minus_1 + 1;
        uint8_t ft_mu = parsed_rach_ie_fields->mu_value_for_ft_beacon; // This was set by parser
        if (ft_mu == 0 || ft_mu > 8) { // Sanitize mu from FT
            LOG_WRN("PT_BEACON_PROC: Invalid mu (%u) in parsed RACH IE for RespWin calc. Defaulting to mu=1.", ft_mu);
            ft_mu = 1;
        }

        uint32_t ft_base_symbol_duration_ticks = NRF_MODEM_DECT_SYMBOL_DURATION; // Ticks for mu=1 symbol
        uint32_t ft_actual_symbol_duration_ticks = ft_base_symbol_duration_ticks;
        if (ft_mu > 1) { // Assuming NRF_MODEM_DECT_SYMBOL_DURATION is for mu=1
            ft_actual_symbol_duration_ticks = ft_base_symbol_duration_ticks / (1U << (ft_mu - 1));
        }
        uint32_t ft_subslot_duration_ticks = ft_actual_symbol_duration_ticks * 5; // 5 OFDM symbols per subslot

        if (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ > 0 && ft_subslot_duration_ticks > 0) {
            ctx->role_ctx.pt.current_ft_rach_params.response_window_duration_us =
                (resp_win_subslots_actual * ft_subslot_duration_ticks * 1000U) / NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ;
        } else {
            LOG_ERR("PT_BEACON_PROC: Invalid tick rate or subslot duration for FT mu %u. Cannot calc RespWin_us.", ft_mu);
            ctx->role_ctx.pt.current_ft_rach_params.response_window_duration_us = ctx->config.rach_response_window_ms * 1000; // Fallback
        }

        LOG_INF("PT_BEACON_PROC: Stored RACH params for FT 0x%04X (L:0x%08X):", ft_short_id, ft_long_id);
        LOG_INF("  RACH OperCarrier: %u, RACH IE mu (for StartSS): %u",
                ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel,
                parsed_rach_ie_fields->mu_value_for_ft_beacon);
        LOG_INF("  CWmin_code: %u (val %u), CWmax_code: %u (val %u)",
                parsed_rach_ie_fields->cwmin_sig_code, ctx->role_ctx.pt.current_ft_rach_params.cw_min_val,
                parsed_rach_ie_fields->cwmax_sig_code, ctx->role_ctx.pt.current_ft_rach_params.cw_max_val);
        LOG_INF("  RespWin: %u subslots => %u us (using FT_mu=%u for timing, FT_subslot_ticks=%u)",
                resp_win_subslots_actual, ctx->role_ctx.pt.current_ft_rach_params.response_window_duration_us,
                ft_mu, ft_subslot_duration_ticks);
        LOG_INF("  RACH StartSS: %u (%sbit), Len: %u %s, MaxRACHLen: %u %s, RepCode: %u, DECTDelay: %d",
                parsed_rach_ie_fields->start_subslot_index,
                (parsed_rach_ie_fields->mu_value_for_ft_beacon > 4 ? "9" : "8"),
                parsed_rach_ie_fields->num_subslots_or_slots, parsed_rach_ie_fields->length_type_is_slots ? "slots" : "subslots",
                parsed_rach_ie_fields->max_rach_pdu_len_units, parsed_rach_ie_fields->max_len_type_is_slots ? "slots" : "subslots",
                parsed_rach_ie_fields->repetition_code, parsed_rach_ie_fields->dect_delay_for_response);
        if (parsed_rach_ie_fields->sfn_validity_present) {
            LOG_INF("  RACH SFN: %u, Validity: %u frames", parsed_rach_ie_fields->sfn_value, parsed_rach_ie_fields->validity_frames);
        }



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



// Brief Overview: Enhances pt_send_association_request_action to fully populate
// the dect_mac_assoc_req_ie_t structure with all relevant ETSI fields,
// including HARQ parameters, and placeholder logic for requested Flow IDs and FT Mode parameters.
// Also populates the PT's RD Capability IE more completely.
static void pt_send_association_request_action(void) {
    dect_mac_context_t* ctx = get_mac_context();

    if (!ctx->role_ctx.pt.target_ft.is_valid || !ctx->role_ctx.pt.target_ft.is_fully_identified) {
        LOG_ERR("PT_SM_ASSOC_REQ: No valid or not fully identified target FT. Restarting scan.");
        dect_mac_sm_pt_start_operation();
        return;
    }
    if (ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel == 0 ||
        ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel == 0xFFFF) {
        LOG_ERR("PT_SM_ASSOC_REQ: Target FT RACH operating channel invalid. Restarting scan.");
        dect_mac_sm_pt_start_operation();
        return;
    }
    uint8_t ft_max_rach_len_actual_units = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.max_rach_pdu_len_units + 1;
    if (ft_max_rach_len_actual_units == 0 || ft_max_rach_len_actual_units > 128) { // Max N-1 is 127 for 7 bits
        LOG_ERR("PT_SM_ASSOC_REQ: Target FT RACH max PDU length invalid (%u units). Cannot send. Restarting scan.", ft_max_rach_len_actual_units);
        dect_mac_sm_pt_start_operation();
        return;
    }

    if (ctx->state != MAC_STATE_PT_ASSOCIATING && ctx->state != MAC_STATE_PT_RACH_BACKOFF) {
        dect_mac_change_state(MAC_STATE_PT_ASSOCIATING);
    } else if (ctx->state == MAC_STATE_PT_RACH_BACKOFF) {
        dect_mac_change_state(MAC_STATE_PT_ASSOCIATING);
    }

    LOG_INF("PT_SM_ASSOC_REQ: Attempting Association Request to FT 0x%04X on RACH carrier %u (Attempt %u).",
            ctx->role_ctx.pt.target_ft.short_rd_id,
            ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel,
            ctx->role_ctx.pt.current_assoc_retries + 1);

    uint8_t sdu_area_buf[128]; 
    dect_mac_assoc_req_ie_t assoc_req_fields;
    memset(&assoc_req_fields, 0, sizeof(assoc_req_fields));
    dect_mac_rd_capability_ie_t rd_cap_fields; // PT's own capabilities
    memset(&rd_cap_fields, 0, sizeof(rd_cap_fields));

    // --- Populate Association Request IE Fields (dect_mac_assoc_req_ie_t) ---
    assoc_req_fields.setup_cause_val = ASSOC_CAUSE_INITIAL_ASSOCIATION;
    assoc_req_fields.power_const_active = false; 
    assoc_req_fields.ft_mode_capable = IS_ENABLED(CONFIG_DECT_MAC_PT_CAN_BE_FT);
    
    assoc_req_fields.number_of_flows_val = 0; // Default: Request 0 specific flows.
    // To request N flows (1-6):
    // assoc_req_fields.number_of_flows_val = N;
    // for (int i=0; i<N; ++i) assoc_req_fields.flow_ids[i] = your_flow_id_array[i] & 0x3F;

    assoc_req_fields.harq_params_present = true; 
    assoc_req_fields.harq_processes_tx_val = CONFIG_DECT_MAC_PT_HARQ_TX_PROC_CODE & 0x07;
    assoc_req_fields.max_harq_re_tx_delay_code = CONFIG_DECT_MAC_PT_HARQ_RETX_DELAY_PT_CODE & 0x1F;
    assoc_req_fields.harq_processes_rx_val = CONFIG_DECT_MAC_PT_HARQ_RX_PROC_CODE & 0x07;
    assoc_req_fields.max_harq_re_rx_delay_code = CONFIG_DECT_MAC_PT_HARQ_RERX_DELAY_PT_CODE & 0x1F;

    if (assoc_req_fields.ft_mode_capable) {
        assoc_req_fields.ft_beacon_periods_octet_present = IS_ENABLED(CONFIG_DECT_MAC_PT_FT_MODE_SIGNAL_PERIODS);
        if (assoc_req_fields.ft_beacon_periods_octet_present) {
            assoc_req_fields.ft_network_beacon_period_code = CONFIG_DECT_MAC_PT_FT_MODE_NET_BEACON_PERIOD_CODE & 0x0F;
            assoc_req_fields.ft_cluster_beacon_period_code = CONFIG_DECT_MAC_PT_FT_MODE_CLUS_BEACON_PERIOD_CODE & 0x0F;
        }

        assoc_req_fields.ft_next_channel_present = IS_ENABLED(CONFIG_DECT_MAC_PT_FT_MODE_NEXT_CHAN_PRESENT);
        assoc_req_fields.ft_time_to_next_present = IS_ENABLED(CONFIG_DECT_MAC_PT_FT_MODE_TIME_TO_NEXT_PRESENT);
        assoc_req_fields.ft_current_channel_present = false; // PT usually doesn't signal current channel when ft_mode_capable in AssocReq

        if (assoc_req_fields.ft_next_channel_present || assoc_req_fields.ft_time_to_next_present || assoc_req_fields.ft_current_channel_present) {
            assoc_req_fields.ft_param_flags_octet_present = true;
        } else {
            assoc_req_fields.ft_param_flags_octet_present = false;
        }

        if (assoc_req_fields.ft_next_channel_present) {
            assoc_req_fields.ft_next_cluster_channel_val = CONFIG_DECT_MAC_PT_FT_MODE_NEXT_CLUSTER_CHANNEL_VAL & 0x1FFF;
        }
        if (assoc_req_fields.ft_time_to_next_present) {
            assoc_req_fields.ft_time_to_next_us_val = CONFIG_DECT_MAC_PT_FT_MODE_TIME_TO_NEXT_US_VAL;
        }
    } else {
        assoc_req_fields.ft_beacon_periods_octet_present = false;
        assoc_req_fields.ft_param_flags_octet_present = false;
    }

    // --- Populate PT's RD Capability IE Fields (dect_mac_rd_capability_ie_t) ---
    rd_cap_fields.release_version = 1; 
    rd_cap_fields.num_phy_capabilities = 1; // PT provides one explicit 5-octet PHY capability set

    rd_cap_fields.supports_group_assignment = IS_ENABLED(CONFIG_DECT_MAC_PT_SUPPORTS_GROUP_ASSIGNMENT);
    rd_cap_fields.supports_paging = IS_ENABLED(CONFIG_DECT_MAC_PT_SUPPORTS_PAGING);
    rd_cap_fields.operating_modes_code = assoc_req_fields.ft_mode_capable ? 0b10 : 0b00; 
    rd_cap_fields.supports_mesh = IS_ENABLED(CONFIG_DECT_MAC_PT_SUPPORTS_MESH);
    rd_cap_fields.supports_sched_data = true;
    rd_cap_fields.mac_security_modes_code = IS_ENABLED(CONFIG_DECT_MAC_SECURITY_ENABLE) ? 0b01 : 0b00;

    dect_mac_phy_capability_set_t *pt_phy_set0 = &rd_cap_fields.phy_variants[0];
    pt_phy_set0->dlc_service_type_support_code = CONFIG_DECT_MAC_PT_DLC_SERVICE_SUPPORT_CODE & 0x07;
    pt_phy_set0->rx_for_tx_diversity_code = CONFIG_DECT_MAC_PT_RX_TX_DIVERSITY_CODE & 0x07;
    pt_phy_set0->mu_value = (ctx->own_phy_params.is_valid ? ctx->own_phy_params.mu : CONFIG_DECT_MAC_OWN_MU_CODE) & 0x07;
    pt_phy_set0->beta_value = (ctx->own_phy_params.is_valid ? ctx->own_phy_params.beta : CONFIG_DECT_MAC_OWN_BETA_CODE) & 0x0F;
    pt_phy_set0->max_nss_for_rx_code = CONFIG_DECT_MAC_PT_MAX_NSS_RX_CODE & 0x07;
    pt_phy_set0->max_mcs_code = CONFIG_DECT_MAC_PT_MAX_MCS_CODE & 0x0F;
    pt_phy_set0->harq_soft_buffer_size_code = CONFIG_DECT_MAC_PT_HARQ_BUFFER_CODE & 0x0F;
    pt_phy_set0->num_harq_processes_code = CONFIG_DECT_MAC_PT_NUM_HARQ_PROC_CODE & 0x03;
    pt_phy_set0->harq_feedback_delay_code = CONFIG_DECT_MAC_PT_HARQ_FEEDBACK_DELAY_CODE & 0x0F;
    pt_phy_set0->supports_dect_delay = IS_ENABLED(CONFIG_DECT_MAC_PT_SUPPORTS_DECT_DELAY);
    pt_phy_set0->supports_half_duplex = IS_ENABLED(CONFIG_DECT_MAC_PT_SUPPORTS_HALF_DUPLEX);

    // --- Build SDU Area and MAC PDU ---
    int sdu_area_len = build_assoc_req_ies_area(sdu_area_buf, sizeof(sdu_area_buf),
                                               &assoc_req_fields, &rd_cap_fields);
    if (sdu_area_len < 0) {
        LOG_ERR("PT_SM_ASSOC_REQ: Failed to build Association Request SDU area: %d. Restarting scan.", sdu_area_len);
        dect_mac_sm_pt_start_operation();
        return;
    }

    dect_mac_header_type_octet_t hdr_type_octet;
    hdr_type_octet.version = 0;
    hdr_type_octet.mac_security = MAC_SECURITY_NONE;
    hdr_type_octet.mac_header_type = MAC_COMMON_HEADER_TYPE_UNICAST;

    dect_mac_unicast_header_t common_hdr;
    increment_psn_and_hpc(ctx);
    common_hdr.sequence_num_high_reset_rsv = SET_SEQ_NUM_HIGH_RESET_RSV((ctx->psn >> 8) & 0x0F, 1 /*reset*/);
    common_hdr.sequence_num_low = ctx->psn & 0xFF;
    common_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);
    common_hdr.receiver_long_rd_id_be = sys_cpu_to_be32(ctx->role_ctx.pt.target_ft.long_rd_id);

    uint8_t *full_mac_pdu_for_phy_slab = NULL;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab, K_MSEC(10));
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

    uint8_t pcc_pkt_len_f, pcc_mcs_f_ignored, pcc_pkt_len_type_f;
    uint8_t rach_tx_mcs = 0; 
    uint8_t ft_mu_for_rach_timing = ctx->role_ctx.pt.current_ft_rach_params.advertised_beacon_ie_fields.mu_value_for_ft_beacon;
    if (ft_mu_for_rach_timing > 7) ft_mu_for_rach_timing = 0; 
    uint8_t ft_beta_for_rach_timing = 0; // Assuming beta_code 0 (beta=1) for RACH for now
                                         // TODO: PT should learn FT's beta for RACH if it can vary and is signalled.

    dect_mac_phy_ctrl_calculate_pcc_params(pdu_len - sizeof(dect_mac_header_type_octet_t),
                                           ft_mu_for_rach_timing,
                                           ft_beta_for_rach_timing,
                                           &pcc_pkt_len_f, &rach_tx_mcs, &pcc_pkt_len_type_f);
    uint32_t assoc_req_tx_duration_actual_units = pcc_pkt_len_f + 1;
    if (pcc_pkt_len_type_f == 1) {
        assoc_req_tx_duration_actual_units *= get_subslots_per_etsi_slot_for_mu(ft_mu_for_rach_timing);
    }

    if (assoc_req_tx_duration_actual_units > ft_max_rach_len_actual_units) {
        LOG_ERR("PT_SM_ASSOC_REQ: Assembled AssocReq PDU needs %u units, but FT RACH max is %u. Cannot send. Restarting scan.",
                assoc_req_tx_duration_actual_units, ft_max_rach_len_actual_units);
        k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);
        dect_mac_sm_pt_start_operation();
        return;
    }

    uint32_t phy_op_handle = sys_rand32_get();
    ret = dect_mac_phy_ctrl_start_tx_assembled(
        ctx->role_ctx.pt.current_ft_rach_params.rach_operating_channel,
        full_mac_pdu_for_phy, pdu_len,
        ctx->role_ctx.pt.target_ft.short_rd_id,
        false, phy_op_handle, PENDING_OP_PT_RACH_ASSOC_REQ,
        true, 0);

    k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab);

    if (ret != 0) {
        LOG_ERR("PT_SM_ASSOC_REQ: Failed to schedule AssocReq TX: %d. OpComplete/timeout will handle.", ret);
        if (ret == -EBUSY && ctx->state == MAC_STATE_PT_ASSOCIATING) {
            dect_mac_change_state(MAC_STATE_PT_RACH_BACKOFF);
            uint32_t rach_contention_slot_ticks = get_subslot_duration_ticks_for_mu(ft_mu_for_rach_timing > 0 ? ft_mu_for_rach_timing : 0);
            if (rach_contention_slot_ticks == 0) rach_contention_slot_ticks = NRF_MODEM_DECT_LBT_PERIOD_MIN;
            uint32_t backoff_ms = (1 + (sys_rand32_get()%4)) * ((rach_contention_slot_ticks * 1000U) / NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ + 1);
            if (backoff_ms == 0) backoff_ms = 10; // Ensure some delay
            k_timer_start(&ctx->rach_context.rach_backoff_timer, K_MSEC(MAX(10, backoff_ms)), K_NO_WAIT);
        }
    } else {
        LOG_INF("PT_SM_ASSOC_REQ: Association Request TX scheduled (Hdl %u) to FT 0x%04X.",
                phy_op_handle, ctx->role_ctx.pt.target_ft.short_rd_id);
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

                    LOG_DBG("PT_SM_ASSOC_RESP: Parsed Assoc Resp IE (ACK: %d, HARQMod: %d, NumFlowsAcc: %u, GrpAct: %d).",
                            resp_fields.ack_nack, resp_fields.harq_mod_present,
                            resp_fields.number_of_flows_accepted, resp_fields.group_assignment_active);
                    if (!resp_fields.ack_nack) {
                        LOG_WRN("PT_SM_ASSOC_RESP: Rejected by FT. Cause: %u, TimerCode: %u",
                                resp_fields.reject_cause, resp_fields.reject_timer_code);
                    } else { // ACK
                        if (resp_fields.harq_mod_present) {
                            LOG_INF("PT_SM_ASSOC_RESP: FT provided HARQ Params -> TX Procs: %u, ReTX DelayCode: %u; RX Procs: %u, ReRX DelayCode: %u",
                                    resp_fields.harq_processes_tx_val_ft, resp_fields.max_harq_re_tx_delay_code_ft,
                                    resp_fields.harq_processes_rx_val_ft, resp_fields.max_harq_re_rx_delay_code_ft);
                            // TODO: PT should store and use these FT-provided HARQ parameters for the link.
                        }
                        if (resp_fields.number_of_flows_accepted <= MAX_FLOW_IDS_IN_ASSOC_REQ && resp_fields.number_of_flows_accepted > 0) {
                            // char flow_ids_str_pt[MAX_FLOW_IDS_IN_ASSOC_REQ * 3 + 1] = {0};
                            // for(int k=0; k < resp_fields.number_of_flows_accepted; ++k) { snprintf(flow_ids_str_pt + strlen(flow_ids_str_pt), sizeof(flow_ids_str_pt)-strlen(flow_ids_str_pt), "%u,", resp_fields.accepted_flow_ids[k]); }
                            // if(strlen(flow_ids_str_pt) > 0) flow_ids_str_pt[strlen(flow_ids_str_pt)-1] = '\0';
                            // LOG_INF("PT_SM_ASSOC_RESP: FT Accepted Flows (%u): [%s]", resp_fields.number_of_flows_accepted, flow_ids_str_pt);
                            LOG_INF("PT_SM_ASSOC_RESP: FT Accepted %u specific flows.", resp_fields.number_of_flows_accepted);
                            // TODO: PT should store these accepted flow_ids and configure DLC/CVG accordingly.
                        } else if (resp_fields.number_of_flows_accepted == 0x07) {
                            LOG_INF("PT_SM_ASSOC_RESP: FT accepted all (0) requested flows.");
                        }
                        if (resp_fields.group_assignment_active) {
                            LOG_INF("PT_SM_ASSOC_RESP: FT activated Group Assignment -> GroupID: %u, ResourceTag: %u",
                                    resp_fields.group_id_val, resp_fields.resource_tag_val);
                            // TODO: PT should store and use these for group communication.
                        }
                    }

                } else { 
                    LOG_ERR("PT_SM_ASSOC_RESP: Failed to parse Assoc Resp IE payload."); 
                }
            
        // This modification is for pt_process_association_response_pdu, not pt_handle_phy_pdc_internal's beacon parsing.
        // The context is parsing IEs from an Association Response.
        // ... (inside the MUX parsing loop of pt_process_association_response_pdu)
        } else if (ie_type == IE_TYPE_RD_CAPABILITY) {
            if (!ft_cap_found) { // Parse only the first RD Capability IE encountered
                if (parse_rd_capability_ie_payload(ie_payload_data, ie_len, &ft_cap_fields) == 0) {
                    ft_cap_found = true; // Mark that we have parsed it
                    LOG_DBG("PT_SM_ASSOC_RESP: Parsed FT RD Capability IE (Release %u, NumPHYAddSets %u).",
                            ft_cap_fields.release_version, ft_cap_fields.num_phy_capabilities);

                    // If an explicit PHY set was parsed, store its mu, beta, max_mcs
                    if (ft_cap_fields.num_phy_capabilities >= 1) { // num_phy_capabilities is N-1
                        // Store into the target_ft context first, will be copied to associated_ft if ACK
                        ctx->role_ctx.pt.target_ft.peer_mu = ft_cap_fields.phy_variants[0].mu_value;
                        ctx->role_ctx.pt.target_ft.peer_beta = ft_cap_fields.phy_variants[0].beta_value;
                        ctx->role_ctx.pt.target_ft.peer_max_mcs_code = ft_cap_fields.phy_variants[0].max_mcs_code;
                        ctx->role_ctx.pt.target_ft.peer_phy_params_known = true;
                        LOG_INF("PT_SM_ASSOC_RESP: Prelim FT PHY Params: mu_code=%u, beta_code=%u, max_mcs_code=%u",
                                ft_cap_fields.phy_variants[0].mu_value,
                                ft_cap_fields.phy_variants[0].beta_value,
                                ft_cap_fields.phy_variants[0].max_mcs_code);
                    } else {
                        LOG_WRN("PT_SM_ASSOC_RESP: FT RD Cap IE has no explicit PHY sets. Using defaults for FT link.");
                        ctx->role_ctx.pt.target_ft.peer_mu = 0; // Default mu_code 0 (mu=1)
                        ctx->role_ctx.pt.target_ft.peer_beta = 0; // Default beta_code 0 (beta=1)
                        ctx->role_ctx.pt.target_ft.peer_max_mcs_code = 0; // Default MCS0
                        ctx->role_ctx.pt.target_ft.peer_phy_params_known = false;
                    }
                } else {
                    LOG_ERR("PT_SM_ASSOC_RESP: Failed to parse FT RD Capability IE payload.");
                }
            }
        } else if (ie_type == IE_TYPE_RES_ALLOC) {

            if (!res_alloc_found) { // Parse only the first one
                // Use the mu of the associated FT (which should now be populated in ctx->role_ctx.pt.associated_ft.peer_mu
                // if RD Capability IE was parsed successfully before this point in the SDU Area).
                uint8_t ft_mu_code_for_schedule = 0; // Default mu_code 0 (actual mu=1)
                if (ctx->role_ctx.pt.associated_ft.is_valid && ctx->role_ctx.pt.associated_ft.peer_phy_params_known) {
                    ft_mu_code_for_schedule = ctx->role_ctx.pt.associated_ft.peer_mu;
                } else {
                    LOG_WRN("PT_SM_ASSOC_RESP: FT's mu not known (peer_phy_params_known=false for associated_ft). Defaulting to mu_code=0 for ResAlloc parse.");
                }

                if (parse_resource_alloc_ie_payload(ie_payload_data, ie_len,
                                                    ft_mu_code_for_schedule,
                                                    &res_alloc_fields) == 0) {
                    res_alloc_found = true;
                    LOG_DBG("PT_SM_ASSOC_RESP: Parsed Resource Allocation IE (Type %u) using FT_mu_code=%u.",
                            res_alloc_fields.alloc_type_val, ft_mu_code_for_schedule);
                    // The res_alloc_fields.resX_is_9bit_subslot flags are now set by the parser
                } else {
                    LOG_ERR("PT_SM_ASSOC_RESP: Failed to parse Res Alloc IE (using FT_mu_code=%u).", ft_mu_code_for_schedule);
                }
            }

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


        // Promote target_ft (which now contains parsed peer_mu/beta if RD Cap was present) to associated_ft
        memcpy(&ctx->role_ctx.pt.associated_ft, &ctx->role_ctx.pt.target_ft, sizeof(dect_mac_peer_info_t));
        ctx->role_ctx.pt.associated_ft.is_valid = true; // Now truly associated

        // Log the PHY params that are now part of associated_ft context
        if (ctx->role_ctx.pt.associated_ft.peer_phy_params_known) {
            LOG_INF("PT_SM_ASSOC_RESP: Final FT PHY Params for associated_ft: mu_code=%u, beta_code=%u, max_mcs_code=%u",
                    ctx->role_ctx.pt.associated_ft.peer_mu,
                    ctx->role_ctx.pt.associated_ft.peer_beta,
                    ctx->role_ctx.pt.associated_ft.peer_max_mcs_code);
        } else {
            LOG_WRN("PT_SM_ASSOC_RESP: associated_ft using default PHY params (mu_code=%u, beta_code=%u) as RD Cap was not fully processed or missing.",
                    ctx->role_ctx.pt.associated_ft.peer_mu, ctx->role_ctx.pt.associated_ft.peer_beta);
        }
        
        // Clear target_ft as we are now associated (or moving to auth with this one)
        memset(&ctx->role_ctx.pt.target_ft, 0, sizeof(dect_mac_peer_info_t));
        ctx->role_ctx.pt.target_ft.is_valid = false;


        if (res_alloc_found) {
            LOG_INF("PT_SM: Storing schedule from FT 0x%04X (FT mu_code for schedule: %u).",
                    ctx->role_ctx.pt.associated_ft.short_rd_id,
                    ctx->role_ctx.pt.associated_ft.peer_mu); // This is the FT's mu_code

            uint32_t frame_duration_ticks_val = 0;
            if (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ > 0) {
                    frame_duration_ticks_val = (uint32_t)FRAME_DURATION_MS_NOMINAL * (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ / 1000U);
            }
            if (frame_duration_ticks_val == 0) { LOG_ERR("PT_SCHED: Frame duration ticks is 0!"); /* Handle error */ return; }

            uint8_t ft_mu_code = ctx->role_ctx.pt.associated_ft.peer_phy_params_known ?
                                    ctx->role_ctx.pt.associated_ft.peer_mu : 0; // Default to mu_code 0 (mu=1)
            if (ft_mu_code > 7) ft_mu_code = 0; // Sanitize

            uint8_t subslots_per_ft_slot = get_subslots_per_etsi_slot_for_mu(ft_mu_code);

            uint16_t schedule_channel = res_alloc_fields.channel_present ?
                                        res_alloc_fields.channel_val :
                                        ctx->role_ctx.pt.associated_ft.operating_carrier;

            // --- Populate Downlink Schedule (Resource 1 from ResAlloc IE) ---
            dect_mac_schedule_t *dl_sched = &ctx->role_ctx.pt.dl_schedule;
            memset(dl_sched, 0, sizeof(dect_mac_schedule_t)); // Clear previous schedule
            dl_sched->is_active = true;
            dl_sched->alloc_type = RES_ALLOC_TYPE_DOWNLINK; // From PT's perspective this is DL
            dl_sched->res1_is_9bit_subslot = res_alloc_fields.res1_is_9bit_subslot; // Copied from parser output
            dl_sched->dl_start_subslot = res_alloc_fields.start_subslot_val_res1;
            dl_sched->dl_length_is_slots = res_alloc_fields.length_type_is_slots_res1;
            dl_sched->dl_duration_subslots = res_alloc_fields.length_val_res1 + 1; // N-1 coded
            if (dl_sched->dl_length_is_slots) {
                dl_sched->dl_duration_subslots *= subslots_per_ft_slot;
            }

            dl_sched->repeat_type = res_alloc_fields.repeat_val;
            dl_sched->repetition_value = res_alloc_fields.repetition_value;
            dl_sched->validity_value = res_alloc_fields.validity_value;
            dl_sched->channel = schedule_channel;
            dl_sched->schedule_init_modem_time = assoc_resp_pcc_rx_time; // Time ResAlloc was received

            if (res_alloc_fields.sfn_present) {
                dl_sched->sfn_of_initial_occurrence = res_alloc_fields.sfn_val;
                uint8_t ft_mu_for_sched = ctx->role_ctx.pt.associated_ft.peer_phy_params_known ? ctx->role_ctx.pt.associated_ft.peer_mu : 0;
                uint8_t ft_beta_for_sched = ctx->role_ctx.pt.associated_ft.peer_phy_params_known ? ctx->role_ctx.pt.associated_ft.peer_beta : 0;
                dl_sched->next_occurrence_modem_time =
                    calculate_target_modem_time(ctx, ctx->ft_sfn_zero_modem_time_anchor,
                                                ctx->current_sfn_at_anchor_update,
                                                res_alloc_fields.sfn_val,
                                                dl_sched->dl_start_subslot,
                                                ft_mu_for_sched,
                                                ft_beta_for_sched);
            } else { // SFN not present, schedule relative to current time + processing
                dl_sched->sfn_of_initial_occurrence = ctx->current_sfn_at_anchor_update; // Or SFN of current frame
                uint64_t now_plus_processing_delay = assoc_resp_pcc_rx_time +
                                modem_us_to_ticks(CONFIG_DECT_MAC_SCHEDULE_PROCESSING_DELAY_US, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
                uint64_t current_frame_start_approx = (now_plus_processing_delay / frame_duration_ticks_val) * frame_duration_ticks_val;
                if (current_frame_start_approx < ctx->ft_sfn_zero_modem_time_anchor) current_frame_start_approx = ctx->ft_sfn_zero_modem_time_anchor;

                uint32_t ft_subslot_duration = get_subslot_duration_ticks_for_mu(ft_mu_code);
                uint64_t candidate_time = current_frame_start_approx + (uint64_t)dl_sched->dl_start_subslot * ft_subslot_duration;
                
                // Ensure it's in the future of now_plus_processing_delay
                while(candidate_time <= now_plus_processing_delay) {
                        candidate_time += frame_duration_ticks_val; // Advance by one full frame
                }
                dl_sched->next_occurrence_modem_time = candidate_time;
            }
            update_next_occurrence(ctx, dl_sched, ctx->last_known_modem_time); // Ensure it's truly future
            LOG_INF("PT_SM: DL Schedule Init: NextOcc @ %llu, StartSS %u, Dur %u subslots, Rep %u, Valid %u, Chan %u",
                    dl_sched->next_occurrence_modem_time, dl_sched->dl_start_subslot,
                    dl_sched->dl_duration_subslots, dl_sched->repetition_value,
                    dl_sched->validity_value, dl_sched->channel);

            // --- Populate Uplink Schedule (Resource 2 from ResAlloc IE, if BIDIR) ---
            if (res_alloc_fields.alloc_type_val == RES_ALLOC_TYPE_BIDIR) {
                dect_mac_schedule_t *ul_sched = &ctx->role_ctx.pt.ul_schedule;
                memset(ul_sched, 0, sizeof(dect_mac_schedule_t));
                ul_sched->is_active = true;
                ul_sched->alloc_type = RES_ALLOC_TYPE_UPLINK;
                ul_sched->res1_is_9bit_subslot = res_alloc_fields.res2_is_9bit_subslot; // Res2 from IE maps to Res1 for UL sched
                ul_sched->ul_start_subslot = res_alloc_fields.start_subslot_val_res2;
                ul_sched->ul_length_is_slots = res_alloc_fields.length_type_is_slots_res2;
                ul_sched->ul_duration_subslots = res_alloc_fields.length_val_res2 + 1;
                if (ul_sched->ul_length_is_slots) {
                    ul_sched->ul_duration_subslots *= subslots_per_ft_slot;
                }
                // Copy common schedule parameters
                ul_sched->repeat_type = res_alloc_fields.repeat_val;
                ul_sched->repetition_value = res_alloc_fields.repetition_value;
                ul_sched->validity_value = res_alloc_fields.validity_value;
                ul_sched->channel = schedule_channel;
                ul_sched->schedule_init_modem_time = assoc_resp_pcc_rx_time;

                if (res_alloc_fields.sfn_present) {
                    ul_sched->sfn_of_initial_occurrence = res_alloc_fields.sfn_val;
                    // ft_mu_for_sched and ft_beta_for_sched are already defined from DL part
                    ul_sched->next_occurrence_modem_time =
                        calculate_target_modem_time(ctx, ctx->ft_sfn_zero_modem_time_anchor,
                                                    ctx->current_sfn_at_anchor_update,
                                                    res_alloc_fields.sfn_val,
                                                    ul_sched->ul_start_subslot,
                                                    ft_mu_for_sched,
                                                    ft_beta_for_sched);
                } else {
                    ul_sched->sfn_of_initial_occurrence = ctx->current_sfn_at_anchor_update;
                    uint64_t now_plus_processing_delay = assoc_resp_pcc_rx_time +
                                modem_us_to_ticks(CONFIG_DECT_MAC_SCHEDULE_PROCESSING_DELAY_US, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
                    uint64_t current_frame_start_approx = (now_plus_processing_delay / frame_duration_ticks_val) * frame_duration_ticks_val;
                    if (current_frame_start_approx < ctx->ft_sfn_zero_modem_time_anchor) current_frame_start_approx = ctx->ft_sfn_zero_modem_time_anchor;
                    
                    uint32_t ft_subslot_duration = get_subslot_duration_ticks_for_mu(ft_mu_code);
                    uint64_t candidate_time = current_frame_start_approx + (uint64_t)ul_sched->ul_start_subslot * ft_subslot_duration;
                    
                    while(candidate_time <= now_plus_processing_delay) {
                            candidate_time += frame_duration_ticks_val;
                    }
                    ul_sched->next_occurrence_modem_time = candidate_time;
                }
                update_next_occurrence(ctx, ul_sched, ctx->last_known_modem_time);
                LOG_INF("PT_SM: UL Schedule Init: NextOcc @ %llu, StartSS %u, Dur %u subslots",
                        ul_sched->next_occurrence_modem_time, ul_sched->ul_start_subslot,
                        ul_sched->ul_duration_subslots);
            } else { // If not BIDIR, ensure UL schedule is marked inactive
                ctx->role_ctx.pt.ul_schedule.is_active = false;
            }
        } else {
            LOG_WRN("PT_SM: Association accepted by FT 0x%04X but NO Resource Allocation IE found! Link may be unusable for data.",
                    ctx->role_ctx.pt.associated_ft.short_rd_id);
            ctx->role_ctx.pt.dl_schedule.is_active = false;
            ctx->role_ctx.pt.ul_schedule.is_active = false;
        }


        // Proceed to "authentication" (simplified PSK key derivation)
        // New call to the authentication protocol initiator stub:
        // Determine if security should be attempted (e.g., based on FT capabilities if parsed, or PT policy)
        bool attempt_security = IS_ENABLED(CONFIG_DECT_MAC_SECURITY_ENABLE);
        if (ft_caps_parsed_successfully) { // ft_caps_parsed_successfully was set if RD Cap IE parsed
            // If FT does not support Mode 1 security, don't attempt.
            if ((ft_cap_fields.mac_security_modes_code & 0x01) == 0) { // Assuming code 0b01 means Mode 1 supported
                LOG_WRN("PT_SM_ASSOC_RESP: FT 0x%04X does not support MAC Security Mode 1. Proceeding unsecure.",
                        ctx->role_ctx.pt.associated_ft.short_rd_id);
                attempt_security = false;
            }
        } else {
            LOG_WRN("PT_SM_ASSOC_RESP: FT capabilities not received/parsed. Assuming security attempt is desired if enabled locally.");
        }

        if (attempt_security) {
            dect_mac_change_state(MAC_STATE_PT_AUTHENTICATING);
            dect_mac_sm_pt_initiate_authentication_protocol(); // Calls the stub which then calls pt_start_authentication_with_ft_action
        } else {
            LOG_INF("PT_SM_ASSOC_RESP: Security not attempted. Moving to ASSOCIATED (unsecure).");
            ctx->keys_provisioned = false; // Ensure this is false
            ctx->role_ctx.pt.associated_ft.is_secure = false;
            dect_mac_change_state(MAC_STATE_ASSOCIATED);
            k_timer_start(&ctx->role_ctx.pt.keep_alive_timer, K_MSEC(ctx->config.keep_alive_period_ms), K_MSEC(ctx->config.keep_alive_period_ms));
            if (IS_ENABLED(CONFIG_DECT_MAC_PT_MOBILITY_ENABLE)) {
                 k_timer_start(&ctx->role_ctx.pt.mobility_scan_timer, K_MSEC(ctx->config.mobility_scan_interval_ms), K_MSEC(ctx->config.mobility_scan_interval_ms));
            }
            ctx->role_ctx.pt.current_assoc_retries = 0;
        }
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

    uint8_t sdu_area_buf[20]; // KeepAlive IE is small, SecIE is 6 bytes.
    size_t current_sdu_area_len = 0;
    // int ie_len_written_val; // Declared later
    size_t len_of_muxed_sec_ie_for_crypto_calc = 0; // Initialize

    bool secure_this_pdu = ctx->role_ctx.pt.associated_ft.is_secure && ctx->keys_provisioned;
    bool include_mac_sec_info_ie_for_ka = false;
    uint8_t sec_iv_type_for_ka_ie = SEC_IV_TYPE_MODE1_HPC_PROVIDED; // Default

    if (secure_this_pdu) {
        dect_mac_peer_info_t *assoc_ft_ctx = &ctx->role_ctx.pt.associated_ft; // This is the peer (FT)

        // Priority 1: PT needs to request FT's HPC
        if (assoc_ft_ctx->self_needs_to_request_hpc_from_peer) {
            include_mac_sec_info_ie_for_ka = true;
            sec_iv_type_for_ka_ie = SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE;
            LOG_DBG("PT_KA_SEC: Sending SecIE with HPC_RESYNC_INITIATE to FT 0x%04X.", assoc_ft_ctx->short_rd_id);
        }
        // Priority 2: FT requested PT's HPC (flag set by PT PDC handler)
        else if (ctx->send_mac_sec_info_ie_on_next_tx) { // Global flag for PT to send its HPC
            include_mac_sec_info_ie_for_ka = true;
            sec_iv_type_for_ka_ie = SEC_IV_TYPE_MODE1_HPC_PROVIDED; // Send own HPC
            LOG_DBG("PT_KA_SEC: Sending SecIE with HPC_PROVIDED to FT 0x%04X (FT requested or own HPC wrap).", assoc_ft_ctx->short_rd_id);
        }
        // Note: assoc_ft_ctx->peer_requested_hpc_resync is a flag *on the peer's context* indicating
        // that the *peer* (FT) wants to send *its* HPC. This is handled when PT *receives* from FT.
        // The flag ctx->send_mac_sec_info_ie_on_next_tx is what PT uses to decide to send its own HPC.
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

    // 5. Apply Security if active
    uint16_t final_tx_pdu_len = assembled_pdu_len_pre_mic; // Length before MIC

    if (secure_this_pdu) { // secure_this_pdu was set earlier based on link state
        uint8_t iv[16];
        // current_hpc_for_iv and current_psn_for_tx were determined earlier
        security_build_iv(iv, ctx->own_long_rd_id, ctx->role_ctx.pt.associated_ft.long_rd_id,
                          current_hpc_for_iv, current_psn_for_tx);

        // MIC Calculation: Covers MAC Common Header + entire MAC SDU Area (cleartext).
        uint8_t *mic_calculation_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t);
        size_t mic_calculation_length = sizeof(common_hdr) + current_sdu_area_len;

        if ((assembled_pdu_len_pre_mic + 5) > CONFIG_DECT_MAC_PDU_MAX_SIZE) {
            LOG_ERR("PT_SM_KA: No space for MIC in PDU.");
            k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
        }
        uint8_t *mic_location_ptr = full_mac_pdu_for_phy + assembled_pdu_len_pre_mic;
        ret = security_calculate_mic(mic_calculation_start_ptr, mic_calculation_length,
                                   ctx->integrity_key, mic_location_ptr);
        if (ret != 0) {
            LOG_ERR("PT_SM_KA: MIC calculation failed: %d", ret);
            k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
        }
        final_tx_pdu_len = assembled_pdu_len_pre_mic + 5;

        // Encryption:
        uint8_t *encryption_start_ptr;
        size_t encryption_length;
        // len_of_muxed_sec_ie_for_crypto_calc was determined when sdu_area_buf was populated

        if (hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) { // i.e. include_mac_sec_info_ie_for_ka was true
            // Encrypt: (Rest of MAC SDU Area, i.e., SDU Area - MUXed SecIE) + MIC
            encryption_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                   sizeof(common_hdr) + len_of_muxed_sec_ie_for_crypto_calc;
            encryption_length = (current_sdu_area_len - len_of_muxed_sec_ie_for_crypto_calc) + 5; // (Rest of SDU Area) + MIC
        } else { // MAC_SECURITY_USED_NO_IE
            encryption_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) + sizeof(common_hdr);
            encryption_length = current_sdu_area_len + 5; // Full SDU Area + MIC
        }

        if (encryption_length > 0) {
             uint8_t* pdu_buffer_end_with_mic = full_mac_pdu_for_phy + final_tx_pdu_len;
             if (encryption_start_ptr < full_mac_pdu_for_phy || (encryption_start_ptr + encryption_length) > pdu_buffer_end_with_mic ) {
                 LOG_ERR("PT_SM_KA: Encryption range error. Start %p + Len %zu > PDU End %p",
                         encryption_start_ptr, encryption_length, pdu_buffer_end_with_mic);
                 k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
             }
             ret = security_crypt_payload(encryption_start_ptr, encryption_length, ctx->cipher_key, iv, true /*encrypt*/);
             if (ret != 0) {
                 LOG_ERR("PT_SM_KA: Encryption failed: %d", ret);
                 k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_for_phy_slab); return;
             }
        }
        LOG_DBG("PT_SM_KA: Keep Alive PDU secured. Final len %u. Mode: %s, MUXSecIELen: %zu",
                final_tx_pdu_len,
                (hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) ? "WITH_SEC_IE" : "NO_SEC_IE",
                len_of_muxed_sec_ie_for_crypto_calc);
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

/**
 * @brief pt_authentication_complete_action
 * 
 * @param ctx 
 * @param success 
 */
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


void dect_mac_sm_pt_initiate_authentication_protocol(void)
{
    dect_mac_context_t* ctx = get_mac_context();

    if (!ctx->role_ctx.pt.associated_ft.is_valid) {
        LOG_ERR("PT_AUTH_INIT: No valid associated FT to authenticate with. Aborting.");
        // Transition to a state that will trigger rescan or error handling
        dect_mac_change_state(MAC_STATE_IDLE); // Or directly call start_operation
        dect_mac_sm_pt_start_operation();
        return;
    }

    // Ensure state is MAC_STATE_PT_AUTHENTICATING.
    // The caller (pt_process_association_response_pdu) should have set this.
    if (ctx->state != MAC_STATE_PT_AUTHENTICATING) {
        LOG_WRN("PT_AUTH_INIT: Called in state %s, expected AUTHENTICATING. Transitioning.", dect_mac_state_to_str(ctx->state));
        dect_mac_change_state(MAC_STATE_PT_AUTHENTICATING);
    }

    LOG_INF("PT_AUTH_INIT: Initiating (stubbed PSK-based) authentication with FT 0x%04X.",
            ctx->role_ctx.pt.associated_ft.short_rd_id);

    // For this stub, directly proceed to the PSK-based key derivation logic.
    // pt_start_authentication_with_ft_action performs PSK derivation and calls pt_authentication_complete_action.
    pt_start_authentication_with_ft_action(ctx);
}

void dect_mac_sm_pt_handle_auth_pdu(const uint8_t *pdu_data, size_t pdu_len)
{
    ARG_UNUSED(pdu_data);
    ARG_UNUSED(pdu_len);
    dect_mac_context_t* ctx = get_mac_context();

    if (ctx->state != MAC_STATE_PT_AUTHENTICATING) {
        LOG_WRN("PT_AUTH_HANDLE_PDU: Received Auth PDU in unexpected state %s. Ignoring.", dect_mac_state_to_str(ctx->state));
        return;
    }

    LOG_INF("PT_AUTH_HANDLE_PDU: Received (stubbed) Auth PDU from FT 0x%04X (len %zu). No action for current PSK model.",
            ctx->role_ctx.pt.associated_ft.is_valid ? ctx->role_ctx.pt.associated_ft.short_rd_id : 0xFFFF,
            pdu_len);

    // For a real multi-step protocol, this would parse pdu_data.
    // If it's the final confirmation from FT:
    // pt_authentication_complete_action(ctx, true_if_auth_ok_else_false);
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