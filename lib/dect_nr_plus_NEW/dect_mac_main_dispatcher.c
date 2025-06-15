/* dect_mac/dect_mac_main_dispatcher.c */
#include <zephyr/logging/log.h>
#include <string.h> // For memcpy if needed, snprintk
#include <stdio.h>  // For snprintk

#include "dect_mac_main_dispatcher.h"
#include "dect_mac_core.h"      // For get_mac_context()
#include "dect_mac_context.h"   // For dect_mac_context_t and its members
#include "dect_mac_sm.h"        // For event types, state enums
#include "dect_mac_sm_pt.h"     // For dect_mac_sm_pt_handle_event()
#include "dect_mac_sm_ft.h"     // For dect_mac_sm_ft_handle_event()
#include "dect_mac_phy_ctrl.h"  // For dect_mac_phy_ctrl_handle_op_complete (though SMs call this now)

LOG_MODULE_REGISTER(dect_mac_dispatcher, CONFIG_DECT_MAC_DISPATCHER_LOG_LEVEL);

// Message queue (mac_event_msgq) is defined in dect_mac_phy_if.c and used by MAC thread in dect_mac_main.c

void dect_mac_change_state(dect_mac_state_t new_state) {
    dect_mac_context_t* ctx = get_mac_context();
    if (ctx->state != new_state) {
        LOG_INF("MAC State: %s (%d) -> %s (%d) (Role: %s)",
                dect_mac_state_to_str(ctx->state), ctx->state,
                dect_mac_state_to_str(new_state), new_state,
                (ctx->role == MAC_ROLE_PT ? "PT" : "FT"));
        ctx->state = new_state;
    }
}

// --- Common PHY Event Pre-Processing ---
// Returns true if event should be dispatched to SM, false otherwise.
static bool common_pre_handle_phy_pcc_event(const struct nrf_modem_dect_phy_pcc_event *pcc_event_data,
                                            const dect_mac_context_t *ctx) {
    if (!pcc_event_data || !ctx) return false;

    LOG_DBG("PCC_DISPATCH: Rcvd. H:%u, Status:%d, PHYType:%d, RSSI2:%.1f, SNR:%.2f, Carr:%u, TID:%u",
            pcc_event_data->handle, pcc_event_data->header_status, pcc_event_data->phy_type,
            (float)pcc_event_data->rssi_2 / 2.0f, (float)pcc_event_data->snr / 4.0f,
            pcc_event_data->pcc_params_from_modem.carrier, // Assuming carrier is here after nRF modem update
            pcc_event_data->transaction_id);

    if (pcc_event_data->header_status != NRF_MODEM_DECT_PHY_HDR_STATUS_VALID) {
        LOG_WRN("PCC_DISPATCH: Invalid PCC status (%d). Not dispatching to SM.", pcc_event_data->header_status);
        return false; // Do not dispatch invalid PCCs further usually, SM might handle specific error if needed
    }

    uint8_t received_short_net_id_from_pcc;
    if (pcc_event_data->phy_type == 0) { // nRF PHY Type 0 (ETSI PCC Type 1)
        received_short_net_id_from_pcc = pcc_event_data->hdr.hdr_type_1.short_network_id;
    } else if (pcc_event_data->phy_type == 1) { // nRF PHY Type 1 (ETSI PCC Type 2)
        received_short_net_id_from_pcc = pcc_event_data->hdr.hdr_type_2.short_network_id;
    } else {
        LOG_ERR("PCC_DISPATCH: Unknown nRF PHY header type in PCC: %d. Not dispatching.", pcc_event_data->phy_type);
        return false;
    }

    // ETSI TS 103 636-4, 4.2.3.1: Last 8 LSB of Network ID are in PHY control field (PCC Short Network ID)
    // Only process PCCs from our network (or from any if NetID is 0 - e.g. during initial scan before NetID known)
    uint8_t own_net_id_lsb = (uint8_t)(ctx->network_id_32bit & 0xFF);
    if (own_net_id_lsb != 0 && received_short_net_id_from_pcc != own_net_id_lsb) {
        // Exception: PT scanning might listen for any network ID before it knows its target.
        // The SM should handle this. For now, this dispatcher assumes if own_net_id_lsb is set, it must match.
        if (!(ctx->role == MAC_ROLE_PT && (ctx->state == MAC_STATE_PT_SCANNING || ctx->state == MAC_STATE_PT_BEACON_PDC_WAIT))) {
            LOG_DBG("PCC_DISPATCH: From different network_id_lsb (0x%02X vs our 0x%02X). Ignoring.",
                    received_short_net_id_from_pcc, own_net_id_lsb);
            return false;
        } else {
            LOG_DBG("PCC_DISPATCH: PT in scan/wait_pdc received from NetID LSB 0x%02X (own: 0x%02X). Allowing for now.",
                    received_short_net_id_from_pcc, own_net_id_lsb);
        }
    }
    return true; // Event is valid enough for SM to look at
}

static bool common_pre_handle_phy_pdc_event(const struct nrf_modem_dect_phy_pdc_event *pdc_event_data) {
    if (!pdc_event_data) return false;

    LOG_DBG("PDC_DISPATCH: Rcvd. H:%u, Len:%zu, RSSI2:%.1f, SNR:%.2f, TID:%u",
            pdc_event_data->handle, pdc_event_data->len,
            (float)pdc_event_data->rssi_2 / 2.0f, (float)pdc_event_data->snr / 4.0f,
            pdc_event_data->transaction_id);

    if (pdc_event_data->data == NULL && pdc_event_data->len > 0) {
        LOG_ERR("PDC_DISPATCH: Data NULL but len %zu > 0. Not dispatching.", pdc_event_data->len);
        return false;
    }
    // Allow zero length PDC (MAC PDU might be empty if only PCC was used for signaling ACK/NACK)
    if (pdc_event_data->len > CONFIG_DECT_MAC_PDU_MAX_SIZE) { // Max size for the SDU part of MAC PDU
        LOG_ERR("PDC_DISPATCH: Data too large (%zu > %d). Not dispatching.",
                pdc_event_data->len, CONFIG_DECT_MAC_PDU_MAX_SIZE);
        return false;
    }
    return true; // Event seems valid for SM processing
}

// --- Main Event Dispatcher ---
void dect_mac_event_dispatch(const struct dect_mac_event_msg *msg)
{
    if (!msg) {
        LOG_ERR("DISPATCH: Received NULL message pointer.");
        return;
    }

    dect_mac_context_t* ctx = get_mac_context();
    if (!ctx) { // Should not happen after core_init
        LOG_ERR("DISPATCH: MAC Context not available! Cannot dispatch event %s.", dect_mac_event_to_str(msg->type));
        return;
    }

    // Update last known modem time from the event itself
    ctx->last_known_modem_time = msg->modem_time_of_event;

    LOG_DBG("MAC Evt Dispatch: Evt %s (Time %llu) in State %s (Role %s, PendOp: %s, Hdl: %u)",
            dect_mac_event_to_str(msg->type),
            msg->modem_time_of_event,
            dect_mac_state_to_str(ctx->state),
            (ctx->role == MAC_ROLE_PT ? "PT" : "FT"),
            dect_pending_op_to_str(ctx->pending_op_type),
            ctx->pending_op_handle);

    bool dispatch_to_sm = true;

    switch (msg->type) {
        case MAC_EVENT_PHY_OP_COMPLETE:
            // The role-specific SM will call dect_mac_phy_ctrl_handle_op_complete()
            // to get the completed_op_type and clear global pending status.
            LOG_INF("DISPATCH: OP_COMPLETE for handle %u, err %d (%s). Forwarding to SM.",
                    msg->data.op_complete.handle, msg->data.op_complete.err,
                    nrf_modem_dect_phy_err_to_str(msg->data.op_complete.err));
            break;
        case MAC_EVENT_PHY_PCC:
            dispatch_to_sm = common_pre_handle_phy_pcc_event(&msg->data.pcc, ctx);
            break;
        case MAC_EVENT_PHY_PDC:
            dispatch_to_sm = common_pre_handle_phy_pdc_event(&msg->data.pdc);
            break;
        case MAC_EVENT_PHY_PCC_ERROR:
            LOG_WRN("DISPATCH: PCC Error Rcvd (H:%u, RSSI2:%.1f, SNR:%.1f, TID:%u). Forwarding to SM.",
                    msg->data.pcc_crc_err.handle,
                    msg->data.pcc_crc_err.rssi_2 / 2.0f, msg->data.pcc_crc_err.snr / 4.0f,
                    msg->data.pcc_crc_err.transaction_id);
            break;
        case MAC_EVENT_PHY_PDC_ERROR:
            LOG_WRN("DISPATCH: PDC Error Rcvd (H:%u, RSSI2:%.1f, SNR:%.1f, TID:%u). Forwarding to SM.",
                    msg->data.pdc_crc_err.handle,
                    msg->data.pdc_crc_err.rssi_2 / 2.0f, msg->data.pdc_crc_err.snr / 4.0f,
                    msg->data.pdc_crc_err.transaction_id);
            break;
        case MAC_EVENT_PHY_RSSI_RESULT:
            LOG_INF("DISPATCH: RSSI Report Rcvd (H:%u, Carr:%u, Count:%u). Forwarding to SM.",
                    msg->data.rssi.handle, msg->data.rssi.carrier, msg->data.rssi.meas_len);
            break;

        // Timer events and Command events are dispatched directly to SM without pre-handling here
        case MAC_EVENT_TIMER_EXPIRED_RACH_BACKOFF:
        case MAC_EVENT_TIMER_EXPIRED_RACH_RESP_WINDOW:
        case MAC_EVENT_TIMER_EXPIRED_KEEPALIVE:
        case MAC_EVENT_TIMER_EXPIRED_MOBILITY_SCAN:
        case MAC_EVENT_TIMER_EXPIRED_PAGING_CYCLE:
        case MAC_EVENT_TIMER_EXPIRED_BEACON:
        case MAC_EVENT_TIMER_EXPIRED_HARQ:
        case MAC_EVENT_CMD_ENTER_PAGING_MODE:
            LOG_DBG("DISPATCH: Timer/Cmd event %s. Forwarding to SM.", dect_mac_event_to_str(msg->type));
            break;
        default:
            LOG_WRN("DISPATCH: Unknown event type %d. Not dispatching.", msg->type);
            dispatch_to_sm = false;
            break;
    }

    if (dispatch_to_sm) {
        if (ctx->role == MAC_ROLE_PT) {
            dect_mac_sm_pt_handle_event(msg);
        } else { // MAC_ROLE_FT
            dect_mac_sm_ft_handle_event(msg);
        }
    }
}


// --- String Conversion Utility Functions ---
const char* dect_mac_state_to_str(dect_mac_state_t state) {
    static const char* const names[] = {
        [MAC_STATE_DEACTIVATED]      = "DEACTIVATED",
        [MAC_STATE_IDLE]             = "IDLE",
        [MAC_STATE_PT_SCANNING]      = "PT_SCANNING",
        [MAC_STATE_PT_BEACON_PDC_WAIT] = "PT_BEACON_PDC_WAIT",
        [MAC_STATE_PT_ASSOCIATING]   = "PT_ASSOCIATING",
        [MAC_STATE_PT_RACH_BACKOFF]  = "PT_RACH_BACKOFF",
        [MAC_STATE_PT_WAIT_ASSOC_RESP] = "PT_WAIT_ASSOC_RESP",
        [MAC_STATE_PT_AUTHENTICATING]= "PT_AUTHENTICATING",
        [MAC_STATE_PT_PAGING]        = "PT_PAGING",
        [MAC_STATE_FT_SCANNING]      = "FT_SCANNING",
        [MAC_STATE_FT_BEACONING]     = "FT_BEACONING",
        [MAC_STATE_FT_RACH_LISTEN]   = "FT_RACH_LISTEN",
        [MAC_STATE_ASSOCIATED]       = "ASSOCIATED",
    };
    if (state < MAC_STATE_COUNT && state >= 0) return names[state];
    return "S_UNKNOWN";
}

const char* dect_mac_event_to_str(dect_mac_event_type_t event_type) {
    static const char* const names[] = {
        [MAC_EVENT_PHY_OP_COMPLETE]    = "PHY_OP_COMPLETE",
        [MAC_EVENT_PHY_PCC]            = "PHY_PCC",
        [MAC_EVENT_PHY_PDC]            = "PHY_PDC",
        [MAC_EVENT_PHY_PCC_ERROR]      = "PHY_PCC_ERROR",
        [MAC_EVENT_PHY_PDC_ERROR]      = "PHY_PDC_ERROR",
        [MAC_EVENT_PHY_RSSI_RESULT]    = "PHY_RSSI_RESULT",
        [MAC_EVENT_TIMER_EXPIRED_RACH_BACKOFF] = "TMR_RACH_BACKOFF",
        [MAC_EVENT_TIMER_EXPIRED_RACH_RESP_WINDOW] = "TMR_RACH_RESP_WIN",
        [MAC_EVENT_TIMER_EXPIRED_KEEPALIVE]    = "TMR_KEEPALIVE",
        [MAC_EVENT_TIMER_EXPIRED_MOBILITY_SCAN]= "TMR_MOBILITY_SCAN",
        [MAC_EVENT_TIMER_EXPIRED_PAGING_CYCLE] = "TMR_PAGING_CYCLE",
        [MAC_EVENT_TIMER_EXPIRED_BEACON]       = "TMR_BEACON",
        [MAC_EVENT_TIMER_EXPIRED_HARQ]         = "TMR_HARQ",
        [MAC_EVENT_CMD_ENTER_PAGING_MODE]      = "CMD_ENTER_PAGING",
    };
    if (event_type < MAC_EVENT_TYPE_COUNT && event_type >= 0) return names[event_type];
    return "E_UNKNOWN";
}

const char* dect_pending_op_to_str(pending_op_type_t op_type) {
    // This mapping needs to be robust and cover all enum values.
    // Using a static array for direct mapping is better if enum values are contiguous.
    switch(op_type) {
        case PENDING_OP_NONE: return "NONE";
        case PENDING_OP_PT_SCAN: return "PT_SCAN";
        case PENDING_OP_PT_RACH_ASSOC_REQ: return "PT_RACH_ASSOC_REQ";
        case PENDING_OP_PT_WAIT_BEACON_PDC: return "PT_WAIT_BEACON_PDC";
        case PENDING_OP_PT_WAIT_ASSOC_RESP: return "PT_WAIT_ASSOC_RESP";
        case PENDING_OP_PT_KEEP_ALIVE: return "PT_KEEP_ALIVE";
        case PENDING_OP_PT_MOBILITY_SCAN: return "PT_MOBILITY_SCAN";
        case PENDING_OP_PT_AUTH_MSG_TX: return "PT_AUTH_MSG_TX";
        case PENDING_OP_PT_AUTH_MSG_RX: return "PT_AUTH_MSG_RX";
        case PENDING_OP_FT_INITIAL_SCAN: return "FT_INITIAL_SCAN";
        case PENDING_OP_FT_BEACON: return "FT_BEACON";
        case PENDING_OP_FT_RACH_RX_WINDOW: return "FT_RACH_RX_WINDOW";
        case PENDING_OP_FT_ASSOC_RESP: return "FT_ASSOC_RESP";
        case PENDING_OP_FT_AUTH_MSG_TX: return "FT_AUTH_MSG_TX";
        case PENDING_OP_FT_AUTH_MSG_RX: return "FT_AUTH_MSG_RX";
        default: break;
    }
    // Handle HARQ ranges
    if (op_type >= PENDING_OP_PT_DATA_TX_HARQ0 && op_type <= PENDING_OP_PT_DATA_TX_HARQ_MAX) {
        static char pt_harq_str[20];
        snprintk(pt_harq_str, sizeof(pt_harq_str), "PT_DATA_TX_HARQ%d", op_type - PENDING_OP_PT_DATA_TX_HARQ0);
        return pt_harq_str;
    }
    if (op_type >= PENDING_OP_FT_DATA_TX_HARQ0 && op_type <= PENDING_OP_FT_DATA_TX_HARQ_MAX) {
        static char ft_harq_str[20];
        snprintk(ft_harq_str, sizeof(ft_harq_str), "FT_DATA_TX_HARQ%d", op_type - PENDING_OP_FT_DATA_TX_HARQ0);
        return ft_harq_str;
    }
    return "P_UNKNOWN";
}

const char* nrf_modem_dect_phy_err_to_str(enum nrf_modem_dect_phy_err err) {
    // This switch case covers all defined errors in nrf_modem_dect_phy.h up to a certain version.
    // Ensure it's kept up-to-date with the header file.
    switch (err) {
        case NRF_MODEM_DECT_PHY_SUCCESS: return "SUCCESS";
        case NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY: return "LBT_CHANNEL_BUSY";
        case NRF_MODEM_DECT_PHY_ERR_UNSUPPORTED_OP: return "UNSUPPORTED_OP";
        case NRF_MODEM_DECT_PHY_ERR_NOT_FOUND: return "NOT_FOUND";
        case NRF_MODEM_DECT_PHY_ERR_NO_MEMORY: return "NO_MEMORY";
        case NRF_MODEM_DECT_PHY_ERR_NOT_ALLOWED: return "NOT_ALLOWED";
        case NRF_MODEM_DECT_PHY_OK_WITH_HARQ_RESET: return "OK_WITH_HARQ_RESET";
        case NRF_MODEM_DECT_PHY_ERR_OP_START_TIME_LATE: return "OP_START_TIME_LATE";
        case NRF_MODEM_DECT_PHY_ERR_LBT_START_TIME_LATE: return "LBT_START_TIME_LATE";
        case NRF_MODEM_DECT_PHY_ERR_RF_START_TIME_LATE: return "RF_START_TIME_LATE";
        case NRF_MODEM_DECT_PHY_ERR_INVALID_START_TIME: return "INVALID_START_TIME";
        case NRF_MODEM_DECT_PHY_ERR_OP_SCHEDULING_CONFLICT: return "OP_SCHEDULING_CONFLICT";
        case NRF_MODEM_DECT_PHY_ERR_OP_TIMEOUT: return "OP_TIMEOUT";
        case NRF_MODEM_DECT_PHY_ERR_NO_ONGOING_HARQ_RX: return "NO_ONGOING_HARQ_RX";
        case NRF_MODEM_DECT_PHY_ERR_PARAMETER_UNAVAILABLE: return "PARAMETER_UNAVAILABLE";
        case NRF_MODEM_DECT_PHY_ERR_PAYLOAD_UNAVAILABLE: return "PAYLOAD_UNAVAILABLE";
        case NRF_MODEM_DECT_PHY_ERR_OP_CANCELED: return "OP_CANCELED";
        case NRF_MODEM_DECT_PHY_ERR_COMBINED_OP_FAILED: return "COMBINED_OP_FAILED";
        case NRF_MODEM_DECT_PHY_ERR_RADIO_MODE_CONFLICT: return "RADIO_MODE_CONFLICT";
        case NRF_MODEM_DECT_PHY_ERR_UNSUPPORTED_CARRIER: return "UNSUPPORTED_CARRIER";
        case NRF_MODEM_DECT_PHY_ERR_UNSUPPORTED_DATA_SIZE: return "UNSUPPORTED_DATA_SIZE";
        case NRF_MODEM_DECT_PHY_ERR_INVALID_NETWORK_ID: return "INVALID_NETWORK_ID";
        case NRF_MODEM_DECT_PHY_ERR_INVALID_PHY_HEADER: return "INVALID_PHY_HEADER";
        case NRF_MODEM_DECT_PHY_ERR_INVALID_DURATION: return "INVALID_DURATION";
        case NRF_MODEM_DECT_PHY_ERR_INVALID_PARAMETER: return "INVALID_PARAMETER";
        case NRF_MODEM_DECT_PHY_ERR_TX_POWER_OVER_MAX_LIMIT: return "TX_POWER_OVER_MAX_LIMIT";
        case NRF_MODEM_DECT_PHY_ERR_MODEM_ERROR: return "MODEM_ERROR";
        case NRF_MODEM_DECT_PHY_ERR_MODEM_ERROR_RF_STATE: return "MODEM_ERROR_RF_STATE";
        case NRF_MODEM_DECT_PHY_ERR_TEMP_HIGH: return "TEMP_HIGH";
        case NRF_MODEM_DECT_PHY_ERR_PROD_LOCK: return "PROD_LOCK";
        default:
            {
                // Using a static buffer for unknown codes has thread-safety implications if multiple
                // threads call this concurrently for different unknown errors before the string is used.
                // For typical Zephyr logging from a single MAC thread, this is usually acceptable.
                static char unknown_err_str[24]; // Enough for "PHY_ERR_0xDEADBEEF"
                snprintk(unknown_err_str, sizeof(unknown_err_str), "PHY_ERR_0x%X", err);
                return unknown_err_str;
            }
    }
}