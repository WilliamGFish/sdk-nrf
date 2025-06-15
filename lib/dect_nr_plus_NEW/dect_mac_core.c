/* dect_mac/dect_mac_core.c */
#include <zephyr/logging/log.h>
#include <zephyr/random/rand32.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <zephyr/sys/util.h> // For ARRAY_SIZE, MIN, MAX if needed
#include <hw_id.h>           // For hw_id_get()

#include "dect_mac_core.h"
#include "dect_mac_context.h"   // For dect_mac_context_t structure and sub-types
#include "dect_mac_sm.h"        // For dect_mac_role_t, event types for timers
#include "dect_mac_data_path.h" // For dect_mac_data_path_init and HARQ timer callback
#include "dect_mac_sm_pt.h"     // For PT timer callback function extern declarations
#include "dect_mac_sm_ft.h"     // For FT timer callback function extern declarations
#include "dect_mac_main_dispatcher.h" // For mac_event_msgq (external)

LOG_MODULE_REGISTER(dect_mac_core, CONFIG_DECT_MAC_CORE_LOG_LEVEL);

// Global MAC Context Definition
static dect_mac_context_t g_mac_ctx; // This is the single instance

dect_mac_context_t* get_mac_context(void) {
    return &g_mac_ctx;
}

// External message queue (defined in dect_mac_phy_if.c, used by timer handlers here)
extern struct k_msgq mac_event_msgq;

// --- Timer Expiry Function Prototypes (actual handlers in SM or DataPath files) ---
// These are the functions that k_timer will call upon expiry.
// They typically just queue an event to the main MAC thread.

// Generic RACH Timer expiry functions (PT SM will react to the queued events)
static void rach_backoff_timer_expiry_fn(struct k_timer *timer_id) {
    ARG_UNUSED(timer_id); // We use global context or pass ID via user_data if needed
    struct dect_mac_event_msg msg = {.type = MAC_EVENT_TIMER_EXPIRED_RACH_BACKOFF};
    // msg.modem_time_of_event = k_uptime_get(); // Example
    if (k_msgq_put(&mac_event_msgq, &msg, K_NO_WAIT) != 0) {
        LOG_ERR("RACH_BKO_TMR: Failed to queue expiry event.");
    }
}

static void rach_response_window_timer_expiry_fn(struct k_timer *timer_id) {
    ARG_UNUSED(timer_id);
    struct dect_mac_event_msg msg = {.type = MAC_EVENT_TIMER_EXPIRED_RACH_RESP_WINDOW};
    if (k_msgq_put(&mac_event_msgq, &msg, K_NO_WAIT) != 0) {
        LOG_ERR("RACH_RESP_TMR: Failed to queue expiry event.");
    }
}

// PT Specific Timer expiry functions
static void pt_keep_alive_timer_expiry_fn(struct k_timer *timer_id) {
    ARG_UNUSED(timer_id);
    struct dect_mac_event_msg msg = {.type = MAC_EVENT_TIMER_EXPIRED_KEEPALIVE};
    if (k_msgq_put(&mac_event_msgq, &msg, K_NO_WAIT) != 0) {
        LOG_ERR("PT_KA_TMR: Failed to queue expiry event.");
    }
}

static void pt_mobility_scan_timer_expiry_fn(struct k_timer *timer_id) {
    ARG_UNUSED(timer_id);
    struct dect_mac_event_msg msg = {.type = MAC_EVENT_TIMER_EXPIRED_MOBILITY_SCAN};
    if (k_msgq_put(&mac_event_msgq, &msg, K_NO_WAIT) != 0) {
        LOG_ERR("PT_MOB_TMR: Failed to queue expiry event.");
    }
}

// FT Specific Timer expiry functions
static void ft_beacon_timer_expiry_fn(struct k_timer *timer_id) {
    ARG_UNUSED(timer_id);
    struct dect_mac_event_msg msg = {.type = MAC_EVENT_TIMER_EXPIRED_BEACON};
    if (k_msgq_put(&mac_event_msgq, &msg, K_NO_WAIT) != 0) {
        LOG_ERR("FT_BCN_TMR: Failed to queue expiry event.");
    }
}


// --- PSN and HPC Management ---
void increment_psn_and_hpc(dect_mac_context_t *ctx)
{
    if (!ctx) return;
    ctx->psn = (ctx->psn + 1) & 0x0FFF; // 12-bit PSN wraps from 4095 to 0
    if (ctx->psn == 0) {
        ctx->hpc = (ctx->hpc + 1);
        if (ctx->hpc == 0) { // HPC wrapped around (32-bit)
            ctx->hpc = 1; // Re-initialize (ETSI IV must not be all zeros if derived from HPC=0, PSN=0)
            LOG_WRN("MAC Core: Own HPC wrapped around! Re-initialized to 1.");
        }
        LOG_INF("MAC Core: Own PSN wrapped, own HPC incremented to %u.", ctx->hpc);
        ctx->send_mac_sec_info_ie_on_next_tx = true;
    }
}

// --- Core Initialization ---
int dect_mac_core_init(dect_mac_role_t role, uint32_t provisioned_long_rd_id)
{
    dect_mac_context_t* ctx = get_mac_context(); // Gets pointer to g_mac_ctx
    memset(ctx, 0, sizeof(dect_mac_context_t));

    ctx->role = role;

    if (provisioned_long_rd_id != 0 && provisioned_long_rd_id != 0xFFFFFFFFU) {
        ctx->own_long_rd_id = provisioned_long_rd_id;
    } else {
        char hw_id_str[HW_ID_LEN + 1]; // HW_ID_LEN from Zephyr's hw_id.h
        memset(hw_id_str, 0, sizeof(hw_id_str));
        int err = hw_id_get((uint8_t*)hw_id_str, HW_ID_LEN); // hw_id_get expects uint8_t*
        if (err < 0) { // hw_id_get returns length on success, neg errno on failure
            LOG_ERR("MAC Core: Failed to get HW ID for Long RD ID derivation (err %d). Using random.", err);
            ctx->own_long_rd_id = sys_rand32_get();
        } else {
            hw_id_str[err] = '\0'; // Ensure null termination if err is actual length
            uint32_t derived_id = 0;
            // Simple hash - consider a more robust hashing algorithm if needed
            for (int i = 0; i < strlen(hw_id_str); i++) {
                derived_id = 31 * derived_id + hw_id_str[i];
            }
            ctx->own_long_rd_id = derived_id;
            LOG_INF("MAC Core: Derived Long RD ID 0x%08X from HW_ID '%s'", ctx->own_long_rd_id, hw_id_str);
        }
        if (ctx->own_long_rd_id == 0 || ctx->own_long_rd_id == 0xFFFFFFFFU) {
            ctx->own_long_rd_id = (sys_rand32_get() & 0xFFFFFFFEU) + 1;
            LOG_WRN("MAC Core: Derived/Random Long RD ID was reserved, re-randomized to 0x%08X", ctx->own_long_rd_id);
        }
    }

    // Generate Short RD ID (random, not 0x0000 or 0xFFFF)
    do {
        ctx->own_short_rd_id = (uint16_t)(sys_rand32_get() & 0xFFFF);
    } while (ctx->own_short_rd_id == 0x0000 || ctx->own_short_rd_id == 0xFFFF);


    // Derive Network ID (ETSI TS 103 636-4, 4.2.3.1)
    // "first 24 MSB bits are used to identify a DECT-2020 network... The 8 LSB bits...are selected locally"
    // "neither the 8 LSB bits are 0x00 nor the 24 MSB bits are 0x000000."
    // Example: Use a fixed vendor part for MS24, LSB from Long RD ID.
    uint32_t net_id_ms24_part = CONFIG_DECT_MAC_NETWORK_ID_MS24_PREFIX; // From Kconfig
    if (net_id_ms24_part == 0x000000) net_id_ms24_part = 0x000001; // Ensure not all zeros

    uint8_t  net_id_ls8_part = (uint8_t)(ctx->own_long_rd_id & 0xFF);
    if (net_id_ls8_part == 0x00) net_id_ls8_part = 0x01; // Ensure not all zeros

    ctx->network_id_32bit = (net_id_ms24_part << 8) | net_id_ls8_part;

    LOG_INF("MAC Core Init: Role %s, LongID 0x%08X, ShortID 0x%04X, NetID 0x%08X",
            (role == MAC_ROLE_PT) ? "PT" : "FT",
            ctx->own_long_rd_id, ctx->own_short_rd_id, ctx->network_id_32bit);

    // Default MAC configurations
    ctx->config.rssi_threshold_min_dbm = CONFIG_DECT_MAC_RSSI_THR_MIN_DBM;
    ctx->config.rssi_threshold_max_dbm = CONFIG_DECT_MAC_RSSI_THR_MAX_DBM;
    ctx->config.rach_cw_min_idx = CONFIG_DECT_MAC_RACH_CW_MIN_IDX;
    ctx->config.rach_cw_max_idx = CONFIG_DECT_MAC_RACH_CW_MAX_IDX;
    ctx->config.rach_response_window_ms = CONFIG_DECT_MAC_RACH_RESP_WIN_MS;
    ctx->config.keep_alive_period_ms = CONFIG_DECT_MAC_KEEP_ALIVE_MS;
    ctx->config.mobility_scan_interval_ms = CONFIG_DECT_MAC_MOBILITY_SCAN_MS;
    ctx->config.ft_cluster_beacon_period_ms = CONFIG_DECT_MAC_FT_CLUSTER_BEACON_MS;
    ctx->config.ft_network_beacon_period_ms = CONFIG_DECT_MAC_FT_NETWORK_BEACON_MS;
    ctx->config.max_assoc_retries = MAX_RACH_ATTEMPTS_CONFIG;
    ctx->config.ft_policy_secure_on_assoc = IS_ENABLED(CONFIG_DECT_MAC_FT_SECURE_ON_ASSOC);
    ctx->config.default_tx_power_code = DEFAULT_TX_POWER_CODE; // From context.h default
    ctx->config.default_data_mcs_code = CONFIG_DECT_MAC_DEFAULT_DATA_MCS;

    // Placeholder PHY latencies (will be updated from PHY via dect_mac_phy_if.c)
    memset(&ctx->phy_latency, 0, sizeof(dect_phy_latency_values_t));

    // Initialize common RACH context and timers
    k_timer_init(&ctx->rach_context.rach_response_window_timer, rach_response_window_timer_expiry_fn, NULL);
    k_timer_init(&ctx->rach_context.rach_backoff_timer, rach_backoff_timer_expiry_fn, NULL);
    ctx->rach_context.rach_cw_current_idx = ctx->config.rach_cw_min_idx;

    // Initialize HARQ processes (done by data_path_init)
    dect_mac_data_path_init();

    // Initialize role-specific contexts and timers
    if (role == MAC_ROLE_PT) {
        memset(&ctx->role_ctx.pt, 0, sizeof(pt_context_t));
        k_timer_init(&ctx->role_ctx.pt.keep_alive_timer, pt_keep_alive_timer_expiry_fn, NULL);
        k_timer_init(&ctx->role_ctx.pt.mobility_scan_timer, pt_mobility_scan_timer_expiry_fn, NULL);
        // Initialize other PT specific fields if needed
    } else { // MAC_ROLE_FT
        memset(&ctx->role_ctx.ft, 0, sizeof(ft_context_t));
        k_timer_init(&ctx->role_ctx.ft.beacon_timer, ft_beacon_timer_expiry_fn, NULL);
        ctx->role_ctx.ft.operating_carrier = DEFAULT_DECT_CARRIER; // Initial, until DCS selects one

        // Populate FT's advertised RACH parameters from its config for beacons
        // These use codes/indices directly as per IE definitions, not calculated ms/slot values
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.cwmin_sig_code = ctx->config.rach_cw_min_idx;
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.cwmax_sig_code = ctx->config.rach_cw_max_idx;
        uint32_t resp_win_subslots = (ctx->config.rach_response_window_ms * MAX_SUBSLOTS_IN_FRAME_NOMINAL) / FRAME_DURATION_MS_NOMINAL;
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.response_window_subslots_val_minus_1 = (resp_win_subslots > 0) ? (resp_win_subslots - 1) : 4; /* Default if 0 */
        // Other advertised_rach_params fields (start_subslot_index, num_subslots_or_slots, repetition_code, validity_frames etc.)
        // should be set by FT scheduler/DCS logic before first beacon. Example defaults:
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.start_subslot_index = 10; // Example
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.num_subslots_or_slots = 4;   // Example: 4 subslots for RACH
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.repetition_code = 0;       // Example: Repeat every frame (code 0 for 1)
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.validity_frames = 200;     // Example: Valid for 200 frames (~2s)
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.sfn_validity_present = true;
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.channel_field_present = true; // Advertise RACH channel
        ctx->role_ctx.ft.advertised_rach_params.advertised_beacon_ie_fields.channel_abs_freq_num = ctx->role_ctx.ft.operating_carrier;


        for (int i = 0; i < MAX_PEERS_PER_FT; i++) {
            k_fifo_init(&ctx->role_ctx.ft.peer_tx_data_fifos[i].high_priority_fifo);
            k_fifo_init(&ctx->role_ctx.ft.peer_tx_data_fifos[i].reliable_data_fifo);
            k_fifo_init(&ctx->role_ctx.ft.peer_tx_data_fifos[i].best_effort_fifo);
            ctx->role_ctx.ft.keys_provisioned_for_peer[i] = false;
        }
    }

    // Initialize general MAC state
    ctx->state = MAC_STATE_IDLE;
    ctx->pending_op_type = PENDING_OP_NONE;
    ctx->pending_op_handle = 0;
    ctx->last_known_modem_time = 0;
    ctx->ft_sfn_zero_modem_time_anchor = 0;
    ctx->current_sfn_at_anchor_update = 0;


    // Initialize security context
    ctx->psn = sys_rand32_get() & 0x0FFF;
    ctx->hpc = 1; // HPC must not start at 0 if PSN can be 0 for IV.
    ctx->master_psk_provisioned = false; // Will be set if PSK loaded
    ctx->keys_provisioned = false;
    ctx->current_key_index = 0;
    ctx->send_mac_sec_info_ie_on_next_tx = false;

    // Example: Hardcode a PSK for demonstration. Replace with secure provisioning.
    const uint8_t example_psk[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    memcpy(ctx->master_psk, example_psk, sizeof(ctx->master_psk));
    ctx->master_psk_provisioned = true;


    LOG_INF("MAC Core Context Initialized. PSN=0x%03X, OwnHPC=%u", ctx->psn, ctx->hpc);
    return 0;
}