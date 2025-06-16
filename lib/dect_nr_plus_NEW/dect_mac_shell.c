/* dect_mac/dect_mac_shell.c */
#include <zephyr/shell/shell.h>
#include <stdlib.h> // For strtol, strtoul
#include <string.h> // For strlen, memcpy
#include <zephyr/sys/util.h> // For MIN, MAX, etc. if needed

#include "dect_mac_context.h"   // For dect_mac_context_t, MAX_PEERS_PER_FT, MAX_HARQ_PROCESSES
#include "dect_mac_core.h"      // For get_mac_context()
#include "dect_mac_sm.h"        // For dect_mac_state_t, dect_mac_role_t, pending_op_type_t
#include "dect_mac_api.h"       // For dect_mac_api_buffer_alloc, _free, _send, mac_sdu_t
#include "dect_mac_main_dispatcher.h" // For string conversion utilities
#include "dect_dlc.h"           // For dlc_send_data for testing app path

#if IS_ENABLED(CONFIG_DECT_MAC_SHELL_ENABLE) // Use a Kconfig option to enable/disable shell

LOG_MODULE_REGISTER(dect_mac_shell, CONFIG_DECT_MAC_SHELL_LOG_LEVEL);

// --- Command Implementations ---

static int cmd_force_state(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 2) {
        shell_error(sh, "Missing state argument. Usage: dect force_state <state_name_or_val>");
        shell_error(sh, "Valid states: DEACTIVATED IDLE PT_SCANNING PT_BEACON_PDC_WAIT PT_ASSOCIATING PT_RACH_BACKOFF PT_WAIT_ASSOC_RESP PT_AUTHENTICATING PT_PAGING FT_SCANNING FT_BEACONING FT_RACH_LISTEN ASSOCIATED");
        return -EINVAL;
    }

    dect_mac_context_t* ctx = get_mac_context();
    if (!ctx) {
        shell_error(sh, "MAC context not available.");
        return -EAGAIN;
    }

    dect_mac_state_t new_state = MAC_STATE_COUNT; // Invalid initial value
    char *endptr;
    long state_val_long = strtol(argv[1], &endptr, 10);

    if (*endptr == '\0') { // Successfully parsed as an integer
        if (state_val_long >= 0 && state_val_long < MAC_STATE_COUNT) {
            new_state = (dect_mac_state_t)state_val_long;
        }
    } else { // Try to parse as string
        // This is a bit manual; a more robust approach might use a lookup table or string array.
        if (strcmp(argv[1], "DEACTIVATED") == 0) new_state = MAC_STATE_DEACTIVATED;
        else if (strcmp(argv[1], "IDLE") == 0) new_state = MAC_STATE_IDLE;
        else if (strcmp(argv[1], "PT_SCANNING") == 0) new_state = MAC_STATE_PT_SCANNING;
        // ... add all other state strings ...
        else if (strcmp(argv[1], "ASSOCIATED") == 0) new_state = MAC_STATE_ASSOCIATED;
    }

    if (new_state == MAC_STATE_COUNT) { // Still invalid
        shell_error(sh, "Invalid state value/name: '%s'. Refer to help.", argv[1]);
        return -EINVAL;
    }

    shell_print(sh, "Forcing MAC state from %s (%d) to %s (%d)",
                dect_mac_state_to_str(ctx->state), ctx->state,
                dect_mac_state_to_str(new_state), new_state);
    // Directly setting state bypasses normal transition logic and actions, use with extreme caution.
    ctx->state = new_state;
    // Potentially trigger any entry actions for the new state if needed for testing,
    // or let the main loop pick it up.
    return 0;
}

static int cmd_get_context(const struct shell *sh, size_t argc, char **argv)
{
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    dect_mac_context_t* ctx = get_mac_context();
    if (!ctx) {
        shell_error(sh, "MAC context not available.");
        return -EAGAIN;
    }

    shell_print(sh, "--- DECT MAC CONTEXT ---");
    shell_print(sh, "Role: %s (%d)", (ctx->role == MAC_ROLE_PT ? "PT" : "FT"), ctx->role);
    shell_print(sh, "State: %s (%d)", dect_mac_state_to_str(ctx->state), ctx->state);
    shell_print(sh, "Own Long ID: 0x%08X, Short ID: 0x%04X, Network ID: 0x%08X",
                ctx->own_long_rd_id, ctx->own_short_rd_id, ctx->network_id_32bit);
    shell_print(sh, "Pending PHY Op Handle: %u, Type: %s (%d)",
                ctx->pending_op_handle, dect_pending_op_to_str(ctx->pending_op_type), ctx->pending_op_type);
    shell_print(sh, "MAC PSN: %u (0x%03X), MAC Own TX HPC: %u", ctx->psn, ctx->psn, ctx->hpc);
    shell_print(sh, "MasterPSK Prov: %s, SessionKeys Prov: %s, CurKeyIdx: %u, SendSecIE: %s",
                ctx->master_psk_provisioned ? "Yes" : "No",
                ctx->keys_provisioned ? "Yes" : "No", /* For PT's session keys */
                ctx->current_key_index,
                ctx->send_mac_sec_info_ie_on_next_tx ? "Yes" : "No");
    shell_print(sh, "Last Known Modem Time: %llu", ctx->last_known_modem_time);
    shell_print(sh, "SFN0 Anchor Time: %llu, SFN at Anchor Update: %u",
                ctx->ft_sfn_zero_modem_time_anchor, ctx->current_sfn_at_anchor_update);


    if (ctx->role == MAC_ROLE_PT) {
        shell_print(sh, "PT Context:");
        shell_print(sh, "  Target FT: Valid:%d Short:0x%04X Long:0x%08X Carr:%u RSSI2:%.1f Id'd:%d",
                    ctx->role_ctx.pt.target_ft.is_valid, ctx->role_ctx.pt.target_ft.short_rd_id,
                    ctx->role_ctx.pt.target_ft.long_rd_id, ctx->role_ctx.pt.target_ft.operating_carrier,
                    (float)ctx->role_ctx.pt.target_ft.rssi_2 / 2.0f, ctx->role_ctx.pt.target_ft.is_fully_identified);
        shell_print(sh, "  Assoc. FT: Valid:%d Short:0x%04X Long:0x%08X Carr:%u RSSI2:%.1f Sec:%d PeerHPC:%u",
                    ctx->role_ctx.pt.associated_ft.is_valid, ctx->role_ctx.pt.associated_ft.short_rd_id,
                    ctx->role_ctx.pt.associated_ft.long_rd_id, ctx->role_ctx.pt.associated_ft.operating_carrier,
                    (float)ctx->role_ctx.pt.associated_ft.rssi_2 / 2.0f, ctx->role_ctx.pt.associated_ft.is_secure,
                    ctx->role_ctx.pt.associated_ft.hpc);
        shell_print(sh, "  Assoc Retries: %u, RACH CW Idx: %u",
                    ctx->role_ctx.pt.current_assoc_retries, ctx->rach_context.rach_cw_current_idx);
        // TODO: Print PT UL/DL schedule info if active
    } else { // MAC_ROLE_FT
        shell_print(sh, "FT Context:");
        shell_print(sh, "  Op. Carrier: %u, SFN: %u (Last Beacon SFN: %u)",
                    ctx->role_ctx.ft.operating_carrier, ctx->role_ctx.ft.sfn, ctx->role_ctx.ft.sfn_for_last_beacon_tx);
        shell_print(sh, "  Connected PTs (%d max):", MAX_PEERS_PER_FT);
        for (int i=0; i < MAX_PEERS_PER_FT; i++) {
            if (ctx->role_ctx.ft.connected_pts[i].is_valid) {
                 shell_print(sh, "    - PT[%d]: Short:0x%04X Long:0x%08X Sec:%d PeerHPC:%u RSSI2:%.1f KeysProv:%d",
                             i, ctx->role_ctx.ft.connected_pts[i].short_rd_id,
                             ctx->role_ctx.ft.connected_pts[i].long_rd_id,
                             ctx->role_ctx.ft.connected_pts[i].is_secure,
                             ctx->role_ctx.ft.connected_pts[i].hpc,
                             (float)ctx->role_ctx.ft.connected_pts[i].rssi_2 / 2.0f,
                             ctx->role_ctx.ft.keys_provisioned_for_peer[i]);
                // TODO: Print schedule for this PT if active
            }
        }
    }

    shell_print(sh, "HARQ TX Processes (%d max):", MAX_HARQ_PROCESSES);
    for (int i = 0; i < MAX_HARQ_PROCESSES; i++) {
        if (ctx->harq_tx_processes[i].is_active) {
            shell_print(sh, "  Proc %d: Active, NeedsReTX:%d, RV:%u, Att:%u, SDU:%p, PSN:%u, HPC:%u, PeerSId:0x%04X, Carr:%u, StartT:%llu", i,
                ctx->harq_tx_processes[i].needs_retransmission, ctx->harq_tx_processes[i].redundancy_version,
                ctx->harq_tx_processes[i].tx_attempts, ctx->harq_tx_processes[i].sdu,
                ctx->harq_tx_processes[i].original_psn, ctx->harq_tx_processes[i].original_hpc,
                ctx->harq_tx_processes[i].peer_short_id_for_ft_dl,
                ctx->harq_tx_processes[i].scheduled_carrier, ctx->harq_tx_processes[i].scheduled_tx_start_time);
        }
    }
    shell_print(sh, "--- END OF CONTEXT ---");
    return 0;
}

static int cmd_disable_timers(const struct shell *sh, size_t argc, char **argv)
{
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    dect_mac_context_t* ctx = get_mac_context();
    if (!ctx) { shell_error(sh, "MAC context not available."); return -EAGAIN; }

    shell_print(sh, "Disabling MAC timers...");
    k_timer_stop(&ctx->rach_context.rach_backoff_timer);
    k_timer_stop(&ctx->rach_context.rach_response_window_timer);

    if (ctx->role == MAC_ROLE_PT) {
        k_timer_stop(&ctx->role_ctx.pt.keep_alive_timer);
        k_timer_stop(&ctx->role_ctx.pt.mobility_scan_timer);
        // k_timer_stop(&ctx->role_ctx.pt.paging_cycle_timer); // If implemented
    } else { // MAC_ROLE_FT
        k_timer_stop(&ctx->role_ctx.ft.beacon_timer);
        // TODO: Stop link supervision timers for each connected PT if they are implemented
    }
    for (int i=0; i < MAX_HARQ_PROCESSES; i++) {
        k_timer_stop(&ctx->harq_tx_processes[i].retransmission_timer);
    }
    shell_print(sh, "All MAC autonomous timers disabled (or attempted to disable).");
    return 0;
}

static int cmd_send_sdu(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 2) {
        shell_error(sh, "Missing data string. Usage: dect send_sdu <\"data string\"> [target_short_id_hex_for_ft]");
        return -EINVAL;
    }

    dect_mac_context_t *ctx = get_mac_context();
    if (!ctx) { shell_error(sh, "MAC context not available."); return -EAGAIN; }

    size_t payload_len = strlen(argv[1]);
    if (payload_len == 0) {
        shell_warn(sh, "Sending empty SDU payload.");
    }
    // Max check is tricky as DLC header size varies by service type.
    // DLC layer will do more precise checks.
    if (payload_len > (CONFIG_DECT_MAC_SDU_MAX_SIZE - 10 /* rough estimate for DLC header */)) {
        shell_error(sh, "Data string too long (%zu). Max approx %d for payload.",
                    payload_len, (int)(CONFIG_DECT_MAC_SDU_MAX_SIZE - 10));
        return -EINVAL;
    }

    int err;
    if (ctx->role == MAC_ROLE_FT) {
        if (argc < 3) {
            shell_error(sh, "FT role: Missing target_pt_short_id_hex. Usage: dect send_sdu <\"data\"> <target_short_id_hex>");
            return -EINVAL;
        }
        char *endptr;
        unsigned long target_id_ul = strtoul(argv[2], &endptr, 16);
        if (*endptr != '\0' || target_id_ul > UINT16_MAX || target_id_ul == 0) {
            shell_error(sh, "Invalid target_pt_short_id_hex: '%s'", argv[2]);
            return -EINVAL;
        }
        uint16_t target_pt_short_id = (uint16_t)target_id_ul;

        // For FT, we need to allocate the mac_sdu_t and then pass it to the FT-specific API
        mac_sdu_t *sdu = dect_mac_api_buffer_alloc(K_NO_WAIT);
        if (!sdu) {
            shell_error(sh, "FT Send: Failed to allocate SDU buffer.");
            return -ENOMEM;
        }
        memcpy(sdu->data, argv[1], payload_len); // This is actually DLC SDU payload
        sdu->len = payload_len;
        sdu->target_peer_short_rd_id = target_pt_short_id; // Set by FT API now

        // The FT will effectively be acting as an "application" here sending data via DLC to a PT.
        // So, it should also use dlc_send_data, which then uses dect_mac_api_ft_send_to_pt.
        // This requires dlc_send_data to be enhanced to take a target_id if sender is FT.
        // For now, bypass DLC and use MAC API directly for FT test send:
        LOG_INF("SHELL: FT sending directly via MAC API to PT 0x%04X.", target_pt_short_id);
        err = dect_mac_api_ft_send_to_pt(sdu, MAC_FLOW_RELIABLE_DATA, target_pt_short_id);
        // dect_mac_api_ft_send_to_pt takes ownership of sdu if successful

    } else { // PT role
        // PT uses DLC API, which uses generic MAC API.
        err = dlc_send_data(DLC_SERVICE_TYPE_0_TRANSPARENT,
                              (const uint8_t *)argv[1], payload_len);
    }


    if (err) {
        shell_error(sh, "Failed to send SDU, err: %d", err);
        // If err, and we allocated sdu (FT case), it was freed by API or needs freeing if API didn't take ownership on error.
        // dect_mac_api_ft_send_to_pt frees SDU on param error or if target not found.
        // If queueing to FIFO fails (ENOMEM), it might not free. Let's assume API handles freeing on error.
        return err;
    }

    shell_print(sh, "Queued SDU for transmission: '%s'", argv[1]);
    return 0;
}


// --- Shell Command Structure Definition ---

SHELL_STATIC_SUBCMD_SET_CREATE(sub_dect_cmds,
    SHELL_CMD(force_state, NULL, "Force MAC state <state_name_or_val_int>", cmd_force_state),
    SHELL_CMD(get_context, NULL, "Print the current MAC context", cmd_get_context),
    SHELL_CMD(disable_timers, NULL, "Disable all autonomous MAC timers", cmd_disable_timers),
    SHELL_CMD(send_sdu, NULL, "Queue an SDU for TX <\"payload\"> [target_pt_short_id_hex_if_ft]", cmd_send_sdu),
    SHELL_CMD(test_pcc, NULL, "Test PCC parameter calculation", cmd_test_pcc_params),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(dect, &sub_dect_cmds, "DECT MAC Debug/Test Commands", NULL);

#if IS_ENABLED(CONFIG_DECT_MAC_SHELL_ENABLE) // Or a specific Kconfig for this test

#include "dect_mac_phy_ctrl.h" // For the function to test

// Existing shell includes and LOG_MODULE_REGISTER if in dect_mac_shell.c

static int cmd_test_pcc_params(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 3) {
        shell_error(sh, "Usage: dect test_pcc <payload_bytes> <mcs_code> [mu] [beta]");
        shell_help(sh, "Calculates PCC params. mu, beta default to 1 if not given.");
        return -EINVAL;
    }

    char *endptr;
    long payload_bytes_long = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || payload_bytes_long < 0 || payload_bytes_long > 2000) { // Max PDC len approx 2000B for 16 subslots MCS0
        shell_error(sh, "Invalid payload_bytes: %s (must be 0-2000).", argv[1]);
        return -EINVAL;
    }
    size_t payload_bytes = (size_t)payload_bytes_long;

    long mcs_code_long = strtol(argv[2], &endptr, 10);
    if (*endptr != '\0' || mcs_code_long < 0 || mcs_code_long > MAX_MCS_INDEX_SUPPORTED_CTRL) {
        shell_error(sh, "Invalid mcs_code: %s (must be 0-%d).", argv[2], MAX_MCS_INDEX_SUPPORTED_CTRL);
        return -EINVAL;
    }
    uint8_t mcs_code = (uint8_t)mcs_code_long;
    uint8_t original_mcs_code = mcs_code; // To see if it gets modified

    uint8_t mu = 1;
    uint8_t beta = 1;

    if (argc > 3) {
        long mu_long = strtol(argv[3], &endptr, 10);
        if (*endptr != '\0' || mu_long <= 0 || mu_long > 8) { // Example valid mu range
            shell_error(sh, "Invalid mu: %s", argv[3]); return -EINVAL;
        }
        mu = (uint8_t)mu_long;
    }
    if (argc > 4) {
        long beta_long = strtol(argv[4], &endptr, 10);
         if (*endptr != '\0' || beta_long <= 0 || beta_long > 16) { // Example valid beta range
            shell_error(sh, "Invalid beta: %s", argv[4]); return -EINVAL;
        }
        beta = (uint8_t)beta_long;
    }

    uint8_t out_pkt_len_field, out_pkt_len_type;
    uint8_t mcs_after_calc = mcs_code; // Pass by value to see if it's changed

    shell_print(sh, "Testing PCC Calc: Payload: %zu B, MCS_in: %u, mu: %u, beta: %u",
                payload_bytes, original_mcs_code, mu, beta);

    dect_mac_phy_ctrl_calculate_pcc_params(payload_bytes, mu, beta,
                                           &out_pkt_len_field,
                                           &mcs_after_calc, // Pass address to allow modification
                                           &out_pkt_len_type);

    shell_print(sh, "Output: PacketLenField: %u (0x%02X) => %u units",
                out_pkt_len_field, out_pkt_len_field, out_pkt_len_field + 1);
    shell_print(sh, "        PacketLenType: %u (%s)",
                out_pkt_len_type, out_pkt_len_type == 0 ? "subslots" : "slots");
    shell_print(sh, "        MCS_final: %u (was %u)", mcs_after_calc, original_mcs_code);

    return 0;
}



#else /* IS_ENABLED(CONFIG_DECT_MAC_SHELL_ENABLE) */
// Provide a stub or log if shell is disabled but file is compiled
#if !defined(LOG_MODULE_NAME) // Simple check if logging is already set up
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(dect_mac_shell_stub, LOG_LEVEL_WRN);
#endif

void dect_mac_shell_disabled_log_if_needed(void) {
    // This function could be called from main if we want a log message
    // indicating that the shell is disabled.
    // For now, the #else block itself is empty if no specific action is needed.
    // LOG_WRN("DECT MAC Shell commands are disabled (CONFIG_DECT_MAC_SHELL_ENABLE=n).");
}

#endif /* CONFIG_DECT_MAC_SHELL_ENABLE */