/* dect_mac/dect_mac_data_path.c */
#include <zephyr/logging/log.h>
#include <string.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include "dect_mac_data_path.h"
#include "dect_mac_core.h"      // For get_mac_context(), increment_psn_and_hpc()
#include "dect_mac_context.h"   // For dect_mac_context_t access and constants
#include "dect_mac_phy_ctrl.h"  // For dect_mac_phy_ctrl_start_tx_assembled, _assemble_final_pdu, calculate_pcc_params
#include "dect_mac_pdu.h"       // For IE_TYPE_USER_DATA_FLOW_1, MAC Common Headers, MAC Hdr Type, parse_mac_mux_header
#include "dect_mac_main_dispatcher.h" // For string utils for logging, mac_event_msgq
#include "dect_mac_api.h"       // For dect_mac_api_buffer_free, mac_sdu_t, mac_tx_fifos (generic for PT), g_mac_sdu_slab
#include "dect_mac_security.h"  // For security_build_iv, _calculate_mic, _crypt_payload

LOG_MODULE_REGISTER(dect_mac_data_path, CONFIG_DECT_MAC_DATA_PATH_LOG_LEVEL);

// External FIFOs and slab (defined in dect_mac_api.c)
extern struct k_fifo * const mac_tx_fifos[]; // Generic TX FIFOs (used by PT for UL)
extern struct k_fifo *g_dlc_rx_sdu_fifo_ptr; // Pointer to DLC's RX FIFO
extern struct k_mem_slab g_mac_sdu_slab;     // For SDU buffers used by MAC API and internal PDU construction
extern struct k_msgq mac_event_msgq;         // For HARQ timer expiry events


// --- Helper Functions ---
static inline uint32_t modem_us_to_ticks(uint32_t us, uint32_t tick_rate_khz) {
    if (tick_rate_khz == 0) return 0;
    return (uint32_t)(((uint64_t)us * tick_rate_khz) / 1000U);
}

uint32_t get_subslot_duration_ticks(dect_mac_context_t *ctx) {
    // ETSI TS 103 636-3, section 4: 1 subslot = 5 OFDM symbols.
    // NRF_MODEM_DECT_SYMBOL_DURATION is duration of 1 symbol in modem ticks (defined in nrf_modem_dect_phy.h)
    // This should be mu-independent as subslot is defined in terms of OFDM symbols,
    // and NRF_MODEM_DECT_SYMBOL_DURATION should be for the base numerology symbol.
    // If NRF_MODEM_DECT_SYMBOL_DURATION changes with mu, this needs ctx->phy_caps.mu.
    // For now, assuming NRF_MODEM_DECT_SYMBOL_DURATION is fixed for the base.
    ARG_UNUSED(ctx); // ctx might be needed if mu affects symbol duration reporting by PHY lib.
    return NRF_MODEM_DECT_SYMBOL_DURATION * 5;
}

void update_next_occurrence(dect_mac_context_t *ctx, dect_mac_schedule_t *schedule, uint64_t current_modem_time) {
    if (!schedule->is_active) {
        return;
    }

    uint32_t subslot_duration_ticks = get_subslot_duration_ticks(ctx);
    uint32_t frame_duration_ticks = (uint32_t)MAX_SUBSLOTS_IN_FRAME_NOMINAL * subslot_duration_ticks;
    uint64_t repetition_period_ticks = 0;
    uint32_t scheduled_duration_subslots = 0;
    uint16_t current_schedule_start_subslot = 0;


    if (schedule->alloc_type == RES_ALLOC_TYPE_DOWNLINK ||
        (schedule->alloc_type == RES_ALLOC_TYPE_BIDIR && ctx->role == MAC_ROLE_FT)) {
        scheduled_duration_subslots = schedule->dl_duration_subslots;
        current_schedule_start_subslot = schedule->dl_start_subslot;
    } else if (schedule->alloc_type == RES_ALLOC_TYPE_UPLINK ||
               (schedule->alloc_type == RES_ALLOC_TYPE_BIDIR && ctx->role == MAC_ROLE_PT)) {
        scheduled_duration_subslots = schedule->ul_duration_subslots;
        current_schedule_start_subslot = schedule->ul_start_subslot;
    } else {
        LOG_ERR("SCHED_UPD: Invalid alloc_type %d in schedule for Ch %u, SS %u. Deactivating.",
                schedule->alloc_type, schedule->channel, current_schedule_start_subslot);
        schedule->is_active = false;
        return;
    }
    if (scheduled_duration_subslots == 0 && schedule->repeat_type != RES_ALLOC_REPEAT_SINGLE) {
        LOG_ERR("SCHED_UPD: Zero duration for repeating schedule (Ch %u, SS %u). Deactivating.",
                schedule->channel, current_schedule_start_subslot);
        schedule->is_active = false;
        return;
    }


    if (schedule->repeat_type == RES_ALLOC_REPEAT_SINGLE) {
        uint64_t single_occurrence_end_time = schedule->next_occurrence_modem_time + ((uint64_t)scheduled_duration_subslots * subslot_duration_ticks);
        if (single_occurrence_end_time < current_modem_time && schedule->next_occurrence_modem_time != 0) { // Check if already passed
            LOG_DBG("SCHED_UPD: Single occurrence schedule (Ch %u, SS %u @ %llu) has passed. Deactivating.",
                    schedule->channel, current_schedule_start_subslot, schedule->next_occurrence_modem_time);
            schedule->is_active = false;
        }
        return;
    }

    if (schedule->repetition_value == 0) {
        LOG_ERR("SCHED_UPD: Repetition value 0 is undefined for schedule (Ch %u, SS %u). Deactivating.",
                schedule->channel, current_schedule_start_subslot);
        schedule->is_active = false;
        return;
    }

    if (schedule->repeat_type == RES_ALLOC_REPEAT_FRAMES || schedule->repeat_type == RES_ALLOC_REPEAT_FRAMES_GROUP) {
        repetition_period_ticks = (uint64_t)schedule->repetition_value * frame_duration_ticks;
    } else if (schedule->repeat_type == RES_ALLOC_REPEAT_SUBSLOTS || schedule->repeat_type == RES_ALLOC_REPEAT_SUBSLOTS_GROUP) {
        repetition_period_ticks = (uint64_t)schedule->repetition_value * subslot_duration_ticks;
    } else {
        LOG_ERR("SCHED_UPD: Unknown repeat type %d for schedule (Ch %u, SS %u). Deactivating.",
                schedule->repeat_type, schedule->channel, current_schedule_start_subslot);
        schedule->is_active = false;
        return;
    }

    if (repetition_period_ticks == 0) { // Should be caught by repetition_value == 0
        schedule->is_active = false;
        return;
    }

    uint64_t current_slot_end_time_for_update = schedule->next_occurrence_modem_time +
                                                ((uint64_t)scheduled_duration_subslots * subslot_duration_ticks);

    if (schedule->next_occurrence_modem_time == 0 && schedule->schedule_init_modem_time != 0) {
         // This can happen if initial calculation was deferred or failed. Re-calculate based on init time.
         // This path needs robust initial calculation logic, for now, just log.
         LOG_WRN("SCHED_UPD: next_occurrence_modem_time is 0 for active repeating schedule. Init needed.");
         // For now, just advance from current_modem_time as a fallback.
         schedule->next_occurrence_modem_time = current_modem_time;
         current_slot_end_time_for_update = current_modem_time; // Recalculate based on this assumption
    }


    while (schedule->next_occurrence_modem_time < current_modem_time || current_slot_end_time_for_update <= current_modem_time) {
        schedule->next_occurrence_modem_time += repetition_period_ticks;
        current_slot_end_time_for_update = schedule->next_occurrence_modem_time +
                                           ((uint64_t)scheduled_duration_subslots * subslot_duration_ticks);
    }

    if (schedule->validity_value != 0xFF && schedule->sfn_of_initial_occurrence != 0xFF && ctx->ft_sfn_zero_modem_time_anchor != 0) {
        uint64_t ticks_from_sfn0_anchor = schedule->next_occurrence_modem_time - ctx->ft_sfn_zero_modem_time_anchor;
        if (schedule->next_occurrence_modem_time < ctx->ft_sfn_zero_modem_time_anchor) { // next_occurrence is before anchor (e.g. SFN wrap)
             ticks_from_sfn0_anchor = (UINT64_MAX - ctx->ft_sfn_zero_modem_time_anchor) + schedule->next_occurrence_modem_time + 1;
        }
        uint64_t frames_from_sfn0_anchor = ticks_from_sfn0_anchor / frame_duration_ticks;
        uint8_t sfn_of_next_occurrence = (uint8_t)(frames_from_sfn0_anchor % 256);

        int16_t frames_elapsed_since_initial = (int16_t)sfn_of_next_occurrence - (int16_t)schedule->sfn_of_initial_occurrence;
        if (frames_elapsed_since_initial < 0) {
            frames_elapsed_since_initial += 256;
        }

        if ((uint8_t)frames_elapsed_since_initial >= schedule->validity_value) {
            LOG_INF("SCHED_UPD: Schedule (Ch %u, SS %u) deactivated: validity expired. Init SFN %u, Next Occ SFN %u, Validity %u frames, Elapsed ~%d",
                    schedule->channel, current_schedule_start_subslot,
                    schedule->sfn_of_initial_occurrence, sfn_of_next_occurrence,
                    schedule->validity_value, frames_elapsed_since_initial);
            schedule->is_active = false;
            return;
        }
    }
    LOG_DBG("SCHED_UPD: Updated schedule (Ch %u, SS %u): next occurrence at %llu",
            schedule->channel, current_schedule_start_subslot, schedule->next_occurrence_modem_time);
}

// --- Initialization and HARQ Management Functions ---
void dect_mac_data_path_init(void) {
    dect_mac_context_t* ctx = get_mac_context();
    if (!ctx) {
        LOG_ERR("DATA_PATH_INIT: MAC Context is NULL. Cannot initialize HARQ.");
        return;
    }
    for (int i = 0; i < MAX_HARQ_PROCESSES; i++) {
        k_timer_init(&ctx->harq_tx_processes[i].retransmission_timer,
                     dect_mac_data_path_harq_timer_expired, NULL); // Expiry function
        // Store HARQ process index in timer's user_data for identification in callback
        ctx->harq_tx_processes[i].retransmission_timer.user_data = (void*)((uintptr_t)i);
        ctx->harq_tx_processes[i].is_active = false;
        ctx->harq_tx_processes[i].needs_retransmission = false;
        ctx->harq_tx_processes[i].sdu = NULL;
        ctx->harq_tx_processes[i].tx_attempts = 0;
        ctx->harq_tx_processes[i].redundancy_version = 0;
        ctx->harq_tx_processes[i].original_hpc = 0;
        ctx->harq_tx_processes[i].original_psn = 0;
        ctx->harq_tx_processes[i].peer_short_id_for_ft_dl = 0;
        ctx->harq_tx_processes[i].scheduled_carrier = 0;
        ctx->harq_tx_processes[i].scheduled_tx_start_time = 0;

    }
    LOG_INF("MAC Data Path Initialized (HARQ Timers and Processes set up).");
}

static int find_free_harq_tx_process(dect_mac_context_t* ctx) {
    if (!ctx) return -1;
    for (int i = 0; i < MAX_HARQ_PROCESSES; i++) {
        if (!ctx->harq_tx_processes[i].is_active) {
            return i;
        }
    }
    LOG_DBG("HARQ_ALLOC: No free HARQ TX processes available.");
    return -1; // No free process
}

void dect_mac_data_path_harq_timer_expired(struct k_timer *timer_id) {
    if (!timer_id) return;
    uintptr_t harq_idx_from_timer = (uintptr_t)timer_id->user_data;

    LOG_WRN("HARQ_TIMER: Timeout for HARQ process %u.", (unsigned int)harq_idx_from_timer);

    struct dect_mac_event_msg msg = {
        .type = MAC_EVENT_TIMER_EXPIRED_HARQ,
        // .modem_time_of_event = k_uptime_get(), // TODO: Use actual modem time if critical
        .data.timer_data.id = (int)harq_idx_from_timer
    };

    if (k_msgq_put(&mac_event_msgq, &msg, K_NO_WAIT) != 0) {
        LOG_ERR("HARQ_TIMER: Failed to queue HARQ expiry for proc %u, msgq full.", (unsigned int)harq_idx_from_timer);
        // Critical: If event queue is full, the NACK action might be missed.
        // As a fallback, directly call the NACK handler. This breaks the strict event flow
        // but prevents losing the timeout information. This should be rare.
        dect_mac_context_t* ctx = get_mac_context(); // Get context again for safety
        if (ctx && harq_idx_from_timer < MAX_HARQ_PROCESSES &&
            ctx->harq_tx_processes[harq_idx_from_timer].is_active) {
            LOG_WRN("HARQ_TIMER: Directly handling NACK for proc %u due to full event queue.", (unsigned int)harq_idx_from_timer);
            dect_mac_data_path_handle_harq_nack_action((int)harq_idx_from_timer);
        }
    }
}

void dect_mac_data_path_handle_harq_ack_action(int harq_process_idx) {
    dect_mac_context_t* ctx = get_mac_context();
    if (!ctx || harq_process_idx < 0 || harq_process_idx >= MAX_HARQ_PROCESSES) {
        LOG_ERR("HARQ_ACK: Invalid context or process_idx %d", harq_process_idx);
        return;
    }
    dect_harq_tx_process_t *harq_p = &ctx->harq_tx_processes[harq_process_idx];

    if (harq_p->is_active) {
        LOG_INF("HARQ_ACK: ACK received for HARQ process %d (PSN: %u, Attempts: %u).",
                harq_process_idx, harq_p->original_psn, harq_p->tx_attempts);
        k_timer_stop(&harq_p->retransmission_timer);
        if (harq_p->sdu) {
            dect_mac_api_buffer_free(harq_p->sdu); // Free the SDU buffer
            harq_p->sdu = NULL;
        }
        // Reset process for reuse
        harq_p->is_active = false;
        harq_p->needs_retransmission = false;
        harq_p->tx_attempts = 0;
        harq_p->redundancy_version = 0;
        harq_p->original_hpc = 0;
        harq_p->original_psn = 0;
        harq_p->peer_short_id_for_ft_dl = 0;
        harq_p->scheduled_carrier = 0;
        harq_p->scheduled_tx_start_time = 0;
    } else {
        LOG_WRN("HARQ_ACK: Received for already inactive HARQ process %d.", harq_process_idx);
    }
}

void dect_mac_data_path_handle_harq_nack_action(int harq_process_idx) {
    dect_mac_context_t* ctx = get_mac_context();
     if (!ctx || harq_process_idx < 0 || harq_process_idx >= MAX_HARQ_PROCESSES) {
        LOG_ERR("HARQ_NACK: Invalid context or process_idx %d", harq_process_idx);
        return;
    }
    dect_harq_tx_process_t *harq_p = &ctx->harq_tx_processes[harq_process_idx];

    if (harq_p->is_active) {
        k_timer_stop(&harq_p->retransmission_timer); // Stop current ACK timeout timer

        if (harq_p->tx_attempts >= MAX_HARQ_RETRIES) {
            LOG_ERR("HARQ_NACK: Max retries (%u) reached for HARQ process %d (PSN: %u). Discarding SDU.",
                    MAX_HARQ_RETRIES, harq_process_idx, harq_p->original_psn);
            if (harq_p->sdu) {
                dect_mac_api_buffer_free(harq_p->sdu);
                harq_p->sdu = NULL;
            }
            // Reset process for reuse
            harq_p->is_active = false;
            harq_p->needs_retransmission = false;
            harq_p->tx_attempts = 0;
            harq_p->redundancy_version = 0;
        } else {
            // tx_attempts is incremented in send_data_mac_sdu_via_phy_internal before the actual reTX
            LOG_WRN("HARQ_NACK: NACK or Timeout for HARQ process %d (PSN: %u, Current Attempts: %u). Scheduling re-TX.",
                    harq_process_idx, harq_p->original_psn, harq_p->tx_attempts);
            harq_p->needs_retransmission = true;

            // ETSI TS 103 636-4, Section 5.5.1: RV sequence {0, 2, 3, 1, 0, ...}
            // Current harq_p->redundancy_version holds the RV of the *last failed attempt*.
            // We set the RV for the *next* attempt here.
            switch (harq_p->redundancy_version) {
                case 0: harq_p->redundancy_version = 2; break;
                case 2: harq_p->redundancy_version = 3; break;
                case 3: harq_p->redundancy_version = 1; break;
                case 1: harq_p->redundancy_version = 0; // Cycle back to 0, or could be to 2 for shorter cycle if preferred
                        // If cycling back to 0 after RV1, it implies SDU is effectively "new" again for combiner
                        // Or, some implementations might stop after one full cycle {0,2,3,1}.
                        // For now, simple cycle.
                        break;
                default: // Should not happen if initialized to 0
                    LOG_ERR("HARQ_NACK: Invalid current RV %u for proc %d. Resetting to RV0 for next attempt.",
                            harq_p->redundancy_version, harq_process_idx);
                    harq_p->redundancy_version = 0;
                    break;
            }
            LOG_DBG("HARQ_NACK: Next RV for HARQ %d will be %u (after %u attempts).",
                    harq_process_idx, harq_p->redundancy_version, harq_p->tx_attempts);
            // The dect_mac_data_path_service_tx function will see needs_retransmission=true and pick it up.
        }
    } else {
        LOG_WRN("HARQ_NACK: Received for already inactive HARQ process %d.", harq_process_idx);
    }
}

void dect_mac_data_path_process_harq_feedback(const union nrf_modem_dect_phy_feedback *feedback,
                                              uint16_t peer_short_rd_id) {
    if (!feedback) {
        LOG_ERR("HARQ_FB_PROC: NULL feedback pointer.");
        return;
    }

    // The format code is in the same position for format1, format2, format3, format5, format6
    uint8_t format_code = (feedback->format1.format & 0x0F);

    LOG_DBG("HARQ_FB_PROC: Rcvd from Peer 0x%04X, PHY Feedback Format Code: %u", peer_short_rd_id, format_code);

    switch (format_code) {
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_1: // Single HARQ process feedback
        {
            int harq_idx = feedback->format1.harq_process_number0;
            if (harq_idx >= MAX_HARQ_PROCESSES) { LOG_ERR("HARQ_FB_FMT1: Invalid HARQ idx %d", harq_idx); return; }
            if (feedback->format1.transmission_feedback0 == 1) { // ACK
                dect_mac_data_path_handle_harq_ack_action(harq_idx);
            } else { // NACK
                dect_mac_data_path_handle_harq_nack_action(harq_idx);
            }
            break;
        }
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_3: // Dual HARQ process feedback
        {
            int harq_idx0 = feedback->format3.harq_process_number0;
            if (harq_idx0 >= MAX_HARQ_PROCESSES) { LOG_ERR("HARQ_FB_FMT3: Invalid HARQ idx0 %d", harq_idx0); /* continue to idx1? */ }
            else {
                if (feedback->format3.transmission_feedback0 == 1) {
                    dect_mac_data_path_handle_harq_ack_action(harq_idx0);
                } else {
                    dect_mac_data_path_handle_harq_nack_action(harq_idx0);
                }
            }

            int harq_idx1 = feedback->format3.harq_process_number1;
            if (harq_idx1 >= MAX_HARQ_PROCESSES) { LOG_ERR("HARQ_FB_FMT3: Invalid HARQ idx1 %d", harq_idx1); return; }
            else {
                if (feedback->format3.transmission_feedback1 == 1) {
                    dect_mac_data_path_handle_harq_ack_action(harq_idx1);
                } else {
                    dect_mac_data_path_handle_harq_nack_action(harq_idx1);
                }
            }
            break;
        }
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_6: // DF Redundancy Version reset requested
        {
            int harq_idx = feedback->format6.harq_process_number;
            if (harq_idx >= MAX_HARQ_PROCESSES) { LOG_ERR("HARQ_FB_FMT6: Invalid HARQ idx %d", harq_idx); return; }

            LOG_INF("HARQ_FB_FMT6: Peer 0x%04X requested RV0 reset for OUR HARQ process %d.", peer_short_rd_id, harq_idx);
            dect_mac_context_t* ctx = get_mac_context();
            if (ctx && ctx->harq_tx_processes[harq_idx].is_active) {
                ctx->harq_tx_processes[harq_idx].redundancy_version = 0;
                // Should this also increment tx_attempts? If peer couldn't decode even previous RVs.
                // For now, just set RV=0 and mark for reTX if not already.
                // If it was already NACKed, needs_retransmission is true. If ACKed, this is unusual.
                if (!ctx->harq_tx_processes[harq_idx].needs_retransmission) {
                    // This implies we thought it was ACKed, or it's a new SDU, but peer asks for RV0.
                    // This is more like a NACK if it was for an ongoing transmission.
                     LOG_WRN("HARQ_FB_FMT6: RV0 reset for HARQ proc %d which was not pending reTX. Marking for reTX.", harq_idx);
                    ctx->harq_tx_processes[harq_idx].needs_retransmission = true;
                }
                 // Restart timer, as peer effectively NACKed current state by asking for RV0.
                k_timer_stop(&ctx->harq_tx_processes[harq_idx].retransmission_timer);
                k_timer_start(&ctx->harq_tx_processes[harq_idx].retransmission_timer, K_MSEC(HARQ_ACK_TIMEOUT_MS), K_NO_WAIT);

            } else {
                 LOG_WRN("HARQ_FB_FMT6: RV0 reset for inactive HARQ proc %d.", harq_idx);
            }
            break;
        }
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_NONE: // Explicitly no feedback
            LOG_DBG("HARQ_FB_PROC: Received 'No Feedback' (Format 0).");
            break;
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_2: // MIMO / Codebook
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_4: // HARQ Bitmap
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_5: // MIMO / Codebook extended
        case NRF_MODEM_DECT_PHY_FEEDBACK_FORMAT_7: // CQI select
            LOG_WRN("HARQ_FB_PROC: Feedback format %u currently unhandled/not expected for basic HARQ ACK/NACK.", format_code);
            break;
        default: // Reserved or unknown formats
            LOG_ERR("HARQ_FB_PROC: Unknown feedback format code %u from 0x%04X", format_code, peer_short_rd_id);
            break;
    }
}

// --- TX Path ---
static int send_data_mac_sdu_via_phy_internal(dect_mac_context_t* ctx,
                                     mac_sdu_t *mac_sdu_dlc_pdu, /* Contains DLC PDU */
                                     int harq_proc_idx, bool is_retransmission,
                                     uint16_t tx_carrier_from_schedule,
                                     int ft_target_peer_slot_idx, // For FT role, index in connected_pts. -1 if PT role.
                                     uint64_t phy_op_target_start_time) // Absolute modem time for PHY op start
{
    uint8_t *full_mac_pdu_phy_buf_slab_alloc;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void**)&full_mac_pdu_phy_buf_slab_alloc, K_NO_WAIT);
    if (ret != 0) {
        LOG_ERR("DATA_TX_INT: Failed to alloc full MAC PDU TX buffer: %d", ret);
        // SDU buffer handling: if new TX, DLC still owns it. If reTX, HARQ process still owns it.
        // This function does not free mac_sdu_dlc_pdu on this type of error.
        return -ENOMEM;
    }
    uint8_t * const full_mac_pdu_for_phy = full_mac_pdu_phy_buf_slab_alloc;


    dect_mac_header_type_octet_t mac_hdr_type_octet;
    mac_hdr_type_octet.version = 0; // ETSI TS 103 636-4 Release 2
    mac_hdr_type_octet.mac_header_type = MAC_COMMON_HEADER_TYPE_UNICAST; // Default for data PDU with Long IDs

    bool security_active_for_this_pdu = false;
    bool include_mac_sec_info_ie = false;
    const uint8_t *session_integrity_key = NULL;
    const uint8_t *session_cipher_key = NULL;

    uint32_t receiver_long_id = 0;
    uint16_t receiver_short_id = 0xFFFF; // Invalid default

    if (ctx->role == MAC_ROLE_PT) {
        if (ctx->role_ctx.pt.associated_ft.is_valid) {
            receiver_long_id = ctx->role_ctx.pt.associated_ft.long_rd_id;
            receiver_short_id = ctx->role_ctx.pt.associated_ft.short_rd_id;
            if (ctx->role_ctx.pt.associated_ft.is_secure && ctx->keys_provisioned) {
                security_active_for_this_pdu = true;
                session_integrity_key = ctx->integrity_key;
                session_cipher_key = ctx->cipher_key;
            }
        } else {
            LOG_ERR("DATA_TX_INT: PT not associated, cannot determine target for data TX.");
            ret = -ENOTCONN;
            goto free_slab_and_return_error_tx_sec_path;
        }
    } else { // MAC_ROLE_FT
        if (ft_target_peer_slot_idx < 0 || ft_target_peer_slot_idx >= MAX_PEERS_PER_FT ||
            !ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].is_valid) {
            LOG_ERR("DATA_TX_INT: FT role, but invalid or inactive peer_slot_idx %d for TX.", ft_target_peer_slot_idx);
            ret = -EINVAL;
            goto free_slab_and_return_error_tx_sec_path;
        }
        receiver_long_id = ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].long_rd_id;
        receiver_short_id = ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].short_rd_id;
        if (ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].is_secure &&
            ctx->role_ctx.ft.keys_provisioned_for_peer[ft_target_peer_slot_idx]) {
            security_active_for_this_pdu = true;
            session_integrity_key = ctx->role_ctx.ft.peer_integrity_keys[ft_target_peer_slot_idx];
            session_cipher_key = ctx->role_ctx.ft.peer_cipher_keys[ft_target_peer_slot_idx];
        }
    }

    if (receiver_long_id == 0 || receiver_short_id == 0xFFFF) {
        LOG_ERR("DATA_TX_INT: Invalid receiver ID for data TX (L:0x%08X, S:0x%04X).", receiver_long_id, receiver_short_id);
        ret = -EINVAL;
        goto free_slab_and_return_error_tx_sec_path;
    }

    uint16_t psn_for_this_pdu;
    uint32_t hpc_for_tx_iv_build; // This is *our* TX HPC for building the IV

    if (!is_retransmission) {
        increment_psn_and_hpc(ctx); // This updates global ctx->psn and ctx->hpc
        psn_for_this_pdu = ctx->psn;
        hpc_for_tx_iv_build = ctx->hpc;
        if (security_active_for_this_pdu && ctx->send_mac_sec_info_ie_on_next_tx) {
            include_mac_sec_info_ie = true; // Send own HPC to peer
        }
    } else { // Retransmission
        if (harq_proc_idx < 0 || harq_proc_idx >= MAX_HARQ_PROCESSES || !ctx->harq_tx_processes[harq_proc_idx].is_active) {
            LOG_ERR("DATA_TX_INT: Invalid HARQ process %d for retransmission.", harq_proc_idx);
            ret = -EINVAL; goto free_slab_and_return_error_tx_sec_path;
        }
        psn_for_this_pdu = ctx->harq_tx_processes[harq_proc_idx].original_psn;
        hpc_for_tx_iv_build = ctx->harq_tx_processes[harq_proc_idx].original_hpc; // Use original HPC for IV consistency
        // include_mac_sec_info_ie = false; // Do NOT send MAC Sec Info IE on retransmissions
    }

// Determine if MAC Security Info IE needs to be included and the type of SecIV
    bool send_own_hpc_as_provided_due_to_peer_req_or_self_wrap = false;
    bool send_hpc_resync_initiate_to_peer = false;
    include_mac_sec_info_ie = false; // Default to false

    if (security_active_for_this_pdu && !is_retransmission) {
        dect_mac_peer_info_t *peer_context_for_tx = NULL;
        if (ctx->role == MAC_ROLE_PT) {
            if (ctx->role_ctx.pt.associated_ft.is_valid && ctx->role_ctx.pt.associated_ft.long_rd_id == receiver_long_id) {
                peer_context_for_tx = &ctx->role_ctx.pt.associated_ft;
            }
        } else if (ft_target_peer_slot_idx != -1) { // MAC_ROLE_FT
             if (ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].is_valid &&
                 ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].long_rd_id == receiver_long_id) {
                peer_context_for_tx = &ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx];
            }
        }

        if (peer_context_for_tx) {
            // Case 1: We need to request peer's HPC (due to our MIC failures from them)
            if (peer_context_for_tx->self_needs_to_request_hpc_from_peer) {
                send_hpc_resync_initiate_to_peer = true;
                include_mac_sec_info_ie = true;
                // Flag is cleared *after* successful TX of this PDU (in op_complete or similar)
                // For now, let's clear it here optimistically. If TX fails, it might get set again.
                // Better: clear it only if this SecIE with INITIATE is actually sent and PHY op is OK.
                // For simplicity now, clear it here.
                // peer_context_for_tx->self_needs_to_request_hpc_from_peer = false; // Moved to after successful send
            }
            // Case 2: Peer requested our HPC, or our own HPC wrapped
            if (peer_context_for_tx->peer_requested_hpc_resync || ctx->send_mac_sec_info_ie_on_next_tx) {
                send_own_hpc_as_provided_due_to_peer_req_or_self_wrap = true;
                include_mac_sec_info_ie = true;
                // Flags cleared after deciding to send
                // peer_context_for_tx->peer_requested_hpc_resync = false; // Moved to after successful send
                // ctx->send_mac_sec_info_ie_on_next_tx = false; // Moved to after successful send
            }
        } else if (ctx->send_mac_sec_info_ie_on_next_tx) { // Global flag for own HPC wrap, even if peer_context not found (e.g. AssocResp)
            send_own_hpc_as_provided_due_to_peer_req_or_self_wrap = true;
            include_mac_sec_info_ie = true;
            // ctx->send_mac_sec_info_ie_on_next_tx = false; // Moved
        }
    }
    // Retransmissions never include MAC Sec Info IE for these purposes
    if (is_retransmission) {
        include_mac_sec_info_ie = false;
    }


    if (security_active_for_this_pdu) {
        mac_hdr_type_octet.mac_security = include_mac_sec_info_ie ? MAC_SECURITY_USED_WITH_IE : MAC_SECURITY_USED_NO_IE;
    } else {
        mac_hdr_type_octet.mac_security = MAC_SECURITY_NONE;
    }

    dect_mac_unicast_header_t common_hdr;
    common_hdr.sequence_num_high_reset_rsv = SET_SEQ_NUM_HIGH_RESET_RSV((psn_for_this_pdu >> 8) & 0x0F, !is_retransmission /*reset bit*/);
    common_hdr.sequence_num_low = psn_for_this_pdu & 0xFF;
    common_hdr.transmitter_long_rd_id_be = sys_cpu_to_be32(ctx->own_long_rd_id);
    common_hdr.receiver_long_rd_id_be = sys_cpu_to_be32(receiver_long_id);

    // SDU Area: [Optional MUXed MAC Sec Info IE] + MUXed User Data IE (containing DLC PDU)
    uint8_t sdu_area_buf[CONFIG_DECT_MAC_SDU_MAX_SIZE + 10]; 
    size_t current_sdu_area_len = 0;
    int ie_len;
    // This was len_of_muxed_sec_ie_for_crypto, renaming for clarity on what it holds
    size_t muxed_sec_ie_actual_len_in_sdu_area = 0;

    if (security_active_for_this_pdu && include_mac_sec_info_ie) {
        uint8_t sec_iv_type_for_ie = SEC_IV_TYPE_MODE1_HPC_PROVIDED; // Default
        if (send_hpc_resync_initiate_to_peer) {
            sec_iv_type_for_ie = SEC_IV_TYPE_MODE1_HPC_RESYNC_INITIATE;
            LOG_INF("DATA_TX_INT: Will send MAC Sec Info IE with HPC Resync Request (type %u) to peer 0x%04X.",
                    sec_iv_type_for_ie, receiver_short_id);
        } else if (send_own_hpc_as_provided_due_to_peer_req_or_self_wrap) {
            LOG_INF("DATA_TX_INT: Will send MAC Sec Info IE with own HPC as Provided (type %u) to peer 0x%04X.",
                    sec_iv_type_for_ie, receiver_short_id);
        }
        // Else: include_mac_sec_info_ie was true due to ctx->send_mac_sec_info_ie_on_next_tx (global HPC wrap),
        // which defaults to SEC_IV_TYPE_MODE1_HPC_PROVIDED.

        ie_len = build_mac_security_info_ie_muxed(
            sdu_area_buf, sizeof(sdu_area_buf),
            0, ctx->current_key_index,
            sec_iv_type_for_ie,
            ctx->hpc); // Always send our current TX HPC in this IE's HPC field
        if (ie_len < 0) { ret = ie_len; LOG_ERR("DATA_TX_INT: Build SecInfoIE failed: %d", ret); goto free_slab_and_return_error_tx_sec_path; }
        current_sdu_area_len += ie_len;
        muxed_sec_ie_actual_len_in_sdu_area = ie_len;
    }

    uint16_t assembled_pdu_len_pre_mic;
    ret = dect_mac_phy_ctrl_assemble_final_pdu(
              full_mac_pdu_for_phy, CONFIG_DECT_MAC_PDU_MAX_SIZE,
              &mac_hdr_type_octet,
              &common_hdr, sizeof(common_hdr),
              sdu_area_buf, current_sdu_area_len,
              &assembled_pdu_len_pre_mic);
    if (ret != 0) { LOG_ERR("DATA_TX_INT: Assemble final PDU failed: %d", ret); goto free_slab_and_return_error_tx_sec_path; }

    uint16_t final_tx_pdu_len_for_phy_ctrl = assembled_pdu_len_pre_mic;

    if (security_active_for_this_pdu) {
        uint8_t iv[16];
        security_build_iv(iv, ctx->own_long_rd_id, receiver_long_id, hpc_for_tx_iv_build, psn_for_this_pdu);

        // MIC calculation: Over (Common Header + Full SDU Area [including MUXed SecIE if present])
        uint8_t *mic_calc_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t);
        size_t mic_calc_len = sizeof(common_hdr) + current_sdu_area_len;

        if (assembled_pdu_len_pre_mic + 5 > CONFIG_DECT_MAC_PDU_MAX_SIZE) {
            ret = -ENOMEM; LOG_ERR("DATA_TX_INT: No space for MIC in PDU."); goto free_slab_and_return_error_tx_sec_path;
        }
        uint8_t *mic_location_ptr = full_mac_pdu_for_phy + assembled_pdu_len_pre_mic;
        ret = security_calculate_mic(mic_calc_start_ptr, mic_calc_len, session_integrity_key, mic_location_ptr);
        if (ret != 0) { LOG_ERR("DATA_TX_INT: MIC calculation failed: %d", ret); goto free_slab_and_return_error_tx_sec_path; }

        // Encryption (aligned with ETSI Figure 6.3.1-1)
        uint8_t *encrypt_start_ptr;
        size_t encrypt_len;
        size_t common_hdr_actual_len = sizeof(common_hdr); // common_hdr is dect_mac_unicast_header_t

        if (mac_hdr_type_octet.mac_security == MAC_SECURITY_USED_WITH_IE) {
            // If SecIE is present, Common Header AND MUXed SecIE are cleartext.
            // Encryption starts AFTER the MUXed MAC Security Info IE.
            // muxed_sec_ie_actual_len_in_sdu_area is the length of (MUX_hdr_for_SecIE + SecIE_payload).
            encrypt_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                common_hdr_actual_len + muxed_sec_ie_actual_len_in_sdu_area;
            // Encrypt (Rest of SDU Area (e.g., MUXed User Data) + MIC)
            encrypt_len = (current_sdu_area_len - muxed_sec_ie_actual_len_in_sdu_area) + 5;
        } else { // MAC_SECURITY_USED_NO_IE (or MAC_SECURITY_NONE, though `security_active_for_this_pdu` catches NONE)
            // Common Header is cleartext.
            // Encryption starts AFTER the MAC Common Header.
            encrypt_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                common_hdr_actual_len;
            // Encrypt (Full SDU Area (e.g., MUXed User Data) + MIC)
            encrypt_len = current_sdu_area_len + 5;
        }

        if (encrypt_len > 0) { // Only encrypt if there's something to encrypt (at least MIC)
            if ((encrypt_start_ptr + encrypt_len) > (full_mac_pdu_for_phy + assembled_pdu_len_pre_mic + 5) ||
                 encrypt_start_ptr < full_mac_pdu_for_phy) { // Basic boundary check
                 LOG_ERR("DATA_TX_INT: Encryption range error. Start %p, Len %zu. PDU End %p",
                         encrypt_start_ptr, encrypt_len, full_mac_pdu_for_phy + assembled_pdu_len_pre_mic + 5);
                 ret = -EINVAL; goto free_slab_and_return_error_tx_sec_path;
            }
            ret = security_crypt_payload(encrypt_start_ptr, encrypt_len, session_cipher_key, iv, true /*encrypt*/);
            if (ret != 0) { LOG_ERR("DATA_TX_INT: Encryption failed: %d", ret); goto free_slab_and_return_error_tx_sec_path; }
        }
        final_tx_pdu_len_for_phy_ctrl = assembled_pdu_len_pre_mic + 5; // Total length including MIC
        // Encryption:
        uint8_t *encrypt_start_ptr;
        size_t encrypt_len;
        size_t common_hdr_actual_len = sizeof(common_hdr); // Assuming common_hdr is dect_mac_unicast_header_t

        if (include_mac_sec_info_ie) { // MAC_SECURITY_USED_WITH_IE was set
            // Common Header and MUXed MAC Sec Info IE are cleartext.
            // Encrypt (Rest of SDU Area (e.g. MUXed User Data IE) + MIC).
            encrypt_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                common_hdr_actual_len + muxed_sec_ie_actual_len_in_sdu_area; // After SecIE
            encrypt_len = (current_sdu_area_len - muxed_sec_ie_actual_len_in_sdu_area) + 5; // (Rest of SDU Area + MIC)
        } else { // MAC_SECURITY_USED_NO_IE
            // Common Header is cleartext.
            // Encrypt (SDU Area (which is MUXed UserData IE(s)) + MIC)
            encrypt_start_ptr = full_mac_pdu_for_phy + sizeof(dect_mac_header_type_octet_t) +
                                common_hdr_actual_len; // Start encryption *after* the Common Header
            encrypt_len = current_sdu_area_len + 5;    // (Full SDU Area + MIC)
        }

        if (encrypt_len > 0) {
            // Boundary check for encryption
            uint8_t* pdu_buffer_end = full_mac_pdu_for_phy + final_tx_pdu_len_for_phy_ctrl; // End of PDU including MIC
            if (encrypt_start_ptr < full_mac_pdu_for_phy || (encrypt_start_ptr + encrypt_len) > pdu_buffer_end) {
                 LOG_ERR("DATA_TX_INT: Encryption range error. Start %p, Len %zu. PDU Range %p - %p",
                         encrypt_start_ptr, encrypt_len, full_mac_pdu_for_phy, pdu_buffer_end);
                 ret = -EINVAL; goto free_slab_and_return_error_tx_sec_path;
            }
            ret = security_crypt_payload(encrypt_start_ptr, encrypt_len, session_cipher_key, iv, true /*encrypt*/);
            if (ret != 0) { LOG_ERR("DATA_TX_INT: Encryption failed: %d", ret); goto free_slab_and_return_error_tx_sec_path; }
        }        
        LOG_DBG("DATA_TX_INT: Secured PDU. Final len %u. Mode: %s",
                final_tx_pdu_len_for_phy_ctrl, include_mac_sec_info_ie ? "WITH_SEC_IE" : "NO_SEC_IE");
    }


    pending_op_type_t op_type_for_phy = (ctx->role == MAC_ROLE_PT) ? PENDING_OP_PT_DATA_TX_HARQ0 : PENDING_OP_FT_DATA_TX_HARQ0;
    op_type_for_phy = (pending_op_type_t)((int)op_type_for_phy + harq_proc_idx);
    uint32_t phy_op_handle = sys_rand32_get(); // Generate a unique handle for this PHY operation instance

    // Pass the full MAC PDU (including MAC Hdr Type octet) and its total length to phy_ctrl
    ret = dect_mac_phy_ctrl_start_tx_assembled(
        tx_carrier_from_schedule,
        full_mac_pdu_for_phy,
        final_tx_pdu_len_for_phy_ctrl,
        receiver_short_id,
        false, /* is_beacon = false for data PDUs */
        phy_op_handle,
        op_type_for_phy,
        true, /* use_lbt = true for data (assuming shared channel access model) */
        phy_op_target_start_time
    );

free_slab_and_return_error_tx_sec_path:
    k_mem_slab_free(&g_mac_sdu_slab, (void**)&full_mac_pdu_phy_buf_slab_alloc);

    if (ret == 0) { // PHY TX successfully scheduled by phy_ctrl
        dect_harq_tx_process_t *harq_p = &ctx->harq_tx_processes[harq_proc_idx];
        if (!is_retransmission) {
            harq_p->sdu = mac_sdu_dlc_pdu; // MAC's HARQ process takes ownership of the SDU buffer
            harq_p->is_active = true;
            harq_p->original_psn = psn_for_this_pdu;
            harq_p->original_hpc = hpc_for_tx_iv_build;
            harq_p->tx_attempts = 1;
            harq_p->redundancy_version = 0; // Initial transmission is RV0
            harq_p->scheduled_carrier = tx_carrier_from_schedule;
            harq_p->scheduled_tx_start_time = phy_op_target_start_time;
            harq_p->peer_short_id_for_ft_dl = receiver_short_id; // Store target for reTX context
        } else { // This was a retransmission attempt
            harq_p->tx_attempts++;
            // RV was already updated by _harq_nack_action
        }
        harq_p->needs_retransmission = false; // Cleared as we are attempting to transmit now
        k_timer_start(&harq_p->retransmission_timer, K_MSEC(HARQ_ACK_TIMEOUT_MS), K_NO_WAIT);

        
        // --- Clear HPC Sync Flags after successful scheduling of PDU containing the SecIE ---
        // This logic should only execute if a MAC Security Info IE was *actually included* in this transmission
        // which is governed by the 'include_mac_sec_info_ie' variable determined earlier in this function.
        if (include_mac_sec_info_ie && security_active_for_this_pdu && !is_retransmission) {
            dect_mac_peer_info_t *peer_context_for_tx_flags = NULL;
            if (ctx->role == MAC_ROLE_PT) {
                // Ensure we are clearing flags for the correct associated FT
                if (ctx->role_ctx.pt.associated_ft.is_valid &&
                    ctx->role_ctx.pt.associated_ft.long_rd_id == receiver_long_id) {
                    peer_context_for_tx_flags = &ctx->role_ctx.pt.associated_ft;
                }
            } else if (ft_target_peer_slot_idx != -1) { // MAC_ROLE_FT
                // Ensure we are clearing flags for the correct connected PT
                 if (ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].is_valid &&
                     ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx].long_rd_id == receiver_long_id) {
                    peer_context_for_tx_flags = &ctx->role_ctx.ft.connected_pts[ft_target_peer_slot_idx];
                }
            }

            if (peer_context_for_tx_flags) {
                // If we just sent an INITIATE request for peer's HPC
                if (send_hpc_resync_initiate_to_peer) {
                    LOG_DBG("DATA_TX_INT: Cleared self_needs_to_request_hpc_from_peer for peer 0x%04X after sending INITIATE.",
                            receiver_short_id);
                    peer_context_for_tx_flags->self_needs_to_request_hpc_from_peer = false;
                }
                // If we just sent our HPC as PROVIDED because peer requested it
                if (send_own_hpc_as_provided_due_to_peer_req_or_self_wrap &&
                    peer_context_for_tx_flags->peer_requested_hpc_resync) {
                    LOG_DBG("DATA_TX_INT: Cleared peer_requested_hpc_resync for peer 0x%04X after sending PROVIDED.",
                            receiver_short_id);
                    peer_context_for_tx_flags->peer_requested_hpc_resync = false;
                }
            }
            // If we just sent our HPC as PROVIDED due to our own HPC wrapping (global flag)
            if (send_own_hpc_as_provided_due_to_peer_req_or_self_wrap && ctx->send_mac_sec_info_ie_on_next_tx) {
                // This clears the global flag if the SecIE was sent *primarily* due to this global flag.
                // (i.e., not because we were sending INITIATE or responding to peer's INITIATE specifically)
                if (!send_hpc_resync_initiate_to_peer &&
                    !(peer_context_for_tx_flags && peer_context_for_tx_flags->peer_requested_hpc_resync) ) {
                    LOG_DBG("DATA_TX_INT: Cleared global send_mac_sec_info_ie_on_next_tx after sending PROVIDED due to own HPC wrap.");
                    ctx->send_mac_sec_info_ie_on_next_tx = false;
                }
            }
        }
    } else { // Failed to schedule PHY TX via phy_ctrl
        LOG_ERR("DATA_TX_INT: PHY TX schedule failed for HARQ %d (err %d).", harq_proc_idx, ret);
        if (!is_retransmission) {
            // New SDU failed to schedule, DLC/App still owns it. It must be freed by caller or re-queued by caller.
            // This function was given ownership (conceptually) when called. So, free it.
            LOG_ERR("DATA_TX_INT: Freeing new SDU (len %u) due to PHY TX schedule failure for HARQ %d.",
                    mac_sdu_dlc_pdu->len, harq_proc_idx);
            dect_mac_api_buffer_free(mac_sdu_dlc_pdu); // Free the SDU if it was new and couldn't be sent
        } else {
            // If retransmission failed to schedule, mark it for retransmission again.
            // The HARQ timer should not be running (or was stopped by NACK handler).
            // It will be picked up again by service_tx.
            ctx->harq_tx_processes[harq_proc_idx].needs_retransmission = true;
        }
    }
    return ret;
}

void dect_mac_data_path_service_tx(void)
{
    dect_mac_context_t *ctx = get_mac_context();
    if (ctx->state < MAC_STATE_ASSOCIATED) {
        // Only service TX for data when in a connected state
        return;
    }

    uint64_t current_modem_time = ctx->last_known_modem_time;
    if (current_modem_time == 0) {
        LOG_WRN("DATA_PATH_SVC_TX: Modem time not yet known. Deferring TX service.");
        return;
    }

    if (ctx->pending_op_type != PENDING_OP_NONE) {
        // A PHY operation is already in flight. We cannot schedule another one.
        // Let the current operation complete.
        LOG_DBG("DATA_PATH_SVC_TX: PHY op %s pending, deferring TX service.",
                dect_pending_op_to_str(ctx->pending_op_type));
        return;
    }

    // --- 1. Prioritize HARQ Retransmissions ---
    for (int i = 0; i < MAX_HARQ_PROCESSES; i++) {
        dect_harq_tx_process_t *harq_p = &ctx->harq_tx_processes[i];
        if (harq_p->is_active && harq_p->needs_retransmission) {
            // This HARQ process needs a re-TX. We need to find its *next* available slot.
            // For simplicity, we assume retransmissions use the same schedule as original transmissions.
            // A more advanced system might have a separate contention-based re-TX schedule.
            dect_mac_schedule_t *schedule = NULL;
            int peer_idx = -1;

            if (ctx->role == MAC_ROLE_PT) {
                schedule = &ctx->role_ctx.pt.ul_schedule;
            } else { // FT Role
                peer_idx = ft_get_peer_slot_idx(ctx, harq_p->peer_short_id_for_ft_dl);
                if (peer_idx != -1) {
                    schedule = &ctx->role_ctx.ft.peer_schedules[peer_idx];
                }
            }

            if (schedule && schedule->is_active) {
                update_next_occurrence(ctx, schedule, current_modem_time);
                uint64_t target_start_time = schedule->next_occurrence_modem_time;
                uint32_t phy_prep_latency_ticks = modem_us_to_ticks(ctx->phy_latency.idle_to_active_tx_us +
                                                                  ctx->phy_latency.scheduled_operation_startup_us,
                                                                  NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);

                if (target_start_time > current_modem_time + phy_prep_latency_ticks) {
                    LOG_INF("DATA_PATH_SVC_TX: Scheduling HARQ re-TX proc %d for next slot at %llu.",
                            i, target_start_time);

                    int ret = send_data_mac_sdu_via_phy_internal(ctx, harq_p->sdu, i, true,
                                                                 schedule->channel, peer_idx,
                                                                 target_start_time);
                    if (ret == 0) {
                        // Mark schedule as used for this cycle by updating to the next occurrence
                        update_next_occurrence(ctx, schedule, target_start_time);
                        return; // One operation scheduled per service call
                    }
                }
            }
        }
    }

    // --- 2. Service New SDUs from TX Queues if no HARQ re-TX was scheduled ---
    int free_harq_idx = find_free_harq_tx_process(ctx);
    if (free_harq_idx == -1) {
        LOG_DBG("DATA_PATH_SVC_TX: No free HARQ TX processes for new SDU.");
        return;
    }

    if (ctx->role == MAC_ROLE_PT) {
        // PT has one uplink schedule and a set of generic FIFOs
        dect_mac_schedule_t *ul_schedule = &ctx->role_ctx.pt.ul_schedule;
        if (ul_schedule->is_active) {
            update_next_occurrence(ctx, ul_schedule, current_modem_time);
            uint64_t target_start_time = ul_schedule->next_occurrence_modem_time;
            uint32_t phy_prep_latency_ticks = modem_us_to_ticks(ctx->phy_latency.idle_to_active_tx_us +
                                                              ctx->phy_latency.scheduled_operation_startup_us,
                                                              NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);

            if (target_start_time > current_modem_time + phy_prep_latency_ticks) {
                // We have a valid future slot. Check if there's data to send.
                for (int flow_idx = 0; flow_idx < MAC_FLOW_COUNT; flow_idx++) {
                    mac_sdu_t *sdu = k_fifo_get(mac_tx_fifos[flow_idx], K_NO_WAIT);
                    if (sdu) {
                        // TODO: PDU Fit Check - ensure this SDU fits in the scheduled slot duration.
                        int ret = send_data_mac_sdu_via_phy_internal(ctx, sdu, free_harq_idx, false,
                                                                     ul_schedule->channel, -1,
                                                                     target_start_time);
                        if (ret == 0) {
                            update_next_occurrence(ctx, ul_schedule, target_start_time);
                        } else {
                            k_fifo_put_first(mac_tx_fifos[flow_idx], sdu); // Re-queue at the front
                        }
                        return; // One attempt per service call
                    }
                }
            }
        }
    } else { // FT Role - iterate through connected PTs
        for (int i = 0; i < MAX_PEERS_PER_FT; i++) {
            if (ctx->role_ctx.ft.connected_pts[i].is_valid && ctx->role_ctx.ft.peer_schedules[i].is_active) {
                dect_mac_schedule_t *dl_schedule = &ctx->role_ctx.ft.peer_schedules[i];
                update_next_occurrence(ctx, dl_schedule, current_modem_time);
                uint64_t target_start_time = dl_schedule->next_occurrence_modem_time;
                uint32_t phy_prep_latency_ticks = modem_us_to_ticks(ctx->phy_latency.idle_to_active_tx_us +
                                                                  ctx->phy_latency.scheduled_operation_startup_us,
                                                                  NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);

                if (target_start_time > current_modem_time + phy_prep_latency_ticks) {
                    // This peer has a valid future slot. Check its FIFOs.
                    dect_mac_peer_tx_fifo_set_t *fifos = &ctx->role_ctx.ft.peer_tx_data_fifos[i];
                    mac_sdu_t *sdu = NULL;
                    sdu = k_fifo_get(&fifos->high_priority_fifo, K_NO_WAIT);
                    if (!sdu) sdu = k_fifo_get(&fifos->reliable_data_fifo, K_NO_WAIT);
                    if (!sdu) sdu = k_fifo_get(&fifos->best_effort_fifo, K_NO_WAIT);

                    if (sdu) {
                        // TODO: PDU Fit Check
                        int ret = send_data_mac_sdu_via_phy_internal(ctx, sdu, free_harq_idx, false,
                                                                     dl_schedule->channel, i,
                                                                     target_start_time);
                        if (ret == 0) {
                            update_next_occurrence(ctx, dl_schedule, target_start_time);
                        } else {
                            k_fifo_put_first(&fifos->high_priority_fifo, sdu); // Re-queue to HP for simplicity
                        }
                        return; // One attempt per service call
                    }
                }
            }
        }
    }
}



void dect_mac_data_path_handle_rx_sdu(const uint8_t *mac_sdu_area_data,
                                      size_t mac_sdu_area_len,
                                      uint32_t transmitter_long_rd_id)
{
    // ... (Full implementation from Phase 4 "SFN Anchoring..." step) ...
    uint8_t ie_type;
    uint16_t dlc_pdu_len_from_mux;
    const uint8_t *dlc_pdu_ptr_from_mux;
    int mux_hdr_len = parse_mac_mux_header(mac_sdu_area_data, mac_sdu_area_len,
                                          &ie_type, &dlc_pdu_len_from_mux, &dlc_pdu_ptr_from_mux);

    if (mux_hdr_len < 0) {
        LOG_ERR("RX_SDU: Failed to parse MAC MUX header: %d", mux_hdr_len);
        return;
    }
    if (dlc_pdu_len_from_mux == 0 && ((mac_sdu_area_data[0] >> 6) & 0x03) == 0b00) {
         if (mac_sdu_area_len < (size_t)mux_hdr_len) { LOG_ERR("RX_SDU: Invalid length for MAC_Ext=00"); return; }
        dlc_pdu_len_from_mux = mac_sdu_area_len - mux_hdr_len;
    }
    if (mac_sdu_area_len < (size_t)mux_hdr_len + dlc_pdu_len_from_mux) {
        LOG_ERR("RX_SDU: Declared MUX payload len %u exceeds actual remaining len %zu.",
                dlc_pdu_len_from_mux, mac_sdu_area_len - mux_hdr_len);
        return;
    }

    if (ie_type >= IE_TYPE_USER_DATA_FLOW_1 && ie_type <= IE_TYPE_USER_DATA_FLOW_4) { // Example check for user data
        if (g_dlc_rx_sdu_fifo_ptr != NULL) {
            mac_sdu_t *sdu_for_dlc = dect_mac_api_buffer_alloc(K_NO_WAIT);
            if (sdu_for_dlc) {
                if (dlc_pdu_len_from_mux <= CONFIG_DECT_MAC_SDU_MAX_SIZE) {
                    memcpy(sdu_for_dlc->data, dlc_pdu_ptr_from_mux, dlc_pdu_len_from_mux);
                    sdu_for_dlc->len = dlc_pdu_len_from_mux;
                    // TODO: Populate sdu_for_dlc->target_peer_short_rd_id with transmitter's Short ID if DLC needs it
                    // This requires transmitter's short ID to be passed into this function.
                    k_fifo_put(g_dlc_rx_sdu_fifo_ptr, sdu_for_dlc);
                    LOG_DBG("RX_SDU: Queued DLC PDU (len %u) from MUX IE 0x%X to DLC RX FIFO.",
                            sdu_for_dlc->len, ie_type);
                } else {
                    LOG_ERR("RX_SDU: Extracted DLC PDU too large (%u > %d).",
                            dlc_pdu_len_from_mux, CONFIG_DECT_MAC_SDU_MAX_SIZE);
                    dect_mac_api_buffer_free(sdu_for_dlc);
                }
            } else {
                LOG_ERR("RX_SDU: Failed to alloc buffer for DLC RX FIFO. DLC PDU (len %u) dropped.", dlc_pdu_len_from_mux);
            }
        } else {
            LOG_ERR("RX_SDU: DLC RX FIFO not registered! DLC PDU (len %u) dropped.", dlc_pdu_len_from_mux);
        }
    } else {
        LOG_DBG("RX_SDU: Received non-user-data MUX IE type 0x%X in SDU Area. MAC SM should handle.", ie_type);
    }
}

void dect_mac_data_path_handle_rx_sdu(const uint8_t *mac_sdu_area_data,
                                      size_t mac_sdu_area_len,
                                      uint32_t transmitter_long_rd_id)
{
    if (mac_sdu_area_data == NULL || mac_sdu_area_len == 0) {
        LOG_DBG("RX_SDU_HANDLER: Received empty or NULL MAC SDU Area.");
        return;
    }

    LOG_DBG("RX_SDU_HANDLER: Processing MAC SDU Area from 0x%08X, len %zu", transmitter_long_rd_id, mac_sdu_area_len);

    // The mac_sdu_area_data points to the start of the first MUXed IE.
    // We need to iterate if multiple MUXed IEs could be present,
    // but typically for user data, it might be one MUXed User Data IE,
    // potentially preceded by a MUXed MAC Security Info IE (which SM should handle first).
    // This function assumes it's called with a pointer to the SDU area *after* any
    // MAC-level control IEs (like MAC Sec Info IE) have been processed by the SM.

    const uint8_t *current_ie_ptr = mac_sdu_area_data;
    size_t remaining_sdu_area_len = mac_sdu_area_len;
    bool user_data_found_and_queued = false;

    while (remaining_sdu_area_len > 0 && !user_data_found_and_queued) { // Process first user data IE found
        uint8_t ie_type_from_mux;
        uint16_t dlc_pdu_len_from_mux; // This is the payload length of the MUXed IE
        const uint8_t *dlc_pdu_ptr_from_mux; // This points to the actual DLC PDU
        int parsed_mux_header_len;

        parsed_mux_header_len = parse_mac_mux_header(current_ie_ptr, remaining_sdu_area_len,
                                                     &ie_type_from_mux, &dlc_pdu_len_from_mux,
                                                     &dlc_pdu_ptr_from_mux);

        if (parsed_mux_header_len < 0) {
            LOG_ERR("RX_SDU_HANDLER: Failed to parse MAC MUX header in SDU Area: %d. Dropping rest of SDU Area.", parsed_mux_header_len);
            break; // Stop processing this SDU Area
        }

        // If MAC_Ext=00 (no length field in MUX header), parse_mac_mux_header returns 0 for dlc_pdu_len_from_mux.
        // The actual length is then (remaining_sdu_area_len - parsed_mux_header_len) if it's the last/only IE,
        // or it's a fixed length known by the ie_type_from_mux.
        if (dlc_pdu_len_from_mux == 0 && ((current_ie_ptr[0] >> 6) & 0x03) == 0b00) {
            if (remaining_sdu_area_len < (size_t)parsed_mux_header_len) {
                LOG_ERR("RX_SDU_HANDLER: Error with MAC_Ext=00, remaining len %zu < mux_hdr_len %d.",
                        remaining_sdu_area_len, parsed_mux_header_len);
                break;
            }
            dlc_pdu_len_from_mux = remaining_sdu_area_len - parsed_mux_header_len;
            LOG_DBG("RX_SDU_HANDLER: MUX IE_TYPE 0x%X with MAC_Ext=00, inferred payload len %u",
                    ie_type_from_mux, dlc_pdu_len_from_mux);
        }

        // Sanity check: does the declared payload length fit in what's remaining?
        if (remaining_sdu_area_len < (size_t)parsed_mux_header_len + dlc_pdu_len_from_mux) {
            LOG_ERR("RX_SDU_HANDLER: MUX IE (type 0x%X) declared payload len %u exceeds actual remaining SDU area %zu. Corrupted PDU?",
                    ie_type_from_mux, dlc_pdu_len_from_mux, remaining_sdu_area_len - parsed_mux_header_len);
            break; // Stop processing
        }

        // Check if this MUXed IE is one of the User Data Flow types
        if (ie_type_from_mux >= IE_TYPE_USER_DATA_FLOW_1 && ie_type_from_mux <= IE_TYPE_USER_DATA_FLOW_4) {
            LOG_INF("RX_SDU_HANDLER: User Data Flow IE (type 0x%X) found. DLC PDU len: %u.",
                    ie_type_from_mux, dlc_pdu_len_from_mux);

            if (g_dlc_rx_sdu_fifo_ptr != NULL) {
                mac_sdu_t *sdu_for_dlc = dect_mac_api_buffer_alloc(K_NO_WAIT);
                if (sdu_for_dlc) {
                    if (dlc_pdu_len_from_mux <= CONFIG_DECT_MAC_SDU_MAX_SIZE) {
                        memcpy(sdu_for_dlc->data, dlc_pdu_ptr_from_mux, dlc_pdu_len_from_mux);
                        sdu_for_dlc->len = dlc_pdu_len_from_mux;
                        // Optional: store transmitter_long_rd_id if mac_sdu_t has a field for it
                        // sdu_for_dlc->source_rd_id_info = transmitter_long_rd_id;
                        k_fifo_put(g_dlc_rx_sdu_fifo_ptr, sdu_for_dlc);
                        LOG_DBG("RX_SDU_HANDLER: Queued DLC PDU (len %u) from MUX IE 0x%X to DLC RX FIFO.",
                                sdu_for_dlc->len, ie_type_from_mux);
                        user_data_found_and_queued = true; // Assume one user data SDU per MAC PDU SDU Area for now
                    } else {
                        LOG_ERR("RX_SDU_HANDLER: Extracted DLC PDU (from MUX IE type 0x%X) too large (%u > %d) for SDU buffer. Dropped.",
                                ie_type_from_mux, dlc_pdu_len_from_mux, CONFIG_DECT_MAC_SDU_MAX_SIZE);
                        dect_mac_api_buffer_free(sdu_for_dlc);
                    }
                } else {
                    LOG_ERR("RX_SDU_HANDLER: Failed to alloc SDU buffer for DLC RX. DLC PDU (len %u) from MUX IE type 0x%X dropped.",
                            dlc_pdu_len_from_mux, ie_type_from_mux);
                }
            } else {
                LOG_ERR("RX_SDU_HANDLER: DLC RX FIFO (g_dlc_rx_sdu_fifo_ptr) is NULL! Cannot queue received DLC PDU.");
            }
        } else {
            LOG_WRN("RX_SDU_HANDLER: Encountered non-UserData MUX IE type 0x%X in SDU Area. MAC SM should have handled it or it's unexpected here. Skipping.",
                    ie_type_from_mux);
            // If other MAC-internal IEs can be in SDU Area after SecIE, they'd be handled here or by SM.
        }

        // Advance pointer and remaining length for next MUXed IE
        current_ie_ptr += parsed_mux_header_len + dlc_pdu_len_from_mux;
        if (remaining_sdu_area_len >= (size_t)parsed_mux_header_len + dlc_pdu_len_from_mux) {
            remaining_sdu_area_len -= (parsed_mux_header_len + dlc_pdu_len_from_mux);
        } else {
            remaining_sdu_area_len = 0; // Should have been caught by sanity check
        }

        if (user_data_found_and_queued) {
            // For simplicity, assuming only one user data SDU (DLC PDU) is expected per call to this handler
            // from the SM. If multiple user data IEs could be legitimately present and need individual queuing,
            // the loop condition and user_data_found_and_queued flag would need adjustment.
            break;
        }
    }

    if (!user_data_found_and_queued && mac_sdu_area_len > 0) {
        LOG_DBG("RX_SDU_HANDLER: No User Data Flow IE found or queued from SDU Area (len %zu).", mac_sdu_area_len);
    }
}