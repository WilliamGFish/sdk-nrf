/* dect_dlc/dect_dlc.c */
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <hw_id.h>                 // For hw_id_get if provisioning locally (used by MAC Core)
#include <string.h>               // For memcpy, strlen
#include <zephyr/sys/byteorder.h> // For endian conversion (used by DLC headers if multi-byte fields)

#include "dect_dlc.h"
#include "dect_mac_api.h"       // For MAC SDU definition and API (buffer_alloc, send, free)
#include "dect_mac_context.h"   // For CONFIG_DECT_MAC_SDU_MAX_SIZE
#include "dect_mac_core.h"      // For dect_mac_core_init

LOG_MODULE_REGISTER(dect_dlc, CONFIG_DECT_DLC_LOG_LEVEL);

// --- DLC Internal State and Buffers ---
#define MAX_DLC_REASSEMBLY_SESSIONS 4
#define MAX_DLC_RETRANSMISSION_JOBS 8
#define DLC_RETRANSMISSION_TIMEOUT_MS 10000 // e.g., 10 seconds
#define DLC_MAX_RETRIES 3
// REASSEMBLY_BUF_SIZE should be large enough for the largest possible *CVG PDU* after reassembly.
// This is a placeholder size. A real system would need this configurable or dynamically sized.
#define DLC_REASSEMBLY_BUF_SIZE (CONFIG_DECT_MAC_SDU_MAX_SIZE * 4) // Example: Can reassemble up to ~4 MAC SDUs
#define DLC_REASSEMBLY_TIMEOUT_MS 5000

// Sequence number for DLC Service Types 1, 2, 3 (10-bit)
static uint16_t dlc_tx_sequence_number = 0; // Per DLC entity set, or global if only one logical link active

typedef struct {
    bool is_active;
    uint16_t sequence_number;
    uint8_t retries;
    dlc_service_type_t service;
    mac_sdu_t *sdu_payload; // Holds the original DLC SDU payload
    struct k_timer timeout_timer;
} dlc_retransmission_job_t;

static dlc_retransmission_job_t retransmission_jobs[MAX_DLC_RETRANSMISSION_JOBS];


typedef struct {
    bool is_active;
    uint16_t sequence_number;       // SN of the DLC SDU (CVG PDU) being reassembled
    uint8_t reassembly_buf[DLC_REASSEMBLY_BUF_SIZE];
    size_t current_len;             // Current total length of data in reassembly_buf (may have gaps)
    size_t expected_total_len;      // Expected total length if known (e.g. from first segment if supported)
    uint32_t received_segments_map; // Bitmap for tracking received segments for a given SN
    struct k_timer timeout_timer;   // Renamed from "timeout" to avoid conflict
    dlc_service_type_t service_type;// Service type of the SDU being reassembled
    // uint32_t source_rd_id;       // If needed to distinguish sessions from multiple MAC peers
} dlc_reassembly_session_t;

static dlc_reassembly_session_t reassembly_sessions[MAX_DLC_REASSEMBLY_SESSIONS];

// FIFO for MAC SDUs (containing DLC PDUs) received from MAC layer, to be processed by dlc_rx_thread
K_FIFO_DEFINE(g_dlc_internal_mac_rx_fifo);
// FIFO for fully reassembled DLC SDUs (CVG PDUs) to be passed to the application layer
K_FIFO_DEFINE(g_dlc_to_app_rx_fifo);
// FIFO to signal the DLC TX service thread which job index needs retransmission
K_FIFO_DEFINE(g_dlc_retransmit_signal_fifo);

// --- Forward Declarations ---
static void dlc_reassembly_timeout_handler(struct k_timer *timer_id);
static void dlc_retransmission_timeout_handler(struct k_timer *timer_id);
static void dlc_tx_service_thread_entry(void *p1, void *p2, void *p3);
static void dlc_rx_thread_entry(void *p1, void *p2, void *p3);
static void dlc_tx_status_cb_handler(uint16_t dlc_sn, bool success);

// Helper to queue a single DLC PDU (which might be a segment) to the MAC layer.
static int queue_dlc_pdu_to_mac(const uint8_t *dlc_header, size_t dlc_header_len,
                                const uint8_t *payload_segment, size_t payload_segment_len,
                                mac_flow_id_t mac_qos_flow,
                                bool report_status, uint16_t dlc_sn_for_report)
{
    size_t total_pdu_len = dlc_header_len + payload_segment_len;
    if (total_pdu_len > CONFIG_DECT_MAC_SDU_MAX_SIZE) {
        LOG_ERR("DLC_PDU_QUEUE: Segment PDU size %zu exceeds MAC SDU capacity %d.",
                total_pdu_len, CONFIG_DECT_MAC_SDU_MAX_SIZE);
        return -EMSGSIZE;
    }

    mac_sdu_t *mac_sdu = dect_mac_api_buffer_alloc(K_MSEC(10));
    if (!mac_sdu) {
        LOG_ERR("DLC_PDU_QUEUE: Failed to allocate MAC SDU buffer for segment.");
        return -ENOMEM;
    }

    mac_sdu->dlc_status_report_required = report_status;
    mac_sdu->dlc_sn_for_status = dlc_sn_for_report;

    memcpy(mac_sdu->data, dlc_header, dlc_header_len);
    if (payload_segment && payload_segment_len > 0) {
        memcpy(mac_sdu->data + dlc_header_len, payload_segment, payload_segment_len);
    }
    mac_sdu->len = total_pdu_len;

    // The role check and specific send API are handled by dect_mac_api_send.
    // However, if we know we are an FT, we'd need to use a different top-level DLC API.
    // For simplicity, we'll assume the main function calls the correct MAC API.

    return dect_mac_api_send(mac_sdu, mac_qos_flow);
}


static dlc_reassembly_session_t* find_reassembly_session(uint16_t sequence_number)
{
    for (int i = 0; i < MAX_DLC_REASSEMBLY_SESSIONS; i++) {
        if (reassembly_sessions[i].is_active && reassembly_sessions[i].sequence_number == sequence_number) {
            return &reassembly_sessions[i];
        }
    }
    return NULL;
}

static dlc_reassembly_session_t* allocate_reassembly_session(uint16_t sequence_number)
{
    for (int i = 0; i < MAX_DLC_REASSEMBLY_SESSIONS; i++) {
        if (!reassembly_sessions[i].is_active) {
            dlc_reassembly_session_t *session = &reassembly_sessions[i];
            session->is_active = true;
            session->sequence_number = sequence_number;
            session->current_len = 0;
            // A more robust bitmap would be dynamically sized or use a bitmask array.
            // For now, a simple bitmap assuming the SDU is not excessively large.
            memset(session->reassembly_buf, 0, DLC_REASSEMBLY_BUF_SIZE);
            session->received_segments_map = 0; // Clear the bitmap
            session->expected_total_len = 0; // Unknown until last segment arrives
            k_timer_start(&session->timeout_timer, K_MSEC(DLC_REASSEMBLY_TIMEOUT_MS), K_NO_WAIT);
            LOG_DBG("DLC_SAR: Allocated reassembly session %d for SN %u.", i, sequence_number);
            return session;
        }
    }
    LOG_ERR("DLC_SAR: No free reassembly sessions available for SN %u!", sequence_number);
    return NULL;
}

/**
 * @brief Handles TX status callbacks from the MAC layer.
 *
 * This function is called from the MAC thread context.
 */
static void dlc_tx_status_cb_handler(uint16_t dlc_sn, bool success)
{
    // Find the job associated with this sequence number
    int job_idx = -1;
    for (int i = 0; i < MAX_DLC_RETRANSMISSION_JOBS; i++) {
        if (retransmission_jobs[i].is_active && retransmission_jobs[i].sequence_number == dlc_sn) {
            job_idx = i;
            break;
        }
    }

    if (job_idx == -1) {
        LOG_WRN("DLC_ARQ_CB: Received status for unknown or already completed SN %u.", dlc_sn);
        return;
    }

    dlc_retransmission_job_t *job = &retransmission_jobs[job_idx];
    k_timer_stop(&job->timeout_timer); // Stop the timeout timer for this job

    if (success) {
        LOG_INF("DLC_ARQ_CB: MAC SUCCESS for SN %u. Freeing job.", dlc_sn);
        // Free the SDU buffer and the job slot
        dect_mac_api_buffer_free(job->sdu_payload);
        job->is_active = false;
    } else {
        // MAC layer has reported permanent failure after all its HARQ retries.
        // The DLC layer will now attempt a full retransmission.
        LOG_WRN("DLC_ARQ_CB: MAC PERMANENT FAILURE for SN %u. Signaling for DLC re-TX.", dlc_sn);
        k_fifo_put(&g_dlc_retransmit_signal_fifo, (void *)((uintptr_t)job_idx));
    }
}

// --- DLC RX Thread for Reassembly and ARQ (if implemented) ---
K_THREAD_DEFINE(g_dlc_rx_thread_id, CONFIG_DECT_DLC_RX_THREAD_STACK_SIZE,
                dlc_rx_thread_entry, NULL, NULL, NULL,
                CONFIG_DECT_DLC_RX_THREAD_PRIORITY, 0, 0);

K_THREAD_DEFINE(g_dlc_tx_service_thread_id, CONFIG_DECT_DLC_TX_SERVICE_THREAD_STACK_SIZE,
                dlc_tx_service_thread_entry, NULL, NULL, NULL,
                CONFIG_DECT_DLC_TX_SERVICE_THREAD_PRIORITY, 0, 0);

static void dlc_rx_thread_entry(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
    LOG_INF("DLC RX Thread started.");

    while (1) {
        mac_sdu_t *mac_sdu = k_fifo_get(&g_dlc_internal_mac_rx_fifo, K_FOREVER);
        if (!mac_sdu) {
            continue;
        }

        if (mac_sdu->len == 0) {
            LOG_WRN("DLC_RX_THREAD: Received empty MAC SDU from MAC layer.");
            dect_mac_api_buffer_free(mac_sdu);
            continue;
        }

        const uint8_t *dlc_pdu = mac_sdu->data;
        size_t dlc_pdu_len = mac_sdu->len;
        dlc_ie_type_val_t ie_type = (dlc_ie_type_val_t)((dlc_pdu[0] >> 4) & 0x0F);

        // --- Handle Transparent Service (Type 0) ---
        if (ie_type == DLC_IE_TYPE_DATA_TYPE_0_NO_ROUTING ||
            ie_type == DLC_IE_TYPE_DATA_TYPE_0_WITH_ROUTING) { // TODO: Add Ext Hdr case
            if (dlc_pdu_len < sizeof(dect_dlc_header_type0_t)) {
                LOG_ERR("DLC_RX: Type 0 PDU too short (%zu).", dlc_pdu_len);
            } else {
                size_t payload_len = dlc_pdu_len - sizeof(dect_dlc_header_type0_t);
                if (payload_len > 0) {
                    mac_sdu_t *app_sdu = dect_mac_api_buffer_alloc(K_NO_WAIT);
                    if (app_sdu) {
                        memcpy(app_sdu->data, dlc_pdu + sizeof(dect_dlc_header_type0_t), payload_len);
                        app_sdu->len = payload_len;
                        // TODO: Use delivery_item struct to pass service type
                        k_fifo_put(&g_dlc_to_app_rx_fifo, app_sdu);
                    } else {
                        LOG_ERR("DLC_RX: Failed to alloc buffer for app delivery.");
                    }
                }
            }
        }
        // --- Handle Segmented/ARQ Services (Type 1, 2, 3) ---
        else if (ie_type == DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING ||
                   ie_type == DLC_IE_TYPE_DATA_TYPE_123_WITH_ROUTING) { // TODO: Add Ext Hdr case

            const dect_dlc_header_type123_basic_t *hdr = (const dect_dlc_header_type123_basic_t*)dlc_pdu;
            dlc_segmentation_indication_t si = dlc_hdr_t123_basic_get_si(hdr);
            uint16_t sn = dlc_hdr_t123_basic_get_sn(hdr);
            const uint8_t *payload_ptr;
            size_t payload_len;
            size_t header_len;
            uint16_t seg_offset = 0;

            if (si == DLC_SI_COMPLETE_SDU || si == DLC_SI_FIRST_SEGMENT) {
                header_len = sizeof(dect_dlc_header_type123_basic_t);
            } else { // MIDDLE or LAST segment
                header_len = sizeof(dect_dlc_header_type13_segmented_t);
                seg_offset = dlc_hdr_t13_segmented_get_offset((const dect_dlc_header_type13_segmented_t*)hdr);
            }

            if (dlc_pdu_len < header_len) {
                LOG_ERR("DLC_RX: Segmented PDU too short for header (SI=%d, len=%zu, hdr_len=%zu)", si, dlc_pdu_len, header_len);
                dect_mac_api_buffer_free(mac_sdu);
                continue;
            }
            payload_ptr = dlc_pdu + header_len;
            payload_len = dlc_pdu_len - header_len;

            // --- Reassembly Logic ---
            if (si == DLC_SI_COMPLETE_SDU) {
                if (payload_len > 0) {
                    mac_sdu_t *app_sdu = dect_mac_api_buffer_alloc(K_NO_WAIT);
                    if (app_sdu) {
                        memcpy(app_sdu->data, payload_ptr, payload_len);
                        app_sdu->len = payload_len;
                        // TODO: Use delivery_item struct to pass service type
                        k_fifo_put(&g_dlc_to_app_rx_fifo, app_sdu);
                    } else { LOG_ERR("DLC_RX: Failed to alloc buffer for complete SDU."); }
                }
            } else { // Segmented PDU
                dlc_reassembly_session_t *session = find_reassembly_session(sn);
                if (!session && si == DLC_SI_FIRST_SEGMENT) {
                    session = allocate_reassembly_session(sn);
                }

                if (!session) {
                    LOG_WRN("DLC_RX: No active reassembly session for SN %u and this is not a FIRST segment (SI=%d). Dropping.", sn, si);
                    dect_mac_api_buffer_free(mac_sdu);
                    continue;
                }

                // Check for buffer overflow before memcpy
                if (seg_offset + payload_len > DLC_REASSEMBLY_BUF_SIZE) {
                    LOG_ERR("DLC_SAR: Segment for SN %u (offset %u, len %zu) would overflow reassembly buffer. Discarding session.",
                            sn, seg_offset, payload_len);
                    session->is_active = false;
                    k_timer_stop(&session->timeout_timer);
                    dect_mac_api_buffer_free(mac_sdu);
                    continue;
                }

                // Copy segment payload into the reassembly buffer
                memcpy(session->reassembly_buf + seg_offset, payload_ptr, payload_len);
                session->current_len += payload_len; // Simple accumulation for now
                // TODO: A more robust approach would use a bitmap to track received chunks.
                // For now, we rely on receiving the last segment to know the total length.

                if (si == DLC_SI_LAST_SEGMENT) {
                    session->expected_total_len = seg_offset + payload_len;
                    LOG_DBG("DLC_SAR: Received LAST segment for SN %u. Expected total len: %zu, current len: %zu",
                            sn, session->expected_total_len, session->current_len);

                    // Simplified check: assume if we got the last segment, we got everything.
                    // A bitmap check would be required here for a robust implementation.
                    if (session->current_len == session->expected_total_len) {
                        LOG_INF("DLC_SAR: Reassembly complete for SN %u, total size %zu.",
                                sn, session->expected_total_len);

                        mac_sdu_t *app_sdu = dect_mac_api_buffer_alloc(K_NO_WAIT);
                        if (app_sdu) {
                            memcpy(app_sdu->data, session->reassembly_buf, session->expected_total_len);
                            app_sdu->len = session->expected_total_len;
                            k_fifo_put(&g_dlc_to_app_rx_fifo, app_sdu);
                        } else {
                            LOG_ERR("DLC_SAR: Failed to alloc buffer for reassembled SDU.");
                        }
                        session->is_active = false; // Free the session
                        k_timer_stop(&session->timeout_timer);
                    } else {
                         LOG_WRN("DLC_SAR: Received LAST segment for SN %u, but size mismatch (exp %zu, got %zu). Waiting for timeout.",
                                 sn, session->expected_total_len, session->current_len);
                    }
                } else {
                    // It was a FIRST or MIDDLE segment, just restart the timer to keep session alive.
                    k_timer_start(&session->timeout_timer, K_MSEC(DLC_REASSEMBLY_TIMEOUT_MS), K_NO_WAIT);
                }
            }
        } else {
            LOG_WRN("DLC_RX_THREAD: Unknown or unsupported DLC IE Type: 0x%X", ie_type);
        }

        dect_mac_api_buffer_free(mac_sdu);
    }
}

/**
 * @brief DLC ARQ Retransmission Thread.
 *
 * Waits for signals to retransmit a DLC SDU that has failed transmission.
 */
static void dlc_tx_service_thread_entry(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
    LOG_INF("DLC TX Service (ARQ) Thread started.");

    while (1) {
        // Wait for a signal that a job needs re-transmitting.
        // The data in the FIFO is the index of the job in the retransmission_jobs array.
        uintptr_t job_idx = (uintptr_t)k_fifo_get(&g_dlc_retransmit_signal_fifo, K_FOREVER);

        if (job_idx >= MAX_DLC_RETRANSMISSION_JOBS || !retransmission_jobs[job_idx].is_active) {
            LOG_WRN("DLC_ARQ_SVC: Spurious re-TX signal for invalid job index %u.", (unsigned int)job_idx);
            continue;
        }

        dlc_retransmission_job_t *job = &retransmission_jobs[job_idx];

        if (job->retries >= DLC_MAX_RETRIES) {
            LOG_ERR("DLC_ARQ_SVC: Job for SN %u has reached max retries. Discarding.", job->sequence_number);
            dect_mac_api_buffer_free(job->sdu_payload);
            job->is_active = false; // Free the job slot
            continue;
        }

        job->retries++;
        LOG_INF("DLC_ARQ_SVC: Re-transmitting SDU for SN %u (attempt %u).",
                job->sequence_number, job->retries + 1);

        // Re-send the SDU. The dlc_send_data function will handle segmentation and queuing.
        // Since this is a retransmission, the SN will be reused, and a new ARQ job will be created.
        // This is a simplification. A more advanced implementation would have a dedicated
        // "resend" function that reuses the original SN.
        // For now, we will treat it as a new send, which will get a new SN.
        // This means the higher layer (CVG) must handle duplicates.
        // TODO: Create a dlc_resend_data() that reuses the SN.
        int err = dlc_send_data(job->service, job->sdu_payload->data, job->sdu_payload->len);
        if (err) {
            LOG_ERR("DLC_ARQ_SVC: Failed to re-queue SDU for SN %u (err %d). Will retry on next timeout.",
                    job->sequence_number, err);
            // Restart the timer to try again later.
            k_timer_start(&job->timeout_timer, K_MSEC(DLC_RETRANSMISSION_TIMEOUT_MS), K_NO_WAIT);
        } else {
            // The original job is now conceptually replaced by the new one created in dlc_send_data.
            // Free the original job's resources.
            dect_mac_api_buffer_free(job->sdu_payload);
            job->is_active = false;
        }
    }
}

/**
 * @brief Handles retransmission timer expiry for a DLC ARQ job.
 */
static void dlc_retransmission_timeout_handler(struct k_timer *timer_id)
{
    uintptr_t job_idx = (uintptr_t)timer_id->user_data;
    if (job_idx < MAX_DLC_RETRANSMISSION_JOBS && retransmission_jobs[job_idx].is_active) {
        LOG_WRN("DLC_ARQ_TIMEOUT: Transmission for SN %u timed out. Signaling for re-TX.",
                retransmission_jobs[job_idx].sequence_number);
        // Signal the TX service thread to handle the retransmission.
        k_fifo_put(&g_dlc_retransmit_signal_fifo, (void *)job_idx);
    }
}


// --- Public API Implementation ---
int dect_dlc_init(void)
{
    // The responsibility of initializing the MAC layer (API and Core) is now
    // handled by the application's main setup, before the upper layers are initialized.
    // This function now only initializes resources specific to the DLC layer.

    // Register our callback handler with the MAC Data Path.
    // The MAC will call this function to report final TX status.
    dect_mac_data_path_register_dlc_callback(dlc_tx_status_cb_handler);

    // Initialize retransmission jobs and their timers
    for (int i = 0; i < MAX_DLC_RETRANSMISSION_JOBS; i++) {
        k_timer_init(&retransmission_jobs[i].timeout_timer, dlc_retransmission_timeout_handler, NULL);
        retransmission_jobs[i].timeout_timer.user_data = (void*)((uintptr_t)i);
        retransmission_jobs[i].is_active = false;
    }

    // Initialize reassembly sessions and their timers
    for (int i=0; i < MAX_DLC_REASSEMBLY_SESSIONS; i++) {
        k_timer_init(&reassembly_sessions[i].timeout_timer, dlc_reassembly_timeout_handler, NULL);
        reassembly_sessions[i].timeout_timer.user_data = (void*)((uintptr_t)i); // Pass session index
        reassembly_sessions[i].is_active = false;
    }

    // The DLC RX thread is auto-started by K_THREAD_DEFINE.
    // We can set its name for easier debugging.
    k_thread_name_set(g_dlc_rx_thread_id, "dect_dlc_rx");
    k_thread_name_set(g_dlc_tx_service_thread_id, "dlc_arq_svc");

    LOG_INF("DLC Layer Initialized.");
    return 0;
}

int dlc_send_data(dlc_service_type_t service, const uint8_t *dlc_sdu_payload, size_t dlc_sdu_payload_len)
{
    if (dlc_sdu_payload == NULL && dlc_sdu_payload_len > 0) {
        return -EINVAL;
    }
    if (dlc_sdu_payload_len > CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE) {
        LOG_ERR("DLC_SEND: DLC SDU payload too large: %zu (max %d)",
                dlc_sdu_payload_len, CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE);
        return -EMSGSIZE;
    }

    mac_flow_id_t mac_qos_flow;
    dlc_ie_type_val_t ie_type = DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING; // Assume no routing.
    int err = 0;
    bool needs_dlc_arq = (service == DLC_SERVICE_TYPE_2_ARQ || service == DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ);

    // Get a new sequence number for any service that uses it
    if (service != DLC_SERVICE_TYPE_0_TRANSPARENT) {
        dlc_tx_sequence_number = (dlc_tx_sequence_number + 1) & 0x03FF;
    }

    dlc_retransmission_job_t *arq_job = NULL;
    if (needs_dlc_arq) {
        int job_idx = -1;
        for (int i = 0; i < MAX_DLC_RETRANSMISSION_JOBS; i++) {
            if (!retransmission_jobs[i].is_active) {
                job_idx = i;
                break;
            }
        }

        if (job_idx == -1) {
            LOG_ERR("DLC_SEND_ARQ: No free retransmission jobs available. Dropping SDU.");
            return -ENOBUFS;
        }

        arq_job = &retransmission_jobs[job_idx];
        arq_job->sdu_payload = dect_mac_api_buffer_alloc(K_NO_WAIT);
        if (!arq_job->sdu_payload) {
            LOG_ERR("DLC_SEND_ARQ: Failed to allocate buffer for re-TX job. Dropping SDU.");
            return -ENOMEM;
        }

        memcpy(arq_job->sdu_payload->data, dlc_sdu_payload, dlc_sdu_payload_len);
        arq_job->sdu_payload->len = dlc_sdu_payload_len;
        arq_job->is_active = true;
        arq_job->sequence_number = dlc_tx_sequence_number;
        arq_job->retries = 0;
        arq_job->service = service;
        k_timer_start(&arq_job->timeout_timer, K_MSEC(DLC_RETRANSMISSION_TIMEOUT_MS), K_NO_WAIT);
    }

    switch (service) {
    case DLC_SERVICE_TYPE_0_TRANSPARENT: {
        size_t hdr_len = sizeof(dect_dlc_header_type0_t);
        uint8_t hdr_buf[hdr_len];
        dlc_hdr_type0_set((dect_dlc_header_type0_t *)hdr_buf, DLC_IE_TYPE_DATA_TYPE_0_NO_ROUTING);
        err = queue_dlc_pdu_to_mac(hdr_buf, hdr_len, dlc_sdu_payload, dlc_sdu_payload_len, MAC_FLOW_BEST_EFFORT, false, 0);
        break;
    }
    case DLC_SERVICE_TYPE_2_ARQ: {
        size_t hdr_len = sizeof(dect_dlc_header_type123_basic_t);
        if (hdr_len + dlc_sdu_payload_len > CONFIG_DECT_MAC_SDU_MAX_SIZE) {
            err = -EMSGSIZE;
            break;
        }
        uint8_t hdr_buf[hdr_len];
        dlc_hdr_t123_basic_set((dect_dlc_header_type123_basic_t *)hdr_buf, ie_type, DLC_SI_COMPLETE_SDU, dlc_tx_sequence_number);
        err = queue_dlc_pdu_to_mac(hdr_buf, hdr_len, dlc_sdu_payload, dlc_sdu_payload_len, MAC_FLOW_RELIABLE_DATA, true, dlc_tx_sequence_number);
        break;
    }
    case DLC_SERVICE_TYPE_1_SEGMENTATION:
    case DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ: {
        mac_qos_flow = (service == DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ) ? MAC_FLOW_RELIABLE_DATA : MAC_FLOW_BEST_EFFORT;
        size_t sent_len = 0;
        while (sent_len < dlc_sdu_payload_len) {
            uint8_t hdr_buf[sizeof(dect_dlc_header_type13_segmented_t)];
            size_t hdr_len;
            size_t payload_this_segment;
            dlc_segmentation_indication_t si;
            uint16_t seg_offset = 0;
            bool is_last_segment = false;

            if (sent_len == 0) {
                hdr_len = sizeof(dect_dlc_header_type123_basic_t);
            } else {
                hdr_len = sizeof(dect_dlc_header_type13_segmented_t);
                seg_offset = sent_len;
            }

            payload_this_segment = CONFIG_DECT_MAC_SDU_MAX_SIZE - hdr_len;
            if (sent_len + payload_this_segment >= dlc_sdu_payload_len) {
                payload_this_segment = dlc_sdu_payload_len - sent_len;
                si = (sent_len == 0) ? DLC_SI_COMPLETE_SDU : DLC_SI_LAST_SEGMENT;
                is_last_segment = true;
            } else {
                si = (sent_len == 0) ? DLC_SI_FIRST_SEGMENT : DLC_SI_MIDDLE_SEGMENT;
            }

            if (si == DLC_SI_COMPLETE_SDU) {
                hdr_len = sizeof(dect_dlc_header_type123_basic_t);
                dlc_hdr_t123_basic_set((dect_dlc_header_type123_basic_t*)hdr_buf, ie_type, si, dlc_tx_sequence_number);
            } else if (si == DLC_SI_FIRST_SEGMENT) {
                dlc_hdr_t123_basic_set((dect_dlc_header_type123_basic_t*)hdr_buf, ie_type, si, dlc_tx_sequence_number);
            } else {
                 dlc_hdr_t13_segmented_set((dect_dlc_header_type13_segmented_t*)hdr_buf, ie_type, si, dlc_tx_sequence_number, seg_offset);
            }

            bool report_status_for_this_segment = needs_dlc_arq && is_last_segment;
            
            err = queue_dlc_pdu_to_mac(hdr_buf, hdr_len, dlc_sdu_payload + sent_len, payload_this_segment,
                                       mac_qos_flow, report_status_for_this_segment, dlc_tx_sequence_number);
            if (err) {
                LOG_ERR("DLC_SEND_SEG: Failed to queue segment (err %d). Aborting send of SN %u.", err, dlc_tx_sequence_number);
                if (arq_job) {
                    k_timer_stop(&arq_job->timeout_timer);
                    dect_mac_api_buffer_free(arq_job->sdu_payload);
                    arq_job->is_active = false;
                }
                break;
            }
            sent_len += payload_this_segment;
        }
        break;
    }
    default:
        LOG_ERR("DLC_SEND: Unknown DLC service type %d", service);
        if (arq_job) { arq_job->is_active = false; dect_mac_api_buffer_free(arq_job->sdu_payload); } // Cleanup
        return -EINVAL;
    }

    if (err && arq_job) {
        LOG_WRN("DLC_SEND: Cleaning up ARQ job for SN %u due to send error %d.", dlc_tx_sequence_number, err);
        k_timer_stop(&arq_job->timeout_timer);
        dect_mac_api_buffer_free(arq_job->sdu_payload);
        arq_job->is_active = false;
    }

    return err;
}

int dlc_receive_data(dlc_service_type_t *service_type_out,
                     uint8_t *app_level_payload_buf,
                     size_t *app_level_payload_len_inout,
                     k_timeout_t timeout)
{
    if (!service_type_out || !app_level_payload_buf || !app_level_payload_len_inout || !(*app_level_payload_len_inout > 0) ) {
        return -EINVAL;
    }

    mac_sdu_t *app_sdu_from_dlc_rx_thread = k_fifo_get(&g_dlc_to_app_rx_fifo, timeout);
    if (!app_sdu_from_dlc_rx_thread) {
        return -EAGAIN; // Timeout or FIFO empty on K_NO_WAIT
    }

    if (*app_level_payload_len_inout < app_sdu_from_dlc_rx_thread->len) {
        *app_level_payload_len_inout = app_sdu_from_dlc_rx_thread->len; // Report required size
        k_fifo_put(&g_dlc_to_app_rx_fifo, app_sdu_from_dlc_rx_thread); // Put it back
        LOG_WRN("DLC_RECV: App buffer too small (got %u, need %u).",
                 (uint16_t)*app_level_payload_len_inout, app_sdu_from_dlc_rx_thread->len);
        return -EMSGSIZE;
    }

    *app_level_payload_len_inout = app_sdu_from_dlc_rx_thread->len;
    memcpy(app_level_payload_buf, app_sdu_from_dlc_rx_thread->data, app_sdu_from_dlc_rx_thread->len);

    // CRITICAL TODO: Determine the actual service_type_out.
    // The mac_sdu_t currently doesn't store the service type.
    // The dlc_rx_thread_entry needs to parse the DLC header of the received PDU
    // to determine the service type and pass it along with the data.
    // This likely means g_dlc_to_app_rx_fifo should hold a struct:
    // typedef struct { mac_sdu_t* sdu_buf; dlc_service_type_t type; } dlc_app_delivery_item_t;
    // For now, hardcoding.
    *service_type_out = DLC_SERVICE_TYPE_0_TRANSPARENT; // FIXME
    LOG_WRN("DLC_RECV: Service type determination is FIXME (defaulting to Transparent).");


    LOG_DBG("DLC_RECV: Delivered CVG PDU (len %zu) to application. Service Type (FIXME): %d",
            *app_level_payload_len_inout, *service_type_out);
    dect_mac_api_buffer_free(app_sdu_from_dlc_rx_thread);
    return 0;
}

static void dlc_reassembly_timeout_handler(struct k_timer *timer_id)
{
    uintptr_t session_idx_from_timer = (uintptr_t)timer_id->user_data; // Retrieve index

    if (session_idx_from_timer < MAX_DLC_REASSEMBLY_SESSIONS &&
        reassembly_sessions[session_idx_from_timer].is_active) {
        LOG_WRN("DLC_SAR_TIMEOUT: Reassembly for session %u (SN %u) timed out. Discarding segments.",
                (unsigned int)session_idx_from_timer, reassembly_sessions[session_idx_from_timer].sequence_number);
        reassembly_sessions[session_idx_from_timer].is_active = false;
        reassembly_sessions[session_idx_from_timer].current_len = 0;
        // Timer is one-shot, no need to k_timer_stop if it fired.
    } else {
        LOG_ERR("DLC_SAR_TIMEOUT: Spurious timeout for invalid/inactive session index %u", (unsigned int)session_idx_from_timer);
    }
}