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

#define DLC_REASSEMBLY_CHUNK_SIZE 64 // Size of each chunk tracked by the bitmap
#define DLC_MAX_REASSEMBLY_CHUNKS (DLC_REASSEMBLY_BUF_SIZE / DLC_REASSEMBLY_CHUNK_SIZE)
#if DLC_MAX_REASSEMBLY_CHUNKS > 64
    #warning "DLC_MAX_REASSEMBLY_CHUNKS > 64; bitmap logic needs extension (e.g., array of uint64_t)"
    // For simplicity, we'll use a single uint64_t, limiting to 64 chunks.
    // This implies DLC_REASSEMBLY_BUF_SIZE <= 64 * 64 = 4096.
    #define DLC_BITMAP_TYPE uint64_t
    #define MAX_BITMAP_TRACKABLE_CHUNKS 64
#elif DLC_MAX_REASSEMBLY_CHUNKS > 32
    #define DLC_BITMAP_TYPE uint64_t
    #define MAX_BITMAP_TRACKABLE_CHUNKS 64
#else
    #define DLC_BITMAP_TYPE uint32_t
    #define MAX_BITMAP_TRACKABLE_CHUNKS 32
#endif
#if DLC_MAX_REASSEMBLY_CHUNKS == 0
#error "DLC_REASSEMBLY_CHUNK_SIZE is too large for DLC_REASSEMBLY_BUF_SIZE"
#endif


typedef struct {
    bool is_active;
    uint16_t sequence_number;       // SN of the DLC SDU (CVG PDU) being reassembled
    uint8_t reassembly_buf[DLC_REASSEMBLY_BUF_SIZE];
    DLC_BITMAP_TYPE received_chunk_bitmap; // Bitmap to track received chunks
    uint16_t total_expected_sdu_len;  // Total length of the SDU once known (from LAST segment or future SLI)
    uint16_t highest_offset_received; // Highest byte offset written to, to estimate current reassembled size
    uint8_t num_expected_chunks;     // Calculated once total_expected_sdu_len is known
    struct k_timer timeout_timer;
    dlc_service_type_t service_type;// Service type of the SDU being reassembled
    // uint32_t source_rd_id;       // If needed for multi-peer
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
            session->service_type = service;
            memset(session->reassembly_buf, 0, DLC_REASSEMBLY_BUF_SIZE); // Clear buffer
            session->received_chunk_bitmap = 0;       // Clear bitmap
            session->total_expected_sdu_len = 0;      // Unknown until last segment or SLI
            session->highest_offset_received = 0;
            session->num_expected_chunks = 0;         // Unknown until total_expected_sdu_len is set
            k_timer_start(&session->timeout_timer, K_MSEC(DLC_REASSEMBLY_TIMEOUT_MS), K_NO_WAIT);
            LOG_DBG("DLC_SAR: Allocated reassembly session %d for SN %u, Svc %u.", i, sequence_number, service);
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
            // This should not happen with K_FOREVER unless k_fifo_init failed,
            // or if the FIFO is being terminated, which is not the case here.
            LOG_ERR("DLC_RX_THREAD: k_fifo_get returned NULL with K_FOREVER. Critical error.");
            k_sleep(K_MSEC(1000)); // Avoid busy loop on critical error
            continue;
        }

        if (mac_sdu->len == 0) {
            LOG_WRN("DLC_RX_THREAD: Received empty MAC SDU from MAC layer. Discarding.");
            dect_mac_api_buffer_free(mac_sdu);
            continue;
        }

        const uint8_t *dlc_pdu = mac_sdu->data;
        size_t dlc_pdu_len = mac_sdu->len;
        dlc_ie_type_val_t ie_type = (dlc_ie_type_val_t)((dlc_pdu[0] >> 4) & 0x0F);
        
        // Placeholder for service type to pass to CVG.
        // Actual service type (0-3) might be inferred from configuration or future PDU fields.
        dlc_service_type_t dlc_sdu_service_type_for_cvg = DLC_SERVICE_TYPE_0_TRANSPARENT; // Default

        if (ie_type == DLC_IE_TYPE_DATA_TYPE_0_NO_ROUTING ||
            ie_type == DLC_IE_TYPE_DATA_TYPE_0_WITH_ROUTING ||
            ie_type == DLC_IE_TYPE_DATA_TYPE_0_EXT_HDR) { // Handle Type 0 with/without routing/ext
            
            dlc_sdu_service_type_for_cvg = DLC_SERVICE_TYPE_0_TRANSPARENT;
            size_t dlc_hdr_len_type0 = sizeof(dect_dlc_header_type0_t);
            // TODO: If _EXT_HDR, need to parse extension header to find start of CVG PDU.
            // For now, assume no extension header payload for Type 0 if _EXT_HDR is used.

            if (dlc_pdu_len < dlc_hdr_len_type0) {
                LOG_ERR("DLC_RX: Type 0 PDU (IE 0x%X) too short (%zu < %zu).", ie_type, dlc_pdu_len, dlc_hdr_len_type0);
                goto free_mac_sdu_and_continue_rx_loop;
            }

            size_t payload_len = dlc_pdu_len - dlc_hdr_len_type0;
            const uint8_t *payload_ptr = dlc_pdu + dlc_hdr_len_type0;

            if (payload_len > 0) {
                mac_sdu_t *cvg_sdu = dect_mac_api_buffer_alloc(K_NO_WAIT);
                if (cvg_sdu) {
                    if (payload_len <= sizeof(cvg_sdu->data)) {
                        memcpy(cvg_sdu->data, payload_ptr, payload_len);
                        cvg_sdu->len = payload_len;
                        // cvg_sdu->dlc_service_type = dlc_sdu_service_type_for_cvg; // If struct supports
                        k_fifo_put(&g_dlc_to_app_rx_fifo, cvg_sdu);
                        LOG_DBG("DLC_RX: Passed Type 0 SDU (len %zu) to CVG.", payload_len);
                    } else {
                        LOG_ERR("DLC_RX: Type 0 payload (%zu) too large for CVG SDU buffer. Dropping.", payload_len);
                        dect_mac_api_buffer_free(cvg_sdu);
                    }
                } else {
                    LOG_ERR("DLC_RX: Failed to alloc buffer for CVG delivery (Type0). Payload len %zu dropped.", payload_len);
                }
            } else {
                 LOG_DBG("DLC_RX: Type 0 PDU (IE 0x%X) with zero payload length.", ie_type);
            }
        } else if (ie_type == DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING ||
                   ie_type == DLC_IE_TYPE_DATA_TYPE_123_WITH_ROUTING ||
                   ie_type == DLC_IE_TYPE_DATA_TYPE_123_EXT_HDR) {

            // TODO: Determine actual service type (1 or 3 for SAR) based on context or ARQ flags if any in PDU
            dlc_service_type_t session_service_type = DLC_SERVICE_TYPE_1_SEGMENTATION; // Default for SAR
            // if (pdu_indicates_arq_service) session_service_type = DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ;
            dlc_sdu_service_type_for_cvg = session_service_type;


            const dect_dlc_header_type123_basic_t *hdr_basic = (const dect_dlc_header_type123_basic_t*)dlc_pdu;
            dlc_segmentation_indication_t si = dlc_hdr_t123_basic_get_si(hdr_basic);
            uint16_t sn = dlc_hdr_t123_basic_get_sn(hdr_basic);
            const uint8_t *segment_payload_ptr;
            size_t segment_payload_len;
            size_t dlc_hdr_len;
            uint16_t segment_offset = 0;

            // TODO: If _EXT_HDR, need to parse extension header first to find where DLC SDU (segment) starts.
            // For now, assume dlc_pdu points to start of actual DLC data header.

            if (si == DLC_SI_COMPLETE_SDU) {
                dlc_hdr_len = sizeof(dect_dlc_header_type123_basic_t);
                if (dlc_pdu_len < dlc_hdr_len) { LOG_ERR("DLC_RX: SN %u COMPLETE SDU too short for header.", sn); goto free_mac_sdu_and_continue_rx_loop; }
                segment_payload_ptr = dlc_pdu + dlc_hdr_len;
                segment_payload_len = dlc_pdu_len - dlc_hdr_len;

                LOG_DBG("DLC_RX: SN %u COMPLETE SDU (len %zu) received.", sn, segment_payload_len);
                if (segment_payload_len > 0) {
                    mac_sdu_t *cvg_sdu = dect_mac_api_buffer_alloc(K_NO_WAIT);
                    if (cvg_sdu) {
                         if (segment_payload_len <= sizeof(cvg_sdu->data)) {
                            memcpy(cvg_sdu->data, segment_payload_ptr, segment_payload_len);
                            cvg_sdu->len = segment_payload_len;
                            k_fifo_put(&g_dlc_to_app_rx_fifo, cvg_sdu);
                        } else {
                             LOG_ERR("DLC_RX: COMPLETE SDU SN %u (len %zu) too large for CVG buffer. Dropping.", sn, segment_payload_len);
                             dect_mac_api_buffer_free(cvg_sdu);
                        }
                    } else { LOG_ERR("DLC_RX: Failed to alloc buffer for CVG delivery (SN %u COMPLETE).", sn); }
                }
                // If this SN was part of an ongoing reassembly session (e.g., due to out-of-order LAST then COMPLETE), clear it.
                dlc_reassembly_session_t *existing_session = find_reassembly_session(sn);
                if (existing_session) {
                    LOG_WRN("DLC_RX: SN %u COMPLETE SDU received while reassembly session was active. Clearing session.", sn);
                    existing_session->is_active = false; k_timer_stop(&existing_session->timeout_timer);
                }
            } else { // Segmented PDU (FIRST, MIDDLE, LAST)
                if (si == DLC_SI_FIRST_SEGMENT) {
                    dlc_hdr_len = sizeof(dect_dlc_header_type123_basic_t);
                    segment_offset = 0; // First segment always starts at offset 0
                } else { // MIDDLE or LAST segment
                    dlc_hdr_len = sizeof(dect_dlc_header_type13_segmented_t);
                    if (dlc_pdu_len < dlc_hdr_len) { // Check before accessing offset from potentially short PDU
                        LOG_ERR("DLC_RX: SN %u Segmented PDU (SI %d) too short for its header type (len %zu < %zu).",
                                sn, si, dlc_pdu_len, dlc_hdr_len);
                        goto free_mac_sdu_and_continue_rx_loop;
                    }
                    segment_offset = dlc_hdr_t13_segmented_get_offset((const dect_dlc_header_type13_segmented_t*)dlc_pdu);
                }

                if (dlc_pdu_len < dlc_hdr_len) { LOG_ERR("DLC_RX: SN %u Segment (SI %d) too short for any header.", sn, si); goto free_mac_sdu_and_continue_rx_loop; }
                segment_payload_ptr = dlc_pdu + dlc_hdr_len;
                segment_payload_len = dlc_pdu_len - dlc_hdr_len;

                LOG_DBG("DLC_RX: SN %u Segment (SI %d, Offset %u, SegLen %zu) received.", sn, si, segment_offset, segment_payload_len);

                dlc_reassembly_session_t *session = find_reassembly_session(sn);
                if (!session && si == DLC_SI_FIRST_SEGMENT) {
                    session = allocate_reassembly_session(sn, session_service_type);
                } else if (!session) {
                    LOG_WRN("DLC_RX: SN %u Segment (SI %d, Offset %u) without active session or not FIRST. Dropping.", sn, si, segment_offset);
                    goto free_mac_sdu_and_continue_rx_loop;
                }
                if (!session) { /* allocate_reassembly_session failed */ goto free_mac_sdu_and_continue_rx_loop; }

                if ((segment_offset + segment_payload_len) > DLC_REASSEMBLY_BUF_SIZE) {
                    LOG_ERR("DLC_SAR: SN %u Segment (Offset %u, Len %zu) would overflow reassembly buffer (%u). Discarding session.",
                            sn, segment_offset, segment_payload_len, DLC_REASSEMBLY_BUF_SIZE);
                    session->is_active = false; k_timer_stop(&session->timeout_timer);
                    goto free_mac_sdu_and_continue_rx_loop;
                }
                if (segment_payload_len > 0) { // Only copy and update bitmap if there's payload
                    memcpy(session->reassembly_buf + segment_offset, segment_payload_ptr, segment_payload_len);

                    uint16_t start_chunk_idx = segment_offset / DLC_REASSEMBLY_CHUNK_SIZE;
                    uint16_t end_chunk_idx_exclusive = (segment_offset + segment_payload_len + DLC_REASSEMBLY_CHUNK_SIZE - 1) / DLC_REASSEMBLY_CHUNK_SIZE;
                    
                    for (uint16_t i = start_chunk_idx; i < end_chunk_idx_exclusive && i < MAX_BITMAP_TRACKABLE_CHUNKS; i++) {
                        session->received_chunk_bitmap |= (1ULL << i);
                    }
                    if (segment_offset + segment_payload_len > session->highest_offset_received) {
                        session->highest_offset_received = segment_offset + segment_payload_len;
                    }
                }


                if (si == DLC_SI_LAST_SEGMENT) {
                    session->total_expected_sdu_len = segment_offset + segment_payload_len;
                    if (session->total_expected_sdu_len > DLC_REASSEMBLY_BUF_SIZE) {
                         LOG_ERR("DLC_SAR: SN %u LAST segment implies total_len %u > buf_size %u. Corrupted? Discarding session.",
                                 sn, session->total_expected_sdu_len, DLC_REASSEMBLY_BUF_SIZE);
                         session->is_active = false; k_timer_stop(&session->timeout_timer);
                         goto free_mac_sdu_and_continue_rx_loop;
                    }
                    if (DLC_REASSEMBLY_CHUNK_SIZE > 0) { // Avoid division by zero if chunk size is misconfigured
                        session->num_expected_chunks = (session->total_expected_sdu_len + DLC_REASSEMBLY_CHUNK_SIZE - 1) / DLC_REASSEMBLY_CHUNK_SIZE;
                        if (session->num_expected_chunks > MAX_BITMAP_TRACKABLE_CHUNKS) {
                            LOG_ERR("DLC_SAR: SN %u SDU needs %u chunks, but bitmap only tracks %u. SDU too large for current chunk/bitmap config.",
                                    sn, session->num_expected_chunks, MAX_BITMAP_TRACKABLE_CHUNKS);
                            session->is_active = false; k_timer_stop(&session->timeout_timer);
                            goto free_mac_sdu_and_continue_rx_loop;
                        }
                    } else {
                        LOG_ERR("DLC_SAR: DLC_REASSEMBLY_CHUNK_SIZE is 0. Cannot calculate expected chunks.");
                        session->is_active = false; k_timer_stop(&session->timeout_timer);
                        goto free_mac_sdu_and_continue_rx_loop;
                    }
                    LOG_DBG("DLC_SAR: SN %u LAST segment. Total SDU len: %u, NumExpectedChunks: %u",
                            sn, session->total_expected_sdu_len, session->num_expected_chunks);
                }

                bool all_chunks_received = false;
                if (session->total_expected_sdu_len > 0 && session->num_expected_chunks > 0) {
                    DLC_BITMAP_TYPE expected_bitmap_val = (session->num_expected_chunks >= MAX_BITMAP_TRACKABLE_CHUNKS) ?
                                                          ((DLC_BITMAP_TYPE)-1) : // All bits set for the type
                                                          ((1ULL << session->num_expected_chunks) - 1);
                    if ((session->received_chunk_bitmap & expected_bitmap_val) == expected_bitmap_val) {
                        // Additional check: ensure highest_offset_received matches total_expected_sdu_len
                        // This helps catch cases where bitmap might be full due to overlapping segments but actual data length is less.
                        if (session->highest_offset_received == session->total_expected_sdu_len) {
                            all_chunks_received = true;
                        } else {
                            LOG_WRN("DLC_SAR: SN %u bitmap full, but highest_offset %u != total_expected %u. Waiting.",
                                    sn, session->highest_offset_received, session->total_expected_sdu_len);
                        }
                    }
                } else if (si == DLC_SI_LAST_SEGMENT && session->total_expected_sdu_len == 0) {
                    // Case: LAST segment with zero payload, and it's the only segment.
                    all_chunks_received = true;
                }

                if (all_chunks_received) {
                    LOG_INF("DLC_SAR: Reassembly complete for SN %u, total size %u.",
                            sn, session->total_expected_sdu_len);
                    mac_sdu_t *cvg_sdu = dect_mac_api_buffer_alloc(K_NO_WAIT);
                    if (cvg_sdu) {
                        if (session->total_expected_sdu_len <= sizeof(cvg_sdu->data)) {
                            memcpy(cvg_sdu->data, session->reassembly_buf, session->total_expected_sdu_len);
                            cvg_sdu->len = session->total_expected_sdu_len;
                            // cvg_sdu->dlc_service_type = session->service_type; // If struct supports
                            k_fifo_put(&g_dlc_to_app_rx_fifo, cvg_sdu);
                        } else {
                             LOG_ERR("DLC_SAR: Reassembled SDU SN %u (len %u) too large for CVG buffer. Dropping.",
                                     sn, session->total_expected_sdu_len);
                             dect_mac_api_buffer_free(cvg_sdu);
                        }
                    } else { LOG_ERR("DLC_SAR: Failed to alloc buffer for reassembled SDU SN %u.", sn); }
                    session->is_active = false; k_timer_stop(&session->timeout_timer);
                } else if (session->is_active) { // Only restart timer if session wasn't just completed
                    k_timer_start(&session->timeout_timer, K_MSEC(DLC_REASSEMBLY_TIMEOUT_MS), K_NO_WAIT);
                }
            }
        } else {
            LOG_WRN("DLC_RX_THREAD: Unknown or unsupported DLC IE Type: 0x%X", ie_type);
        }

free_mac_sdu_and_continue_rx_loop:
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
        LOG_ERR("DLC_SEND: NULL payload with non-zero length %zu.", dlc_sdu_payload_len);
        return -EINVAL;
    }
    // Assuming CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE_CONFIG is defined in Kconfig or a header
    // This represents the max size of the *original* SDU the DLC layer can accept.
    // Individual segments sent to MAC must fit CONFIG_DECT_MAC_SDU_MAX_SIZE.
    #ifndef CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE_CONFIG
    #define CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE_CONFIG (4096) // Example fallback
    LOG_WRN("DLC_SEND: CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE_CONFIG not defined, using %d", CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE_CONFIG);
    #endif

    if (dlc_sdu_payload_len > CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE_CONFIG) {
        LOG_ERR("DLC_SEND: Original DLC SDU payload too large: %zu (max %d)",
                dlc_sdu_payload_len, CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE_CONFIG);
        return -EMSGSIZE;
    }

    mac_flow_id_t mac_qos_flow;
    // TODO: Determine if routing header is needed based on higher layer or destination.
    // If routing_header_needed is true, the dlc_sdu_payload itself would be (RoutingHdr + CVG_PDU)
    // or this layer would prepend a DLC routing header. For now, assume dlc_sdu_payload is CVG_PDU.
    bool routing_header_needed = false; // Placeholder for now
    dlc_ie_type_val_t base_ie_type; // Base IE type without extension bit
    int err = 0;
    bool needs_dlc_arq = (service == DLC_SERVICE_TYPE_2_ARQ || service == DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ);
    uint16_t current_dlc_sn_for_this_sdu = 0; // To store the SN for this SDU

    if (service != DLC_SERVICE_TYPE_0_TRANSPARENT) {
        // For services 1, 2, 3, assign/increment a 10-bit sequence number
        dlc_tx_sequence_number = (dlc_tx_sequence_number + 1) & 0x03FF;
        current_dlc_sn_for_this_sdu = dlc_tx_sequence_number;
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
            LOG_ERR("DLC_SEND_ARQ: No free retransmission jobs available. Dropping SDU SN %u.", current_dlc_sn_for_this_sdu);
            return -ENOBUFS; // Or some other error indicating resource exhaustion
        }

        arq_job = &retransmission_jobs[job_idx];
        // Allocate buffer for the ARQ job to store the original SDU
        arq_job->sdu_payload = dect_mac_api_buffer_alloc(K_NO_WAIT); // Use mac_sdu_t for convenience
        if (!arq_job->sdu_payload) {
            LOG_ERR("DLC_SEND_ARQ: Failed to allocate buffer for re-TX job SN %u. Dropping SDU.", current_dlc_sn_for_this_sdu);
            return -ENOMEM;
        }
        if (dlc_sdu_payload_len > sizeof(arq_job->sdu_payload->data)){
            LOG_ERR("DLC_SEND_ARQ: SDU too large for ARQ job buffer. SN %u", current_dlc_sn_for_this_sdu);
            dect_mac_api_buffer_free(arq_job->sdu_payload);
            arq_job->sdu_payload = NULL;
            return -EMSGSIZE;
        }

        memcpy(arq_job->sdu_payload->data, dlc_sdu_payload, dlc_sdu_payload_len);
        arq_job->sdu_payload->len = dlc_sdu_payload_len;
        arq_job->is_active = true;
        arq_job->sequence_number = current_dlc_sn_for_this_sdu;
        arq_job->retries = 0;
        arq_job->service = service;
        // Timer is started after the (last) segment is successfully queued to MAC
    }

    switch (service) {
    case DLC_SERVICE_TYPE_0_TRANSPARENT: {
        base_ie_type = routing_header_needed ? DLC_IE_TYPE_DATA_TYPE_0_WITH_ROUTING : DLC_IE_TYPE_DATA_TYPE_0_NO_ROUTING;
        // TODO: Add handling for DLC_IE_TYPE_DATA_TYPE_0_EXT_HDR if extension header is needed
        size_t hdr_len = sizeof(dect_dlc_header_type0_t);
        uint8_t hdr_buf[hdr_len];
        dlc_hdr_type0_set((dect_dlc_header_type0_t *)hdr_buf, base_ie_type);
        // For Type 0, no DLC ARQ, so no status report needed for the DLC layer itself.
        err = queue_dlc_pdu_to_mac(hdr_buf, hdr_len, dlc_sdu_payload, dlc_sdu_payload_len, MAC_FLOW_BEST_EFFORT, false, 0);
        break;
    }
    case DLC_SERVICE_TYPE_2_ARQ: {
        base_ie_type = routing_header_needed ? DLC_IE_TYPE_DATA_TYPE_123_WITH_ROUTING : DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING;
        // TODO: Add handling for DLC_IE_TYPE_DATA_TYPE_123_EXT_HDR if extension header is needed
        size_t hdr_len = sizeof(dect_dlc_header_type123_basic_t);
        if (hdr_len + dlc_sdu_payload_len > CONFIG_DECT_MAC_SDU_MAX_SIZE) {
            LOG_ERR("DLC_SEND_ARQ: SDU (SN %u) too large (%zu) for single MAC PDU (max %d for payload). Type 2 does not segment.",
                    current_dlc_sn_for_this_sdu, dlc_sdu_payload_len, CONFIG_DECT_MAC_SDU_MAX_SIZE - (int)hdr_len);
            err = -EMSGSIZE;
            break;
        }
        uint8_t hdr_buf[hdr_len];
        dlc_hdr_t123_basic_set((dect_dlc_header_type123_basic_t *)hdr_buf, base_ie_type, DLC_SI_COMPLETE_SDU, current_dlc_sn_for_this_sdu);
        // For Type 2, status report is needed for the ARQ job.
        err = queue_dlc_pdu_to_mac(hdr_buf, hdr_len, dlc_sdu_payload, dlc_sdu_payload_len, MAC_FLOW_RELIABLE_DATA, true, current_dlc_sn_for_this_sdu);
        if (err == 0 && arq_job) {
            k_timer_start(&arq_job->timeout_timer, K_MSEC(DLC_RETRANSMISSION_TIMEOUT_MS), K_NO_WAIT);
        }
        break;
    }
    case DLC_SERVICE_TYPE_1_SEGMENTATION:
    case DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ: {
        mac_qos_flow = (service == DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ) ? MAC_FLOW_RELIABLE_DATA : MAC_FLOW_BEST_EFFORT;
        base_ie_type = routing_header_needed ? DLC_IE_TYPE_DATA_TYPE_123_WITH_ROUTING : DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING;
        // TODO: Add handling for DLC_IE_TYPE_DATA_TYPE_123_EXT_HDR if extension header is needed

        size_t sent_len = 0;
        uint16_t current_segment_offset = 0;

        while (sent_len < dlc_sdu_payload_len) {
            uint8_t hdr_buf[sizeof(dect_dlc_header_type13_segmented_t)]; // Max possible DLC header for segments
            size_t current_hdr_len;
            size_t max_payload_for_this_segment;
            size_t payload_to_send_this_segment;
            dlc_segmentation_indication_t si;
            bool is_first_segment = (sent_len == 0);
            bool is_last_segment_of_sdu = false; // Flag to track if this is the final segment
            bool report_status_for_this_pdu = false;

            if (is_first_segment) {
                current_hdr_len = sizeof(dect_dlc_header_type123_basic_t); // 2 bytes
                max_payload_for_this_segment = CONFIG_DECT_MAC_SDU_MAX_SIZE - current_hdr_len;
                if (dlc_sdu_payload_len <= max_payload_for_this_segment) {
                    si = DLC_SI_COMPLETE_SDU;
                    payload_to_send_this_segment = dlc_sdu_payload_len;
                    is_last_segment_of_sdu = true;
                } else {
                    si = DLC_SI_FIRST_SEGMENT;
                    payload_to_send_this_segment = max_payload_for_this_segment;
                }
                dlc_hdr_t123_basic_set((dect_dlc_header_type123_basic_t *)hdr_buf, base_ie_type, si, current_dlc_sn_for_this_sdu);
            } else { // Middle or Last segment
                current_hdr_len = sizeof(dect_dlc_header_type13_segmented_t); // 4 bytes
                max_payload_for_this_segment = CONFIG_DECT_MAC_SDU_MAX_SIZE - current_hdr_len;
                current_segment_offset = sent_len; // Offset is where the current segment starts in original SDU

                if ((dlc_sdu_payload_len - sent_len) <= max_payload_for_this_segment) {
                    si = DLC_SI_LAST_SEGMENT;
                    payload_to_send_this_segment = dlc_sdu_payload_len - sent_len;
                    is_last_segment_of_sdu = true;
                } else {
                    si = DLC_SI_MIDDLE_SEGMENT;
                    payload_to_send_this_segment = max_payload_for_this_segment;
                }
                dlc_hdr_t13_segmented_set((dect_dlc_header_type13_segmented_t *)hdr_buf, base_ie_type, si, current_dlc_sn_for_this_sdu, current_segment_offset);
            }

            if (payload_to_send_this_segment == 0 && dlc_sdu_payload_len > 0 && !is_last_segment_of_sdu) {
                LOG_ERR("DLC_SEND_SEG: Max payload for segment is 0. MAC SDU size %d too small for headers (len %zu). SDU SN %u.",
                        CONFIG_DECT_MAC_SDU_MAX_SIZE, current_hdr_len, current_dlc_sn_for_this_sdu);
                err = -EMSGSIZE;
                break;
            }
             if (payload_to_send_this_segment > (dlc_sdu_payload_len - sent_len) ) {
                 payload_to_send_this_segment = dlc_sdu_payload_len - sent_len;
            }

            // For ARQ services (Type 3), request MAC status report only for the last segment of the SDU
            if (needs_dlc_arq && is_last_segment_of_sdu) {
                report_status_for_this_pdu = true;
            }

            LOG_DBG("DLC_SEND_SEG: SN %u, SI %d, Offset %u, SegPyldLen %zu, HdrLen %zu, Report %d",
                    current_dlc_sn_for_this_sdu, si, (is_first_segment || si == DLC_SI_COMPLETE_SDU) ? 0 : current_segment_offset,
                    payload_to_send_this_segment, current_hdr_len, report_status_for_this_pdu);

            err = queue_dlc_pdu_to_mac(hdr_buf, current_hdr_len,
                                       dlc_sdu_payload + sent_len, payload_to_send_this_segment,
                                       mac_qos_flow, report_status_for_this_pdu, current_dlc_sn_for_this_sdu);
            if (err) {
                LOG_ERR("DLC_SEND_SEG: Failed to queue segment (err %d). Aborting send of SN %u.", err, current_dlc_sn_for_this_sdu);
                break; 
            }
            sent_len += payload_to_send_this_segment;

            if (is_last_segment_of_sdu && err == 0 && arq_job) { // If it was the last segment and successfully queued
                k_timer_start(&arq_job->timeout_timer, K_MSEC(DLC_RETRANSMISSION_TIMEOUT_MS), K_NO_WAIT);
            }
        }
        break;
    }
    default:
        LOG_ERR("DLC_SEND: Unknown DLC service type %d", service);
        err = -EINVAL; // Set error if not already set by a failed segmentation
        break;
    }

    if (err && arq_job) { // If any error occurred during sending/segmentation for an ARQ service
        LOG_WRN("DLC_SEND: Cleaning up ARQ job for SN %u due to send error %d.", current_dlc_sn_for_this_sdu, err);
        k_timer_stop(&arq_job->timeout_timer); // Stop timer if it was started
        if (arq_job->sdu_payload) { // Check if buffer was allocated
            dect_mac_api_buffer_free(arq_job->sdu_payload);
            arq_job->sdu_payload = NULL;
        }
        arq_job->is_active = false;
    } else if (!err && arq_job && service == DLC_SERVICE_TYPE_2_ARQ) {
        // For non-segmented ARQ (Type 2), timer was started if queue_dlc_pdu_to_mac was successful.
        // No explicit action here, already handled in its case.
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