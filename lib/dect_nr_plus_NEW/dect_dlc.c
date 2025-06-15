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
// REASSEMBLY_BUF_SIZE should be large enough for the largest possible *CVG PDU* after reassembly.
// This is a placeholder size. A real system would need this configurable or dynamically sized.
#define DLC_REASSEMBLY_BUF_SIZE (CONFIG_DECT_MAC_SDU_MAX_SIZE * 4) // Example: Can reassemble up to ~4 MAC SDUs
#define DLC_REASSEMBLY_TIMEOUT_MS 5000

// Sequence number for DLC Service Types 1, 2, 3 (10-bit)
static uint16_t dlc_tx_sequence_number = 0; // Per DLC entity set, or global if only one logical link active

typedef struct {
    bool is_active;
    uint16_t sequence_number;       // SN of the DLC SDU (CVG PDU) being reassembled
    uint8_t reassembly_buf[DLC_REASSEMBLY_BUF_SIZE];
    size_t current_len;             // Current total length of data in reassembly_buf (may have gaps)
    size_t expected_total_len;      // Expected total length if known (e.g. from first segment if supported)
    // uint32_t received_segments_map; // Bitmap for tracking received segments for a given SN
    struct k_timer timeout_timer;   // Renamed from "timeout" to avoid conflict
    dlc_service_type_t service_type;// Service type of the SDU being reassembled
    // uint32_t source_rd_id;       // If needed to distinguish sessions from multiple MAC peers
} dlc_reassembly_session_t;

static dlc_reassembly_session_t reassembly_sessions[MAX_DLC_REASSEMBLY_SESSIONS];

// FIFO for MAC SDUs (containing DLC PDUs) received from MAC layer, to be processed by dlc_rx_thread
K_FIFO_DEFINE(g_dlc_internal_mac_rx_fifo);
// FIFO for fully reassembled DLC SDUs (CVG PDUs) to be passed to the application layer
K_FIFO_DEFINE(g_dlc_to_app_rx_fifo);


// --- Forward Declarations ---
static void dlc_reassembly_timeout_handler(struct k_timer *timer_id);
static void dlc_rx_thread_entry(void *p1, void *p2, void *p3);

// --- DLC RX Thread for Reassembly and ARQ (if implemented) ---
K_THREAD_DEFINE(g_dlc_rx_thread_id, CONFIG_DECT_DLC_RX_THREAD_STACK_SIZE,
                dlc_rx_thread_entry, NULL, NULL, NULL,
                CONFIG_DECT_DLC_RX_THREAD_PRIORITY, 0, 0);


static void dlc_rx_thread_entry(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
    LOG_INF("DLC RX Thread started.");

    while (1) {
        mac_sdu_t *mac_sdu_from_mac = k_fifo_get(&g_dlc_internal_mac_rx_fifo, K_FOREVER);
        if (!mac_sdu_from_mac) {
            continue; // Should not happen with K_FOREVER unless FIFO is flushed/cancelled
        }

        if (mac_sdu_from_mac->len == 0) {
            LOG_WRN("DLC_RX_THREAD: Received empty MAC SDU from MAC layer.");
            dect_mac_api_buffer_free(mac_sdu_from_mac);
            continue;
        }

        // The mac_sdu_from_mac->data contains a full DLC PDU (DLC Header + DLC SDU Payload)
        const uint8_t *dlc_pdu_start = mac_sdu_from_mac->data;
        size_t dlc_pdu_total_len = mac_sdu_from_mac->len;

        dlc_ie_type_val_t dlc_ie_type;
        const uint8_t *dlc_sdu_payload_ptr = NULL; // Points to start of CVG PDU (or segment)
        size_t dlc_sdu_payload_len = 0;
        // dlc_service_type_t effective_service_type = DLC_SERVICE_TYPE_0_TRANSPARENT; // Placeholder

        // --- Parse DLC Header ---
        // Assuming first byte contains IE type in MSB 4 bits for all relevant types
        dlc_ie_type = (dlc_ie_type_val_t)((dlc_pdu_start[0] >> 4) & 0x0F);

        if (dlc_ie_type == DLC_IE_TYPE_DATA_TYPE_0_NO_ROUTING ||
            dlc_ie_type == DLC_IE_TYPE_DATA_TYPE_0_WITH_ROUTING ||
            dlc_ie_type == DLC_IE_TYPE_DATA_TYPE_0_EXT_HDR) {
            // Service Type 0: Transparent
            if (dlc_pdu_total_len < sizeof(dect_dlc_header_type0_t)) {
                LOG_ERR("DLC_RX_THREAD: Type 0 PDU too short (%zu) for header.", dlc_pdu_total_len);
                dect_mac_api_buffer_free(mac_sdu_from_mac);
                continue;
            }
            dlc_sdu_payload_ptr = dlc_pdu_start + sizeof(dect_dlc_header_type0_t);
            dlc_sdu_payload_len = dlc_pdu_total_len - sizeof(dect_dlc_header_type0_t);
            // effective_service_type = DLC_SERVICE_TYPE_0_TRANSPARENT; // Handled by dlc_receive_data now

            // For Type 0, pass directly to application if payload exists
            if (dlc_sdu_payload_len > 0) {
                mac_sdu_t* app_sdu_buf = dect_mac_api_buffer_alloc(K_NO_WAIT);
                if (app_sdu_buf) {
                    if (dlc_sdu_payload_len <= CONFIG_DECT_MAC_SDU_MAX_SIZE) { // Max app SDU size
                        app_sdu_buf->len = dlc_sdu_payload_len;
                        memcpy(app_sdu_buf->data, dlc_sdu_payload_ptr, app_sdu_buf->len);
                        // TODO: Need to associate service type with this buffer for dlc_receive_data()
                        // For now, dlc_receive_data() assumes type 0 if it gets from this path.
                        // Or, the FIFO item needs to be a struct {mac_sdu_t*, dlc_service_type_t}.
                        k_fifo_put(&g_dlc_to_app_rx_fifo, app_sdu_buf);
                    } else { /* Error handling */ dect_mac_api_buffer_free(app_sdu_buf); }
                } else { /* Error handling */ }
            }

        } else if (dlc_ie_type == DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING ||
                   dlc_ie_type == DLC_IE_TYPE_DATA_TYPE_123_WITH_ROUTING ||
                   dlc_ie_type == DLC_IE_TYPE_DATA_TYPE_123_EXT_HDR) {
            // Service Type 1, 2, or 3 (Segmentation and/or ARQ)
            // CRITICAL TODO: Implement full Segmentation and Reassembly (SAR) logic here.
            // This involves:
            // 1. Parsing basic or segmented header to get SI, SN, Segmentation Offset.
            // 2. Finding or creating a reassembly_session_t based on SN (and source RD ID if multi-peer).
            // 3. If FIRST_SEGMENT: Initialize session, start reassembly timer.
            // 4. If MIDDLE/LAST: Append data to reassembly_buf, check for completeness.
            // 5. If COMPLETE SDU (SI=00 or reassembly finishes): Pass to g_dlc_to_app_rx_fifo. Reset timer.
            // 6. If LAST_SEGMENT and reassembly finishes: Pass to app. Reset timer.
            // 7. If reassembly_sessions[i].timeout_timer expires: Discard session.
            // 8. Handle DLC ARQ (ACK/NACK) for Type 2/3.

            LOG_WRN("DLC_RX_THREAD: Segmentation/Reassembly for Type 1/2/3 not fully implemented. Passing through if complete SDU.");
            const dect_dlc_header_type123_basic_t *hdr123 = (const dect_dlc_header_type123_basic_t*)dlc_pdu_start;
            if (dlc_pdu_total_len < sizeof(dect_dlc_header_type123_basic_t)) { /* error */ dect_mac_api_buffer_free(mac_sdu_from_mac); continue; }

            dlc_segmentation_indication_t si = dlc_hdr_t123_basic_get_si(hdr123);
            // uint16_t sn = dlc_hdr_t123_basic_get_sn(hdr123);

            if (si == DLC_SI_COMPLETE_SDU) {
                dlc_sdu_payload_ptr = dlc_pdu_start + sizeof(dect_dlc_header_type123_basic_t);
                dlc_sdu_payload_len = dlc_pdu_total_len - sizeof(dect_dlc_header_type123_basic_t);
                if (dlc_sdu_payload_len > 0) {
                     mac_sdu_t* app_sdu_buf = dect_mac_api_buffer_alloc(K_NO_WAIT);
                     /* ... (copy and queue to g_dlc_to_app_rx_fifo as for Type 0) ... */
                     if (app_sdu_buf) { /* ... */ dect_mac_api_buffer_free(app_sdu_buf); } // Temp if not queued
                }
            } else {
                // TODO: Handle FIRST, MIDDLE, LAST segments for reassembly
                LOG_INF("DLC_RX_THREAD: Received segmented PDU (SI=%d, SN=%u) - reassembly TODO.", si, dlc_hdr_t123_basic_get_sn(hdr123));
            }
        } else {
            LOG_ERR("DLC_RX_THREAD: Unknown or unsupported DLC IE Type: 0x%X", dlc_ie_type);
        }
        dect_mac_api_buffer_free(mac_sdu_from_mac);
    }
}


// --- Public API Implementation ---
int dect_stack_init(dect_mac_role_t role, uint32_t provisioned_long_rd_id)
{
    int err;
    LOG_INF("Initializing DECT Stack (DLC & MAC)... Role: %s", (role == MAC_ROLE_PT ? "PT" : "FT"));

    // Initialize MAC API first (provides SDU buffers and TX FIFOs to MAC, registers DLC RX FIFO)
    err = dect_mac_api_init(&g_dlc_internal_mac_rx_fifo);
    if (err) {
        LOG_ERR("Failed to initialize MAC API: %d", err);
        return err;
    }

    // Initialize MAC Core (sets up context, IDs, default configs, timers, HARQ processes via data_path_init)
    err = dect_mac_core_init(role, provisioned_long_rd_id);
    if (err) {
        LOG_ERR("Failed to initialize MAC Core: %d", err);
        // No specific deinit for mac_api if core_init fails before SMs start using it.
        return err;
    }

    // Initialize reassembly sessions and their timers
    for (int i=0; i < MAX_DLC_REASSEMBLY_SESSIONS; i++) {
        k_timer_init(&reassembly_sessions[i].timeout_timer, dlc_reassembly_timeout_handler, NULL);
        reassembly_sessions[i].timeout_timer.user_data = (void*)((uintptr_t)i); // Pass session index
        reassembly_sessions[i].is_active = false;
    }

    // Start the DLC RX thread (if not already auto-started by K_THREAD_DEFINE)
    // k_thread_name_set(g_dlc_rx_thread_id, "dect_dlc_rx"); // Name set by K_THREAD_DEFINE

    LOG_INF("DECT Stack Initialized successfully.");
    return 0;
}

int dlc_send_data(dlc_service_type_t service, const uint8_t *dlc_sdu_payload, size_t dlc_sdu_payload_len)
{
    if (dlc_sdu_payload == NULL && dlc_sdu_payload_len > 0) {
        LOG_ERR("DLC_SEND: NULL payload with non-zero length.");
        return -EINVAL;
    }
    if (dlc_sdu_payload_len > CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE) { // Need this Kconfig
        LOG_ERR("DLC_SEND: DLC SDU payload too large: %zu (max %d)", dlc_sdu_payload_len, CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE);
        return -EMSGSIZE;
    }


    uint8_t dlc_header_buf[4]; // Max DLC header size (Type 1/3 segmented)
    size_t dlc_header_actual_len = 0;
    mac_flow_id_t mac_qos_flow;
    dlc_ie_type_val_t ie_type_to_use; // Assuming NO_ROUTING for now.

    switch (service) {
        case DLC_SERVICE_TYPE_0_TRANSPARENT:
        {
            dect_dlc_header_type0_t hdr0;
            dlc_hdr_type0_set(&hdr0, DLC_IE_TYPE_DATA_TYPE_0_NO_ROUTING); // Assume no routing for now
            memcpy(dlc_header_buf, &hdr0, sizeof(hdr0));
            dlc_header_actual_len = sizeof(hdr0);
            mac_qos_flow = MAC_FLOW_BEST_EFFORT; // Or configurable
            break;
        }
        case DLC_SERVICE_TYPE_1_SEGMENTATION: // Fallthrough for header
        case DLC_SERVICE_TYPE_2_ARQ:
        case DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ:
        {
            // CRITICAL TODO: Full Segmentation Logic for Type 1 & 3
            // This simplified version assumes the payload fits in one DLC PDU (MAC SDU).
            size_t required_dlc_pdu_len_unsegmented = sizeof(dect_dlc_header_type123_basic_t) + dlc_sdu_payload_len;
            if (required_dlc_pdu_len_unsegmented > CONFIG_DECT_MAC_SDU_MAX_SIZE) {
                if (service == DLC_SERVICE_TYPE_1_SEGMENTATION || service == DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ) {
                    LOG_WRN("DLC_SEND: Payload len %zu requires DLC segmentation; NOT YET IMPLEMENTED. Dropping.", dlc_sdu_payload_len);
                    return -EMSGSIZE; // Indicate failure due to size and lack of SAR
                } else { // Type 2 ARQ (no segmentation by DLC spec)
                    LOG_ERR("DLC_SEND: Payload len %zu too large for unsegmented DLC Service Type 2 (max MAC SDU payload %d).",
                            dlc_sdu_payload_len, (int)(CONFIG_DECT_MAC_SDU_MAX_SIZE - sizeof(dect_dlc_header_type123_basic_t)));
                    return -EMSGSIZE;
                }
            }

            dect_dlc_header_type123_basic_t hdr123_basic;
            ie_type_to_use = DLC_IE_TYPE_DATA_TYPE_123_NO_ROUTING; // Assume no routing
            dlc_tx_sequence_number = (dlc_tx_sequence_number + 1) & 0x03FF; // 10-bit SN wrap
            dlc_hdr_t123_basic_set(&hdr123_basic, ie_type_to_use, DLC_SI_COMPLETE_SDU, dlc_tx_sequence_number);
            memcpy(dlc_header_buf, &hdr123_basic, sizeof(hdr123_basic));
            dlc_header_actual_len = sizeof(hdr123_basic);

            if (service == DLC_SERVICE_TYPE_2_ARQ || service == DLC_SERVICE_TYPE_3_SEGMENTATION_ARQ) {
                mac_qos_flow = MAC_FLOW_RELIABLE_DATA;
            } else { // Type 1
                mac_qos_flow = MAC_FLOW_BEST_EFFORT;
            }
            break;
        }
        default:
            LOG_ERR("DLC_SEND: Unknown DLC service type %d", service);
            return -EINVAL;
    }

    // Total DLC PDU length = DLC header + DLC SDU payload (CVG PDU)
    size_t total_dlc_pdu_len = dlc_header_actual_len + dlc_sdu_payload_len;
    if (total_dlc_pdu_len > CONFIG_DECT_MAC_SDU_MAX_SIZE) {
        // This check should ideally be redundant if segmentation check above is robust
        LOG_ERR("DLC_SEND: Total DLC PDU size %zu exceeds MAC SDU capacity %d.",
                total_dlc_pdu_len, CONFIG_DECT_MAC_SDU_MAX_SIZE);
        return -EMSGSIZE;
    }

    mac_sdu_t *mac_sdu_to_send = dect_mac_api_buffer_alloc(K_MSEC(10)); // Short timeout for buffer
    if (!mac_sdu_to_send) {
        LOG_ERR("DLC_SEND: Failed to allocate MAC SDU buffer for TX.");
        return -ENOMEM;
    }

    memcpy(mac_sdu_to_send->data, dlc_header_buf, dlc_header_actual_len);
    if (dlc_sdu_payload && dlc_sdu_payload_len > 0) {
        memcpy(mac_sdu_to_send->data + dlc_header_actual_len, dlc_sdu_payload, dlc_sdu_payload_len);
    }
    mac_sdu_to_send->len = total_dlc_pdu_len;
    // mac_sdu_to_send->target_peer_short_rd_id is set by FT API or implicitly handled for PT

    LOG_DBG("DLC_SEND: Queuing DLC PDU (MAC SDU len %u) for Svc %d, SN %u, MAC QoS %d",
            mac_sdu_to_send->len, service, dlc_tx_sequence_number, mac_qos_flow);

    dect_mac_context_t *ctx = get_mac_context(); // To check role for send API
    if (ctx->role == MAC_ROLE_FT) {
        // FT needs to specify target PT. This API doesn't take it.
        // This implies dlc_send_data on FT is for data originating *from* the FT itself to a PT,
        // and that PT must be implicitly known or broadcast (not supported by this send).
        // Solution: dlc_send_data needs target_pt_short_id if FT.
        // For now, FT cannot use this generic dlc_send_data effectively for specific PTs.
        // It would use dect_mac_api_ft_send_to_pt directly or a new dlc_ft_send_to_pt.
        // Let's assume for now FT data is broadcast-like or not targeted by this simple API.
        LOG_WRN("DLC_SEND: FT role using generic dlc_send_data. Target PT not specified. Sending via generic MAC API.");
        return dect_mac_api_send(mac_sdu_to_send, mac_qos_flow); // This will fail in dect_mac_api_send if FT
    } else { // PT role
        return dect_mac_api_send(mac_sdu_to_send, mac_qos_flow);
    }
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