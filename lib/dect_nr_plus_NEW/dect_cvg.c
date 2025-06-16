/* dect_cvg/dect_cvg.c */

#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <string.h>

#include "dect_cvg.h"
#include "dect_dlc.h" // For dlc_send_data() and dlc_receive_data()
#include "dect_mac_api.h" // For mac_sdu_t definition and buffer management

LOG_MODULE_REGISTER(dect_cvg, CONFIG_DECT_CVG_LOG_LEVEL);

#define CVG_MAX_IN_FLIGHT_SDUS 16 // Should be >= max_window_size

// --- CVG Internal FIFOs and Buffers ---
/**
 * @brief Context for a single CVG data flow.
 *
 * For now, we only have one logical flow. In the future, this would be an array
 * or list, indexed by an endpoint multiplexer value.
 */
typedef struct {
    // Common
    cvg_service_type_t service_type;
    bool is_configured;

    // TX side (sliding window)
    uint16_t tx_sequence_number;        // Next SN to be used
    uint16_t tx_window_start_sn;        // Marker A: Oldest un-acked SDU
    uint16_t tx_window_end_sn;          // Marker B: SN of newest sent SDU + 1
    uint16_t max_window_size;           // W_MAX for this flow
    struct k_sem tx_window_sem;         // Semaphore to block TX thread when window is full
    mac_sdu_t *tx_in_flight_sdu[CVG_MAX_IN_FLIGHT_SDUS]; // Buffer for retransmissions
    
    // RX side
    uint16_t rx_expected_sn;            // Next in-sequence SDU we are waiting for
    uint16_t last_ack_sent_sn;          // Marker C: Last ACK we sent
    // TODO: Add buffer for out-of-order RX packets

} cvg_flow_context_t;

static cvg_flow_context_t g_default_cvg_flow_ctx;

// This buffer pool is for application data passed to/from the CVG layer.
// It uses the same mac_sdu_t structure for convenience, as its size is well-defined
// and it can be allocated/freed with the existing MAC API buffer functions.
#define CVG_APP_BUFFER_COUNT 8
K_MEM_SLAB_DEFINE(g_cvg_app_sdu_slab, sizeof(mac_sdu_t), CVG_APP_BUFFER_COUNT, 4);

// FIFO for App -> CVG TX Thread communication
K_FIFO_DEFINE(g_app_to_cvg_tx_fifo);

// FIFO for CVG RX Thread -> App communication
K_FIFO_DEFINE(g_cvg_to_app_rx_fifo);

// The TX FIFO now needs to hold more than just the SDU buffer.
// It needs to know which service the application requested.
typedef struct {
    void *fifo_reserved;
    cvg_service_type_t service_type;
    mac_sdu_t *app_sdu_buf;
} cvg_tx_queue_item_t;

K_MEM_SLAB_DEFINE(g_cvg_tx_item_slab, sizeof(cvg_tx_queue_item_t), CVG_APP_BUFFER_COUNT, 4);


// --- Forward Declarations for Threads ---
static void cvg_tx_thread_entry(void *p1, void *p2, void *p3);
static void cvg_rx_thread_entry(void *p1, void *p2, void *p3);

// --- CVG Layer Threads ---
K_THREAD_DEFINE(g_cvg_tx_thread_id, CONFIG_DECT_CVG_TX_THREAD_STACK_SIZE,
                cvg_tx_thread_entry, NULL, NULL, NULL,
                CONFIG_DECT_CVG_TX_THREAD_PRIORITY, 0, 0);

K_THREAD_DEFINE(g_cvg_rx_thread_id, CONFIG_DECT_CVG_RX_THREAD_STACK_SIZE,
                cvg_rx_thread_entry, NULL, NULL, NULL,
                CONFIG_DECT_CVG_RX_THREAD_PRIORITY, 0, 0);


/**
 * @brief Builds a complete CVG PDU for a transparent service.
 *
 * Wraps the application payload in a CVG Header and a Data Transparent IE.
 *
 * @param target_buf Buffer to store the resulting CVG PDU.
 * @param target_buf_len Max size of the target buffer.
 * @param app_payload The raw application data.
 * @param app_payload_len Length of the application data.
 * @return The total length of the generated CVG PDU, or a negative error code.
 */
static int build_cvg_transparent_pdu(uint8_t *target_buf, size_t target_buf_len,
                                     const uint8_t *app_payload, size_t app_payload_len)
{
    // For a Data Transparent IE, the simplest header is Format 1 (MT=0) with a length field.
    // CVG Header: Octet 1: [CVG_Ext (2b) | MT (1b) | IE Type (5b)]
    // We will use CVG_Ext=01 (8-bit len) or 10 (16-bit len)
    // and IE Type = CVG_IE_TYPE_DATA_TRANSPARENT.

    size_t header_len;
    cvg_header_ext_len_t len_type;

    if (app_payload_len <= 255) {
        header_len = 2; // CVG Header (1) + 8-bit length (1)
        len_type = CVG_EXT_8BIT_LEN_FIELD;
    } else {
        header_len = 3; // CVG Header (1) + 16-bit length (1)
        len_type = CVG_EXT_16BIT_LEN_FIELD;
    }

    if (header_len + app_payload_len > target_buf_len) {
        return -ENOMEM;
    }

    // Build the header
    uint8_t mt_bit = 0; // Format 1
    target_buf[0] = ((len_type & 0x03) << 6) | ((mt_bit & 0x01) << 5) | (CVG_IE_TYPE_DATA_TRANSPARENT & 0x1F);

    if (len_type == CVG_EXT_8BIT_LEN_FIELD) {
        target_buf[1] = (uint8_t)app_payload_len;
    } else {
        sys_put_be16(app_payload_len, &target_buf[1]);
    }

    // Copy the payload
    if (app_payload && app_payload_len > 0) {
        memcpy(target_buf + header_len, app_payload, app_payload_len);
    }

    return header_len + app_payload_len;
}

/**
 * @brief Builds a complete CVG PDU for a sequenced service (Type 1).
 *
 * Wraps the application payload in a CVG Header and a Data IE.
 */
static int build_cvg_data_ie_pdu(uint8_t *target_buf, size_t target_buf_len,
                                 const uint8_t *app_payload, size_t app_payload_len,
                                 uint16_t sequence_number)
{
    // A Data IE requires its own CVG Header.
    cvg_header_t cvg_hdr;
    // For simplicity, we use Format 1 (MT=0) with no length field (Ext=00),
    // as the length is defined by the underlying DLC PDU.
    cvg_hdr.ext_mt_f2c_or_type = ((CVG_EXT_NO_LEN_FIELD & 0x03) << 6) |
                                 ((0 & 0x01) << 5) | // MT bit = 0
                                 (CVG_IE_TYPE_DATA & 0x1F);

    // Then, the Data IE base follows
    cvg_ie_data_base_t data_ie_base;
    cvg_ie_data_base_set(&data_ie_base, CVG_SI_COMPLETE_SDU, false, sequence_number);

    size_t total_hdr_len = sizeof(cvg_hdr) + sizeof(data_ie_base);
    if (total_hdr_len + app_payload_len > target_buf_len) {
        return -ENOMEM;
    }

    memcpy(target_buf, &cvg_hdr, sizeof(cvg_hdr));
    memcpy(target_buf + sizeof(cvg_hdr), &data_ie_base, sizeof(data_ie_base));

    if (app_payload && app_payload_len > 0) {
        memcpy(target_buf + total_hdr_len, app_payload, app_payload_len);
    }

    return total_hdr_len + app_payload_len;
}

/**
 * @brief Builds and sends a CVG ARQ Feedback IE.
 *
 * @param ack True for ACK, false for NACK.
 * @param feedback_info_code The 3-bit feedback info code (e.g., complete SDU, range).
 * @param sn The sequence number the feedback refers to.
 * @return 0 on success, or a negative error code.
 */
static int send_cvg_arq_feedback(bool ack, uint8_t feedback_info_code, uint16_t sn)
{
    uint8_t pdu_buf[sizeof(cvg_ie_arq_feedback_base_t)]; // Format 1 is 3 bytes total
    size_t pdu_len = sizeof(pdu_buf);

    // Build CVG Header
    cvg_header_t cvg_hdr;
    cvg_hdr.ext_mt_f2c_or_type = ((CVG_EXT_NO_LEN_FIELD & 0x03) << 6) |
                                 ((0 & 0x01) << 5) | // MT bit = 0
                                 (CVG_IE_TYPE_ARQ_FEEDBACK & 0x1F);
    memcpy(pdu_buf, &cvg_hdr, sizeof(cvg_hdr));

    // Build ARQ Feedback Base
    cvg_ie_arq_feedback_base_t *fb_base = (cvg_ie_arq_feedback_base_t *)(pdu_buf);
    uint8_t an_bit = ack ? 0 : 1; // 0=ACK, 1=NACK
    fb_base->an_fbinfo_sn_msb = ((an_bit & 0x01) << 7) |
                                ((feedback_info_code & 0x07) << 4) |
                                ((uint8_t)(sn >> 8) & 0x0F);
    fb_base->sequence_number_lsb = (uint8_t)(sn & 0xFF);

    LOG_DBG("CVG_ARQ_TX: Sending %s for SN %u (fb_info %u).", ack ? "ACK" : "NACK", sn, feedback_info_code);

    // Send the PDU to DLC. This is control traffic, might use a higher priority flow eventually.
    return dlc_send_data(DLC_SERVICE_TYPE_0_TRANSPARENT, pdu_buf, pdu_len);
}


/**
 * @brief CVG Transmit Thread.
 *
 * Waits for data from the application, wraps it in a CVG PDU, and passes it to the DLC layer.
 */
static void cvg_tx_thread_entry(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
    LOG_INF("CVG TX Thread started.");

    uint8_t cvg_pdu_buf[CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE];

    while (1) {
        cvg_tx_queue_item_t *tx_item = k_fifo_get(&g_app_to_cvg_tx_fifo, K_FOREVER);
        if (!tx_item) {
            continue;
        }

        cvg_service_type_t service = g_default_cvg_flow_ctx.service_type;
        mac_sdu_t *app_sdu = tx_item->app_sdu_buf;
        int cvg_pdu_len = 0;
        int err = 0;
        uint16_t current_sn = 0;
        bool is_reliable_service = (service >= CVG_SERVICE_TYPE_3_FC);

        if (is_reliable_service) {
            // --- FLOW CONTROL: Wait for the window to have space ---
            // This call will block if the number of in-flight SDUs has reached the window size.
            // The semaphore is given back by the RX thread when an ACK is processed.
            LOG_DBG("CVG_FC: Waiting for TX window (current available: %d)",
                    k_sem_count_get(&g_default_cvg_flow_ctx.tx_window_sem));
            k_sem_take(&g_default_cvg_flow_ctx.tx_window_sem, K_FOREVER);
            LOG_DBG("CVG_FC: TX window available. Proceeding with send.");
        }

        // Use the service type from the flow context, not the one from the queue item,
        // as the flow must be pre-configured.
        switch (service) {
        case CVG_SERVICE_TYPE_0_TRANSPARENT:
            cvg_pdu_len = build_cvg_transparent_pdu(cvg_pdu_buf, sizeof(cvg_pdu_buf),
                                                    app_sdu->data, app_sdu->len);
            break;

        case CVG_SERVICE_TYPE_1_SEQ_NUM:
        case CVG_SERVICE_TYPE_3_FC:
        case CVG_SERVICE_TYPE_4_FC_ARQ: // Also uses Data IE
            current_sn = g_default_cvg_flow_ctx.tx_sequence_number;
            cvg_pdu_len = build_cvg_data_ie_pdu(cvg_pdu_buf, sizeof(cvg_pdu_buf),
                                                app_sdu->data, app_sdu->len,
                                                current_sn);
            break;

        default:
            LOG_WRN("CVG_TX: Configured service type %d is not yet supported for sending.", service);
            err = -ENOTSUP;
            break;
        }

        if (cvg_pdu_len > 0) {
            // Send the complete CVG PDU to the DLC layer.
            // For now, we use a simple, unreliable DLC service.
            // A real implementation might select a DLC service based on the CVG service.
            err = dlc_send_data(DLC_SERVICE_TYPE_0_TRANSPARENT, cvg_pdu_buf, cvg_pdu_len);
        } else if (err == 0) { // If no PDU was built but no error was set
            err = -EINVAL;
        }

        if (err == 0) {
            LOG_DBG("CVG_TX: Queued CVG PDU (len %d, svc %d) to DLC.", cvg_pdu_len, service);
            if (is_reliable_service) {
                // Store the SDU in the in-flight buffer, indexed by its sequence number.
                uint16_t buffer_index = current_sn % CVG_MAX_IN_FLIGHT_SDUS;
                if (g_default_cvg_flow_ctx.tx_in_flight_sdu[buffer_index] != NULL) {
                    // This should not happen if window size is respected. It means we wrapped
                    // around the buffer before the old packet was ACKed.
                    LOG_ERR("CVG_FC: In-flight buffer overwrite at index %u for SN %u! Freeing old packet.",
                            buffer_index, current_sn);
                    dect_mac_api_buffer_free(g_default_cvg_flow_ctx.tx_in_flight_sdu[buffer_index]);
                }
                g_default_cvg_flow_ctx.tx_in_flight_sdu[buffer_index] = app_sdu;
                // Update window markers
                g_default_cvg_flow_ctx.tx_sequence_number = (current_sn + 1) & 0x0FFF;
                g_default_cvg_flow_ctx.tx_window_end_sn = g_default_cvg_flow_ctx.tx_sequence_number;
            } else {
                // For unreliable services, we don't need the buffer after sending.
                k_mem_slab_free(&g_cvg_app_sdu_slab, (void **)&app_sdu);
            }
        } else {
            LOG_ERR("CVG_TX: Failed to build or send CVG PDU for service %d: %d", service, err);
            // Free the buffer as it was not sent or stored for re-TX.
            k_mem_slab_free(&g_cvg_app_sdu_slab, (void **)&app_sdu);
            if (is_reliable_service) {
                // Give back the semaphore since the send failed.
                k_sem_give(&g_default_cvg_flow_ctx.tx_window_sem);
            }
        }

        // Free the TX queue item wrapper in all cases.
        k_mem_slab_free(&g_cvg_tx_item_slab, (void **)&tx_item);
    }
}


/**
 * @brief CVG Receive Thread.
 *
 * Waits for data from the DLC layer, parses the CVG PDU, and passes the application
 * payload up to the application via a FIFO.
 */
static void cvg_rx_thread_entry(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
    LOG_INF("CVG RX Thread started.");

    uint8_t dlc_sdu_buf[CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE];

    while(1) {
        dlc_service_type_t service_type; // From DLC, currently unused
        size_t dlc_sdu_len = sizeof(dlc_sdu_buf);
        int err = dlc_receive_data(&service_type, dlc_sdu_buf, &dlc_sdu_len, K_FOREVER);
        if (err) {
            LOG_WRN("CVG_RX: dlc_receive_data failed: %d", err);
            continue;
        }

        const cvg_header_t *hdr = (const cvg_header_t *)dlc_sdu_buf;
        uint8_t mt_bit = (hdr->ext_mt_f2c_or_type >> 5) & 0x01;
        cvg_ie_type_t ie_type;

        if (mt_bit == 0) { // Format 1
            ie_type = (cvg_ie_type_t)(hdr->ext_mt_f2c_or_type & 0x1F);
        } else { // Format 2
            // TODO: Handle Format 2 parsing logic
            LOG_WRN("CVG_RX: Unhandled CVG Header Format 2.");
            continue;
        }


        if (ie_type == CVG_IE_TYPE_DATA || ie_type == CVG_IE_TYPE_DATA_EP) {
            // This is a sequenced or flow-controlled data packet
            const cvg_ie_data_base_t *data_base = (const cvg_ie_data_base_t *)(dlc_sdu_buf + sizeof(cvg_header_t));
            uint16_t sn = cvg_ie_data_base_get_sn(data_base);
            cvg_segmentation_indication_t si = cvg_ie_data_base_get_si(data_base);

            // TODO: Full SAR and out-of-order buffering logic required here.
            // For now, we only process complete SDUs that arrive in sequence.
            if (si == CVG_SI_COMPLETE_SDU && sn == g_default_cvg_flow_ctx.rx_expected_sn) {
                g_default_cvg_flow_ctx.rx_expected_sn = (sn + 1) & 0x0FFF;

                size_t header_len = sizeof(cvg_header_t) + sizeof(cvg_ie_data_base_t);
                size_t payload_len = dlc_sdu_len - header_len;

                // Pass payload to application
                mac_sdu_t *app_sdu = NULL;
                if (k_mem_slab_alloc(&g_cvg_app_sdu_slab, (void **)&app_sdu, K_NO_WAIT) == 0) {
                    memcpy(app_sdu->data, (uint8_t*)data_base + sizeof(cvg_ie_data_base_t), payload_len);
                    app_sdu->len = payload_len;
                    k_fifo_put(&g_cvg_to_app_rx_fifo, app_sdu);
                } else {
                    LOG_ERR("CVG_RX: Failed to alloc buffer for app delivery.");
                }

                // If this is a flow-controlled service, send an ACK.
                // We send an ACK for the newly expected SN-1, which is the one we just received.
                if (g_default_cvg_flow_ctx.service_type >= CVG_SERVICE_TYPE_3_FC) {
                    // ETSI 6.2.9.3: ACK is sent for the highest in-sequence SN.
                    // To avoid sending an ACK for every single packet, a real implementation
                    // would use a timer or a counter. For now, we ACK every packet for simplicity.
                    uint16_t ack_sn = (g_default_cvg_flow_ctx.rx_expected_sn - 1) & 0x0FFF;
                    send_cvg_arq_feedback(true, 0b000, ack_sn); // 000 = "A complete SDU"
                    g_default_cvg_flow_ctx.last_ack_sent_sn = ack_sn;
                }

            } else {
                LOG_WRN("CVG_RX: Received out-of-order/segmented SDU (SN %u, expected %u, SI %d). Dropping.",
                        sn, g_default_cvg_flow_ctx.rx_expected_sn, si);
                // TODO: For Service 4, a NACK would be generated here.
            }

        } else if (ie_type == CVG_IE_TYPE_ARQ_FEEDBACK) {
            // This is an ACK/NACK for data we sent.
            const cvg_ie_arq_feedback_base_t *fb_base = (const cvg_ie_arq_feedback_base_t *)(dlc_sdu_buf);
            bool is_ack = ((fb_base->an_fbinfo_sn_msb >> 7) & 0x01) == 0;
            uint8_t fb_info = (fb_base->an_fbinfo_sn_msb >> 4) & 0x07;
            uint16_t sn = (((uint16_t)(fb_base->an_fbinfo_sn_msb & 0x0F)) << 8) | fb_base->sequence_number_lsb;

            if (is_ack) {
                // ETSI 6.2.9.2: When ACK for SN is received, transmitter considers all SDUs up to
                // and including SN as successfully delivered.
                LOG_INF("CVG_ARQ_RX: Received ACK for SN up to %u", sn);

                // --- FLOW CONTROL: Advance the TX window ---
                uint16_t old_start_sn = g_default_cvg_flow_ctx.tx_window_start_sn;
                uint16_t new_start_sn = (sn + 1) & 0x0FFF;

                // Calculate how many SDUs are being newly acknowledged.
                int16_t diff = new_start_sn - old_start_sn;
                if (diff < 0) diff += 4096; // Handle 12-bit wraparound

                for (int i = 0; i < diff; i++) {
                    uint16_t acked_sn = (old_start_sn + i) & 0x0FFF;
                    uint16_t buffer_index = acked_sn % CVG_MAX_IN_FLIGHT_SDUS;

                    if (g_default_cvg_flow_ctx.tx_in_flight_sdu[buffer_index] != NULL) {
                        dect_mac_api_buffer_free(g_default_cvg_flow_ctx.tx_in_flight_sdu[buffer_index]);
                        g_default_cvg_flow_ctx.tx_in_flight_sdu[buffer_index] = NULL;
                        k_sem_give(&g_default_cvg_flow_ctx.tx_window_sem); // Open the window
                    }
                }
                g_default_cvg_flow_ctx.tx_window_start_sn = new_start_sn;

            } else { // NACK
                // TODO: Handle NACK for Service Type 4. This would involve
                // marking the SDU in tx_in_flight_sdu for retransmission.
                LOG_WRN("CVG_ARQ_RX: Received NACK for SN %u. Re-transmission not yet implemented.", sn);
            }

        } else if (ie_type == CVG_IE_TYPE_DATA_TRANSPARENT) {
             // Logic from previous implementation
             size_t header_len = 1;
             size_t payload_len = dlc_sdu_len - header_len; // Simplistic
             mac_sdu_t *app_sdu = NULL;
             if (k_mem_slab_alloc(&g_cvg_app_sdu_slab, (void **)&app_sdu, K_NO_WAIT) == 0) {
                 memcpy(app_sdu->data, dlc_sdu_buf + header_len, payload_len);
                 app_sdu->len = payload_len;
                 k_fifo_put(&g_cvg_to_app_rx_fifo, app_sdu);
             }

        } else {
            LOG_WRN("CVG_RX: Received unhandled CVG IE type: 0x%X", ie_type);
        }
    }
}




// --- Public API Implementation ---

int dect_cvg_init(void)
{
    // The init sequence is critical. Lower layers must be ready before upper layers use them.
    // The responsibility of calling dect_mac_core_init is now considered part of the
    // application's main setup, before calling dect_cvg_init.
    int err = dect_dlc_init(); // dlc_init will initialize the DLC layer and its threads.
    if (err) {
        LOG_ERR("Failed to initialize DLC layer: %d", err);
        return err;
    }

    // Threads are auto-started by K_THREAD_DEFINE.
    // We can set names for easier debugging.
    k_thread_name_set(g_cvg_tx_thread_id, "dect_cvg_tx");
    k_thread_name_set(g_cvg_rx_thread_id, "dect_cvg_rx");

    // Initialize the flow context
    memset(&g_default_cvg_flow_ctx, 0, sizeof(g_default_cvg_flow_ctx));
    g_default_cvg_flow_ctx.service_type = CVG_SERVICE_TYPE_0_TRANSPARENT; // Default
    g_default_cvg_flow_ctx.is_configured = false;
    k_sem_init(&g_default_cvg_flow_ctx.tx_window_sem, 0, K_SEM_MAX_LIMIT);

    for (int i = 0; i < CVG_MAX_IN_FLIGHT_SDUS; i++) {
        g_default_cvg_flow_ctx.tx_in_flight_sdu[i] = NULL;
    }    

    LOG_INF("CVG Layer Initialized.");
    return 0;
}

int dect_cvg_configure_flow(cvg_service_type_t service, uint16_t max_window_size, uint32_t lifetime_ms)
{
    // This is a simplified configuration for our single default flow.
    // A real implementation would likely take a flow ID.
    if (service >= CVG_SERVICE_TYPE_3_FC && max_window_size == 0) {
        LOG_ERR("CVG_CFG: Max window size cannot be 0 for a flow-controlled service.");
        return -EINVAL;
    }

    g_default_cvg_flow_ctx.service_type = service;
    g_default_cvg_flow_ctx.max_window_size = max_window_size;
    // The lifetime_ms would be used to configure SDU discard timers. (TODO)
    g_default_cvg_flow_ctx.is_configured = true;

    // Initialize the semaphore count to the window size. The TX thread will "take" the
    // semaphore for each packet sent and the RX thread will "give" it back when ACKs are processed.
    k_sem_init(&g_default_cvg_flow_ctx.tx_window_sem, max_window_size, max_window_size);

    LOG_INF("CVG Flow configured. Service: %d, Window Size: %u", service, max_window_size);

    return 0;
}

int dect_cvg_send(cvg_service_type_t service, const uint8_t *app_sdu, size_t app_sdu_len)
{
    if (!app_sdu && app_sdu_len > 0) {
        return -EINVAL;
    }
    if (app_sdu_len > (sizeof(mac_sdu_t) - offsetof(mac_sdu_t, data))) {
        LOG_ERR("CVG_SEND: App SDU too large for transport buffer (%zu > %zu)",
                app_sdu_len, (sizeof(mac_sdu_t) - offsetof(mac_sdu_t, data)));
        return -EMSGSIZE;
    }

    // Allocate the wrapper item for the TX queue
    cvg_tx_queue_item_t *tx_item = NULL;
    if (k_mem_slab_alloc(&g_cvg_tx_item_slab, (void **)&tx_item, K_NO_WAIT) != 0) {
        LOG_WRN("CVG_SEND: Could not allocate TX queue item.");
        return -ENOMEM;
    }

    // Allocate the buffer for the SDU data
    mac_sdu_t *sdu_buf = NULL;
    if (k_mem_slab_alloc(&g_cvg_app_sdu_slab, (void **)&sdu_buf, K_NO_WAIT) != 0) {
        LOG_WRN("CVG_SEND: Could not allocate app sdu buffer for TX queue.");
        k_mem_slab_free(&g_cvg_tx_item_slab, (void **)&tx_item); // Free the wrapper
        return -ENOMEM;
    }

    memcpy(sdu_buf->data, app_sdu, app_sdu_len);
    sdu_buf->len = app_sdu_len;

    tx_item->app_sdu_buf = sdu_buf;
    tx_item->service_type = service;

    k_fifo_put(&g_app_to_cvg_tx_fifo, tx_item);
    return 0;
}

int dect_cvg_receive(uint8_t *app_sdu_buf, size_t *len_inout, k_timeout_t timeout)
{
    if (!app_sdu_buf || !len_inout || *len_inout == 0) {
        return -EINVAL;
    }

    mac_sdu_t *sdu_buf = k_fifo_get(&g_cvg_to_app_rx_fifo, timeout);
    if (!sdu_buf) {
        return -EAGAIN; // Timeout
    }

    if (*len_inout < sdu_buf->len) {
        *len_inout = sdu_buf->len; // Report required size
        k_fifo_put(&g_cvg_to_app_rx_fifo, sdu_buf); // Put it back
        return -EMSGSIZE;
    }

    *len_inout = sdu_buf->len;
    memcpy(app_sdu_buf, sdu_buf->data, sdu_buf->len);

    k_mem_slab_free(&g_cvg_app_sdu_slab, (void **)&sdu_buf);
    return 0;
}