/* dect_cvg/dect_cvg.c */

#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <string.h>

#include "dect_cvg.h"
#include "dect_dlc.h" // For dlc_send_data() and dlc_receive_data()
#include "dect_mac_api.h" // For mac_sdu_t definition and buffer management

LOG_MODULE_REGISTER(dect_cvg, CONFIG_DECT_CVG_LOG_LEVEL);

// --- CVG Internal FIFOs and Buffers ---
/**
 * @brief Context for a single CVG data flow.
 *
 * For now, we only have one logical flow. In the future, this would be an array
 * or list, indexed by an endpoint multiplexer value.
 */
typedef struct {
    uint16_t tx_sequence_number; // 12-bit sequence number for CVG Data IEs
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

        mac_sdu_t *app_sdu = tx_item->app_sdu_buf;
        int cvg_pdu_len = 0;

        switch (tx_item->service_type) {
        case CVG_SERVICE_TYPE_0_TRANSPARENT:
            cvg_pdu_len = build_cvg_transparent_pdu(cvg_pdu_buf, sizeof(cvg_pdu_buf),
                                                    app_sdu->data, app_sdu->len);
            break;

        case CVG_SERVICE_TYPE_1_SEQ_NUM:
            g_default_cvg_flow_ctx.tx_sequence_number =
                (g_default_cvg_flow_ctx.tx_sequence_number + 1) & 0x0FFF; // 12-bit wrap

            cvg_pdu_len = build_cvg_data_ie_pdu(cvg_pdu_buf, sizeof(cvg_pdu_buf),
                                                app_sdu->data, app_sdu->len,
                                                g_default_cvg_flow_ctx.tx_sequence_number);
            break;

        default:
            LOG_WRN("CVG_TX: Unsupported service type %d.", tx_item->service_type);
            break;
        }

        if (cvg_pdu_len > 0) {
            // Send the complete CVG PDU to the DLC layer.
            int err = dlc_send_data(DLC_SERVICE_TYPE_0_TRANSPARENT,
                                      cvg_pdu_buf, cvg_pdu_len);
            if (err) {
                LOG_ERR("CVG_TX: dlc_send_data failed: %d", err);
            } else {
                LOG_DBG("CVG_TX: Queued CVG PDU (len %d, svc %d) to DLC.",
                        cvg_pdu_len, tx_item->service_type);
            }
        } else {
            LOG_ERR("CVG_TX: Failed to build CVG PDU for service %d: %d",
                    tx_item->service_type, cvg_pdu_len);
        }

        // Free the SDU buffer and the TX queue item wrapper
        k_mem_slab_free(&g_cvg_app_sdu_slab, (void **)&app_sdu);
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
        dlc_service_type_t service_type;
        size_t dlc_sdu_len = sizeof(dlc_sdu_buf);

        // Wait for a complete SDU (which is a CVG PDU) from the DLC layer.
        int err = dlc_receive_data(&service_type, dlc_sdu_buf, &dlc_sdu_len, K_FOREVER);
        if (err) {
            LOG_WRN("CVG_RX: dlc_receive_data failed: %d", err);
            continue;
        }

        // For now, assume all data is for transparent service.
        // A more advanced CVG would parse the header to determine how to process it.
        const cvg_header_t *hdr = (const cvg_header_t *)dlc_sdu_buf;
        uint8_t mt_bit = (hdr->ext_mt_f2c_or_type >> 5) & 0x01;
        cvg_ie_type_t ie_type = (cvg_ie_type_t)(hdr->ext_mt_f2c_or_type & 0x1F);

        if (mt_bit == 0 && ie_type == CVG_IE_TYPE_DATA_TRANSPARENT) {
            cvg_header_ext_len_t len_type = (hdr->ext_mt_f2c_or_type >> 6) & 0x03;
            size_t header_len = 1;
            size_t payload_len = 0;

            if (len_type == CVG_EXT_8BIT_LEN_FIELD) {
                header_len = 2;
                payload_len = dlc_sdu_buf[1];
            } else if (len_type == CVG_EXT_16BIT_LEN_FIELD) {
                header_len = 3;
                payload_len = sys_be16_to_cpu(&dlc_sdu_buf[1]);
            } else { // No length field, assume rest of PDU is payload
                 payload_len = dlc_sdu_len - header_len;
            }

            if (header_len + payload_len > dlc_sdu_len) {
                LOG_ERR("CVG_RX: Invalid CVG PDU length. Declared: %zu, Actual: %zu",
                        header_len + payload_len, dlc_sdu_len);
                continue;
            }

            // Allocate a buffer to pass to the application
            mac_sdu_t *app_sdu = NULL;
            if (k_mem_slab_alloc(&g_cvg_app_sdu_slab, (void **)&app_sdu, K_NO_WAIT) == 0) {
                memcpy(app_sdu->data, dlc_sdu_buf + header_len, payload_len);
                app_sdu->len = payload_len;
                k_fifo_put(&g_cvg_to_app_rx_fifo, app_sdu);
                LOG_DBG("CVG_RX: Queued App SDU (len %zu) to application.", payload_len);
            } else {
                LOG_ERR("CVG_RX: Failed to alloc buffer for app delivery. Dropping SDU.");
            }
        } else {
            LOG_WRN("CVG_RX: Received unhandled CVG PDU type (MT=%d, IE_Type=%d)", mt_bit, ie_type);
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
    g_default_cvg_flow_ctx.tx_sequence_number = 0;    

    LOG_INF("CVG Layer Initialized.");
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