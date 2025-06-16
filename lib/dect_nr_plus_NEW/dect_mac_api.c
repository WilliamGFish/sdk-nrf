/* dect_mac/dect_mac_api.c */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h> // For memset if used, though k_mem_slab_alloc often returns zeroed or uninit memory

#include "dect_mac_api.h"
#include "dect_mac_sm.h"        // For MAC_EVENT_CMD_ENTER_PAGING_MODE (event type)
#include "dect_mac_main_dispatcher.h" // For mac_event_msgq (external from dect_mac_phy_if.c)
#include "dect_mac_core.h"      // For get_mac_context() to check role
#include "dect_mac_context.h"   // For dect_mac_context_t and role_ctx for FT FIFOs

LOG_MODULE_REGISTER(dect_mac_api, CONFIG_DECT_MAC_API_LOG_LEVEL);

// Define the number of SDU buffers available in the slab.
// This should be sized based on expected throughput, number of HARQ processes,
// and desired depth of TX queues.
#ifndef MAX_MAC_SDU_BUFFERS_CONFIG // Allow override by Kconfig
#define MAX_MAC_SDU_BUFFERS_CONFIG 16 // Example: 8 HARQ processes + 8 for TX queues
#endif

// Memory slab for mac_sdu_t buffers shared between DLC and MAC.
K_MEM_SLAB_DEFINE(g_mac_sdu_slab, sizeof(mac_sdu_t), MAX_MAC_SDU_BUFFERS_CONFIG, 4);

// --- Generic TX FIFOs (used by PT for UL, or if FT has generic outgoing that's not peer-specific) ---
K_FIFO_DEFINE(g_mac_tx_fifo_high_priority);
K_FIFO_DEFINE(g_mac_tx_fifo_reliable_data);
K_FIFO_DEFINE(g_mac_tx_fifo_best_effort);

// Array of pointers to the generic TX FIFOs, indexed by mac_flow_id_t
// This array is used by dect_mac_data_path.c to dequeue SDUs.
struct k_fifo * const mac_tx_fifos[MAC_FLOW_COUNT] = {
    &g_mac_tx_fifo_high_priority,
    &g_mac_tx_fifo_reliable_data,
    &g_mac_tx_fifo_best_effort
};

// Pointer to the DLC's RX FIFO, where MAC places received SDUs for DLC consumption.
// This is populated by dect_mac_api_init().
// It's used by dect_mac_data_path.c (handle_rx_sdu).
struct k_fifo *g_dlc_rx_sdu_fifo_ptr = NULL;

// External message queue for sending commands to the MAC thread
// Defined in dect_mac_phy_if.c
extern struct k_msgq mac_event_msgq;


int dect_mac_api_init(struct k_fifo *rx_fifo_from_dlc)
{
    if (rx_fifo_from_dlc == NULL) {
        LOG_ERR("DLC RX FIFO pointer cannot be NULL for MAC API init.");
        return -EINVAL;
    }
    g_dlc_rx_sdu_fifo_ptr = rx_fifo_from_dlc;

    // Initialize generic TX FIFOs (used by PT, or FT if not sending to specific peer via new API)
    // k_fifo_init(&g_mac_tx_fifo_high_priority); // K_FIFO_DEFINE already does this
    // k_fifo_init(&g_mac_tx_fifo_reliable_data);
    // k_fifo_init(&g_mac_tx_fifo_best_effort);
    // Note: Per-peer TX FIFOs for FT are initialized in dect_mac_core_init.

    LOG_INF("MAC API Initialized. DLC RX FIFO registered. Generic TX FIFOs ready.");
    return 0;
}

mac_sdu_t* dect_mac_api_buffer_alloc(k_timeout_t timeout)
{
    mac_sdu_t *sdu = NULL;
    int ret = k_mem_slab_alloc(&g_mac_sdu_slab, (void **)&sdu, timeout);
    if (ret != 0) {                
        // LOG_WRN: Use WRN for transient failures like timeout, ERR for persistent.
        if (K_TIMEOUT_EQ(timeout, K_NO_WAIT) && ret == -ENOMEM) { // Changed from -EAGAIN to -ENOMEM for k_mem_slab_alloc
             LOG_DBG("Failed to allocate MAC SDU buffer (no wait), slab empty or err: %d", ret);
        } else if (ret == -ENOMEM) { // Changed from -EAGAIN
            LOG_WRN("Failed to allocate MAC SDU buffer (timeout), slab empty or err: %d", ret);
        } else {
            LOG_ERR("Failed to allocate MAC SDU buffer, unexpected err: %d", ret);
        }
        return NULL;
    }
    // This memset correctly initializes the new boolean field to false and the SN to 0.
    memset(sdu, 0, sizeof(mac_sdu_t));
    return sdu;
}

void dect_mac_api_buffer_free(mac_sdu_t *sdu)
{
    if (sdu == NULL) {
        LOG_WRN("Attempted to free a NULL SDU buffer.");
        return;
    }
    k_mem_slab_free(&g_mac_sdu_slab, (void **)&sdu);
}

int dect_mac_api_send(mac_sdu_t *sdu, mac_flow_id_t flow)
{
    dect_mac_context_t *ctx = get_mac_context();
    if (ctx->role == MAC_ROLE_FT) {
        LOG_ERR("Generic dect_mac_api_send() called by FT. Use dect_mac_api_ft_send_to_pt() instead to specify target PT.");
        if (sdu) dect_mac_api_buffer_free(sdu);
        return -EPERM; // Or -EINVAL, as this API form is not for FT data to specific PTs
    }

    if (sdu == NULL) {
        LOG_ERR("Cannot send NULL SDU via generic API.");
        return -EINVAL;
    }
    if (flow >= MAC_FLOW_COUNT) {
        LOG_ERR("Invalid MAC flow ID: %d in generic send.", flow);
        dect_mac_api_buffer_free(sdu);
        return -EINVAL;
    }
    if (sdu->len == 0 || sdu->len > CONFIG_DECT_MAC_SDU_MAX_SIZE) {
        LOG_ERR("Invalid SDU length for TX: %u via generic send.", sdu->len);
        dect_mac_api_buffer_free(sdu);
        return -EMSGSIZE;
    }

    LOG_DBG("PT_SEND_API: Queueing SDU (len %u) to generic MAC TX Flow %d (for associated FT)", sdu->len, flow);
    k_fifo_put(mac_tx_fifos[flow], sdu);
    return 0;
}

int dect_mac_api_ft_send_to_pt(mac_sdu_t *sdu, mac_flow_id_t flow, uint16_t target_pt_short_rd_id)
{
    dect_mac_context_t *ctx = get_mac_context();

    if (ctx->role != MAC_ROLE_FT) {
        LOG_ERR("FT_SEND_API: Not in FT role. Cannot send to specific PT.");
        if (sdu) dect_mac_api_buffer_free(sdu);
        return -EPERM;
    }
    if (sdu == NULL) {
        LOG_ERR("FT_SEND_API: Cannot send NULL SDU.");
        return -EINVAL;
    }
    if (flow >= MAC_FLOW_COUNT) {
        LOG_ERR("FT_SEND_API: Invalid MAC flow ID: %d", flow);
        dect_mac_api_buffer_free(sdu);
        return -EINVAL;
    }
    if (target_pt_short_rd_id == 0 || target_pt_short_rd_id == 0xFFFF) {
        LOG_ERR("FT_SEND_API: Invalid target PT ShortID: 0x%04X", target_pt_short_rd_id);
        dect_mac_api_buffer_free(sdu);
        return -EINVAL;
    }
    if (sdu->len == 0 || sdu->len > CONFIG_DECT_MAC_SDU_MAX_SIZE) {
        LOG_ERR("FT_SEND_API: Invalid SDU length for TX: %u", sdu->len);
        dect_mac_api_buffer_free(sdu);
        return -EMSGSIZE;
    }
    // sdu->target_peer_short_rd_id should already be set by caller or here.
    // Let's enforce it or set it if not already.
    sdu->target_peer_short_rd_id = target_pt_short_rd_id;


    int target_peer_slot_idx = -1;
    for (int i = 0; i < MAX_PEERS_PER_FT; i++) {
        if (ctx->role_ctx.ft.connected_pts[i].is_valid &&
            ctx->role_ctx.ft.connected_pts[i].short_rd_id == target_pt_short_rd_id) {
            target_peer_slot_idx = i;
            break;
        }
    }

    if (target_peer_slot_idx == -1) {
        LOG_ERR("FT_SEND_API: Target PT ShortID 0x%04X not found or not connected.", target_pt_short_rd_id);
        dect_mac_api_buffer_free(sdu);
        return -ENOTCONN;
    }

    struct k_fifo *target_fifo_ptr = NULL; // Corrected name
    switch (flow) {
        case MAC_FLOW_HIGH_PRIORITY:
            target_fifo_ptr = &ctx->role_ctx.ft.peer_tx_data_fifos[target_peer_slot_idx].high_priority_fifo;
            break;
        case MAC_FLOW_RELIABLE_DATA:
            target_fifo_ptr = &ctx->role_ctx.ft.peer_tx_data_fifos[target_peer_slot_idx].reliable_data_fifo;
            break;
        case MAC_FLOW_BEST_EFFORT:
            target_fifo_ptr = &ctx->role_ctx.ft.peer_tx_data_fifos[target_peer_slot_idx].best_effort_fifo;
            break;
        default: // Should be caught by flow >= MAC_FLOW_COUNT check earlier
            LOG_ERR("FT_SEND_API: Unhandled flow ID %d (should not happen).", flow);
            dect_mac_api_buffer_free(sdu);
            return -EINVAL;
    }

    LOG_DBG("FT_SEND_API: Queueing SDU (len %u) to PT Slot %d (ShortID 0x%04X), Flow %d",
            sdu->len, target_peer_slot_idx, target_pt_short_rd_id, flow);
    k_fifo_put(target_fifo_ptr, sdu);
    return 0;
}

int dect_mac_api_enter_paging_mode(void)
{
    dect_mac_context_t *ctx = get_mac_context();
    if (ctx->role != MAC_ROLE_PT) {
        LOG_WRN("PAGING_CMD_API: Paging mode request ignored, not in PT role.");
        return -EPERM;
    }
    // Further state checks (e.g., must be associated) will be done by the PT state machine.

    struct dect_mac_event_msg msg = { .type = MAC_EVENT_CMD_ENTER_PAGING_MODE };
    // msg.modem_time_of_event = k_uptime_get(); // Or not strictly needed for CMD events
    int ret = k_msgq_put(&mac_event_msgq, &msg, K_NO_WAIT);
    if (ret != 0) {
        LOG_ERR("PAGING_CMD_API: Failed to queue CMD_ENTER_PAGING_MODE to MAC thread: %d", ret);
        return -EIO;
    }
    LOG_INF("PAGING_CMD_API: CMD_ENTER_PAGING_MODE queued to MAC thread.");
    return 0;
}