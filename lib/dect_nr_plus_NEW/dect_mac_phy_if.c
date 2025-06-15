/* dect_mac/dect_mac_phy_if.c */

#include <zephyr/kernel.h>
#include <nrf_modem_dect_phy.h>
#include <zephyr/logging/log.h>
#include <string.h>             // For memcpy

#include "dect_mac_sm.h"        // For struct dect_mac_event_msg definition and event types
#include "dect_mac_core.h"      // For get_mac_context()
#include "dect_mac_context.h"   // For dect_phy_latency_values_t, NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ

LOG_MODULE_REGISTER(dect_mac_phy_if, CONFIG_DECT_MAC_PHY_IF_LOG_LEVEL);

/**
 * @brief Message queue for safely passing events from the PHY callback (modem library context)
 *        to the main MAC processing thread.
 *
 * This queue is consumed by the MAC thread in dect_mac_main.c.
 * Size should be sufficient for the expected event rate.
 */
K_MSGQ_DEFINE(mac_event_msgq, sizeof(struct dect_mac_event_msg), 16, 4); // 16 messages, 4-byte aligned


// Helper to convert modem ticks to microseconds for storing latency values
static inline uint32_t modem_ticks_to_us_phy_if(uint32_t ticks) {
    if (NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ == 0) return 0;
    return (uint32_t)(((uint64_t)ticks * 1000U) / NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ);
}

/**
 * @brief The single event handler callback registered with the nRF modem DECT PHY library.
 *
 * Executes in the modem library's event callback context.
 * Copies relevant event data into a `dect_mac_event_msg` and posts it to `mac_event_msgq`.
 */
static void phy_event_handler_callback(const struct nrf_modem_dect_phy_event *event)
{
    if (!event) {
        LOG_ERR("PHY_IF: Received NULL event pointer from modem library!");
        return;
    }

    struct dect_mac_event_msg msg_to_queue;
    // Zero initialize the message, especially the data union part
    memset(&msg_to_queue, 0, sizeof(struct dect_mac_event_msg));
    msg_to_queue.modem_time_of_event = event->time; // Store top-level event time

    bool should_queue_msg = true;
    int err;

    switch (event->id) {
    case NRF_MODEM_DECT_PHY_EVT_COMPLETED:
        msg_to_queue.type = MAC_EVENT_PHY_OP_COMPLETE;
        memcpy(&msg_to_queue.data.op_complete, &event->op_complete, sizeof(event->op_complete));
        break;

    case NRF_MODEM_DECT_PHY_EVT_PCC:
        msg_to_queue.type = MAC_EVENT_PHY_PCC;
        memcpy(&msg_to_queue.data.pcc, &event->pcc, sizeof(event->pcc));
        break;

    case NRF_MODEM_DECT_PHY_EVT_PDC:
        msg_to_queue.type = MAC_EVENT_PHY_PDC;
        // Data pointer (event->pdc.data) is modem-owned. MAC thread must copy.
        memcpy(&msg_to_queue.data.pdc, &event->pdc, sizeof(event->pdc));
        break;

    case NRF_MODEM_DECT_PHY_EVT_PCC_ERROR:
        msg_to_queue.type = MAC_EVENT_PHY_PCC_ERROR;
        memcpy(&msg_to_queue.data.pcc_crc_err, &event->pcc_crc_err, sizeof(event->pcc_crc_err));
        break;

    case NRF_MODEM_DECT_PHY_EVT_PDC_ERROR:
        msg_to_queue.type = MAC_EVENT_PHY_PDC_ERROR;
        memcpy(&msg_to_queue.data.pdc_crc_err, &event->pdc_crc_err, sizeof(event->pdc_crc_err));
        break;

    case NRF_MODEM_DECT_PHY_EVT_RSSI:
        msg_to_queue.type = MAC_EVENT_PHY_RSSI_RESULT;
        // RSSI measurements (event->rssi.meas) are modem-owned. MAC thread must copy.
        memcpy(&msg_to_queue.data.rssi, &event->rssi, sizeof(event->rssi));
        break;

    case NRF_MODEM_DECT_PHY_EVT_INIT:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_INIT result: %d (Temp: %dC, Volt: %umV, Limit: %uC)",
                event->init.err, event->init.temp, event->init.voltage, event->init.temperature_limit);
        if (event->init.err == NRF_MODEM_DECT_PHY_SUCCESS) {
            LOG_INF("PHY_IF: DECT PHY Initialized by modem. Requesting latency information.");
            err = nrf_modem_dect_phy_latency_get(); // Asynchronous call
            if (err != 0) {
                LOG_ERR("PHY_IF: Failed to request nrf_modem_dect_phy_latency_get(): %d", err);
            }
        } else {
            LOG_ERR("PHY_IF: Modem DECT PHY Initialization failed with error %d.", event->init.err);
            // MAC layer or application needs a mechanism to handle this critical failure.
        }
        should_queue_msg = false; // This event itself is informational, latency comes in separate event.
        break;

    case NRF_MODEM_DECT_PHY_EVT_LATENCY:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_LATENCY result: %d", event->latency_get.err);
        if (event->latency_get.err == NRF_MODEM_DECT_PHY_SUCCESS && event->latency_get.latency_info) {
            dect_mac_context_t* ctx = get_mac_context();
            if (ctx) {
                const struct nrf_modem_dect_phy_latency_info *modem_lat = event->latency_get.latency_info;
                // Store relevant latencies, converting from modem ticks to microseconds.
                // Example using Low Latency with Standby, as it's often a good balance.
                enum nrf_modem_dect_phy_radio_mode mode_to_use = NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY_WITH_STANDBY;

                ctx->phy_latency.scheduled_operation_startup_us = modem_ticks_to_us_phy_if(
                    modem_lat->radio_mode[mode_to_use].scheduled_operation_startup);
                ctx->phy_latency.scheduled_operation_transition_us = modem_ticks_to_us_phy_if(
                    modem_lat->radio_mode[mode_to_use].scheduled_operation_transition);
                ctx->phy_latency.idle_to_active_rx_us = modem_ticks_to_us_phy_if(modem_lat->operation.receive.idle_to_active);
                ctx->phy_latency.idle_to_active_tx_us = modem_ticks_to_us_phy_if(modem_lat->operation.transmit.idle_to_active);
                ctx->phy_latency.active_to_idle_rx_us = modem_ticks_to_us_phy_if(modem_lat->operation.receive.active_to_idle_rx);
                ctx->phy_latency.active_to_idle_tx_us = modem_ticks_to_us_phy_if(modem_lat->operation.transmit.active_to_idle);
                // TODO: Copy other latency values as deemed necessary by MAC scheduler logic.
                LOG_INF("PHY_IF: Latency info stored in MAC context (e.g., sched_startup_us: %u, idle_to_rx_us: %u).",
                        ctx->phy_latency.scheduled_operation_startup_us, ctx->phy_latency.idle_to_active_rx_us);
            } else {
                LOG_ERR("PHY_IF: MAC context NULL, cannot store latency info.");
            }
        } else if (event->latency_get.err != NRF_MODEM_DECT_PHY_SUCCESS) {
            LOG_ERR("PHY_IF: Failed to get latency info from modem: %d", event->latency_get.err);
        } else { /* latency_info pointer was NULL despite success */
            LOG_ERR("PHY_IF: Latency info event success, but latency_info pointer is NULL from modem.");
        }
        should_queue_msg = false; // MAC context updated directly.
        break;

    // Other informational events that MAC SM might not directly act upon via its main event loop
    case NRF_MODEM_DECT_PHY_EVT_DEINIT:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_DEINIT result: %d", event->deinit.err);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_CONFIGURE:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_CONFIGURE result: %d", event->configure.err);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_RADIO_CONFIG:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_RADIO_CONFIG result: %d (handle %u)",
                event->radio_config.err, event->radio_config.handle);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_ACTIVATE:
         LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_ACTIVATE result: %d (Temp: %dC, Volt: %umV)",
                 event->activate.err, event->activate.temp, event->activate.voltage);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_DEACTIVATE:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_DEACTIVATE result: %d", event->deactivate.err);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_CANCELED:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_CANCELED (for cancel op itself) result: %d for handle %u",
                event->cancel.err, event->cancel.handle);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_TIME: // Response to nrf_modem_dect_phy_time_get()
        LOG_DBG("PHY_IF: NRF_MODEM_DECT_PHY_EVT_TIME: current modem time is %llu", event->time); // event->time holds current time
        // Typically, the requester of time_get would have its own mechanism for this response.
        // If MAC needs to react, a specific MAC_EVENT could be queued. For now, just log.
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_CAPABILITY:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_CAPABILITY result: %d. Capability data ptr: %p", event->capability_get.err, event->capability_get.capability);
        // MAC might want to store these capabilities if requested via nrf_modem_dect_phy_capability_get()
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_BANDS:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_BANDS result: %d. Band count: %u", event->band_get.err, event->band_get.band_count);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_LINK_CONFIG:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_LINK_CONFIG result: %d", event->link_config.err);
        should_queue_msg = false;
        break;
    case NRF_MODEM_DECT_PHY_EVT_STF_CONFIG:
        LOG_INF("PHY_IF: NRF_MODEM_DECT_PHY_EVT_STF_CONFIG result: %d", event->stf_cover_seq_control.err);
        should_queue_msg = false;
        break;

    default:
        LOG_WRN("PHY_IF: Received unknown/unhandled PHY event ID: 0x%02X from modem. Not queueing.", event->id);
        should_queue_msg = false;
        break;
    }

    if (should_queue_msg) {
        err = k_msgq_put(&mac_event_msgq, &msg_to_queue, K_NO_WAIT);
        if (err != 0) {
            LOG_ERR("PHY_IF: MAC event message queue FULL! Event type %d (PHY ID 0x%02X) was dropped. Error: %d",
                    msg_to_queue.type, event->id, err);
            // Consider critical error handling, e.g., resetting MAC state or logging more persistently.
        }
    }
}

int dect_mac_phy_if_init(void)
{
    int err = nrf_modem_dect_phy_event_handler_set(phy_event_handler_callback);
    if (err) {
        LOG_ERR("PHY_IF: Failed to set nRF DECT PHY event handler, err: %d", err);
    } else {
        LOG_INF("PHY_IF: nRF DECT PHY event handler registered successfully.");
    }
    // Note: nrf_modem_dect_phy_init() is called by dect_mac_phy_ctrl_init() or similar
    // after the modem library itself (nrf_modem_init) is up.
    // This function only sets the handler.
    return err;
}