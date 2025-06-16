/* dect_mac/dect_mac_main.c */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h> // For settings subsystem (optional)
#include <string.h>                 // For strlen if used
#include <hw_id.h>                  // For hw_id_get() if needed by core_init directly

#include "dect_mac_mgmt.h"      // For dect_mac_mgmt_service_register_callback, _init
#include "dect_mac_core.h"      // For dect_mac_core_init, get_mac_context
#include "dect_mac_context.h"   // For dect_mac_context_t and role access
#include "dect_mac_main_dispatcher.h" // For dect_mac_event_dispatch
#include "dect_mac_sm_pt.h"     // For dect_mac_sm_pt_start_operation
#include "dect_mac_sm_ft.h"     // For dect_mac_sm_ft_start_operation
#include "dect_mac_phy_if.h"    // For dect_mac_phy_if_init()
#include "dect_mac_data_path.h" // For dect_mac_data_path_service_tx()

// For DLC API usage by this "application" main thread
#include "dect_cvg.h"           // For dect_cvg_init, dect_cvg_send, dect_cvg_receive
#include "dect_mac_api.h"       // For dect_mac_api_init (now called from main)
#include "dect_dlc.h"           // For the g_dlc_internal_mac_rx_fifo reference

LOG_MODULE_REGISTER(dect_app_main, CONFIG_DECT_APP_MAIN_LOG_LEVEL);

/**
 * Message queue for events from PHY/timers to the MAC thread.
 * Defined in dect_mac_phy_if.c
 */
extern struct k_msgq mac_event_msgq;

// This now needs to be visible to main for passing to dect_mac_api_init
extern struct k_fifo g_dlc_internal_mac_rx_fifo;

/**
 * The MAC layer's dedicated thread stack area.
 * Size needs to be determined based on actual usage, including ISR/callback contexts
 * that might put messages into the queue.
 */
K_THREAD_STACK_DEFINE(dect_mac_stack_area, CONFIG_DECT_MAC_THREAD_STACK_SIZE); // Use Kconfig for size

/**
 * The MAC layer's thread control block.
 */
static struct k_thread dect_mac_thread_data;
static k_tid_t dect_mac_thread_id;


/**
 * The main entry point for the MAC layer's dedicated Zephyr thread.
 * This thread waits for events on `mac_event_msgq` and dispatches them.
 * It also periodically services TX queues and scheduled operations.
 */
void dect_mac_thread_entry(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    struct dect_mac_event_msg msg;
    LOG_INF("DECT MAC Thread Started. TID: %p", k_current_get());

    dect_mac_context_t* ctx = get_mac_context();

    while (1) {
        // 1. Service TX Data Path (HARQ retransmissions, new SDUs from TX queues based on schedule)
        // This function should be designed to run quickly if nothing to do.
        if (ctx->state >= MAC_STATE_PT_ASSOCIATING) { // Only service TX if trying to connect or connected
            dect_mac_data_path_service_tx();
        }

        // 2. Wait for next event with a timeout.
        // Timeout allows proactive scheduler (service_tx) to run periodically even if no external events.
        // A shorter timeout makes service_tx run more often but increases idle CPU load.
        // A longer timeout is more power-efficient but might delay scheduled TX.
        // Balance based on latency requirements.
        int ret = k_msgq_get(&mac_event_msgq, &msg, K_MSEC(CONFIG_DECT_MAC_THREAD_SERVICE_INTERVAL_MS));
        if (ret == 0) {
            // An event was received, dispatch it
            dect_mac_event_dispatch(&msg);
        } else if (ret == -EAGAIN) {
            // Timeout, no event. Loop will call service_tx again.
        } else {
            LOG_ERR("Error reading from MAC event queue: %d", ret);
            // Potentially a critical error if queue is corrupt.
        }
    }
}


/**
 * Example application-level handler for management frames.
 */
static void app_management_handler(const uint8_t *data, size_t len, uint32_t source_long_rd_id)
{
    LOG_INF("APP_MGMT_CB: Received management frame (len %zu) from 0x%08X", len, source_long_rd_id);
    // Example: Print payload as hex
    LOG_HEXDUMP_INF(data, len, "Mgmt Payload:");
    // Application-specific logic for OTA, config, diagnostics would go here.
}

/**
 * The main application entry point.
 */
void main(void)
{
    int err;
    LOG_INF("DECT NR+ Application Main Started (Zephyr Main Thread)");

    // Initialize settings subsystem (optional, for loading/saving config)
    // err = settings_subsys_init(); ...

    // --- STACK INITIALIZATION (ORDER IS CRITICAL) ---

    // 1. Initialize the MAC's interface to the nRF Modem DECT PHY library.
    // This registers the PHY event handler that queues events to mac_event_msgq.
    err = dect_mac_phy_if_init();
    if (err) {
        LOG_ERR("CRITICAL: Failed to initialize MAC-PHY interface, halting. Err: %d", err);
        return;
    }

    // 2. Initialize the MAC API layer.
    // This sets up the buffer slab and registers the DLC's RX FIFO with the MAC.
    err = dect_mac_api_init(&g_dlc_internal_mac_rx_fifo);
    if (err) {
        LOG_ERR("CRITICAL: Failed to initialize MAC API, halting. Err: %d", err);
        return;
    }

    // 3. Initialize the MAC Core layer.
    // This sets up the main context, role, IDs, and timers.
#if defined(CONFIG_DECT_MAC_ROLE_FT)
    dect_mac_role_t my_role = MAC_ROLE_FT;
    LOG_INF("APP_MAIN: Configuring DECT Stack in FT Role.");
#elif defined(CONFIG_DECT_MAC_ROLE_PT)
    dect_mac_role_t my_role = MAC_ROLE_PT;
    LOG_INF("APP_MAIN: Configuring DECT Stack in PT Role.");
#else
    #error "No DECT MAC role (FT or PT) selected in Kconfig (CONFIG_DECT_MAC_ROLE_...)"
#endif
    uint32_t provisioned_id = CONFIG_DECT_MAC_PROVISIONED_LONG_RD_ID;
    err = dect_mac_core_init(my_role, provisioned_id);
    if (err) {
        LOG_ERR("CRITICAL: Failed to initialize MAC Core, halting. Err: %d", err);
        return;
    }

    // 4. Initialize the CVG layer (which in turn initializes the DLC layer).
    err = dect_cvg_init();
    if (err) {
        LOG_ERR("CRITICAL: Failed to initialize CVG/DLC layers, halting. Err: %d", err);
        return;
    }


    // 5. Initialize and register application's management service handler (optional)
    dect_mac_mgmt_service_init();
    dect_mac_mgmt_service_register_callback(app_management_handler);

    // 6. Create and start the dedicated MAC processing thread
    dect_mac_thread_id = k_thread_create(&dect_mac_thread_data, dect_mac_stack_area,
                                         K_THREAD_STACK_SIZEOF(dect_mac_stack_area),
                                         dect_mac_thread_entry,
                                         NULL, NULL, NULL,
                                         CONFIG_DECT_MAC_THREAD_PRIORITY,
                                         0, K_NO_WAIT);
    if (dect_mac_thread_id == NULL) {
        LOG_ERR("CRITICAL: Failed to create DECT MAC thread!");
        return;
    }
    k_thread_name_set(dect_mac_thread_id, "dect_mac");
    LOG_INF("DECT MAC Thread created and started.");

    // 7. Start the role-specific MAC State Machine operations
    k_sleep(K_MSEC(100)); // Brief delay to ensure threads are scheduled and running
    if (my_role == MAC_ROLE_PT) {
        dect_mac_sm_pt_start_operation();
    } else { // MAC_ROLE_FT
        dect_mac_sm_ft_start_operation();
    }

    // --- Application Setup ---
    // Wait for the stack to become associated before proceeding
    dect_mac_context_t *ctx = get_mac_context();
    LOG_INF("APP_MAIN: Waiting for MAC to become associated...");
    while (ctx->state != MAC_STATE_ASSOCIATED) {
        k_sleep(K_SECONDS(1));
    }
    LOG_INF("APP_MAIN: MAC is associated. Configuring CVG flow control.");

    // Configure a flow-controlled service with a small window size for testing
    const uint16_t test_window_size = 4;
    err = dect_cvg_configure_flow(CVG_SERVICE_TYPE_3_FC, test_window_size, 0);
    if (err) {
        LOG_ERR("APP_MAIN: Failed to configure CVG flow: %d", err);
        return;
    }

    // --- Application Main Loop (Example using CVG API) ---
    uint8_t rx_app_buf[128];
    int app_tx_counter = 0;

    while (1) {
        // Send a burst of packets to test the flow control window
        LOG_INF("APP_MAIN: Sending a burst of %d packets...", test_window_size + 2);
        for (int i = 0; i < test_window_size + 2; i++) {
            char payload_buf[64];
            snprintk(payload_buf, sizeof(payload_buf), "FC Packet %d (Overall %d)", i, app_tx_counter++);

            // Note: The service type is now taken from the configured flow context,
            // so passing it here is for the TX queue item, but the thread uses the configured one.
            err = dect_cvg_send(CVG_SERVICE_TYPE_3_FC, (const uint8_t *)payload_buf, strlen(payload_buf));
            if (err) {
                LOG_WRN("APP_MAIN: dect_cvg_send failed for burst packet %d: %d", i, err);
            }
            // No delay between sends to ensure we fill the window quickly
        }
        LOG_INF("APP_MAIN: Burst sent. The CVG TX thread should now be blocked by the window semaphore.");

        // In a real app, this thread would do other work or sleep.
        // Here, we'll just check for received data and then sleep before the next burst.
        for (int i = 0; i < 10; i++) {
             size_t received_len_inout = sizeof(rx_app_buf);
             err = dect_cvg_receive(rx_app_buf, &received_len_inout, K_MSEC(100)); // Poll for 100ms
             if (err == 0) {
                 rx_app_buf[received_len_inout < sizeof(rx_app_buf) ? received_len_inout : sizeof(rx_app_buf) - 1] = '\0';
                 LOG_INF("APP_MAIN: CVG Received data (Len %zu): '%s'",
                         received_len_inout, rx_app_buf);
             } else if (err != -EAGAIN) {
                 LOG_WRN("APP_MAIN: dect_cvg_receive error: %d", err);
             }
        }

        k_sleep(K_SECONDS(CONFIG_DECT_APP_TX_INTERVAL_S));
    }
}

