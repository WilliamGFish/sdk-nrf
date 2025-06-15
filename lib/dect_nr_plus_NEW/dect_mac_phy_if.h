/* dect_mac/dect_mac_phy_if.h */
#ifndef DECT_MAC_PHY_IF_H__
#define DECT_MAC_PHY_IF_H__

/**
 * @file dect_mac_phy_if.h
 * @brief Interface layer between the DECT MAC and the nRF Modem DECT PHY library.
 *
 * This module is primarily responsible for:
 *  1. Registering a single callback function with the nRF modem DECT PHY library.
 *  2. Receiving all asynchronous events from the nRF modem DECT PHY in that callback.
 *  3. Translating/copying these modem-specific events into MAC-specific event
 *     structures (`dect_mac_event_msg`).
 *  4. Posting these MAC event messages to a message queue (`mac_event_msgq`)
 *     for processing by the main MAC processing thread.
 * This decoupling ensures that the modem callback context is exited quickly and
 * complex MAC logic runs in its own dedicated thread.
 */

/**
 * @brief Initialize the DECT MAC's interface to the nRF DECT PHY layer.
 *
 * This function registers the MAC's single event handler with the nRF modem library.
 * It must be called once during the overall DECT stack initialization,
 * typically after `nrf_modem_init()` and before `nrf_modem_dect_phy_init()`.
 * The MAC processing thread should be created and started after this function
 * successfully returns, so it can consume events from the `mac_event_msgq`.
 *
 * @return 0 on success.
 * @retval -NRF_EFAULT if the modem library's `nrf_modem_dect_phy_event_handler_set` fails internally.
 * @retval Other negative error codes from the nRF modem library.
 */
int dect_mac_phy_if_init(void);

#endif /* DECT_MAC_PHY_IF_H__ */