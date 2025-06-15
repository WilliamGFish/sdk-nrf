/* dect_mac/dect_mac_sm_ft.h */
#ifndef DECT_MAC_SM_FT_H__
#define DECT_MAC_SM_FT_H__

#include "dect_mac_sm.h" // For dect_mac_event_msg structure

/**
 * @brief Initializes and starts the Fixed Termination (FT) role operations.
 *
 * This function should be called once by the main MAC control logic (e.g., in dect_mac_main.c)
 * after dect_mac_core_init() has been successfully executed and if the device's
 * role is determined to be MAC_ROLE_FT.
 *
 * It sets the initial FT state and typically triggers the first action for an FT,
 * which is to perform an initial channel scan (Dynamic Channel Selection - DCS)
 * to find a suitable operating carrier.
 */
void dect_mac_sm_ft_start_operation(void);

/**
 * @brief Handles events for the Fixed Termination (FT) role state machine.
 *
 * This function is the main entry point for event processing when the MAC layer
 * is operating as an FT. It is called by the central MAC event dispatcher
 * (`dect_mac_event_dispatch`) with events received from the PHY layer or
 * internal MAC timers.
 *
 * The function processes the event based on the FT's current operational state
 * (e.g., SCANNING, BEACONING, ASSOCIATED) and the type of event received,
 * driving the FT through its defined procedures like beaconing, handling association
 * requests, and managing connected PTs.
 *
 * @param msg Pointer to the const dect_mac_event_msg structure containing the
 *            event type and its associated data payload.
 */
void dect_mac_sm_ft_handle_event(const struct dect_mac_event_msg *msg);

/**
 * @brief FT specific action function to be called by the dispatcher when a beacon timer event occurs.
 *
 * This function is invoked from the MAC main thread context when a MAC_EVENT_TIMER_EXPIRED_BEACON
 * is dispatched. It checks if a beacon can be sent (e.g., no other critical PHY operation
 * is pending) and then calls an internal action function to build and schedule the beacon PDU.
 * It also reschedules the beacon timer.
 */
void dect_mac_sm_ft_beacon_timer_expired_action(void);


#endif /* DECT_MAC_SM_FT_H__ */