/* dect_mac/dect_mac_sm_pt.h */
#ifndef DECT_MAC_SM_PT_H__
#define DECT_MAC_SM_PT_H__

#include "dect_mac_sm.h" // For dect_mac_event_msg structure

/**
 * @brief Initializes and starts the Portable Termination (PT) role operations.
 *
 * This function should be called once by the main MAC control logic (e.g., in dect_mac_main.c)
 * after dect_mac_core_init() has been successfully executed and if the device's
 * role is determined to be MAC_ROLE_PT.
 *
 * It sets the initial PT state and typically triggers the first action for a PT,
 * which is to start scanning for Fixed Terminations (FTs).
 */
void dect_mac_sm_pt_start_operation(void);

/**
 * @brief Handles events for the Portable Termination (PT) role state machine.
 *
 * This function is the main entry point for event processing when the MAC layer
 * is operating as a PT. It is called by the central MAC event dispatcher
 * (`dect_mac_event_dispatch`) with events received from the PHY layer or
 * internal MAC timers.
 *
 * The function processes the event based on the PT's current operational state
 * (e.g., SCANNING, ASSOCIATING, ASSOCIATED) and the type of event received,
 * driving the PT through its defined procedures like scanning for FTs, associating,
 * maintaining the link (keep-alives), and handling mobility.
 *
 * @param msg Pointer to the const dect_mac_event_msg structure containing the
 *            event type and its associated data payload.
 */
void dect_mac_sm_pt_handle_event(const struct dect_mac_event_msg *msg);

/**
 * @brief PT specific action function to be called by the dispatcher when the keep-alive timer event occurs.
 *
 * This function is invoked from the MAC main thread context when a MAC_EVENT_TIMER_EXPIRED_KEEPALIVE
 * is dispatched. It checks if a Keep Alive PDU can be sent and then calls an internal
 * action function to build and schedule it. It also reschedules the keep-alive timer.
 */
void dect_mac_sm_pt_keep_alive_timer_expired_action(void);

/**
 * @brief PT specific action function to be called by the dispatcher when the mobility scan timer event occurs.
 *
 * This function is invoked from the MAC main thread context when a MAC_EVENT_TIMER_EXPIRED_MOBILITY_SCAN
 * is dispatched. It checks if a mobility scan should be initiated (e.g., if associated and no
 * other critical operation is pending) and then calls an internal action function to start the scan.
 * It also reschedules the mobility scan timer.
 */
void dect_mac_sm_pt_mobility_scan_timer_expired_action(void);

/**
 * @brief PT specific action function called by the dispatcher when the RACH backoff timer event occurs.
 *
 * This function is invoked from the MAC main thread context when a MAC_EVENT_TIMER_EXPIRED_RACH_BACKOFF
 * is dispatched. It typically re-attempts sending the RACH PDU (e.g., Association Request) after
 * the backoff period.
 */
void pt_rach_backoff_timer_expired_action(void);

/**
 * @brief PT specific action function called by the dispatcher when the RACH response window timer event occurs.
 *
 * This function is invoked from the MAC main thread context when a MAC_EVENT_TIMER_EXPIRED_RACH_RESP_WINDOW
 * is dispatched. This means the PT did not receive an expected response (e.g., Association Response)
 * in time. It handles retry logic or initiates a rescan.
 */
void pt_rach_response_window_timer_expired_action(void);


#endif /* DECT_MAC_SM_PT_H__ */