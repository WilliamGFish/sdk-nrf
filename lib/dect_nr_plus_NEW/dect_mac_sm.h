/* dect_mac/dect_mac_sm.h */
#ifndef DECT_MAC_SM_H__
#define DECT_MAC_SM_H__

#include <nrf_modem_dect_phy.h> // For nrf_modem_dect_phy event structs and enums
#include <stdint.h>             // For uintxx_t types

// Forward declaration for MAX_HARQ_PROCESSES if not defined by an earlier include (like dect_mac_context.h)
// It's better if dect_mac_context.h (which defines it) is included before this by files needing both.
// However, to make this header somewhat self-contained for its enum:
#ifndef MAX_HARQ_PROCESSES
#define MAX_HARQ_PROCESSES 8
#endif

/** @brief Defines the logical role of the MAC instance. */
typedef enum {
    MAC_ROLE_PT, // Portable Termination
    MAC_ROLE_FT, // Fixed Termination
} dect_mac_role_t;

/** @brief Defines the high-level operational states of the MAC layer. */
typedef enum {
    MAC_STATE_DEACTIVATED,      // PHY not initialized or inactive
    MAC_STATE_IDLE,             // Core initialized, role set, deciding next action

    /* Portable Termination (PT) Specific States */
    MAC_STATE_PT_SCANNING,          // PT actively scanning for beacons
    MAC_STATE_PT_BEACON_PDC_WAIT,   // PT saw a beacon PCC, waiting for its PDC to get FT details
    MAC_STATE_PT_ASSOCIATING,       // PT building/sending Association Request (RACH op in progress, or waiting for LBT slot)
    MAC_STATE_PT_RACH_BACKOFF,      // PT in RACH contention window backoff
    MAC_STATE_PT_WAIT_ASSOC_RESP,   // PT sent Assoc Req, PHY op done, RXing/waiting for Assoc Response PDU
    MAC_STATE_PT_AUTHENTICATING,    // PT performing security handshake after basic association
    MAC_STATE_PT_PAGING,            // PT in low-power paging cycle (listening for pages) TODO

    /* Fixed Termination (FT) Specific States */
    MAC_STATE_FT_SCANNING,          // FT performing initial channel scan (DCS)
    MAC_STATE_FT_BEACONING,         // FT is operational: transmitting beacons, ready for associations & data
    MAC_STATE_FT_RACH_LISTEN,       // FT specifically listening on RACH resources (can be a sub-state of BEACONING)

    /* Common Connected State (after association & authentication for PT; after PT connects for FT) */
    MAC_STATE_ASSOCIATED,           // Secure and/or operational link established, ready for data

    MAC_STATE_COUNT,                // Total number of states, for validation/arrays
} dect_mac_state_t;


/**
 * @brief Defines the types of MAC operations that might be pending a PHY op completion.
 * This helps the NRF_MODEM_DECT_PHY_EVT_COMPLETED handler understand what MAC procedure
 * just finished at the PHY level.
 */
typedef enum {
    PENDING_OP_NONE = 0,                // No PHY operation actively tracked by MAC SM

    /* PT Operations */
    PENDING_OP_PT_SCAN,                 // PT's continuous beacon scan RX operation
    PENDING_OP_PT_RACH_ASSOC_REQ,       // PT's TX of Association Request on RACH
    PENDING_OP_PT_WAIT_BEACON_PDC,      // PT's specific RX for a beacon's PDC (not generally used if scan is continuous)
    PENDING_OP_PT_WAIT_ASSOC_RESP,      // PT's RX for Association Response PDU
    PENDING_OP_PT_KEEP_ALIVE,           // PT's TX of Keep Alive message
    PENDING_OP_PT_MOBILITY_SCAN,        // PT's RSSI scan for mobility candidates (TODO)
    PENDING_OP_PT_AUTH_MSG_TX,          // PT sending an authentication message (TODO)
    PENDING_OP_PT_AUTH_MSG_RX,          // PT expecting an authentication message (TODO)

    /* FT Operations */
    PENDING_OP_FT_INITIAL_SCAN,         // FT's initial RSSI scan (for DCS)
    PENDING_OP_FT_BEACON,               // FT's TX of a Beacon PDU
    PENDING_OP_FT_RACH_RX_WINDOW,       // FT is listening on its RACH resources
    PENDING_OP_FT_ASSOC_RESP,           // FT's TX of Association Response PDU
    PENDING_OP_FT_AUTH_MSG_TX,          // FT sending an authentication message (TODO)
    PENDING_OP_FT_AUTH_MSG_RX,          // FT expecting an authentication message (TODO)

    /* Data Path Operations - HARQ process index encoded */
    // Base value for PT data TX HARQ operations
    PENDING_OP_PT_DATA_TX_HARQ0 = 30, // Ensure distinct from other ops
    PENDING_OP_PT_DATA_TX_HARQ_MAX = PENDING_OP_PT_DATA_TX_HARQ0 + MAX_HARQ_PROCESSES - 1,

    // Base value for FT data TX HARQ operations
    PENDING_OP_FT_DATA_TX_HARQ0 = PENDING_OP_PT_DATA_TX_HARQ_MAX + 1, // Start after PT HARQ range
    PENDING_OP_FT_DATA_TX_HARQ_MAX = PENDING_OP_FT_DATA_TX_HARQ0 + MAX_HARQ_PROCESSES - 1,

    PENDING_OP_MAX_VALUE // For validation or array sizing if needed
} pending_op_type_t;


/**
 * @brief Defines the types of events that can be passed to the MAC thread's message queue.
 * These events originate from PHY layer callbacks (via nrf_modem_dect_phy) or internal MAC timers.
 */
typedef enum {
    /* PHY Layer Events - Mapped from nrf_modem_dect_phy_event_id */
    MAC_EVENT_PHY_OP_COMPLETE,          // NRF_MODEM_DECT_PHY_EVT_COMPLETED
    MAC_EVENT_PHY_PCC,                  // NRF_MODEM_DECT_PHY_EVT_PCC (PCC header received)
    MAC_EVENT_PHY_PDC,                  // NRF_MODEM_DECT_PHY_EVT_PDC (PDC data received)
    MAC_EVENT_PHY_PCC_ERROR,            // NRF_MODEM_DECT_PHY_EVT_PCC_ERROR (PCC CRC fail)
    MAC_EVENT_PHY_PDC_ERROR,            // NRF_MODEM_DECT_PHY_EVT_PDC_ERROR (PDC CRC fail)
    MAC_EVENT_PHY_RSSI_RESULT,          // NRF_MODEM_DECT_PHY_EVT_RSSI (RSSI measurements ready)
    // Other PHY events like _INIT_COMPLETE, _ACTIVATE_COMPLETE could be added
    // but are currently handled in dect_mac_phy_if.c without queueing to MAC SM directly.

    /* Timer Expiry Events - Generated by MAC internal timers */
    MAC_EVENT_TIMER_EXPIRED_RACH_BACKOFF,       // PT RACH backoff period ended
    MAC_EVENT_TIMER_EXPIRED_RACH_RESP_WINDOW,   // PT timeout waiting for Association Response
    MAC_EVENT_TIMER_EXPIRED_KEEPALIVE,          // PT periodic Keep Alive timer
    MAC_EVENT_TIMER_EXPIRED_MOBILITY_SCAN,      // PT periodic mobility scan timer (TODO)
    MAC_EVENT_TIMER_EXPIRED_PAGING_CYCLE,       // PT paging listen interval timer (TODO)
    MAC_EVENT_TIMER_EXPIRED_BEACON,             // FT periodic Beacon transmission timer
    MAC_EVENT_TIMER_EXPIRED_HARQ,               // Data Path HARQ retransmission/ACK timeout timer

    /* Internal Command Events (e.g., from Application/DLC to MAC control plane) */
    MAC_EVENT_CMD_ENTER_PAGING_MODE,    // PT command from App/DLC (TODO)
    // MAC_EVENT_CMD_START_ASSOCIATION, // PT command from App/DLC (alternative to auto-scan)
    // MAC_EVENT_CMD_RELEASE_LINK,      // PT or FT command from App/DLC

    MAC_EVENT_TYPE_COUNT                // Number of defined event types
} dect_mac_event_type_t;


/**
 * @brief The message structure passed in the mac_event_msgq from PHY event callbacks
 *        (via dect_mac_phy_if.c) and from MAC internal timer handlers to the
 *        main MAC processing thread.
 */
struct dect_mac_event_msg {
    dect_mac_event_type_t type;
    uint64_t modem_time_of_event; // Copied from nrf_modem_dect_phy_event.time for PHY events
                                  // For timer events, this might be k_uptime_get() or similar if needed.
    union {
        /* PHY Event Payloads (these are direct copies from nrf_modem_dect_phy_event.data portion) */
        struct nrf_modem_dect_phy_op_complete_event op_complete;
        struct nrf_modem_dect_phy_pcc_event pcc;
        struct nrf_modem_dect_phy_pdc_event pdc; // Note: pdc.data points to modem-owned memory
        struct nrf_modem_dect_phy_pcc_crc_failure_event pcc_crc_err;
        struct nrf_modem_dect_phy_pdc_crc_failure_event pdc_crc_err;
        struct nrf_modem_dect_phy_rssi_event rssi; // Note: rssi.meas points to modem-owned memory

        /* Timer Event Payloads */
        struct {
            int id; // e.g., HARQ process index for MAC_EVENT_TIMER_EXPIRED_HARQ,
                    // or a specific timer identifier if multiple timers of same type exist.
        } timer_data;

        /* Command Event Payloads (if any specific data needed for commands) */
        // struct { uint16_t target_ft_short_id; } cmd_start_assoc_payload;

    } data;
};

#endif /* DECT_MAC_SM_H__ */