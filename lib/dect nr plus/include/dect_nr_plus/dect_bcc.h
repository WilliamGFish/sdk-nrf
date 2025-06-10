/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_BCC_H__
#define DECT_BCC_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h>
#include <dect_nr_plus/dect_errors.h> // For dect_status_t
#include <dect_nr_plus/dect_types.h> // For mac_ie_t

/**
 * @brief Initializes the Broadcast Control (BCC) module.
 *
 * This function sets up any necessary timers for BCC operations,
 * such as periodic beacon transmission for Fixed Parts.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_bcc_init(void);

/**
 * @brief Starts periodic beacon transmission (for Fixed Parts).
 *
 * This function configures and starts a timer to periodically send
 * DECT NR+ beacons on the current operating channel.
 *
 * @param interval_ms The interval in milliseconds for beacon transmission.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_bcc_start_beacon_tx(uint32_t interval_ms);

/**
 * @brief Stops periodic beacon transmission.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_bcc_stop_beacon_tx(void);

/**
 * @brief Constructs and sends a DECT NR+ MAC Broadcast Beacon PDU.
 * (Part 4, Clause 5.4.3.1.2, Control Type 0x05)
 *
 * This function is called by the beacon transmission timer handler (for FPs)
 * or manually to send a beacon. It now allows for dynamic customization
 * of beacon content by including Information Elements (IEs).
 *
 * @param channel The channel on which to transmit the beacon.
 * @param ies Optional array of Information Elements to include in the beacon.
 * @param ie_count Number of IEs in the `ies` array.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_bcc_send_beacon(uint8_t channel, const mac_ie_t *ies, uint8_t ie_count);

/**
 * @brief Adjusts power management awareness based on BCC activity.
 *
 * This function is called to inform the power manager about ongoing
 * beacon transmission activity, preventing the device from entering
 * deep sleep modes that would interfere with beaconing.
 */
void dect_bcc_adjust_power_awareness(void);

#endif /* DECT_BCC_H__ */

/* End of File
 * Last Amended: 2025-05-31 15:20 BST: Added initial function prototypes and footer.
 * Last Amended: 2025-06-02 18:00 BST: Updated `dect_bcc_send_beacon` to accept `ies` and `ie_count` for beacon content customization.
 * Updated Doxygen comments for `dect_bcc_send_beacon` and `dect_bcc_adjust_power_awareness`.
 */
