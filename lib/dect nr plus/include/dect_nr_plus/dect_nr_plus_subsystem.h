/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_NR_PLUS_SUBSYSTEM_H__
#define DECT_NR_PLUS_SUBSYSTEM_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h>

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For qos_priority_t

/**
 * @brief Initializes the complete DECT NR+ subsystem.
 * This function orchestrates the initialization of all DECT NR+ layers
 * (Config, Stats, Channel Manager, Power Manager, Crypto, MAC, DLC, CVG, Routing, Security)
 * and starts their respective Zephyr threads.
 *
 * @return DECT_STATUS_OK on successful initialization of all layers,
 * or a DECT_ERROR code if any layer fails to initialize.
 */
dect_status_t dect_nr_plus_init(void);

/**
 * @brief Sends application data through the DECT NR+ stack.
 * This function is a convenience API for the application to send data.
 * It encapsulates the process of allocating a net_buf and passing it to the CVG layer.
 *
 * @param dest_short_rd_id The Short RD ID of the destination peer.
 * @param data Pointer to the application data to send.
 * @param len Length of the application data.
 * @param qos_priority Quality of Service priority for the data.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_nr_plus_send_app_data(uint16_t dest_short_rd_id,
                                         const uint8_t *data, size_t len,
                                         qos_priority_t qos_priority);

/**
 * @brief Prints the current DECT NR+ stack statistics.
 * This function provides a way for the application to query performance metrics.
 */
void dect_nr_plus_print_stats(void);

/**
 * @brief Sets the device role for the DECT NR+ subsystem.
 * This function can be used by the application to dynamically set the role (FP/PP).
 *
 * @param role The desired role (MAC_ROLE_FP or MAC_ROLE_PP).
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_nr_plus_set_role(mac_role_t role);

#endif /* DECT_NR_PLUS_SUBSYSTEM_H__ */

/* End of File
 * Last Amended: 2025-06-05 12:30 BST: Added dect_nr_plus_subsystem.h
 * - Defined `dect_nr_plus_init()` as the main initialization function for the entire subsystem.
 * - Added `dect_nr_plus_send_app_data()` as a simplified API for applications to send data.
 * - Added `dect_nr_plus_print_stats()` for external access to statistics.
 * - Added `dect_nr_plus_set_role()` to allow dynamic role configuration.
 */
