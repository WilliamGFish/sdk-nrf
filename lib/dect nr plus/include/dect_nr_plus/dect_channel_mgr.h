/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_CHANNEL_MGR_H__
#define DECT_CHANNEL_MGR_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h> // For k_timer, k_mutex

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For channel_quality_info_t, MAX_DECT_CHANNELS

/**
 * @brief Channel Manager context structure.
 */
typedef struct {
	channel_quality_info_t channel_info[MAX_DECT_CHANNELS]; /**< Array of channel quality information. */
	uint8_t current_active_channel;                         /**< The currently active channel ID. */
	K_MUTEX_DEFINE(mutex);                                  /**< Mutex to protect context access. */
} dect_channel_mgr_context_t;

/**
 * @brief Global Channel Manager context instance.
 * Defined in dect_channel_mgr.c.
 */
extern dect_channel_mgr_context_t channel_mgr_ctx;

/**
 * @brief Enum for current channel status.
 */
typedef enum {
	CHANNEL_STATUS_UNKNOWN,       /**< Channel status is unknown. */
	CHANNEL_STATUS_GOOD,          /**< Channel quality is good. */
	CHANNEL_STATUS_POOR,          /**< Channel quality is poor. */
	CHANNEL_STATUS_BLACKLISTED,   /**< Channel is explicitly blacklisted. */
	CHANNEL_STATUS_WHITELISTED,   /**< Channel is explicitly whitelisted. */
	CHANNEL_STATUS_BLOCKED_BY_WHITELIST, /**< Channel is not whitelisted, and whitelisting is active. */
} channel_status_t;

/**
 * @brief Initializes the Channel Manager module.
 * Sets up internal state and timers.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_channel_mgr_init(void);

/**
 * @brief Updates the quality metrics for a specific channel.
 * This function is typically called by the PHY layer or a monitoring task.
 *
 * @param channel_id The ID of the channel to update.
 * @param rssi The latest RSSI measurement for the channel.
 * @param lqi The latest LQI measurement for the channel.
 * @param fer_x100 The latest Frame Error Rate (x100) for the channel.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_channel_mgr_update_channel_quality(uint8_t channel_id, int8_t rssi,
                                                      uint8_t lqi, uint16_t fer_x100);

/**
 * @brief Triggers a channel monitoring and reselection process.
 * This function evaluates current channel conditions and, if necessary,
 * selects a better channel and initiates a switch.
 *
 * @return DECT_STATUS_OK if reselection was successful or not needed,
 * DECT_ERROR_CHAN_NO_BETTER_FOUND if no better channel could be found,
 * or other error codes.
 */
dect_status_t dect_channel_monitor_and_reselect(void);

/**
 * @brief Blacklists a specific channel.
 * Blacklisted channels will not be considered for reselection.
 * This setting is persistent via `dect_config`.
 *
 * @param channel_id The ID of the channel to blacklist.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_channel_mgr_blacklist_channel(uint8_t channel_id);

/**
 * @brief Whitelists a specific channel.
 * If any channels are whitelisted, only whitelisted channels will be considered for reselection.
 * This setting is persistent via `dect_config`.
 *
 * @param channel_id The ID of the channel to whitelist.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_channel_mgr_whitelist_channel(uint8_t channel_id);

/**
 * @brief Removes a channel from the blacklist.
 * This setting is persistent via `dect_config`.
 *
 * @param channel_id The ID of the channel to remove from blacklist.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_channel_mgr_remove_from_blacklist(uint8_t channel_id);

/**
 * @brief Removes a channel from the whitelist.
 * This setting is persistent via `dect_config`.
 *
 * @param channel_id The ID of the channel to remove from whitelist.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_channel_mgr_remove_from_whitelist(uint8_t channel_id);

/**
 * @brief Gets the current status and quality information for a specific channel.
 *
 * @param channel_id The ID of the channel to query.
 * @param quality_info Pointer to a `channel_quality_info_t` structure to fill with data.
 * Can be NULL if only status is needed.
 * @return The `channel_status_t` of the queried channel.
 */
channel_status_t dect_channel_mgr_get_channel_status(uint8_t channel_id,
                                                     channel_quality_info_t *quality_info);

#endif /* DECT_CHANNEL_MGR_H__ */

/* End of File
 * Last Amended: 2025-05-31 15:20 BST: Added initial function prototypes and footer.
 * Last Amended: 2025-06-02 20:20 BST: Implemented Recommendation 12 for dect_channel_mgr.h.
 * Added `channel_status_t` enum for detailed channel status.
 * Added `dect_channel_mgr_blacklist_channel`, `dect_channel_mgr_whitelist_channel`,
 * `dect_channel_mgr_remove_from_blacklist`, `dect_channel_mgr_remove_from_whitelist` prototypes
 * for dynamic channel management.
 * Added `dect_channel_mgr_get_channel_status` prototype to query channel status and quality.
 * Updated `dect_channel_monitor_and_reselect` prototype to reflect its role in reselection.
 * Updated Doxygen comments for new and modified functions.
 */
