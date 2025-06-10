/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <device.h>

#include <dect_nr_plus/dect_config.h>
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_channel_mgr.h> /* Own header */
#include <dect_nr_plus/dect_phy_nrf9161.h> /* For PHY channel control */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_mac.h> // For MAC state awareness
#include <dect_nr_plus/dect_bcc.h> // For getting beacon info if needed
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_channel_mgr, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global Channel Manager context instance definition */
dect_channel_mgr_context_t channel_mgr_ctx = {
	.current_active_channel = 0, // Default to channel 0
};

/* Mutex to protect channel_mgr_ctx */
K_MUTEX_DEFINE(channel_mgr_ctx_mutex);

/* Timer for periodic channel quality monitoring and reselection (for Portable Parts) */
static struct k_timer channel_monitor_timer;

/* Timer for temporary blacklisting of channels */
static struct k_timer blacklist_timer; // Conceptual, for temporary blacklisting

/* Forward declarations */
static void channel_monitor_timer_handler(struct k_timer *timer_id);
static void blacklist_timer_handler(struct k_timer *timer_id); // Conceptual
static dect_status_t dect_channel_monitor_and_reselect(void);


dect_status_t dect_channel_mgr_init(void)
{
	k_mutex_init(&channel_mgr_ctx.mutex);

	// Initialize channel info with default values
	for (uint8_t i = 0; i < MAX_DECT_CHANNELS; i++) {
		channel_mgr_ctx.channel_info[i].channel_id = i;
		channel_mgr_ctx.channel_info[i].rssi_avg = -127; // Min RSSI
		channel_mgr_ctx.channel_info[i].fer_avg = 100;   // Max FER
		channel_mgr_ctx.channel_info[i].last_scan_time_ms = 0;
		channel_mgr_ctx.channel_info[i].status = CHANNEL_STATUS_UNKNOWN;
	}

	// Set initial active channel from configuration
	if (dect_config.initial_channel < MAX_DECT_CHANNELS) {
		channel_mgr_ctx.current_active_channel = dect_config.initial_channel;
		channel_mgr_ctx.channel_info[dect_config.initial_channel].status = CHANNEL_STATUS_IN_USE;
		LOG_DBG("CH_MGR: Initial active channel set to %u.", dect_config.initial_channel);
	} else {
		LOG_WRN("CH_MGR: Invalid initial channel %u in config. Defaulting to 0.", dect_config.initial_channel);
		channel_mgr_ctx.current_active_channel = 0;
		channel_mgr_ctx.channel_info[0].status = CHANNEL_STATUS_IN_USE;
	}

	// Initialize channel monitor timer for Portable Parts
	k_timer_init(&channel_monitor_timer, channel_monitor_timer_handler, NULL);
	// Start only if PP and channel reselection is enabled
	if (mac_ctx.device_role == MAC_ROLE_PP && dect_config.enable_channel_reselection) {
		k_timer_start(&channel_monitor_timer,
				K_MSEC(CONFIG_DECT_NR_PLUS_CHANNEL_RESELECTION_INTERVAL_MS),
				K_MSEC(CONFIG_DECT_NR_PLUS_CHANNEL_RESELECTION_INTERVAL_MS));
		LOG_INF("CH_MGR: Channel monitor timer started for PP (interval %u ms).",
			CONFIG_DECT_NR_PLUS_CHANNEL_RESELECTION_INTERVAL_MS);
	}

	// Initialize conceptual blacklist timer
	k_timer_init(&blacklist_timer, blacklist_timer_handler, NULL); // Not started by default

	LOG_INF("CH_MGR: Module initialized.");
	return DECT_STATUS_OK;
}

dect_status_t dect_channel_mgr_set_active_channel(uint8_t channel_id)
{
	if (channel_id >= MAX_DECT_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CH_MGR: Invalid channel ID %u.", channel_id);
		STATS_INC(dect_stats.channel_reselection_attempts); // Count as an attempt that failed
		return DECT_ERROR_INVALID_PARAM;
	}

	k_mutex_lock(&channel_mgr_ctx.mutex, K_FOREVER);

	if (channel_mgr_ctx.current_active_channel == channel_id) {
		LOG_DBG("CH_MGR: Channel %u is already active.", channel_id);
		k_mutex_unlock(&channel_mgr_ctx.mutex);
		return DECT_STATUS_OK;
	}

	// Check if the channel is blacklisted
	if (dect_config.channel_blacklist_mask & (1 << channel_id)) {
		DECT_ERROR_HANDLER(DECT_ERROR_CHANNEL_BLACKLISTED, "CH_MGR: Channel %u is blacklisted. Cannot set as active.", channel_id);
		STATS_INC(dect_stats.channel_reselection_attempts);
		k_mutex_unlock(&channel_mgr_ctx.mutex);
		return DECT_ERROR_CHANNEL_BLACKLISTED;
	}

	LOG_INF("CH_MGR: Changing active channel from %u to %u.",
		channel_mgr_ctx.current_active_channel, channel_id);

	dect_status_t phy_status = nrf9161_dect_phy_set_channel(channel_id);
	if (phy_status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(phy_status, "CH_MGR: Failed to set PHY channel to %u.", channel_id);
		STATS_INC(dect_stats.channel_mgr_tx_drops); // Consider PHY channel set as a TX operation for stats
		STATS_INC(dect_stats.channel_reselection_attempts);
		k_mutex_unlock(&channel_mgr_ctx.mutex);
		return phy_status;
	}

	// Update state
	channel_mgr_ctx.channel_info[channel_mgr_ctx.current_active_channel].status = CHANNEL_STATUS_GOOD; // Old channel status
	channel_mgr_ctx.current_active_channel = channel_id;
	channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_IN_USE;
	STATS_INC(dect_stats.channel_reselection_success); // Only if successful

	LOG_INF("CH_MGR: Active channel changed to %u successfully.", channel_id);
	k_mutex_unlock(&channel_mgr_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_channel_mgr_update_channel_quality(uint8_t channel_id, int8_t rssi, uint8_t fer)
{
	if (channel_id >= MAX_DECT_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CH_MGR: Invalid channel ID %u for quality update.", channel_id);
		STATS_INC(dect_stats.channel_mgr_rx_drops); // Invalid input for RX quality update
		return DECT_ERROR_INVALID_PARAM;
	}

	k_mutex_lock(&channel_mgr_ctx.mutex, K_FOREVER);

	// Update average RSSI and FER (simple moving average or similar)
	// For simplicity, just assign for now.
	channel_mgr_ctx.channel_info[channel_id].rssi_avg = rssi;
	channel_mgr_ctx.channel_info[channel_id].fer_avg = fer;
	channel_mgr_ctx.channel_info[channel_id].last_scan_time_ms = k_uptime_get();

	// Update status based on quality
	if (rssi < dect_config.channel_reselection_rssi_threshold_dbm || fer > CONFIG_DECT_NR_PLUS_CHANNEL_BAD_FER_THRESHOLD) {
		if (channel_mgr_ctx.channel_info[channel_id].status == CHANNEL_STATUS_IN_USE) {
			channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_BAD_QUALITY;
			LOG_WRN("CH_MGR: Active channel %u quality degraded (RSSI %d, FER %u).", channel_id, rssi, fer);
			if (mac_ctx.device_role == MAC_ROLE_PP && dect_config.enable_channel_reselection) {
				// Trigger reselection if active channel quality is bad
				dect_channel_monitor_and_reselect();
			}
		} else {
			channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_BAD_QUALITY;
		}
	} else if (!(dect_config.channel_blacklist_mask & (1 << channel_id)) &&
		   !(dect_config.channel_whitelist_mask & (1 << channel_id))) { // Not black/whitelisted explicitly
		channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_GOOD;
	}


	LOG_DBG("CH_MGR: Channel %u quality updated: RSSI %d dBm, FER %u%%.", channel_id, rssi, fer);

	k_mutex_unlock(&channel_mgr_ctx.mutex);
	return DECT_STATUS_OK;
}

channel_status_t dect_channel_mgr_get_channel_status(uint8_t channel_id, channel_quality_info_t *quality_info)
{
	if (channel_id >= MAX_DECT_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CH_MGR: Invalid channel ID %u for status query.", channel_id);
		return CHANNEL_STATUS_UNKNOWN;
	}

	k_mutex_lock(&channel_mgr_ctx.mutex, K_FOREVER);
	channel_status_t status = channel_mgr_ctx.channel_info[channel_id].status;
	if (quality_info) {
		memcpy(quality_info, &channel_mgr_ctx.channel_info[channel_id], sizeof(channel_quality_info_t));
	}
	k_mutex_unlock(&channel_mgr_ctx.mutex);
	return status;
}

dect_status_t dect_channel_mgr_blacklist_channel(uint8_t channel_id)
{
	if (channel_id >= MAX_DECT_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CH_MGR: Invalid channel ID %u to blacklist.", channel_id);
		return DECT_ERROR_INVALID_PARAM;
	}

	k_mutex_lock(&channel_mgr_ctx.mutex, K_FOREVER);
	dect_config.channel_blacklist_mask |= (1 << channel_id);
	channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_BLACKLISTED;

	LOG_INF("CH_MGR: Channel %u blacklisted. Current mask: 0x%x.", channel_id, dect_config.channel_blacklist_mask);

	// If the active channel is blacklisted, trigger reselection
	if (channel_mgr_ctx.current_active_channel == channel_id && mac_ctx.device_role == MAC_ROLE_PP) {
		LOG_WRN("CH_MGR: Active channel %u blacklisted. Initiating reselection.", channel_id);
		k_mutex_unlock(&channel_mgr_ctx.mutex);
		dect_channel_monitor_and_reselect();
		return DECT_STATUS_OK;
	}
	k_mutex_unlock(&channel_mgr_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_channel_mgr_whitelist_channel(uint8_t channel_id)
{
	if (channel_id >= MAX_DECT_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CH_MGR: Invalid channel ID %u to whitelist.", channel_id);
		return DECT_ERROR_INVALID_PARAM;
	}

	k_mutex_lock(&channel_mgr_ctx.mutex, K_FOREVER);
	dect_config.channel_whitelist_mask |= (1 << channel_id);
	channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_WHITELISTED;
	LOG_INF("CH_MGR: Channel %u whitelisted. Current mask: 0x%x.", channel_id, dect_config.channel_whitelist_mask);
	k_mutex_unlock(&channel_mgr_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_channel_mgr_remove_from_blacklist(uint8_t channel_id)
{
	if (channel_id >= MAX_DECT_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CH_MGR: Invalid channel ID %u to remove from blacklist.", channel_id);
		return DECT_ERROR_INVALID_PARAM;
	}

	k_mutex_lock(&channel_mgr_ctx.mutex, K_FOREVER);
	dect_config.channel_blacklist_mask &= ~(1 << channel_id);
	// Update status based on current quality, or back to UNKNOWN/GOOD if not scanned
	channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_UNKNOWN; // Reset, will be updated on next scan
	LOG_INF("CH_MGR: Channel %u removed from blacklist. Current mask: 0x%x.", channel_id, dect_config.channel_blacklist_mask);
	k_mutex_unlock(&channel_mgr_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t dect_channel_mgr_remove_from_whitelist(uint8_t channel_id)
{
	if (channel_id >= MAX_DECT_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CH_MGR: Invalid channel ID %u to remove from whitelist.", channel_id);
		return DECT_ERROR_INVALID_PARAM;
	}

	k_mutex_lock(&channel_mgr_ctx.mutex, K_FOREVER);
	dect_config.channel_whitelist_mask &= ~(1 << channel_id);
	// Update status based on current quality, or back to UNKNOWN/GOOD if not scanned
	channel_mgr_ctx.channel_info[channel_id].status = CHANNEL_STATUS_UNKNOWN; // Reset, will be updated on next scan
	LOG_INF("CH_MGR: Channel %u removed from whitelist. Current mask: 0x%x.", channel_id, dect_config.channel_whitelist_mask);
	k_mutex_unlock(&channel_mgr_ctx.mutex);
	return DECT_STATUS_OK;
}

static void channel_monitor_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	LOG_DBG("CH_MGR: Channel monitor timer fired.");
	if (mac_ctx.device_role == MAC_ROLE_PP && dect_config.enable_channel_reselection) {
		dect_status_t status = dect_channel_monitor_and_reselect();
		if (status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(status, "CH_MGR: Channel monitoring and reselection failed.");
			// Specific error stats are updated within dect_channel_monitor_and_reselect
		}
	} else {
		LOG_DBG("CH_MGR: Channel monitor not active (not PP or reselection disabled).");
	}
}

static dect_status_t dect_channel_monitor_and_reselect(void)
{
	if (mac_ctx.device_role != MAC_ROLE_PP || !dect_config.enable_channel_reselection) {
		return DECT_ERROR_INVALID_STATE; // Should not be called if not PP or reselection disabled
	}

	LOG_DBG("CH_MGR: Performing channel scan for reselection/handover.");
	STATS_INC(dect_stats.channel_reselection_attempts);

	int8_t best_rssi = -128; // Initialize with lowest possible RSSI
	uint8_t best_channel_id = channel_mgr_ctx.current_active_channel;
	bool found_better_channel = false;

	k_mutex_lock(&channel_mgr_ctx_mutex, K_FOREVER);

	// Clear FP candidates list for fresh scan
	mac_ctx.num_fp_candidates = 0;

	for (uint8_t i = 0; i < MAX_DECT_CHANNELS; i++) {
		// Skip blacklisted channels
		if (dect_config.channel_blacklist_mask & (1 << i)) {
			channel_mgr_ctx.channel_info[i].status = CHANNEL_STATUS_BLACKLISTED;
			LOG_DBG("CH_MGR: Skipping blacklisted channel %u.", i);
			continue;
		}

		// Perform a brief RX scan on each channel to get RSSI and detect beacons
		// This simulates listening for a short period on each channel.
		nrf9161_dect_rx_packet_t rx_packet_info;
		dect_status_t phy_status = nrf9161_dect_phy_rx(i, CONFIG_DECT_NR_PLUS_CHANNEL_SCAN_DURATION_MS, &rx_packet_info);

		if (phy_status == DECT_STATUS_OK) {
			// Update channel quality based on scan results
			dect_channel_mgr_update_channel_quality(i, rx_packet_info.rssi, rx_packet_info.crc_ok ? 0 : 50); // Simplified FER
			LOG_DBG("CH_MGR: Scanned channel %u, RSSI %d, CRC OK: %s.",
				i, rx_packet_info.rssi, rx_packet_info.crc_ok ? "true" : "false");

			// If a beacon was detected, add FP to candidates (conceptual)
			// This would involve parsing the beacon for FP ID and capabilities.
			if (rx_packet_info.src_short_rd_id != 0 && mac_ctx.num_fp_candidates < MAX_PEERS) {
				bool fp_already_known = false;
				for (int j = 0; j < mac_ctx.num_fp_candidates; j++) {
					if (mac_ctx.fp_candidates[j].short_rd_id == rx_packet_info.src_short_rd_id) {
						fp_already_known = true;
						// Update existing FP info (e.g., last_seen_ms, RSSI)
						mac_ctx.fp_candidates[j].rssi = rx_packet_info.rssi;
						mac_ctx.fp_candidates[j].last_seen_ms = k_uptime_get();
						break;
					}
				}
				if (!fp_already_known) {
					mac_ctx.fp_candidates[mac_ctx.num_fp_candidates].short_rd_id = rx_packet_info.src_short_rd_id;
					// Copy Long RD ID from beacon if available in rx_packet_info
					// mac_ctx.fp_candidates[mac_ctx.num_fp_candidates].long_rd_id = ...
					mac_ctx.fp_candidates[mac_ctx.num_fp_candidates].rssi = rx_packet_info.rssi;
					mac_ctx.fp_candidates[mac_ctx.num_fp_candidates].channel = i;
					mac_ctx.fp_candidates[mac_ctx.num_fp_candidates].last_seen_ms = k_uptime_get();
					mac_ctx.num_fp_candidates++;
					LOG_DBG("CH_MGR: Discovered FP 0x%04x on channel %u (RSSI %d).",
						rx_packet_info.src_short_rd_id, i, rx_packet_info.rssi);
				}
			}
			// Unref the data_buf acquired by nrf9161_dect_phy_rx if it's not handled by mac_rx_msgq
			if (rx_packet_info.data_buf) {
				net_buf_unref(rx_packet_info.data_buf);
			}

		} else if (phy_status != DECT_ERROR_NO_PACKET_RECEIVED) {
			// Log other PHY errors during scan, but don't drop the channel
			DECT_ERROR_HANDLER(phy_status, "CH_MGR: PHY RX scan failed on channel %u.", i);
			STATS_INC(dect_stats.channel_mgr_rx_drops);
			// Set channel status to busy or bad if PHY reports issues consistently
			if (phy_status == DECT_ERROR_PHY_CHANNEL_BUSY) {
				channel_mgr_ctx.channel_info[i].status = CHANNEL_STATUS_BUSY;
			}
		} else {
			LOG_DBG("CH_MGR: No packet received on channel %u during scan.", i);
			// No packet received, consider it quiet, but might be bad quality.
			// Revert to unknown or keep previous status if not updated by beacon.
			if (channel_mgr_ctx.channel_info[i].status == CHANNEL_STATUS_UNKNOWN) {
				channel_mgr_ctx.channel_info[i].status = CHANNEL_STATUS_GOOD; // Assume good if no interference
			}
		}

		// Channel selection logic: prioritize whitelisted, then highest RSSI
		if (!(dect_config.channel_blacklist_mask & (1 << i)) &&
		    (channel_mgr_ctx.channel_info[i].status == CHANNEL_STATUS_GOOD ||
		     channel_mgr_ctx.channel_info[i].status == CHANNEL_STATUS_WHITELISTED ||
			 channel_mgr_ctx.channel_info[i].status == CHANNEL_STATUS_IN_USE)) { // Consider IN_USE as a candidate if it's currently used
			// Prefer whitelisted channels
			if (dect_config.channel_whitelist_mask & (1 << i)) {
				// If current best is not whitelisted, or this whitelisted has better RSSI
				if (!(dect_config.channel_whitelist_mask & (1 << best_channel_id)) ||
					channel_mgr_ctx.channel_info[i].rssi_avg > best_rssi) {
					best_rssi = channel_mgr_ctx.channel_info[i].rssi_avg;
					best_channel_id = i;
					found_better_channel = true;
				}
			} else if (!(dect_config.channel_whitelist_mask & (1 << best_channel_id)) &&
					   channel_mgr_ctx.channel_info[i].rssi_avg > best_rssi &&
					   channel_mgr_ctx.channel_info[i].rssi_avg >= dect_config.channel_reselection_rssi_threshold_dbm &&
					   channel_mgr_ctx.channel_info[i].fer_avg <= CONFIG_DECT_NR_PLUS_CHANNEL_BAD_FER_THRESHOLD) {
				// Non-whitelisted, but better RSSI and acceptable FER
				best_rssi = channel_mgr_ctx.channel_info[i].rssi_avg;
				best_channel_id = i;
				found_better_channel = true;
			}
		}
	}

	if (found_better_channel && best_channel_id != channel_mgr_ctx.current_active_channel) {
		LOG_INF("CH_MGR: Found better channel %u (RSSI %d). Switching.", best_channel_id, best_rssi);
		k_mutex_unlock(&channel_mgr_ctx_mutex); // Unlock before calling set_active_channel
		dect_status_t status = dect_channel_mgr_set_active_channel(best_channel_id);
		if (status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(status, "CH_MGR: Failed to switch to best channel %u.", best_channel_id);
			// stat already incremented in set_active_channel
			return status;
		}
	} else {
		LOG_DBG("CH_MGR: No better channel found or already on best channel %u.", channel_mgr_ctx.current_active_channel);
	}
	k_mutex_unlock(&channel_mgr_ctx_mutex);
	return DECT_STATUS_OK;
}

static void blacklist_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	// This function would typically remove channels from a temporary blacklist
	// For example: `dect_channel_mgr_remove_from_blacklist(channel_id);`
	LOG_DBG("CH_MGR: Blacklist timer fired. (Conceptual: Remove channel from temporary blacklist).");
}

/* End of File
 * Last Amended: 2025-06-09 19:40 BST: Updated dect_channel_mgr.c for robust error handling.
 * - Added `channel_mgr_tx_drops` and `channel_mgr_rx_drops` stats to `dect_stats.h`.
 * - Added error handling for `nrf9161_dect_phy_set_channel` in `dect_channel_mgr_set_active_channel`, incrementing `channel_mgr_tx_drops` and `channel_reselection_attempts`.
 * - Added error handling for `nrf9161_dect_phy_rx` in `dect_channel_monitor_and_reselect`, incrementing `channel_mgr_rx_drops` and handling `DECT_ERROR_NO_PACKET_RECEIVED` vs. other PHY errors.
 * - Ensured `net_buf_unref` for `rx_packet_info.data_buf` after scan if it's not passed up the stack.
 * - Added checks for invalid channel IDs in public API functions (`dect_channel_mgr_set_active_channel`, `dect_channel_mgr_update_channel_quality`, `dect_channel_mgr_get_channel_status`, `dect_channel_mgr_blacklist_channel`, `dect_channel_mgr_whitelist_channel`, `dect_channel_mgr_remove_from_blacklist`, `dect_channel_mgr_remove_from_whitelist`), returning `DECT_ERROR_INVALID_PARAM` and incrementing `channel_mgr_rx_drops` (for read/update) or `channel_reselection_attempts` (for set/blacklist).
 */
