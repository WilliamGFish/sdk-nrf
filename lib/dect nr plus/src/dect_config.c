/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <settings/settings.h> // For settings subsystem

#include <dect_nr_plus/dect_config.h> /* Own header */
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For LONG_RD_ID_LEN_BYTES, MAX_DECT_CHANNELS
#include <nrf_modem_dect_phy.h> // For NRF_MODEM_DECT_LBT_PERIOD_MIN/MAX

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_config, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global configuration instance definition */
dect_config_t dect_config = {
	// Default values
	.mac_address = {0x00, 0x11, 0x22, 0x33}, // Example default Long RD ID
	.short_rd_id = 0x0001,                   // Example default Short RD ID
	.initial_channel = 0,                    // Default to channel 0
	.enable_encryption = true,               // Encryption enabled by default
	.enable_qos = false,                     // QoS disabled by default
	.enable_routing = false,                 // Routing disabled by default
	.enable_channel_reselection = true,      // Channel reselection enabled by default
	.channel_reselection_rssi_threshold_dbm = -90, // Default RSSI threshold
	.t_mac_assoc_timeout_ms = 5000,          // 5 seconds
	.t_mac_inactivity_timeout_ms = 10000,    // 10 seconds
	.t_mac_sync_period_ms = 1000,            // 1 second
	.device_role = MAC_ROLE_PP,              // Default to Portable Part
	.enable_mobility_support = false,        // Mobility disabled by default
	.t_mac_handover_timeout_ms = 3000,       // 3 seconds
	.mac_max_handover_retries = 3,           // 3 retries
	.channel_whitelist_mask = 0,             // No channels whitelisted by default
	.channel_blacklist_mask = 0,             // No channels blacklisted by default
	.lbt_rssi_threshold_dbm = -80,           // Default LBT RSSI threshold
	.lbt_period_modem_units = NRF_MODEM_DECT_LBT_PERIOD_MIN, // Default LBT period
	.t_mac_sync_loss_timeout_ms = 5000,      // Default sync loss timeout
};

/* Settings handler for loading/saving configuration */
static int settings_set_handler(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	int rc = 0;

	if (settings_base_name_val(name, &next) == 0) {
		return -EINVAL;
	}

	if (!strcmp(name, "dect_nr_plus/mac_address")) {
		if (len != LONG_RD_ID_LEN_BYTES) {
			LOG_ERR("Config: Invalid length for mac_address (%zu, expected %u).", len, LONG_RD_ID_LEN_BYTES);
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.mac_address, sizeof(dect_config.mac_address));
		if (rc != sizeof(dect_config.mac_address)) {
			LOG_ERR("Config: Failed to read mac_address (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded mac_address: %02x:%02x:%02x:%02x",
			dect_config.mac_address[0], dect_config.mac_address[1],
			dect_config.mac_address[2], dect_config.mac_address[3]);
	} else if (!strcmp(name, "dect_nr_plus/short_rd_id")) {
		if (len != sizeof(dect_config.short_rd_id)) {
			LOG_ERR("Config: Invalid length for short_rd_id (%zu, expected %u).", len, sizeof(dect_config.short_rd_id));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.short_rd_id, sizeof(dect_config.short_rd_id));
		if (rc != sizeof(dect_config.short_rd_id)) {
			LOG_ERR("Config: Failed to read short_rd_id (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded short_rd_id: 0x%04x", dect_config.short_rd_id);
	} else if (!strcmp(name, "dect_nr_plus/initial_channel")) {
		if (len != sizeof(dect_config.initial_channel)) {
			LOG_ERR("Config: Invalid length for initial_channel (%zu, expected %u).", len, sizeof(dect_config.initial_channel));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.initial_channel, sizeof(dect_config.initial_channel));
		if (rc != sizeof(dect_config.initial_channel)) {
			LOG_ERR("Config: Failed to read initial_channel (rc=%d).", rc);
			return -EIO;
		}
		if (dect_config.initial_channel >= MAX_DECT_CHANNELS) {
			LOG_WRN("Config: Loaded initial_channel %u is out of range. Setting to 0.", dect_config.initial_channel);
			dect_config.initial_channel = 0;
		}
		LOG_DBG("Config: Loaded initial_channel: %u", dect_config.initial_channel);
	} else if (!strcmp(name, "dect_nr_plus/enable_encryption")) {
		if (len != sizeof(dect_config.enable_encryption)) {
			LOG_ERR("Config: Invalid length for enable_encryption (%zu, expected %u).", len, sizeof(dect_config.enable_encryption));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.enable_encryption, sizeof(dect_config.enable_encryption));
		if (rc != sizeof(dect_config.enable_encryption)) {
			LOG_ERR("Config: Failed to read enable_encryption (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded enable_encryption: %s", dect_config.enable_encryption ? "true" : "false");
	} else if (!strcmp(name, "dect_nr_plus/enable_qos")) {
		if (len != sizeof(dect_config.enable_qos)) {
			LOG_ERR("Config: Invalid length for enable_qos (%zu, expected %u).", len, sizeof(dect_config.enable_qos));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.enable_qos, sizeof(dect_config.enable_qos));
		if (rc != sizeof(dect_config.enable_qos)) {
			LOG_ERR("Config: Failed to read enable_qos (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded enable_qos: %s", dect_config.enable_qos ? "true" : "false");
	} else if (!strcmp(name, "dect_nr_plus/enable_routing")) {
		if (len != sizeof(dect_config.enable_routing)) {
			LOG_ERR("Config: Invalid length for enable_routing (%zu, expected %u).", len, sizeof(dect_config.enable_routing));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.enable_routing, sizeof(dect_config.enable_routing));
		if (rc != sizeof(dect_config.enable_routing)) {
			LOG_ERR("Config: Failed to read enable_routing (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded enable_routing: %s", dect_config.enable_routing ? "true" : "false");
	} else if (!strcmp(name, "dect_nr_plus/enable_channel_reselection")) {
		if (len != sizeof(dect_config.enable_channel_reselection)) {
			LOG_ERR("Config: Invalid length for enable_channel_reselection (%zu, expected %u).", len, sizeof(dect_config.enable_channel_reselection));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.enable_channel_reselection, sizeof(dect_config.enable_channel_reselection));
		if (rc != sizeof(dect_config.enable_channel_reselection)) {
			LOG_ERR("Config: Failed to read enable_channel_reselection (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded enable_channel_reselection: %s", dect_config.enable_channel_reselection ? "true" : "false");
	} else if (!strcmp(name, "dect_nr_plus/channel_reselection_rssi_threshold_dbm")) {
		if (len != sizeof(dect_config.channel_reselection_rssi_threshold_dbm)) {
			LOG_ERR("Config: Invalid length for channel_reselection_rssi_threshold_dbm (%zu, expected %u).", len, sizeof(dect_config.channel_reselection_rssi_threshold_dbm));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.channel_reselection_rssi_threshold_dbm, sizeof(dect_config.channel_reselection_rssi_threshold_dbm));
		if (rc != sizeof(dect_config.channel_reselection_rssi_threshold_dbm)) {
			LOG_ERR("Config: Failed to read channel_reselection_rssi_threshold_dbm (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded channel_reselection_rssi_threshold_dbm: %d", dect_config.channel_reselection_rssi_threshold_dbm);
	} else if (!strcmp(name, "dect_nr_plus/t_mac_assoc_timeout_ms")) {
		if (len != sizeof(dect_config.t_mac_assoc_timeout_ms)) {
			LOG_ERR("Config: Invalid length for t_mac_assoc_timeout_ms (%zu, expected %u).", len, sizeof(dect_config.t_mac_assoc_timeout_ms));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.t_mac_assoc_timeout_ms, sizeof(dect_config.t_mac_assoc_timeout_ms));
		if (rc != sizeof(dect_config.t_mac_assoc_timeout_ms)) {
			LOG_ERR("Config: Failed to read t_mac_assoc_timeout_ms (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded t_mac_assoc_timeout_ms: %u", dect_config.t_mac_assoc_timeout_ms);
	} else if (!strcmp(name, "dect_nr_plus/t_mac_inactivity_timeout_ms")) {
		if (len != sizeof(dect_config.t_mac_inactivity_timeout_ms)) {
			LOG_ERR("Config: Invalid length for t_mac_inactivity_timeout_ms (%zu, expected %u).", len, sizeof(dect_config.t_mac_inactivity_timeout_ms));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.t_mac_inactivity_timeout_ms, sizeof(dect_config.t_mac_inactivity_timeout_ms));
		if (rc != sizeof(dect_config.t_mac_inactivity_timeout_ms)) {
			LOG_ERR("Config: Failed to read t_mac_inactivity_timeout_ms (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded t_mac_inactivity_timeout_ms: %u", dect_config.t_mac_inactivity_timeout_ms);
	} else if (!strcmp(name, "dect_nr_plus/t_mac_sync_period_ms")) {
		if (len != sizeof(dect_config.t_mac_sync_period_ms)) {
			LOG_ERR("Config: Invalid length for t_mac_sync_period_ms (%zu, expected %u).", len, sizeof(dect_config.t_mac_sync_period_ms));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.t_mac_sync_period_ms, sizeof(dect_config.t_mac_sync_period_ms));
		if (rc != sizeof(dect_config.t_mac_sync_period_ms)) {
			LOG_ERR("Config: Failed to read t_mac_sync_period_ms (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded t_mac_sync_period_ms: %u", dect_config.t_mac_sync_period_ms);
	} else if (!strcmp(name, "dect_nr_plus/device_role")) {
		if (len != sizeof(dect_config.device_role)) {
			LOG_ERR("Config: Invalid length for device_role (%zu, expected %u).", len, sizeof(dect_config.device_role));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.device_role, sizeof(dect_config.device_role));
		if (rc != sizeof(dect_config.device_role)) {
			LOG_ERR("Config: Failed to read device_role (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded device_role: %s", dect_config.device_role == MAC_ROLE_FP ? "FP" : "PP");
	} else if (!strcmp(name, "dect_nr_plus/enable_mobility_support")) {
		if (len != sizeof(dect_config.enable_mobility_support)) {
			LOG_ERR("Config: Invalid length for enable_mobility_support (%zu, expected %u).", len, sizeof(dect_config.enable_mobility_support));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.enable_mobility_support, sizeof(dect_config.enable_mobility_support));
		if (rc != sizeof(dect_config.enable_mobility_support)) {
			LOG_ERR("Config: Failed to read enable_mobility_support (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded enable_mobility_support: %s", dect_config.enable_mobility_support ? "true" : "false");
	} else if (!strcmp(name, "dect_nr_plus/t_mac_handover_timeout_ms")) {
		if (len != sizeof(dect_config.t_mac_handover_timeout_ms)) {
			LOG_ERR("Config: Invalid length for t_mac_handover_timeout_ms (%zu, expected %u).", len, sizeof(dect_config.t_mac_handover_timeout_ms));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.t_mac_handover_timeout_ms, sizeof(dect_config.t_mac_handover_timeout_ms));
		if (rc != sizeof(dect_config.t_mac_handover_timeout_ms)) {
			LOG_ERR("Config: Failed to read t_mac_handover_timeout_ms (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded t_mac_handover_timeout_ms: %u", dect_config.t_mac_handover_timeout_ms);
	} else if (!strcmp(name, "dect_nr_plus/mac_max_handover_retries")) {
		if (len != sizeof(dect_config.mac_max_handover_retries)) {
			LOG_ERR("Config: Invalid length for mac_max_handover_retries (%zu, expected %u).", len, sizeof(dect_config.mac_max_handover_retries));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.mac_max_handover_retries, sizeof(dect_config.mac_max_handover_retries));
		if (rc != sizeof(dect_config.mac_max_handover_retries)) {
			LOG_ERR("Config: Failed to read mac_max_handover_retries (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded mac_max_handover_retries: %u", dect_config.mac_max_handover_retries);
	} else if (!strcmp(name, "dect_nr_plus/channel_whitelist_mask")) {
		if (len != sizeof(dect_config.channel_whitelist_mask)) {
			LOG_ERR("Config: Invalid length for channel_whitelist_mask (%zu, expected %u).", len, sizeof(dect_config.channel_whitelist_mask));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.channel_whitelist_mask, sizeof(dect_config.channel_whitelist_mask));
		if (rc != sizeof(dect_config.channel_whitelist_mask)) {
			LOG_ERR("Config: Failed to read channel_whitelist_mask (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded channel_whitelist_mask: 0x%x", dect_config.channel_whitelist_mask);
	} else if (!strcmp(name, "dect_nr_plus/channel_blacklist_mask")) {
		if (len != sizeof(dect_config.channel_blacklist_mask)) {
			LOG_ERR("Config: Invalid length for channel_blacklist_mask (%zu, expected %u).", len, sizeof(dect_config.channel_blacklist_mask));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.channel_blacklist_mask, sizeof(dect_config.channel_blacklist_mask));
		if (rc != sizeof(dect_config.channel_blacklist_mask)) {
			LOG_ERR("Config: Failed to read channel_blacklist_mask (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded channel_blacklist_mask: 0x%x", dect_config.channel_blacklist_mask);
	} else if (!strcmp(name, "dect_nr_plus/lbt_rssi_threshold_dbm")) {
		if (len != sizeof(dect_config.lbt_rssi_threshold_dbm)) {
			LOG_ERR("Config: Invalid length for lbt_rssi_threshold_dbm (%zu, expected %u).", len, sizeof(dect_config.lbt_rssi_threshold_dbm));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.lbt_rssi_threshold_dbm, sizeof(dect_config.lbt_rssi_threshold_dbm));
		if (rc != sizeof(dect_config.lbt_rssi_threshold_dbm)) {
			LOG_ERR("Config: Failed to read lbt_rssi_threshold_dbm (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded lbt_rssi_threshold_dbm: %d", dect_config.lbt_rssi_threshold_dbm);
	} else if (!strcmp(name, "dect_nr_plus/lbt_period_modem_units")) {
		if (len != sizeof(dect_config.lbt_period_modem_units)) {
			LOG_ERR("Config: Invalid length for lbt_period_modem_units (%zu, expected %u).", len, sizeof(dect_config.lbt_period_modem_units));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.lbt_period_modem_units, sizeof(dect_config.lbt_period_modem_units));
		if (rc != sizeof(dect_config.lbt_period_modem_units)) {
			LOG_ERR("Config: Failed to read lbt_period_modem_units (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded lbt_period_modem_units: %u", dect_config.lbt_period_modem_units);
	} else if (!strcmp(name, "dect_nr_plus/t_mac_sync_loss_timeout_ms")) {
		if (len != sizeof(dect_config.t_mac_sync_loss_timeout_ms)) {
			LOG_ERR("Config: Invalid length for t_mac_sync_loss_timeout_ms (%zu, expected %u).", len, sizeof(dect_config.t_mac_sync_loss_timeout_ms));
			return -EINVAL;
		}
		rc = read_cb(cb_arg, &dect_config.t_mac_sync_loss_timeout_ms, sizeof(dect_config.t_mac_sync_loss_timeout_ms));
		if (rc != sizeof(dect_config.t_mac_sync_loss_timeout_ms)) {
			LOG_ERR("Config: Failed to read t_mac_sync_loss_timeout_ms (rc=%d).", rc);
			return -EIO;
		}
		LOG_DBG("Config: Loaded t_mac_sync_loss_timeout_ms: %u", dect_config.t_mac_sync_loss_timeout_ms);
	}
	return rc;
}

SETTINGS_STATIC_HANDLER_DEFINE(dect_nr_plus_config, "dect_nr_plus", NULL, settings_set_handler, NULL, NULL);

dect_status_t dect_config_init(void)
{
	int rc = settings_load();
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to load settings (%d). Using defaults.", rc);
		// Return OK as defaults are applied
		return DECT_STATUS_OK;
	}

	LOG_INF("Config: Module initialized. Settings loaded successfully.");
	// Apply sane limits if loaded values are out of bounds (e.g., from corrupt flash)
	if (dect_config.initial_channel >= MAX_DECT_CHANNELS) {
		LOG_WRN("Config: initial_channel %u out of bounds. Clamping to %u.", dect_config.initial_channel, MAX_DECT_CHANNELS - 1);
		dect_config.initial_channel = MAX_DECT_CHANNELS - 1;
	}
	if (dect_config.lbt_period_modem_units < NRF_MODEM_DECT_LBT_PERIOD_MIN ||
	    dect_config.lbt_period_modem_units > NRF_MODEM_DECT_LBT_PERIOD_MAX) {
		LOG_WRN("Config: lbt_period_modem_units %u out of bounds. Clamping to %u.", dect_config.lbt_period_modem_units, NRF_MODEM_DECT_LBT_PERIOD_MIN);
		dect_config.lbt_period_modem_units = NRF_MODEM_DECT_LBT_PERIOD_MIN;
	}

	return DECT_STATUS_OK;
}

dect_status_t dect_save_config(void)
{
	int rc;

	rc = settings_save_one("dect_nr_plus/mac_address", &dect_config.mac_address, sizeof(dect_config.mac_address));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save mac_address: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/short_rd_id", &dect_config.short_rd_id, sizeof(dect_config.short_rd_id));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save short_rd_id: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/initial_channel", &dect_config.initial_channel, sizeof(dect_config.initial_channel));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save initial_channel: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/enable_encryption", &dect_config.enable_encryption, sizeof(dect_config.enable_encryption));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save enable_encryption: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/enable_qos", &dect_config.enable_qos, sizeof(dect_config.enable_qos));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save enable_qos: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/enable_routing", &dect_config.enable_routing, sizeof(dect_config.enable_routing));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save enable_routing: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/enable_channel_reselection", &dect_config.enable_channel_reselection, sizeof(dect_config.enable_channel_reselection));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save enable_channel_reselection: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/channel_reselection_rssi_threshold_dbm", &dect_config.channel_reselection_rssi_threshold_dbm, sizeof(dect_config.channel_reselection_rssi_threshold_dbm));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save channel_reselection_rssi_threshold_dbm: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/t_mac_assoc_timeout_ms", &dect_config.t_mac_assoc_timeout_ms, sizeof(dect_config.t_mac_assoc_timeout_ms));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save t_mac_assoc_timeout_ms: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/t_mac_inactivity_timeout_ms", &dect_config.t_mac_inactivity_timeout_ms, sizeof(dect_config.t_mac_inactivity_timeout_ms));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save t_mac_inactivity_timeout_ms: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/t_mac_sync_period_ms", &dect_config.t_mac_sync_period_ms, sizeof(dect_config.t_mac_sync_period_ms));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save t_mac_sync_period_ms: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/device_role", &dect_config.device_role, sizeof(dect_config.device_role));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save device_role: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/enable_mobility_support", &dect_config.enable_mobility_support, sizeof(dect_config.enable_mobility_support));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save enable_mobility_support: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/t_mac_handover_timeout_ms", &dect_config.t_mac_handover_timeout_ms, sizeof(dect_config.t_mac_handover_timeout_ms));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save t_mac_handover_timeout_ms: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/mac_max_handover_retries", &dect_config.mac_max_handover_retries, sizeof(dect_config.mac_max_handover_retries));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save mac_max_handover_retries: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/channel_whitelist_mask", &dect_config.channel_whitelist_mask, sizeof(dect_config.channel_whitelist_mask));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save channel_whitelist_mask: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/channel_blacklist_mask", &dect_config.channel_blacklist_mask, sizeof(dect_config.channel_blacklist_mask));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save channel_blacklist_mask: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/lbt_rssi_threshold_dbm", &dect_config.lbt_rssi_threshold_dbm, sizeof(dect_config.lbt_rssi_threshold_dbm));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save lbt_rssi_threshold_dbm: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/lbt_period_modem_units", &dect_config.lbt_period_modem_units, sizeof(dect_config.lbt_period_modem_units));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save lbt_period_modem_units: %d.", rc);
		return DECT_ERROR_GENERIC;
	}

	rc = settings_save_one("dect_nr_plus/t_mac_sync_loss_timeout_ms", &dect_config.t_mac_sync_loss_timeout_ms, sizeof(dect_config.t_mac_sync_loss_timeout_ms));
	if (rc != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "Config: Failed to save t_mac_sync_loss_timeout_ms: %d.", rc);
		return DECT_ERROR_GENERIC;
	}


	LOG_INF("Config: Configuration saved successfully.");
	return DECT_STATUS_OK;
}

/* End of File
 * Last Amended: 2025-06-09 20:05 BST: Updated dect_config.c for robust error handling.
 * - Added error checks for `settings_load()` in `dect_config_init()`, logging failures but allowing defaults to be used.
 * - Added error checks for `settings_save_one()` in `dect_save_config()`, using `DECT_ERROR_HANDLER` and returning an error code.
 * - Added input validation for loaded config values in `settings_set_handler` (e.g., length checks, channel ID bounds) to prevent invalid configurations.
 * - Added clamping for `initial_channel` and `lbt_period_modem_units` in `dect_config_init` to ensure values are within sane limits even if loaded from corrupt storage.
 * - Updated logging to use `LOG_ERR` for critical errors during loading/saving, and `LOG_WRN` for non-critical issues like out-of-bounds config values that are corrected.
 */
