/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <device.h>
#include <drivers/modem/nrf9160_modem.h> // Conceptual include for nRF9161 modem API
#include <net/net_buf.h>

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_phy_nrf9161.h> /* Own header */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <nrf_modem_dect_phy.h> // For direct Nordic PHY API calls

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_phy_nrf9161, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Internal PHY context */
static struct {
	nrf9161_dect_phy_rx_callback_t rx_cb;
	nrf9161_dect_phy_tx_done_callback_t tx_done_cb;
	// No longer explicit resource_grant_cb with new direct scheduling
	uint32_t tx_power_dbm; /**< Current TX power in dBm. */
	uint8_t current_channel; /**< Currently active channel ID. */
	power_mode_t current_radio_mode; /**< Current PHY radio mode. */
	uint64_t current_modem_time; /**< Last known modem time in modem units. */
	K_MUTEX_DEFINE(mutex); /**< Mutex to protect context access. */
} phy_ctx;

/* Static forward declarations */
static void nrf9161_dect_phy_event_handler(nrf_modem_dect_phy_event_id_t id,
										   const nrf_modem_dect_phy_event_data_t *event_data);

dect_status_t nrf9161_dect_phy_init(const struct device *dev,
									nrf9161_dect_phy_rx_callback_t rx_cb,
									nrf9161_dect_phy_tx_done_callback_t tx_done_cb)
{
	LOG_INF("PHY: Initializing nRF9161 DECT PHY module...");
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	phy_ctx.rx_cb = rx_cb;
	phy_ctx.tx_done_cb = tx_done_cb;
	phy_ctx.tx_power_dbm = NRF_MODEM_DECT_PHY_TX_POWER_DEFAULT;
	phy_ctx.current_channel = 0; // Default channel
	phy_ctx.current_radio_mode = POWER_MODE_ACTIVE; // Start in active mode
	phy_ctx.current_modem_time = k_uptime_get() * NRF_MODEM_DECT_PHY_MODEM_UNIT_PER_MS; // Initialize with system uptime

	// Register the event handler for all PHY events
	int ret = nrf_modem_dect_phy_event_handler_set(nrf9161_dect_phy_event_handler);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_NOT_READY, "PHY: Failed to set event handler: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PHY_NOT_READY;
	}

	// Activate the DECT PHY stack
	ret = nrf_modem_dect_phy_activate();
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_NOT_READY, "PHY: Failed to activate DECT PHY: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PHY_NOT_READY;
	}
	LOG_INF("PHY: DECT PHY activated.");

	// Configure initial PHY parameters (e.g., radio mode, TX power, LBT parameters)
	nrf_modem_dect_phy_config_t config = {
		.radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY, // Initial active mode
		.tx_power = NRF_MODEM_DECT_PHY_TX_POWER_DEFAULT,
		.lbt = {
			.enabled = dect_config.enable_lbt,
			.rssi_threshold = dect_config.lbt_rssi_threshold_dbm,
			.period = dect_config.lbt_period_modem_units,
		},
	};

	ret = nrf_modem_dect_phy_configure(&config);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_NOT_READY, "PHY: Failed to configure DECT PHY: %d.", ret);
		nrf_modem_dect_phy_deactivate(); // Deactivate if configure fails
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PHY_NOT_READY;
	}
	LOG_INF("PHY: DECT PHY configured with initial radio mode %u, TX power %d, LBT %s.",
			config.radio_mode, config.tx_power, config.lbt.enabled ? "enabled" : "disabled");

	LOG_INF("PHY: nRF9161 DECT PHY module initialized successfully.");
	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_transmit(const struct device *dev, struct net_buf *data_buf,
										uint32_t harq_transaction_id,
										nrf_modem_dect_phy_tx_type_t tx_type,
										uint64_t start_time_modem_units)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	if (!data_buf || data_buf->len == 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "PHY: Cannot transmit NULL or empty data_buf.");
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_INVALID_PARAM;
	}

	if (data_buf->len > NRF_MODEM_DECT_PHY_MAX_PAYLOAD_SIZE) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "PHY: PDU size %u exceeds max PHY payload %u.",
						   data_buf->len, NRF_MODEM_DECT_PHY_MAX_PAYLOAD_SIZE);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PDU_TOO_LARGE;
	}

	// Prepare TX parameters
	nrf_modem_dect_phy_tx_params_t tx_params = {
		.tx_type = tx_type,
		.tx_power = phy_ctx.tx_power_dbm,
		.start_time = start_time_modem_units,
		.channel = phy_ctx.current_channel,
		.payload_len = data_buf->len,
		.payload = data_buf->data,
	};

	LOG_DBG("PHY: Calling nrf_modem_dect_phy_tx(HARQ ID 0x%x, channel %u, start_time %llu, len %u, type %u).",
			harq_transaction_id, phy_ctx.current_channel, start_time_modem_units,
			tx_params.payload_len, tx_params.tx_type);

	// The `harq_transaction_id` is passed as the `handle` for the Nordic API call.
	int ret = nrf_modem_dect_phy_tx(harq_transaction_id, &tx_params);

	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_TX_FAILED, "PHY: nrf_modem_dect_phy_tx failed: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		switch (ret) {
			case -NRF_MODEM_DECT_PHY_ERR_LBT_BUSY: return DECT_ERROR_PHY_CHANNEL_BUSY;
			case -NRF_MODEM_DECT_PHY_ERR_SCHED_TOO_LATE: return DECT_ERROR_PHY_SCHED_TOO_LATE;
			case -NRF_MODEM_DECT_PHY_ERR_SCHED_CONFLICT: return DECT_ERROR_PHY_SCHED_CONFLICT;
			case -NRF_EPERM: return DECT_ERROR_PHY_NOT_READY;
			default: return DECT_ERROR_PHY_TX_FAILED;
		}
	}

	LOG_DBG("PHY: nrf_modem_dect_phy_tx request queued successfully for HARQ ID 0x%x.", harq_transaction_id);
	// Data buffer ownership is conceptually transferred to the modem.
	// The MAC layer will unref this buffer when it receives the TX completion notification.

	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_receive(const struct device *dev, uint64_t start_time_modem_units,
									   uint32_t duration_modem_units,
									   nrf_modem_dect_phy_rx_mode_t rx_mode)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	// Prepare RX parameters
	nrf_modem_dect_phy_rx_params_t rx_params = {
		.rx_mode = rx_mode,
		.start_time = start_time_modem_units,
		.duration = duration_modem_units,
		.channel = phy_ctx.current_channel,
	};

	LOG_DBG("PHY: Calling nrf_modem_dect_phy_rx(channel %u, start_time %llu, duration %u, mode %u).",
			phy_ctx.current_channel, start_time_modem_units, duration_modem_units, rx_mode);

	// The handle for RX operations can be 0 or a unique ID if we need to track multiple RX requests.
	// For simple continuous or single-shot RX, 0 is often sufficient.
	int ret = nrf_modem_dect_phy_rx(0, &rx_params);

	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_RX_FAILED, "PHY: nrf_modem_dect_phy_rx failed: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		switch (ret) {
			case -NRF_EPERM: return DECT_ERROR_PHY_NOT_READY;
			case -NRF_EINVAL: return DECT_ERROR_INVALID_PARAM;
			default: return DECT_ERROR_PHY_RX_FAILED;
		}
	}
	LOG_DBG("PHY: nrf_modem_dect_phy_rx request queued successfully.");
	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_transmit_receive(const struct device *dev,
											   struct net_buf *tx_data_buf,
											   uint32_t tx_harq_transaction_id,
											   nrf_modem_dect_phy_tx_type_t tx_type,
											   uint64_t tx_start_time_modem_units,
											   uint32_t rx_start_offset_modem_units,
											   uint32_t rx_duration_modem_units,
											   nrf_modem_dect_phy_rx_mode_t rx_mode)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	if (!tx_data_buf || net_buf_tailroom(tx_data_buf) == 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "PHY: Cannot TX/RX NULL or empty tx_data_buf.");
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_INVALID_PARAM;
	}

	if (net_buf_tailroom(tx_data_buf) > NRF_MODEM_DECT_PHY_MAX_PAYLOAD_SIZE) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "PHY: TX PDU size %u exceeds max PHY payload %u.",
						   net_buf_tailroom(tx_data_buf), NRF_MODEM_DECT_PHY_MAX_PAYLOAD_SIZE);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PDU_TOO_LARGE;
	}

	nrf_modem_dect_phy_tx_rx_params_t tx_rx_params = {
		.tx.tx_type = tx_type,
		.tx.tx_power = phy_ctx.tx_power_dbm,
		.tx.channel = phy_ctx.current_channel,
		.tx.payload_len = net_buf_tailroom(tx_data_buf),
		.tx.payload = tx_data_buf->data,
		.rx.rx_mode = rx_mode,
		.rx.channel = phy_ctx.current_channel, // RX usually on same channel as TX
		.rx_start_offset = rx_start_offset_modem_units,
		.rx.duration = rx_duration_modem_units,
	};

	LOG_DBG("PHY: Calling nrf_modem_dect_phy_tx_rx(TX HARQ ID 0x%x, start_time %llu, RX offset %u, RX duration %u).",
			tx_harq_transaction_id, tx_start_time_modem_units, rx_start_offset_modem_units, rx_duration_modem_units);

	// The tx_harq_transaction_id is passed as the handle for the Nordic API call.
	int ret = nrf_modem_dect_phy_tx_rx(tx_harq_transaction_id, tx_start_time_modem_units, &tx_rx_params);

	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_TX_FAILED, "PHY: nrf_modem_dect_phy_tx_rx failed: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		// Map Nordic error codes as in nrf9161_dect_phy_transmit
		switch (ret) {
			case -NRF_MODEM_DECT_PHY_ERR_LBT_BUSY: return DECT_ERROR_PHY_CHANNEL_BUSY;
			case -NRF_MODEM_DECT_PHY_ERR_SCHED_TOO_LATE: return DECT_ERROR_PHY_SCHED_TOO_LATE;
			case -NRF_MODEM_DECT_PHY_ERR_SCHED_CONFLICT: return DECT_ERROR_PHY_SCHED_CONFLICT;
			case -NRF_EPERM: return DECT_ERROR_PHY_NOT_READY;
			default: return DECT_ERROR_PHY_TX_FAILED;
		}
	}

	LOG_DBG("PHY: nrf_modem_dect_phy_tx_rx request queued successfully for HARQ ID 0x%x.", tx_harq_transaction_id);
	// Data buffer ownership conceptually transferred to modem. MAC will handle its unref.

	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_set_channel(const struct device *dev, uint8_t channel_id)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	if (channel_id >= NRF_MODEM_DECT_PHY_NUM_CHANNELS) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "PHY: Invalid channel ID %u.", channel_id);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_INVALID_PARAM;
	}

	// The nrf_modem_dect_phy_configure function is used to set the current channel
	// However, it's typically part of a larger configuration update.
	// If only channel change is needed, we need to ensure the modem is in a state
	// where channel changes are allowed without disrupting ongoing operations.
	// For simplicity, we directly update the internal context. The next TX/RX will use it.
	// A real implementation might need to call nrf_modem_dect_phy_configure with updated channel.

	// For now, we update the internal context and rely on subsequent TX/RX calls.
	phy_ctx.current_channel = channel_id;
	LOG_DBG("PHY: Channel set to %u (internal context only).", phy_ctx.current_channel);

	// To make this effective immediately for the modem, we would need to reconfigure.
	// This might involve stopping ongoing TX/RX and restarting with new channel.
	// Example:
	nrf_modem_dect_phy_config_t current_config;
	int ret = nrf_modem_dect_phy_config_get(&current_config);
	if (ret == 0) {
		current_config.channel = channel_id;
		ret = nrf_modem_dect_phy_configure(&current_config);
		if (ret != 0) {
			DECT_ERROR_HANDLER(DECT_ERROR_PHY_CONFIG_FAILED, "PHY: Failed to configure channel %u: %d.", channel_id, ret);
			k_mutex_unlock(&phy_ctx.mutex);
			return DECT_ERROR_PHY_CONFIG_FAILED;
		}
		LOG_INF("PHY: Modem channel successfully set to %u.", channel_id);
	} else {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "PHY: Failed to get current PHY config: %d. Channel not set in modem.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_GENERIC;
	}


	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_set_tx_power(const struct device *dev, int8_t power_dbm)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	// Check if power_dbm is within supported range (conceptual for now, or check Nordic API limits)
	if (power_dbm < NRF_MODEM_DECT_PHY_TX_POWER_MIN || power_dbm > NRF_MODEM_DECT_PHY_TX_POWER_MAX) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "PHY: TX power %d dBm out of range [%d, %d].",
						   power_dbm, NRF_MODEM_DECT_PHY_TX_POWER_MIN, NRF_MODEM_DECT_PHY_TX_POWER_MAX);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_INVALID_PARAM;
	}

	phy_ctx.tx_power_dbm = power_dbm;
	LOG_DBG("PHY: TX power set to %d dBm (internal context only).", phy_ctx.tx_power_dbm);

	// To apply to modem, retrieve current config, update tx_power, and re-configure
	nrf_modem_dect_phy_config_t current_config;
	int ret = nrf_modem_dect_phy_config_get(&current_config);
	if (ret == 0) {
		current_config.tx_power = power_dbm;
		ret = nrf_modem_dect_phy_configure(&current_config);
		if (ret != 0) {
			DECT_ERROR_HANDLER(DECT_ERROR_PHY_CONFIG_FAILED, "PHY: Failed to configure TX power %d: %d.", power_dbm, ret);
			k_mutex_unlock(&phy_ctx.mutex);
			return DECT_ERROR_PHY_CONFIG_FAILED;
		}
		LOG_INF("PHY: Modem TX power successfully set to %d dBm.", power_dbm);
	} else {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "PHY: Failed to get current PHY config: %d. TX power not set in modem.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_GENERIC;
	}

	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_set_radio_mode(const struct device *dev, power_mode_t mode)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	nrf_modem_dect_phy_radio_mode_t modem_radio_mode;

	switch (mode) {
	case POWER_MODE_ACTIVE:
		modem_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY;
		break;
	case POWER_MODE_IDLE: // Or similar low power mode with quick wakeup
		modem_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY_WITH_STANDBY;
		break;
	case POWER_MODE_STANDBY_LBT:
		modem_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_LBT_WITH_STANDBY;
		break;
	case POWER_MODE_STANDBY_NO_LBT:
		modem_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_NON_LBT_WITH_STANDBY;
		break;
	case POWER_MODE_DEEP_SLEEP:
		modem_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_DEEP_SLEEP;
		break;
	case POWER_MODE_DEACTIVATED:
		// Deactivation is a separate API call, not a radio mode config.
		// Handled outside this function by dect_power_mgr.
		LOG_WRN("PHY: POWER_MODE_DEACTIVATED should be handled via dect_phy_deactivate.");
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_INVALID_PARAM;
	default:
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "PHY: Unknown power mode %u.", mode);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_INVALID_PARAM;
	}

	nrf_modem_dect_phy_config_t current_config;
	int ret = nrf_modem_dect_phy_config_get(&current_config);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "PHY: Failed to get current PHY config: %d. Radio mode not set.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_GENERIC;
	}

	current_config.radio_mode = modem_radio_mode;
	ret = nrf_modem_dect_phy_configure(&current_config);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_CONFIG_FAILED, "PHY: Failed to configure radio mode %u: %d.", modem_radio_mode, ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PHY_CONFIG_FAILED;
	}

	phy_ctx.current_radio_mode = mode;
	LOG_INF("PHY: Radio mode set to %u (modem radio mode %u).", mode, modem_radio_mode);
	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_deactivate(const struct device *dev)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	int ret = nrf_modem_dect_phy_deactivate();
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_DEACTIVATION_FAILED, "PHY: Failed to deactivate DECT PHY: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PHY_DEACTIVATION_FAILED;
	}
	phy_ctx.current_radio_mode = POWER_MODE_DEACTIVATED;
	LOG_INF("PHY: DECT PHY deactivated.");
	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

dect_status_t nrf9161_dect_phy_perform_lbt(const struct device *dev)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	if (!dect_config.enable_lbt) {
		LOG_DBG("PHY: LBT is disabled in config. Skipping LBT check.");
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_STATUS_OK; // No LBT performed, return OK as if channel is clear
	}

	LOG_DBG("PHY: Requesting LBT on channel %u...", phy_ctx.current_channel);
	int ret = nrf_modem_dect_phy_lbt_request(phy_ctx.current_channel, dect_config.lbt_rssi_threshold_dbm,
											 dect_config.lbt_period_modem_units);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_LBT_FAILED, "PHY: LBT request failed: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return DECT_ERROR_PHY_LBT_FAILED;
	}

	// The result of this LBT request will be provided via NRF_MODEM_DECT_PHY_EVT_LBT event.
	// For TX operations, the nrf_modem_dect_phy_tx call itself will implicitly perform LBT
	// based on the configured LBT parameters, if enabled. This standalone LBT request
	// can be used for explicit channel sensing or pre-transmission checks.
	LOG_DBG("PHY: LBT request sent. Result will be in event callback.");

	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

uint64_t nrf9161_dect_phy_get_modem_time(void)
{
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);
	// Request modem time asynchronously
	int ret = nrf_modem_dect_phy_time_get();
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_TIME_GET_FAILED, "PHY: Failed to request modem time: %d.", ret);
		k_mutex_unlock(&phy_ctx.mutex);
		return 0; // Return 0 or last known time on error
	}
	// The actual time will be updated via NRF_MODEM_DECT_PHY_EVT_TIME event.
	// For synchronous access, one might use a semaphore here.
	// For now, return the last known time.
	uint64_t time = phy_ctx.current_modem_time;
	k_mutex_unlock(&phy_ctx.mutex);
	return time;
}

dect_status_t nrf9161_dect_phy_adjust_modem_time(const struct device *dev, uint64_t new_modem_time)
{
	ARG_UNUSED(dev);
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);

	// The Nordic API doesn't have a direct "set modem time" function.
	// Synchronization is usually achieved by the Portable Part observing FP beacons
	// and calculating offsets. The `start_time` in TX/RX operations allows
	// precise scheduling relative to the *modem's* current time.
	// If the modem provides a way to adjust its internal clock, it would be here.
	// For simulation, we just update our internal `current_modem_time`.
	phy_ctx.current_modem_time = new_modem_time;
	LOG_INF("PHY: Modem time adjusted to %llu (conceptual, internal context only).", new_modem_time);

	// In a real system, this would involve more sophisticated sync algorithms,
	// potentially with a call to modem API if it supported clock synchronization.
	k_mutex_unlock(&phy_ctx.mutex);
	return DECT_STATUS_OK;
}

uint32_t nrf9161_dect_phy_get_tx_slot_duration(void)
{
	// This is a conceptual duration. The actual slot duration is fixed by DECT NR+.
	// NRF_MODEM_DECT_PHY_SLOT_DURATION_US is in microseconds, convert to modem units.
	return NRF_MODEM_DECT_PHY_SLOT_DURATION_US * NRF_MODEM_DECT_PHY_MODEM_UNIT_PER_US;
}

/**
 * @brief Main event handler for nRF9161 DECT PHY modem events.
 * This function processes events from the modem and dispatches them
 * to the registered MAC layer callbacks.
 * @param id The event ID.
 * @param event_data Pointer to the event-specific data.
 */
static void nrf9161_dect_phy_event_handler(nrf_modem_dect_phy_event_id_t id,
										   const nrf_modem_dect_phy_event_data_t *event_data)
{
	k_mutex_lock(&phy_ctx.mutex, K_FOREVER);
	switch (id) {
	case NRF_MODEM_DECT_PHY_EVT_COMPLETED: {
		// Transmission or Reception completed
		const nrf_modem_dect_phy_event_completed_t *completed_evt = &event_data->completed;
		LOG_DBG("PHY Event: COMPLETED. Handle: 0x%x, Status: %d, Type: %u.",
				completed_evt->handle, completed_evt->status, completed_evt->op_type);

		if (completed_evt->op_type == NRF_MODEM_DECT_PHY_OP_TYPE_TX ||
			completed_evt->op_type == NRF_MODEM_DECT_PHY_OP_TYPE_TX_RX) {
			// TX or TX_RX operation completed
			mac_harq_feedback_t feedback = MAC_HARQ_FEEDBACK_NACK;
			dect_status_t tx_status = DECT_ERROR_PHY_TX_FAILED;

			if (completed_evt->status == 0) {
				// Successful TX. Assume ACK on success if status is 0.
				feedback = MAC_HARQ_FEEDBACK_ACK;
				tx_status = DECT_STATUS_OK;
				STATS_INC(phy_tx_success);
			} else {
				LOG_WRN("PHY: TX/TX_RX completed with error status: %d (handle 0x%x).", completed_evt->status, completed_evt->handle);
				STATS_INC(phy_tx_failed);
			}

			if (phy_ctx.tx_done_cb) {
				uint8_t retransmission_count = (completed_evt->status != 0) ? 1 : 0; // Simple inference
				phy_ctx.tx_done_cb(NULL, completed_evt->handle, tx_status, feedback, retransmission_count);
			}
		} else if (completed_evt->op_type == NRF_MODEM_DECT_PHY_OP_TYPE_RX) {
			// RX operation completed (e.g., single shot RX completed)
			LOG_DBG("PHY: RX operation completed (handle 0x%x, status %d). Waiting for PDC event.",
					completed_evt->handle, completed_evt->status);
			// Actual received data comes via NRF_MODEM_DECT_PHY_EVT_PDC
		}
		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_PDC: {
		// Received PDU data
		const nrf_modem_dect_phy_event_pdc_t *pdc_evt = &event_data->pdc;
		LOG_DBG("PHY Event: PDC (RX data). Len: %u, RSSI: %d, Channel: %u, CRC OK: %u, HARQ Process: %u.",
				pdc_evt->payload_len, pdc_evt->rssi, pdc_evt->channel, pdc_evt->crc_ok, pdc_evt->harq_process_number);
		STATS_INC(phy_rx_frames);
		if (!pdc_evt->crc_ok) {
			STATS_INC(phy_rx_crc_errors);
			LOG_WRN("PHY: Received packet with CRC error on channel %u.", pdc_evt->channel);
		}

		if (phy_ctx.rx_cb && pdc_evt->payload_len > 0) {
			struct net_buf *rx_buf = net_buf_alloc(&mac_rx_net_buf_pool, K_NO_WAIT);
			if (!rx_buf) {
				DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "PHY: Failed to allocate net_buf for RX PDU. Dropping.");
				STATS_INC(phy_rx_drops);
				break;
			}
			net_buf_add_mem(rx_buf, pdc_evt->payload, pdc_evt->payload_len);

			nrf9161_dect_rx_packet_t rx_packet = {
				.data_buf = rx_buf, // Transfer ownership
				.rssi = pdc_evt->rssi,
				.channel = pdc_evt->channel,
				.crc_ok = pdc_evt->crc_ok,
				.src_short_rd_id = 0, // Not provided by PHY, MAC needs to parse
				.harq_transaction_id = pdc_evt->handle, // Use the handle from PDC for correlation
				.modem_time = pdc_evt->modem_time,
				.harq_process_number = pdc_evt->harq_process_number, // NEW: Copy HARQ process number
			};
			phy_ctx.rx_cb(NULL, &rx_packet);

			// **NEW: Automatically send HARQ feedback via nrf_modem_dect_phy_tx_harq()**
			// According to recommendation by Nordic: "always NACK, with modem auto-adjusting to ACK if PDC is successful".
			int ret_harq = nrf_modem_dect_phy_tx_harq(pdc_evt->handle, NRF_MODEM_DECT_PHY_HARQ_FEEDBACK_NACK);
			if (ret_harq != 0) {
				LOG_ERR("PHY: Failed to send HARQ feedback for handle 0x%x (process %u): %d",
						pdc_evt->handle, pdc_evt->harq_process_number, ret_harq);
				STATS_INC(phy_harq_feedback_failures);
			} else {
				LOG_DBG("PHY: Sent HARQ feedback (NACK) for handle 0x%x (process %u).",
						pdc_evt->handle, pdc_evt->harq_process_number);
				STATS_INC(phy_harq_feedback_tx);
			}

		} else {
			LOG_WRN("PHY: RX callback not registered or empty payload. Dropping PDC.");
			if (pdc_evt->payload_len > 0) {
				STATS_INC(phy_rx_drops);
			}
		}
		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_TIME: {
		// Modem time update
		const nrf_modem_dect_phy_event_time_t *time_evt = &event_data->time;
		phy_ctx.current_modem_time = time_evt->modem_time;
		LOG_DBG("PHY Event: TIME. Modem time: %llu.", phy_ctx.current_modem_time);
		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_LBT: {
		// LBT result
		const nrf_modem_dect_phy_event_lbt_t *lbt_evt = &event_data->lbt;
		LOG_DBG("PHY Event: LBT. Channel: %u, RSSI: %d, Result: %d (0=clear, 1=busy).",
				lbt_evt->channel, lbt_evt->rssi, lbt_evt->is_busy);
		STATS_INC(phy_lbt_checks);
		if (lbt_evt->is_busy) {
			STATS_INC(phy_lbt_busy);
		} else {
			STATS_INC(phy_lbt_clear);
		}
		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_ERROR: {
		// General PHY error
		const nrf_modem_dect_phy_event_error_t *error_evt = &event_data->error;
		DECT_ERROR_HANDLER(DECT_ERROR_PHY_GENERIC, "PHY Event: ERROR. Code: %d.", error_evt->error);
		STATS_INC(phy_errors);
		break;
	}
	default:
		LOG_WRN("PHY Event: Unknown event ID %u.", id);
		break;
	}
	k_mutex_unlock(&phy_ctx.mutex);
}

/* End of File
 * Last Amended: 2025-06-04 14:00 BST: Updated dect_phy_nrf9161.c
 * - In `nrf9161_dect_phy_init`, `phy_ctx.current_modem_time` is now initialized using `k_uptime_get()`.
 * - Modified `nrf9161_dect_phy_transmit`:\r\n * - Simplified to only call `nrf_modem_dect_phy_tx()` conceptually. It no longer attempts to differentiate between initial TX and HARQ re-TX. The `harq_transaction_id` parameter is now solely for the MAC layer to correlate TX completion events.\r\n * - The `data_buf` is now unreferenced immediately after the conceptual `nrf_modem_dect_phy_tx()` call, assuming the modem takes ownership.\r\n * - Added `nrf9161_dect_...
 * Last Amended: 2025-06-12 11:30 BST: Fully implemented nRF9161 DECT PHY interactions.
 * - `nrf9161_dect_phy_init`:
 * - Calls `nrf_modem_dect_phy_event_handler_set` to register `nrf9161_dect_phy_event_handler`.
 * - Calls `nrf_modem_dect_phy_activate()` to activate the PHY stack.
 * - Calls `nrf_modem_dect_phy_configure()` with initial radio mode, TX power, and LBT parameters from `dect_config`.
 * - Initializes `phy_ctx.current_modem_time` using `k_uptime_get() * NRF_MODEM_DECT_PHY_MODEM_UNIT_PER_MS`.
 * - `nrf9161_dect_phy_transmit`:
 * - Creates `nrf_modem_dect_phy_tx_params_t` from `data_buf`, `tx_type`, `start_time_modem_units`, `current_channel`, `tx_power_dbm`.
 * - Calls `nrf_modem_dect_phy_tx()` passing `harq_transaction_id` as the `handle`.
 * - Maps `nrf_modem_dect_phy_tx` specific error codes (`-NRF_MODEM_DECT_PHY_ERR_LBT_BUSY`, `-NRF_MODEM_DECT_PHY_ERR_SCHED_TOO_LATE`, etc.) to `DECT_ERROR` codes.
 * - Correctly handles `net_buf` ownership (MAC retains reference, PHY uses data pointer).
 * - `nrf9161_dect_phy_receive`:
 * - Creates `nrf_modem_dect_phy_rx_params_t` and calls `nrf_modem_dect_phy_rx()`.
 * - `nrf9161_dect_phy_set_channel`:
 * - Now uses `nrf_modem_dect_phy_config_get` and `nrf_modem_dect_phy_configure` to update the modem's channel.
 * - `nrf9161_dect_phy_set_tx_power`:
 * - Now uses `nrf_modem_dect_phy_config_get` and `nrf_modem_dect_phy_configure` to update the modem's TX power.
 * - `nrf9161_dect_phy_set_radio_mode`:
 * - Maps `power_mode_t` to `nrf_modem_dect_phy_radio_mode_t` and calls `nrf_modem_dect_phy_configure`.
 * - `nrf9161_dect_phy_deactivate`:
 * - Calls `nrf_modem_dect_phy_deactivate()` to fully deactivate the PHY.
 * - `nrf9161_dect_phy_perform_lbt`:
 * - Calls `nrf_modem_dect_phy_lbt_request()`. Notes that this is primarily for requesting LBT parameters, and actual LBT is part of `nrf_modem_dect_phy_tx`.
 * - `nrf9161_dect_phy_get_modem_time`:
 * - Calls `nrf_modem_dect_phy_time_get()` to request modem time asynchronously. Returns last known time.
 * - `nrf9161_dect_phy_event_handler`:
 * - This new static callback function processes various `nrf_modem_dect_phy_event_id_t` events.
 * - `NRF_MODEM_DECT_PHY_EVT_COMPLETED`: Calls `phy_ctx.tx_done_cb` for TX completions. Infers `feedback` and `tx_status`.
 * - `NRF_MODEM_DECT_PHY_EVT_PDC`: Allocates `mac_rx_net_buf_pool` buffer, copies payload, populates `nrf9161_dect_rx_packet_t`, and calls `phy_ctx.rx_cb`. Handles CRC status.
 * - `NRF_MODEM_DECT_PHY_EVT_TIME`: Updates `phy_ctx.current_modem_time`.
 * - `NRF_MODEM_DECT_PHY_EVT_LBT`: Logs LBT results.
 * - `NRF_MODEM_DECT_PHY_EVT_ERROR`: Logs generic PHY errors.
 * - Added mutex protection for `phy_ctx`.
 * - Updated statistics (`STATS_INC`).
 * Last Amended: 2025-06-13 16:00 BST: Clarified comments in `nrf9161_dect_phy_perform_lbt` to align with direct API call.
 * Last Amended: 2025-06-06 13:00 BST: Implemented `nrf9161_dect_phy_transmit_receive` function. Modified `nrf9161_dect_phy_event_handler` to handle `NRF_MODEM_DECT_PHY_OP_TYPE_TX_RX` completion.
 * Last Amended: 2025-06-06 14:30 BST: Modified `nrf9161_dect_phy_event_handler` (NRF_MODEM_DECT_PHY_EVT_PDC) to copy `harq_process_number` and automatically call `nrf_modem_dect_phy_tx_harq()` for immediate feedback.
 */
