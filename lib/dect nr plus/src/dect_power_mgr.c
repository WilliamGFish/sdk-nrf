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
#include <dect_nr_plus/dect_power_mgr.h> /* Own header */
#include <dect_nr_plus/dect_phy_nrf9161.h> /* For PHY power control */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <nrf_modem_dect_phy.h> // For nrf_modem_dect_phy_activate/deactivate

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_power_mgr, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global Power Manager context instance definition */
dect_power_mgr_context_t power_mgr_ctx = {
	.current_power_mode = POWER_MODE_DEACTIVATED, // Start as deactivated, will activate on init
	.state = POWER_MGR_STATE_DEACTIVATED,
	.last_activity_time_ms = 0,
	.inactivity_timer_active = false,
	.transition_in_progress = false,
	.requested_power_mode = POWER_MODE_DEACTIVATED,
	.change_reason = POWER_CHANGE_REASON_INIT,
	.lbt_failures_in_current_mode = 0,
	.last_lbt_success_time_ms = 0,
};

/* Mutex to protect power_mgr_ctx */
K_MUTEX_DEFINE(power_mgr_ctx_mutex);

/* Forward declarations */
static dect_status_t power_mgr_perform_transition(power_mode_t new_mode);


dect_status_t dect_power_mgr_init(void)
{
	k_mutex_init(&power_mgr_ctx.mutex);
	k_timer_init(&power_mgr_ctx.inactivity_timer, dect_power_mgr_inactivity_timeout_handler, NULL);
	k_timer_init(&power_mgr_ctx.transition_delay_timer, dect_power_mgr_transition_delay_timeout_handler, NULL);

	// Initial activation to ACTIVE mode
	dect_status_t status = dect_power_mgr_set_power_mode_request(POWER_MODE_ACTIVE, POWER_CHANGE_REASON_INIT);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "PWR_MGR: Failed to transition to initial ACTIVE mode.");
		return status;
	}

	LOG_INF("PWR_MGR: Module initialized. Current mode: %s.",
		(power_mgr_ctx.current_power_mode == POWER_MODE_ACTIVE) ? "ACTIVE" : "UNKNOWN");
	return DECT_STATUS_OK;
}

dect_status_t dect_power_mgr_set_power_mode_request(power_mode_t new_mode, power_change_reason_t reason)
{
	k_mutex_lock(&power_mgr_ctx.mutex, K_FOREVER);

	if (power_mgr_ctx.current_power_mode == new_mode) {
		LOG_DBG("PWR_MGR: Already in requested mode %u. No action.", new_mode);
		k_mutex_unlock(&power_mgr_ctx.mutex);
		return DECT_STATUS_OK;
	}

	LOG_DBG("PWR_MGR: Request to change power mode from %u to %u (reason %u).",
		power_mgr_ctx.current_power_mode, new_mode, reason);

	power_mgr_ctx.requested_power_mode = new_mode;
	power_mgr_ctx.change_reason = reason;

	// Perform immediate transition if possible, otherwise queue or handle state
	dect_status_t status = power_mgr_perform_transition(new_mode);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "PWR_MGR: Failed to initiate transition to mode %u.", new_mode);
	}

	k_mutex_unlock(&power_mgr_ctx.mutex);
	return status;
}

static dect_status_t power_mgr_perform_transition(power_mode_t new_mode)
{
	// This function assumes power_mgr_ctx_mutex is already locked.
	dect_status_t status = DECT_STATUS_OK;

	LOG_DBG("PWR_MGR: Performing transition to mode %u.", new_mode);

	nrf_modem_dect_phy_radio_mode_t phy_radio_mode;
	uint32_t transition_delay_ms = 0; // Default to no delay

	switch (new_mode) {
	case POWER_MODE_DEACTIVATED:
		phy_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_OFF;
		transition_delay_ms = 0; // Immediate
		power_mgr_ctx.state = POWER_MGR_STATE_DEEP_SLEEP_REQUESTED; // Use deep sleep state for deactivation
		break;
	case POWER_MODE_ACTIVE:
		phy_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY;
		transition_delay_ms = 0; // Immediate for now, could have wake-up delay
		power_mgr_ctx.state = POWER_MGR_STATE_ACTIVE;
		break;
	case POWER_MODE_IDLE:
		phy_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY_WITH_STANDBY;
		transition_delay_ms = CONFIG_DECT_NR_PLUS_POWER_TRANSITION_DELAY_MS;
		power_mgr_ctx.state = POWER_MGR_STATE_IDLE_REQUESTED;
		break;
	case POWER_MODE_STANDBY_LBT:
		phy_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_LBT_WITH_STANDBY;
		transition_delay_ms = CONFIG_DECT_NR_PLUS_POWER_TRANSITION_DELAY_MS;
		power_mgr_ctx.state = POWER_MGR_STATE_STANDBY_LBT_REQUESTED;
		break;
	case POWER_MODE_STANDBY_NO_LBT:
		phy_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_NON_LBT_WITH_STANDBY;
		transition_delay_ms = CONFIG_DECT_NR_PLUS_POWER_TRANSITION_DELAY_MS;
		power_mgr_ctx.state = POWER_MGR_STATE_STANDBY_NO_LBT_REQUESTED;
		break;
	case POWER_MODE_DEEP_SLEEP:
		phy_radio_mode = NRF_MODEM_DECT_PHY_RADIO_MODE_OFF; // PHY off for deep sleep
		transition_delay_ms = CONFIG_DECT_NR_PLUS_POWER_TRANSITION_DELAY_MS;
		power_mgr_ctx.state = POWER_MGR_STATE_DEEP_SLEEP_REQUESTED;
		break;
	default:
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "PWR_MGR: Unsupported power mode requested: %u.", new_mode);
		return DECT_ERROR_INVALID_PARAM;
	}

	power_mgr_ctx.transition_in_progress = true;

	dect_status_t phy_ret;
	if (new_mode == POWER_MODE_DEACTIVATED || new_mode == POWER_MODE_DEEP_SLEEP) {
		phy_ret = nrf9161_dect_phy_deactivate(phy_radio_mode); // Pass radio mode to deactivate
	} else {
		phy_ret = nrf9161_dect_phy_activate(phy_radio_mode);
	}

	if (phy_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(phy_ret, "PWR_MGR: PHY operation failed for mode %u (radio_mode %u).", new_mode, phy_radio_mode);
		power_mgr_ctx.transition_in_progress = false;
		power_mgr_ctx.state = POWER_MGR_STATE_ACTIVE; // Revert to active or last stable state
		return phy_ret;
	}

	if (transition_delay_ms > 0) {
		k_timer_start(&power_mgr_ctx.transition_delay_timer, K_MSEC(transition_delay_ms), K_NO_WAIT);
		LOG_DBG("PWR_MGR: Transition delay timer started for %u ms.", transition_delay_ms);
	} else {
		// No delay, update current mode immediately
		power_mgr_ctx.current_power_mode = new_mode;
		power_mgr_ctx.state = new_mode; // Final state
		power_mgr_ctx.transition_in_progress = false;
		LOG_INF("PWR_MGR: Immediately transitioned to mode %u.", new_mode);
	}

	// Restart inactivity timer if transitioning to an idle/sleep mode
	if (new_mode != POWER_MODE_ACTIVE && new_mode != POWER_MODE_DEACTIVATED &&
		dect_config.t_mac_inactivity_timeout_ms > 0) {
		k_timer_start(&power_mgr_ctx.inactivity_timer, K_MSEC(dect_config.t_mac_inactivity_timeout_ms), K_NO_WAIT);
		power_mgr_ctx.inactivity_timer_active = true;
		LOG_DBG("PWR_MGR: Inactivity timer started (timeout %u ms).", dect_config.t_mac_inactivity_timeout_ms);
	} else {
		k_timer_stop(&power_mgr_ctx.inactivity_timer);
		power_mgr_ctx.inactivity_timer_active = false;
	}

	return DECT_STATUS_OK;
}

void dect_power_mgr_activity_detected(void)
{
	k_mutex_lock(&power_mgr_ctx.mutex, K_FOREVER);
	power_mgr_ctx.last_activity_time_ms = k_uptime_get();

	if (power_mgr_ctx.current_power_mode != POWER_MODE_ACTIVE &&
		!power_mgr_ctx.transition_in_progress) {
		LOG_DBG("PWR_MGR: Activity detected. Requesting transition to ACTIVE mode.");
		dect_status_t status = power_mgr_perform_transition(POWER_MODE_ACTIVE);
		if (status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(status, "PWR_MGR: Failed to transition to ACTIVE mode on activity detection.");
		}
	} else {
		LOG_DBG("PWR_MGR: Activity detected. Already in ACTIVE mode or transitioning.");
	}

	// Reset inactivity timer
	if (power_mgr_ctx.inactivity_timer_active) {
		k_timer_stop(&power_mgr_ctx.inactivity_timer);
		k_timer_start(&power_mgr_ctx.inactivity_timer, K_MSEC(dect_config.t_mac_inactivity_timeout_ms), K_NO_WAIT);
		LOG_DBG("PWR_MGR: Inactivity timer reset.");
	}
	k_mutex_unlock(&power_mgr_ctx.mutex);
}

power_mode_t dect_power_mgr_get_current_power_mode(void)
{
	k_mutex_lock(&power_mgr_ctx.mutex, K_FOREVER);
	power_mode_t mode = power_mgr_ctx.current_power_mode;
	k_mutex_unlock(&power_mgr_ctx.mutex);
	return mode;
}

void dect_power_mgr_inactivity_timeout_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&power_mgr_ctx.mutex, K_FOREVER);
	LOG_INF("PWR_MGR: Inactivity timeout. Requesting transition to IDLE mode.");
	// Request transition to IDLE or a lower power mode based on config
	dect_status_t status = dect_power_mgr_set_power_mode_request(POWER_MODE_IDLE, POWER_CHANGE_REASON_IDLE_TIMEOUT);
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "PWR_MGR: Failed to transition to IDLE mode on inactivity timeout.");
	}
	k_mutex_unlock(&power_mgr_ctx.mutex);
}

void dect_power_mgr_transition_delay_timeout_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&power_mgr_ctx.mutex, K_FOREVER);
	if (power_mgr_ctx.transition_in_progress) {
		LOG_DBG("PWR_MGR: Transition delay timer expired. Completing transition to mode %u.",
			power_mgr_ctx.requested_power_mode);
		power_mgr_ctx.current_power_mode = power_mgr_ctx.requested_power_mode;
		power_mgr_ctx.state = power_mgr_ctx.requested_power_mode; // Final state
		power_mgr_ctx.transition_in_progress = false;
	} else {
		LOG_WRN("PWR_MGR: Transition delay timer expired, but no transition was in progress.");
	}
	k_mutex_unlock(&power_mgr_ctx.mutex);
}

/* End of File
 * Last Amended: 2025-06-09 20:00 BST: Updated dect_power_mgr.c for robust error handling.
 * - Added error checks for `nrf9161_dect_phy_activate` and `nrf9161_dect_phy_deactivate` calls within `power_mgr_perform_transition`.
 * - If PHY operation fails, the state is reverted or set to a stable `ACTIVE` state.
 * - Enhanced logging for power mode transitions and requests.
 * - Added checks for invalid `new_mode` in `power_mgr_perform_transition`.
 * - Updated initial `current_power_mode` to `POWER_MODE_DEACTIVATED` for clarity, and explicitly calls `set_power_mode_request` to `ACTIVE` during init.
 */
