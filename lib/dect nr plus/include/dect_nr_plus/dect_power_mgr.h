/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_POWER_MGR_H__
#define DECT_POWER_MGR_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h> // For k_timer, k_mutex

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For power_mode_t, power_change_reason_t

/**
 * @brief Power Manager states.
 */
typedef enum {
	POWER_MGR_STATE_ACTIVE,       /**< Device is fully active. */
	POWER_MGR_STATE_IDLE_REQUESTED, /**< Idle mode requested, waiting for transition. */
	POWER_MGR_STATE_IDLE,         /**< Device is in idle mode. */
	POWER_MGR_STATE_DEEP_SLEEP_REQUESTED, /**< Deep sleep requested, waiting for transition. */
	POWER_MGR_STATE_DEEP_SLEEP,   /**< Device is in deep sleep mode. */
	POWER_MGR_STATE_STANDBY_LBT_REQUESTED, /**< Standby with LBT requested. */
	POWER_MGR_STATE_STANDBY_LBT,  /**< Device is in standby with LBT. */
	POWER_MGR_STATE_STANDBY_NO_LBT_REQUESTED, /**< Standby without LBT requested. */
	POWER_MGR_STATE_STANDBY_NO_LBT, /**< Device is in standby without LBT. */
	POWER_MGR_STATE_DEACTIVATED_REQUESTED, /**< Deactivated mode requested. */
	POWER_MGR_STATE_DEACTIVATED,  /**< Device is fully deactivated. */
} power_mgr_state_t;

/**
 * @brief Power Manager context structure.
 */
typedef struct {
	power_mode_t current_power_mode;        /**< Current active power mode of the device. */
	power_mgr_state_t state;                 /**< Internal state machine state. */
	uint64_t last_activity_time_ms;          /**< Uptime of last detected activity. */
	struct k_timer inactivity_timer;         /**< Timer for inactivity detection. */
	struct k_timer transition_delay_timer;   /**< Timer for power mode transition delays. */
	K_MUTEX_DEFINE(mutex);                   /**< Mutex to protect context access. */
} dect_power_mgr_context_t;

/**
 * @brief Global Power Manager context instance.
 * Defined in dect_power_mgr.c.
 */
extern dect_power_mgr_context_t power_mgr_ctx;

/**
 * @brief Initializes the Power Manager module.
 * Sets up timers and initial power mode.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_power_mgr_init(void);

/**
 * @brief Requests a change in the device's power mode.
 * The power manager will handle the transition gracefully.
 *
 * @param new_mode The desired `power_mode_t`.
 * @param reason The reason for the power mode change request.
 * @return DECT_STATUS_OK if request accepted, or an error code.
 */
dect_status_t dect_power_mgr_set_power_mode_request(power_mode_t new_mode, power_change_reason_t reason);

/**
 * @brief Notifies the power manager that activity has been detected.
 * This will reset inactivity timers and potentially bring the device to an active state.
 */
void dect_power_mgr_activity_detected(void);

/**
 * @brief Gets the current power mode of the device.
 *
 * @return The current `power_mode_t`.
 */
power_mode_t dect_power_mgr_get_current_power_mode(void);

/**
 * @brief Timer handler for inactivity timeout.
 * Triggers a request to transition to a lower power mode.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dect_power_mgr_inactivity_timeout_handler(struct k_timer *timer_id);

/**
 * @brief Timer handler for power mode transition delays.
 * This is used to ensure components have time to shut down/wake up.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void dect_power_mgr_transition_delay_timeout_handler(struct k_timer *timer_id);

#endif /* DECT_POWER_MGR_H__ */

/* End of File
 * Last Amended: 2025-06-04 14:00 BST: Updated dect_power_mgr.h
 * - Added new `power_mgr_state_t` enum values:
 * - `POWER_MGR_STATE_STANDBY_LBT_REQUESTED`, `POWER_MGR_STATE_STANDBY_LBT`
 * - `POWER_MGR_STATE_STANDBY_NO_LBT_REQUESTED`, `POWER_MGR_STATE_STANDBY_NO_LBT`
 * - `POWER_MGR_STATE_DEACTIVATED_REQUESTED`, `POWER_MGR_STATE_DEACTIVATED`
 * to support more granular power modes for the nRF9161 PHY.
 */
