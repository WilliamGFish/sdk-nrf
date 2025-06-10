/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_CONFIG_H__
#define DECT_CONFIG_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h> // For K_FOREVER
#include <dect_nr_plus/dect_errors.h> // For dect_status_t

/**
 * @brief DECT NR+ configuration structure.
 * This structure holds all configurable parameters for the DECT NR+ driver.
 */
typedef struct {
	uint8_t mac_address[4]; /**< Long RD ID (MAC address) of the device. */
	uint16_t short_rd_id;   /**< Short RD ID of the device. */
	uint8_t initial_channel;/**< Initial channel to operate on (0-9). */
	bool enable_encryption; /**< Enable/disable AES-128 encryption. */
	bool enable_qos;        /**< Enable/disable Quality of Service features. */
	bool enable_routing;    /**< Enable/disable Routing layer (e.g., AODV). */
	bool enable_channel_reselection; /**< Enable/disable automatic channel reselection. */
	int8_t channel_reselection_rssi_threshold_dbm; /**< RSSI threshold (dBm) to trigger channel reselection. */
	uint32_t t_mac_assoc_timeout_ms; /**< MAC Association timeout in ms. */
	uint8_t mac_max_assoc_retries; /**< Max MAC association retries. */
	uint32_t t_mac_inactivity_timeout_ms; /**< MAC Inactivity timeout in ms. */
	uint32_t t_mac_sync_timeout_ms; /**< MAC Synchronization timeout in ms. */
	uint8_t mac_max_sync_retries; /**< Max MAC synchronization retries. */
	uint32_t t_mac_resource_req_timeout_ms; /**< MAC Resource Request timeout in ms. */
	uint8_t mac_max_resource_req_retries; /**< Max MAC resource request retries. */
	uint32_t t_mac_beacon_interval_ms; /**< MAC Beacon interval in ms (FP). */
	uint32_t t_mac_security_timeout_ms; /**< MAC Security Handshake timeout in ms. */
	uint8_t mac_max_security_retries; /**< Max MAC security handshake retries. */
	uint32_t t_mac_sync_drift_threshold_us; /**< Threshold for modem time synchronization drift in us. */
	uint32_t t_dlc_conn_timeout_ms; /**< DLC connection timeout in ms. */
	uint32_t t_dlc_release_timeout_ms; /**< DLC release timeout in ms. */
	uint32_t t_dlc_retransmission_timeout_ms; /**< DLC retransmission timeout in ms. */
	uint8_t dlc_max_retransmissions; /**< Max DLC retransmissions. */
	uint32_t dlc_tx_window_size; /**< DLC TX window size. */
	uint32_t dlc_rx_window_size; /**< DLC RX window size. */
	uint32_t t_dlc_delayed_ack_ms; /**< DLC Delayed ACK timeout in ms. */
	uint32_t t_cvg_reassembly_timeout_ms; /**< CVG SDU reassembly timeout in ms. */
	uint32_t t_routing_route_discovery_timeout_ms; /**< Routing route discovery timeout in ms. */
	uint32_t routing_route_expiry_timeout_s; /**< Routing route expiry timeout in seconds. */
	uint8_t routing_max_hops; /**< Routing max hops. */
	uint8_t routing_max_route_retries; /**< Routing max route retries. */
	int8_t lbt_rssi_threshold_dbm; /**< LBT RSSI threshold in dBm. */
	uint32_t lbt_period_modem_units; /**< LBT period in modem units. */
	uint32_t channel_blacklist_mask; /**< Bitmask of blacklisted channels. */
	uint32_t channel_whitelist_mask; /**< Bitmask of whitelisted channels. */
	uint16_t max_mac_assoc_peers; /**< Max number of associated peers FP can handle. */
	mac_role_t device_role; /**< Configured device role (FP/PP). */
	bool enable_mobility_support; /**< New: Enable/disable mobility features. */
	uint32_t t_mac_handover_timeout_ms; /**< New: MAC Handover timeout in ms. */
	uint8_t mac_max_handover_retries; /**< New: Max MAC handover retries. */
	uint32_t t_mac_sync_loss_timeout_ms; /**< Timeout for sync loss detection in ms. */ // Missing in last prj.conf but part of original driver
} dect_config_t;

/**
 * @brief Global DECT NR+ configuration instance.
 * Defined in dect_config.c.
 */
extern dect_config_t dect_config;

/**
 * @brief Initializes the DECT NR+ configuration module.
 * This function loads configuration from persistent storage (if available)
 * and applies default values if no stored configuration is found.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_config_init(void);

/**
 * @brief Saves the current DECT NR+ configuration to persistent storage.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_save_config(void);

#endif /* DECT_CONFIG_H__ */

/* End of File
 * Last Amended: 2025-06-05 15:30 BST: Updated dect_config.h for Mobility.
 * - Added `enable_mobility_support` flag.
 * - Added `t_mac_handover_timeout_ms` for handover negotiation timeout.
 * - Added `mac_max_handover_retries` for handover retry attempts.
 * - Included `t_mac_sync_loss_timeout_ms` which was missing from previous prj.conf but was in `dect_types.h`.
 */
