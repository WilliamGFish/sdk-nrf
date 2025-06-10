/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_PHY_NRF9161_H__
#define DECT_PHY_NRF9161_H__

#include <zephyr/types.h>
#include <device.h>
#include <net/net_buf.h>

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For nrf_modem_dect_phy_tx_type_t, nrf_modem_dect_phy_rx_mode_t, etc.
#include <nrf_modem_dect_phy.h> // For nrf_modem_dect_phy_tx_type_t, nrf_modem_dect_phy_rx_mode_t, etc.

/**
 * @brief PHY RX packet structure.
 * Contains the received data buffer and associated metadata from the PHY layer.
 */
typedef struct {
	struct net_buf *data_buf; /**< Net buffer containing the received PHY payload. */
	int8_t rssi; /**< Received Signal Strength Indicator in dBm. */
	uint8_t channel; /**< Channel ID on which the packet was received. */
	bool crc_ok; /**< True if PHY CRC check passed. */
	uint16_t src_short_rd_id; /**< Source Short RD ID (if known/parsed by lower layer, else 0). */
	uint32_t harq_transaction_id; /**< HARQ transaction ID (if associated with a TX/RX pair). */
	uint64_t modem_time; /**< Modem time when the packet was received. */
	uint8_t harq_process_number; /**< HARQ process number for received PDU (for feedback). */
} nrf9161_dect_rx_packet_t;

/**
 * @brief Callback function type for PHY RX events.
 * @param dev Pointer to the PHY device.
 * @param rx_packet Pointer to the received PHY packet.
 */
typedef void (*nrf9161_dect_phy_rx_callback_t)(const struct device *dev,
											   nrf9161_dect_rx_packet_t *rx_packet);

/**
 * @brief Callback function type for PHY TX completion events.
 * @param dev Pointer to the PHY device.
 * @param harq_transaction_id HARQ transaction ID of the completed TX.
 * @param status Status of the PHY transmission (DECT_STATUS_OK for success).
 * @param feedback HARQ feedback received (MAC_HARQ_FEEDBACK_ACK/NACK).
 * @param retransmission_count Number of retransmissions by PHY for this PDU.
 */
typedef void (*nrf9161_dect_phy_tx_done_callback_t)(const struct device *dev,
													uint32_t harq_transaction_id,
													dect_status_t status,
													mac_harq_feedback_t feedback,
													uint8_t retransmission_count);

/**
 * @brief Initializes the nRF9161 DECT PHY module.
 * @param dev Pointer to the PHY device.
 * @param rx_cb Callback for received packets.
 * @param tx_done_cb Callback for TX completion.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_init(const struct device *dev,
									nrf9161_dect_phy_rx_callback_t rx_cb,
									nrf9161_dect_phy_tx_done_callback_t tx_done_cb);

/**
 * @brief Transmits a packet through the nRF9161 DECT PHY.
 * @param dev Pointer to the PHY device.
 * @param data_buf Net buffer containing the data payload. PHY takes ownership.
 * @param harq_transaction_id A unique ID for this transmission for HARQ tracking.
 * @param tx_type The type of transmission (e.g., normal, retransmit).
 * @param start_time_modem_units Absolute modem time in modem units for transmission start.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_transmit(const struct device *dev, struct net_buf *data_buf,
										uint32_t harq_transaction_id,
										nrf_modem_dect_phy_tx_type_t tx_type,
										uint64_t start_time_modem_units);

/**
 * @brief Configures the nRF9161 DECT PHY for reception.
 * @param dev Pointer to the PHY device.
 * @param start_time_modem_units Absolute modem time in modem units for reception start.
 * @param duration_modem_units Duration of the reception window in modem units (0 for continuous).
 * @param rx_mode The reception mode (e.g., single shot, continuous).
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_receive(const struct device *dev, uint64_t start_time_modem_units,
									   uint32_t duration_modem_units,
									   nrf_modem_dect_phy_rx_mode_t rx_mode);

/**
 * @brief Transmits a packet immediately followed by a reception window.
 * This utilizes the nrf_modem_dect_phy_tx_rx() function for lower latency.
 * @param dev Pointer to the PHY device.
 * @param tx_data_buf Net buffer containing the data payload for transmission. PHY takes ownership.
 * @param tx_harq_transaction_id A unique ID for the transmission part for HARQ tracking.
 * @param tx_type The type of transmission.
 * @param tx_start_time_modem_units Absolute modem time for transmission start.
 * @param rx_start_offset_modem_units Offset from the start of TX to the start of RX window.
 * @param rx_duration_modem_units Duration of the reception window in modem units.
 * @param rx_mode The reception mode for the RX part of the operation.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_transmit_receive(const struct device *dev,
											   struct net_buf *tx_data_buf,
											   uint32_t tx_harq_transaction_id,
											   nrf_modem_dect_phy_tx_type_t tx_type,
											   uint64_t tx_start_time_modem_units,
											   uint32_t rx_start_offset_modem_units,
											   uint32_t rx_duration_modem_units,
											   nrf_modem_dect_phy_rx_mode_t rx_mode);

/**
 * @brief Sets the active channel for PHY operations.
 * @param dev Pointer to the PHY device.
 * @param channel_id The ID of the channel to set.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_set_channel(const struct device *dev, uint8_t channel_id);

/**
 * @brief Sets the transmit power for PHY operations.
 * @param dev Pointer to the PHY device.
 * @param power_dbm The transmit power in dBm.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_set_tx_power(const struct device *dev, int8_t power_dbm);

/**
 * @brief Sets the radio operating mode of the PHY.
 * @param dev Pointer to the PHY device.
 * @param mode The desired power mode.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_set_radio_mode(const struct device *dev, power_mode_t mode);

/**
 * @brief Deactivates the nRF9161 DECT PHY.
 * @param dev Pointer to the PHY device.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_deactivate(const struct device *dev);

/**
 * @brief Performs a Listen Before Talk (LBT) operation on the current channel.
 * @param dev Pointer to the PHY device.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_perform_lbt(const struct device *dev);

/**
 * @brief Retrieves the current modem time.
 * @return Current modem time in modem units, or 0 on error.
 */
uint64_t nrf9161_dect_phy_get_modem_time(void);

/**
 * @brief Adjusts the internal modem time (conceptual for synchronization).
 * @param dev Pointer to the PHY device.
 * @param new_modem_time The new modem time to set.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t nrf9161_dect_phy_adjust_modem_time(const struct device *dev, uint64_t new_modem_time);

/**
 * @brief Gets the nominal duration of a DECT NR+ TX slot in modem units.
 * @return TX slot duration in modem units.
 */
uint32_t nrf9161_dect_phy_get_tx_slot_duration(void);

#endif /* DECT_PHY_NRF9161_H__ */

/* End of File
 * Last Amended: 2025-06-13 16:00 BST: Clarified comments in `nrf9161_dect_phy_perform_lbt` to align with direct API call.
 * Last Amended: 2025-06-06 13:00 BST: Added `nrf9161_dect_phy_transmit_receive` prototype for combined TX/RX operations.
 * Last Amended: 2025-06-06 14:30 BST: Added `harq_process_number` to `nrf9161_dect_rx_packet_t` for HARQ feedback.
 */
