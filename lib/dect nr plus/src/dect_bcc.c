/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>

#include <dect_nr_plus/dect_config.h>
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_mac.h> /* For MAC layer interaction */
#include <dect_nr_plus/dect_bcc.h> /* Own header */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_crc.h> // For CRC computation
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness
#include <dect_nr_plus/dect_phy_nrf9161.h> // For PHY-specific information like TX slot duration

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_bcc, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global timer for periodic beacon transmission */
static struct k_timer beacon_timer;

/* Forward declaration for internal timer handler */
static void beacon_timer_handler(struct k_timer *timer_id);

/**
 * @brief Helper function to handle net_buf allocation for TX path.
 *
 * This function attempts to allocate a net_buf from the specified pool.
 * If allocation fails, it logs an error and increments a statistic.
 *
 * @param out_buf Pointer to a net_buf pointer where the allocated buffer will be stored.
 * @param pool Pointer to the net_buf_pool to allocate from.
 * @return DECT_STATUS_OK on success, DECT_ERROR_NO_MEM if allocation fails.
 */
static dect_status_t handle_tx_buffer_allocation(struct net_buf **out_buf, struct net_buf_pool *pool)
{
	*out_buf = net_buf_alloc(pool, K_NO_WAIT);
	if (!(*out_buf)) {
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "BCC: Failed to allocate net_buf from pool %s. No memory.", pool->name->name);
		STATS_INC(dect_stats.tx_drops_no_mem); // Increment global stat for TX drops due to no memory
		return DECT_ERROR_NO_MEM;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_bcc_init(void)
{
	k_timer_init(&beacon_timer, beacon_timer_handler, NULL);
	LOG_INF("BCC: Module initialized.");
	return DECT_STATUS_OK;
}

dect_status_t dect_bcc_start_beacon_tx(uint32_t interval_ms)
{
	if (mac_ctx.device_role != MAC_ROLE_FP) {
		LOG_WRN("BCC: Only Fixed Parts can transmit periodic beacons. Role is %s.",
			mac_ctx.device_role == MAC_ROLE_PP ? "Portable Part" : "Unknown");
		return DECT_ERROR_INVALID_STATE;
	}

	if (interval_ms == 0) {
		LOG_ERR("BCC: Beacon transmission interval cannot be 0.");
		return DECT_ERROR_INVALID_PARAM;
	}

	k_timer_start(&beacon_timer, K_MSEC(interval_ms), K_MSEC(interval_ms));
	LOG_INF("BCC: Started periodic beacon transmission every %u ms.", interval_ms);
	return DECT_STATUS_OK;
}

dect_status_t dect_bcc_stop_beacon_tx(void)
{
	k_timer_stop(&beacon_timer);
	LOG_INF("BCC: Stopped periodic beacon transmission.");
	return DECT_STATUS_OK;
}

static void beacon_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	LOG_DBG("BCC: Beacon timer fired. Sending beacon.");
	// In a real application, IEs might be generated dynamically
	dect_status_t status = dect_bcc_send_beacon(mac_ctx.current_active_channel, NULL, 0); // No IEs for now
	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "BCC: Failed to send beacon.");
	}
}

dect_status_t dect_bcc_send_beacon(uint8_t channel, const mac_ie_t *ies, uint8_t ie_count)
{
	struct net_buf *beacon_pdu = NULL;
	dect_status_t ret_alloc = handle_tx_buffer_allocation(&beacon_pdu, &mac_tx_net_buf_pool);
	if (ret_alloc != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(ret_alloc, "BCC: Failed to allocate beacon PDU buffer.");
		// Stats already incremented by helper function
		return ret_alloc;
	}

	// Prepend MAC Control Type for Beacon (0x01)
	net_buf_add_u8(beacon_pdu, MAC_CONTROL_TYPE_BEACON);

	// Append Information Elements (IEs)
	for (int i = 0; i < ie_count; i++) {
		if (ies[i].len > MAC_IE_MAX_DATA_LEN) {
			DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "BCC: IE data length too large (%u). Max is %u. Dropping beacon.",
					   ies[i].len, MAC_IE_MAX_DATA_LEN);
			STATS_INC(dect_stats.bcc_beacon_ie_errors); // Specific IE error stat
			net_buf_unref(beacon_pdu);
			return DECT_ERROR_INVALID_PARAM;
		}
		if (net_buf_tailroom(beacon_pdu) < (sizeof(ies[i].type) + sizeof(ies[i].len) + ies[i].len)) {
			DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "BCC: Not enough buffer space for IE %d. Dropping beacon.", i);
			STATS_INC(dect_stats.tx_drops_no_mem); // Or a more specific "buffer full during build" stat
			net_buf_unref(beacon_pdu);
			return DECT_ERROR_PDU_TOO_LARGE;
		}
		net_buf_add_u8(beacon_pdu, ies[i].type);
		net_buf_add_u8(beacon_pdu, ies[i].len);
		if (ies[i].data) {
			net_buf_add_mem(beacon_pdu, ies[i].data, ies[i].len);
		}
		LOG_DBG("BCC: Added IE Type 0x%02x, Length %u.", ies[i].type, ies[i].len);
	}

	// Compute and append CRC
	uint16_t crc = compute_crc(beacon_pdu->data, beacon_pdu->len);
	if (net_buf_tailroom(beacon_pdu) < DLC_CRC_LEN_BYTES) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "BCC: Not enough buffer space for CRC. Dropping beacon.");
		STATS_INC(dect_stats.tx_drops_no_mem);
		net_buf_unref(beacon_pdu);
		return DECT_ERROR_PDU_TOO_LARGE;
	}
	net_buf_add_le16(beacon_pdu, crc);

	LOG_DBG("BCC: Beacon PDU constructed (len %u, CRC 0x%04x). Sending to MAC.",
		beacon_pdu->len, crc);

	// Pass to MAC layer for transmission
	// For beacons, the destination is implicitly broadcast (SHORT_RD_ID_BROADCAST)
	// Beacons typically don't use encryption (hpc/psn are 0 or dummy for beacons if not encrypted)
	dect_status_t mac_ret = dect_mac_send_pdu_from_dlc(SHORT_RD_ID_BROADCAST, beacon_pdu,
							   DLC_PDU_TYPE_BEACON, MAC_HEADER_TYPE_1_CONTROL,
							   0, 0, // HPC/PSN not typically used for unencrypted beacons
							   false, sys_rand32_get()); // Dummy HARQ ID
	if (mac_ret != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(mac_ret, "BCC: Failed to send beacon PDU to MAC layer.");
		STATS_INC(dect_stats.mac_tx_drops); // Buffer unref'd by MAC on failure
		return mac_ret;
	}

	STATS_INC(dect_stats.bcc_beacons_tx);
	LOG_DBG("BCC: Beacon sent successfully on channel %u.", channel);
	dect_bcc_adjust_power_awareness(); // Notify power manager of TX activity

	return DECT_STATUS_OK;
}

void dect_bcc_adjust_power_awareness(void)
{
	// Beacon transmission is a form of activity that keeps the Fixed Part active.
	// Notify the power manager that activity has been detected.
	dect_power_mgr_activity_detected();
	LOG_DBG("BCC: Activity detected due to beacon transmission. Power manager notified.");
}

/* End of File
 * Last Amended: 2025-06-09 19:30 BST: Updated dect_bcc.c for robust error handling.
 * - Added `handle_tx_buffer_allocation` helper function.
 * - Modified `dect_bcc_send_beacon` to use `handle_tx_buffer_allocation` for `beacon_pdu` allocation.
 * - Enhanced error handling for:
 * - `DECT_ERROR_INVALID_PARAM` for invalid IE length.
 * - `DECT_ERROR_PDU_TOO_LARGE` for insufficient buffer space during IE/CRC appending.
 * - Ensured all error paths (allocation failures, IE errors, buffer full) increment `dect_stats.tx_drops_no_mem`, `dect_stats.bcc_beacon_ie_errors`, or `dect_stats.mac_tx_drops` and unreference `net_buf`s.
 * - Updated `dect_mac_send_pdu_from_dlc` call to be robust for `mac_tx_drops`.
 */
