/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>

#include <dect_nr_plus/dect_stats.h> /* Own header */
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For MAX_PEERS, SHORT_RD_ID_LEN_BYTES

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_stats, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global statistics instance definition */
dect_stats_t dect_stats = {
	// All counters are initialized to 0 by default for global/static variables
	// Mutex is initialized by K_MUTEX_DEFINE in the header
};

/* Internal helper to find a peer stats entry by Short RD ID */
static int find_peer_stats_entry(uint16_t short_rd_id)
{
	for (int i = 0; i < dect_stats.num_active_peers; i++) {
		if (dect_stats.peer_stats[i].short_rd_id == short_rd_id) {
			return i;
		}
	}
	return -1; // Not found
}

/* Internal helper to get or create a peer stats entry */
static int get_or_create_peer_stats_entry(uint16_t short_rd_id)
{
	int idx = find_peer_stats_entry(short_rd_id);
	if (idx != -1) {
		return idx;
	}

	if (dect_stats.num_active_peers < MAX_PEERS) {
		idx = dect_stats.num_active_peers++;
		memset(&dect_stats.peer_stats[idx], 0, sizeof(dect_peer_stats_t));
		dect_stats.peer_stats[idx].short_rd_id = short_rd_id;
		LOG_DBG("Stats: Created new peer stats entry for 0x%04X at index %d. Total active peers: %u.",
				short_rd_id, idx, dect_stats.num_active_peers);
		return idx;
	} else {
		LOG_WRN("Stats: Max peer stats entries reached. Cannot create entry for 0x%04X.", short_rd_id);
		return -1;
	}
}


dect_status_t dect_stats_init(void)
{
	LOG_INF("Stats: Initializing statistics module...");
	k_mutex_lock(&dect_stats.mutex, K_FOREVER);
	memset(&dect_stats, 0, sizeof(dect_stats_t)); // Clear all stats to 0
	dect_stats.num_active_peers = 0; // Explicitly reset active peers count
	// Mutex is initialized by K_MUTEX_DEFINE, no need to init here
	k_mutex_unlock(&dect_stats.mutex);
	LOG_INF("Stats: Statistics module initialized.");
	return DECT_STATUS_OK;
}

void dect_stats_update_global(dect_global_stat_t stat_type, int32_t value)
{
	k_mutex_lock(&dect_stats.mutex, K_FOREVER);
	switch (stat_type) {
	case STATS_TX_FRAMES:
		dect_stats.tx_frames += value;
		break;
	case STATS_RX_FRAMES:
		dect_stats.rx_frames += value;
		break;
	case STATS_TX_DATA_BYTES:
		dect_stats.tx_data_bytes += value;
		break;
	case STATS_RX_DATA_BYTES:
		dect_stats.rx_data_bytes += value;
		break;
	case STATS_DLC_TX_REQUESTS:
		dect_stats.dlc_tx_requests += value;
		break;
	case STATS_DLC_TX_SUCCESS:
		dect_stats.dlc_tx_success += value;
		break;
	case STATS_DLC_TX_FAILURES:
		dect_stats.dlc_tx_failures += value;
		break;
	case STATS_DLC_RETRANSMISSIONS:
		dect_stats.dlc_retransmissions += value;
		break;
	case STATS_DLC_RX_DUPLICATES:
		dect_stats.dlc_rx_duplicates += value;
		break;
	case STATS_DLC_RX_OUT_OF_WINDOW:
		dect_stats.dlc_rx_out_of_window += value;
		break;
	case STATS_DLC_RX_IN_ORDER:
		dect_stats.dlc_rx_in_order += value;
		break;
	case STATS_DLC_TX_ACKS:
		dect_stats.dlc_tx_acks += value;
		break;
	case STATS_DLC_RX_ACKS:
		dect_stats.dlc_rx_acks += value;
		break;
	case STATS_DLC_CRC_ERRORS:
		dect_stats.dlc_crc_errors += value;
		break;
	case STATS_MAC_MIC_FAILURES:
		dect_stats.mac_mic_failures += value;
		break;
	case STATS_PHY_TX_FAILED:
		dect_stats.phy_tx_failed += value;
		break;
	case STATS_PHY_RX_CRC_ERRORS:
		dect_stats.phy_rx_crc_errors += value;
		break;
	case STATS_PHY_EVENTS_DROPPED:
		dect_stats.phy_events_dropped += value;
		break;
	case STATS_MAC_SCAN_ATTEMPTS:
		dect_stats.mac_scan_attempts += value;
		break;
	case STATS_MAC_SCAN_FAILURES:
		dect_stats.mac_scan_failures += value;
		break;
	case STATS_MAC_SYNC_SUCCESS:
		dect_stats.mac_sync_success += value;
		break;
	case STATS_MAC_SYNC_FAILURES:
		dect_stats.mac_sync_failures += value;
		break;
	case STATS_MAC_ASSOC_ATTEMPTS:
		dect_stats.mac_assoc_attempts += value;
		break;
	case STATS_MAC_ASSOC_SUCCESS:
		dect_stats.mac_assoc_success += value;
		break;
	case STATS_MAC_ASSOC_FAILURES:
		dect_stats.mac_assoc_failures += value;
		break;
	case STATS_MAC_LINK_FAILURES:
		dect_stats.mac_link_failures += value;
		break;
	case STATS_MAC_TX_BEACONS:
		dect_stats.mac_tx_beacons += value;
		break;
	case STATS_RX_MAC_BEACONS:
		dect_stats.rx_mac_beacons += value;
		break;
	case STATS_RX_MAC_ASSOC_REQUESTS:
		dect_stats.rx_mac_assoc_requests += value;
		break;
	case STATS_RX_MAC_ASSOC_RESPONSES:
		dect_stats.rx_mac_assoc_responses += value;
		break;
	case STATS_RX_MAC_DROPS:
		dect_stats.rx_mac_drops += value;
		break;
	case STATS_TX_MAC_DROPS:
		dect_stats.tx_mac_drops += value;
		break;
	case STATS_HARQ_PROCESSES_ALLOCATED:
		dect_stats.harq_processes_allocated += value;
		break;
	case STATS_HARQ_PROCESSES_FREED:
		dect_stats.harq_processes_freed += value;
		break;
	case STATS_HARQ_PROCESSES_FAILED_ALLOC:
		dect_stats.harq_processes_failed_alloc += value;
		break;
	case STATS_HARQ_RETRANSMISSIONS:
		dect_stats.harq_retransmissions += value;
		break;
	case STATS_HARQ_SUCCESS_COUNT:
		dect_stats.harq_success_count += value;
		break;
	case STATS_HARQ_FAILURES_COUNT:
		dect_stats.harq_failures_count += value;
		break;
	case STATS_HARQ_RESETS:
		dect_stats.harq_resets += value;
		break;
	case STATS_RX_MAC_PCC:
		dect_stats.rx_mac_pcc += value;
		break;
	case STATS_RX_MAC_PDC:
		dect_stats.rx_mac_pdc += value;
		break;
	case STATS_RX_MAC_PCC_CRC_ERRORS:
		dect_stats.rx_mac_pcc_crc_errors += value;
		break;
	case STATS_RX_MAC_PDC_CRC_ERRORS:
		dect_stats.rx_mac_pdc_crc_errors += value;
		break;
	case STATS_TX_PHY_OPS_COMPLETED:
		dect_stats.tx_phy_ops_completed += value;
		break;
	case STATS_CHANNEL_CHANGES:
		dect_stats.channel_changes += value;
		break;
	case STATS_CHANNEL_BLACKLISTED:
		dect_stats.channel_blacklisted += value;
		break;
	case STATS_CHANNEL_WHITELISTED:
		dect_stats.channel_whitelisted += value;
		break;
	case STATS_POWER_MODE_CHANGES:
		dect_stats.power_mode_changes += value;
		break;
	case STATS_POWER_MODE_TRANSITION_FAILURES:
		dect_stats.power_mode_transition_failures += value;
		break;
	case STATS_TX_APP_DATA_REQUESTS:
		dect_stats.tx_app_data_requests += value;
		break;
	case STATS_TX_APP_DATA_BYTES:
		dect_stats.tx_app_data_bytes += value;
		break;
	case STATS_RX_APP_DATA_BYTES:
		dect_stats.rx_app_data_bytes += value;
		break;
	case STATS_CVG_FRAG_TX:
		dect_stats.cvg_frag_tx += value;
		break;
	case STATS_CVG_FRAG_RX:
		dect_stats.cvg_frag_rx += value;
		break;
	case STATS_CVG_REASSEMBLY_SUCCESS:
		dect_stats.cvg_reassembly_success += value;
		break;
	case STATS_CVG_REASSEMBLY_FAILURES:
		dect_stats.cvg_reassembly_failures += value;
		break;
	case STATS_ROUTING_RREQ_TX:
		dect_stats.routing_rreq_tx += value;
		break;
	case STATS_ROUTING_RREP_RX:
		dect_stats.routing_rrep_rx += value;
		break;
	case STATS_ROUTING_ROUTE_ADD:
		dect_stats.routing_route_add += value;
		break;
	case STATS_ROUTING_ROUTE_EXPIRE:
		dect_stats.routing_route_expire += value;
		break;
	case STATS_ROUTING_ROUTE_ERROR:
		dect_stats.routing_route_error += value;
		break;
	case STATS_SECURITY_HANDSHAKES_INITIATED:
		dect_stats.security_handshakes_initiated += value;
		break;
	case STATS_SECURITY_HANDSHAKES_SUCCESS:
		dect_stats.security_handshakes_success += value;
		break;
	case STATS_SECURITY_HANDSHAKES_FAILURES:
		dect_stats.security_handshakes_failures += value;
		break;
	case STATS_SECURITY_REKEYS:
		dect_stats.security_rekeys += value;
		break;
	case STATS_6LO_COMPRESSION_SUCCESS:
		dect_stats.sixlo_compression_success += value;
		break;
	case STATS_6LO_COMPRESSION_FAILURES:
		dect_stats.sixlo_compression_failures += value;
		break;
	case STATS_6LO_DECOMPRESSION_SUCCESS:
		dect_stats.sixlo_decompression_success += value;
		break;
	case STATS_6LO_DECOMPRESSION_FAILURES:
		dect_stats.sixlo_decompression_failures += value;
		break;
	case STATS_MOBILITY_HANDOVER_REQUESTS_TX:
		dect_stats.mobility_handover_requests_tx += value;
		break;
	case STATS_MOBILITY_HANDOVER_RESPONSES_RX:
		dect_stats.mobility_handover_responses_rx += value;
		break;
	case STATS_MOBILITY_HANDOVER_ACCEPTS_TX:
		dect_stats.mobility_handover_accepts_tx += value;
		break;
	case STATS_MOBILITY_HANDOVER_REJECTS_TX:
		dect_stats.mobility_handover_rejects_tx += value;
		break;
	case STATS_MOBILITY_HANDOVER_SUCCESS:
		dect_stats.mobility_handover_success += value;
		break;
	case STATS_MOBILITY_HANDOVER_FAILURES:
		dect_stats.mobility_handover_failures += value;
		break;
	case STATS_MOBILITY_HANDOVER_TIMEOUT_FAILURES:
		dect_stats.mobility_handover_timeout_failures += value;
		break;
	case STATS_MOBILITY_HANDOVER_UNSUPPORTED_FAILURES:
		dect_stats.mobility_handover_unsupported_failures += value;
		break;
	default:
		LOG_WRN("Stats: Unknown global stat type %u.", stat_type);
		break;
	}
	k_mutex_unlock(&dect_stats.mutex);
}

void dect_stats_update_peer(uint16_t short_rd_id, dect_peer_stat_t stat_type, int32_t value)
{
	k_mutex_lock(&dect_stats.mutex, K_FOREVER);
	int idx = get_or_create_peer_stats_entry(short_rd_id);
	if (idx == -1) {
		k_mutex_unlock(&dect_stats.mutex);
		return;
	}

	switch (stat_type) {
	case PEER_STATS_TX_FRAMES:
		dect_stats.peer_stats[idx].tx_frames += value;
		break;
	case PEER_STATS_RX_FRAMES:
		dect_stats.peer_stats[idx].rx_frames += value;
		break;
	case PEER_STATS_TX_DATA_BYTES:
		dect_stats.peer_stats[idx].tx_data_bytes += value;
		break;
	case PEER_STATS_RX_DATA_BYTES:
		dect_stats.peer_stats[idx].rx_data_bytes += value;
		break;
	case PEER_STATS_DLC_RETRANSMISSIONS:
		dect_stats.peer_stats[idx].dlc_retransmissions += value;
		break;
	case PEER_STATS_DLC_CRC_ERRORS:
		dect_stats.peer_stats[idx].dlc_crc_errors += value;
		break;
	case PEER_STATS_MAC_MIC_FAILURES:
		dect_stats.peer_stats[idx].mac_mic_failures += value;
		break;
	case PEER_STATS_HARQ_TX_SUCCESS:
		dect_stats.peer_stats[idx].harq_tx_success += value;
		break;
	case PEER_STATS_HARQ_TX_RETRANSMISSIONS:
		dect_stats.peer_stats[idx].harq_tx_retransmissions += value;
		break;
	case PEER_STATS_HARQ_RX_COMBINED:
		dect_stats.peer_stats[idx].harq_rx_combined += value;
		break;
	case PEER_STATS_HARQ_TX_FAILURES:
		dect_stats.peer_stats[idx].harq_tx_failures += value;
		break;
	case PEER_STATS_MAC_HANDOVER_REQUESTS_TX:
		dect_stats.peer_stats[idx].mac_handover_requests_tx += value;
		break;
	case PEER_STATS_MAC_HANDOVER_RESPONSES_RX:
		dect_stats.peer_stats[idx].mac_handover_responses_rx += value;
		break;
	case PEER_STATS_MAC_HANDOVER_FAILURES:
		dect_stats.peer_stats[idx].mac_handover_failures += value;
		break;
	default:
		LOG_WRN("Stats: Unknown peer stat type %u for peer 0x%04X.", stat_type, short_rd_id);
		break;
	}
	k_mutex_unlock(&dect_stats.mutex);
}


void dect_stats_print(void)
{
	k_mutex_lock(&dect_stats.mutex, K_FOREVER);
	LOG_INF("--- DECT NR+ Global Statistics ---");
	LOG_INF("General:");
	LOG_INF("  Total TX Frames: %u, Total RX Frames: %u", dect_stats.tx_frames, dect_stats.rx_frames);
	LOG_INF("  Total TX Data Bytes: %u, Total RX Data Bytes: %u", dect_stats.tx_data_bytes, dect_stats.rx_data_bytes);
	LOG_INF("  Total App Data TX Requests: %u, Bytes: %u", dect_stats.tx_app_data_requests, dect_stats.tx_app_data_bytes);
	LOG_INF("  Total App Data RX Bytes: %u", dect_stats.rx_app_data_bytes);

	LOG_INF("DLC Layer:");
	LOG_INF("  DLC TX Requests: %u, Success: %u, Failures: %u",
			dect_stats.dlc_tx_requests, dect_stats.dlc_tx_success, dect_stats.dlc_tx_failures);
	LOG_INF("  DLC Retransmissions: %u, CRC Errors: %u", dect_stats.dlc_retransmissions, dect_stats.dlc_crc_errors);
	LOG_INF("  DLC RX Duplicates: %u, Out-of-Window: %u, In-Order: %u",
			dect_stats.dlc_rx_duplicates, dect_stats.dlc_rx_out_of_window, dect_stats.dlc_rx_in_order);
	LOG_INF("  DLC ACKs TX: %u, RX: %u", dect_stats.dlc_tx_acks, dect_stats.dlc_rx_acks);

	LOG_INF("MAC Layer:");
	LOG_INF("  MAC MIC Failures: %u", dect_stats.mac_mic_failures);
	LOG_INF("  MAC Scan Attempts: %u, Failures: %u", dect_stats.mac_scan_attempts, dect_stats.mac_scan_failures);
	LOG_INF("  MAC Sync Success: %u, Failures: %u", dect_stats.mac_sync_success, dect_stats.mac_sync_failures);
	LOG_INF("  MAC Assoc Attempts: %u, Success: %u, Failures: %u",
			dect_stats.mac_assoc_attempts, dect_stats.mac_assoc_success, dect_stats.mac_assoc_failures);
	LOG_INF("  MAC Link Failures: %u", dect_stats.mac_link_failures);
	LOG_INF("  MAC TX Beacons: %u, RX Beacons: %u", dect_stats.mac_tx_beacons, dect_stats.rx_mac_beacons);
	LOG_INF("  MAC RX Assoc Requests: %u, RX Assoc Responses: %u",
			dect_stats.rx_mac_assoc_requests, dect_stats.rx_mac_assoc_responses);
	LOG_INF("  MAC Drops RX: %u, TX: %u", dect_stats.rx_mac_drops, dect_stats.tx_mac_drops);

	LOG_INF("PHY Layer:");
	LOG_INF("  PHY TX Failed: %u, RX CRC Errors: %u", dect_stats.phy_tx_failed, dect_stats.phy_rx_crc_errors);
	LOG_INF("  PHY Events Dropped: %u", dect_stats.phy_events_dropped);
	LOG_INF("  PHY TX Operations Completed: %u", dect_stats.tx_phy_ops_completed);

	LOG_INF("HARQ:");
	LOG_INF("  HARQ Processes Allocated: %u, Freed: %u, Failed Alloc: %u",
			dect_stats.harq_processes_allocated, dect_stats.harq_processes_freed,
			dect_stats.harq_processes_failed_alloc);
	LOG_INF("  HARQ Retransmissions: %u, Success: %u, Failures: %u, Resets: %u",
			dect_stats.harq_retransmissions, dect_stats.harq_success_count,
			dect_stats.harq_failures_count, dect_stats.harq_resets);
	LOG_INF("  MAC PCC RX: %u, PDC RX: %u", dect_stats.rx_mac_pcc, dect_stats.rx_mac_pdc);
	LOG_INF("  MAC PCC CRC Errors: %u, PDC CRC Errors: %u", dect_stats.rx_mac_pcc_crc_errors, dect_stats.rx_mac_pdc_crc_errors);

	LOG_INF("Channel Manager:");
	LOG_INF("  Channel Changes: %u, Blacklisted: %u, Whitelisted: %u",
			dect_stats.channel_changes, dect_stats.channel_blacklisted, dect_stats.channel_whitelisted);

	LOG_INF("Power Manager:");
	LOG_INF("  Power Mode Changes: %u, Transition Failures: %u",
			dect_stats.power_mode_changes, dect_stats.power_mode_transition_failures);

	LOG_INF("6LoWPAN:");
	LOG_INF("  Compression Success: %u, Failures: %u", dect_stats.sixlo_compression_success, dect_stats.sixlo_compression_failures);
	LOG_INF("  Decompression Success: %u, Failures: %u", dect_stats.sixlo_decompression_success, dect_stats.sixlo_decompression_failures);

	LOG_INF("Routing:");
	LOG_INF("  RREQ TX: %u, RREP RX: %u, Route Add: %u, Route Expire: %u, Route Error: %u",
			dect_stats.routing_rreq_tx, dect_stats.routing_rrep_rx, dect_stats.routing_route_add,
			dect_stats.routing_route_expire, dect_stats.routing_route_error);

	LOG_INF("Security:");
	LOG_INF("  Handshakes Initiated: %u, Success: %u, Failures: %u, Rekey: %u",
			dect_stats.security_handshakes_initiated, dect_stats.security_handshakes_success,
			dect_stats.security_handshakes_failures, dect_stats.security_rekeys);

	LOG_INF("Mobility (Handover):");
	LOG_INF("  Handover Requests TX: %u, Responses RX: %u",
			dect_stats.mobility_handover_requests_tx, dect_stats.mobility_handover_responses_rx);
	LOG_INF("  Handover Accepts TX: %u, Rejects TX: %u",
			dect_stats.mobility_handover_accepts_tx, dect_stats.mobility_handover_rejects_tx);
	LOG_INF("  Handover Success: %u, Failures: %u, Timeout Failures: %u, Unsupported Failures: %u",
			dect_stats.mobility_handover_success, dect_stats.mobility_handover_failures,
			dect_stats.mobility_handover_timeout_failures, dect_stats.mobility_handover_unsupported_failures);


	LOG_INF("--- Per-Peer Statistics (Active Peers: %u) ---", dect_stats.num_active_peers);
	for (int i = 0; i < dect_stats.num_active_peers; i++) {
		LOG_INF("  Peer 0x%04X:", dect_stats.peer_stats[i].short_rd_id);
		LOG_INF("    TX Frames: %u, RX Frames: %u", dect_stats.peer_stats[i].tx_frames, dect_stats.peer_stats[i].rx_frames);
		LOG_INF("    TX Data Bytes: %u, RX Data Bytes: %u", dect_stats.peer_stats[i].tx_data_bytes, dect_stats.peer_stats[i].rx_data_bytes);
		LOG_INF("    DLC Retransmissions: %u, DLC CRC Errors: %u", dect_stats.peer_stats[i].dlc_retransmissions, dect_stats.peer_stats[i].dlc_crc_errors);
		LOG_INF("    MAC MIC Failures: %u", dect_stats.peer_stats[i].mac_mic_failures);
		LOG_INF("    HARQ TX Success: %u, HARQ TX Retransmissions: %u, HARQ RX Combined: %u, HARQ TX Failures: %u",
		        dect_stats.peer_stats[i].harq_tx_success, dect_stats.peer_stats[i].harq_tx_retransmissions,
		        dect_stats.peer_stats[i].harq_rx_combined, dect_stats.peer_stats[i].harq_tx_failures);
		LOG_INF("    Mobility: Handover Requests TX: %u, Responses RX: %u, Failures: %u",
				dect_stats.peer_stats[i].mac_handover_requests_tx,
				dect_stats.peer_stats[i].mac_handover_responses_rx,
				dect_stats.peer_stats[i].mac_handover_failures);
	}
	LOG_INF("---------------------------\n");
	k_mutex_unlock(&dect_stats.mutex);
}

/* End of File
 * Last Amended: 2025-06-06 12:30 BST: Updated dect_stats.c for Mobility.
 * - Added `mobility_handover_requests_tx`, `mobility_handover_responses_rx`, `mobility_handover_accepts_tx`,
 * `mobility_handover_rejects_tx`, `mobility_handover_success`, `mobility_handover_failures`,
 * `mobility_handover_timeout_failures`, `mobility_handover_unsupported_failures` to `dect_global_stat_t`
 * and corresponding update logic in `dect_stats_update_global`.
 * - Added `PEER_STATS_MAC_HANDOVER_REQUESTS_TX`, `PEER_STATS_MAC_HANDOVER_RESPONSES_RX`, `PEER_STATS_MAC_HANDOVER_FAILURES`
 * to `dect_peer_stat_t` and corresponding update logic in `dect_stats_update_peer`.
 * - Updated `dect_stats_print()` to include the new global and per-peer mobility statistics.
 * - Ensured `dect_stats_init()` correctly initializes all new fields to zero.
 */
