/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/ipv6.h> // For IPv6 header definitions, if needed for inspection/debugging
#include <net/net_l2.h> // For NET_L2_GET_CTX, net_l2_cb
#include <sys/util.h> // For DIV_ROUND_UP
#include <drivers/ethernet/eth_config.h> // For ETH_MAX_FRAME_SIZE if needed for max payload size

#ifdef CONFIG_NET_6LO // Include 6LoWPAN headers if enabled
#include <net/net_6lo.h>
#endif

#include <dect_nr_plus/dect_config.h>
#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h>
#include <dect_nr_plus/dect_dlc.h> /* For DLC layer interaction */
#include <dect_nr_plus/dect_crc.h> /* For CRC computation */
#include <dect_nr_plus/dect_crypto.h> /* For encryption/decryption */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness
#include <dect_nr_plus/dect_cvg.h> // Own header

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_cvg, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global CVG context instance definition */
dect_cvg_context_t cvg_ctx = {
	.reassembly_buffer_active = false,
	.last_frag_rx_time_ms = 0,
	.next_frag_id = 0,
};

/* Net buffer pool for CVG transmit PDUs */
NET_BUF_POOL_DEFINE(cvg_tx_net_buf_pool, CONFIG_DECT_NR_PLUS_CVG_TX_BUF_COUNT,
					CONFIG_DECT_NR_PLUS_CVG_TX_BUF_SIZE, 0, NULL);

/* Message queue for network stack to CVG (TX path) */
K_MSGQ_DEFINE(cvg_tx_net_pkt_msgq, sizeof(struct net_pkt *),
	      CONFIG_DECT_NR_PLUS_CVG_TX_NET_PKT_QUEUE_SIZE, 4);

/* Mutex for CVG context protection */
K_MUTEX_DEFINE(cvg_ctx_mutex);

/* Forward declarations */
static struct net_pkt *cvg_reassemble_fragment(struct net_pkt *frag_pkt,
											   struct net_ipv6_hdr *ipv6_hdr,
											   struct net_ipv6_frag_hdr *frag_hdr);
static dect_status_t cvg_send_fragment(uint16_t dest_short_rd_id, struct net_pkt *frag_pkt,
									   cvg_service_type_t service_type,
									   qos_priority_t qos_priority);
static dect_status_t cvg_process_incoming_sdu(uint16_t src_short_rd_id, struct net_buf *sdu_buf,
											  cvg_service_type_t service_type,
											  uint32_t hpc, uint16_t psn);

// Function to provide the L2 context type if needed by the network stack.
// For a custom L2 like DECT NR+, you might return a unique identifier or NULL.
// If you define a specific enum for L2 types, you'd return that.
static void *dect_nr_plus_get_l2_context_type(void)
{
	// Replace with a proper DECT-NR+ specific L2 type if defined in Zephyr or a custom enum
	// For now, return NULL or a generic type if applicable.
	// E.g., return (void *)NET_L2_TYPE_DUMMY; if you have a dummy L2 type for custom radios.
	return NULL; // Or a specific enum value if you define one for DECT NR+
}


/* DECT NR+ L2 API (exposed to Zephyr network stack) */
// Corrected usage: Define the struct directly, assigning function pointers.
static const struct net_l2 dect_nr_plus_l2_api = {
	.iface_init = dect_nr_plus_iface_init,
	.send = cvg_send_ipv6_pkt,
	.recv = NULL, // Not typically used for custom L2; RX handled by events and net_pkt_rx()
	.event_handler = NULL, // No specific L2 event handler defined here
	.get_context_type = dect_nr_plus_get_l2_context_type, // Provide a function returning the L2 context type
};

// Thread for handling outgoing network packets from Zephyr stack
K_THREAD_DEFINE(cvg_tx_thread_id, CONFIG_DECT_NR_PLUS_CVG_TX_THREAD_STACK_SIZE,
				cvg_tx_thread, NULL, NULL, NULL,
				CONFIG_DECT_NR_PLUS_CVG_TX_THREAD_PRIORITY, 0, K_NO_WAIT);


dect_status_t dect_cvg_init(void)
{
	k_mutex_init(&cvg_ctx.mutex);

	// Start the TX thread
	k_thread_name_set(cvg_tx_thread_id, "dect_cvg_tx_thread");

	LOG_INF("CVG: Module initialized.");
	return DECT_STATUS_OK;
}

void cvg_tx_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("CVG: TX Thread started.");

	struct net_pkt *pkt;
	while (true) {
		// Wait for network packets from the network stack
		k_msgq_get(&cvg_tx_net_pkt_msgq, &pkt, K_FOREVER);

		if (!pkt) {
			LOG_ERR("CVG TX: Received NULL net_pkt. Skipping.");
			continue;
		}

		LOG_DBG("CVG TX: Received net_pkt from stack (len %u).", net_pkt_get_len(pkt));
		dect_power_mgr_activity_detected(); // Notify power manager of TX activity

		// Check if the packet is destined for a known peer or broadcast
		uint16_t dest_short_rd_id = SHORT_RD_ID_BROADCAST; // Default to broadcast for unknown
		// In a real implementation, you'd parse the IPv6 destination address
		// and map it to a DECT NR+ Short RD ID. For simplicity, assume broadcast.
		// If you have a way to get the destination L2 address from net_pkt:
		// const struct net_linkaddr *dst_lladdr = net_pkt_l2addr(pkt);
		// if (dst_lladdr && dst_lladdr->len == SHORT_RD_ID_LEN_BYTES) {
		// 	dest_short_rd_id = (dst_lladdr->addr[0] << 8) | dst_lladdr->addr[1];
		// }

		// Handle fragmentation if necessary
		// Check against maximum PDU size for DLC/MAC layer (e.g., 256 bytes)
		if (net_pkt_get_len(pkt) > CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE) {
			LOG_DBG("CVG TX: Packet needs fragmentation (len %u > max PDU %u).",
					net_pkt_get_len(pkt), CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE);
			STATS_INC(dect_stats.cvg_frag_tx);

			// Fragmentation logic:
			// 1. Create IPv6 fragmentation header.
			// 2. Break original net_pkt into smaller net_pkt fragments.
			// 3. Send each fragment using cvg_send_fragment.
			// For simplicity, this example does not implement full fragmentation.
			// A real implementation would involve careful handling of offsets, more_fragments flag, etc.

			// For now, if fragmentation is needed, we drop the packet.
			DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "CVG TX: Fragmentation not implemented. Dropping large packet (len %u).",
							   net_pkt_get_len(pkt));
			net_pkt_unref(pkt); // Release original packet
			STATS_INC(dect_stats.cvg_tx_drops);
			continue;
		}

		// Prepare CVG PDU (which is just the original IPv6 packet in this simplified case)
		// For the direct `dlc_send_data_from_cvg` call, we need a `net_buf`
		// The net_pkt contains one or more net_buf's. We take the first one's data.
		// This assumes the net_pkt's data is contiguous or can be read as such.
		struct net_buf *sdu_buf = pkt->frags; // Get the first net_buf fragment
		if (!sdu_buf || sdu_buf->len == 0) {
			DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG TX: net_pkt has no data fragments. Dropping.");
			net_pkt_unref(pkt);
			STATS_INC(dect_stats.cvg_tx_drops);
			continue;
		}

		// Pass the entire network packet (as the first net_buf fragment) to DLC
		// The DLC layer will handle its own buffer allocation if it copies the data,
		// or take ownership if `net_buf_ref` is used correctly.
		// Here, we just pass the fragment; DLC is expected to ref/unref as needed.
		// Assuming DLC takes ownership of the `sdu_buf` (which is part of `pkt`).
		// If DLC copies, then `net_pkt_unref(pkt)` needs to happen here.
		// For now, let DLC manage the net_buf from the net_pkt.
		dect_status_t status = dlc_send_data_from_cvg(dest_short_rd_id, sdu_buf,
													  CVG_SERVICE_TYPE_DATA, QOS_PRIORITY_NORMAL);
		if (status != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(status, "CVG TX: Failed to send data SDU to DLC.");
			STATS_INC(dect_stats.cvg_tx_drops);
			net_pkt_unref(pkt); // Ensure packet is freed if DLC didn't take ownership
		} else {
			LOG_DBG("CVG TX: Packet sent to DLC for transmission.");
			STATS_INC(dect_stats.tx_app_data_requests);
			STATS_INC_VAL(dect_stats.tx_app_data_bytes, net_pkt_get_len(pkt));
			net_pkt_unref(pkt); // DLC copies or refs its own. Free the original net_pkt.
		}
	}
}

dect_status_t cvg_send_ipv6_pkt(struct net_if *iface, struct net_pkt *pkt)
{
	ARG_UNUSED(iface);
	if (!pkt) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CVG: Cannot send NULL net_pkt.");
		STATS_INC(dect_stats.cvg_tx_drops);
		return DECT_ERROR_INVALID_PARAM;
	}

	// Queue the packet for the CVG TX thread
	int ret = k_msgq_put(&cvg_tx_net_pkt_msgq, &pkt, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_QUEUE_FULL, "CVG: Failed to queue net_pkt for TX. Queue full.");
		net_pkt_unref(pkt); // Release the packet if it can't be queued
		STATS_INC(dect_stats.cvg_tx_drops);
		return DECT_ERROR_QUEUE_FULL;
	}
	LOG_DBG("CVG: Queued net_pkt (len %u) for TX.", net_pkt_get_len(pkt));
	return DECT_STATUS_OK;
}

dect_status_t dect_cvg_receive_sdu_from_dlc(uint16_t src_short_rd_id, struct net_buf *sdu_buf,
											cvg_service_type_t service_type,
											uint32_t hpc, uint16_t psn)
{
	if (!sdu_buf || sdu_buf->len == 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CVG RX: Received NULL or empty SDU from DLC. Dropping.");
		STATS_INC(dect_stats.cvg_rx_drops);
		if (sdu_buf) {
			net_buf_unref(sdu_buf); // Ensure buffer is freed if invalid
		}
		return DECT_ERROR_INVALID_PARAM;
	}

	dect_power_mgr_activity_detected(); // Notify power manager of RX activity

	LOG_DBG("CVG RX: Received SDU from DLC (src 0x%04x, len %u, service type %u).",
			src_short_rd_id, sdu_buf->len, service_type);

	// The `sdu_buf` now contains the IPv6 packet or a fragment.
	// We need to pass it to the network stack.

	// In a complete implementation, this is where you'd handle
	// 6LoWPAN decompression, IPv6 fragmentation/reassembly, etc.

	// For now, assuming the sdu_buf directly contains a full IPv6 packet
	// or a fragment that needs to be reassembled by Zephyr's 6LoWPAN or IPv6 stack.

	struct net_pkt *rx_pkt;
	struct net_if *iface = net_if_get_default(); // Get the default network interface

	if (!iface) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG RX: No default network interface. Dropping SDU.");
		STATS_INC(dect_stats.cvg_rx_drops);
		net_buf_unref(sdu_buf);
		return DECT_ERROR_GENERIC;
	}

	// Create a new net_pkt from the received net_buf.
	// The net_pkt_rx function usually takes ownership of the net_buf.
	rx_pkt = net_pkt_rx_alloc_with_buffer(iface, sdu_buf->len, AF_UNSPEC, 0, K_NO_WAIT);
	if (!rx_pkt) {
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "CVG RX: Failed to allocate net_pkt for RX. Dropping SDU.");
		STATS_INC(dect_stats.cvg_rx_drops);
		net_buf_unref(sdu_buf); // Free the original buffer if net_pkt allocation failed
		return DECT_ERROR_NO_MEM;
	}

	// Append the data from sdu_buf to rx_pkt.
	// net_pkt_insert_frag will append the fragment and take ownership.
	if (net_pkt_insert_frag(rx_pkt, sdu_buf) < 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG RX: Failed to insert fragment into net_pkt. Dropping.");
		net_pkt_unref(rx_pkt); // Release partially formed net_pkt
		net_buf_unref(sdu_buf); // Ensure fragment is unref'd
		STATS_INC(dect_stats.cvg_rx_drops);
		return DECT_ERROR_GENERIC;
	}

#ifdef CONFIG_NET_6LO
	// Attempt 6LoWPAN decompression if enabled
	int ret = net_6lo_uncompress(rx_pkt);
	if (ret < 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_6LO_DECOMPRESSION_FAILED, "CVG RX: 6LoWPAN decompression failed (%d). Dropping.", ret);
		STATS_INC(dect_stats.sixlo_decompression_failures);
		net_pkt_unref(rx_pkt);
		STATS_INC(dect_stats.cvg_rx_drops);
		return DECT_ERROR_6LO_DECOMPRESSION_FAILED;
	}
	if (ret == 0) { // Successfully uncompressed
		LOG_DBG("CVG RX: 6LoWPAN decompression successful.");
		STATS_INC(dect_stats.sixlo_decompression_success);
	} else { // No 6LoWPAN header or not needed decompression
		LOG_DBG("CVG RX: No 6LoWPAN header or not applicable for decompression.");
	}
#endif // CONFIG_NET_6LO


	// Pass the packet up the network stack
	int ret_rx = net_recv_data(iface, rx_pkt);
	if (ret_rx < 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG RX: Failed to pass packet to network stack (%d). Dropping.", ret_rx);
		net_pkt_unref(rx_pkt); // Ensure packet is freed if net_recv_data fails
		STATS_INC(dect_stats.cvg_rx_drops);
		return DECT_ERROR_GENERIC;
	}
	LOG_DBG("CVG RX: Packet passed to network stack.");
	STATS_INC_VAL(dect_stats.rx_app_data_bytes, net_pkt_get_len(rx_pkt));

	return DECT_STATUS_OK;
}

static struct net_pkt *cvg_reassemble_fragment(struct net_pkt *frag_pkt,
											   struct net_ipv6_hdr *ipv6_hdr,
											   struct net_ipv6_frag_hdr *frag_hdr)
{
	// This is a placeholder. Full IPv6 reassembly would be complex.
	// Zephyr's net_core handles fragmentation for IPv6, but typically expects
	// fragments to be passed to net_recv_data and it will do the reassembly if CONFIG_NET_IPV6_FRAGMENT is enabled.
	// This function might be removed if net_recv_data is expected to handle it.
	LOG_WRN("CVG: Fragmentation reassembly is a placeholder, not fully implemented.");
	STATS_INC(dect_stats.cvg_frag_drops); // Treat as a drop for now if not handled by stack

	net_pkt_unref(frag_pkt); // Release fragment as it's not being reassembled here
	return NULL;
}

static dect_status_t cvg_send_fragment(uint16_t dest_short_rd_id, struct net_pkt *frag_pkt,
									   cvg_service_type_t service_type,
									   qos_priority_t qos_priority)
{
	LOG_DBG("CVG: Sending fragment to DLC (len %u).", net_pkt_get_len(frag_pkt));
	// This function would be called by the fragmentation logic to send individual fragments.
	// It would call dlc_send_data_from_cvg with the fragment.
	// For now, it's a placeholder.
	STATS_INC(dect_stats.cvg_frag_tx);
	net_pkt_unref(frag_pkt); // Release fragment as it's not being sent
	return DECT_ERROR_NOT_IMPLEMENTED;
}


dect_status_t dect_nr_plus_iface_init(struct net_if *iface)
{
	iface->l2 = &dect_nr_plus_l2_api;
	iface->l2_data = NULL; // No specific L2 data context needed for this example

	// Set MAC address. This should come from dect_config.mac_address.
	net_if_set_link_addr(iface, dect_config.mac_address, sizeof(dect_config.mac_address), NET_L2_TYPE_UNKNOWN);
	LOG_INF("DECT NR+ Interface initialized with MAC address: %02x:%02x:%02x:%02x.",
			dect_config.mac_address[0], dect_config.mac_address[1],
			dect_config.mac_address[2], dect_config.mac_address[3]);

	// Bring the network interface up
	net_if_carrier_on(iface);
	LOG_INF("DECT NR+ Interface carrier ON.");

	// Add a default IPv6 address based on MAC address
	// This uses the Zephyr standard EUI-64 generation if configured, or a custom one.
	struct in6_addr ipv6_addr;
	// Call net_if_ipv6_addr_create() or manually construct from MAC
	// For a 4-byte MAC, a custom IID generation might be needed if not using EUI-64.
	// Assuming dect_nr_plus_iface_iid_cb handles custom IID generation for this 4-byte MAC.
	if (net_if_ipv6_addr_add(iface, &ipv6_addr, NET_ADDR_AUTOCONF, 0) == NULL) {
		DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG: Failed to add IPv6 address to interface.");
		return DECT_ERROR_GENERIC;
	}

	return DECT_STATUS_OK;
}

bool dect_nr_plus_iface_iid_cb(struct net_if *iface, struct in6_addr *iid)
{
	// This callback is used by Zephyr's IPv6 stack to generate an Interface ID (IID)
	// for a link-local address, based on the L2 address (MAC address).
	// For DECT NR+ with a 4-byte MAC, this is a custom mapping.
	// Standard EUI-64 would involve padding a 48-bit MAC to 64 bits.
	// For a 4-byte MAC, you'd typically zero-pad or use a fixed prefix.

	ARG_UNUSED(iface);

	// Assuming a simplified mapping for a 4-byte MAC to a 64-bit IID:
	// Copy MAC address to first 4 bytes of IID, then pad with zeros or a fixed pattern.
	// A typical EUI-64 conversion for a 48-bit MAC would insert 0xFFFE in the middle
	// and invert the U/L bit. For 4 bytes, we need a custom approach.
	// For simplicity, we'll fill the first 4 bytes with the MAC address and then fill the rest.
	// IID format: [MAC byte 0] [MAC byte 1] : [MAC byte 2] [MAC byte 3] : 0000 : 0000 : 0000 : 0001 (example)

	// Note: The standard EUI-64 conversion for 48-bit MAC (e.g., 00-11-22-33-44-55) to IID is:
	// 02-11-22-FF-FE-33-44-55 (invert 7th bit of first byte, insert FFFE)
	// For a 4-byte MAC, you might define a specific custom scheme or use a fixed prefix.

	// Example: Copy MAC address directly and pad
	iid->s6_addr[0] = dect_config.mac_address[0];
	iid->s6_addr[1] = dect_config.mac_address[1];
	iid->s6_addr[2] = dect_config.mac_address[2];
	iid->s6_addr[3] = dect_config.mac_address[3];
	iid->s6_addr[4] = 0x00; // Example padding
	iid->s6_addr[5] = 0x00; // Example padding
	iid->s6_addr[6] = 0x00; // Example padding
	iid->s6_addr[7] = 0x01; // Example padding (last byte is typically 0x01 for first IID)

	// Invert the universal/local bit (bit 1 of the first octet) if using EUI-48/64 conversion
	// For a 4-byte MAC, this mapping might be custom.
	// iid->s6_addr[0] ^= 0x02; // Example for EUI-64 derived from 48-bit MAC

	LOG_DBG("CVG: Derived IPv6 IID: %02x%02x:%02x%02x:%02x%02x:%02x%02x",
		iid->s6_addr[0], iid->s6_addr[1], iid->s6_addr[2], iid->s6_addr[3],
		iid->s6_addr[4], iid->s6_addr[5], iid->s6_addr[6], iid->s6_addr[7]);

	return true; // IID successfully derived
}
