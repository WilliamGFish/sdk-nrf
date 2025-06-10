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
#include <random/rand32.h> // For sys_rand32_get for Fragmentation ID

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
#include <dect_nr_plus/dect_routing.h> // For routing layer interaction
#include <dect_nr_plus/dect_cvg.h> /* Own header */
#include <dect_nr_plus/dect_mac.h> // For dect_mac_lookup_ipv6_to_short_rd_id

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_cvg, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global CVG context instance definition */
dect_cvg_context_t cvg_ctx = {
	.next_datagram_tag = 0, // Initial datagram tag
};

/* Net buffer pool for CVG transmit PDUs (fragments to DLC) */
NET_BUF_POOL_DEFINE(cvg_tx_net_buf_pool, CONFIG_DECT_NR_PLUS_CVG_TX_BUF_COUNT,
					CONFIG_DECT_NR_PLUS_CVG_TX_BUF_SIZE, 0, NULL);

/* Message queue for net_pkts from higher layers (e.g., application, IP stack) to CVG TX thread */
K_MSGQ_DEFINE(cvg_tx_net_pkt_msgq, sizeof(cvg_tx_queue_entry_t),
			  CONFIG_DECT_NR_PLUS_CVG_TX_QUEUE_COUNT, 4);

/* Message queue for data from DLC to CVG (for the CVG RX thread) */
K_MSGQ_DEFINE(cvg_rx_msgq, sizeof(dlc_rx_msg_t),
			  CONFIG_DECT_NR_PLUS_CVG_RX_QUEUE_COUNT, 4);


/* Forward declarations for internal functions */
static int cvg_send_ipv6_pkt(struct net_if *iface, struct net_pkt *pkt);
static bool dect_nr_plus_iface_iid_cb(struct net_if *iface, struct in6_addr *iid);
static void reassembly_timeout_handler(struct k_timer *timer_id);
static void dect_cvg_thread(void *p1, void *p2, void *p3); // Combined CVG thread prototype


/* IPv6 Fragmentation Header length in bytes */
#define IPV6_FRAG_HDR_LEN 8
/* Offset of Fragment Offset field in Fragmentation Header */
#define IPV6_FRAG_OFFSET_OFFSET 2
/* Mask for Fragment Offset field (13 bits, shifted by 3) */
#define IPV6_FRAG_OFFSET_MASK 0xFFF8
/* Mask for M (More Fragments) flag in Fragmentation Header */
#define IPV6_FRAG_M_FLAG_MASK 0x01
/* Identification field offset */
#define IPV6_FRAG_ID_OFFSET 4

/* Helper to handle net_buf allocation and error paths */
static dect_status_t handle_tx_buffer_allocation(struct net_buf **out_buf, struct net_buf_pool *pool, const char *caller_name,
												   size_t size, enum dect_status_t error_code)
{
	*out_buf = net_buf_alloc(pool, K_NO_WAIT);
	if (!(*out_buf)) {
		DECT_ERROR_HANDLER(error_code, "%s: Failed to allocate TX net_buf of size %zu.", caller_name, size);
		STATS_INC(dect_stats.cvg_tx_drops); // Specific CVG TX drop stat
		return error_code;
	}
	return DECT_STATUS_OK;
}

void dect_cvg_init(void)
{
	int status;

	/* Initialize reassembly sessions */
	for (int i = 0; i < MAX_PEERS; i++) {
		cvg_ctx.rx_reassembly_sessions[i].pkt = NULL;
		cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id = 0;
		cvg_ctx.rx_reassembly_sessions[i].datagram_tag = 0;
		cvg_ctx.rx_reassembly_sessions[i].datagram_size = 0;
		cvg_ctx.rx_reassembly_sessions[i].current_length = 0;
		cvg_ctx.rx_reassembly_sessions[i].fragment_mask = 0;
		cvg_ctx.rx_reassembly_sessions[i].last_rx_time_ms = 0;
	}

	/* Initialize reassembly timeout timer */
	k_timer_init(&cvg_ctx.reassembly_timeout_timer, reassembly_timeout_handler, NULL);
	k_timer_start(&cvg_ctx.reassembly_timeout_timer, K_MSEC(CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_TIMEOUT_MS),
				  K_MSEC(CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_TIMEOUT_MS / 2)); // Check every half timeout interval

	LOG_DBG("CVG: Initialized. Reassembly timer started.");
	// The `cvg_reassembly_failures` stat is now incremented on actual failures within receive_sdu_from_dlc,
	// not just on init.
	status = DECT_STATUS_OK; // Placeholder, assuming success for now.

	if (status != DECT_STATUS_OK) {
		DECT_ERROR_HANDLER(status, "CVG: Initialization failed.");
	} else {
		LOG_DBG("CVG: Module initialized successfully.");
	}
}

/**
 * @brief Zephyr L2 network interface API for DECT NR+.
 *
 * This struct defines the callbacks the Zephyr network stack will use
 * to interact with our DECT NR+ convergence layer.
 */
static const struct net_l2_api dect_nr_plus_l2_api = {
	.send = cvg_send_ipv6_pkt,
	.init = dect_nr_plus_iface_init, // This is called once on interface setup
};

/**
 * @brief Zephyr network interface initialization function for DECT NR+.
 *
 * This function is called by the Zephyr network stack to initialize our
 * DECT NR+ interface. It registers the L2 API and sets up IPv6 IID generation.
 *
 * @param iface Pointer to the network interface being initialized.
 * @return 0 on success, or a negative error code.
 */
int dect_nr_plus_iface_init(struct net_if *iface)
{
	net_l2_set_cb(iface, &dect_nr_plus_l2_api);
	net_if_set_link_addr(iface, dect_config.mac_address, LONG_RD_ID_LEN_BYTES, NET_L2_TYPE_ETHERNET);
	net_if_ipv6_set_iid_cb(iface, dect_nr_plus_iface_iid_cb);

	// Store the network interface pointer in the MAC context for later use
	// Note: This creates a tight coupling. Consider a more abstract way to pass iface down if needed.
	mac_ctx.net_if_ptr = iface;

	LOG_DBG("CVG: DECT NR+ network interface initialized (iface: %p).", iface);
	return 0; // Success
}

/**
 * @brief Custom IPv6 Interface Identifier (IID) generation for DECT NR+.
 *
 * This callback is used by the Zephyr IPv6 stack to generate the unique
 * IID for IPv6 Stateless Address Autoconfiguration (SLAAC). It's derived
 * from the device's 4-byte DECT MAC address.
 *
 * @param iface Pointer to the network interface.
 * @param iid Pointer to the in6_addr structure to fill with the IID.
 * @return True on success, false otherwise.
 */
static bool dect_nr_plus_iface_iid_cb(struct net_if *iface, struct in6_addr *iid)
{
	ARG_UNUSED(iface);

	/*
	 * For a 4-byte MAC address (Long RD ID), a simple IID derivation:
	 * Example: MAC (00:11:22:33) -> IID (0011:2233:0000:0000:0000:0000:0000:0001)
	 * Standard EUI-64 conversion for 48-bit MAC is:
	 * MAC (byte0 byte1 byte2 byte3 byte4 byte5) -> IID (byte0^0x02 byte1 byte2 FF FE byte3 byte4 byte5)
	 *
	 * For a 4-byte MAC, we will use a simplified approach:
	 * Copy MAC address directly to the first 4 bytes of the IID,
	 * then pad with zeros, and set the last byte to 1 for uniqueness
	 * (or use another part of the MAC for the last bytes if desired).
	 * If more complex mapping is needed as per DECT NR+ specific IID rules,
	 * this function should be updated.
	 */

	memset(iid->s6_addr, 0, sizeof(iid->s6_addr)); // Zero out the entire IID

	// Copy MAC address to the first 4 bytes
	memcpy(iid->s6_addr, dect_config.mac_address, LONG_RD_ID_LEN_BYTES);

	// Optionally, for EUI-64, the U/L bit (0x02) in the first byte is inverted.
	// For DECT NR+ specific IID, this might be different.
	// iid->s6_addr[0] ^= 0x02; // Uncomment for EUI-64 U/L bit inversion

	// Add some unique part or fixed value if desired, e.g., the last byte
	iid->s6_addr[sizeof(iid->s6_addr) - 1] = 0x01; // Example: set last byte to 1

	LOG_DBG("CVG: Generated IPv6 IID: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			iid->s6_addr[0], iid->s6_addr[1], iid->s6_addr[2], iid->s6_addr[3],
			iid->s6_addr[4], iid->s6_addr[5], iid->s6_addr[6], iid->s6_addr[7],
			iid->s6_addr[8], iid->s6_addr[9], iid->s6_addr[10], iid->s6_addr[11],
			iid->s6_addr[12], iid->s6_addr[13], iid->s6_addr[14], iid->s6_addr[15]);

	return true;
}

/**
 * @brief L2 send function for Zephyr net_stack.
 *
 * This function is called by the Zephyr IP stack to send a net_pkt.
 * It queues the net_pkt to the CVG TX thread for further processing,
 * including fragmentation if necessary.
 *
 * @param iface Pointer to the network interface.
 * @param pkt Pointer to the net_pkt to send.
 * @return 0 on success, or a negative error code.
 */
static int cvg_send_ipv6_pkt(struct net_if *iface, struct net_pkt *pkt)
{
	ARG_UNUSED(iface);
	int ret = -EINVAL;

	if (!pkt) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CVG: cvg_send_ipv6_pkt received NULL pkt.");
		return -EINVAL;
	}

	// The `net_pkt` needs to be `ref`'d as it's put into a queue and processed by another thread.
	net_pkt_ref(pkt);

	cvg_tx_queue_entry_t tx_entry = {
		.pkt = pkt,
		.dest_short_rd_id = SHORT_RD_ID_BROADCAST, // Placeholder, resolve in tx_thread
		.qos_priority = QOS_PRIORITY_NORMAL,      // Placeholder, resolve in tx_thread
		.routing_mode = DECT_ROUTING_MODE_NONE,   // Will determine based on destination
	};

	ret = k_msgq_put(&cvg_tx_net_pkt_msgq, &tx_entry, K_NO_WAIT);
	if (ret != 0) {
		DECT_ERROR_HANDLER(DECT_ERROR_CVG_TX_DROPS, "CVG: Failed to queue net_pkt for TX (ret: %d).", ret);
		net_pkt_unref(pkt); // Unref if queuing fails
		STATS_INC(dect_stats.cvg_tx_drops);
		return -ENOBUFS;
	}

	LOG_DBG("CVG: Queued net_pkt (len %zu) for TX.", net_pkt_get_len(pkt));
	STATS_INC(dect_stats.tx_app_data_requests);

	return 0; // Success
}

/**
 * @brief Handles incoming data from the DLC layer to the CVG layer.
 *
 * This function processes received DLC PDUs, performs IPv6 reassembly if needed,
 * and passes complete IP packets to the Zephyr network stack.
 *
 * @param src_short_rd_id The Short RD ID of the source peer.
 * @param dlc_pdu_buf The net_buf containing the DLC payload (IP packet/fragment).
 * @param service_type The CVG service type (e.g., CVG_SERVICE_TYPE_DATA).
 * @param hpc Half-Permanent Counter from MAC.
 * @param psn Packet Sequence Number from MAC.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_cvg_receive_sdu_from_dlc(uint16_t src_short_rd_id,
											struct net_buf *dlc_pdu_buf,
											cvg_service_type_t service_type,
											uint32_t hpc,
											uint16_t psn)
{
	int status = DECT_STATUS_OK;

	if (!dlc_pdu_buf) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CVG RX: Received NULL DLC PDU buffer.");
		STATS_INC(dect_stats.cvg_rx_drops);
		return DECT_ERROR_INVALID_PARAM;
	}

	if (service_type != CVG_SERVICE_TYPE_DATA && service_type != CVG_SERVICE_TYPE_CONTROL) {
		LOG_WRN("CVG RX: Received non-data/non-control service type %d. Dropping.", service_type);
		net_buf_unref(dlc_pdu_buf);
		STATS_INC(dect_stats.cvg_rx_drops);
		return DECT_ERROR_INVALID_PARAM; // Or a more specific error code
	}

	STATS_ADD(dect_stats.rx_app_data_bytes, dlc_pdu_buf->len);

	k_mutex_lock(&cvg_ctx.mutex, K_FOREVER);

	// If the service_type is CONTROL, it implies a routing PDU that has already been
	// processed by the routing layer and potentially stripped of its routing header.
	// This function (dect_cvg_receive_sdu_from_dlc) now expects the buffer to be a "clean"
	// IP packet (or fragment) if it's coming from the routing layer's DATA_FORWARD path.

	// Check if the received PDU is an IPv6 fragment
	// This check relies on the IP header (or IPv6 Fragmentation Header) being at the start of the DLC payload.
	// We assume that if other IPv6 Extension Headers are present before the Fragmentation Header,
	// they are part of the initial IPv6 header and will be processed by the IP stack after reassembly.
	uint8_t *dlc_payload_ptr = net_buf_pull_unaligned_mem(dlc_pdu_buf, dlc_pdu_buf->len);
	uint8_t next_hdr_val = 0xFF; // Default to unknown

	if (dlc_pdu_buf->len >= (NET_IPV6_HDR_LEN + IPV6_FRAG_HDR_LEN)) {
		// Case 1: Full IPv6 header (at least base header) + Fragmentation header
		// Peek the Next Header field (offset 6 in IPv6 header)
		next_hdr_val = dlc_payload_ptr[6];
	} else if (dlc_pdu_buf->len >= IPV6_FRAG_HDR_LEN) {
		// Case 2: Only Fragmentation header (e.g., subsequent fragment or after 6LoWPAN decompression if it was compressed without full IP header)
		// The first byte of the fragmentation header is the 'Next Header' field.
		next_hdr_val = dlc_payload_ptr[0];
	}

	bool is_fragment = (next_hdr_val == IPPROTO_FRAGMENT);

	if (is_fragment) {
		// This is likely an IPv6 fragment
		STATS_INC(dect_stats.cvg_frag_rx);

		// Extract fragment header fields
		uint8_t *frag_hdr_ptr;
		size_t ip_header_len = 0; // Length of the original IPv6 header if present

		if (dlc_pdu_buf->len >= (NET_IPV6_HDR_LEN + IPV6_FRAG_HDR_LEN) &&
			dlc_payload_ptr[6] == IPPROTO_FRAGMENT) {
			// It's a first fragment with full IPv6 header + fragment header
			frag_hdr_ptr = dlc_payload_ptr + NET_IPV6_HDR_LEN;
			ip_header_len = NET_IPV6_HDR_LEN;
			// For reassembly, we usually only pass the fragment header + payload.
			// The original IPv6 header is handled by the IP stack during reassembly.
			// So, pull the IPv6 header if present
			net_buf_pull(dlc_pdu_buf, ip_header_len);
		} else if (dlc_pdu_buf->len >= IPV6_FRAG_HDR_LEN && dlc_payload_ptr[0] == IPPROTO_FRAGMENT) {
			// It's a fragment with only the fragmentation header (e.g., subsequent fragment or after 6LoWPAN)
			frag_hdr_ptr = dlc_payload_ptr;
		} else {
			// If we reach here, `is_fragment` was true based on `next_hdr_val`, but the buffer length
			// or initial byte didn't match expected fragment header patterns. This is an error.
			DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_TYPE, "CVG RX: Fragment detected but malformed header. Dropping.");
			net_buf_unref(dlc_pdu_buf);
			STATS_INC(dect_stats.cvg_reassembly_drops);
			STATS_INC(dect_stats.cvg_reassembly_failures);
			status = DECT_ERROR_INVALID_PARAM;
			goto exit_mutex_unlock;
		}


		// Read Fragment Offset and M flag (big endian)
		uint16_t frag_offset_and_m_flag = (frag_hdr_ptr[2] << 8) | frag_hdr_ptr[3];
		size_t frag_offset_units = (frag_offset_and_m_flag & IPV6_FRAG_OFFSET_MASK) >> 3; // Offset in 8-octet units
		bool more_fragments_flag = (frag_offset_and_m_flag & IPV6_FRAG_M_FLAG_MASK) != 0;

		// Read Identification (big endian)
		uint32_t frag_id = (frag_hdr_ptr[4] << 24) | (frag_hdr_ptr[5] << 16) |
								 (frag_hdr_ptr[6] << 8) | frag_hdr_ptr[7];

		// Find reassembly session
		cvg_rx_sdu_reassembly_t *session = NULL;
		int free_session_idx = -1;

		for (int i = 0; i < MAX_PEERS; i++) {
			if (cvg_ctx.rx_reassembly_sessions[i].pkt &&
				cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id == src_short_rd_id &&
				cvg_ctx.rx_reassembly_sessions[i].datagram_tag == frag_id) {
				session = &cvg_ctx.rx_reassembly_sessions[i];
				break;
			}
			if (!cvg_ctx.rx_reassembly_sessions[i].pkt && free_session_idx == -1) {
				free_session_idx = i;
			}
		}

		if (!session) {
			if (free_session_idx != -1) {
				session = &cvg_ctx.rx_reassembly_sessions[free_session_idx];
				memset(session, 0, sizeof(*session)); // Clear new session
				session->src_short_rd_id = src_short_rd_id;
				session->datagram_tag = frag_id;
				session->last_rx_time_ms = k_uptime_get();
				LOG_DBG("CVG RX: Started new reassembly session for src 0x%04x, ID %08x.", src_short_rd_id, frag_id);
			} else {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_REASSEMBLY_DROPS, "CVG RX: No reassembly session available for ID %08x (src 0x%04x). Dropping fragment.", frag_id, src_short_rd_id);
				net_buf_unref(dlc_pdu_buf); // Drop fragment
				STATS_INC(dect_stats.cvg_reassembly_failures); // Increment failure stat
				status = DECT_ERROR_NO_RESOURCES;
				goto exit_mutex_unlock;
			}
		}

		// Check for duplicate or out-of-bounds fragment (simple check based on mask)
		uint8_t fragment_idx = (uint8_t)frag_offset_units; // Index based on 8-octet units offset
		if (fragment_idx >= CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_MAX_FRAGMENTS) {
			LOG_ERR("CVG RX: Out-of-bounds fragment index %u for ID %08x. Max allowed %u. Dropping.",
					fragment_idx, frag_id, CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_MAX_FRAGMENTS - 1);
			net_buf_unref(dlc_pdu_buf); // Drop fragment
			STATS_INC(dect_stats.cvg_reassembly_drops);
			STATS_INC(dect_stats.cvg_reassembly_failures); // Increment failure stat
			status = DECT_ERROR_INVALID_PARAM;
			goto exit_mutex_unlock;
		}
		if (session->fragment_mask & (1U << fragment_idx)) {
			LOG_WRN("CVG RX: Duplicate fragment %u for ID %08x. Dropping.", fragment_idx, frag_id);
			net_buf_unref(dlc_pdu_buf); // Drop duplicate fragment
			STATS_INC(dect_stats.cvg_reassembly_drops);
			status = DECT_STATUS_OK; // Not a failure but a drop (still ok operation)
			goto exit_mutex_unlock;
		}

		// Pull the fragmentation header before appending to net_pkt
		net_buf_pull(dlc_pdu_buf, IPV6_FRAG_HDR_LEN);

		if (!session->pkt) {
			// This is the first fragment received for this session.
			// Allocate the initial net_pkt and attach the fragment's net_buf.
			session->pkt = net_pkt_rx_alloc_with_buffer(cvg_ctx.net_if_ptr, dlc_pdu_buf->len, AF_UNSPEC, 0, K_NO_WAIT);
			if (!session->pkt) {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_NO_MEM, "CVG RX: Failed to allocate net_pkt for reassembly (ID %08x).", frag_id);
				net_buf_unref(dlc_pdu_buf);
				STATS_INC(dect_stats.cvg_reassembly_failures); // Increment failure stat
				status = DECT_ERROR_NO_MEMORY;
				goto exit_mutex_unlock;
			}
			net_pkt_frag_add(session->pkt, dlc_pdu_buf); // Attach the net_buf
			session->datagram_size = 0; // Will be determined by last fragment
			session->first_hpc = hpc; // Store HPC/PSN from first fragment
			session->first_psn = psn;
			session->current_length = dlc_pdu_buf->len;
		} else {
			// Not the first fragment, append to existing net_pkt
			net_pkt_frag_add(session->pkt, dlc_pdu_buf); // Append the fragment's net_buf
			session->current_length += dlc_pdu_buf->len;
		}

		session->fragment_mask |= (1U << fragment_idx);
		session->last_rx_time_ms = k_uptime_get();

		// Determine if all fragments have arrived for this session
		bool all_fragments_received = false;
		if (!more_fragments_flag) { // This is the last fragment
			// Calculate total size if it hasn't been determined yet (should only be for first fragment where more_fragments_flag was true initially)
			// Or, if this is the last fragment, we now know the total length.
			session->datagram_size = (frag_offset_units * 8) + dlc_pdu_buf->len;
			LOG_DBG("CVG RX: Last fragment received for ID %08x, calculated total datagram size: %u.", frag_id, session->datagram_size);

			// Verify contiguity and completeness of fragments
			// The mask should cover all 8-octet units from 0 up to (total_datagram_size / 8) - 1.
			// `DIV_ROUND_UP` for the number of 8-octet units to handle payloads not perfectly divisible by 8.
			size_t expected_total_8_octet_units = DIV_ROUND_UP(session->datagram_size, 8);
			// For a 0-length payload with fragment header, it still signifies offset 0
			if (session->datagram_size == 0 && expected_total_8_octet_units == 0) {
				expected_total_8_octet_units = 1; // At least offset 0 should be present
			}

			// Generate the mask that *should* be set if all contiguous fragments are present from 0 up to expected_total_8_octet_units - 1
			uint32_t required_mask = (1U << expected_total_8_octet_units) - 1;

			if (session->fragment_mask == required_mask) {
				// Additional check: ensure the accumulated length exactly matches the determined datagram_size
				if (session->current_length == session->datagram_size) {
					all_fragments_received = true;
				} else {
					LOG_ERR("CVG RX: Reassembly error for ID %08x: Mask complete (0x%x) but current_length %zu != calculated datagram_size %u. (Possible overlap/corruption)",
							frag_id, session->fragment_mask, session->current_length, session->datagram_size);
					STATS_INC(dect_stats.cvg_reassembly_failures);
				}
			} else {
				LOG_ERR("CVG RX: Reassembly error for ID %08x: Missing fragments. Mask 0x%x, Expected 0x%x (for %zu units). Current len %zu, Expected len %u.",
						frag_id, session->fragment_mask, required_mask, expected_total_8_octet_units, session->current_length, session->datagram_size);
				STATS_INC(dect_stats.cvg_reassembly_failures);
			}
		}

		if (all_fragments_received) {
			LOG_DBG("CVG RX: All fragments for ID %08x reassembled. Total length %zu. Passing to IP stack.", frag_id, session->current_length);
			// Pass reassembled packet to IP stack
			status = net_recv_data(session->pkt);
			if (status != 0) {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_REASSEMBLY_DROPS, "CVG RX: Failed to pass reassembled pkt to IP stack (ret: %d).", status);
				net_pkt_unref(session->pkt); // Unref if IP stack fails to process
				STATS_INC(dect_stats.cvg_reassembly_failures);
			} else {
				STATS_INC(dect_stats.cvg_reassembly_success);
			}
			// Clear reassembly session
			session->pkt = NULL;
			session->src_short_rd_id = 0; // Mark as free
			session->datagram_tag = 0;
			session->datagram_size = 0;
			session->current_length = 0;
			session->fragment_mask = 0;
			session->last_rx_time_ms = 0;
		} else if (more_fragments_flag || session->current_length == 0) { // Only log this if more fragments are still expected or it's an initial fragment
			LOG_DBG("CVG RX: Fragment %u (ID %08x) received, waiting for more. Mask: 0x%x, Current len: %zu.",
					fragment_idx, frag_id, session->fragment_mask, session->current_length);
		} else { // Case where last fragment received, but reassembly check failed (e.g., missing fragments)
			LOG_WRN("CVG RX: Reassembly for ID %08x completed (last fragment received) but failed integrity checks. Dropping reassembled packet.", frag_id);
			net_pkt_unref(session->pkt); // Drop the partially reassembled packet
			STATS_INC(dect_stats.cvg_reassembly_drops);
			STATS_INC(dect_stats.cvg_reassembly_failures);
			// Clear reassembly session
			session->pkt = NULL;
			session->src_short_rd_id = 0;
			session->datagram_tag = 0;
			session->datagram_size = 0;
			session->current_length = 0;
			session->fragment_mask = 0;
			session->last_rx_time_ms = 0;
		}
	} else {
		// Not an IPv6 fragment, pass directly to IP stack (or to Routing/Control handlers)
		LOG_DBG("CVG RX: Non-fragmented PDU (len %zu) received. Passing to IP stack or control handler.", dlc_pdu_buf->len);

		if (service_type == CVG_SERVICE_TYPE_CONTROL) {
			// Handle CVG control messages (e.g., connection setup/teardown if applicable)
			// For now, just log and drop, or extend with specific control PDU handling
			LOG_DBG("CVG RX: Received CVG Control PDU. Processing...");
			// Example: if it's a routing PDU, pass to routing layer
			uint8_t *control_pdu_ptr = net_buf_pull_unaligned_mem(dlc_pdu_buf, dlc_pdu_buf->len);
			if (dect_config.enable_routing && dlc_pdu_buf->len > 0 &&
				(control_pdu_ptr[0] == ROUTING_PDU_TYPE_ROUTE_REQUEST ||
				 control_pdu_ptr[0] == ROUTING_PDU_TYPE_ROUTE_REPLY ||
				 control_pdu_ptr[0] == ROUTING_PDU_TYPE_ROUTE_ERROR ||
				 control_pdu_ptr[0] == ROUTING_PDU_TYPE_DATA_FORWARD)) { // Also pass data_forward to routing
				LOG_DBG("CVG RX: Identified as Routing PDU. Passing to Routing layer.");
				// The routing layer handles its own buffer unref, so we don't unref here.
				dect_status_t routing_status = dect_routing_process_incoming_pdu(src_short_rd_id, dlc_pdu_buf, hpc, psn);
				if (routing_status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(routing_status, "CVG RX: Failed to pass Routing PDU to Routing layer.");
					// routing layer should unref the buffer, but add a fallback here if it didn't
					net_buf_unref(dlc_pdu_buf); // Fallback unref
					STATS_INC(dect_stats.cvg_rx_drops);
				}
			} else {
				LOG_WRN("CVG RX: Unhandled CVG Control PDU type or Routing disabled. Dropping.");
				net_buf_unref(dlc_pdu_buf); // Drop unhandled control PDU
				STATS_INC(dect_stats.cvg_rx_drops);
			}
		} else { // CVG_SERVICE_TYPE_DATA (non-fragmented IP packet)
			struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(cvg_ctx.net_if_ptr, dlc_pdu_buf->len, AF_UNSPEC, 0, K_NO_WAIT);
			if (!pkt) {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_NO_MEM, "CVG RX: Failed to allocate net_pkt for non-fragmented PDU.");
				net_buf_unref(dlc_pdu_buf); // Drop incoming buffer
				STATS_INC(dect_stats.cvg_rx_drops);
				status = DECT_ERROR_NO_MEMORY;
				goto exit_mutex_unlock;
			}

			net_pkt_frag_add(pkt, dlc_pdu_buf); // Attach the net_buf to the net_pkt

	#ifdef CONFIG_NET_6LO
			// If 6LoWPAN is enabled, try to decompress
			int ret_6lo = net_6lo_uncompress(pkt);
			if (ret_6lo < 0) {
				DECT_ERROR_HANDLER(DECT_ERROR_6LO_DECOMPRESSION_FAILED, "CVG RX: 6LoWPAN decompression failed (ret: %d).", ret_6lo);
				net_pkt_unref(pkt);
				STATS_INC(dect_stats.sixlo_decompression_failures);
				status = DECT_ERROR_DECOMPRESSION_FAILED;
				goto exit_mutex_unlock;
			}
			LOG_DBG("CVG RX: 6LoWPAN decompression successful.");
			STATS_INC(dect_stats.sixlo_decompression_success);
	#endif /* CONFIG_NET_6LO */

			// When a new IP packet is received from a peer, potentially update the IP-to-Short RD ID map.
			// This is a simplified approach; in a full NDP equivalent, you'd extract source IP and map it.
			if (net_pkt_family(pkt) == AF_INET6) {
				const struct in6_addr *src_ipv6_addr = net_pkt_ipv6_src(pkt);
				if (src_ipv6_addr && !net_ipv6_is_addr_unspecified(src_ipv6_addr) &&
					!net_ipv6_is_addr_multicast(src_ipv6_addr)) {
					// Add or update mapping. This needs to be done carefully to avoid conflicts
					// and manage lifetime of mappings. For now, a simple add/update.
					dect_mac_add_ipv6_to_short_rd_id_mapping(src_ipv6_addr, src_short_rd_id);
					LOG_DBG("CVG RX: Added/updated IP-to-RD ID mapping for %s -> 0x%04x.",
							log_strdup(net_ipv6_sprint(src_ipv6_addr)), src_short_rd_id);
				}
			}


			status = net_recv_data(pkt);
			if (status != 0) {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_RX_DROPS, "CVG RX: Failed to pass non-fragmented pkt to IP stack (ret: %d).", status);
				net_pkt_unref(pkt);
			} else {
				LOG_DBG("CVG RX: Non-fragmented pkt (len %zu) passed to IP stack.", net_pkt_get_len(pkt));
			}
		}
	}

exit_mutex_unlock:
	k_mutex_unlock(&cvg_ctx.mutex);
	dect_power_mgr_activity_detected(); // Notify power manager of RX activity
	return status;
}

/**
 * @brief Combined thread entry point for the CVG layer.
 * This thread handles IPv6 fragmentation and sends data to the DLC layer,
 * and processes incoming data from the DLC layer, performing reassembly.
 * It uses a polling mechanism with k_msgq_get(K_NO_WAIT) and k_sleep
 * for consistency with other layers.
 *
 * @param p1 Unused.
 * @param p2 Unused.
 * @param p3 Unused.
 */
static void dect_cvg_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_DBG("DECT CVG Thread started.");

	cvg_tx_queue_entry_t tx_entry;
	dlc_rx_msg_t rx_msg;
	dect_status_t status;
	bool had_activity_this_loop;

	while (true) {
		had_activity_this_loop = false;

		/* Process TX messages first */
		if (k_msgq_get(&cvg_tx_net_pkt_msgq, &tx_entry, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;

			struct net_pkt *pkt = tx_entry.pkt;
			uint16_t dest_short_rd_id = tx_entry.dest_short_rd_id;
			qos_priority_t qos_priority = tx_entry.qos_priority;
			dect_routing_mode_t routing_mode = tx_entry.routing_mode;

			if (!pkt) {
				DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CVG TX: Received NULL net_pkt from queue.");
				STATS_INC(dect_stats.cvg_tx_drops);
				continue;
			}

			size_t original_pkt_len = net_pkt_get_len(pkt);
			STATS_ADD(dect_stats.tx_app_data_bytes, original_pkt_len);

			// Resolve destination Short RD ID and determine routing mode
			if (dest_short_rd_id == SHORT_RD_ID_BROADCAST || dest_short_rd_id == 0) { // If it's still default, try to resolve
				if (net_pkt_family(pkt) == AF_INET6) {
					const struct in6_addr *dest_ipv6_addr = net_pkt_ipv6_dst(pkt);

					if (net_ipv6_is_addr_multicast(dest_ipv6_addr)) {
						dest_short_rd_id = SHORT_RD_ID_BROADCAST;
						routing_mode = DECT_ROUTING_MODE_HORIZONTAL; // Multicast often uses horizontal flooding
						LOG_DBG("CVG TX: Identified IPv6 multicast, using DECT broadcast Short RD ID and Horizontal routing.");
					} else {
						// Try to look up in local MAC table
						dest_short_rd_id = dect_mac_lookup_ipv6_to_short_rd_id(dest_ipv6_addr);
						if (dest_short_rd_id == 0) { // If not found in direct map
							if (dect_config.enable_routing) {
								LOG_DBG("CVG TX: No direct IP-to-RD ID map for %s. Initiating route discovery via Routing layer for potential horizontal routing.",
										log_strdup(net_ipv6_sprint(dest_ipv6_addr)));
								// For now, if no direct mapping, assume horizontal routing for discovery.
								// A full implementation would involve:
								// 1. MAC/Routing learn IPv6-to-ShortRDID mappings.
								// 2. CVG queries these mappings.
								// 3. If missing, CVG can initiate IP-level discovery which translates to DECT NR+ routing.
								// Assigning a dummy Short RD ID or forcing a discovery to a specific peer type.
								// For this robust native routing, we'll try to discover a route for the IP destination
								// if it's not a direct peer.
								// In the absence of a direct Short RD ID, we cannot call dect_routing_discover_route directly
								// with just an IPv6 address. A proper integration would involve
								// the routing layer knowing how to initiate discovery based on IPv6.
								// For now, we will drop the packet if no direct mapping is found and routing is enabled but no
								// specific mechanism to start IP-based routing discovery is defined.
								// The previous solution of assigning a dummy 0x0002 could lead to packets
								// being routed to unintended destinations.
								LOG_WRN("CVG TX: No IP-to-RD ID map for %s and no explicit DECT NR+ routing discovery for IP. Dropping packet.",
										log_strdup(net_ipv6_sprint(dest_ipv6_addr)));
								net_pkt_unref(pkt);
								STATS_INC(dect_stats.cvg_tx_drops);
								continue;
							} else {
								LOG_WRN("CVG TX: No IP-to-RD ID map for %s and routing disabled. Dropping packet.",
										log_strdup(net_ipv6_sprint(dest_ipv6_addr)));
								net_pkt_unref(pkt);
								STATS_INC(dect_stats.cvg_tx_drops);
								continue;
							}
						} else {
							// Found a direct mapping, now determine routing mode
							// If it's a peer we're directly associated with, it's typically direct.
							// If not, and routing is enabled, it's multi-hop (uplink, downlink, or horizontal)
							if (dect_config.role == MAC_ROLE_PP && dest_short_rd_id == mac_ctx.associated_fp_short_rd_id) {
								routing_mode = DECT_ROUTING_MODE_UPLINK;
							} else if (dect_config.role == MAC_ROLE_FP && dect_mac_is_peer_associated(dest_short_rd_id)) {
								routing_mode = DECT_ROUTING_MODE_DOWNLINK;
							} else {
								// If not directly associated or not uplink/downlink, assume horizontal for now.
								// A more robust system would involve checking the routing table's mode for `dest_short_rd_id`.
								routing_mode = DECT_ROUTING_MODE_HORIZONTAL;
							}
							LOG_DBG("CVG TX: Resolved dest Short RD ID 0x%04x for %s, determined routing mode: %u.",
									dest_short_rd_id, log_strdup(net_ipv6_sprint(dest_ipv6_addr)), routing_mode);
						}
					}
				} else {
					LOG_WRN("CVG TX: Non-IPv6 packet with unknown dest Short RD ID. Dropping.");
					net_pkt_unref(pkt);
					STATS_INC(dect_stats.cvg_tx_drops);
					continue;
				}
			}
			// If dest_short_rd_id was already set (not 0 or broadcast), then routing_mode should also be set by application or higher layer.
			// If not, we'll try to infer a default.
			if (routing_mode == DECT_ROUTING_MODE_NONE) {
				// Fallback or attempt to infer a default mode if not set
				if (dest_short_rd_id == mac_ctx.associated_fp_short_rd_id && dect_config.role == MAC_ROLE_PP) {
					routing_mode = DECT_ROUTING_MODE_UPLINK;
				} else if (dect_mac_is_peer_associated(dest_short_rd_id) && dect_config.role == MAC_ROLE_FP) {
					routing_mode = DECT_ROUTING_MODE_DOWNLINK;
				} else {
					routing_mode = DECT_ROUTING_MODE_HORIZONTAL; // Default to horizontal if uncertain
					LOG_DBG("CVG TX: Defaulting routing mode to HORIZONTAL for dest 0x%04x.", dest_short_rd_id);
				}
			}


			// If still no valid dest_short_rd_id (e.g., after lookup, still 0 or broadcast for unicast)
			if (dest_short_rd_id == 0 || (dest_short_rd_id == SHORT_RD_ID_BROADCAST && !net_ipv6_is_addr_multicast(net_pkt_ipv6_dst(pkt)))) {
				LOG_WRN("CVG TX: Could not resolve final destination Short RD ID for packet. Dropping.");
				net_pkt_unref(pkt);
				STATS_INC(dect_stats.cvg_tx_drops);
				continue;
			}


			size_t max_dlc_payload_size = CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE - DLC_DATA_HDR_LEN_BYTES - DLC_CRC_LEN_BYTES;

			// Before fragmentation, perform 6LoWPAN compression if enabled
	#ifdef CONFIG_NET_6LO
			int ret_6lo_comp = net_6lo_compress(pkt);
			if (ret_6lo_comp < 0) {
				DECT_ERROR_HANDLER(DECT_ERROR_6LO_COMPRESSION_FAILED, "CVG TX: 6LoWPAN compression failed (ret: %d). Dropping packet.", ret_6lo_comp);
				net_pkt_unref(pkt);
				STATS_INC(dect_stats.sixlo_compression_failures);
				STATS_INC(dect_stats.cvg_tx_drops);
				continue;
			}
			LOG_DBG("CVG TX: 6LoWPAN compression successful, new length: %zu.", net_pkt_get_len(pkt));
			STATS_INC(dect_stats.sixlo_compression_success);
	#endif /* CONFIG_NET_6LO */

			// Recalculate original_pkt_len after potential compression
			original_pkt_len = net_pkt_get_len(pkt);


			if (original_pkt_len > max_dlc_payload_size) {
				LOG_DBG("CVG TX: Packet too large (%zu bytes). Fragmenting...", original_pkt_len);
				STATS_INC(dect_stats.cvg_frag_tx);

				uint32_t fragment_id = sys_rand32_get();
				size_t current_offset = 0;
				bool more_fragments = true;
				uint8_t fragment_idx = 0;

				// Fragment payload size must be a multiple of 8, and room for frag header
				size_t frag_payload_size = max_dlc_payload_size - IPV6_FRAG_HDR_LEN;
				frag_payload_size -= (frag_payload_size % 8); // Ensure multiple of 8
				if (frag_payload_size == 0) {
					DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "CVG TX: Fragment payload size zero after alignment. Cannot fragment.");
					net_pkt_unref(pkt);
					STATS_INC(dect_stats.cvg_frag_drops);
					continue;
				}

				while (more_fragments) {
					size_t bytes_left = original_pkt_len - current_offset;
					size_t current_frag_len = MIN(bytes_left, frag_payload_size);

					if (current_frag_len == 0) {
						LOG_WRN("CVG TX: current_frag_len is 0, breaking fragmentation loop.");
						break;
					}

					more_fragments = (bytes_left > current_frag_len);

					struct net_buf *dlc_pdu_buf = NULL;
					dect_status_t alloc_status = handle_tx_buffer_allocation(&dlc_pdu_buf, &cvg_tx_net_buf_pool, __func__,
																			current_frag_len + IPV6_FRAG_HDR_LEN, DECT_ERROR_CVG_NO_MEM);
					if (alloc_status != DECT_STATUS_OK) {
						net_pkt_unref(pkt);
						STATS_INC(dect_stats.cvg_frag_drops);
						break;
					}

					// Build Fragmentation Header
					// The Next Header field in the Fragmentation Header refers to the header of the *original* payload.
					// For IPv6, this means the next header after the base IPv6 header.
					net_buf_add_u8(dlc_pdu_buf, net_pkt_ipv6_next_hdr(pkt)); // Next Header (original payload type)
					net_buf_add_u8(dlc_pdu_buf, 0); // Reserved
					uint16_t frag_offset_and_m = (current_offset / 8) << 3; // Fragment Offset (8-octet units)
					if (more_fragments) {
						frag_offset_and_m |= IPV6_FRAG_M_FLAG_MASK; // Set M flag if more fragments
					}
					net_buf_add_be16(dlc_pdu_buf, frag_offset_and_m); // Fragment Offset and M flag
					net_buf_add_be32(dlc_pdu_buf, fragment_id); // Identification

					size_t copied_len = net_pkt_read(pkt, net_buf_tail(dlc_pdu_buf), current_offset, current_frag_len);
					if (copied_len != current_frag_len) {
						DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG TX: Failed to read full fragment payload (copied %zu of %zu).", copied_len, current_frag_len);
						net_buf_unref(dlc_pdu_buf);
						net_pkt_unref(pkt);
						STATS_INC(dect_stats.cvg_frag_drops);
						break;
					}
					net_buf_add(dlc_pdu_buf, copied_len);

					LOG_DBG("CVG TX: Sending fragment %u (offset %zu, len %zu, more %d, ID %08x).",
							fragment_idx, current_offset, current_frag_len, more_fragments, fragment_id);

					// Pass to routing layer if enabled, otherwise directly to DLC
					if (dect_config.enable_routing) {
						status = dect_routing_send_data(dest_short_rd_id, dlc_pdu_buf, qos_priority, routing_mode);
						if (status != DECT_STATUS_OK) {
							DECT_ERROR_HANDLER(status, "CVG TX: Failed to send fragment to Routing layer.");
							// dlc_pdu_buf is unref'd by dect_routing_send_data on failure
							STATS_INC(dect_stats.cvg_tx_drops);
							STATS_INC(dect_stats.cvg_frag_drops);
							net_pkt_unref(pkt); // Original pkt unref'd as fragmentation failed
							break;
						}
					} else {
						status = dect_dlc_send_data_from_cvg(dest_short_rd_id, dlc_pdu_buf, CVG_SERVICE_TYPE_DATA, qos_priority);
						if (status != DECT_STATUS_OK) {
							DECT_ERROR_HANDLER(status, "CVG TX: Failed to send fragment to DLC.");
							net_buf_unref(dlc_pdu_buf);
							STATS_INC(dect_stats.cvg_tx_drops);
							STATS_INC(dect_stats.cvg_frag_drops);
							net_pkt_unref(pkt); // Original pkt unref'd as fragmentation failed
							break;
						}
					}

					current_offset += current_frag_len;
					fragment_idx++;
				}
				net_pkt_unref(pkt); // Original net_pkt is unref'd after all fragments are processed/dropped

			} else {
				LOG_DBG("CVG TX: Packet fits in single PDU (len %zu). Sending to DLC.", original_pkt_len);

				struct net_buf *dlc_pdu_buf = NULL;
				dect_status_t alloc_status = handle_tx_buffer_allocation(&dlc_pdu_buf, &cvg_tx_net_buf_pool, __func__,
																			original_pkt_len, DECT_ERROR_CVG_NO_MEM);
				if (alloc_status != DECT_STATUS_OK) {
					net_pkt_unref(pkt);
					continue;
				}

				size_t copied_len = net_pkt_read(pkt, net_buf_tail(dlc_pdu_buf), 0, original_pkt_len);
				if (copied_len != original_pkt_len) {
					DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG TX: Failed to read full packet payload (copied %zu of %zu).", copied_len, original_pkt_len);
					net_buf_unref(dlc_pdu_buf);
					net_pkt_unref(pkt);
					STATS_INC(dect_stats.cvg_tx_drops);
					continue;
				}
				net_buf_add(dlc_pdu_buf, copied_len);

				// Pass to routing layer if enabled, otherwise directly to DLC
				if (dect_config.enable_routing) {
					status = dect_routing_send_data(dest_short_rd_id, dlc_pdu_buf, qos_priority, routing_mode);
					if (status != DECT_STATUS_OK) {
						DECT_ERROR_HANDLER(status, "CVG TX: Failed to send non-fragmented packet to Routing layer.");
						// dlc_pdu_buf is unref'd by dect_routing_send_data on failure
						STATS_INC(dect_stats.cvg_tx_drops);
					}
				} else {
					status = dect_dlc_send_data_from_cvg(dest_short_rd_id, dlc_pdu_buf, CVG_SERVICE_TYPE_DATA, qos_priority);
					if (status != DECT_STATUS_OK) {
						DECT_ERROR_HANDLER(status, "CVG TX: Failed to send non-fragmented packet to DLC.");
						net_buf_unref(dlc_pdu_buf);
						STATS_INC(dect_stats.cvg_tx_drops);
					}
				}
				net_pkt_unref(pkt); // Original net_pkt is unref'd after the single PDU is processed/dropped
			}
			dect_power_mgr_activity_detected();
		}

		/* Process RX messages */
		if (k_msgq_get(&cvg_rx_msgq, &rx_msg, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;

			LOG_DBG("CVG RX: Received message from DLC (src 0x%04x, len %u, type %u).",
					rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf->len, rx_msg.dlc_pdu_type);

			// Now call the main SDU processing function in CVG
			// If DLC_PDU_TYPE_ROUTING is passed, it means it's a routing control PDU
			// (not a data PDU from the routing layer). It will be handled in CVG_SERVICE_TYPE_CONTROL.
			// Data PDUs from routing are already handled as CVG_SERVICE_TYPE_DATA because
			// dect_routing_process_incoming_pdu sets that service type when calling this function
			// for DATA_FORWARD type.

			status = dect_cvg_receive_sdu_from_dlc(
											rx_msg.src_short_rd_id,
											rx_msg.dlc_pdu_buf,
											rx_msg.dlc_pdu_type == DLC_PDU_TYPE_DATA ? CVG_SERVICE_TYPE_DATA : CVG_SERVICE_TYPE_CONTROL, // Map DLC PDU type to CVG service type
											rx_msg.hpc,
											rx_msg.psn);

			if (status != DECT_STATUS_OK) {
				DECT_ERROR_HANDLER(status, "CVG RX: Error processing SDU from DLC.");
				// dect_cvg_receive_sdu_from_dlc is expected to unref the buffer on error.
			}
		}

		if (!had_activity_this_loop) {
			// If no messages were processed in this iteration, sleep to yield CPU
			k_sleep(K_MSEC(10)); // Sleep for a short period
		}
	}
}

/**
 * @brief Timer handler for reassembly timeouts.
 *
 * This function periodically scans the reassembly sessions and frees any
 * expired (incomplete) sessions, dropping their fragments.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
static void reassembly_timeout_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);
	uint64_t current_time = k_uptime_get();

	k_mutex_lock(&cvg_ctx.mutex, K_FOREVER);
	for (int i = 0; i < MAX_PEERS; i++) {
		if (cvg_ctx.rx_reassembly_sessions[i].pkt) {
			if ((current_time - cvg_ctx.rx_reassembly_sessions[i].last_rx_time_ms) >= CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_TIMEOUT_MS) {
				LOG_WRN("CVG RX: Reassembly session for ID 0x%08x (src 0x%04x) timed out. Dropping %zu bytes.",
						cvg_ctx.rx_reassembly_sessions[i].datagram_tag,
						cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id,
						cvg_ctx.rx_reassembly_sessions[i].current_length); // Log dropped length
				net_pkt_unref(cvg_ctx.rx_reassembly_sessions[i].pkt);
				cvg_ctx.rx_reassembly_sessions[i].pkt = NULL;
				cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id = 0; // Mark as free
				cvg_ctx.rx_reassembly_sessions[i].datagram_tag = 0;
				cvg_ctx.rx_reassembly_sessions[i].datagram_size = 0;
				cvg_ctx.rx_reassembly_sessions[i].current_length = 0;
				cvg_ctx.rx_reassembly_sessions[i].fragment_mask = 0;
				cvg_ctx.rx_reassembly_sessions[i].last_rx_time_ms = 0;
				STATS_INC(dect_stats.cvg_reassembly_failures); // Timeout is a failure
				STATS_INC(dect_stats.cvg_reassembly_drops);
			}
		}
	}
	k_mutex_unlock(&cvg_ctx.mutex);
}

/* Combined CVG Thread definition */
K_THREAD_DEFINE(dect_cvg_thread_id,
				CONFIG_DECT_NR_PLUS_CVG_THREAD_STACK_SIZE, // Sum of TX and RX stack sizes
				dect_cvg_thread, NULL, NULL, NULL,
				CONFIG_DECT_NR_PLUS_CVG_THREAD_PRIORITY, 0, K_FOREVER);

/* End of File
 * Last Amended: 2025-06-10 17:15 BST: Combined CVG TX/RX into a single `dect_cvg_thread` using `k_msgq_get(K_NO_WAIT)` for consistency.
 * - Updated `dect_cvg.h` to declare only `dect_cvg_thread`.
 * Last Amended: 2025-06-10 17:35 BST: Implemented IPv6 Fragment Header Logic recommendations.
 * - Enhanced `dect_cvg_receive_sdu_from_dlc` to include a stricter reassembly completion check, verifying `fragment_mask` contiguity and total length.
 * - Added more specific error logging for reassembly failures (malformed header, out-of-bounds index, missing fragments, length mismatch).
 * - Increment `cvg_reassembly_failures` stat for various reassembly errors, including timeouts.
 * - Updated `reassembly_timeout_handler` to log dropped length.
 * Last Amended: 2025-06-10 17:45 BST: Further refinements to IPv6 Fragment Header Logic and error logging.
 * - Corrected the potential bug in `dect_cvg_receive_sdu_from_dlc` where `frag_id` might be used before it's guaranteed to be available for early error logging. Removed `frag_id` from that specific early log.
 * - Adjusted logging for reassembly success/waiting for more fragments to be more concise.
 * - Added a final `LOG_WRN` and cleanup for sessions where the last fragment arrives but integrity checks fail.
 * - Ensured `STATS_INC(dect_stats.cvg_reassembly_failures)` is called consistently for all reassembly failures.
 * Last Amended: 2025-06-10 17:50 BST: Confirmed full implementation of IPv6 Fragment Header Logic recommendations. No further code changes.
 * Last Amended: 2025-06-10 19:15 BST: Implemented Robust IP-to-Short RD ID Resolution.
 * - Modified `dect_cvg_thread` (TX path) to use `dect_mac_lookup_ipv6_to_short_rd_id` to resolve IPv6 destination to Short RD ID.
 * - If routing is enabled and no direct map, a dummy Short RD ID is assigned for routing lookup (placeholder, needs full AODV integration with IP awareness).
 * - Modified `dect_cvg_receive_sdu_from_dlc` (RX path) to update the MAC's IPv6-to-Short RD ID map when a new IP packet is received from a peer.
 * - Updated `dect_cvg_receive_sdu_from_dlc` to pass `ROUTING_PDU_TYPE_DATA_FORWARD` to the routing layer.
 * - Integrated `dect_routing_send_data` into CVG TX path when routing is enabled.
 * Last Amended: 2025-06-10 20:20 BST: Implemented Robust DECT NR+ Native Routing in CVG.
 * - Updated `cvg_tx_queue_entry_t` instantiation to include `routing_mode = DECT_ROUTING_MODE_NONE`.
 * - Modified TX path in `dect_cvg_thread` to determine `routing_mode` based on `dest_short_rd_id` and device role (Uplink/Downlink/Horizontal).
 * - Removed the previous dummy Short RD ID assignment when no direct IP-to-RD ID map is found; now explicitly logs and drops if no direct map and no IP-based routing discovery mechanism is defined.
 * - Ensured `dect_routing_send_data` is called with the determined `routing_mode`.
 * - Confirmed `dect_cvg_receive_sdu_from_dlc` correctly handles `CVG_SERVICE_TYPE_CONTROL` for routing PDUs that have had their routing headers stripped by the routing layer.
 */
