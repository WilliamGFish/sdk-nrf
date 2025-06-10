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
	STATS_INC(dect_stats.cvg_reassembly_failures); // Placeholder for initial count
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

	// Check if the received PDU is an IPv6 fragment
	// This check relies on the IP header (or IPv6 Fragmentation Header) being at the start of the DLC payload.
	// We need enough bytes to peek at the Next Header field and potentially the Fragmentation Header.
	uint8_t *dlc_payload_ptr = net_buf_pull_unaligned_mem(dlc_pdu_buf, dlc_pdu_buf->len);
	uint8_t next_hdr_val = 0xFF; // Default to unknown

	if (dlc_pdu_buf->len >= (NET_IPV6_HDR_LEN + IPV6_FRAG_HDR_LEN)) {
		// Case 1: Full IPv6 header + Fragmentation header
		// Peek the Next Header field (offset 6 in IPv6 header)
		next_hdr_val = dlc_payload_ptr[6];
	} else if (dlc_pdu_buf->len >= IPV6_FRAG_HDR_LEN) {
		// Case 2: Only Fragmentation header (e.g., after 6LoWPAN decompression or subsequent fragment)
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
			DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PDU_TYPE, "CVG RX: Detected IPPROTO_FRAGMENT but header malformed. Dropping.");
			net_buf_unref(dlc_pdu_buf);
			STATS_INC(dect_stats.cvg_reassembly_drops);
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
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_REASSEMBLY_DROPS, "CVG RX: No reassembly session available for ID %08x (src 0x%04x).", frag_id, src_short_rd_id);
				net_buf_unref(dlc_pdu_buf); // Drop fragment
				status = DECT_ERROR_NO_RESOURCES;
				goto exit_mutex_unlock;
			}
		}

		// Check for duplicate or out-of-bounds fragment (simple check based on mask)
		uint8_t fragment_idx = (uint8_t)frag_offset_units; // Index based on 8-octet units offset
		if (fragment_idx >= CONFIG_DECT_NR_PLUS_CVG_REASSEMBLY_MAX_FRAGMENTS || // Use Kconfig define
			(session->fragment_mask & (1U << fragment_idx))) {
			LOG_DBG("CVG RX: Duplicate or out-of-bounds fragment %u (ID %08x). Dropping.", fragment_idx, frag_id);
			net_buf_unref(dlc_pdu_buf); // Drop fragment
			status = DECT_ERROR_INVALID_PARAM; // Or specific reassembly error
			goto exit_mutex_unlock;
		}

		// Pull the fragmentation header before appending to net_pkt
		net_buf_pull(dlc_pdu_buf, IPV6_FRAG_HDR_LEN);

		if (!session->pkt) {
			// This is the first fragment received for this session.
			// Allocate the initial net_pkt and attach the fragment's net_buf.
			// The original IPv6 header is expected to be part of the first fragment.
			session->pkt = net_pkt_rx_alloc_with_buffer(cvg_ctx.net_if_ptr, dlc_pdu_buf->len, AF_UNSPEC, 0, K_NO_WAIT);
			if (!session->pkt) {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_NO_MEM, "CVG RX: Failed to allocate net_pkt for reassembly (ID %08x).", frag_id);
				net_buf_unref(dlc_pdu_buf);
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

		// If this is the last fragment, we now know the total length
		if (!more_fragments_flag) {
			// The total length of the original SDU is now known from the last fragment's offset + its length
			session->datagram_size = (frag_offset_units * 8) + dlc_pdu_buf->len; // frag_offset_units * 8 to get bytes
			LOG_DBG("CVG RX: Last fragment received, total datagram size: %u.", session->datagram_size);
		}

		// Check if all fragments received (basic check: mask has all bits set up to last_fragment_idx)
		// A more robust check would involve iterating the mask and ensuring no gaps
		// and that the total length matches the sum of fragment lengths.
		bool all_fragments_received = (!more_fragments_flag && session->datagram_size > 0 &&
											   (session->current_length >= session->datagram_size));


		if (all_fragments_received) {
			LOG_DBG("CVG RX: All fragments for ID %08x reassembled. Total length %zu.", frag_id, session->current_length);
			// Pass reassembled packet to IP stack
			status = net_recv_data(session->pkt);
			if (status != 0) {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_REASSEMBLY_DROPS, "CVG RX: Failed to pass reassembled pkt to IP stack (ret: %d).", status);
				net_pkt_unref(session->pkt);
				STATS_INC(dect_stats.cvg_reassembly_failures);
			} else {
				LOG_DBG("CVG RX: Reassembled pkt (len %zu) passed to IP stack.", net_pkt_get_len(session->pkt));
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
		} else {
			LOG_DBG("CVG RX: Fragment %u (ID %08x) received, waiting for more. Mask: 0x%x, Current len: %zu.",
					fragment_idx, frag_id, session->fragment_mask, session->current_length);
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
				(control_pdu_ptr[0] == ROUTING_PDU_TYPE_RREQ ||
				 control_pdu_ptr[0] == ROUTING_PDU_TYPE_RREP ||
				 control_pdu_ptr[0] == ROUTING_PDU_TYPE_RERR)) {
				LOG_DBG("CVG RX: Identified as Routing PDU. Passing to Routing layer.");
				dect_status_t routing_status = dect_routing_process_incoming_pdu(src_short_rd_id, dlc_pdu_buf, hpc, psn);
				if (routing_status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(routing_status, "CVG RX: Failed to pass Routing PDU to Routing layer.");
					net_buf_unref(dlc_pdu_buf);
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

			if (!pkt) {
				DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CVG TX: Received NULL net_pkt from queue.");
				STATS_INC(dect_stats.cvg_tx_drops);
				continue;
			}

			size_t original_pkt_len = net_pkt_get_len(pkt);
			STATS_ADD(dect_stats.tx_app_data_bytes, original_pkt_len);

			// Determine actual destination Short RD ID if it's still BROADCAST (from L2 send)
			if (dest_short_rd_id == SHORT_RD_ID_BROADCAST) {
				if (net_ipv6_is_addr_multicast(net_pkt_ipv6_dst(pkt))) {
					dest_short_rd_id = SHORT_RD_ID_BROADCAST;
					LOG_DBG("CVG TX: Identified IPv6 multicast/broadcast, using DECT broadcast.");
				} else if (dect_config.enable_routing) {
					LOG_DBG("CVG TX: Routing enabled, attempting route lookup for unicast destination.");
					// Placeholder for actual route lookup.
					// For now, simple toggle if no specific routing implemented yet.
					dest_short_rd_id = dect_config.short_rd_id == 0x0001 ? 0x0002 : 0x0001;
				} else {
					LOG_DBG("CVG TX: Routing disabled, assuming direct unicast to specified dest.");
					// Placeholder for IP-to-DECT-ID mapping.
					dest_short_rd_id = dect_config.short_rd_id == 0x0001 ? 0x0002 : 0x0001;
				}
			}

			size_t max_dlc_payload_size = CONFIG_DECT_NR_PLUS_MAX_DLC_PDU_SIZE - DLC_DATA_HDR_LEN_BYTES - DLC_CRC_LEN_BYTES;

			if (original_pkt_len > max_dlc_payload_size) {
				LOG_DBG("CVG TX: Packet too large (%zu bytes). Fragmenting...", original_pkt_len);
				STATS_INC(dect_stats.cvg_frag_tx);

				uint32_t fragment_id = sys_rand32_get();
				size_t current_offset = 0;
				bool more_fragments = true;
				uint8_t fragment_idx = 0;

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

					net_buf_add_u8(dlc_pdu_buf, net_pkt_ipv6_next_hdr(pkt));
					net_buf_add_u8(dlc_pdu_buf, 0); // Reserved

					uint16_t frag_offset_and_m = (current_offset / 8) << 3;
					if (more_fragments) {
						frag_offset_and_m |= IPV6_FRAG_M_FLAG_MASK;
					}
					net_buf_add_be16(dlc_pdu_buf, frag_offset_and_m);

					net_buf_add_be32(dlc_pdu_buf, fragment_id);

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

					status = dect_dlc_send_data_from_cvg(dest_short_rd_id, dlc_pdu_buf, CVG_SERVICE_TYPE_DATA, qos_priority);
					if (status != DECT_STATUS_OK) {
						DECT_ERROR_HANDLER(status, "CVG TX: Failed to send fragment to DLC.");
						net_buf_unref(dlc_pdu_buf);
						STATS_INC(dect_stats.cvg_tx_drops);
						STATS_INC(dect_stats.cvg_frag_drops);
						net_pkt_unref(pkt);
						break;
					}

					current_offset += current_frag_len;
					fragment_idx++;
				}
				net_pkt_unref(pkt);

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

				status = dect_dlc_send_data_from_cvg(dest_short_rd_id, dlc_pdu_buf, CVG_SERVICE_TYPE_DATA, qos_priority);
				if (status != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(status, "CVG TX: Failed to send non-fragmented packet to DLC.");
					net_buf_unref(dlc_pdu_buf);
					STATS_INC(dect_stats.cvg_tx_drops);
				}
				net_pkt_unref(pkt);
			}
			dect_power_mgr_activity_detected();
		}

		/* Process RX messages */
		if (k_msgq_get(&cvg_rx_msgq, &rx_msg, K_NO_WAIT) == 0) {
			had_activity_this_loop = true;

			LOG_DBG("CVG RX: Received message from DLC (src 0x%04x, len %u, type %u).",
					rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf->len, rx_msg.dlc_pdu_type);

			// Now call the main SDU processing function in CVG
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
				LOG_WRN("CVG RX: Reassembly session for ID %08x (src 0x%04x) timed out. Dropping fragments.",
						cvg_ctx.rx_reassembly_sessions[i].datagram_tag,
						cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id);
				net_pkt_unref(cvg_ctx.rx_reassembly_sessions[i].pkt);
				cvg_ctx.rx_reassembly_sessions[i].pkt = NULL;
				cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id = 0; // Mark as free
				cvg_ctx.rx_reassembly_sessions[i].datagram_tag = 0;
				cvg_ctx.rx_reassembly_sessions[i].current_length = 0;
				cvg_ctx.rx_reassembly_sessions[i].fragment_mask = 0;
				cvg_ctx.rx_reassembly_sessions[i].last_rx_time_ms = 0;
				STATS_INC(dect_stats.cvg_reassembly_failures);
				STATS_INC(dect_stats.cvg_reassembly_drops);
			}
		}
	}
	k_mutex_unlock(&cvg_ctx.mutex);
}

/* Combined CVG Thread definition */
K_THREAD_DEFINE(dect_cvg_thread_id,
				CONFIG_DECT_NR_PLUS_CVG_TX_STACK_SIZE + CONFIG_DECT_NR_PLUS_CVG_RX_STACK_SIZE, // Sum of TX and RX stack sizes
				dect_cvg_thread, NULL, NULL, NULL,
				CONFIG_DECT_NR_PLUS_CVG_THREAD_PRIORITY, 0, K_FOREVER);

