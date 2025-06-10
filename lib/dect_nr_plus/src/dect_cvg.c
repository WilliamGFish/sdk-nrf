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
#include <dect_nr_plus/dect_cvg.h> /* Own header */
#include <dect_nr_plus/dect_stats.h> // For updating statistics
#include <dect_nr_plus/dect_power_mgr.h> // For power management awareness

#include <logging/log.h>
LOG_MODULE_REGISTER(dect_cvg, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

/* Global CVG context instance definition */
dect_cvg_context_t cvg_ctx = {
	.next_datagram_tag = 0, // Initialize to 0
};

/* Mutex to protect cvg_ctx */
K_MUTEX_DEFINE(cvg_ctx_mutex);

/* Net buffer pool for CVG transmit PDUs to DLC layer */
NET_BUF_POOL_DEFINE(cvg_tx_sdu_pool, CONFIG_DECT_NR_PLUS_CVG_TX_BUF_COUNT,
		    CONFIG_DECT_NR_PLUS_CVG_TX_BUF_SIZE, 0, NULL);

/* Message queue for transmitting net_pkt from network stack to CVG thread */
K_MSGQ_DEFINE(cvg_tx_net_pkt_msgq, sizeof(cvg_tx_sdu_entry_t),
	      CONFIG_DECT_NR_PLUS_CVG_TX_NET_PKT_QUEUE_SIZE, 4);

/* Message queue for receiving net_buf from DLC layer to CVG thread */
K_MSGQ_DEFINE(cvg_rx_msgq, sizeof(dlc_rx_msg_t),
	      CONFIG_DECT_NR_PLUS_CVG_RX_QUEUE_SIZE, 4);

/* Forward declarations for internal functions */
static dect_status_t cvg_fragment_sdu(struct net_pkt *pkt, qos_priority_t qos_priority);
static dect_status_t cvg_reassemble_sdu(cvg_rx_sdu_reassembly_t *session, struct net_buf *fragment_buf);
static int find_reassembly_session(uint16_t src_short_rd_id, uint16_t datagram_tag);
static int get_or_create_reassembly_session(uint16_t src_short_rd_id, uint16_t datagram_tag);
static void cvg_reassembly_timeout_handler(struct k_timer *timer_id);

/**
 * @brief Helper function to handle net_pkt allocation for TX path.
 *
 * This function attempts to allocate a net_pkt with a buffer.
 * If allocation fails, it logs an error and increments a statistic.
 *
 * @param net_if_ptr Pointer to the network interface.
 * @param size The size of the payload buffer to allocate.
 * @param out_pkt Pointer to a net_pkt pointer where the allocated packet will be stored.
 * @return DECT_STATUS_OK on success, DECT_ERROR_NO_MEM if allocation fails.
 */
static dect_status_t handle_tx_net_pkt_allocation(struct net_if *net_if_ptr, size_t size, struct net_pkt **out_pkt)
{
	*out_pkt = net_pkt_alloc_with_buffer(net_if_ptr, size, AF_INET6, IPPROTO_UDP, K_NO_WAIT); // Using UDP as typical for DECT NR+ data
	if (!(*out_pkt)) {
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "CVG: Failed to allocate net_pkt with buffer. No memory.");
		STATS_INC(dect_stats.tx_drops_no_mem); // Increment global stat for TX drops due to no memory
		return DECT_ERROR_NO_MEM;
	}
	return DECT_STATUS_OK;
}

dect_status_t dect_cvg_init(void)
{
	k_mutex_init(&cvg_ctx.mutex);
	k_timer_init(&cvg_ctx.reassembly_timeout_timer, cvg_reassembly_timeout_handler, NULL);
	// Start reassembly timeout timer, periodically checking for expired sessions
	k_timer_start(&cvg_ctx.reassembly_timeout_timer, K_SECONDS(1), K_SECONDS(1));

	// Initialize reassembly sessions
	for (int i = 0; i < MAX_PEERS; i++) {
		cvg_ctx.rx_reassembly_sessions[i].pkt = NULL;
		cvg_ctx.rx_reassembly_sessions[i].valid = false;
	}

	LOG_INF("CVG: Module initialized.");
	return DECT_STATUS_OK;
}

dect_status_t cvg_send_ipv6_pkt(struct net_pkt *pkt, qos_priority_t qos_priority)
{
	cvg_tx_sdu_entry_t tx_entry = {
		.pkt = pkt,
		.service_type = CVG_SERVICE_TYPE_DATA,
		.next_tx_time_ms = k_uptime_get(), // For scheduling within CVG if needed
	};

	LOG_DBG("CVG: Queuing IPv6 pkt (len %u) to DLC. Remaining data %u", net_pkt_get_len(pkt), net_pkt_remaining_len(pkt));

	// Put the net_pkt into the CVG TX message queue
	// The DLC layer will unref this net_pkt after processing, or on failure.
	int ret = DECT_MSGQ_PUT_OR_DROP(&cvg_tx_net_pkt_msgq, &tx_entry, K_NO_WAIT,
					DECT_ERROR_QUEUE_FULL,
					"CVG: TX net_pkt queue full. Dropping IPv6 packet.",
					NULL, &dect_stats.cvg_tx_drops); // dlc_tx_msg_t does not own net_buf directly, so NULL for buf_to_unref

	if (ret != 0) {
		// If queue is full, the net_pkt still needs to be unref'd by this layer
		net_pkt_unref(pkt);
		return DECT_ERROR_QUEUE_FULL;
	}

	return DECT_STATUS_OK;
}

static dect_status_t cvg_fragment_sdu(struct net_pkt *pkt, qos_priority_t qos_priority)
{
	uint16_t sdu_len = net_pkt_get_len(pkt);
	uint16_t max_frag_payload = CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE - MAC_HEADER_LEN_TYPE_2 - DLC_DATA_HDR_LEN_BYTES - DLC_CRC_LEN_BYTES - MAX_FRAGMENT_HDR_SIZE;
	uint8_t num_fragments = DIV_ROUND_UP(sdu_len, max_frag_payload);

	if (num_fragments > MAX_FRAGMENTS_PER_SDU) {
		DECT_ERROR_HANDLER(DECT_ERROR_PDU_TOO_LARGE, "CVG: SDU too large (%u bytes) to fragment. Max fragments %u.",
				   sdu_len, MAX_FRAGMENTS_PER_SDU);
		STATS_INC(dect_stats.cvg_frag_drops);
		net_pkt_unref(pkt); // Original pkt dropped
		return DECT_ERROR_PDU_TOO_LARGE;
	}

	k_mutex_lock(&cvg_ctx.mutex, K_FOREVER);
	uint16_t datagram_tag = cvg_ctx.next_datagram_tag++;
	k_mutex_unlock(&cvg_ctx.mutex);

	uint16_t offset = 0;
	for (uint8_t i = 0; i < num_fragments; i++) {
		uint16_t frag_len = MIN(sdu_len - offset, max_frag_payload);
		struct net_buf *fragment_buf = NULL;
		dect_status_t ret_alloc;

		// Allocate net_buf for each fragment
		ret_alloc = handle_tx_buffer_allocation(&fragment_buf, &cvg_tx_sdu_pool);
		if (ret_alloc != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(ret_alloc, "CVG: Failed to allocate net_buf for fragment %u/%u. Dropping SDU.", i + 1, num_fragments);
			// Clean up already allocated fragments if any, but in this simple example, just unref original pkt
			net_pkt_unref(pkt); // Original pkt dropped
			return ret_alloc;
		}

		// Add CVG fragmentation header
		net_buf_add_u8(fragment_buf, CVG_HEADER_TYPE_FRAGMENT);
		net_buf_add_le16(fragment_buf, datagram_tag);
		net_buf_add_u8(fragment_buf, (i << 4) | (num_fragments - 1)); // Fragment Offset (upper 4 bits) | Last Fragment (lower 4 bits)

		// Copy fragment payload from original net_pkt
		struct net_pkt_cursor cur;
		net_pkt_cursor_init(&cur, pkt);
		net_pkt_set_cursor(&cur, offset);
		net_pkt_read(&cur, net_buf_tail(fragment_buf), frag_len);
		net_buf_add(fragment_buf, frag_len);

		LOG_DBG("CVG: Sending fragment %u/%u (tag 0x%04x, offset %u, len %u)", i + 1, num_fragments, datagram_tag, offset, frag_len);

		// Pass fragment to DLC layer
		dlc_tx_msg_t dlc_tx_msg = {
			.dest_short_rd_id = net_pkt_peer_short_rd_id(pkt), // Assuming short_rd_id stored in pkt
			.dlc_pdu_buf = fragment_buf,
			.service_type = CVG_SERVICE_TYPE_DATA,
			.qos_priority = qos_priority
		};

		int ret_msgq = DECT_MSGQ_PUT_OR_DROP(&dlc_tx_msgq, &dlc_tx_msg, K_NO_WAIT,
						     DECT_ERROR_QUEUE_FULL,
						     "CVG: Failed to send fragment to DLC queue (full).",
						     fragment_buf, &dect_stats.cvg_tx_drops);
		if (ret_msgq != 0) {
			// Fragment already unref'd by macro
			net_pkt_unref(pkt); // Original pkt dropped
			return DECT_ERROR_QUEUE_FULL;
		}

		offset += frag_len;
	}

	net_pkt_unref(pkt); // Original pkt unref'd after all fragments are queued
	return DECT_STATUS_OK;
}

static dect_status_t cvg_reassemble_sdu(cvg_rx_sdu_reassembly_t *session, struct net_buf *fragment_buf)
{
	// This function receives a fragment_buf which has already passed initial checks
	// The fragment_buf contains the fragment header + payload.

	// Extract fragment header info (assuming already validated as fragment)
	uint8_t fragment_hdr_type = net_buf_pull_u8(fragment_buf); // Should be CVG_HEADER_TYPE_FRAGMENT
	uint16_t datagram_tag = net_buf_pull_le16(fragment_buf);
	uint8_t frag_info = net_buf_pull_u8(fragment_buf);
	uint8_t fragment_offset_idx = (frag_info >> 4); // Relative offset in units of max_frag_payload
	uint8_t last_fragment_idx = (frag_info & 0x0F); // Total number of fragments - 1

	if (session->pkt == NULL) {
		// First fragment for this session, allocate net_pkt to hold reassembled SDU
		// Need to allocate with enough headroom for IPv6 headers if 6LoWPAN is not enabled yet
		// For simplicity, let's assume worst case for now or rely on net_pkt_frag_add to extend.
		// A more robust solution would know the full SDU size from the first fragment.
		// Here, we allocate a net_pkt. The actual buffer comes with net_pkt_frag_add later.
		dect_status_t ret_pkt_alloc = handle_tx_net_pkt_allocation(mac_ctx.net_if_ptr, DECT_NR_PLUS_IPV6_MTU, &session->pkt); // Allocate with max MTU size buffer
		if (ret_pkt_alloc != DECT_STATUS_OK) {
			DECT_ERROR_HANDLER(ret_pkt_alloc, "CVG: Failed to allocate net_pkt for reassembly (tag 0x%04x). Dropping fragment.", datagram_tag);
			net_buf_unref(fragment_buf); // Drop current fragment
			STATS_INC(dect_stats.cvg_reassembly_drops);
			return ret_pkt_alloc;
		}
		// Initialize session metadata if this is the first fragment
		session->datagram_tag = datagram_tag;
		session->fragment_mask = 0;
		session->current_length = 0;
		session->datagram_size = 0; // Will be determined when last fragment is received or known
	}

	// Add fragment to the net_pkt. This will allocate a new fragment buffer and copy data.
	struct net_buf *new_frag_buf = net_pkt_frag_add(session->pkt, fragment_buf);
	if (!new_frag_buf) {
		DECT_ERROR_HANDLER(DECT_ERROR_NO_MEM, "CVG: Failed to add fragment to net_pkt. No buffer space.");
		net_buf_unref(fragment_buf); // Unref the incoming fragment_buf
		net_pkt_unref(session->pkt); // Unref the partially reassembled net_pkt
		session->pkt = NULL;
		session->valid = false;
		STATS_INC(dect_stats.cvg_reassembly_drops);
		return DECT_ERROR_NO_MEM;
	}
	// The original fragment_buf is now owned by net_pkt_frag_add if successful, no need to unref here.

	session->fragment_mask |= (1 << fragment_offset_idx);
	session->current_length += new_frag_buf->len; // Add the length of the fragment payload

	// If this is the last fragment, set the total size
	if (fragment_offset_idx == last_fragment_idx) {
		session->datagram_size = session->current_length; // Assuming contiguous fragments for total length calc
	}

	// Check if all fragments are received
	if (session->datagram_size > 0 && session->current_length == session->datagram_size &&
	    session->fragment_mask == ((1 << (last_fragment_idx + 1)) - 1)) { // All bits set
		LOG_DBG("CVG: SDU reassembled (tag 0x%04x, len %u). Passing to network stack.",
			session->datagram_tag, session->datagram_size);

		// If 6LoWPAN compression is enabled, uncompress the IPv6 header
#ifdef CONFIG_NET_6LO
		if (dect_config.enable_6lowpan_compression) {
			if (net_6lo_uncompress(session->pkt) < 0) {
				DECT_ERROR_HANDLER(DECT_ERROR_CVG_BAD_HEADER, "CVG: 6LoWPAN uncompression failed. Dropping reassembled SDU.");
				net_pkt_unref(session->pkt);
				session->pkt = NULL;
				session->valid = false;
				STATS_INC(dect_stats.cvg_rx_drops);
				return DECT_ERROR_CVG_BAD_HEADER;
			}
			LOG_DBG("CVG: 6LoWPAN uncompression successful.");
		}
#endif

		// Pass the reassembled net_pkt to the Zephyr network stack
		if (net_recv_data(session->pkt) < 0) {
			DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG: Failed to pass reassembled SDU to network stack. Dropping.");
			net_pkt_unref(session->pkt); // Net stack takes ownership or unrefs
			session->pkt = NULL;
			session->valid = false;
			STATS_INC(dect_stats.cvg_rx_drops);
			return DECT_ERROR_GENERIC;
		}

		// Reset session
		session->pkt = NULL;
		session->valid = false;
	}

	return DECT_STATUS_OK;
}


void dect_cvg_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("CVG: Thread started.");

	cvg_tx_sdu_entry_t tx_entry;
	dlc_rx_msg_t rx_msg;

	while (true) {
		// Process outgoing application data from network stack
		if (k_msgq_get(&cvg_tx_net_pkt_msgq, &tx_entry, K_NO_WAIT) == 0) {
			struct net_pkt *pkt = tx_entry.pkt;
			qos_priority_t qos_priority = tx_entry.qos_priority;

			if (net_pkt_get_len(pkt) > (CONFIG_DECT_NR_PLUS_MAC_TX_BUF_SIZE - MAC_HEADER_LEN_TYPE_2 - DLC_DATA_HDR_LEN_BYTES - DLC_CRC_LEN_BYTES - MAX_FRAGMENT_HDR_SIZE)) {
				// SDU needs fragmentation
				LOG_DBG("CVG: SDU length %u requires fragmentation.", net_pkt_get_len(pkt));
				cvg_fragment_sdu(pkt, qos_priority); // This function unrefs pkt
			} else {
				// SDU does not need fragmentation
				struct net_buf *dlc_pdu_buf;
				dect_status_t ret_alloc = handle_tx_buffer_allocation(&dlc_pdu_buf, &cvg_tx_sdu_pool);
				if (ret_alloc != DECT_STATUS_OK) {
					DECT_ERROR_HANDLER(ret_alloc, "CVG: Failed to allocate net_buf for unfragmented SDU. Dropping.");
					net_pkt_unref(pkt); // Original pkt dropped
					return; // Or continue
				}

				// Copy IPv6 packet payload to DLC PDU buffer
				// If 6LoWPAN compression is enabled, compress the IPv6 header
#ifdef CONFIG_NET_6LO
				if (dect_config.enable_6lowpan_compression) {
					int ret_compress = net_6lo_compress(pkt, dlc_pdu_buf);
					if (ret_compress < 0) {
						DECT_ERROR_HANDLER(DECT_ERROR_CVG_BAD_HEADER, "CVG: 6LoWPAN compression failed. Dropping SDU.");
						net_pkt_unref(pkt);
						net_buf_unref(dlc_pdu_buf);
						STATS_INC(dect_stats.cvg_tx_drops);
						continue;
					}
					LOG_DBG("CVG: 6LoWPAN compression successful, compressed len %u.", dlc_pdu_buf->len);
				} else
#endif
				{
					// No compression, just copy raw IPv6 payload
					struct net_pkt_cursor cur;
					net_pkt_cursor_init(&cur, pkt);
					net_pkt_read(&cur, net_buf_tail(dlc_pdu_buf), net_pkt_get_len(pkt));
					net_buf_add(dlc_pdu_buf, net_pkt_get_len(pkt));
				}
				net_pkt_unref(pkt); // Original pkt unref'd after copying/compression

				LOG_DBG("CVG: Sending unfragmented SDU (len %u) to DLC.", dlc_pdu_buf->len);

				// Pass the SDU to DLC layer
				dlc_tx_msg_t dlc_tx_msg = {
					.dest_short_rd_id = net_pkt_peer_short_rd_id(pkt), // Assuming short_rd_id stored in pkt
					.dlc_pdu_buf = dlc_pdu_buf,
					.service_type = CVG_SERVICE_TYPE_DATA,
					.qos_priority = qos_priority
				};
				int ret_msgq = DECT_MSGQ_PUT_OR_DROP(&dlc_tx_msgq, &dlc_tx_msg, K_NO_WAIT,
							     DECT_ERROR_QUEUE_FULL,
							     "CVG: Failed to send unfragmented SDU to DLC queue (full).",
							     dlc_pdu_buf, &dect_stats.cvg_tx_drops);
				if (ret_msgq != 0) {
					// dlc_pdu_buf unref'd by macro
					continue;
				}
			}
			dect_power_mgr_activity_detected(); // Notify power manager of TX activity
		}

		// Process incoming data from DLC layer
		if (k_msgq_get(&cvg_rx_msgq, &rx_msg, K_NO_WAIT) == 0) {
			LOG_DBG("CVG: Received data from DLC (src 0x%04x, len %u, PDU type %u).",
				rx_msg.src_short_rd_id, rx_msg.dlc_pdu_buf->len, rx_msg.dlc_pdu_type);
			dect_power_mgr_activity_detected(); // Notify power manager of RX activity

			if (rx_msg.dlc_pdu_type == DLC_PDU_TYPE_DATA) {
				struct net_buf *data_buf = rx_msg.dlc_pdu_buf;
				uint8_t cvg_hdr_type = net_buf_peek_u8(data_buf);

				if (cvg_hdr_type == CVG_HEADER_TYPE_FRAGMENT) {
					// Handle fragmented SDU
					uint16_t datagram_tag = sys_get_le16(&data_buf->data[1]); // Peek tag
					int session_idx = get_or_create_reassembly_session(rx_msg.src_short_rd_id, datagram_tag);
					if (session_idx < 0) {
						DECT_ERROR_HANDLER(DECT_ERROR_NO_RESOURCES, "CVG: No reassembly session available for src 0x%04x, tag 0x%04x. Dropping fragment.",
								   rx_msg.src_short_rd_id, datagram_tag);
						net_buf_unref(data_buf);
						STATS_INC(dect_stats.cvg_reassembly_drops);
						continue;
					}
					cvg_reassemble_sdu(&cvg_ctx.rx_reassembly_sessions[session_idx], data_buf); // This function unrefs data_buf
				} else {
					// Handle unfragmented SDU (e.g., direct IPv6 packet)
					struct net_pkt *pkt = NULL;
					dect_status_t ret_pkt_alloc = handle_tx_net_pkt_allocation(mac_ctx.net_if_ptr, data_buf->len, &pkt);
					if (ret_pkt_alloc != DECT_STATUS_OK) {
						DECT_ERROR_HANDLER(ret_pkt_alloc, "CVG: Failed to allocate net_pkt for unfragmented RX SDU. Dropping.");
						net_buf_unref(data_buf);
						STATS_INC(dect_stats.rx_drops_no_mem);
						continue;
					}

					// Copy data to net_pkt
					if (net_pkt_write(pkt, data_buf->data, data_buf->len)) {
						DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG: Failed to write data to net_pkt for unfragmented SDU. Dropping.");
						net_pkt_unref(pkt);
						net_buf_unref(data_buf);
						STATS_INC(dect_stats.cvg_rx_drops);
						continue;
					}
					net_buf_unref(data_buf); // Data copied, unref original buffer

					// If 6LoWPAN compression is enabled, uncompress the IPv6 header
#ifdef CONFIG_NET_6LO
					if (dect_config.enable_6lowpan_compression) {
						if (net_6lo_uncompress(pkt) < 0) {
							DECT_ERROR_HANDLER(DECT_ERROR_CVG_BAD_HEADER, "CVG: 6LoWPAN uncompression failed. Dropping SDU.");
							net_pkt_unref(pkt);
							STATS_INC(dect_stats.cvg_rx_drops);
							continue;
						}
						LOG_DBG("CVG: 6LoWPAN uncompression successful.");
					}
#endif

					// Pass to network stack
					if (net_recv_data(pkt) < 0) {
						DECT_ERROR_HANDLER(DECT_ERROR_GENERIC, "CVG: Failed to pass unfragmented SDU to network stack. Dropping.");
						net_pkt_unref(pkt); // Net stack takes ownership or unrefs
						STATS_INC(dect_stats.cvg_rx_drops);
						continue;
					}
				}
			} else {
				// Handle other DLC PDU types if CVG needs to process them (e.g., Mobility control)
				LOG_DBG("CVG: Received non-data DLC PDU type %u. Discarding for now.", rx_msg.dlc_pdu_type);
				net_buf_unref(rx_msg.dlc_pdu_buf); // Unref buffer as it's not processed
				STATS_INC(dect_stats.cvg_rx_drops);
			}
		}

		k_sleep(K_MSEC(10)); // Small sleep to yield CPU
	}
}

/* Zephyr L2 Network Interface Implementation */

static enum net_l2_flags dect_nr_plus_get_flags(struct net_if *iface)
{
	ARG_UNUSED(iface);
	return NET_L2_MULTICAST | NET_L2_POINT_TO_POINT;
}

static void dect_nr_plus_iface_init(struct net_if *iface)
{
	LOG_DBG("DECT NR+ L2: Interface %p initialized.", iface);

	// Store the net_if pointer in MAC context for carrier control
	mac_ctx.net_if_ptr = iface;

	// Set the link address (Long RD ID / MAC address)
	net_if_set_link_addr(iface, dect_config.mac_address, LONG_RD_ID_LEN_BYTES,
			     NET_L2_GET_CTX_TYPE(dect_nr_plus_l2_api, iface));

	// Set MTU for IPv6 (e.g., 1280 for 6LoWPAN)
	net_if_set_mtu(iface, DECT_NR_PLUS_IPV6_MTU);

	// Initially carrier is off, will be turned on when MAC is associated
	net_if_carrier_off(iface);
}

static int dect_nr_plus_iface_send(struct net_if *iface, struct net_pkt *pkt)
{
	ARG_UNUSED(iface);

	if (net_pkt_family(pkt) != AF_INET6) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_PARAM, "CVG: Only IPv6 packets supported. Dropping.");
		net_pkt_unref(pkt);
		STATS_INC(dect_stats.cvg_tx_drops);
		return -ENOTSUP;
	}

	if (!net_if_is_carrier_on(iface)) {
		DECT_ERROR_HANDLER(DECT_ERROR_INVALID_STATE, "CVG: Network carrier is off. Dropping packet.");
		net_pkt_unref(pkt);
		STATS_INC(dect_stats.cvg_tx_drops);
		return -EAGAIN; // Try again later
	}

	// Assuming peer_short_rd_id is already set in the net_pkt if it's not a broadcast
	// For simplicity, this example doesn't dynamically discover peer Short RD IDs.
	// In a real application, this might involve routing lookups or peer management.
	if (net_pkt_peer_short_rd_id(pkt) == 0) { // If short_rd_id is not set, assume broadcast for now
		net_pkt_set_peer_short_rd_id(pkt, SHORT_RD_ID_BROADCAST);
	}

	// Pass the IPv6 packet to the CVG layer for fragmentation/compression and transmission
	dect_status_t status = cvg_send_ipv6_pkt(pkt, QOS_PRIORITY_NORMAL); // Use normal QoS for app data
	if (status != DECT_STATUS_OK) {
		// cvg_send_ipv6_pkt already unrefs pkt and logs error
		return -EIO;
	}

	return 0; // Success
}

static int find_reassembly_session(uint16_t src_short_rd_id, uint16_t datagram_tag)
{
	k_mutex_lock(&cvg_ctx.mutex, K_FOREVER);
	for (int i = 0; i < MAX_PEERS; i++) {
		if (cvg_ctx.rx_reassembly_sessions[i].valid &&
		    cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id == src_short_rd_id &&
		    cvg_ctx.rx_reassembly_sessions[i].datagram_tag == datagram_tag) {
			k_mutex_unlock(&cvg_ctx.mutex);
			return i;
		}
	}
	k_mutex_unlock(&cvg_ctx.mutex);
	return -1; // Not found
}

static int get_or_create_reassembly_session(uint16_t src_short_rd_id, uint16_t datagram_tag)
{
	k_mutex_lock(&cvg_ctx.mutex, K_FOREVER);
	int session_idx = find_reassembly_session(src_short_rd_id, datagram_tag);

	if (session_idx != -1) {
		k_mutex_unlock(&cvg_ctx.mutex);
		return session_idx;
	}

	// Try to find a free session
	for (int i = 0; i < MAX_PEERS; i++) {
		if (!cvg_ctx.rx_reassembly_sessions[i].valid) {
			cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id = src_short_rd_id;
			cvg_ctx.rx_reassembly_sessions[i].datagram_tag = datagram_tag;
			cvg_ctx.rx_reassembly_sessions[i].pkt = NULL; // Will be allocated on first fragment
			cvg_ctx.rx_reassembly_sessions[i].fragment_mask = 0;
			cvg_ctx.rx_reassembly_sessions[i].current_length = 0;
			cvg_ctx.rx_reassembly_sessions[i].datagram_size = 0;
			cvg_ctx.rx_reassembly_sessions[i].last_rx_time_ms = k_uptime_get();
			cvg_ctx.rx_reassembly_sessions[i].valid = true;
			LOG_DBG("CVG: Created new reassembly session %d for src 0x%04x, tag 0x%04x.",
				i, src_short_rd_id, datagram_tag);
			k_mutex_unlock(&cvg_ctx.mutex);
			return i;
		}
	}

	LOG_WRN("CVG: No free reassembly sessions available.");
	k_mutex_unlock(&cvg_ctx.mutex);
	return -1; // No free session
}

static void cvg_reassembly_timeout_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_mutex_lock(&cvg_ctx.mutex, K_FOREVER);
	uint64_t current_time = k_uptime_get();

	for (int i = 0; i < MAX_PEERS; i++) {
		if (cvg_ctx.rx_reassembly_sessions[i].valid &&
		    (current_time - cvg_ctx.rx_reassembly_sessions[i].last_rx_time_ms) > CVG_REASSEMBLY_TIMEOUT_MS) {
			LOG_WRN("CVG: Reassembly session for src 0x%04x, tag 0x%04x timed out. Dropping incomplete SDU.",
				cvg_ctx.rx_reassembly_sessions[i].src_short_rd_id,
				cvg_ctx.rx_reassembly_sessions[i].datagram_tag);

			if (cvg_ctx.rx_reassembly_sessions[i].pkt) {
				net_pkt_unref(cvg_ctx.rx_reassembly_sessions[i].pkt);
			}
			cvg_ctx.rx_reassembly_sessions[i].pkt = NULL;
			cvg_ctx.rx_reassembly_sessions[i].valid = false;
			STATS_INC(dect_stats.cvg_reassembly_drops); // Increment specific reassembly drop stat
		}
	}
	k_mutex_unlock(&cvg_ctx.mutex);
}

// Zephyr L2 API definition
NET_L2_INIT(dect_nr_plus_l2_api, dect_nr_plus_get_flags, dect_nr_plus_iface_init,
	    dect_nr_plus_iface_send, NULL, NULL, NULL);


bool dect_nr_plus_iface_iid_cb(struct net_if *iface, struct in6_addr *iid)
{
	// Example EUI-64 generation from MAC address (Long RD ID)
	// This is a common method for IPv6 Stateless Address Autoconfiguration (SLAAC).
	// The MAC address is 4 bytes (Long RD ID). EUI-64 is 8 bytes.
	// A common transformation: MAC becomes EUI-48, then FFFE is inserted.
	// For a 4-byte MAC, we'll need to define how it maps to a 64-bit IID.
	// A simplified approach for DECT-NR+ might just use the Long RD ID directly or extended.

	// Assuming dect_config.mac_address is the 4-byte Long RD ID
	// Example: Pad with zeros or specific pattern to make it 8 bytes, then flip U/L bit
	// This is a placeholder and needs to conform to actual DECT NR+ IID derivation if specified.
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

/* End of File
 * Last Amended: 2025-06-09 17:55 BST: Updated dect_cvg.c for robust error handling.
 * - Added `handle_tx_net_pkt_allocation` for `net_pkt` allocation with stat updates.
 * - Integrated `DECT_MSGQ_PUT_OR_DROP` macro for `cvg_tx_net_pkt_msgq` and `dlc_tx_msgq` puts.
 * - Enhanced error paths for `net_buf_alloc`, `net_pkt_frag_add`, `net_pkt_write`, `net_6lo_compress/uncompress` with `DECT_ERROR_HANDLER` and stat increments (`cvg_tx_drops`, `cvg_rx_drops`, `cvg_frag_drops`, `cvg_reassembly_drops`).
 * - Ensured `net_pkt_unref` for dropped packets.
 * - Updated `cvg_reassembly_timeout_handler` to increment `cvg_reassembly_drops` and `net_pkt_unref` timed-out sessions.
 */
