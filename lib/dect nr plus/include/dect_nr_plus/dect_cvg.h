/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_CVG_H__
#define DECT_CVG_H__

#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h>
#include <net/net_pkt.h> // For struct net_pkt
#include <net/net_l2.h> // For NET_L2_GET_CTX, net_l2_cb
#include <net/net_if.h> // For struct net_if
#include <net/ipv6.h> // For struct in6_addr

#ifdef CONFIG_NET_6LO // Include 6LoWPAN headers if enabled
#include <net/net_6lo.h>
#endif

#include <dect_nr_plus/dect_errors.h>
#include <dect_nr_plus/dect_types.h> // For dect_cvg_context_t, cvg_service_type_t, etc.

/**
 * @brief Global CVG context instance.
 * Defined in dect_cvg.c.
 */
extern dect_cvg_context_t cvg_ctx;

/* Net buffer pool for CVG transmit PDUs */
NET_BUF_POOL_PROTOTYPE(cvg_tx_net_buf_pool, 10, 256, 0, NULL); // Example: 10 buffers, max 256 bytes

/* Message queues for inter-layer communication for net_pkt */
extern struct k_msgq cvg_tx_net_pkt_msgq; // From network stack to CVG

/**
 * @brief Message structure for data received from DLC to CVG.
 */
typedef struct {
	struct net_buf *data_buf; /**< Pointer to the net_buf containing the DLC payload. */
	uint16_t src_short_rd_id; /**< Short RD ID of the source. */
	cvg_service_type_t service_type; /**< Service type of the PDU. */
	bool encrypted; /**< True if the PDU was encrypted. */
	uint32_t current_hpc; /**< HPC value at receive. */
	uint16_t current_psn; /**< PSN value at receive. */
} cvg_rx_msg_t;

extern struct k_msgq cvg_rx_msgq; // From DLC to CVG

/**
 * @brief CVG context structure.
 */
typedef struct {
	uint32_t next_tx_frag_id; /**< Next fragmentation ID to use for outgoing PDUs. */
	struct k_timer reassembly_timer; /**< Timer for SDU reassembly timeout. */
	K_MUTEX_DEFINE(mutex); /**< Mutex to protect context access. */
	struct cvg_tx_sdu_entry_t {
		struct net_pkt *pkt;
		uint11_t frag_id;
		uint8_t total_fragments;
		uint8_t transmitted_fragments;
		uint8_t current_fragment_idx;
		struct k_timer tx_timer;
		uint32_t next_tx_time_ms; // For delaying next fragment TX
	} tx_sdu_pending[CONFIG_DECT_NR_PLUS_MAX_PENDING_TX_SDUS];
	uint8_t num_tx_sdu_pending;

	struct cvg_rx_sdu_reassembly_t {
		struct net_pkt *pkt; // The reassembled net_pkt (or first fragment)
		uint11_t frag_id;
		uint8_t expected_total_fragments;
		uint8_t received_fragment_mask; // Bitmask of received fragments
		struct k_timer reassembly_timeout_timer;
		uint16_t src_short_rd_id;
		uint32_t first_hpc; // HPC of the first fragment for reassembly consistency
	} rx_sdu_active[CONFIG_DECT_NR_PLUS_MAX_REASSEMBLY_SDUS];
	uint8_t num_rx_sdu_active;
} dect_cvg_context_t;

/**
 * @brief Initializes the Convergence (CVG) layer.
 * Sets up message queues, timers, and internal state.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dect_cvg_init(void);

/**
 * @brief Sends an IPv6 packet from the network stack to the CVG layer for transmission.
 * This function handles queuing the net_pkt for the CVG thread to process.
 *
 * @param pkt Pointer to the net_pkt to send. The CVG layer takes ownership.
 * @return 0 on success, or a negative error code.
 */
int cvg_send_ipv6_pkt(struct net_pkt *pkt);

/**
 * @brief Receives data from the DLC layer and processes it in the CVG layer.
 * This function performs reassembly and passes complete SDUs to the network stack.
 *
 * @param data_buf Pointer to the net_buf containing the DLC payload.
 * @param src_short_rd_id The Short RD ID of the source.
 * @param service_type The service type of the PDU.
 * @param encrypted True if the PDU was encrypted.
 * @param current_hpc Current HPC of the received frame.
 * @param current_psn Current PSN of the received frame.
 * @return DECT_STATUS_OK on success, or an error code.
 */
dect_status_t dlc_cvg_receive_data(struct net_buf *data_buf,
								   uint16_t src_short_rd_id,
								   cvg_service_type_t service_type,
								   bool encrypted,
								   uint32_t current_hpc,
								   uint16_t current_psn);

/**
 * @brief Timer handler for SDU reassembly timeout.
 * This function is called when a reassembly timer expires, indicating a
 * fragmented SDU was not fully received. It frees resources and logs the event.
 *
 * @param timer_id Pointer to the k_timer that expired.
 */
void cvg_reassembly_timeout_handler(struct k_timer *timer_id);

/**
 * @brief Thread entry point for the Convergence layer.
 *
 * This thread is responsible for processing incoming messages from the DLC
 * layer (for reassembly) and outgoing messages from the network interface
 * (for fragmentation and transmission).
 *
 * @param p1 Unused.
 * @param p2 Unused.
 * @param p3 Unused.
 */
void dect_cvg_thread(void *p1, void *p2, void *p3);


/**
 * @brief Initializes the DECT NR+ L2 network interface.
 * This function is called by the Zephyr network stack during interface setup.
 *
 * @param iface Pointer to the network interface being initialized.
 * @return 0 on success, or a negative error code.
 */
int dect_nr_plus_iface_init(struct net_if *iface);

/**
 * @brief Get the DECT NR+ L2 network interface API.
 * This macro defines the Zephyr L2 API for our DECT NR+ driver.
 */
extern const struct net_l2_init dect_nr_plus_l2_api;

/**
 * @brief Custom IPv6 IID generation callback for DECT NR+.
 * Derives the EUI-64 compliant Interface Identifier from the Long RD ID.
 *
 * @param iface Pointer to the network interface.
 * @param iid Pointer to the in6_addr structure to store the generated IID.
 * @return True if IID was generated successfully, false otherwise.
 */
bool dect_nr_plus_iface_iid_cb(struct net_if *iface, struct in6_addr *iid);


#endif /* DECT_CVG_H__ */

/* End of File
 * Last Amended: 2025-06-05 13:00 BST: Updated dect_cvg.h for 6LoWPAN integration and L2 API.
 * - Added `CONFIG_NET_6LO` includes and definitions.
 * - Defined `cvg_tx_net_pkt_msgq` for `net_pkt`s from the network stack.
 * - Updated `cvg_tx_sdu_entry_t` with `pkt` and `next_tx_time_ms`.
 * - Updated `cvg_rx_sdu_reassembly_t` with `pkt` and `first_hpc`.
 * - Updated `dect_cvg_init` to reference `cvg_tx_net_pkt_msgq`.
 * - Updated `cvg_send_ipv6_pkt` to take `net_pkt` and queue it.
 * - Added `dect_nr_plus_iface_init` and `dect_nr_plus_l2_api` for Zephyr L2 integration.
 * - Added `dect_nr_plus_iface_iid_cb` for custom IPv6 IID generation.
 */


/* End of File
 * Last Amended: 2025-06-05 13:00 BST: Updated dect_cvg.h for 6LoWPAN integration and L2 API.
 * - Added `CONFIG_NET_6LO` includes and definitions.
 * - Defined `cvg_tx_net_pkt_msgq` for `net_pkt`s from the network stack.
 * - Updated `cvg_tx_sdu_entry_t` with `pkt` and `next_tx_time_ms`.
 * - Updated `cvg_rx_sdu_reassembly_t` with `pkt` and `first_hpc`.
 * - Updated `dect_cvg_init` to reference `cvg_tx_net_pkt_msgq`.
 * - Updated `cvg_send_ipv6_pkt` to take `net_pkt` and queue it.
 * - Added `dect_nr_plus_iface_init` and `dect_nr_plus_l2_api` for Zephyr L2 integration.
 * - Added `dect_nr_plus_iface_iid_cb` for custom IPv6 IID generation.
 */
