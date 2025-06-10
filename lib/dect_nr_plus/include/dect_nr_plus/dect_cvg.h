/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
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
#include <dect_nr_plus/dect_types.h> // For dect_cvg_context_t, cvg_service_type_t, cvg_tx_queue_entry_t etc.

/**
 * @brief Global CVG context instance.
 * Defined in dect_cvg.c.
 */
extern dect_cvg_context_t cvg_ctx;

/* Message queue for net_pkts from higher layers (e.g., application, IP stack) to CVG TX thread */
extern struct k_msgq cvg_tx_net_pkt_msgq;

/* Message queue for data from DLC to CVG (for the CVG RX thread) */
extern struct k_msgq cvg_rx_msgq;

/**
 * @brief Initializes the DECT NR+ network interface.
 * This function is called by the Zephyr network stack to set up the L2 API
 * and IPv6 IID generation callback for the DECT NR+ interface.
 *
 * @param iface Pointer to the network interface being initialized.
 * @return 0 on success, or a negative error code.
 */
int dect_nr_plus_iface_init(struct net_if *iface);

/**
 * @brief Handles incoming data from the DLC layer to the CVG layer.
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
											uint16_t psn);

/**
 * @brief Initializes the Convergence (CVG) layer.
 * Sets up message queues, reassembly context, and timers.
 *
 * @return DECT_STATUS_OK on success, or an error code.
 */
void dect_cvg_init(void);

/**
 * @brief Combined thread entry point for the CVG layer.
 * This thread handles IPv6 fragmentation and sends data to the DLC layer,
 * and processes incoming data from the DLC layer, performing reassembly.
 *
 * @param p1 Unused.
 * @param p2 Unused.
 * @param p3 Unused.
 */
void dect_cvg_thread(void *p1, void *p2, void *p3);


#endif /* DECT_CVG_H__ */

/* End of File
 * Last Amended: 2025-06-05 13:00 BST: Updated dect_cvg.h for 6LoWPAN integration and L2 API.
 * - Added `CONFIG_NET_6LO` includes and definitions.
 * - Defined `cvg_tx_net_pkt_msgq` for `net_pkt`s from the network stack.
 * - Updated `cvg_tx_sdu_entry_t` with `pkt` and `next_tx_time_ms`. (Replaced by cvg_tx_queue_entry_t)
 * - Updated `cvg_rx_sdu_reassembly_t` with `pkt` and `first_hpc`.
 * - Updated `dect_cvg_init` to reference `cvg_tx_net_pkt_msgq`.
 * - Updated `cvg_send_ipv6_pkt` to take `net_pkt` and queue it. (Now static, not in header)
 * - Added `dect_nr_plus_iface_init` and `dect_nr_plus_l2_api` for Zephyr L2 integration.
 * - Added `dect_nr_plus_iface_iid_cb` for custom IPv6 IID generation. (Now static, not in header)
 * Last Amended: 2025-06-10 16:50 BST: Modified dect_cvg.h for IPv6 fragmentation/reassembly.
 * - Declared `cvg_tx_net_pkt_msgq` as extern to match `dect_cvg.c`.
 * - Removed `cvg_send_ipv6_pkt` and `dect_nr_plus_iface_iid_cb` prototypes as they are now static within `dect_cvg.c` and part of the `net_l2_api`.
 * - Added prototype for `cvg_tx_thread`.
 * - Ensured inclusion of `dect_types.h` for new CVG structs.
 * Last Amended: 2025-06-10 17:00 BST: Combined `cvg_tx_thread` and `cvg_rx_thread` into `dect_cvg_thread`.
 * - Updated `dect_cvg.h` to declare `dect_cvg_thread` instead of separate TX/RX threads.
 * Last Amended: 2025-06-10 17:05 BST: Reverted to separate `cvg_tx_thread` and `cvg_rx_thread` for consistency.
 * - Updated `dect_cvg.h` to declare `cvg_tx_thread` and `cvg_rx_thread` prototypes again.
 * Last Amended: 2025-06-10 17:15 BST: Combined CVG TX/RX into a single `dect_cvg_thread` using `k_msgq_get(K_NO_WAIT)` for consistency.
 * - Updated `dect_cvg.h` to declare only `dect_cvg_thread`.
 */
