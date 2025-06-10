/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file main.c
 * @brief Simple DECT NR+ application demonstrating basic data transmission and reception
 * using the DECT NR+ stack over Zephyr's network interface (IPv6/UDP).
 *
 * This example showcases:
 * - Proper initialization of the complete DECT NR+ subsystem (`dect_nr_plus_init`).
 * - Configuration of the device role (Fixed Part or Portable Part) via `dect_config`.
 * - Setting up a Zephyr IPv6 UDP network context for application data.
 * - Transmitting a simple counter value as a UDP packet.
 * - Receiving and processing incoming UDP packets via a network callback.
 * - Integration with MAC layer's association and synchronization states,
 * waiting for the network carrier to be established.
 *
 * NOTE: This example assumes the DECT NR+ stack (MAC, DLC, CVG, PHY, etc.)
 * is correctly integrated into the Zephyr build system and available.
 * The `dect_config` module should be configured for the desired device role
 * (FP or PP) and Short RD IDs for the devices in the network.
 * For two devices to communicate:
 * - One device should be configured as `MAC_ROLE_FP`.
 * - The other device should be configured as `MAC_ROLE_PP`.
 * - Their IPv6 addresses for this example are hardcoded as 2001:db8::1 and 2001:db8::2.
 * Ensure `dect_nr_plus_iface_iid_cb` (in `dect_cvg.h`) uses an appropriate
 * mechanism to derive Interface IDs compatible with these addresses.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h> // For network interface functions
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/udp.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_ip.h> // For net_sprint_ipv6_addr
#include <zephyr/sys/byteorder.h> // For sys_le32_to_cpu

#include <dect_nr_plus/dect_nr_plus_subsystem.h> // Public API for the DECT NR+ subsystem
#include <dect_nr_plus/dect_config.h> // To check device role
#include <dect_nr_plus/dect_mac.h> // To check MAC association state (mac_ctx)
#include <dect_nr_plus/dect_dlc.h>
#include <dect_nr_plus/dect_cvg.h> // For dect_nr_plus_l2_api, iface_iid_cb etc.
#include <dect_nr_plus/dect_errors.h> // For error logging
#include <dect_nr_plus/dect_security.h> // To check Security authentication state (sec_ctx)

LOG_MODULE_REGISTER(dect_app, CONFIG_DECT_NR_PLUS_LOG_LEVEL);

// Define UDP port for application data
#define UDP_PORT 4242
// Interval for transmitting data in milliseconds
#define APP_TX_INTERVAL_MS 1000
// Length of the application data payload (integer counter)
#define APP_DATA_LEN 4 // Size of a uint32_t

// Network context for sending UDP packets
static struct net_context *udp_ctx;

// Global flag to indicate if network setup was successful
static bool network_ready = false;

// Global counter for transmission
static uint32_t tx_counter = 0;

// Last received counter value and RSSI (for display)
static int32_t last_rx_counter = -1;
static int8_t last_rx_rssi = 0; // RSSI would need to be passed up through net_pkt_user_data or similar

// Forward declarations for static functions
static void setup_network_context(void);
static void rx_callback(struct net_context *context,
                        struct net_pkt *pkt,
                        union net_ip_header *ip_hdr,
                        union net_proto_header *proto_hdr,
                        int status,
                        void *user_data);

/**
 * @brief Main entry point for the DECT NR+ rxtx_example application.
 *
 * This function initializes the DECT NR+ stack, sets up network communication,
 * and enters a loop to transmit or receive data based on the configured device role.
 */
int main(void)
{
    printk("DECT NR+ rxtx_example Application Started.\n");

    // Initialize the complete DECT NR+ subsystem.
    // This will internally initialize MAC, DLC, CVG, PHY, etc., and start their threads.
    printk("Initializing complete DECT NR+ subsystem...\n");
    dect_status_t status = dect_nr_plus_init();
    if (status != DECT_STATUS_OK) {
        printk("Failed to initialize DECT NR+ subsystem: %d. Exiting.\n", status);
        return 0; // Indicate failure
    }
    printk("DECT NR+ subsystem initialized. Role: %s (Short RD ID: 0x%04X).\n",
           (dect_config.device_role == MAC_ROLE_FP) ? "Fixed Part" : "Portable Part",
           dect_config.short_rd_id);

    // Give some time for stack threads to start and perform initial tasks (e.g., beaconing/sync)
    k_sleep(K_SECONDS(2));

    // Setup network context for UDP communication over the DECT NR+ interface
    setup_network_context();

    if (!network_ready) {
        printk("Network setup failed. Cannot proceed with application logic.\n");
        return 0; // Indicate failure
    }

    // Wait for the MAC layer to establish association and bring up the network carrier.
    // Portable Parts need to synchronize and associate with a Fixed Part.
    // Fixed Parts are generally assumed to be beaconing and ready.
    if (dect_config.device_role == MAC_ROLE_PP) {
        printk("PP: Waiting for association and network carrier.\n");
        int connection_wait_count = 0;
        // while (mac_ctx.association_state != MAC_ASSOC_STATE_ASSOCIATED ||
        //        sec_ctx.auth_state != SECURITY_AUTH_STATE_AUTHENTICATED) {
        while (!dect_mac_is_associated() || !dect_security_is_established(mac_ctx.connected_peer_info.peer_short_rd_id)) {
            printk("PP: Waiting for DECT NR+ connection (Sync/Assoc/Security)... (%d)\n", connection_wait_count);
            k_sleep(K_SECONDS(2));
            connection_wait_count++;
            if (connection_wait_count > 30) { // Timeout after 60 seconds
                printk("PP: DECT NR+ connection timeout. Cannot proceed.\n");
                return 0; // Indicate failure
            }
        }
        printk("PP: DECT NR+ connection established (Associated and Authenticated) with FP 0x%04X.\n", mac_ctx.connected_peer_info.peer_short_rd_id);
    } else { // MAC_ROLE_FP
        printk("FP: Waiting for network carrier. (Assumed beaconing and ready for PPs).\n");
        // For FP, carrier usually comes up when a PP associates, or when it's ready to handle traffic.
    }

    // Final check for network interface being up before proceeding with data transfer
    while (!net_if_is_up(mac_ctx.net_if_ptr)) {
        printk("Waiting for network interface to come up...\n");
        k_sleep(K_SECONDS(1));
    }
    printk("Network interface is UP.\n");

    // Main application loop for transmitting/receiving data
    printk("Starting data transmission/reception loop.\n");
    while (1) {
        // TRANSMITTER LOGIC:
        // The FP will continuously transmit if no PP is associated (broadcast or general data).
        // If a PP, it will transmit only when associated.
        if (dect_config.device_role == MAC_ROLE_FP ||
            (dect_config.device_role == MAC_ROLE_PP && mac_ctx.association_state == MAC_ASSOC_STATE_ASSOCIATED)) {

            // Allocate a new network packet with a buffer
            struct net_pkt *pkt = net_pkt_alloc_with_buffer(udp_ctx->tx_slab,
                                                            APP_DATA_LEN,
                                                            K_FOREVER); // Wait indefinitely for buffer
            if (!pkt) {
                printk("Failed to allocate net_pkt for TX! Retrying...\n");
                k_sleep(K_MSEC(APP_TX_INTERVAL_MS));
                continue;
            }

            // Set packet properties for the network context
            net_pkt_set_context(pkt, udp_ctx);
            net_pkt_set_family(pkt, AF_INET6);
            net_pkt_set_udp_src_port(pkt, UDP_PORT);
            net_pkt_set_udp_dst_port(pkt, UDP_PORT);

            // Add the current counter value to the packet payload
            // Use little-endian conversion for consistency over the wire
            net_buf_simple_add_le32(pkt->buffer, tx_counter);

            printk("TX: Sending counter value %u (len %u) to %s\n", tx_counter,
                   net_pkt_get_len(pkt), net_sprint_ipv6_addr(&NET_IPV6_HDR(udp_ctx->remote)->addr));

            // Send the packet via the network context. This call traverses Zephyr's IP stack
            // and then our DECT NR+ L2 interface (CVG layer).
            int ret = net_context_send(pkt, NULL, NULL, NULL); // No reply callback needed for UDP
            if (ret < 0) {
                printk("Failed to send UDP packet: %d\n", ret);
                net_pkt_unref(pkt); // Free packet if sending failed
            } else {
                tx_counter++; // Increment counter only on successful send request
            }
        } else {
             printk("PP: Not associated yet, skipping data transmission.\n");
        }

        // RECEIVER LOGIC:
        // Incoming packets are processed asynchronously by the `rx_callback` function.
        // We just print the last received information if new data arrived.
        if (last_rx_counter != -1) {
            printk("RX: Last received counter: %d (Approx. RSSI: %d dBm)\n", last_rx_counter, last_rx_rssi);
            last_rx_counter = -1; // Reset flag to indicate that this packet has been displayed
        }

        k_sleep(K_MSEC(APP_TX_INTERVAL_MS)); // Wait before next TX/RX cycle
    }
}

/**
 * @brief Sets up the network context for UDP communication.
 *
 * This involves:
 * - Getting the DECT NR+ network interface (from `mac_ctx.net_if_ptr`).
 * - Assigning a static IPv6 address (for demonstration purposes).
 * - Creating and binding a UDP network context.
 * - Connecting the UDP context to a peer's hardcoded IPv6 address.
 * - Registering a receive callback for incoming UDP packets.
 */
static void setup_network_context(void)
{
    struct net_if *iface = mac_ctx.net_if_ptr;
    if (!iface) {
        printk("Error: Network interface not available. Cannot setup network context.\n");
        return;
    }

    // Add a dummy IPv6 address to the interface for testing.
    // In a real application, this would typically involve Stateless Address Autoconfiguration (SLAAC)
    // or DHCPv6, leveraging the EUI-64 derived from the device's Long RD ID.
    struct in6_addr my_ipv6_addr;
    if (dect_config.device_role == MAC_ROLE_FP) {
        // FP uses 2001:db8::1
        net_ipv6_addr_set_raw(&my_ipv6_addr, (uint8_t[]){0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    } else {
        // PP uses 2001:db8::2
        net_ipv6_addr_set_raw(&my_ipv6_addr, (uint8_t[]){0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    }

    net_if_ipv6_addr_add(iface, &my_ipv6_addr, NET_ADDR_MANUAL, 0);
    printk("Assigned IPv6 address to interface: %s\n", net_sprint_ipv6_addr(&my_ipv6_addr));

    // Create a UDP network context for IPv6 datagrams
    udp_ctx = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (!udp_ctx) {
        printk("Failed to get UDP context! Cannot proceed.\n");
        return;
    }

    // Bind the UDP context to the local port.
    // NET_IPV6_ADDR_UNSPECIFIED allows binding to any available local IPv6 address.
    int ret = net_context_bind(udp_ctx, NET_IPV6_ADDR_UNSPECIFIED, UDP_PORT);
    if (ret < 0) {
        printk("Failed to bind UDP context to port %d: %d\n", UDP_PORT, ret);
        net_context_put(udp_ctx); // Clean up context on failure
        udp_ctx = NULL;
        return;
    }

    // Connect the UDP context to a specific remote peer's IPv6 address and port.
    // This example hardcodes the peer's address.
    struct in6_addr peer_ipv6_addr;
    if (dect_config.device_role == MAC_ROLE_FP) {
        // FP will send to PP (2001:db8::2)
        net_ipv6_addr_set_raw(&peer_ipv6_addr, (uint8_t[]){0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    } else {
        // PP will send to FP (2001:db8::1)
        net_ipv6_addr_set_raw(&peer_ipv6_addr, (uint8_t[]){0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    }

    ret = net_context_connect(udp_ctx, (struct sockaddr *)&peer_ipv6_addr, sizeof(peer_ipv6_addr),
                              NULL, UDP_PORT, NULL, 0); // No timeout for connect
    if (ret < 0) {
        printk("Failed to connect UDP context to peer %s:%d: %d\n",
               net_sprint_ipv6_addr(&peer_ipv6_addr), UDP_PORT, ret);
        net_context_put(udp_ctx); // Clean up context on failure
        udp_ctx = NULL;
        return;
    }

    // Register the receive callback for this UDP context.
    // This function will be asynchronously called by the Zephyr network stack
    // whenever a UDP packet arrives for this context.
    net_context_set_recv_cb(udp_ctx, rx_callback, NULL);

    printk("UDP context setup complete. Listening on port %d, sending to %s.\n",
           UDP_PORT, net_sprint_ipv6_addr(&peer_ipv6_addr));
    network_ready = true;
}

/**
 * @brief Receive callback for incoming UDP packets.
 *
 * This function is invoked by the Zephyr network stack when a UDP packet is received
 * on the bound UDP context. It extracts the counter value and prints it.
 *
 * @param context The network context associated with the received packet.
 * @param pkt The received network packet.
 * @param ip_hdr Pointer to the IP header of the packet.
 * @param proto_hdr Pointer to the protocol header (UDP) of the packet.
 * @param status Status of the packet (0 for success, negative for error).
 * @param user_data User data passed during callback registration (unused here).
 */
static void rx_callback(struct net_context *context,
                        struct net_pkt *pkt,
                        union net_ip_header *ip_hdr,
                        union net_proto_header *proto_hdr,
                        int status,
                        void *user_data)
{
    ARG_UNUSED(context);
    ARG_UNUSED(ip_hdr);
    ARG_UNUSED(proto_hdr);
    ARG_UNUSED(user_data);

    if (status < 0) {
        printk("RX callback error: %d\n", status);
        // Error in receiving, packet might already be unreffed
        return;
    }

    if (!pkt) {
        printk("RX callback: NULL packet received.\n");
        return;
    }

    // Read the counter value from the packet payload
    if (net_pkt_get_len(pkt) >= APP_DATA_LEN) {
        uint32_t received_val;
        if (net_pkt_read(pkt, (uint8_t *)&received_val, APP_DATA_LEN) == APP_DATA_LEN) {
            last_rx_counter = sys_le32_to_cpu(received_val); // Convert from little-endian to host
            // RSSI cannot be directly accessed from net_pkt at this layer.
            // It would need to be passed up from MAC/PHY using `net_pkt_user_data` or similar mechanisms.
            // For this example, `last_rx_rssi` remains a placeholder.
        } else {
            printk("RX: Failed to read full counter from packet payload.\n");
        }
    } else {
        printk("RX: Received packet too short for counter (len %u bytes).\n", net_pkt_get_len(pkt));
    }

    net_pkt_unref(pkt); // Always unreference the received packet to free its resources
}

/* End of File
 * Last Amended: 2025-06-05 12:30 BST: Updated main.c
 * - Simplified `main()` function to primarily call `dect_nr_plus_init()` to initialize the entire DECT NR+ subsystem.
 * - Added logic to find the registered DECT NR+ network interface using `NET_L2_FOREACH`.
 * - Modified the FP role to assign a dummy IPv6 address and periodically print statistics.
 * - Modified the PP role to:
 * - Wait for the DECT NR+ connection (synchronization, association, security) to be established by the subsystem threads.
 * - Assign a dummy IPv6 address to the DECT network interface.
 * - Simulate sending IP packets using `net_pkt_alloc_with_buffer`, `net_ipv6_set_src/dst`, `net_udp_set_src/dst_port`, and `net_if_send_data`. This demonstrates the application-level interaction with the DECT stack via Zephyr's networking API.
 * - Removed direct calls to individual layer inits and thread creations, as these are now handled by `dect_nr_plus_init()`.
 * Last Amended: 2025-06-06 14:00 BST: Updated main.c to conform to new driver.
 * - Replaced content with the enhanced `rxtx_example.c` logic.
 * - Added necessary Zephyr network headers for UDP/IPv6 operations.
 * - Utilizes `dect_nr_plus_init()` for full stack initialization.
 * - Added `static bool network_ready = false;` flag.
 * - Simplified network interface lookup by relying on `mac_ctx.net_if_ptr` being set by the subsystem.
 * - Implemented `setup_network_context` for IPv6 address assignment, UDP context creation, binding, connecting, and receive callback registration.
 * - Implemented application loop for transmitting/receiving counter data via UDP over IPv6.
 * - Incorporated wait conditions for MAC association and network carrier readiness.
 * - Updated comments for clarity and consistency with the new application structure.
 */
