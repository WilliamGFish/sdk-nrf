/*
 * Copyright (c) 2025 - Manulyitca Ltd (William Fish)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/udp.h> // For UDP specific definitions if needed, though general socket covers it
#include <arpa/inet.h>     // For inet_pton, inet_ntop

#include <dect_nr_plus/dect_nr_plus_subsystem.h> // Include the DECT NR+ top-level API
#include <dect_nr_plus/dect_types.h> // For any DECT-specific types like MAC addresses
#include <dect_nr_plus/dect_config.h> // For dect_config

LOG_MODULE_REGISTER(dect_app, CONFIG_DECT_APP_LOG_LEVEL);

#define UDP_PORT 5000
#define MSG_SIZE 64

// Define a dummy master_key for security.c and crypto.c if not provided by configuration
// In a real system, this would be securely provisioned.
#ifndef MASTER_KEY_DEFINE
const uint8_t master_key[AES_KEY_LEN] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
#endif

// Main application thread
void dect_app_main_thread(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    LOG_INF("DECT NR+ Sample Application Started.");

    // 1. Initialize the DECT NR+ subsystem
    dect_status_t status = dect_nr_plus_init();
    if (status != DECT_STATUS_OK) {
        LOG_ERR("Failed to initialize DECT NR+ subsystem: %d", status);
        return;
    }
    LOG_INF("DECT NR+ subsystem initialized successfully.");

    // Wait for the network interface to be up and configured.
    // The `dect_nr_plus_iface_init` function (called internally by Zephyr)
    // will bring up the carrier and add the IPv6 address.
    struct net_if *dect_iface = NULL;
    struct net_if_addr *if_addr = NULL;
    char my_ipv6_addr_str[NET_IPV6_ADDR_LEN]; // Buffer to store our IPv6 address string

    LOG_INF("Waiting for DECT NR+ network interface to come up and get IPv6 address...");
    while (dect_iface == NULL || if_addr == NULL) {
        dect_iface = net_if_get_by_name(CONFIG_DECT_NR_PLUS_NET_IF_NAME);
        if (dect_iface && net_if_is_up(dect_iface)) {
            // Check if it has at least one unicast IPv6 address
            if_addr = net_if_ipv6_addr_lookup_by_state(dect_iface, NET_ADDR_PREFERRED);
            if (if_addr == NULL) {
                if_addr = net_if_ipv6_addr_lookup_by_state(dect_iface, NET_ADDR_TENTATIVE);
            }
            if (if_addr) {
                // Convert the address to a string for logging
                inet_ntop(AF_INET6, &if_addr->address.in6_addr, my_ipv6_addr_str, sizeof(my_ipv6_addr_str));
                LOG_INF("DECT NR+ network interface (%s) is up with IPv6 address: [%s]",
                        CONFIG_DECT_NR_PLUS_NET_IF_NAME, my_ipv6_addr_str);
                break;
            }
        }
        k_sleep(K_MSEC(100)); // Sleep briefly before re-checking
    }

#if defined(CONFIG_APP_ROLE_SENDER)
    // ------------------------------------
    // SENDER ROLE
    // ------------------------------------
    int sock;
    struct sockaddr_in6 dest_addr;
    char ipv6_str[NET_IPV6_ADDR_LEN]; // Buffer for IPv6 address string
    const char *target_ipv6_addr_str = CONFIG_APP_TARGET_IPV6_ADDR; // From Kconfig

    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG_ERR("Failed to create UDP socket: %d", errno);
        return;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    dest_addr.sin6_port = htons(UDP_PORT);

    if (inet_pton(AF_INET6, target_ipv6_addr_str, &dest_addr.sin6_addr) != 1) {
        LOG_ERR("Failed to convert IPv6 address string: %s", target_ipv6_addr_str);
        close(sock);
        return;
    }

    LOG_INF("SENDER: Sending dummy messages from [%s] to [%s]:%d", my_ipv6_addr_str, target_ipv6_addr_str, UDP_PORT);

    int count = 0;
    while (true) {
        char msg_buf[MSG_SIZE];
        snprintk(msg_buf, sizeof(msg_buf), "Hello DECT NR+ from %02x%02x%02x%02x! Msg %d",
                 dect_config.mac_address[0], dect_config.mac_address[1],
                 dect_config.mac_address[2], dect_config.mac_address[3], count++);

        int bytes_sent = sendto(sock, msg_buf, strlen(msg_buf), 0,
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (bytes_sent < 0) {
            LOG_ERR("Failed to send message: %d", errno);
        } else {
            LOG_INF("SENDER: Sent %d bytes: '%s'", bytes_sent, msg_buf);
        }
        k_sleep(K_SECONDS(CONFIG_APP_SENDER_INTERVAL_S));
    }

    close(sock);

#elif defined(CONFIG_APP_ROLE_RECEIVER)
    // ------------------------------------
    // RECEIVER ROLE
    // ------------------------------------
    int sock;
    struct sockaddr_in6 bind_addr;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    char rx_buf[MSG_SIZE + 1]; // +1 for null terminator
    char peer_ipv6_str[NET_IPV6_ADDR_LEN];

    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG_ERR("Failed to create UDP socket: %d", errno);
        return;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin6_family = AF_INET6;
    bind_addr.sin6_port = htons(UDP_PORT);
    bind_addr.sin6_addr = in6addr_any; // Listen on all interfaces

    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_ERR("Failed to bind UDP socket: %d", errno);
        close(sock);
        return;
    }

    LOG_INF("RECEIVER: Listening on UDP port %d on address [%s]...", UDP_PORT, my_ipv6_addr_str);

    while (true) {
        int bytes_received = recvfrom(sock, rx_buf, sizeof(rx_buf) - 1, 0,
                                      (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (bytes_received < 0) {
            LOG_ERR("Failed to receive message: %d", errno);
            k_sleep(K_MSEC(100)); // Small sleep on error to prevent tight loop
            continue;
        }

        rx_buf[bytes_received] = '\0'; // Null-terminate received data
        inet_ntop(AF_INET6, &peer_addr.sin6_addr, peer_ipv6_str, sizeof(peer_ipv6_str));

        LOG_INF("RECEIVER: Received %d bytes from [%s]:%d: '%s'",
                bytes_received, peer_ipv6_str, ntohs(peer_addr.sin6_port), rx_buf);

        // Optional: Echo back the message
#if defined(CONFIG_APP_RECEIVER_ECHO_RESPONSE)
        int bytes_sent = sendto(sock, rx_buf, bytes_received, 0,
                                (struct sockaddr *)&peer_addr, peer_addr_len);
        if (bytes_sent < 0) {
            LOG_ERR("RECEIVER: Failed to echo response: %d", errno);
        } else {
            LOG_DBG("RECEIVER: Echoed %d bytes back.", bytes_sent);
        }
#endif
    }

    close(sock);

#else
    LOG_WRN("No application role (sender/receiver) defined in Kconfig. Doing nothing.");
#endif // CONFIG_APP_ROLE_SENDER / CONFIG_APP_ROLE_RECEIVER
}

// Define the main application thread
K_THREAD_DEFINE(dect_app_thread, CONFIG_DECT_APP_THREAD_STACK_SIZE,
                dect_app_main_thread, NULL, NULL, NULL,
                CONFIG_DECT_APP_THREAD_PRIORITY, 0, 0);

