/*
 * Copyright (c) 2025 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DECT_ERRORS_H__
#define DECT_ERRORS_H__

#include <stdint.h>
#include <logging/log.h> // Include for logging in the error handler

/**
 * @brief Custom Error Codes for the DECT NR+ stack.
 *
 * This enum defines a set of specific error codes that can be returned
 * by functions within the DECT NR+ protocol stack, providing more
 * detailed information about the cause of a failure.
 */
typedef enum {
    DECT_STATUS_OK = 0,                 /**< Operation successful */
    DECT_ERROR_GENERIC = -1,            /**< General unspecified error */
    DECT_ERROR_PHY_NOT_READY = -2,      /**< Physical layer device not ready */
    DECT_ERROR_CRYPTO_NOT_READY = -3,   /**< Crypto device not ready */
    DECT_ERROR_PDU_TOO_LARGE = -4,      /**< PDU exceeds max frame size */
    DECT_ERROR_INVALID_PHY_HDR_TYPE = -5, /**< Invalid PHY header type specified */
    DECT_ERROR_ENCRYPTION_FAILED = -6,  /**< Data encryption failed */
    DECT_ERROR_DECRYPTION_FAILED = -7,  /**< Data decryption failed */
    DECT_ERROR_FRAME_TOO_SHORT = -8,    /**< Received frame is shorter than expected */
    DECT_ERROR_INVALID_PARAMETER = -9,  /**< A function received an invalid parameter */
    DECT_ERROR_NO_MEMORY = -10,         /**< Memory allocation failed */
    DECT_ERROR_TIMEOUT = -11,           /**< Operation timed out */
    DECT_ERROR_BUSY = -12,              /**< Resource is busy */
    DECT_ERROR_NOT_FOUND = -13,         /**< Item not found */
    DECT_ERROR_NOT_SUPPORTED = -14,     /**< Feature not supported */
    DECT_ERROR_INVALID_STATE = -15,     /**< Operation requested in an invalid state */
    DECT_ERROR_MSGQ_FULL = -16,         /**< Message queue is full */
    DECT_ERROR_SECURITY_FAILED = -17,   /**< Generic security operation failed */
    DECT_ERROR_SECURITY_MIC_MISMATCH = -18, /**< Message Integrity Code mismatch */
    DECT_ERROR_SECURITY_AUTH_FAILED = -19, /**< Authentication failed */
    DECT_ERROR_MAC_SCHED_FAILED = -20,  /**< MAC scheduling failed */
    DECT_ERROR_MAC_NO_RESOURCES = -21,  /**< No MAC resources available */
    DECT_ERROR_MAC_SYNC_FAILED = -22,   /**< MAC synchronization failed */
    DECT_ERROR_MAC_ASSOC_FAILED = -23,  /**< MAC association failed */
    DECT_ERROR_MAC_ASSOC_REJECTED = -24, /**< MAC association rejected by peer */
    DECT_ERROR_MAC_INVALID_IE = -25,    /**< Invalid Information Element received */
    DECT_ERROR_MAC_INVALID_HEADER = -26,/**< Invalid MAC header received */
    DECT_ERROR_DLC_CONN_FAILED = -27,   /**< DLC connection establishment failed */
    DECT_ERROR_DLC_CONN_TIMEOUT = -28,  /**< DLC connection timed out */
    DECT_ERROR_DLC_RELEASE_FAILED = -29,/**< DLC connection release failed */
    DECT_ERROR_DLC_ARQ_ERROR = -30,     /**< DLC ARQ error (e.g., sequence mismatch) */
    DECT_ERROR_DLC_FLOW_CONTROL_BLOCKED = -31, /**< DLC TX blocked by flow control */
    DECT_ERROR_DLC_CRC_ERROR = -32,     /**< DLC CRC error */
    DECT_ERROR_ROUTING_NO_ROUTE = -33,  /**< Routing: No route to destination */
    DECT_ERROR_ROUTING_DISCOVERY_FAILED = -34, /**< Routing: Route discovery failed */
    DECT_ERROR_ROUTING_TABLE_FULL = -35,/**< Routing: Routing table full */
    DECT_ERROR_CVG_FRAGMENT_TOO_LARGE = -36, /**< CVG: Fragment too large for DLC */
    DECT_ERROR_CVG_REASSEMBLY_FAILED = -37, /**< CVG: SDU reassembly failed */
    DECT_ERROR_NET_PKT_READ_FAILED = -40, /**< Failed to read data from network packet */
    DECT_ERROR_CVG_REASSEMBLY_TIMEOUT = -44, /**< CVG SDU reassembly timed out */
    DECT_ERROR_CVG_OUT_OF_ORDER = -45,  /**< CVG fragment received out of order or unexpectedly */

    // New specific errors from Nordic PHY integration
    DECT_ERROR_PHY_TX_FAILED = -46,     /**< Physical layer transmit operation failed */
    DECT_ERROR_CHANNEL_RESELECTION_FAILED = -47, /**< Channel reselection process failed to complete successfully */
    DECT_ERROR_PHY_CHANNEL_BUSY = -48,  /**< Physical layer channel was busy during LBT */
    DECT_ERROR_PHY_SCHED_TOO_LATE = -49, /**< Physical layer scheduling failed: start time in past */
    DECT_ERROR_PHY_SCHED_CONFLICT = -50, /**< Physical layer scheduling failed: conflict with other operation */
    DECT_ERROR_PHY_TX_TIMEOUT = -51,    /**< Physical layer transmit operation timed out */
    DECT_ERROR_PHY_GENERIC = -52,       /**< Generic physical layer error */
    DECT_ERROR_PHY_TEMP_HIGH = -53,     /**< Modem temperature is too high */
    DECT_ERROR_PHY_NO_CALLBACK = -54,   /**< No PHY callback registered for an event */
    DECT_ERROR_OPERATION_CANCELED = -55, /**< Operation was canceled */
    DECT_ERROR_MAC_RESOURCE_REQ_FAILED = -56, /**< MAC resource request failed */

} dect_status_t;

/**
 * @brief Macro for consistent error handling and logging.
 *
 * This macro logs an error message with the specified error code and description.
 * In a more advanced system, it could also trigger a system-wide fault handler,
 * increment a global error counter, or perform other recovery actions.
 *
 * @param err_code The DECT_ERROR_ code.
 * @param description A string literal describing the error.
 */
#define DECT_ERROR_HANDLER(err_code, description, ...) \\\
    do { \\\
        LOG_ERR("DECT_ERROR: " description " (%d)", ##__VA_ARGS__, err_code); \\\
        /* Optionally, increment a global error counter or trigger a fault state */ \\\
        /* STATS_INC(total_errors); // If a global error stat exists */ \\\
    } while (0)

#endif /* DECT_ERRORS_H__ */

/* End of File
 * Last Amended: 2025-06-04 13:36 BST: Updated dect_errors.h
 * - Added new error codes related to Nordic PHY integration:
 * - `DECT_ERROR_PHY_CHANNEL_BUSY`
 * - `DECT_ERROR_PHY_SCHED_TOO_LATE`
 * - `DECT_ERROR_PHY_SCHED_CONFLICT`
 * - `DECT_ERROR_PHY_TX_TIMEOUT`
 * - `DECT_ERROR_PHY_GENERIC`
 * - `DECT_ERROR_PHY_TEMP_HIGH`
 * - `DECT_ERROR_PHY_NO_CALLBACK`
 * - `DECT_ERROR_OPERATION_CANCELED`
 * - `DECT_ERROR_MAC_RESOURCE_REQ_FAILED`
 * - Modified `DECT_ERROR_HANDLER` macro to support variadic arguments for more flexible logging.
 */
