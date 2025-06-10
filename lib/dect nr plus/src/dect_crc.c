/*
 * Copyright (c) 2025 Google LLC
 * Manulytica
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <crc.h> // Zephyr CRC API

/**
 * @brief Computes the CRC-16-CCITT checksum for a given data block.
 *
 * This function uses Zephyr's built-in CRC16-CCITT implementation to
 * calculate the checksum, which is used for integrity checking in
 * various DECT NR+ PDUs.
 *
 * @param data Pointer to the data buffer for which to compute the CRC.
 * @param len Length of the data buffer in bytes.
 * @return The computed 16-bit CRC value.
 */
uint16_t compute_crc(const uint8_t *data, size_t len)
{
	/* Initial value for CRC-16-CCITT is typically 0xFFFF */
	return crc16_ccitt(0xFFFF, data, len);
}
