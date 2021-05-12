/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _STR_UTILS_H_
#define _STR_UTILS_H_

int str_hex_to_bytes(char *str, uint32_t str_length, uint8_t *buf,
		     uint16_t *buf_length);

#endif /* _STR_UTILS_H_ */
