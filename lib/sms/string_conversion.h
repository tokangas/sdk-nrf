/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _STRING_CONVERSION_H_
#define _STRING_CONVERSION_H_

#include <stdint.h>
#include <stdbool.h>


uint8_t string_conversion_ascii_to_gsm7bit(const uint8_t *p_data,
						 uint8_t  data_len,
						 uint8_t *p_out_data,
						 uint8_t *p_out_bytes,
						 uint8_t *p_out_chars,
						 bool     packing);

uint8_t string_conversion_gsm7bit_to_ascii(const uint8_t *p_data,
						 uint8_t *p_out_data,
						 uint8_t  num_char,
						 bool     packed);

uint8_t string_conversion_7bit_sms_packing(uint8_t *p_data, uint8_t data_len);

uint8_t string_conversion_7bit_sms_unpacking(const uint8_t *p_packed,
						   uint8_t *p_unpacked,
						   uint8_t  num_char);

#endif /* STRING_CONVERSION_H_ */
