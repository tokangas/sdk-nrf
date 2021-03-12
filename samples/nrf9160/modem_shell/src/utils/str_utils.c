/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <assert.h>
#include <strings.h>
#include <stdio.h>
#include <zephyr.h>

#include "str_utils.h"

static inline uint8_t char2int(char input)
{
        if (input >= '0' && input <= '9') {
                return input - '0';
        }
        if (input >= 'A' && input <= 'F') {
                return input - 'A' + 10;
        }
        if(input >= 'a' && input <= 'f') {
                return input - 'a' + 10;
        }

        return 0;
}

int str_hex_to_bytes(char *str, uint32_t str_length,
        uint8_t* buf, uint16_t *buf_length)
{
	/* Remove any spaces from the input string */
	uint32_t index = 0;
	for (int i = 0; i < str_length; i++) {
		if (str[i] != ' ') {
			str[index] = str[i];
			index++;
		}
	}

	/* Convert each character into half byte.
	   Two characters form a byte. */
	for (int i = 0; i < index; ++i) {
		__ASSERT((i>>1) <= *buf_length, "Too small internal buffer");

		if(!(i%2)) {
			buf[i>>1] = 0;
		}

		buf[i>>1] |= (char2int(str[i]) << (4*!(i%2)));
	}

	/* Length calculation will drop signle character
	   if the length is not divisible by 2 */
	*buf_length = index / 2;

	return 0;
}
