/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <logging/log.h>

#include "parser.h"
#include "sms_deliver.h"

LOG_MODULE_DECLARE(sms, CONFIG_SMS_LOG_LEVEL);

/**
 * @brief Convert hexadecimal character to integer value.
 * 
 * @param[in] input Hexadecimal character.
 * 
 * @return Integer value of the hexadecimal character
 */
static inline uint8_t char2int(char input)
{
	if (input >= '0' && input <= '9') {
		return input - '0';
	}
	if (input >= 'A' && input <= 'F') {
		return input - 'A' + 10;
	}
	if (input >= 'a' && input <= 'f') {
		return input - 'a' + 10;
	}

	return 0;
}

/**
 * @brief Convert ASCII formatted hexadecimal string into byte sequence.
 * 
 * @details Every two characters form a single byte. 3GPP TS 27.005 Section 3.1 says
 * the following in <pdu> definition:
 *   "ME/TA converts each octet of TP data unit into two IRA character long hexadecimal number
 *    (e.g. octet with integer value 42 is presented to TE as two characters 2A (IRA 50 and 65))"
 *
 * @param[in] str Hexadecimal string.
 * @param[in] str_length Hexadecimal string length.
 * @param[out] buf Output buffer.
 * @param[in] buf Output buffer length.
 */
static void convert_to_bytes(char *str, uint32_t str_length, uint8_t* buf, uint16_t buf_length)
{
	for (int i = 0; i < str_length; i++) {
		__ASSERT((i >> 1) <= buf_length, "Too small internal buffer");

		/* Character in an even index will be filled into byte that should be
		 * initialized to zero to make sure the memory area is clean. */
		if (!(i % 2)) {
			buf[i >> 1] = 0;
		}

		/* The integer value of each character is added into the output buffer into
		 * index that's half of the characters index in the input buffer as each byte is
		 * represented by two characters. Division by 2 is done with right shift.
		 * The first character of the two character set forms the most significant
		 * 4 bits of the integer and the second character forms the least significant
		 * 4 bits. This is where the shifting by four comes from based on whether the
		 * index is even or odd.
		 */
		buf[i >> 1] |= (char2int(str[i]) << (4 * !(i % 2)));
	}
}

int parser_create(struct parser *parser, struct parser_api *api)
{
	memset(parser, 0, sizeof(struct parser));

	parser->api = api;

	parser->data = k_calloc(1, api->data_size());
	if (parser->data == NULL) {
		LOG_ERR("Out of memory when creating parser");
		return -ENOMEM;
	}

	return 0;
}

int parser_delete(struct parser *parser)
{
	k_free(parser->data);
	parser->data = NULL;

	return 0;
}

/**
 * @brief Process given data with all sub parser of the given parser.
 * 
 * @param[in] parser Parser instance which has information on sub parsers that are executed.
 *
 * @return Zero if successful, negative value in error cases.
 */
static int parser_process(struct parser *parser)
{
	int ofs_inc;

	parser_module *parsers = parser->api->get_parsers();

	parser->buf_pos = 0;

	for (int i = 0; i < parser->api->get_parser_count(); i++) {
		ofs_inc = parsers[i](parser, &parser->buf[parser->buf_pos]);

		if (ofs_inc < 0) {
			return ofs_inc;
		}

		parser->buf_pos += ofs_inc;

		/* If we have gone beyond the length of the given data,
		   we need to return a failure. We don't have issues in
		   accessing memory beyond parser->data_length bytes of
		   parser->buf as the buffer is overly long.
		   */
		if (parser->buf_pos > parser->data_length) {
			return -EMSGSIZE;
		}
	}

	parser->payload_pos = parser->buf_pos;

	return 0;
}

int parser_process_str(struct parser *parser, char *data)
{
	uint16_t length = strlen(data);

	parser->data_length = length / 2;

	if (parser->data_length > PARSER_BUF_SIZE) {
		LOG_ERR("Data length (%d) is bigger than the internal buffer size (%d)",
			parser->data_length,
			PARSER_BUF_SIZE);
		return -EMSGSIZE;
	}

	convert_to_bytes(data, length, parser->buf, PARSER_BUF_SIZE);

	return parser_process(parser);
}

int parser_get_payload(struct parser *parser, char *buf, uint8_t buf_size)
{
	parser_module payload_decoder = parser->api->get_decoder();

	parser->payload = buf;
	parser->payload_buf_size = buf_size;
	return payload_decoder(parser, &parser->buf[parser->payload_pos]);
}

int parser_get_header(struct parser *parser, void *header)
{
	return parser->api->get_header(parser, header);
}

