/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "parser.h"
#include "sms_deliver.h"

static inline uint8_t char2int(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;

  return 0;
}

static int convert_to_bytes(char *str, uint32_t str_length,
			    uint8_t* buf, uint16_t buf_length)
{
	for(int i=0;i<str_length;++i) {
		if((i>>1) > buf_length) {
			return -EMSGSIZE;
		}

		if(!(i%2)) {
			buf[i>>1] = 0;
		}

		buf[i>>1] |= (char2int(str[i]) << (4*!(i%2)));
	}

	return 0;
}

int parser_create(struct parser *parser, struct parser_api *api)
{
	parser->api              = api;

	parser->data             = k_malloc(api->data_size());
	parser->payload          = NULL;
	parser->payload_buf_size = 0;
	parser->payload_pos      = 0;

	return 0;
}

int parser_delete(struct parser *parser)
{
	k_free(parser->data);

	return 0;
}

static int parser_process(struct parser *parser, uint8_t *data)
{
	int ofs_inc;

	parser_module *parsers = parser->api->get_parsers();

	parser->buf_pos = 0;

	for(int i=0;i<parser->api->get_parser_count();i++) {
		ofs_inc = parsers[i](parser, &parser->buf[parser->buf_pos]);

		if(ofs_inc < 0) {
			return ofs_inc;
		}

		parser->buf_pos += ofs_inc;
	}

	parser->payload_pos = parser->buf_pos;

	return 0;
}

int parser_process_raw(struct parser *parser, uint8_t *data, uint8_t length)
{
	parser->data_length = length;

	memcpy(parser->buf, data, length);

	return parser_process(parser, data);
}

int parser_process_str(struct parser *parser, char *data)
{
	uint8_t length = strlen(data);

	parser->data_length = length / 2;

	convert_to_bytes(data, length, parser->buf, BUF_SIZE);

	return parser_process(parser, data);
}

int parser_get_payload(struct parser *parser, char *buf, uint8_t buf_size)
{
	parser_module payload_decoder = parser->api->get_decoder();

	parser->payload          = buf;
	parser->payload_buf_size = buf_size;
	return payload_decoder(parser, &parser->buf[parser->payload_pos]);
}

int parser_get_header(struct parser *parser, void *header)
{
	return parser->api->get_header(parser, header);
}

