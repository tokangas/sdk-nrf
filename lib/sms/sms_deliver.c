/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include "parser.h"
#include "sms_deliver.h"

#include <string.h>
#include <zephyr.h>

#define SCTS_FIELD_SIZE 7

#define DELIVER_DATA(parser_data) ((struct pdu_deliver_data*)parser_data->data)

/**
 * @brief SMS-DELIVER type of PDU in 3GPP TS 23.040 chapter 9.2.2.1.
 * TODO: Seems sri and udhi are in wrong order in the code compared to
 *       3GPP TS 23.040 chapter 9.2.2.1. Also, tp is not the last bit.
 */
struct pdu_deliver_header {
	uint8_t mti:2;  /** TP-Message-Type-Indicator */
	uint8_t mms:1;  /** TP-More-Messages-to-Send */
	uint8_t :2;     /** TP-Loop-Prevention, TP-Reply-Path */
	uint8_t sri:1;  /** TP-Status-Report-Indication */
	uint8_t udhi:1; /** TP-User-Data-Header-Indicator */
	uint8_t rp:1;   /** TODO: Is this supposed to be TP-Reply-Path which is not in here in the spec? */
};

/**
 * @brief Address field in 3GPP TS 23.040 chapter 9.1.2.5.
 */
struct pdu_do_field {
	uint8_t length;   /** Address-Length */
	uint8_t adr_type; /** Type-of-Address */
	uint8_t adr[10];  /** Address */
};

/**
 * @brief Address field in 3GPP TS 23.038 chapter 4.
 * This encoding applies if bits 7 to 6 are zeroes.
 */
struct pdu_dcs_field {
	uint8_t class:2;      /** Message Class */
	uint8_t alphabet:2;   /** Character set */
	/** If set to 1, indicates that bits 1 to 0 have a message class
	 *  meaning. Otherwise bits 1 to 0 are reserved. */
	uint8_t presence_of_class:1; 
	/** If set to 0, indicates the text is uncompressed.
	 *  Otherwise it's compressed. */
	uint8_t compressed:1;
};

struct pdu_deliver_data {
	struct pdu_deliver_header field_header;
	struct pdu_do_field       field_do;  /** TP-Originating-Address */
/* TODO: Seems dcs and pid are in wrong order in the code compared to 3GPP TS 23.040 chapter 9.2.2.1 */
	struct pdu_dcs_field      field_dcs; /** TP-Data-Coding-Scheme */
	uint8_t                   field_pid; /** TP-Protocol-Identifier */
	struct sms_deliver_time   timestamp; /** TP-Service-Centre-Time-Stamp */
	uint8_t                   field_udl; /** TP-User-Data-Length */
	uint8_t                   field_ud[140]; /** TP-User-Data */ 
};

static uint8_t swap_nibbles(uint8_t value)
{
	return ((value&0x0f)<<4) | ((value&0xf0)>>4);
}

static int decode_pdu_deliver_header(struct parser *parser, uint8_t *buf)
{
	uint8_t smsc_size = *buf;
	buf += smsc_size + 1;

	DELIVER_DATA(parser)->field_header = 
		*((struct pdu_deliver_header*)buf);

	return smsc_size + 2;
}

static int decode_pdu_do_field(struct parser *parser, uint8_t *buf)
{

	DELIVER_DATA(parser)->field_do.length   = (uint8_t)*buf++;
	DELIVER_DATA(parser)->field_do.adr_type = (uint8_t)*buf++;

	memcpy(DELIVER_DATA(parser)->field_do.adr,
	       buf, 
	       DELIVER_DATA(parser)->field_do.length/2);

	for(int i=0;i<DELIVER_DATA(parser)->field_do.length/2;i++) {
		DELIVER_DATA(parser)->field_do.adr[i] = 
			swap_nibbles(DELIVER_DATA(parser)->field_do.adr[i]);
	}
	
	return 2+(DELIVER_DATA(parser)->field_do.length/2);
}

static int decode_pdu_pid_field(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_pid = (uint8_t)*buf;

	return 1;
}

static int decode_pdu_dcs_field(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_dcs = *((struct pdu_dcs_field*)buf);

	return 1;
}

static int decode_pdu_scts_field(struct parser *parser, uint8_t *buf)
{
	int tmp_tz;
	
	DELIVER_DATA(parser)->timestamp.year   = swap_nibbles(*(buf++));
	DELIVER_DATA(parser)->timestamp.month  = swap_nibbles(*(buf++));
	DELIVER_DATA(parser)->timestamp.day    = swap_nibbles(*(buf++));
	DELIVER_DATA(parser)->timestamp.hour   = swap_nibbles(*(buf++));
	DELIVER_DATA(parser)->timestamp.minute = swap_nibbles(*(buf++));
	DELIVER_DATA(parser)->timestamp.second = swap_nibbles(*(buf++));

	tmp_tz = ((*buf&0xf7) * 15) / 60;

	if(*buf&0x08) {
		tmp_tz = -(tmp_tz);
	}

	DELIVER_DATA(parser)->timestamp.timezone = tmp_tz;

	return SCTS_FIELD_SIZE;
}

static int decode_pdu_udl_field(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_udl = (uint8_t)*buf;

	return 1;
}

static int decode_pdu_ud_field_7bit(struct parser *parser, uint8_t *buf)
{
	uint8_t mask           = 0x7f;
	uint8_t shift;
	uint8_t remainder_bits = 0;
	uint8_t payload_ofs    = 0;
	uint8_t length         = parser->data_length - parser->buf_pos;

	if(length > parser->payload_buf_size) {
		return -EMSGSIZE;
	}

	for(int i=0;i<length;i++) {
		if(i%7) { // If this is the first byte of the seven byte sequence (divisible by seven)
			mask >>= 1; // Shift mask to right by a bit
		} else {
			if (i>0) { // Done only if this is not the first byte we are handling
				parser->payload[payload_ofs++] =
					(uint8_t)(remainder_bits);

				mask           = 0x7f;
				remainder_bits = 0;
			}
		}

		// What's the byte number here divisble by 7
		shift = i%7;

		// Set current value to be buf[i] shifted left based on which byte in the 7 byte sequence we are handling.
		// And or the remaining bits from the previous number
		parser->payload[payload_ofs++] =
			(uint8_t)(((buf[i]&mask)<<(shift))|remainder_bits);

		// Take the remaining bits of bit[i] that were not set into current value
		remainder_bits = (buf[i]&(~mask))>>(7-(shift));

		if(payload_ofs>parser->payload_buf_size) {
			break;
		}
	}

	if(payload_ofs != DELIVER_DATA(parser)->field_udl) {
		return -EMSGSIZE;
	} else {
		return payload_ofs;
	}
}

static int decode_pdu_ud_field_8bit(struct parser *parser, uint8_t *buf)
{
	uint32_t length = DELIVER_DATA(parser)->field_udl;

	if(length>parser->payload_buf_size) {
		return -EMSGSIZE;
	}

	memcpy(parser->payload, buf, length);

	return length;
}

static int decode_pdu_deliver_message(struct parser *parser, uint8_t *buf)
{
	switch(DELIVER_DATA(parser)->field_dcs.alphabet) {
		case 0:
			return decode_pdu_ud_field_7bit(parser, buf);
			break;
		case 1:
			return decode_pdu_ud_field_8bit(parser, buf);
			break;
		default:
			return -ENOTSUP;
	};

	return 0;
}

const static parser_module sms_pdu_deliver_parsers[] = {
		decode_pdu_deliver_header,
		decode_pdu_do_field,
		decode_pdu_pid_field,
		decode_pdu_dcs_field,
		decode_pdu_scts_field,
		decode_pdu_udl_field,
	};

static void *sms_deliver_get_parsers(void) 
{
	return (parser_module*)sms_pdu_deliver_parsers;
}

static void *sms_deliver_get_decoder(void)
{
	return decode_pdu_deliver_message;
}

static int sms_deliver_get_parser_count(void)
{
	return sizeof(sms_pdu_deliver_parsers) /
			sizeof(sms_pdu_deliver_parsers[0]);
}

static uint32_t sms_deliver_get_data_size(void)
{
	return sizeof(struct pdu_deliver_data);
}

static int sms_deliver_get_header(struct parser *parser, void *header)
{
	struct sms_deliver_header *sms_header = header;

	memcpy(&sms_header->time,
	       &DELIVER_DATA(parser)->timestamp,
	       sizeof(struct sms_deliver_time));

	sms_header->protocol_id       = DELIVER_DATA(parser)->field_pid;

	/* 7-bit encodig will always be returned as 8-bit by the parser */
	if(DELIVER_DATA(parser)->field_dcs.alphabet < 2) {
		sms_header->alphabet = GSM_ENCODING_8BIT;
	} else {
		sms_header->alphabet = GSM_ENCODING_UCS2;
	}

	sms_header->compressed =
		(bool)DELIVER_DATA(parser)->field_dcs.compressed;

	sms_header->presence_of_class =
		(bool)DELIVER_DATA(parser)->field_dcs.presence_of_class;

	sms_header->class = DELIVER_DATA(parser)->field_dcs.class;

	sms_header->service_center_address.length = parser->buf[0];
	sms_header->service_center_address.type   = 0;
	memcpy(sms_header->service_center_address.address,
	       &parser->buf[1],
	       parser->buf[0]);

	sms_header->orginator_address.length =
		DELIVER_DATA(parser)->field_do.length;
	sms_header->orginator_address.type   =
		DELIVER_DATA(parser)->field_do.adr_type;

	memcpy(sms_header->orginator_address.address,
	       DELIVER_DATA(parser)->field_do.adr,
	       DELIVER_DATA(parser)->field_do.length);

	return 0;
}

const static struct parser_api sms_deliver_api = {
	.data_size        = sms_deliver_get_data_size,
	.get_parsers      = sms_deliver_get_parsers,
	.get_decoder      = sms_deliver_get_decoder,
	.get_parser_count = sms_deliver_get_parser_count,
	.get_header       = sms_deliver_get_header,
};

void *sms_deliver_get_api(void)
{
	return (struct parser_api*)&sms_deliver_api;
}

