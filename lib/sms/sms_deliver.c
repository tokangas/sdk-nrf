/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <zephyr.h>
#include <modem/sms.h>
#include <logging/log.h>

#include "sms_deliver.h"
#include "parser.h"
#include "string_conversion.h"

LOG_MODULE_DECLARE(sms, CONFIG_SMS_LOG_LEVEL);

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
	struct pdu_deliver_header   field_header;
	struct pdu_do_field         field_do;  /** TP-Originating-Address */
/* TODO: Seems dcs and pid are in wrong order in the code compared to 3GPP TS 23.040 chapter 9.2.2.1 */
	struct pdu_dcs_field        field_dcs; /** TP-Data-Coding-Scheme */
	uint8_t                     field_pid; /** TP-Protocol-Identifier */
	struct sms_deliver_time     timestamp; /** TP-Service-Centre-Time-Stamp */
	uint8_t                     field_udl; /** TP-User-Data-Length */
	uint8_t                     field_udhl; /** User Data Header Length */
	struct sms_udh_app_port     field_udh_app_port;
	struct sms_udh_concatenated field_udh_concatenated;
	uint8_t                     field_ud[140]; /** TP-User-Data */ 
};

static uint8_t swap_nibbles(uint8_t value)
{
	return ((value&0x0f)<<4) | ((value&0xf0)>>4);
}

static int decode_pdu_deliver_header(struct parser *parser, uint8_t *buf)
{
	uint8_t smsc_size = *buf;
	buf += smsc_size + 1;

	LOG_DBG("SMSC size: %d", smsc_size);

	DELIVER_DATA(parser)->field_header = 
		*((struct pdu_deliver_header*)buf);

	LOG_DBG("SMS header 1st byte: 0x%X", *buf);

	LOG_DBG("TP-Message-Type-Indicator: %d", DELIVER_DATA(parser)->field_header.mti);
	LOG_DBG("TP-More-Messages-to-Send: %d", DELIVER_DATA(parser)->field_header.mms);
	LOG_DBG("TP-Status-Report-Indication: %d", DELIVER_DATA(parser)->field_header.sri);
	LOG_DBG("TP-User-Data-Header-Indicator: %d", DELIVER_DATA(parser)->field_header.udhi);
	LOG_DBG("TP-Reply-Path: %d", DELIVER_DATA(parser)->field_header.rp);

	return smsc_size + 2;
}

static int decode_pdu_do_field(struct parser *parser, uint8_t *buf)
{

	DELIVER_DATA(parser)->field_do.length   = (uint8_t)*buf++;
	DELIVER_DATA(parser)->field_do.adr_type = (uint8_t)*buf++;

	LOG_DBG("Address-Length: %d", DELIVER_DATA(parser)->field_do.length);
	LOG_DBG("Type-of-Address: %02X", DELIVER_DATA(parser)->field_do.adr_type);

	uint8_t length = DELIVER_DATA(parser)->field_do.length / 2;
	if (DELIVER_DATA(parser)->field_do.length % 2 == 1) {
		/* There is an extra number in semi-octet and fill bits*/
		length++;
	}

	memcpy(DELIVER_DATA(parser)->field_do.adr,
	       buf, 
	       length);

	for(int i = 0; i < length; i++) {
		DELIVER_DATA(parser)->field_do.adr[i] = 
			swap_nibbles(DELIVER_DATA(parser)->field_do.adr[i]);
	}

	return 2 + length;
}

static int decode_pdu_pid_field(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_pid = (uint8_t)*buf;

	LOG_DBG("TP-Protocol-Identifier: %d", DELIVER_DATA(parser)->field_pid);

	return 1;
}

static int decode_pdu_dcs_field(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_dcs = *((struct pdu_dcs_field*)buf);

	LOG_DBG("TP-Data-Coding-Scheme: %02X", *buf);

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

	LOG_DBG("TP-User-Data-Length: %d", DELIVER_DATA(parser)->field_udl);

	return 1;
}

static int decode_pdu_udh(struct parser *parser, uint8_t *buf)
{	
	/* Check if TP-User-Data-Header-Indicator is not set */
	if (!DELIVER_DATA(parser)->field_header.udhi) {
		return 0;
	}

	uint8_t ofs=0;

	DELIVER_DATA(parser)->field_udhl = buf[ofs++];
	LOG_DBG("User Data Header Length: %d", DELIVER_DATA(parser)->field_udhl);
	DELIVER_DATA(parser)->field_udhl += 1;  /* +1 for length field itself */

	/* Reduce User-Data-length based on UDH length */
	/* TODO: Check what to do with this:
	int field_udl_old = DELIVER_DATA(parser)->field_udl;
	DELIVER_DATA(parser)->field_udl -= DELIVER_DATA(parser)->field_udhl;*/
	if (DELIVER_DATA(parser)->field_udhl > DELIVER_DATA(parser)->field_udl) {
		LOG_ERR("User Data Header Length %d is bigger than User-Data-Length %d",
			DELIVER_DATA(parser)->field_udhl,
			DELIVER_DATA(parser)->field_udl);
		return -EMSGSIZE;
	}
	/*LOG_DBG("User-Data-Length reduced from %d to %d",
		field_udl_old, DELIVER_DATA(parser)->field_udl);
	*/

	while (ofs < DELIVER_DATA(parser)->field_udhl) {
		int ie_id     = buf[ofs++];
		int ie_length = buf[ofs++];

		LOG_DBG("User Data Header id=0x%02X, length=%d", ie_id, ie_length);

		switch (ie_id) {
		case 0x00: /* Concatenated short messages, 8-bit reference number */
			if (ie_length != 3) {
				LOG_ERR("Concatenated short messages, 8-bit reference number: IE length 3 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_concatenated.ref_number = buf[ofs++];
			DELIVER_DATA(parser)->field_udh_concatenated.total_msgs = buf[ofs++];
			DELIVER_DATA(parser)->field_udh_concatenated.seq_number = buf[ofs++];

			DELIVER_DATA(parser)->field_udh_concatenated.present = true;

			LOG_DBG("UDH concatenated, reference number: %d", DELIVER_DATA(parser)->field_udh_concatenated.ref_number);
			LOG_DBG("UDH concatenated, total number of messages: %d", DELIVER_DATA(parser)->field_udh_concatenated.total_msgs);
			LOG_DBG("UDH concatenated, sequence number: %d", DELIVER_DATA(parser)->field_udh_concatenated.seq_number);

			if (DELIVER_DATA(parser)->field_udh_concatenated.total_msgs == 0) {
				LOG_ERR("Total number of concatenated message 0, ignoring concatenated info");
				DELIVER_DATA(parser)->field_udh_concatenated.present = false;
			}
			break;

		case 0x04: /* Application port addressing scheme, 8 bit address */
			if (ie_length != 2) {
				LOG_ERR("Application port addressing scheme, 8 bit address: IE length 2 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_app_port.dest_port = buf[ofs++];
			DELIVER_DATA(parser)->field_udh_app_port.src_port = buf[ofs++];

			DELIVER_DATA(parser)->field_udh_app_port.present = true;

			LOG_DBG("UDH port scheme, destination port: %d", DELIVER_DATA(parser)->field_udh_app_port.dest_port);
			LOG_DBG("UDH port scheme, source port: %d", DELIVER_DATA(parser)->field_udh_app_port.src_port);
			break;

		case 0x05: /* Application port addressing scheme, 16 bit address */
			if (ie_length != 4) {
				LOG_ERR("Application port addressing scheme, 16 bit address: IE length 4 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_app_port.dest_port = buf[ofs++]<<8;
			DELIVER_DATA(parser)->field_udh_app_port.dest_port |= buf[ofs++];

			DELIVER_DATA(parser)->field_udh_app_port.src_port = buf[ofs++]<<8;
			DELIVER_DATA(parser)->field_udh_app_port.src_port |= buf[ofs++];

			DELIVER_DATA(parser)->field_udh_app_port.present = true;

			LOG_DBG("UDH port scheme, destination port: %d", DELIVER_DATA(parser)->field_udh_app_port.dest_port);
			LOG_DBG("UDH port scheme, source port: %d", DELIVER_DATA(parser)->field_udh_app_port.src_port);

			break;
		case 0x08: /* Concatenated short messages, 16-bit reference number */
			if (ie_length != 4) {
				LOG_ERR("Concatenated short messages, 16-bit reference number: IE length 4 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_concatenated.ref_number = buf[ofs++]<<8;
			DELIVER_DATA(parser)->field_udh_concatenated.ref_number |= buf[ofs++];

			DELIVER_DATA(parser)->field_udh_concatenated.total_msgs = buf[ofs++];
			DELIVER_DATA(parser)->field_udh_concatenated.seq_number = buf[ofs++];

			DELIVER_DATA(parser)->field_udh_concatenated.present = true;

			LOG_DBG("UDH concatenated, reference number: %d", DELIVER_DATA(parser)->field_udh_concatenated.ref_number);
			LOG_DBG("UDH concatenated, total number of messages: %d", DELIVER_DATA(parser)->field_udh_concatenated.total_msgs);
			LOG_DBG("UDH concatenated, sequence number: %d", DELIVER_DATA(parser)->field_udh_concatenated.seq_number);

			if (DELIVER_DATA(parser)->field_udh_concatenated.total_msgs == 0) {
				LOG_ERR("Total number of concatenated message 0, ignoring concatenated info");
				DELIVER_DATA(parser)->field_udh_concatenated.present = false;
			}
			break;

		default:
			LOG_WRN("Ignoring not supported User Data Header information element id=0x%02X, length=%d", ie_id, ie_length);
			break;
		}
	}

	/* TODO: Returning zero so that the start of the payload won't move further as SMS 7bit encoding requires this.
	   This breaks 8bit "decoding" though so need to find a way to handle this.
	   Current implementation is NOT the way to go!!! */
	if (DELIVER_DATA(parser)->field_udh_app_port.present) {
		return DELIVER_DATA(parser)->field_udhl;
	} else {
		return 0;
	}
}

static int decode_pdu_ud_field_7bit(struct parser *parser, uint8_t *buf)
{
	if (DELIVER_DATA(parser)->field_udl > 160) {
		LOG_ERR("User Data Length exceeds maximum number of characters (160) in SMS spec");
		return -EMSGSIZE;
	}

	/* Convert GSM 7bit data to ASCII characters */
	uint8_t temp_buf[160];
	uint8_t length = string_conversion_gsm7bit_to_ascii(
		buf, temp_buf, DELIVER_DATA(parser)->field_udl, true);

	/* Check whether User Data Header is present.
	   If yes, we need to skip those septets in the temp_buf, which has
	   all of the data decoded including User Data Header. This is done
	   because the actual data/text is aligned into septet (7bit) boundary
	   after User Data Header. */
	uint8_t skip_bits = DELIVER_DATA(parser)->field_udhl * 8;
	uint8_t skip_septets = skip_bits / 7;
	if (skip_bits % 7 > 0) {
		skip_septets++;
	}

	/* Number of characters/bytes in the actual data which excludes
	   User Data Header */
	int length_udh_skipped = (int)(length - skip_septets);

	/* Verify that payload buffer is not too short */
	if (length_udh_skipped > parser->payload_buf_size) {
		LOG_ERR("Buffer for SMS data is too small (%d) for decoded data length %d. Discarding additional data.",
			parser->payload_buf_size, length_udh_skipped);
		length_udh_skipped = parser->payload_buf_size;
	}

	/* Copy decoded data/text into the output buffer */
	memcpy(parser->payload, temp_buf + skip_septets, length_udh_skipped);

	return length_udh_skipped;

#if 0
	uint8_t mask           = 0x7f;
	uint8_t shift;
	uint8_t remainder_bits = 0;
	uint16_t payload_ofs   = 0;
	uint16_t length        = parser->data_length - parser->buf_pos;

	LOG_DBG("Parser internals data_length=%d, buf_pos=%d, payload_buf_size=%d",
		parser->data_length,
		parser->buf_pos,
		parser->payload_buf_size);

	/* Skip septets of User Data Header */
	uint8_t skip_bits = DELIVER_DATA(parser)->field_udhl * 8;
	uint8_t skip_septets = skip_bits / 7;
	if (skip_bits % 7 > 0) {
		skip_septets++;
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

		/* What's the byte number here divisible by 7 */
		shift = i%7;
		/* Set current value to be buf[i] shifted left based on which
		   byte in the 7 byte sequence we are handling.
		   And or the remaining bits from the previous number */
		uint8_t data = (uint8_t)(((buf[i]&mask)<<(shift))|remainder_bits);
		if (i >= skip_septets) {
			parser->payload[payload_ofs++] = data;
		} else {
			LOG_DBG("Skipping user data header bytes in 7bit encoding septet=0x%02X", data);
		}
		/* Take the remaining bits of bit[i] that were not set
		   into current value */
		remainder_bits = (buf[i]&(~mask))>>(7-(shift));

		if(payload_ofs>parser->payload_buf_size) {
			LOG_WRN("Buffer for SMS data (%d) is too small",
				parser->payload_buf_size);
			break;
		}
	}

	if(payload_ofs + skip_septets != DELIVER_DATA(parser)->field_udl) {
		/* TODO: Check whether this if statement should just be removed */
		//return -EMSGSIZE;
		return payload_ofs;
	} else {
		return payload_ofs;
	}
#endif
}

static int decode_pdu_ud_field_8bit(struct parser *parser, uint8_t *buf)
{
	uint32_t length = DELIVER_DATA(parser)->field_udl -
			  DELIVER_DATA(parser)->field_udhl;

	if(length>parser->payload_buf_size) {
		return -EMSGSIZE;
	}

	memcpy(parser->payload, buf, length);

	return length;
}

static int decode_pdu_deliver_message(struct parser *parser, uint8_t *buf)
{
	/* TODO: There are other bits (bits 4 to 7) than alphabet we need to consider because alphabet is not what we expect in some cases */
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
		decode_pdu_udh,
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

	sms_header->ud_len = DELIVER_DATA(parser)->field_udl -
			     DELIVER_DATA(parser)->field_udhl;

	sms_header->app_port = DELIVER_DATA(parser)->field_udh_app_port;
	sms_header->concatenated = DELIVER_DATA(parser)->field_udh_concatenated;

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
