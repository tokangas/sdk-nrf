/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <string.h>
#include <stdio.h>
#include <zephyr.h>
#include <modem/sms.h>
#include <logging/log.h>

#include "sms_deliver.h"
#include "parser.h"
#include "string_conversion.h"

LOG_MODULE_DECLARE(sms, CONFIG_SMS_LOG_LEVEL);

/** @brief Maximum length of SMS address, i.e., phone number, in octets. */
#define SMS_MAX_ADDRESS_LEN_OCTETS 10

/** @brief Length of TP-Service-Centre-Time-Stamp field. */
#define SCTS_FIELD_SIZE 7

/** @brief Convenience macro to access parser data. */
#define DELIVER_DATA(parser_data) ((struct pdu_deliver_data*)parser_data->data)

/**
 * @brief First byte of SMS-DELIVER PDU in 3GPP TS 23.040 chapter 9.2.2.1.
 */
struct pdu_deliver_header {
	uint8_t mti:2;  /** TP-Message-Type-Indicator */
	uint8_t mms:1;  /** TP-More-Messages-to-Send */
	uint8_t lp:1;   /** TP-Loop-Prevention */
	uint8_t :1;     /** Empty bit */
	uint8_t sri:1;  /** TP-Status-Report-Indication */
	uint8_t udhi:1; /** TP-User-Data-Header-Indicator */
	uint8_t rp:1;   /** TP-Reply-Path */
};

/**
 * @brief Data Coding Scheme (DCS) in 3GPP TS 23.038 chapter 4.
 * 
 * @details This encoding applies if bits 7..6 are 00.
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

/**
 * @brief SMS-DELIVER PDU fields specified in 3GPP TS 23.040 chapter 9.2.2.1
 */
struct pdu_deliver_data {
	struct pdu_deliver_header   field_header; /** First byte of header */
	struct sms_address          field_oa;  /** TP-Originating-Address */
	uint8_t                     field_pid; /** TP-Protocol-Identifier */
	struct pdu_dcs_field        field_dcs; /** TP-Data-Coding-Scheme */
	struct sms_time             timestamp; /** TP-Service-Centre-Time-Stamp */
	uint8_t                     field_udl; /** TP-User-Data-Length */
	uint8_t                     field_udhl; /** User Data Header Length */
	struct sms_udh_app_port     field_udh_app_port; /** Port addressing */
	struct sms_udh_concatenated field_udh_concatenated; /** Concatenation */
	uint8_t                     field_ud[140]; /** TP-User-Data */
};

/**
 * @brief Swap upper and lower 4 bits between each other.
 */
static uint8_t swap_nibbles(uint8_t value)
{
	return ((value&0x0f)<<4) | ((value&0xf0)>>4);
}

/**
 * @brief Converts an octet having two semi-octets into a decimal.
 * 
 * @details Semi-octet representation is explained in 3GPP TS 23.040 Section 9.1.2.3.
 * An octet has semi-octets in the following order:
 *   semi-octet-digit2, semi-octet-digit1
 * Octet for decimal number '21' is hence represented as semi-octet bits:
 *   00010010
 * This function is needed in timestamp (TP SCTS) conversion that is specified
 * in 3GPP TS 23.040 Section 9.2.3.11.
 * 
 * @param[in] value Octet to be converted.
 * 
 * @return Decimal value.
 */
static uint8_t semioctet_to_dec(uint8_t value)
{
	/* 4 LSBs represent decimal that should be multiplied by 10. */
	/* 4 MSBs represent decimal that should be add as is. */
	return ((value & 0xf0) >> 4) + ((value & 0x0f) * 10);
}

/**
 * @brief Convert phone number into string format.
 * 
 * @param[in] number Number in semi-octet representation.
 * @param[in] number_length Number length 
 * @param[out] str_number Output buffer where number is stored. Size shall be at minimum twice the
 *                        number length rounded up.
 */
static void convert_number_to_str(uint8_t *number, uint8_t number_length, char *str_number)
{
	/* Copy and log address string */
	uint8_t length = number_length / 2;
	bool fill_bits = false;
	if (number_length % 2 == 1) {
		/* There is one more number in semi-octet and 4 fill bits*/
		length++;
		fill_bits = true;
	}

	uint8_t hex_str_index = 0;
	for (int i = 0; i < length; i++) {
		/* Handle most significant 4 bits */
		uint8_t number_value = (number[i] & 0xF0) >> 4;
		if (number_value >= 10) {
			LOG_WRN("Single number in phone number is higher than 10: index=%d, number_value=%d, lower semi-octet",
				i, number_value);
		}
		sprintf(str_number + hex_str_index, "%d", number_value);

		if (i < length - 1 || !fill_bits) {
			/* Handle least significant 4 bits */
			uint8_t number_value = number[i] & 0x0F;
			if (number_value >= 10) {
				LOG_WRN("Single number in phone number is higher than 10: index=%d, number_value=%d, lower semi-octet",
					i, number_value);
			}
			sprintf(str_number + hex_str_index + 1,	"%d", number_value);
		}
		hex_str_index += 2;
	}
	str_number[hex_str_index] = '\0';
}

/**
 * @brief Decode SMS service center number specified in 3GPP TS 24.011 Section 8.2.5.1.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_deliver_smsc(struct parser *parser, uint8_t *buf)
{
	uint8_t smsc_size = *buf;
	buf += smsc_size + 1;

	LOG_DBG("SMSC size: %d", smsc_size);

	return smsc_size + 1;
}

/**
 * @brief Decode first byte of SMS-DELIVER header as specified in 3GPP TS 23.040 Section 9.2.2.1.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_deliver_header(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_header = *((struct pdu_deliver_header*)buf);

	LOG_DBG("SMS header 1st byte: 0x%02X", *buf);

	LOG_DBG("TP-Message-Type-Indicator: %d", DELIVER_DATA(parser)->field_header.mti);
	LOG_DBG("TP-More-Messages-to-Send: %d", DELIVER_DATA(parser)->field_header.mms);
	LOG_DBG("TP-Status-Report-Indication: %d", DELIVER_DATA(parser)->field_header.sri);
	LOG_DBG("TP-User-Data-Header-Indicator: %d", DELIVER_DATA(parser)->field_header.udhi);
	LOG_DBG("TP-Reply-Path: %d", DELIVER_DATA(parser)->field_header.rp);

	return 1;
}

/**
 * @brief Decode TP-Originating-Address as specified in 3GPP TS 23.040 Section 9.2.3.7 and 9.1.2.5.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_oa_field(struct parser *parser, uint8_t *buf)
{
	uint8_t address[SMS_MAX_ADDRESS_LEN_OCTETS];

	DELIVER_DATA(parser)->field_oa.length = (uint8_t)*buf++;
	DELIVER_DATA(parser)->field_oa.type = (uint8_t)*buf++;

	LOG_DBG("Address-Length: %d", DELIVER_DATA(parser)->field_oa.length);
	LOG_DBG("Type-of-Address: 0x%02X", DELIVER_DATA(parser)->field_oa.type);

	if (DELIVER_DATA(parser)->field_oa.length > SMS_MAX_ADDRESS_LEN_CHARS) {
		LOG_ERR("Maximum address length (%d) exceeded %d. Aborting decoding.",
			SMS_MAX_ADDRESS_LEN_OCTETS,
			DELIVER_DATA(parser)->field_oa.length);
		return -EINVAL;
	}

	uint8_t length = DELIVER_DATA(parser)->field_oa.length / 2;
	if (DELIVER_DATA(parser)->field_oa.length % 2 == 1) {
		/* There is an extra number in semi-octet and fill bits*/
		length++;
	}

	memcpy(address, buf, length);

	for (int i = 0; i < length; i++) {
		address[i] = swap_nibbles(address[i]);
	}

	convert_number_to_str(
		address,
		DELIVER_DATA(parser)->field_oa.length,
		DELIVER_DATA(parser)->field_oa.address_str);

	/* 2 for length and type fields */
	return 2 + length;
}

/**
 * @brief Decode TP-Protocol-Identifier as specified in 3GPP TS 23.040 Section 9.2.3.9.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_pid_field(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_pid = (uint8_t)*buf;

	LOG_DBG("TP-Protocol-Identifier: %d", DELIVER_DATA(parser)->field_pid);

	return 1;
}

/**
 * @brief Decode TP-Data-Coding-Scheme as specified in 3GPP TS 23.038 Section 4.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_dcs_field(struct parser *parser, uint8_t *buf)
{
	uint8_t value = *buf;
	if ((value & 0b11000000) == 0) {
		/* If bits 7..6 of the Coding Group Bits are 00 */
		DELIVER_DATA(parser)->field_dcs = *((struct pdu_dcs_field*)&value);

	} else if (((value & 0b11110000) >> 4) == 0b1111) {
		/* If bits 7..4 of the Coding Group Bits are 1111,
		 * only first 3 bits are meaningful and they match to
		 * the first 3 bits when Coding Group Bits 7..6 are 00 */
		uint8_t temp = value & 0b00000111;
		DELIVER_DATA(parser)->field_dcs = *(struct pdu_dcs_field*)&temp;
		/* Additionally, to convert Coding Group Bits 7..4=1111 to same
		 * meaning as 7..6=00, message class presence bit should be set. */
		DELIVER_DATA(parser)->field_dcs.presence_of_class = 1;
	}

	LOG_DBG("TP-Data-Coding-Scheme: 0x%02X", *buf);

	return 1;
}

/**
 * @brief Decode TP-Service-Centre-Time-Stamp as specified in 3GPP TS 23.040 Section 9.2.3.11.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_scts_field(struct parser *parser, uint8_t *buf)
{
	int tmp_tz;
	
	DELIVER_DATA(parser)->timestamp.year   = semioctet_to_dec(*(buf++));
	DELIVER_DATA(parser)->timestamp.month  = semioctet_to_dec(*(buf++));
	DELIVER_DATA(parser)->timestamp.day    = semioctet_to_dec(*(buf++));
	DELIVER_DATA(parser)->timestamp.hour   = semioctet_to_dec(*(buf++));
	DELIVER_DATA(parser)->timestamp.minute = semioctet_to_dec(*(buf++));
	DELIVER_DATA(parser)->timestamp.second = semioctet_to_dec(*(buf++));

	tmp_tz = ((*buf&0xf7) * 15) / 60;

	if(*buf&0x08) {
		tmp_tz = -(tmp_tz);
	}

	DELIVER_DATA(parser)->timestamp.timezone = tmp_tz;

	return SCTS_FIELD_SIZE;
}

/**
 * @brief Decode TP-User-Data-Length as specified in 3GPP TS 23.040 Section 9.2.3.16.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_udl_field(struct parser *parser, uint8_t *buf)
{
	DELIVER_DATA(parser)->field_udl = (uint8_t)*buf;

	LOG_DBG("TP-User-Data-Length: %d", DELIVER_DATA(parser)->field_udl);

	return 1;
}

/**
 * @brief Check validity of concatenated message information element.
 * 
 * @details This is specified in 3GPP TS 23.040 Section 9.2.3.24.1 and 9.2.3.24.8.
 * 
 * @param[in,out] parser Parser instance containing the fields to check. If invalid fields are
 *                       detected, all concatenation fields are reset and whole information
 *                       element is ignored.
 */
static void concatenated_udh_ie_validity_check(struct parser *parser)
{
	LOG_DBG("UDH concatenated, reference number: %d",
		DELIVER_DATA(parser)->field_udh_concatenated.ref_number);
	LOG_DBG("UDH concatenated, total number of messages: %d",
		DELIVER_DATA(parser)->field_udh_concatenated.total_msgs);
	LOG_DBG("UDH concatenated, sequence number: %d",
		DELIVER_DATA(parser)->field_udh_concatenated.seq_number);

	if (DELIVER_DATA(parser)->field_udh_concatenated.total_msgs == 0) {
		LOG_ERR("Total number of concatenated messages must be higher than 0, ignoring concatenated info");
		DELIVER_DATA(parser)->field_udh_concatenated.present = false;
		DELIVER_DATA(parser)->field_udh_concatenated.ref_number = 0;
		DELIVER_DATA(parser)->field_udh_concatenated.total_msgs = 0;
		DELIVER_DATA(parser)->field_udh_concatenated.seq_number = 0;

	} else if (DELIVER_DATA(parser)->field_udh_concatenated.seq_number == 0 ||
			(DELIVER_DATA(parser)->field_udh_concatenated.seq_number >
			DELIVER_DATA(parser)->field_udh_concatenated.total_msgs)) {

		LOG_ERR("Sequence number of current concatenated message (%d) must be higher than 0 and smaller or equal than total number of messages (%d), ignoring concatenated info",
			DELIVER_DATA(parser)->field_udh_concatenated.seq_number,
			DELIVER_DATA(parser)->field_udh_concatenated.total_msgs);
		DELIVER_DATA(parser)->field_udh_concatenated.present = false;
		DELIVER_DATA(parser)->field_udh_concatenated.ref_number = 0;
		DELIVER_DATA(parser)->field_udh_concatenated.total_msgs = 0;
		DELIVER_DATA(parser)->field_udh_concatenated.seq_number = 0;
	}
}

/**
 * @brief Decode User Data Header Information Elements as specified
 * in 3GPP TS 23.040 Section 9.2.3.24.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static void decode_pdu_udh_ie(struct parser *parser, uint8_t *buf)
{
	/* Start from 1 as 0 index has UDHL */
	uint8_t ofs = 1;

	while (ofs < DELIVER_DATA(parser)->field_udhl) {
		int ie_id     = buf[ofs++];
		int ie_length = buf[ofs++];

		LOG_DBG("User Data Header id=0x%02X, length=%d", ie_id, ie_length);

		if (ie_length > DELIVER_DATA(parser)->field_udhl - ofs) {
			/* 3GPP TS 23.040 Section 9.2.3.24:
			     If the length of the User Data Header is such that
			     there are too few or too many octets in the final
			     Information Element then the whole User Data Header shall be ignored.
			*/
			LOG_DBG("User Data Header Information Element too long (%d) for remaining length (%d)",
				ie_length, DELIVER_DATA(parser)->field_udhl - ofs);

			/* Clean UDH information */
			DELIVER_DATA(parser)->field_udh_concatenated.present = false;
			DELIVER_DATA(parser)->field_udh_concatenated.ref_number = 0;
			DELIVER_DATA(parser)->field_udh_concatenated.total_msgs = 0;
			DELIVER_DATA(parser)->field_udh_concatenated.seq_number = 0;
			DELIVER_DATA(parser)->field_udh_app_port.present = false;
			DELIVER_DATA(parser)->field_udh_app_port.dest_port = 0;
			DELIVER_DATA(parser)->field_udh_app_port.src_port = 0;
			break;
		}

		switch (ie_id) {
		case 0x00: /* Concatenated short messages, 8-bit reference number */
			if (ie_length != 3) {
				LOG_ERR("Concatenated short messages, 8-bit reference number: IE length 3 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_concatenated.ref_number = buf[ofs];
			DELIVER_DATA(parser)->field_udh_concatenated.total_msgs = buf[ofs+1];
			DELIVER_DATA(parser)->field_udh_concatenated.seq_number = buf[ofs+2];
			DELIVER_DATA(parser)->field_udh_concatenated.present = true;

			concatenated_udh_ie_validity_check(parser);
			break;

		case 0x04: /* Application port addressing scheme, 8 bit address */
			if (ie_length != 2) {
				LOG_ERR("Application port addressing scheme, 8 bit address: IE length 2 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_app_port.dest_port = buf[ofs];
			DELIVER_DATA(parser)->field_udh_app_port.src_port = buf[ofs+1];
			DELIVER_DATA(parser)->field_udh_app_port.present = true;

			LOG_DBG("UDH port scheme, destination port: %d",
				DELIVER_DATA(parser)->field_udh_app_port.dest_port);
			LOG_DBG("UDH port scheme, source port: %d",
				DELIVER_DATA(parser)->field_udh_app_port.src_port);
			break;

		case 0x05: /* Application port addressing scheme, 16 bit address */
			if (ie_length != 4) {
				LOG_ERR("Application port addressing scheme, 16 bit address: IE length 4 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_app_port.dest_port = buf[ofs]<<8;
			DELIVER_DATA(parser)->field_udh_app_port.dest_port |= buf[ofs+1];

			DELIVER_DATA(parser)->field_udh_app_port.src_port = buf[ofs+2]<<8;
			DELIVER_DATA(parser)->field_udh_app_port.src_port |= buf[ofs+3];
			DELIVER_DATA(parser)->field_udh_app_port.present = true;

			LOG_DBG("UDH port scheme, destination port: %d",
				DELIVER_DATA(parser)->field_udh_app_port.dest_port);
			LOG_DBG("UDH port scheme, source port: %d",
				DELIVER_DATA(parser)->field_udh_app_port.src_port);

			break;
		case 0x08: /* Concatenated short messages, 16-bit reference number */
			if (ie_length != 4) {
				LOG_ERR("Concatenated short messages, 16-bit reference number: IE length 4 required, %d received",
					ie_length);
				break;
			}
			DELIVER_DATA(parser)->field_udh_concatenated.ref_number = buf[ofs]<<8;
			DELIVER_DATA(parser)->field_udh_concatenated.ref_number |= buf[ofs+1];
			DELIVER_DATA(parser)->field_udh_concatenated.total_msgs = buf[ofs+2];
			DELIVER_DATA(parser)->field_udh_concatenated.seq_number = buf[ofs+3];
			DELIVER_DATA(parser)->field_udh_concatenated.present = true;

			concatenated_udh_ie_validity_check(parser);
			break;

		default:
			LOG_WRN("Ignoring not supported User Data Header information element id=0x%02X, length=%d",
				ie_id, ie_length);
			break;
		}
		ofs += ie_length;
	}
}

/**
 * @brief Decode User Data Header as specified in 3GPP TS 23.040 Section 9.2.3.24.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_udh(struct parser *parser, uint8_t *buf)
{
	/* Check if TP-User-Data-Header-Indicator is not set */
	if (!DELIVER_DATA(parser)->field_header.udhi) {
		return 0;
	}

	DELIVER_DATA(parser)->field_udhl = buf[0];
	LOG_DBG("User Data Header Length: %d", DELIVER_DATA(parser)->field_udhl);
	DELIVER_DATA(parser)->field_udhl += 1;  /* +1 for length field itself */

	if (DELIVER_DATA(parser)->field_udhl > DELIVER_DATA(parser)->field_udl) {
		LOG_ERR("User Data Header Length %d is bigger than User-Data-Length %d",
			DELIVER_DATA(parser)->field_udhl,
			DELIVER_DATA(parser)->field_udl);
		return -EMSGSIZE;
	}
	if (DELIVER_DATA(parser)->field_udhl > parser->buf_size - parser->buf_pos) {
		LOG_ERR("User Data Header Length %d is bigger than remaining input data length %d",
			DELIVER_DATA(parser)->field_udhl,
			parser->buf_size - parser->buf_pos);
		return -EMSGSIZE;
	}

	decode_pdu_udh_ie(parser, buf);

	/* Returning zero for GSM 7bit encoding so that the start of the
	   payload won't move further as SMS 7bit encoding is done for UDH
	   also to get the fill bits correctly for the actual user data.
	   For any other encoding, we'll return User Data Header Length.
	*/
	if (DELIVER_DATA(parser)->field_dcs.alphabet != 0) {
		return DELIVER_DATA(parser)->field_udhl;
	} else {
		return 0;
	}
}

/**
 * @brief Decode user data for GSM 7 bit coding scheme.
 * 
 * @details This will decode the user data based on GSM 7 bit coding scheme and packing
 * specified in 3GPP TS 23.038 Section 6.1.2.1 and 6.2.1.
 * User Data Header is also taken into account as specified in 3GPP TS 23.040 Section 9.2.3.24.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_ud_field_7bit(struct parser *parser, uint8_t *buf)
{
	if (DELIVER_DATA(parser)->field_udl > 160) {
		LOG_ERR("User Data Length exceeds maximum number of characters (160) in SMS spec");
		return -EMSGSIZE;
	}

	/* Data length to be used is the minimum from the
	   remaining bytes in the input buffer and
	   length indicated by User-Data-Length.
	   User-Data-Header-Length is taken into account later
	   because UDH is part of GSM 7bit encoding w.r.t.
	   fill bits for the actual data. */
	uint16_t actual_data_length =
		(parser->buf_size - parser->payload_pos) * 8 / 7;
	actual_data_length = MIN(actual_data_length,
				DELIVER_DATA(parser)->field_udl);

	/* Convert GSM 7bit data to ASCII characters */
	uint8_t temp_buf[160];
	uint8_t length = string_conversion_gsm7bit_to_ascii(
		buf, temp_buf, actual_data_length, true);

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
	   User Data Header but minimum is 0. In some corner cases this would
	   result in negative value causing crashes. */
	int length_udh_skipped = (length >= skip_septets) ?
		(int)(length - skip_septets) : 0;

	/* Verify that payload buffer is not too short */
	__ASSERT(length_udh_skipped <= parser->payload_buf_size,
		"GSM 7bit User-Data-Length shorter than output buffer");

	/* Copy decoded data/text into the output buffer */
	memcpy(parser->payload, temp_buf + skip_septets, length_udh_skipped);

	return length_udh_skipped;
}

/**
 * @brief Decode user data for 8 bit data coding scheme.
 * 
 * @details This will essentially just copy the data from the SMS-DELIVER message into the
 * decoded payload as 8bit data means there is really no coding scheme.
 *
 * User Data Header is also taken into account as specified in 3GPP TS 23.040 Section 9.2.3.24.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Number of parsed bytes.
 */
static int decode_pdu_ud_field_8bit(struct parser *parser, uint8_t *buf)
{
	/* Data length to be used is the minimum from the
	   remaining bytes in the input buffer and
	   length indicated by User-Data-Length taking into account
	   User-Data-Header-Length. */
	uint32_t actual_data_length =
		MIN(parser->buf_size - parser->payload_pos,
		    DELIVER_DATA(parser)->field_udl - DELIVER_DATA(parser)->field_udhl);

	__ASSERT(parser->buf_size >= parser->payload_pos,
		"Data length smaller than data iterator");
	__ASSERT(actual_data_length <= parser->payload_buf_size,
		"8bit User-Data-Length shorter than output buffer");

	memcpy(parser->payload, buf, actual_data_length);

	return actual_data_length;
}

/**
 * @brief Decode user data for SMS-DELIVER message based on data coding scheme.
 * 
 * @details User Data Header is also taken into account as specified in
 * 3GPP TS 23.040 Section 9.2.3.24.
 * 
 * @param[in,out] parser Parser instance.
 * @param[in] buf Buffer containing PDU and pointing to this field.
 * 
 * @return Non-negative number indicates number of parsed bytes. Negative value is an error code.
 */
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

/**
 * @brief List of parser required to parse entire SMS-DELIVER PDU.
 */
const static parser_module sms_pdu_deliver_parsers[] = {
	decode_pdu_deliver_smsc,
	decode_pdu_deliver_header,
	decode_pdu_oa_field,
	decode_pdu_pid_field,
	decode_pdu_dcs_field,
	decode_pdu_scts_field,
	decode_pdu_udl_field,
	decode_pdu_udh,
};

/**
 * @brief Return parsers.
 * 
 * @return Parsers.
 */
static void *sms_deliver_get_parsers(void) 
{
	return (parser_module*)sms_pdu_deliver_parsers;
}

/**
 * @brief Data decoder for the parser.
 */
static void *sms_deliver_get_decoder(void)
{
	return decode_pdu_deliver_message;
}

/**
 * @brief Return number of parsers.
 * 
 * @return Number of parsers.
 */
static int sms_deliver_get_parser_count(void)
{
	return sizeof(sms_pdu_deliver_parsers) /
			sizeof(sms_pdu_deliver_parsers[0]);
}

/**
 * @brief Return deliver data structure size to store all the information.
 * 
 * @return Data structure size.
 */
static uint32_t sms_deliver_get_data_size(void)
{
	return sizeof(struct pdu_deliver_data);
}

/**
 * @brief Get SMS-DELIVER header for given parser.
 * 
 * @param[in] parser Parser instance.
 * @param[out] header Output structure of type: struct sms_deliver_header*
 * 
 * @return Zero on success, otherwise error code.
 */
static int sms_deliver_get_header(struct parser *parser, void *header)
{
	struct sms_deliver_header *sms_header = header;

	memcpy(&sms_header->time, &DELIVER_DATA(parser)->timestamp, sizeof(struct sms_time));

	memcpy(&sms_header->originating_address, &DELIVER_DATA(parser)->field_oa,
		sizeof(struct sms_address));

	sms_header->app_port = DELIVER_DATA(parser)->field_udh_app_port;
	sms_header->concatenated = DELIVER_DATA(parser)->field_udh_concatenated;

	return 0;
}

/**
 * @brief Parser API functions for SMS-DELIVER PDU parsing.
 */
const static struct parser_api sms_deliver_api = {
	.data_size        = sms_deliver_get_data_size,
	.get_parsers      = sms_deliver_get_parsers,
	.get_decoder      = sms_deliver_get_decoder,
	.get_parser_count = sms_deliver_get_parser_count,
	.get_header       = sms_deliver_get_header,
};

/**
 * @brief Return SMS-DELIVER parser API.
 * 
 * @return SMS-DELIVER API structure of type struct parser_api*.
 */
void *sms_deliver_get_api(void)
{
	return (struct parser_api*)&sms_deliver_api;
}

int sms_deliver_pdu_parse(char *pdu, struct sms_data *data)
{
	struct parser sms_deliver;
	int err = 0;

	__ASSERT(pdu != NULL, "Parameter 'pdu' cannot be NULL.");
	__ASSERT(data != NULL, "Parameter 'data' cannot be NULL.");

	struct sms_deliver_header *header = &data->header.deliver;
	__ASSERT(header != NULL, "Parameter 'header' cannot be NULL.");
	memset(header, 0, sizeof(struct sms_deliver_header));

	err = parser_create(&sms_deliver, sms_deliver_get_api());
	if (err) {
		return err;
	}

	err = parser_process_str(&sms_deliver, pdu);
	if (err) {
		LOG_ERR("Parsing error (%d) in decoding SMS-DELIVER message due to no memory", err);
		return err;
	}

	parser_get_header(&sms_deliver, header);

	data->data_len = parser_get_payload(&sms_deliver,
					  data->data,
					  SMS_MAX_DATA_LEN_CHARS);

	if (data->data_len < 0) {
		LOG_ERR("Getting sms deliver payload failed: %d\n",
			data->data_len);
		return data->data_len;
	}

	LOG_DBG("Time:   %02x-%02x-%02x %02x:%02x:%02x",
		header->time.year,
		header->time.month,
		header->time.day,
		header->time.hour,
		header->time.minute,
		header->time.second);
	LOG_DBG("Text:   '%s'", log_strdup(data->data));

	LOG_DBG("Length: %d", data->data_len);

	parser_delete(&sms_deliver);
	return 0;
}
