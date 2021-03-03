/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdint.h>
#include <stdbool.h>

#ifndef _PARSER_H_
#define _PARSER_H_

/*
 * Maximum length of a valid SMS message is 175 bytes so we'll reserve buffer
 * of 180 bytes to be safe and we are able to handle properly few extra bytes.
 * 175 is result of the following calculation of maximum field lengths:
 *   12: SMSC address
 *    4: Misc bytes in SMS-DELIVER msg:
 *       First byte with several bit fields, TP-PID, TP-DCS, TP-UDL.
 *   12: Originating address (phone number)
 *    7: Timestamp
 *  140: User data
 */
#define PARSER_BUF_SIZE 180

/* Forward declaration of the parser struct */
struct parser;

typedef int (*parser_module)(struct parser *parser, uint8_t *buf);

struct parser_api {
	uint32_t (*data_size)(void);
	void*    (*get_parsers)(void);
	void*    (*get_decoder)(void);
	int      (*get_parser_count)(void);
	int      (*get_header)(struct parser *parser, void *header);
};

struct parser {
	uint8_t             buf_pos;
	uint8_t             buf[PARSER_BUF_SIZE];

	uint8_t             *payload;
	uint8_t             payload_buf_size;
	uint8_t             payload_pos;

	void                *data;
	uint16_t            data_length;

	struct parser_api   *api;
};

/** @brief Parser instance creation
 *
 * @details This function is used to create a new parser instance
 *
 * @param[in] parser Pointer to parser instance data struct
 * @param[in] api    Pointer to parser_api struct with an parser implementation
 *
 * @return             Returns 0 if initialization was successful,
 *                     otherwise negative value
 */
int parser_create(struct parser *parser, struct parser_api *api);

/** @brief Parser instance deletion
 *
 * @details This function will destroy a parser instance and free up any memory
 *          used.
 *
 * @param[in] parser Pointer to parser instance data struct
 *
 * @return             Returns 0 if initialization was successful,
 *                     otherwise negative value
 */
int parser_delete(struct parser *parser);

/** @brief Parse ASCII formatted hex string
 *
 * @details This function will take hex data as an 0-terminated ASCII string.
 *
 * @param[in] parser Pointer to parser instance data struct
 * @param[in] data   Pointer to a HEX formatted ASCII string containing the
                     data to be parsed
 *
 * @return             Returns 0 if initialization was successful,
 *                     otherwise negative value
 */
int parser_process_str(struct parser *parser, char *data);

/** @brief Parse raw data
 *
 * @details This function will take data as an uint8_t data buffer.
 *
 * @param[in] parser Pointer to parser instance data struct
 * @param[in] data   Pointer to a data buffer withthe data to be parsed
 * @param[in] length Length of the data buffer
 *
 * @return             Returns 0 if initialization was successful,
 *                     otherwise negative value
 */
int parser_process_raw(struct parser *parser, uint8_t *data, uint8_t length);

/** @brief Get the payload in the data
 *
 * @details This function will fill a user supplied buffer with payload data
 *
 * @param[in] parser   Pointer to parser instance data struct
 * @param[in] buf      A user supplied buffer to put payload data in
 * @param[in] buf_size How much can be stored in the buffer
 *
 * @return             Returns 0 if initialization was successful,
 *                     otherwise negative value
 */
int parser_get_payload(struct parser *parser, char *buf, uint8_t buf_size);

/** @brief Get the header 
 *
 * @details This function will fill a databuffer with message header
	    information. The header structure is defined in the parser
	    implementation.
 *
 * @param[in] parser   Pointer to parser instance data struct
 * @param[in] header   A buffer big enough to hold the header information
 *
 * @return             Returns 0 if initialization was successful,
 *                     otherwise negative value
 */
int parser_get_header(struct parser *parser, void *header);

#endif /* _PARSER_H_ */


