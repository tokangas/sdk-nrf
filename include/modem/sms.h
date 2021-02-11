/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SMS_H_
#define SMS_H_

/**
 * @file sms.h
 *
 * @defgroup sms SMS subscriber manager
 *
 * @{
 *
 * @brief Public APIs of the SMS subscriber manager module.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <zephyr/types.h>
#include <sys/types.h>

enum sms_type {
	SMS_TYPE_DELIVER = 0,
	SMS_TYPE_SUBMIT_REPORT
};

#define SMS_MAX_ADDRESS_LEN_OCTETS 10
#define SMS_MAX_ADDRESS_LEN_CHARS (2 * SMS_MAX_ADDRESS_LEN_OCTETS)

/** @brief SMS PDU data. */
struct sms_data {
	enum sms_type type;
	char *alpha;
	uint16_t length;
	char *pdu;
};

enum sms_deliver_alphabet {
	GSM_ENCODING_8BIT,
	GSM_ENCODING_UCS2,
};

enum sms_deliver_class {
	GSM_CLASS0,
	GSM_CLASS1,
	GSM_CLASS2,
	GSM_CLASS3,
};

struct sms_deliver_time {
	uint8_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	int8_t timezone;
};

struct sms_deliver_address {
	char    address_str[SMS_MAX_ADDRESS_LEN_CHARS + 1];
	uint8_t address[SMS_MAX_ADDRESS_LEN_OCTETS];
	uint8_t length;
	uint8_t type;
};

struct sms_udh_concatenated {
	bool present;
	uint16_t ref_number;
	uint8_t total_msgs;
	uint8_t seq_number;
};

struct sms_udh_app_port {
	bool present;
	uint16_t dest_port;
	uint16_t src_port;
};

struct sms_deliver_header {
	struct sms_deliver_time     time;
	uint8_t                     protocol_id;
	enum sms_deliver_alphabet   alphabet;
	bool                        compressed;
	bool                        presence_of_class;
	enum sms_deliver_class      class;
	struct sms_deliver_address  service_center_address;
	struct sms_deliver_address  orginator_address;
	uint8_t                     ud_len;
	struct sms_udh_app_port     app_port;
	struct sms_udh_concatenated concatenated;
	int			    data_len; /* TODO: Check if this is needed */
	char 			    *ud;
};

/** TODO: The function name is not good at the moment. It's a leftover when
 *        there was a plan to have sms_get_header() and sms_get_payload().
 *        Maybe this should be sms_decode.
 * 
 * @brief Decode received SMS message.
 * 
 * @param in Received SMS PDU that is still decoded.
 * @param out SMS message decoded into a structure.
 * 
 * @retval -EINVAL Invalid parameter.
 * @retval -ENOMEM No memory to register new observers.
 * @return Zero on success, otherwise error code.
 */
int sms_get_header(struct sms_data *in, struct sms_deliver_header *out);

/** @brief SMS listener callback function. */
typedef void (*sms_callback_t)(struct sms_data *const data, void *context);

/**
 * @brief Initialize the SMS subscriber module.
 *
 * @return Zero on success, or a negative error code. The EBUSY error
 *         indicates that one SMS client has already been registered.
 */
int sms_init(void);

/**
 * @brief Register a new listener.
 *
 * A listener is identified by a unique handle value. This handle should be used
 * to unregister the listener. A listener can be registered multiple times with
 * the same or a different context.
 *
 * @param listener Callback function. Cannot be null.
 * @param context User context. Can be null if not used.
 *
 * @retval -EINVAL Invalid parameter.
 * @retval -ENOMEM No memory to register new observers.
 * @return Handle identifying the listener,
 *         or a negative value if an error occurred.
 */
int sms_register_listener(sms_callback_t listener, void *context);

/**
 * @brief Unregister a listener.
 *
 * @param handle Handle identifying the listener to unregister.
 */
void sms_unregister_listener(int handle);

/**
 * @brief Uninitialize the SMS subscriber module.
 */
void sms_uninit(void);

/**
 * @brief Send SMS message.
 *
 * @param number Recipient number.
 * @param text Text to be sent.
 */
int sms_send(char *number, char *text);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* SMS_H_ */
