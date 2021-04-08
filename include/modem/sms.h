/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
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

/**
 * @brief SMS message type.
 */
enum sms_type {
	/** @brief SMS-DELIVER message type. */
	SMS_TYPE_DELIVER,
	/** @brief SMS-STATUS-REPORT message type. */
	SMS_TYPE_STATUS_REPORT
};

/** @brief Maximum length of SMS in number of characters. */
#define SMS_MAX_DATA_LEN_CHARS 160
/** @brief Maximum length of SMS address, i.e., phone number, in octets. */
#define SMS_MAX_ADDRESS_LEN_OCTETS 10
/** @brief Maximum length of SMS address, i.e., phone number, in characters. */
#define SMS_MAX_ADDRESS_LEN_CHARS (2 * SMS_MAX_ADDRESS_LEN_OCTETS)

/**
 * @brief SMS time information specified in 3GPP TS 23.040 Section 9.2.3.11.
 */
struct sms_time {
	uint8_t year;    /**< @brief Year. Last two digits of the year.*/
	uint8_t month;   /**< @brief Month. */
	uint8_t day;     /**< @brief Day. */
	uint8_t hour;    /**< @brief Hour. */
	uint8_t minute;  /**< @brief Minute. */
	uint8_t second;  /**< @brief Second. */
	int8_t timezone; /**< @brief Timezone. */
};

/**
 * @brief SMS address, i.e., phone number.
 * 
 * @details This may represent either originating or destination address and is
 * specified in 3GPP TS 23.040 Section 9.1.2.5.
 */
struct sms_address {
	/** @brief Address in NUL-terminated string format. */
	char    address_str[SMS_MAX_ADDRESS_LEN_CHARS + 1];
	/**
	 * @brief Address in semi-octet representation specified in
	 * 3GPP TS 23.040 Section 9.1.2.3.
	 * 
	 * TODO: Just remove this field?
	 */
	uint8_t address[SMS_MAX_ADDRESS_LEN_OCTETS];
	/** @brief Address length in number of characters. */
	uint8_t length;
	/** @brief Address type as specified in 3GPP TS 23.040 Section 9.1.2.5. */
	uint8_t type;
};

/**
 * @brief SMS concatenated short message information.
 * 
 * @details This is specified in 3GPP TS 23.040 Section 9.2.3.24.1 and 9.2.3.24.8.
 */
struct sms_udh_concatenated {
	/** @brief Indicates whether this field is present in the SMS message. */
	bool present;
	/** @brief Concatenated short message reference number. */
	uint16_t ref_number;
	/** @brief Maximum number of short messages in the concatenated short message. */
	uint8_t total_msgs;
	/** @brief Sequence number of the current short message. */
	uint8_t seq_number;
};

/**
 * @brief SMS application port addressing information.
 * 
 * @details This is specified in 3GPP TS 23.040 Section 9.2.3.24.3 and 9.2.3.24.4.
 */
struct sms_udh_app_port {
	/** @brief Indicates whether this field is present in the SMS message. */
	bool present;
	/** @brief Destination port. */
	uint16_t dest_port;
	/** @brief Source port. */
	uint16_t src_port;
};

/**
 * SMS-DELIVER message header.
 * This is for incoming SMS message and more specifically SMS-DELIVER
 * message specified in 3GPP TS 23.040.
 */
struct sms_deliver_header {
	/** @brief Timestamp. */
	struct sms_time time;
	/** @brief Originating address, i.e., phone number. */
	struct sms_address originating_address;
	/** @brief Application port addressing information. */
	struct sms_udh_app_port app_port;
	/** @brief Concatenated short message information. */
	struct sms_udh_concatenated concatenated;
};

/**
 * @brief SMS header.
 * 
 * @details This can easily be extended to support additional message types.
 */
union sms_header {
	struct sms_deliver_header deliver;
};

/** @brief SMS PDU data. */
struct sms_data {
	/** Received message type. */
	enum sms_type type;
	/** SMS header. */
	union sms_header header;

	/** Length of the data in data buffer. */
	int data_len;
	/** SMS message data. */
	char data[SMS_MAX_DATA_LEN_CHARS + 1];
};

/** @brief SMS listener callback function. */
typedef void (*sms_callback_t)(struct sms_data *const data, void *context);

/**
 * @brief Register a new listener to SMS library.
 *
 * Also registers to modem's SMS service if it's not already subscribed.
 *
 * A listener is identified by a unique handle value. This handle should be used
 * to unregister the listener. A listener can be registered multiple times with
 * the same or a different context.
 *
 * @param[in] listener Callback function. Cannot be null.
 * @param[in] context User context. Can be null if not used.
 *
 * @retval -EINVAL Invalid parameter.
 * @retval -ENOSPC List of observers is full.
 * @retval -EBUSY Indicates that one SMS client has already been registered.
 * @retval -ENOMEM Out of memory.
 * @return Handle identifying the listener,
 *         or a negative value if an error occurred.
 * TODO: List of error codes is not complete.
 */
int sms_register_listener(sms_callback_t listener, void *context);

/**
 * @brief Unregister a listener.
 *
 * Also unregisters from modem's SMS service if there are
 * no listeners registered.
 *
 * @param[in] handle Handle identifying the listener to unregister.
 */
void sms_unregister_listener(int handle);

/**
 * @brief Send SMS message.
 *
 * @param[in] number Recipient number.
 * @param[in] text Text to be sent.
 */
int sms_send(char *number, char *text);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* SMS_H_ */
