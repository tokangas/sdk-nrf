/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
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

/** @brief SMS PDU data. */
struct sms_data {
	enum sms_type type;
	char *alpha;
	uint16_t length;
	char *pdu;
};

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
int sms_send_message(char *number, char *text);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* SMS_H_ */
