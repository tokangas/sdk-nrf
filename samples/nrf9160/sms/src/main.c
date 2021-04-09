/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <kernel.h>
#include <string.h>
#include <modem/sms.h>


static void sms_callback(struct sms_data *const data, void *context)
{
	if (data == NULL) {
		printk("sms_callback with NULL data\n");
	}

	if (data->type == SMS_TYPE_DELIVER) {
		/* When SMS message is received, print information */
		struct sms_deliver_header *header = &data->header.deliver;
		printk("\nSMS received:\n");
		printk("\tTime:   %02d-%02d-%02d %02d:%02d:%02d\n",
			header->time.year,
			header->time.month,
			header->time.day,
			header->time.hour,
			header->time.minute,
			header->time.second);

		printk("\tText:   '%s'\n", data->data);
		printk("\tLength: %d\n", data->data_len);

		if (header->app_port.present) {
			printk("\tApplication port addressing scheme: dest_port=%d, src_port=%d\n",
				header->app_port.dest_port,
				header->app_port.src_port);
		}
		if (header->concatenated.present) {
			printk("\tConcatenated short message: ref_number=%d, msg %d/%d\n",
				header->concatenated.ref_number,
				header->concatenated.seq_number,
				header->concatenated.total_msgs);
		}
	} else if (data->type == SMS_TYPE_STATUS_REPORT) {
		printk("SMS status report received\n");
		return;
	} else {
		printk("SMS protocol message with unknown type received\n");
	}
}

void main(void)
{
	printk("\nSMS sample starting\n");

	int handle = sms_register_listener(sms_callback, NULL);
	if (handle) {
		printk("sms_register_listener returned err: %d\n", handle);
		return;
	}

	printk("SMS sample is ready for receiving messages\n");

	/* SMS sending is commented out here as destination phone number that
	 * we should use is unknown. User can tweak the code, e.g., to send
	 * the message to his/her personal phone.
	 */
	printk("\nIf you want to send an SMS, please find this line from the code.\n"
		"Then, uncomment next line and change your phone number in there.\n");
	/*
	int ret = sms_send("000000000000", "SMS sample: testing"); 
	if (ret) {
		printk("sms_send returned err: %d\n", ret);
	}
	*/

	/* In our application, we should unregister SMS in some conditions with:
	 *   sms_unregister_listener(handle);
	 * However, this sample will continue to be registered for
	 * received SMS messages and they can be seen in serial port log.
	 */
}
