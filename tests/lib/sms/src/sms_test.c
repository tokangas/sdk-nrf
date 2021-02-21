/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <unity.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <kernel.h>
#include <modem/sms.h>
#include <mock_at_cmd.h>


static struct sms_data test_sms_data;
static struct sms_deliver_header test_sms_header;
static int test_handle;

void helper_sms_data_clear()
{
	memset(&test_sms_data, 0, sizeof(test_sms_data));

	test_sms_data.type = SMS_TYPE_DELIVER;

	test_sms_data.alpha = malloc(SMS_MAX_ADDRESS_LEN_CHARS);
	memset(test_sms_data.alpha, 0, SMS_MAX_ADDRESS_LEN_CHARS);
	test_sms_data.pdu = malloc(512);
	memset(test_sms_data.pdu, 0, 512);

	memset(&test_sms_header, 0, sizeof(test_sms_header));
	test_sms_header.ud = malloc(512);
	memset(test_sms_header.ud, 0, 512);
}

void setUp(void)
{
	helper_sms_data_clear();
	test_handle = 0;
}

static void sms_callback(struct sms_data *const data, void *context)
{
	TEST_ASSERT_EQUAL(test_sms_data.type, data->type);
	TEST_ASSERT_EQUAL_STRING(test_sms_data.alpha, data->alpha);
	TEST_ASSERT_EQUAL(test_sms_data.length, data->length);
	TEST_ASSERT_EQUAL_STRING(test_sms_data.pdu, data->pdu);

	struct sms_deliver_header *sms_header = data->header;

	TEST_ASSERT_EQUAL(test_sms_header.time.year, sms_header->time.year);
	TEST_ASSERT_EQUAL(test_sms_header.time.month, sms_header->time.month);
	TEST_ASSERT_EQUAL(test_sms_header.time.day, sms_header->time.day);
	TEST_ASSERT_EQUAL(test_sms_header.time.hour, sms_header->time.hour);
	TEST_ASSERT_EQUAL(test_sms_header.time.minute, sms_header->time.minute);
	TEST_ASSERT_EQUAL(test_sms_header.time.second, sms_header->time.second);

	TEST_ASSERT_EQUAL_STRING(test_sms_header.ud, sms_header->ud);
	TEST_ASSERT_EQUAL(test_sms_header.data_len, sms_header->data_len);

	TEST_ASSERT_EQUAL(test_sms_header.app_port.present, sms_header->app_port.present);
	TEST_ASSERT_EQUAL(test_sms_header.app_port.dest_port, sms_header->app_port.dest_port);
	TEST_ASSERT_EQUAL(test_sms_header.app_port.src_port, sms_header->app_port.src_port);

	TEST_ASSERT_EQUAL(test_sms_header.concatenated.present, sms_header->concatenated.present);
	TEST_ASSERT_EQUAL(test_sms_header.concatenated.ref_number, sms_header->concatenated.ref_number);
	TEST_ASSERT_EQUAL(test_sms_header.concatenated.seq_number, sms_header->concatenated.seq_number);
	TEST_ASSERT_EQUAL(test_sms_header.concatenated.total_msgs, sms_header->concatenated.total_msgs);
}

void sms_init_helper()
{
	__wrap_at_cmd_write_ExpectAndReturn("AT+CNMI?", NULL, 0, NULL, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();
	char resp[] = "+CNMI: 0,0,0,0,1\r\n";
	__wrap_at_cmd_write_ReturnArrayThruPtr_buf(resp, sizeof(resp));
	__wrap_at_cmd_write_ExpectAndReturn("AT+CNMI=3,2,0,1", NULL, 0, NULL, 0);
	int ret = sms_init();
	TEST_ASSERT_EQUAL(0, ret);

	int test_handle = sms_register_listener(sms_callback, NULL);
	TEST_ASSERT_EQUAL(0, test_handle);
}

void sms_uninit_helper()
{
	sms_unregister_listener(test_handle);
	test_handle = 0;

	__wrap_at_cmd_write_ExpectAndReturn("AT+CNMI=0,0,0,0", NULL, 0, NULL, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();
	sms_uninit();
}

/********* SMS SEND TESTS ***********************/
/* The following site used as a reference for generated messages:
   http://smstools3.kekekasvi.com/topic.php?id=288 */

void test_sms_init_uninit(void)
{
	sms_init_helper();
	sms_uninit_helper();
}

void test_send_len3_number10plus(void)
{
	enum at_cmd_state state = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=16\r0031000A9121436587090000FF03CD771A\x1A", NULL, 0, &state, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	int ret = sms_send("+1234567890", "Moi");
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state);
}

void test_send_len1_number20plus(void)
{
	enum at_cmd_state state = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=19\r0031001491214365870921436587090000FF0131\x1A", NULL, 0, &state, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	int ret = sms_send("+12345678901234567890", "1");
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state);
}

/* Test message length 7 to see that alignment with 7bit GSM encoding works properly. */
void test_send_len7_number11(void)
{
	enum at_cmd_state state = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=21\r0031000B912143658709F10000FF0731D98C56B3DD00\x1A", NULL, 0, &state, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	int ret = sms_send("12345678901", "1234567");
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state);
}

/* Test message length 8 to see that alignment with 7bit GSM encoding works properly. */
void test_send_len8_number1(void)
{
	enum at_cmd_state state = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=16\r0031000191F10000FF0831D98C56B3DD70\x1A", NULL, 0, &state, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	int ret = sms_send("1", "12345678");
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state);
}

/* Test message length 9 to see that alignment with 7bit GSM encoding works properly. */
void test_send_len9_number5(void)
{
	enum at_cmd_state state = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=19\r00310005912143F50000FF0931D98C56B3DD7039\x1A", NULL, 0, &state, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	int ret = sms_send("12345", "123456789");
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state);
}

void test_send_concat_220(void)
{
	enum at_cmd_state state1 = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=153\r0061010C915348803061250000A005000301020162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966\x1A", NULL, 0, &state1, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	enum at_cmd_state state2 = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=78\r0061020C9153488030612500004A0500030102026835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031D98C56B3DD703918\x1A", NULL, 0, &state2, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	int ret = sms_send("+358408031652", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state1);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state2);
}

void test_send_concat_291(void)
{
	enum at_cmd_state state1 = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=153\r0061030C915348803061250000A005000302020162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966\x1A", NULL, 0, &state1, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	enum at_cmd_state state2 = 0;
	__wrap_at_cmd_write_ExpectAndReturn("AT+CMGS=140\r0061040C915348803061250000910500030202026835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031\x1A", NULL, 0, &state2, 0);
	__wrap_at_cmd_write_IgnoreArg_buf();
	__wrap_at_cmd_write_IgnoreArg_buf_len();

	int ret = sms_send("+358408031652", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901");
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state1);
	TEST_ASSERT_EQUAL(AT_CMD_OK, state2);
}

/********* SMS SEND TESTS ***********************/

void test_recv_len3_number10(void)
{
	sms_init_helper();

	strcpy(test_sms_data.alpha, "+1234567890");
	test_sms_data.length = 22;
	strcpy(test_sms_data.pdu, "0791534874894320040A91214365870900001220900285438003CD771A");
	test_sms_header.data_len = 3;
	strcpy(test_sms_header.ud, "Moi");
	test_sms_header.time.year = 21;
	test_sms_header.time.month = 2;
	test_sms_header.time.day = 9;
	test_sms_header.time.hour = 20;
	test_sms_header.time.minute = 58;
	test_sms_header.time.second = 34;

	__wrap_at_cmd_write_ExpectAndReturn("AT+CNMA=1", NULL, 0, NULL, 0);
	sms_at_handler(NULL, "+CMT: \"+1234567890\",22\r\n0791534874894320040A91214365870900001220900285438003CD771A\r\n");

	sms_uninit_helper();
}

void test_recv_concat(void)
{
	sms_init_helper();

	strcpy(test_sms_data.alpha, "+1234567890");
	test_sms_data.length = 22;
	strcpy(test_sms_data.pdu, "0791534874894310440A912143658709000012201232054480A00500037E020162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966");
	test_sms_header.data_len = 153;
	strcpy(test_sms_header.ud, "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123");
	test_sms_header.time.year = 21;
	test_sms_header.time.month = 2;
	test_sms_header.time.day = 21;
	test_sms_header.time.hour = 23;
	test_sms_header.time.minute = 50;
	test_sms_header.time.second = 44;

	test_sms_header.concatenated.present = true;
	test_sms_header.concatenated.total_msgs = 2;
	test_sms_header.concatenated.ref_number = 126;
	test_sms_header.concatenated.seq_number = 1;

	__wrap_at_cmd_write_ExpectAndReturn("AT+CNMA=1", NULL, 0, NULL, 0);
	sms_at_handler(NULL, "+CMT: \"+1234567890\",22\r\n0791534874894310440A912143658709000012201232054480A00500037E020162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966B49AED86CBC162B219AD66BBE172B0986C46ABD96EB81C2C269BD16AB61B2E078BC966\r\n");

	strcpy(test_sms_data.pdu, "0791534874894320440A912143658709000012201232054480910500037E02026835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031");
	test_sms_header.data_len = 138;
	strcpy(test_sms_header.ud, "456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901");
	test_sms_header.concatenated.seq_number = 2;

	__wrap_at_cmd_write_ExpectAndReturn("AT+CNMA=1", NULL, 0, NULL, 0);
	sms_at_handler(NULL, "+CMT: \"+1234567890\",22\r\n0791534874894320440A912143658709000012201232054480910500037E02026835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031D98C56B3DD7039584C36A3D56C375C0E1693CD6835DB0D9783C564335ACD76C3E56031\r\n");

	sms_uninit_helper();
}

void test_recv_wap_push(void)
{
	sms_init_helper();

	strcpy(test_sms_data.alpha, "69923221");
	test_sms_data.length = 22;
	strcpy(test_sms_data.pdu, "004408819629231200040230503231732b1c0b05040b84000000037c0101010603c4af9a40027d76b13101320138");
	test_sms_header.data_len = 16;
	strcpy(test_sms_header.ud, "\x01\x06\x03\xC4\xAF\x9A\x40\x02\x7D\x76\xB1\x31\x01\x32\x01\x38");//"\x01\x06\x03\xC4\xAF\x9A@\x02}v\xB11\x012\x018");//00037C0101010603C4AF9A40027D76B13101320138");
	test_sms_header.time.year = 20;
	test_sms_header.time.month = 3;
	test_sms_header.time.day = 5;
	test_sms_header.time.hour = 23;
	test_sms_header.time.minute = 13;
	test_sms_header.time.second = 37;

	test_sms_header.app_port.present = true;
	test_sms_header.app_port.dest_port = 2948;

	test_sms_header.concatenated.present = true;
	test_sms_header.concatenated.total_msgs = 1;
	test_sms_header.concatenated.ref_number = 124;
	test_sms_header.concatenated.seq_number = 1;

	__wrap_at_cmd_write_ExpectAndReturn("AT+CNMA=1", NULL, 0, NULL, 0);
	sms_at_handler(NULL, "+CMT: \"69923221\",22\r\n004408819629231200040230503231732b1c0b05040b84000000037c0101010603c4af9a40027d76b13101320138\r\n");

	sms_uninit_helper();
}

/* It is required to be added to each test. That is because unity is using
 * different main signature (returns int) and zephyr expects main which does
 * not return value.
 */
extern int unity_main(void);

void main(void)
{
	(void)unity_main();
}
