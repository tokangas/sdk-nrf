.. _sms_sample:

nRF9160: SMS
############

.. contents::
   :local:
   :depth: 2

The SMS sample demonstrates how you can send and receive SMS messages with your nRF9160 device.


Overview
********

The SMS sample registers for SMS service within the nRF9160 modem.
Then, it will receive all SMS message and print out information about them including the text that is sent.
The sample includes a code block that is commented which has sending of SMS message included.
This can be modified with the desired recipient phone number to send the message when the sample starts.


Requirements
************

The sample supports the following development kit:

.. table-from-rows:: /includes/sample_board_rows.txt
   :header: heading
   :rows: nrf9160dk_nrf9160ns


Building and running
********************

.. |sample path| replace:: :file:`samples/nrf9160/sms`

.. include:: /includes/build_and_run_nrf9160.txt


Testing
=======

After programming the sample to your development kit, test the sample by performing the following steps:

1. |connect_kit|
#. |connect_terminal|
#. Observe that the sample shows the :ref:`UART output <sms_uart_output>` from the device.
   Note that this is an example and the output need not be identical to your observed output.
#. Send SMS message to the number of the SIM card that you have placed into nRF9160 device.

.. note::
   Not all IOT SIM cards support SMS service so you need to check with your operator if SMS service doesn't seem to work.

.. note::
   If more verbose logging of the SMS module processing is preferred, set the :option:`CONFIG_SMS_LOG_LEVEL_DBG` option in the ``prj.conf``.

.. _sms_uart_output:


Sample output
=============

The following is a sample output:

.. code-block:: console

   *** Booting Zephyr OS build v2.4.99-ncs1-1818-g54dea0b2b530  ***

   SMS sample starting
   SMS sample is ready for receiving messages
   Sending SMS: number=1234567890, text="SMS sample: testing"
   SMS status report received

   SMS received:
         Time:   21-04-12 15:42:52
         Text:   'Testing'
         Length: 7

Dependencies
************

This sample uses the following |NCS| libraries:

* :ref:`sms_readme` which includes:

It uses the following `sdk-nrfxlib`_ library:

* :ref:`nrfxlib:nrf_modem`


References
**********

