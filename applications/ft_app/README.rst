.. _ft_app_application:

nRF9160: Field Test Application
###############################

Field test application includes functionality to test various device connectivity features related to sockets including data throughput.

Overview
********

Field test application use LTE link control driver to establish LTE connection and
initializes Zephyr shell to provide shell command line interface for users.

Requirements
************

* The following development board:

  * |nRF9160DK|

Building and running
********************

.. |sample path| replace:: :file:`applications/ft_app`

Testing
=======

After programming the application and all prerequisites to your board, test the Asset Tracker application by performing the following steps:

1. Connect the board to the computer using a USB cable.
   The board is assigned a COM port (Windows) or ttyACM device (Linux), which is visible in the Device Manager.
#. Create serial connection to the board (J-Link COM port) with a terminal
   * Hardware flow control: disabled
   * Baud rate: 115200
   * Parity bit: no
#. Reset the board.
#. Observe in the terminal window that the board starts up in the Secure Partition Manager and that the application starts.
   This is indicated by output similar to the following lines::

	SPM: prepare to jump to Non-Secure image.

	uart-fta:~$ *** Booting Zephyr OS build v2.3.0-rc1-ncs1-2407-g91d81dc7e0ce  ***

	The FT app sample started

	LTE cell changed: Cell ID: 1480706, Tracking area: 2002
	Network registration status: searching
	Network registration status: Connected - roaming
	uart-fta:~$

#. Type any of the commands listed in the Features section to the terminal. Typing just the command will show the usage, e.g. 'sock'.

Dependencies
************

This sample uses the following libraries:

From |NCS|
  * :ref:`modem_info_readme`
  * :ref:`at_cmd_readme`
  * :ref:`lte_lc_readme`

From nrfxlib
  * :ref:`nrfxlib:bsdlib`

References
**********
