.. _modem_shell_application:

nRF9160: Modem Shell application
###############################

Modem Shell (MoSH) application includes functionality to test various device connectivity features related to sockets including data throughput.

Overview
********

MoSH uses LTE link control driver to establish LTE connection and
initializes Zephyr shell to provide shell command line interface for users.

Requirements
************

* The following development board:

  * |nRF9160DK|

Building and running
********************

.. |sample path| replace:: :file:`samples/modem_shell`

PPP support
============

To build the MoSH sample with PPP / dial up support for Windows, build it with the ``-DOVERLAY_CONFIG=overlay-ppp.conf`` option.
For example ``west build -b nrf9160dk_nrf9160ns -d build -- -DOVERLAY_CONFIG=overlay-ppp.conf``
See :ref:`cmake_options` for instructions on how to add this option.

Testing
=======

After programming the application and all prerequisites to your board, test the MoSH by performing the following steps:

1. Connect the board to the computer using a USB cable.
   The board is assigned a COM port (Windows) or ttyACM device (Linux), which is visible in the Device Manager.

#. Create serial connection to the board (J-Link COM port) with a terminal

   * Hardware flow control: disabled
   * Baud rate: 115200
   * Parity bit: no

#. Reset the board.

#. Observe in the terminal window that the application starts.
   This is indicated by output similar to the following lines::

	SPM: prepare to jump to Non-Secure image.

	uart-fta:~$ *** Booting Zephyr OS build v2.3.0 ***

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
