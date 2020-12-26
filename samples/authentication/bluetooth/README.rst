.. _auth_bluetooth-sample:

Authentication over Bluetooth
#############################

Overview
********

There are two Bluetooth firmware applications, central and peripheral.  The Central acts as t
he client, the peripheral acts as the server.  The Central initiates the authentication
messages.

IMPORTANT: The Central starts scanning and the authentication process after the DT_ALIAS_SW0_GPIOS_PIN
button is pressed.  For the Nordic nRF52840 DK, this GPIO maps to button Button 1.

The authentication method, DTLS or Challenge-Response, is configurable via KConfig menu.

Building and Running
--------------------
This sample was developed and tested with two Nordic nRF52840 dev
kits (see: https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK).  Two Ubuntu
VMs were used, one running the Central the other VM running the Peripheral.


