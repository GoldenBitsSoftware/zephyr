.. _auth_serial-sample:

Authentication over Serial
##########################

Overview
********

There are two Serial firmware applications, client and server.  Pin P.06 and P.08 were used
for TX and RX lines.

The authentication method, DTLS or Challenge-Response, is configurable via KConfig menu.

Building and Running
--------------------
This sample was developed and tested with two Nordic nRF52840 dev
kits (see: https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK).  Two Ubuntu
VMs were used, one running the Client the other VM running the Server.

Note:  To avoid problems, insure debug output is done via Jlink RTT, not UART backend.





