preparing
---------

* sudo apt install python3-scapy

If 192.168.1.1 is the local IP-address, execute:

* sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.1 -j DROP

this prevents that the Linux kernel will interfere.

Sometimes offloading functionality of a network-apdapter/system interferes:
Linux and Windows 11 under QEMU then fail to adhere to the TCP MSS option.
FreeBSD 15 runs fine immediately.

To disable the offloading in Linux, enter this:
* sudo ethtool -K eth0 tso off gso off
(if the DUT is a Linux system that is).


running
-------

sudo ./ct-tcp.py

You may want to edit configure.py first.


Written by Folkert van Heusden, MIT license
