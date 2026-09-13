preparing
---------

* sudo apt install python3-scapy

If 192.168.1.1 is the local IP-address, execute:

* sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.1 -j DROP

this prevents that the Linux kernel will interfere.

Also:

* sudo ethtool -K eth0 tso off gso off

makes sure things like the TCP "MSS"-option is not ignored (eth0 is the interface on the DUT, in case it is a Linux system).


running
-------

If 192.168.1.2 is the DUT (device under test), enter e.g.:

sudo ./ct-syn.py 192.168.1.1 192.168.1.2
