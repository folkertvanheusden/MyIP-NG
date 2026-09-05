## requirements

* libiniparser-dev
* cmake
* c++ compiler (23)
* graphviz
* libwolfssl-dev
* libturbojpeg-dev

## compile

```bash
mkdir build
cd build
cmake ..
cd ..
(cd build && make -j4)
```

## configuration

See examples/ for a few example configuration files.
Note that a 'tap' device needs to be brought 'up' after you've started the tap-server:
```bash
sudo ip link set up dev test
```
Maybe you want to attach a local IP-address to the TAP as well:
```bash
sudo ip address add 192.168.1.1 dev test
sudo ip route add 192.168.1.0/24 dev test
```


## tips

When restarting the tap server, also restart the arp server as the tap server may have gotten a new mac address.


## written by

folkert@vanheusden.com
