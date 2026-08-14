## requirements

* libiniparser-dev
* cmake
* clang++-22

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
```


## written by

folkert@vanheusden.com
