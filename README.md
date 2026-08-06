## requirements

* libiniparser-dev
* cmake
* clang++-22


## configuration

See examples/ for a few example configuration files.
Note that a 'tap' device needs to be brought 'up' after you've started the tap-server:
```bash
sudo ip link set up dev test
```


## written by

folkert@vanheusden.com
