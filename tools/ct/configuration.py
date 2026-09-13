#! /usr/bin/env python3

if True:
    src = '192.168.1.1'
    dst = '192.168.1.2'
    dest_port = 80  # a simple http/1.0 server will do
    rst_dest_port = 81  # should return RST
    timeout = 1
    interface = 'test'

else:
    src = '192.168.122.1'
    dst = '192.168.122.3'
    dest_port = 80  # a simple http/1.0 server will do
    rst_dest_port = 81  # should return RST
    timeout = 1
    interface = 'virbr0'
