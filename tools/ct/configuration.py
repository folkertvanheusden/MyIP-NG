#! /usr/bin/env python3

# several DUTs are configured here
# you can, if you like, replace all of it

nr=0

if nr == 0:
    src = '192.168.1.1'
    dst = '192.168.1.2'
    dest_port = 80  # a simple http/1.0 server will do
    rst_dest_port = 81  # should return RST
    timeout = 1
    interface = 'test'

elif nr == 1:
    src = '192.168.122.1'
    dst = '192.168.122.2'
    dest_port = 80  # a simple http/1.0 server will do
    rst_dest_port = 81  # should return RST
    timeout = 1
    interface = 'virbr0'

elif nr == 2:
    src = '192.168.122.1'
    dst = '192.168.122.17'
    dest_port = 80  # a simple http/1.0 server will do
    rst_dest_port = 81  # should return RST
    timeout = 1
    interface = 'virbr0'
