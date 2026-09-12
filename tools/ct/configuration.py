#! /usr/bin/env python3

src = '192.168.122.1'
dst = '192.168.122.3'
dest_port = 80  # a simple http/1.0 server will do
rst_dest_port = 81  # should return RST
timeout = 2
interface = 'vnet1'
