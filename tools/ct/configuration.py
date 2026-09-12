#! /usr/bin/env python3

src = '192.168.122.1'
dst = '192.168.122.3'

local_port = 8123
local_port2 = 8124
local_port3 = 8125
local_port4 = 8126
dest_port = 80  # something must answer on that port
rst_dest_port = 81  # should return RST
timeout = 2
interface = 'virbr0'
