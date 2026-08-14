#! /usr/bin/python3

from scapy.all import rdpcap, TCP, IP
import sys


packets = rdpcap(sys.argv[1])

class seq_nrs:
    start_local = 0
    local_calc = 0

srvr_port = None

client = seq_nrs()
server = seq_nrs()

for p in packets:
    if IP not in p or TCP not in p:
        continue

    tcp = p[TCP]
    payload_len = len(tcp.payload)
    if tcp.flags == 'S':
        client.local_calc = client.start_local = client.local = tcp.seq
        srvr_port = tcp.dport
    elif tcp.flags == 'SA':
        server.local_calc = server.start_local = server.local = tcp.seq

    print(
        f"{p.time:.6f} "
        f"{tcp.sport:5} -> {tcp.dport:5} "
        f"flags={tcp.sprintf('%TCP.flags%'):8} "
        f"seq={tcp.seq - (server.start_local if tcp.sport == srvr_port else client.start_local):10} "
        f"ack={tcp.ack - (client.start_local if tcp.sport == srvr_port else server.start_local):10} "
        f"expseq={(client.local_calc if tcp.dport == srvr_port else server.local_calc) - (server.start_local if tcp.sport == srvr_port else client.start_local):10} "
        f"expack={(client.local_calc if tcp.sport == srvr_port else server.local_calc) - (server.start_local if tcp.dport == srvr_port else client.start_local):10} "
        f"len={payload_len:5} "
        f"win={tcp.window}")

    if 'S' in tcp.flags or 'F' in tcp.flags:
        if tcp.sport == srvr_port:
            server.local_calc += 1
        else:
            client.local_calc += 1

    if tcp.sport == srvr_port:
        server.local_calc += payload_len
    else:
        client.local_calc += payload_len
