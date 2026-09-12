#! /usr/bin/python3

from scapy.all import rdpcap, TCP, IP
import sys
import time


packets = rdpcap(sys.argv[1])

class seq_nrs:
    start_local = 0
    local_calc = 0

class state:
    wait_for_syn = 0
    syn_received = 1
    syn_ack_sent = 2
    established = 3

srvr_port = None

client = seq_nrs()
server = seq_nrs()

nr = 0

s = state.wait_for_syn

for p in packets:
    if IP not in p or TCP not in p:
        continue

    err = ''

    ip = p[IP]
    tcp = p[TCP]
    payload_len = ip.len - tcp.dataofs * 4 - ip.ihl * 4
    if tcp.flags == 'S':
        if s == state.wait_for_syn:
            client.local_calc = client.start_local = client.local = tcp.seq
            srvr_port = tcp.dport
            s = state.syn_received
        else:
            err = '!'
    elif tcp.flags == 'SA':
        if s == state.syn_received:
            s = state.syn_ack_sent
            server.local_calc = server.start_local = server.local = tcp.seq
        else:
            err = '!'
    elif tcp.flags == 'A':
        if s == state.syn_ack_sent:
            s = state.established

    seq_rel_offset = server.start_local if tcp.sport == srvr_port else client.start_local
    ack_rel_offset = client.start_local if tcp.sport == srvr_port else server.start_local
    exp_seq = client.local_calc if tcp.dport == srvr_port else server.local_calc
    exp_ack = client.local_calc if tcp.sport == srvr_port else server.local_calc

    if tcp.seq != exp_seq or tcp.ack != exp_ack:
        err = '!'

    nr += 1
    ts_str = time.strftime('%H:%M:%S', time.gmtime(float(p.time))) + f'.{int(p.time * 1000000) % 1000000:06}'
    print(
        f"{nr:3} "
        f"{ts_str} "
        f"{tcp.sport:5} -> {tcp.dport:5} "
        f"flags={tcp.sprintf('%TCP.flags%'):8} "
        f"seq={tcp.seq - seq_rel_offset:10} "
        f"expseq={exp_seq - seq_rel_offset:10} "
        f"ack={tcp.ack - ack_rel_offset:10} "
        f"expack={exp_ack - ack_rel_offset:10} "
        f"len={payload_len:5} "
        f"win={tcp.window} {err}")

    if 'S' in tcp.flags or 'F' in tcp.flags:
        if tcp.sport == srvr_port:
            server.local_calc += 1
        else:
            client.local_calc += 1

    if tcp.sport == srvr_port:
        server.local_calc += payload_len
    else:
        client.local_calc += payload_len
