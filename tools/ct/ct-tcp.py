#! /usr/bin/env python3

import configuration as cfg
import random
from scapy.all import *
import sys
import time
import unittest


class ct_tcp(unittest.TestCase):
    ports_used = set()

    def sel_port(self):
        while True:
            port = random.randint(1, 65534)
            if port in self.ports_used:
                continue
            self.ports_used.add(port)
            return port

    seqs_used = set()

    def sel_seq(self):
        while True:
            seq = random.randint(0, 0xffffffff)
            if seq in self.seqs_used:
                continue
            self.seqs_used.add(seq)
            return seq


    def test_syn_rst(self):
        # a port with nothing listening on it should return a RST
        ip = IP(src=cfg.src, dst=cfg.dst)
        syn = TCP(sport=self.sel_port(), dport=cfg.rst_dest_port, flags='S', seq=self.sel_seq())
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertIn(result[TCP].flags, [0x14, 0x04])  # TODO is R ok? or only AR?


    def test_syn_succes(self):
        # a port with something listening on it should return a SYN
        ip = IP(src=cfg.src, dst=cfg.dst)
        use_seq = self.sel_seq()
        syn = TCP(sport=self.sel_port(), dport=cfg.dest_port, flags='S', seq=use_seq)
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x12)

        with self.subTest('ack seq nr'):
            self.assertEqual(result[TCP].ack, (use_seq + 1) & 0xffffffff)


    def test_synack_seq(self):
        # should not use a sequence number twice
        ip = IP(src=cfg.src, dst=cfg.dst)
        # send first
        use_seq1 = self.sel_seq()
        port1 = self.sel_port()
        syn = TCP(sport=port1, dport=cfg.dest_port, flags='S', seq=use_seq1)
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x12)
        seq_nr1 = result[TCP].seq
        # send second 
        use_seq2 = self.sel_seq()
        port2 = self.sel_port()
        syn = TCP(sport=port2, dport=cfg.dest_port, flags='S', seq=use_seq2)
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x12)
        seq_nr2 = result[TCP].seq
        self.assertNotEqual(seq_nr1, seq_nr2)

        # RST
        rst = TCP(sport=port1, dport=cfg.dest_port, flags='R', seq=use_seq1)
        send(ip/rst, verbose=0)
        rst = TCP(sport=port2, dport=cfg.dest_port, flags='R', seq=use_seq2)
        send(ip/rst, verbose=0)

        # ...and retry
        syn = TCP(sport=self.sel_port(), dport=cfg.dest_port, flags='S', seq=self.sel_seq())
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x12)
        self.assertNotEqual(result[TCP].seq, seq_nr1)
        self.assertNotEqual(result[TCP].seq, seq_nr2)


    def test_establish_happy_flow(self):
        # test a full setup with sending data
        ip = IP(src=cfg.src, dst=cfg.dst)
        my_seq = self.sel_seq()
        local_port = self.sel_port()
        syn = TCP(sport=local_port, dport=cfg.dest_port, flags='S', seq=my_seq)
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x12)  # should be SA
        seq_nr = result[TCP].seq
        syn = TCP(sport=local_port, dport=cfg.dest_port, flags='PA', ack=seq_nr + 1, seq=my_seq + 1, window=1)
        teststring = 'Hello, world!'
        result = sr1(ip/syn/Raw(load=teststring), timeout=cfg.timeout, verbose=0)
        # should ACK as window size is 1
        self.assertEqual(result[TCP].flags & 0x10, 0x10)
        # verify sequence numbers
        self.assertEqual(result[TCP].ack, my_seq + 1 + len(teststring))
        self.assertEqual(result[TCP].seq, seq_nr + 1)


    def test_establish_rst(self):
        # should not allow data on RST connection
        ip = IP(src=cfg.src, dst=cfg.dst)
        my_seq = self.sel_seq()
        local_port = self.sel_port()
        syn = TCP(sport=local_port, dport=cfg.dest_port, flags='S', seq=my_seq)
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x12)  # should be SA
        seq_nr = result[TCP].seq
        # RST
        rst = TCP(sport=local_port, dport=cfg.dest_port, flags='R', ack=seq_nr + 1, seq=my_seq + 1, window=1)
        send(ip/rst, verbose=0)

        # send data
        syn = TCP(sport=local_port, dport=cfg.dest_port, flags='PA', ack=seq_nr + 1, seq=my_seq + 1, window=1)
        result = sr1(ip/syn/Raw(load='test'), timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x04)  # should be R


    def test_establish_resend(self):
        # test that dut triggers a resend when data is missing
        ip = IP(src=cfg.src, dst=cfg.dst)
        my_seq = self.sel_seq()
        local_port = self.sel_port()
        syn = TCP(sport=local_port, dport=cfg.dest_port, flags='S', seq=my_seq)
        result = sr1(ip/syn, timeout=cfg.timeout, verbose=0)
        self.assertEqual(result[TCP].flags, 0x12)  # should be SA
        seq_nr = result[TCP].seq
        syn_ack = TCP(sport=local_port, dport=cfg.dest_port, flags='PA', ack=seq_nr + 1, seq=my_seq + 1, window=1)
        send(ip/syn_ack, verbose=0)
        # + 100 instead of + 1 so that DUT things 99 bytes are missing
        pl = TCP(sport=local_port, dport=cfg.dest_port, flags='PA', ack=seq_nr + 1, seq=my_seq + 100, window=1)
        teststring = 'User-Agent: not relevant for the test\r\n\r\n'

        def got_ack(p):
            return (IP in p and TCP in p and
                    p[IP].src == cfg.dst and
                    p[IP].dst == cfg.src and
                    p[TCP].sport == cfg.dest_port and
                    p[TCP].dport == local_port)

        sniffer_h = AsyncSniffer(iface=cfg.interface, lfilter=got_ack, timeout=cfg.timeout, count=1,
                                 started_callback=lambda: send(ip/pl/Raw(load=teststring), verbose=0))
        sniffer_h.start()
        sniffer_h.join()
        pkt = sniffer_h.results
        self.assertNotEqual(pkt, None)
        self.assertNotEqual(len(pkt), 0)
        self.assertEqual(pkt[0][TCP].ack, my_seq + 1)
 

if __name__ == '__main__':
    unittest.main()
