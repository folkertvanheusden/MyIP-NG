#! /usr/bin/python3

from dataclasses import dataclass, field
from scapy.all import rdpcap, TCP, IP
import sys
import time

MASK32 = 0xFFFFFFFF
HALF32 = 0x80000000
MOD32 = 0x100000000


class conn_state:
    new = 'NEW'
    syn_seen = 'SYN_SEEN'
    syn_ack_seen = 'SYN_ACK_SEEN'
    established = 'ESTABLISHED'
    fin_wait = 'FIN_WAIT'
    fin_both = 'FIN_BOTH'
    closed = 'CLOSED'
    reset = 'RESET'
    midstream = 'MIDSTREAM'


@dataclass
class direction_tracker:
    isn: int | None = None
    last_seq_unwrapped: int | None = None
    contig_end: int | None = None
    highest_ack_seen: int | None = None
    dup_ack_count: int = 0
    ranges: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class flow_tracker:
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    dirs: dict[tuple[str, int], direction_tracker] = field(default_factory=dict)
    state: str = conn_state.new
    initiator: tuple[str, int] | None = None
    responder: tuple[str, int] | None = None
    fin_from: tuple[str, int] | None = None

    def __post_init__(self):
        self.dirs[self.endpoint_a] = direction_tracker()
        self.dirs[self.endpoint_b] = direction_tracker()


def unwrap32(value: int, ref: int | None) -> int:
    value &= MASK32
    if ref is None:
        return value

    candidate = (ref & ~MASK32) | value
    if candidate - ref > HALF32:
        candidate -= MOD32
    elif ref - candidate > HALF32:
        candidate += MOD32
    return candidate


def range_covered(ranges: list[tuple[int, int]], start: int, end: int) -> bool:
    for rs, re in ranges:
        if start >= rs and end <= re:
            return True
        if re >= end:
            break
    return False


def add_range(ranges: list[tuple[int, int]], start: int, end: int) -> list[tuple[int, int]]:
    if start >= end:
        return ranges

    merged = []
    placed = False
    for rs, re in ranges:
        if re < start:
            merged.append((rs, re))
            continue
        if end < rs:
            if not placed:
                merged.append((start, end))
                placed = True
            merged.append((rs, re))
            continue

        start = min(start, rs)
        end = max(end, re)

    if not placed:
        merged.append((start, end))

    merged.sort()
    return merged


def update_contiguous(tr: direction_tracker):
    if not tr.ranges:
        return

    if tr.contig_end is None:
        tr.contig_end = tr.ranges[0][0]

    changed = True
    while changed:
        changed = False
        for rs, re in tr.ranges:
            if rs <= tr.contig_end < re:
                tr.contig_end = re
                changed = True


def is_pure_ack(has_ack: bool, payload_len: int, has_syn: bool, has_fin: bool, has_rst: bool) -> bool:
    return has_ack and payload_len == 0 and not has_syn and not has_fin and not has_rst


def rel(value: int | None, base: int | None) -> int:
    if value is None or base is None:
        return 0
    return value - base


def classify_state(flow: flow_tracker, src_ep: tuple[str, int], dst_ep: tuple[str, int], has_syn: bool, has_ack: bool, has_fin: bool, has_rst: bool) -> list[str]:
    st = []

    if has_rst:
        flow.state = conn_state.reset
        st.append('RST')
        return st

    if flow.state == conn_state.new:
        if has_syn and not has_ack:
            flow.state = conn_state.syn_seen
            flow.initiator = src_ep
            flow.responder = dst_ep
        else:
            flow.state = conn_state.midstream
            st.append('MIDSTREAM')
        return st

    if flow.state == conn_state.syn_seen:
        if has_syn and has_ack and src_ep == flow.responder and dst_ep == flow.initiator:
            flow.state = conn_state.syn_ack_seen
        elif has_syn and not has_ack and src_ep == flow.initiator:
            st.append('SYN_RTX')
        elif has_syn:
            st.append('STATE_ERR')
        return st

    if flow.state == conn_state.syn_ack_seen:
        if has_ack and not has_syn and src_ep == flow.initiator and dst_ep == flow.responder:
            flow.state = conn_state.established
        elif has_syn and has_ack and src_ep == flow.responder:
            st.append('SYNACK_RTX')
        elif has_syn:
            st.append('STATE_ERR')
        return st

    if flow.state in (conn_state.established, conn_state.midstream):
        if has_syn:
            st.append('STATE_ERR')
        if has_fin:
            flow.state = conn_state.fin_wait
            flow.fin_from = src_ep
        return st

    if flow.state == conn_state.fin_wait:
        if has_fin and src_ep != flow.fin_from:
            flow.state = conn_state.fin_both
        return st

    if flow.state == conn_state.fin_both:
        if has_ack and not has_fin:
            flow.state = conn_state.closed
        return st

    return st


def flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    return (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)


if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <pcap-file>')
    sys.exit(1)

packets = rdpcap(sys.argv[1])
flows: dict[tuple[tuple[str, int], tuple[str, int]], flow_tracker] = {}
nr = 0

for p in packets:
    if IP not in p or TCP not in p:
        continue

    ip = p[IP]
    tcp = p[TCP]
    payload_len = max(0, ip.len - tcp.dataofs * 4 - ip.ihl * 4)

    src_ep = (ip.src, int(tcp.sport))
    dst_ep = (ip.dst, int(tcp.dport))

    key = flow_key(ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
    flow = flows.get(key)
    if flow is None:
        flow = flow_tracker(endpoint_a=key[0], endpoint_b=key[1])
        flows[key] = flow

    sender = flow.dirs[src_ep]
    peer = flow.dirs[dst_ep]

    has_syn = bool(int(tcp.flags) & 0x02)
    has_ack = bool(int(tcp.flags) & 0x10)
    has_fin = bool(int(tcp.flags) & 0x01)
    has_rst = bool(int(tcp.flags) & 0x04)

    statuses = classify_state(flow, src_ep, dst_ep, has_syn, has_ack, has_fin, has_rst)

    seg_len_seq_space = payload_len + (1 if has_syn else 0) + (1 if has_fin else 0)
    seq_u = unwrap32(int(tcp.seq), sender.last_seq_unwrapped)
    sender.last_seq_unwrapped = seq_u

    pre_contig = sender.contig_end if sender.contig_end is not None else seq_u

    if sender.isn is None:
        sender.isn = seq_u
    if peer.isn is None and (has_syn and has_ack):
        peer.isn = unwrap32(int(tcp.ack) - 1, peer.last_seq_unwrapped)

    if seg_len_seq_space > 0:
        seg_end = seq_u + seg_len_seq_space

        if range_covered(sender.ranges, seq_u, seg_end):
            statuses.append('RTX')
        elif sender.contig_end is not None and seq_u > sender.contig_end:
            statuses.append('OOO')
        else:
            statuses.append('OK')

        sender.ranges = add_range(sender.ranges, seq_u, seg_end)
        if sender.contig_end is None:
            sender.contig_end = seq_u
        update_contiguous(sender)
    elif is_pure_ack(has_ack, payload_len, has_syn, has_fin, has_rst):
        statuses.append('PURE_ACK')
    elif not statuses:
        statuses.append('OK')

    ack_u = None
    if has_ack:
        ack_u = unwrap32(int(tcp.ack), sender.highest_ack_seen)

        if peer.isn is not None and ack_u < peer.isn:
            statuses.append('BAD_ACK')
        elif peer.contig_end is not None and ack_u > peer.contig_end:
            statuses.append('BAD_ACK')
        else:
            if sender.highest_ack_seen is None or ack_u > sender.highest_ack_seen:
                sender.highest_ack_seen = ack_u
                sender.dup_ack_count = 0
                statuses.append('ACK_ADV')
            elif ack_u == sender.highest_ack_seen:
                sender.dup_ack_count += 1
                statuses.append('DUPACK')
            else:
                statuses.append('ACK_BACK')

    nr += 1
    ts_str = time.strftime('%H:%M:%S', time.gmtime(float(p.time))) + f'.{int(p.time * 1000000) % 1000000:06}'

    seq_rel_offset = sender.isn if sender.isn is not None else seq_u
    ack_rel_offset = peer.isn if peer.isn is not None else (ack_u if ack_u is not None else 0)

    print(
        f"{nr:3} "
        f"{ts_str} "
        f"flow={hash(key) & 0xffff:04x} "
        f"{tcp.sport:5} -> {tcp.dport:5} "
        f"flags={tcp.sprintf('%TCP.flags%'):8} "
        f"seq={rel(seq_u, seq_rel_offset):10} "
        f"next={rel(pre_contig, seq_rel_offset):10} "
        f"ack={rel(ack_u, ack_rel_offset):10} "
        f"len={payload_len:5} "
        f"win={tcp.window:5} "
        f"state={flow.state:11} "
        f"status={','.join(dict.fromkeys(statuses))}")
