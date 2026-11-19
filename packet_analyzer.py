#!/usr/bin/env python3
"""
Network Packet Analyzer
------------------------
Captures live network traffic using a raw socket and manually parses
Ethernet, IP, TCP, UDP, and ICMP headers -- no scapy/pyshark, so every
byte offset in these headers is handled by hand. Built to demonstrate
understanding of the TCP/IP stack at the wire level.

Requires: Linux, Python 3, and root privileges (raw sockets need
CAP_NET_RAW). Run with: sudo python3 packet_analyzer.py

Author: your-name-here
"""

import socket
import struct
import argparse
import sys
import time
from collections import defaultdict

# ---------------------------------------------------------------------------
# Statistics tracking
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.total_packets = 0
        self.protocol_counts = defaultdict(int)
        self.start_time = time.time()

    def record(self, proto_name):
        self.total_packets += 1
        self.protocol_counts[proto_name] += 1

    def summary(self):
        elapsed = time.time() - self.start_time
        lines = [
            "\n--- Capture Summary ---",
            f"Total packets captured: {self.total_packets}",
            f"Duration: {elapsed:.1f}s",
        ]
        for proto, count in sorted(self.protocol_counts.items(), key=lambda x: -x[1]):
            pct = (count / self.total_packets * 100) if self.total_packets else 0
            lines.append(f"  {proto:6s}: {count:6d} ({pct:5.1f}%)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Header parsers
# ---------------------------------------------------------------------------

def parse_ethernet_header(raw_data):
    """Unpacks the 14-byte Ethernet II header."""
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return {
        "dest_mac": format_mac(dest_mac),
        "src_mac": format_mac(src_mac),
        "eth_proto": socket.htons(proto),
    }, raw_data[14:]


def format_mac(raw_mac):
    return ":".join(f"{b:02x}" for b in raw_mac)


def parse_ipv4_header(raw_data):
    """Unpacks the IPv4 header (first 20 bytes, assuming no options)."""
    version_ihl = raw_data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # header length in bytes

    (ttl, proto, checksum, src, dest) = struct.unpack(
        "! 8x B B H 4s 4s", raw_data[:20]
    )
    return {
        "version": version,
        "header_len": ihl,
        "ttl": ttl,
        "protocol": proto,
        "src_ip": socket.inet_ntoa(src),
        "dest_ip": socket.inet_ntoa(dest),
    }, raw_data[ihl:]


def parse_tcp_header(raw_data):
    """Unpacks the TCP header (first 20 bytes, assuming no options)."""
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack(
        "! H H L L H", raw_data[:14]
    )
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x03F
    flag_str = "".join([
        "F" if flags & 0x01 else "-",
        "S" if flags & 0x02 else "-",
        "R" if flags & 0x04 else "-",
        "P" if flags & 0x08 else "-",
        "A" if flags & 0x10 else "-",
        "U" if flags & 0x20 else "-",
    ])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "seq": seq,
        "ack": ack,
        "flags": flag_str,
    }, raw_data[offset:]


def parse_udp_header(raw_data):
    """Unpacks the 8-byte UDP header."""
    src_port, dest_port, length, checksum = struct.unpack("! H H H H", raw_data[:8])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "length": length,
    }, raw_data[8:]


def parse_icmp_header(raw_data):
    """Unpacks the first 4 bytes of the ICMP header (type, code, checksum)."""
    icmp_type, code, checksum = struct.unpack("! B B H", raw_data[:4])
    return {
        "type": icmp_type,
        "code": code,
    }, raw_data[4:]


# ---------------------------------------------------------------------------
# Protocol numbers (IANA)
# ---------------------------------------------------------------------------
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


# ---------------------------------------------------------------------------
# Main capture loop
# ---------------------------------------------------------------------------

def print_packet(eth, ip, transport, proto_name, payload_len):
    print(f"[{proto_name}] {ip['src_ip']} -> {ip['dest_ip']}  "
          f"TTL={ip['ttl']}", end="")
    if proto_name in ("TCP", "UDP"):
        print(f"  {transport['src_port']} -> {transport['dest_port']}", end="")
    if proto_name == "TCP":
        print(f"  flags={transport['flags']}", end="")
    if proto_name == "ICMP":
        print(f"  type={transport['type']} code={transport['code']}", end="")
    print(f"  payload={payload_len}B")


def main():
    parser = argparse.ArgumentParser(description="Simple raw-socket packet analyzer")
    parser.add_argument(
        "-p", "--protocol", choices=["tcp", "udp", "icmp", "all"], default="all",
        help="Only display packets of this protocol (default: all)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Stop after capturing this many packets (default: run until Ctrl+C)"
    )
    args = parser.parse_args()

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Error: raw sockets require root. Try: sudo python3 packet_analyzer.py")
        sys.exit(1)
    except AttributeError:
        print("Error: AF_PACKET is only available on Linux.")
        sys.exit(1)

    stats = Stats()
    print("Capturing packets... Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, _ = sock.recvfrom(65535)
            eth, payload = parse_ethernet_header(raw_data)

            # Only handle IPv4 (0x0800); skip ARP and other ethertypes for now
            if eth["eth_proto"] != 0x0800:
                continue

            ip, payload = parse_ipv4_header(payload)

            if ip["protocol"] == PROTO_TCP:
                proto_name = "TCP"
                transport, payload = parse_tcp_header(payload)
            elif ip["protocol"] == PROTO_UDP:
                proto_name = "UDP"
                transport, payload = parse_udp_header(payload)
            elif ip["protocol"] == PROTO_ICMP:
                proto_name = "ICMP"
                transport, payload = parse_icmp_header(payload)
            else:
                proto_name = f"OTHER({ip['protocol']})"
                transport = {}

            if args.protocol != "all" and proto_name.lower() != args.protocol:
                continue

            stats.record(proto_name)
            print_packet(eth, ip, transport, proto_name, len(payload))

            if args.count and stats.total_packets >= args.count:
                break

    except KeyboardInterrupt:
        pass
    finally:
        print(stats.summary())


if __name__ == "__main__":
    main()
