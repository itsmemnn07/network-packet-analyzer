"""
Unit tests for packet_analyzer.py's header parsing functions.

These tests build synthetic packet bytes by hand (no live capture, no
root required) so they can run anywhere, including in CI.

Run with: python3 -m pytest tests/test_parsers.py
       or: python3 -m unittest tests.test_parsers
"""

import socket
import struct
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from packet_analyzer import (
    parse_ethernet_header,
    parse_ipv4_header,
    parse_tcp_header,
    parse_udp_header,
    parse_icmp_header,
)


class TestEthernetParser(unittest.TestCase):
    def test_parses_dest_src_and_ethertype(self):
        dest_mac = bytes.fromhex("aabbccddeeff")
        src_mac = bytes.fromhex("112233445566")
        ethertype = struct.pack("!H", socket.htons(0x0800))  # IPv4
        raw = dest_mac + src_mac + ethertype + b"payload"

        header, remainder = parse_ethernet_header(raw)

        self.assertEqual(header["dest_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(header["src_mac"], "11:22:33:44:55:66")
        self.assertEqual(header["eth_proto"], 0x0800)
        self.assertEqual(remainder, b"payload")


class TestIPv4Parser(unittest.TestCase):
    def test_parses_ttl_protocol_and_addresses(self):
        version_ihl = (4 << 4) | 5  # version 4, IHL 5 (20 bytes)
        header = struct.pack(
            "! B B H H H B B H 4s 4s",
            version_ihl, 0, 40, 0, 0, 64, 6, 0,
            socket.inet_aton("192.168.1.10"),
            socket.inet_aton("192.168.1.20"),
        )
        raw = header + b"payload"

        parsed, remainder = parse_ipv4_header(raw)

        self.assertEqual(parsed["version"], 4)
        self.assertEqual(parsed["header_len"], 20)
        self.assertEqual(parsed["ttl"], 64)
        self.assertEqual(parsed["protocol"], 6)  # TCP
        self.assertEqual(parsed["src_ip"], "192.168.1.10")
        self.assertEqual(parsed["dest_ip"], "192.168.1.20")
        self.assertEqual(remainder, b"payload")


class TestTCPParser(unittest.TestCase):
    def test_parses_ports_and_syn_flag(self):
        data_offset_reserved_flags = (5 << 12) | 0x02  # offset=5 (20B), SYN flag
        header = struct.pack(
            "! H H L L H H H H",
            51342, 443, 1000, 0, data_offset_reserved_flags, 65535, 0, 0,
        )
        raw = header + b"payload"

        parsed, remainder = parse_tcp_header(raw)

        self.assertEqual(parsed["src_port"], 51342)
        self.assertEqual(parsed["dest_port"], 443)
        self.assertEqual(parsed["seq"], 1000)
        self.assertIn("S", parsed["flags"])
        self.assertEqual(remainder, b"payload")

    def test_ack_flag_detected(self):
        data_offset_reserved_flags = (5 << 12) | 0x10  # ACK flag
        header = struct.pack(
            "! H H L L H H H H",
            80, 51342, 5000, 1001, data_offset_reserved_flags, 65535, 0, 0,
        )
        parsed, _ = parse_tcp_header(header)
        self.assertIn("A", parsed["flags"])


class TestUDPParser(unittest.TestCase):
    def test_parses_ports_and_length(self):
        header = struct.pack("! H H H H", 53, 51342, 8, 0)
        raw = header + b"payload"

        parsed, remainder = parse_udp_header(raw)

        self.assertEqual(parsed["src_port"], 53)
        self.assertEqual(parsed["dest_port"], 51342)
        self.assertEqual(parsed["length"], 8)
        self.assertEqual(remainder, b"payload")


class TestICMPParser(unittest.TestCase):
    def test_parses_echo_request_type_and_code(self):
        header = struct.pack("! B B H", 8, 0, 0)  # type 8 = echo request
        raw = header + b"payload"

        parsed, remainder = parse_icmp_header(raw)

        self.assertEqual(parsed["type"], 8)
        self.assertEqual(parsed["code"], 0)
        self.assertEqual(remainder, b"payload")


if __name__ == "__main__":
    unittest.main()
