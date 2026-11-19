# Network Packet Analyzer

A live network traffic analyzer built in Python using raw sockets —
no Scapy, no pyshark. Every header (Ethernet, IPv4, TCP, UDP, ICMP) is
parsed by hand from the raw bytes using Python's `struct` module, to
demonstrate a real working understanding of the TCP/IP stack at the
wire level rather than relying on a library to do the parsing.

## What it does

- Opens a raw socket and captures live traffic on the local interface
- Parses Ethernet headers (source/destination MAC, ethertype)
- Parses IPv4 headers (source/destination IP, TTL, protocol)
- Parses TCP headers (ports, sequence/ack numbers, flags)
- Parses UDP headers (ports, length)
- Parses ICMP headers (type, code)
- Prints each packet in real time with source/destination info
- Supports filtering by protocol (`--protocol tcp/udp/icmp`)
- Prints a summary of protocol distribution when you stop the capture

## Example output

```
$ sudo python3 packet_analyzer.py --protocol tcp
Capturing packets... Ctrl+C to stop.

[TCP] 192.168.1.15 -> 142.250.72.14  TTL=64  51342 -> 443  flags=-S-A--  payload=0B
[TCP] 142.250.72.14 -> 192.168.1.15  TTL=115  443 -> 51342  flags=-SFA--  payload=0B
[TCP] 192.168.1.15 -> 142.250.72.14  TTL=64  51342 -> 443  flags=----A-  payload=517B
^C
--- Capture Summary ---
Total packets captured: 3
Duration: 4.2s
  TCP   :      3 (100.0%)
```

## Requirements

- Linux (this uses `socket.AF_PACKET`, which is Linux-specific — see
  [docs/platform-notes.md](docs/platform-notes.md) for why macOS/Windows
  need a different approach)
- Python 3.8+
- Root privileges (raw sockets require `CAP_NET_RAW`)

No external dependencies — standard library only.

## Usage

```bash
# Capture everything
sudo python3 packet_analyzer.py

# Only show TCP traffic
sudo python3 packet_analyzer.py --protocol tcp

# Stop after 50 packets
sudo python3 packet_analyzer.py --count 50
```

Run `python3 packet_analyzer.py --help` for all options.

## How the parsing works

Each header is unpacked with `struct.unpack` using a format string that
matches the exact byte layout defined in the relevant RFC:

| Header | Size | Reference |
|---|---|---|
| Ethernet II | 14 bytes | dest MAC (6B) + src MAC (6B) + ethertype (2B) |
| IPv4 | 20 bytes (no options) | [RFC 791](https://www.rfc-editor.org/rfc/rfc791) |
| TCP | 20 bytes (no options) | [RFC 793](https://www.rfc-editor.org/rfc/rfc793) |
| UDP | 8 bytes | [RFC 768](https://www.rfc-editor.org/rfc/rfc768) |
| ICMP | 4 bytes (type/code/checksum) | [RFC 792](https://www.rfc-editor.org/rfc/rfc792) |

See [docs/protocol-reference.md](docs/protocol-reference.md) for a
byte-by-byte breakdown of each header and how the offsets in the code
map to it.

## Project structure

```
network-packet-analyzer/
├── packet_analyzer.py          # main script
├── docs/
│   ├── protocol-reference.md   # header byte-layout notes
│   └── platform-notes.md       # why this needs Linux + raw sockets
├── tests/
│   └── test_parsers.py         # unit tests for header parsing functions
└── screenshots/                # example capture output
```

## Known limitations

- IPv4 only (no IPv6 parsing yet)
- Assumes no IP/TCP options (20-byte headers) — packets with options
  will have their payload offset calculated incorrectly if not
  accounted for (this is actually handled via the IHL/data-offset
  fields, but options themselves aren't decoded)
- Ethernet only — no support for other link-layer types
- Linux only, due to `AF_PACKET`

## Roadmap

- [ ] Add IPv6 header parsing
- [ ] Decode TCP options (MSS, window scaling, SACK)
- [ ] Add a `--pcap` export option to save captures for Wireshark
- [ ] Add basic anomaly flags (e.g. SYN flood detection: high rate of SYN with no matching ACK)

## Legal / ethical note

This tool only captures traffic visible to the interface it runs on
(your own machine's traffic, or traffic on a network you have explicit
permission to monitor). Capturing network traffic you don't own or
don't have permission to monitor may be illegal depending on your
jurisdiction. Use only on your own lab network or networks you're
authorized to test.

## License

MIT
