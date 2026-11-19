# Protocol Reference

Byte-by-byte notes on each header this tool parses, and how that maps
to the `struct.unpack` format strings in `packet_analyzer.py`.

## Ethernet II header (14 bytes)

| Bytes | Field | Format code |
|---|---|---|
| 0–5 | Destination MAC | `6s` |
| 6–11 | Source MAC | `6s` |
| 12–13 | EtherType (e.g. 0x0800 = IPv4) | `H` |

Format string used: `"! 6s 6s H"`
`!` forces network byte order (big-endian), which matters — without it,
the EtherType field would come out byte-swapped.

## IPv4 header (20 bytes, no options)

| Bytes | Field | Notes |
|---|---|---|
| 0 | Version (4 bits) + IHL (4 bits) | IHL is header length in 32-bit words; multiply by 4 for bytes |
| 1 | DSCP/ECN | Skipped in this implementation |
| 2–3 | Total length | Skipped |
| 4–5 | Identification | Skipped |
| 6–7 | Flags + Fragment offset | Skipped |
| 8 | TTL | `B` |
| 9 | Protocol (6=TCP, 17=UDP, 1=ICMP) | `B` |
| 10–11 | Header checksum | Skipped |
| 12–15 | Source IP | `4s`, converted with `socket.inet_ntoa` |
| 16–19 | Destination IP | `4s` |

Format string used: `"! 8x B B H 4s 4s"` — the `8x` skips the first 8
bytes we don't care about, landing directly on TTL.

**Why IHL matters:** if a packet has IP options, the header is longer
than 20 bytes. The code always calculates the real header length from
IHL (`(version_ihl & 0xF) * 4`) and slices the payload from there, so
options-bearing packets are still handled correctly for the purposes of
finding where the header ends — the options themselves just aren't
decoded.

## TCP header (20 bytes, no options)

| Bytes | Field |
|---|---|
| 0–1 | Source port |
| 2–3 | Destination port |
| 4–7 | Sequence number |
| 8–11 | Acknowledgment number |
| 12 | Data offset (4 bits) + reserved (4 bits) |
| 13 | Flags (6 bits used: URG, ACK, PSH, RST, SYN, FIN) |
| 14–15 | Window size |
| 16–17 | Checksum |
| 18–19 | Urgent pointer |

This tool only unpacks through byte 14 (`"! H H L L H"`, 14 bytes) since
that's enough to get ports, sequence/ack numbers, and the flags/offset
field. Window size, checksum, and urgent pointer are not currently
displayed.

**Flag bits**, from the combined offset+flags 16-bit field:
```
bit 0 (0x01) = FIN
bit 1 (0x02) = SYN
bit 2 (0x04) = RST
bit 3 (0x08) = PSH
bit 4 (0x10) = ACK
bit 5 (0x20) = URG
```

## UDP header (8 bytes)

| Bytes | Field |
|---|---|
| 0–1 | Source port |
| 2–3 | Destination port |
| 4–5 | Length (header + data) |
| 6–7 | Checksum |

Format string used: `"! H H H H"`.

## ICMP header (first 4 bytes)

| Bytes | Field |
|---|---|
| 0 | Type (8 = Echo Request, 0 = Echo Reply, etc.) |
| 1 | Code |
| 2–3 | Checksum |

Format string used: `"! B B H"`. The rest of the ICMP packet (e.g. the
echo identifier/sequence for ping) isn't parsed in this version.
