# Platform Notes

## Why this only runs on Linux

This tool uses `socket.AF_PACKET`, which gives access to raw Ethernet
frames directly from a network interface. This socket family is
**Linux-specific**:

- **Linux**: `AF_PACKET` + `SOCK_RAW` gives full access to raw Ethernet
  frames, which is what lets this tool parse the Ethernet header itself.
- **macOS/BSD**: doesn't have `AF_PACKET`. Raw packet capture there
  normally goes through BPF (Berkeley Packet Filter) devices
  (`/dev/bpf*`), which uses a different API entirely.
- **Windows**: doesn't support raw sockets for arbitrary packet capture
  at all without a driver like Npcap/WinPcap (which is what tools like
  Wireshark install under the hood).

## Running this on non-Linux systems

The easiest path is to run this inside a Linux VM or container:

```bash
# Using a lightweight Ubuntu container (requires --privileged for raw sockets)
docker run --rm -it --privileged --net=host ubuntu:24.04 bash
apt update && apt install -y python3
python3 packet_analyzer.py
```

A future version of this project could add a BPF-based backend for
macOS and an Npcap-based backend for Windows, but that would add an
external dependency (e.g. `pyshark`/`scapy`) — this version intentionally
stays dependency-free to keep the header-parsing logic fully visible
and hand-written.

## Why root/administrator is required

Opening a raw socket lets a program see every packet on the interface,
not just traffic addressed to it — this is a privileged operation on
every OS, gated by `CAP_NET_RAW` on Linux specifically. This is a
standard, well-understood requirement (the same reason `tcpdump` and
Wireshark's capture engine also need elevated privileges), not a
security issue specific to this script.
