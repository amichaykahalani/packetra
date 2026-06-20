# Packetra – Network Packet Crafting & Analysis Tool

Packetra is a Python-based, low-level network packet crafting and analysis tool built for networking research, protocol understanding, and cybersecurity education.

Every packet is hand-built from raw bytes using `struct` and raw sockets — there's no Scapy or other packet-crafting library underneath. The goal is to make the full layering, serialization, and socket-handling process visible and hackable, not to wrap an existing tool.

---

## Requirements

- **Linux only.** Packetra relies on `AF_PACKET` sockets for Ethernet/ARP, `IPPROTO_RAW`/`IP_HDRINCL` for raw IP construction, `/proc/net/route` for interface detection, and `fcntl`/`ioctl` for MAC address lookups — all Linux-specific. It will not run as-is on macOS or Windows.
- **Root / `CAP_NET_RAW`.** Raw socket creation requires elevated privileges. Run with `sudo`, or grant the capability directly:
  
  ```bash
  sudo setcap cap_net_raw+ep $(which python3)
  ```
- Python 3.8+

---

## Features

- Craft custom packets across multiple layers: **Ethernet II, ARP, IPv4, UDP, ICMP, DNS, NTP**
- Build nested packet structures, e.g.:
  - `IPv4 → UDP → DNS`
  - `IPv4 → UDP → NTP`
  - `IPv4 → ICMP`
  - `Ethernet → ARP`
- Interactive CLI for real-time packet construction — edit any field, in any part, before sending
- The menu auto-wraps protocols that can't stand alone (UDP-borne protocols get `IPv4 → UDP → X`; ARP gets `Ethernet → ARP`) so you don't have to hand-build the lower layers every time
- Send crafted packets and parse the real response back into the same layered structure
- Built-in attack/stress-testing primitives (UDP flood, ICMP flood, DNS/NTP amplification, ARP spoofing) for controlled lab use

---

## Educational Purpose

Packetra is designed to help users understand:

- The OSI model and how layers actually separate and encapsulate data
- TCP/IP protocol stack behavior, byte-for-byte
- Packet encapsulation/decapsulation in practice, not just diagrams
- The real field structure of common network protocols
- How checksums, pseudo-headers, and reply matching work under the hood

---

## Example Use Case

Build and send `IPv4 → UDP → DNS`:

1. Launch Packetra and choose **DNS** from the packet menu — IPv4 and UDP are wrapped around it automatically
2. Set the destination IP and the domain to query
3. Edit any header field interactively (transaction ID, flags, etc.)
4. Send the packet and view the parsed response, including the answer section

---

## Supported Protocols

- **Ethernet II** (L2) — Linux/`AF_PACKET` only
- **ARP** (L2) — auto-wrapped in Ethernet from the menu
- **IPv4** (L3)
- **ICMP** (L4) — auto-wrapped in IPv4 from the menu
- **UDP** (L4) — auto-wrapped in IPv4 from the menu
- **DNS** (L7) — auto-wrapped in IPv4 → UDP from the menu
- **NTP** (L7) — modes 3/4 (client/server) and 6 (control); auto-wrapped in IPv4 → UDP from the menu

---

## Ethical and Legal Notice

Packetra is intended strictly for educational use and **authorized** testing environments — your own lab, a network you own, or a target you have explicit written permission to test.

Using this tool against systems, networks, or devices without authorization is illegal in most jurisdictions and is strictly prohibited. This applies in particular to the attack/flood/spoofing features, which are included for controlled lab demonstration of how these attacks work, not for use against real infrastructure.

The author assumes no responsibility for misuse or damage caused by this tool.
