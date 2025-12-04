*Packetra – Network Packet Crafting Tool*

Packetra is an advanced Python tool for creating, customizing, and sending network packets. It supports multiple protocols, including IPv4, UDP, ICMP, DNS, NTP, Ethernet, and ARP. This tool is designed for learning, testing, and research purposes in networking and cybersecurity.

*Features*

Craft packets for IPv4, UDP, ICMP, DNS, NTP, Ethernet, and ARP.

Add nested payloads (e.g., IP → UDP → DNS/NTP).

Interactive modification of packet fields (IP headers, UDP ports, DNS questions, NTP timestamps, etc.).

Send packets and receive responses from real servers.

Supports raw packet building for advanced networking experiments.

Simple, user-friendly command-line interface.
You will be prompted to choose an action:

- DoS Attack

- MITM Attack

- Create packets

Follow the prompts to build your packets:

- Select the protocol(s) you want to use.

- Add nested protocols if needed.

- Modify fields interactively.

- Send the packet and view the response.

Example:
Craft an IPv4 packet with UDP → DNS payload, change the DNS query domain, and send it to a DNS server.

*Supported Protocols*

- IPv4

- UDP

- ICMP

- DNS

- NTP

- Ethernet

- ARP

*Security and Legal Disclaimer*

Packetra is intended for educational and research purposes only.

Do not use this tool to attack systems without permission. Unauthorized use may violate laws and regulations.

Users are fully responsible for their actions.