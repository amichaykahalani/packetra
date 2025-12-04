from protocols.arp import ARP
from protocols.ethernet import Ethernet
from protocols.ipv4 import IPv4
from protocols.icmp import ICMP
from protocols.udp import UDP
from protocols.ntp import NTP
from protocols.dns import DNS

class Registry:
    def __init__(self):
        self.ether_type = {
            0x0806: ARP(),
            0x0800: IPv4()
        }

        self.ip_type = {
            1: ICMP(),
            17: UDP()
        }

        self.protocol_ports = {
            53: DNS(),
            123: NTP()
        }

        self.packets = {
            1: DNS,
            2: NTP,
            3: Ethernet,
            4: IPv4
        }

        #i changed things here dont forget
        self.ip_protocols = {
            "udp": UDP(),
            "icmp": ICMP()
        }

        self.ethernet_protocols = {
            "arp": ARP(),
        }