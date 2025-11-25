from protocols.arp import ARP
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