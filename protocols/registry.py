from .arp import ARP
from .ipv4 import IPv4
from .icmp import ICMP
from .udp import UDP

class Registry:
    def __init__(self):
        self.ether_type = {0x0806: ARP,
                          0x0800: IPv4}

        self.ip_type = {1: ICMP,
                        17: UDP}

