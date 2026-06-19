import logging

from protocols.arp import ARP
from protocols.dns import DNS
from protocols.ethernet import Ethernet
from protocols.icmp import ICMP
from protocols.ipv4 import IPv4
from protocols.ntp import NTP
from protocols.udp import UDP

logger = logging.getLogger(__name__)


class ProtocolFactory:
    # Lookup is case-insensitive on the key; built once at class-definition
    # time rather than rebuilt on every create() call.
    _PROTOCOLS = {
        'dns': DNS,
        'ipv4': IPv4,
        'udp': UDP,
        'ntp': NTP,
        'arp': ARP,
        'ethernet': Ethernet,
        'icmp': ICMP,
    }

    @staticmethod
    def create(name: str):
        protocol_class = ProtocolFactory._PROTOCOLS.get(name.strip().lower())

        if protocol_class is None:
            available = ", ".join(sorted(ProtocolFactory._PROTOCOLS.keys()))
            logger.warning("Protocol '%s' not found. Available: %s", name, available)
            return None

        return protocol_class()

    @staticmethod
    def available_protocols() -> list[str]:
        """Returns the list of protocol names create() will accept."""
        return sorted(ProtocolFactory._PROTOCOLS.keys())