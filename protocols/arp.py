from protocols.ethernet import Ethernet
from protocols.protocol import Protocol
from network import Network
import struct


class ARP(Protocol):
    TYPE_ID = 0x0806

    BROADCAST_MAC = b"\x00" * 6

    def __init__(self, **kwargs):
        super().__init__("ARP")

        self.header = {
            'hardware_type': kwargs.get('hardware_type', 1),
            'protocol_type': kwargs.get('protocol_type', 0x0800),
            'hardware_length': kwargs.get('hardware_length', 6),
            'protocol_length': kwargs.get('protocol_length', 4),
            'operation': kwargs.get('operation', 1),
            'sender_mac': kwargs.get('sender_mac', Network.get_my_mac(Network.get_default_iface())),
            'sender_ip': kwargs.get('sender_ip', Network.get_my_ip()),
            'target_mac': kwargs.get('target_mac', self.BROADCAST_MAC),
            'target_ip': kwargs.get('target_ip', '192.168.1.1'),
        }

    def to_binary(self) -> bytes:
        arp_bin = struct.pack(
            "!HHBBH",
            self.header['hardware_type'],
            self.header['protocol_type'],
            self.header['hardware_length'],
            self.header['protocol_length'],
            self.header['operation'],
        )

        arp_bin += self.header['sender_mac']
        arp_bin += Network.convert_ip_into_bytes(self.header['sender_ip'])
        arp_bin += self.header['target_mac']
        arp_bin += Network.convert_ip_into_bytes(self.header['target_ip'])
        return arp_bin

    def deserializer(self, data: bytes):
        fields = struct.unpack("!HHBBH6s4s6s4s", data[:28])

        self.header['hardware_type'] = fields[0]
        self.header['protocol_type'] = fields[1]
        self.header['hardware_length'] = fields[2]
        self.header['protocol_length'] = fields[3]
        self.header['operation'] = fields[4]
        # Keep MAC fields as raw bytes (not strings) so a deserialized ARP
        # object remains round-trippable through to_binary() without a
        # type mismatch (e.g. when reusing a received header's fields to
        # craft and send a reply).
        self.header['sender_mac'] = fields[5]
        self.header['sender_ip'] = Network.convert_bytes_into_ip(fields[6])
        self.header['target_mac'] = fields[7]
        self.header['target_ip'] = Network.convert_bytes_into_ip(fields[8])
        return self
    
    def setup(self):
        target_ip = input(f"Target IP to query (default {self.header['target_ip']}): ").strip()
        if target_ip:
            self.header['target_ip'] = target_ip
 
        op = input(f"Operation - 1=request, 2=reply (default {self.header['operation']}): ").strip()
        if op.isdigit() and int(op) in (1, 2):
            self.header['operation'] = int(op)
    
    def get_socket_info(self):
        """ARP has no IP layer above it, so AF_INET sockets don't apply.
        Like Ethernet, this needs AF_header bound to an interface, and
        Network.send_and_received does not yet support that socket family.
        Note: when ARP is properly wrapped inside Ethernet (the correct
        way to send it), Ethernet.get_socket_info() is what should be
        called instead -- this only gets hit if ARP is sent as root
        directly, which menu.py currently allows but shouldn't."""
        import socket
        return socket.SOCK_RAW, ("", 0)
