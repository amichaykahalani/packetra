import struct

from protocols.protocol import Protocol


class Ethernet(Protocol):
    TYPE_ID = 3
    BROADCAST_MAC = bytes([0xFF] * 6)
    HEADER_LENGTH = 14  # dst (6) + src (6) + ethertype (2)

    def __init__(self, **kwargs):
        from network import Network
        super().__init__('Ethernet')

        self.header = {
            'dst_mac_addr': kwargs.get('dst_mac_addr', self.BROADCAST_MAC),
            'src_mac_addr': kwargs.get('src_mac_addr', Network.get_my_mac(Network.get_default_iface())),
            'type': kwargs.get('type', 0x0806),
            }

        self.data = b'',
        

        self.payload = None

    def to_binary(self):
        bin_frame = (
            self.header["dst_mac_addr"] +
            self.header["src_mac_addr"] +
            struct.pack("!H", self.header["type"])
        )

        if self.payload:
            self.data = self.payload.to_binary()

        return bin_frame + self.data

    def deserializer(self, data: bytes):
        if len(data) < self.HEADER_LENGTH:
            raise ValueError("Data too short for Ethernet header")

        self.header["dst_mac_addr"] = data[:6]
        self.header["src_mac_addr"] = data[6:12]
        self.header["type"] = struct.unpack("!H", data[12:14])[0]

        self.data = data[self.HEADER_LENGTH:]
        self.frame['data'] = payload_data
        self.payload = self._deserialize_payload(payload_data)

        return self

    def _deserialize_payload(self, payload_data: bytes):
        ethertype = self.frame['header']['type']

        if ethertype == 0x0806 and len(payload_data) >= 28:  # ARP
            from protocols.arp import ARP
            return ARP().deserializer(payload_data)

        return None

    def get_socket_info(self):
        """Ethernet frames require a raw L2 socket (AF_PACKET), not the
        AF_INET raw sockets used by IPv4/ICMP. Network.send_and_received
        currently only opens AF_INET sockets, so sending an Ethernet
        frame as the root protocol will not work without changes there."""
        import socket
        return socket.SOCK_RAW, ("", 0)

    @staticmethod
    def mac_to_str(mac_bytes: bytes) -> str:
        return ':'.join(f'{b:02x}' for b in mac_bytes)