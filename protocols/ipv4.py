import random
import struct
from typing import Dict

from network import Network
from protocols.protocol import Protocol
from utils import Utils


class IPv4(Protocol):
    TYPE_ID = 0x0800

    # Protocol numbers this class knows how to serialize as a payload
    SUPPORTED_PROTOCOLS = {17, 1}  # UDP, ICMP

    def __init__(self, **kwargs):
        super().__init__('IPv4')
        self.header: Dict[str, int | str] = {
            'version': 4,
            'IHL': 5,
            'DSCP': 0,
            'ECN': 0,
            'total_length': 20 + 8,
            'identification': random.randint(0, 65535),
            'flags': 0,
            'frag_offset': 0,
            'TTL': 64,
            'protocol': 17,
            'checksum': 0,
            'src_ip': kwargs.get('src_ip', Network.get_my_ip()),
            'dst_ip': kwargs.get('dst_ip', '8.8.8.8'),
        }

    def setup(self):
        dst = input("Enter Destination IP: ").strip()
        if dst:
            self.header['dst_ip'] = dst

    def to_binary(self) -> bytes:
        self.header['protocol'] = self.get_protocol_number()
        payload = self._build_payload()

        ip_header = self.build_header(checksum=0)
        self.header['checksum'] = Utils.checksum(ip_header)
        ip_header = self.build_header(checksum=self.header['checksum'])

        return ip_header + payload

    def _build_payload(self) -> bytes:
        """Serialize self.payload, propagating IP context where the
        sub-protocol needs it (e.g. UDP/TCP checksums)."""
        protocol_id = self.header['protocol']

        if protocol_id not in self.SUPPORTED_PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {protocol_id}")

        if protocol_id == 17:  # UDP
            self.payload.src_ip = self.header['src_ip']
            self.payload.dst_ip = self.header['dst_ip']
            payload_bin = self.payload.to_binary()
            self.header['total_length'] = self.header['IHL'] * 4 + self.payload.header['length']
        else:  # ICMP (protocol_id == 1)
            payload_bin = self.payload.to_binary()
            self.header['total_length'] = self.header['IHL'] * 4 + len(payload_bin)

        return payload_bin

    def build_header(self, checksum: int) -> bytes:
        first_byte = (self.header['version'] << 4) | (self.header['IHL'] & 0x0F)
        second_byte = ((self.header['DSCP'] & 0x3F) << 2) | (self.header['ECN'] & 0x03)

        header = first_byte.to_bytes(1, 'big') + second_byte.to_bytes(1, 'big')
        header += struct.pack('!2H', self.header['total_length'], self.header['identification'])
        header += ((self.header['flags'] & 0x7) << 13 | (self.header['frag_offset'] & 0x1FFF)).to_bytes(2, 'big')
        header += struct.pack('!2BH', self.header['TTL'], self.header['protocol'], checksum)
        header += Network.convert_ip_into_bytes(self.header['src_ip'])
        header += Network.convert_ip_into_bytes(self.header['dst_ip'])
        return header

    def deserializer(self, data: bytes) -> Protocol:
        if len(data) < 20:
            raise ValueError("IPv4 packet too short")

        first_byte = data[0]
        self.header['version'] = first_byte >> 4
        self.header['IHL'] = first_byte & 0x0F

        second_byte = data[1]
        self.header['DSCP'] = second_byte >> 2
        self.header['ECN'] = second_byte & 0x03

        self.header['total_length'], self.header['identification'] = struct.unpack('!2H', data[2:6])

        flags_and_frag_offset = struct.unpack('!H', data[6:8])[0]
        self.header['flags'] = flags_and_frag_offset >> 13
        self.header['frag_offset'] = flags_and_frag_offset & 0x1FFF

        self.header['TTL'], self.header['protocol'], self.header['checksum'] = struct.unpack('!2BH', data[8:12])
        self.header['src_ip'] = Network.convert_bytes_into_ip(data[12:16])
        self.header['dst_ip'] = Network.convert_bytes_into_ip(data[16:20])

        ihl_bytes = self.header['IHL'] * 4
        total_len = self.header['total_length']
        if total_len < ihl_bytes:
            raise ValueError("Invalid total_length: smaller than header length")

        payload_data = data[ihl_bytes:min(len(data), total_len)]

        protocol_class = Protocol.registry.get(self.header['protocol'])
        if protocol_class:
            self.payload = protocol_class()
            self.payload.deserializer(payload_data)
        else:
            print(f"Warning: Unknown protocol ID {self.header['protocol']}")
            self.payload = None

        return self

    def get_protocol_number(self) -> int:
        return getattr(self.payload, 'TYPE_ID', 17)

    def get_socket_info(self):
        """IPv4 packets are hand-built (custom header + checksum), so they
        must go out over a raw socket rather than a regular UDP/ICMP socket."""
        import socket
        return socket.SOCK_RAW, (self.header['dst_ip'], 0)

   