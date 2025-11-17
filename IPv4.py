from Network import Network
from Protocol import Protocol
import random
import struct

class IPv4(Protocol):
    def __init__(self):
        super().__init__('IPv4')
        self.header = {
            'version': 4,
            'IHL': 5,
            'DSCP': 0,
            'ECN': 0,
            'total_length': 20 + 8,
            'identification': random.randint(0, 65535),
            'flags':0,
            'frag_offset': 0,
            'TTL' : 64,
            'Protocol': 17,
            'checksum': 0,
            'src_ip' : Network.get_my_ip(),
            'dst_ip' : '8.8.8.8'
        }

    def to_binary(self) -> bytes:
        print("---------------IPv4 to_binary-----------------")
        ip_header = self.build_header(checksum=0)
        self.header['checksum'] = IPv4.ip_checksum(ip_header)
        ip_header = self.build_header(checksum=self.header['checksum'])
        udp_header = self.payload.to_binary(src_ip=self.header['src_ip'], dst_ip=self.header['dst_ip'])
        self.header['total_length'] = (self.header['IHL'] * 4) + self.payload.header['length']
        return ip_header + udp_header

    def build_header(self, checksum: int) -> bytes:
        first_byte = (self.header['version'] << 4 | self.header['IHL'])
        second_byte = (self.header['DSCP'] << 6 | self.header['ECN'])
        header = first_byte.to_bytes(1, 'big') + second_byte.to_bytes(1, 'big')
        header += struct.pack('!2H', self.header['total_length'], self.header['identification'])
        header += (self.header['flags'] << 13 | self.header['frag_offset']).to_bytes(2, 'big')
        header += struct.pack('!2BH', self.header['TTL'], self.header['Protocol'], checksum)
        header += Network.convert_ip_into_bytes(self.header['src_ip'])
        header += Network.convert_ip_into_bytes(self.header['dst_ip'])
        return header

    def deserializer(self, data) -> Protocol:
        return IPv4()

    @staticmethod
    def ip_checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack(f"!{len(data) // 2}H", data))
        s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

