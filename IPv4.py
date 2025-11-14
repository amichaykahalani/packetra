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
            'src_ip' : 0,
            'dst_ip' : 0
        }

    def to_binary(self) -> bytes:
        ip_header = b''
        first_byte = (self.header['version'] << 4 | self.header['IHL'])
        second_byte = (self.header['DSCP'] << 6 | self.header['ECN'])
        second_byte_value = second_byte.to_bytes(1, byteorder='big')
        first_byte_value = first_byte.to_bytes(1, 'big')
        ip_header += first_byte_value + second_byte_value
        ip_header += struct.pack('!2H', self.header['total_length'], self.header['identification'])
        ip_header += (self.header['flags'] << 13 | self.header['frag_offset']).to_bytes(2, byteorder='big')
        ip_header += struct.pack('!2BH2I', self.header['TTL'], self.header['Protocol'], self.header['checksum'], self.header['src_ip'], self.header['dst_ip'])

        return ip_header
