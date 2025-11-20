from Network import Network
from Protocol import Protocol
from UDP import UDP
import random
import struct

class IPv4(Protocol):
    def __init__(self, **kwargs):
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
            'dst_ip' : kwargs.get("dst_ip", "8.8.8.8"),
        }

    def to_binary(self) -> bytes:
        ip_header = self.build_header(checksum=0)
        self.header['checksum'] = IPv4.ip_checksum(ip_header)
        ip_header = self.build_header(checksum=self.header['checksum'])
        udp_header = self.payload.to_binary(self.header['src_ip'], self.header['dst_ip'])
        self.header['total_length'] = (self.header['IHL'] * 4) + self.payload.header['length']
        return ip_header + udp_header

    def build_header(self, checksum: int) -> bytes:
        first_byte = (self.header['version'] << 4) | (self.header['IHL'] & 0x0F)
        second_byte = ((self.header['DSCP'] & 0x3F) << 2) | (self.header['ECN'] & 0x03)

        header = first_byte.to_bytes(1, 'big') + second_byte.to_bytes(1, 'big')
        header += struct.pack('!2H', self.header['total_length'], self.header['identification'])
        header += ((self.header['flags'] & 0x7) << 13 | (self.header['frag_offset'] & 0x1FFF)).to_bytes(2, 'big')
        header += struct.pack('!2BH', self.header['TTL'], self.header['Protocol'], checksum)
        header += Network.convert_ip_into_bytes(self.header['src_ip'])
        header += Network.convert_ip_into_bytes(self.header['dst_ip'])
        return header

    def deserializer(self, data) -> Protocol:
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
        self.header['TTL'], self.header['Protocol'], self.header['checksum'] = struct.unpack('!2BH', data[8:12])

        self.header['src_ip'] = Network.convert_bytes_into_ip(data[12:16])
        self.header['dst_ip'] = Network.convert_bytes_into_ip(data[16:20])

        ihl_bytes = self.header['IHL'] * 4
        total_len = self.header['total_length']
        if total_len < ihl_bytes:
            raise ValueError("Invalid total_length smaller than header length")

        end = min(len(data), total_len)
        payload_data = data[ihl_bytes:end]

        if self.header['Protocol'] == 17:
            from UDP import UDP
            udp_obj = UDP().deserializer(payload_data)
            self.payload = udp_obj
        else:
            self.payload = payload_data

        return self

    @staticmethod
    def ip_checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack(f"!{len(data) // 2}H", data))
        s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    def __str__(self):
        return f"IP({self.header})\n{self.payload.__str__()}\n{self.payload.payload.__str__()}"



