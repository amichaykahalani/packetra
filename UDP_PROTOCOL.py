from NTP_PROTOCOL import NTP
from NetworkHandler import Network
from BaseProtocol import Protocol
import struct
import typing
import random


class UDP(Protocol):
    def __init__(self, **kwargs):
        super().__init__('UDP')
        # ------------Header------------
        self.header: typing.Dict[str, typing.Any] = {
            'src_port': kwargs.get('src_port', random.randint(1025, 65535)),
            'dst_port': kwargs.get('dst_port', 53),
            'checksum': 0,
            'length': None
        }

    def to_binary(self, src_ip, dst_ip) -> bytes:
        payload_bin = self.payload.to_binary()

        length = 8 + len(payload_bin)
        self.header['length'] = length

        udp_header = struct.pack("!HHHH",
                                 self.header['src_port'],
                                 self.header['dst_port'],
                                 self.header['length'],
                                 self.header['checksum'])
        checksum = UDP.udp_checksum(src_ip, dst_ip, udp_header, payload_bin)
        self.header['checksum'] = checksum
        udp_header = struct.pack("!HHHH",
                                 self.header['src_port'],
                                 self.header['dst_port'],
                                 self.header['length'],
                                 self.header['checksum'])

        return udp_header + payload_bin

    def deserializer(self, data: bytes) -> Protocol:
        from DNS_PROTOCOL import DNS
        self.header['src_port'], self.header['dst_port'], self.header['checksum'], self.header[
            'length'] = struct.unpack('!4H', data[:8])
        payload_data = data[8:self.header['length']]

        if self.header['src_port'] == 53 or self.header['dst_port'] == 53:
            dns = DNS(is_response=True)
            dns.deserializer(payload_data)
            self.payload = dns

        if self.header['src_port'] == 123 or self.header['dst_port'] == 123:
            ntp = NTP()
            ntp.deserializer(payload_data)
            self.payload = ntp

        return self

    def __str__(self) -> str:
        return f'UDP({self.header})'

    @staticmethod
    def udp_checksum(src_ip, dst_ip, udp_header, udp_payload):
        pseudo_header = struct.pack(
            "!4s4sBBH",
            Network.convert_ip_into_bytes(src_ip),
            Network.convert_ip_into_bytes(dst_ip),
            0,
            17,  # UDP
            len(udp_header) + len(udp_payload)
        )
        data = pseudo_header + udp_header + udp_payload

        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack(f"!{len(data) // 2}H", data))
        s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff