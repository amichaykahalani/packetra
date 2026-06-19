import struct

from message import Data
from protocols.protocol import Protocol
from utils import Utils


class ICMP(Protocol):
    TYPE_ID = 1

    # ICMP types that use the echo request/reply format (identifier + sequence)
    ECHO_TYPES = (0, 8)

    def __init__(self, **kwargs):
        super().__init__('ICMP')
        icmp_type = kwargs.get('type', 8)

        if icmp_type in self.ECHO_TYPES:
            self.header = {
                'type': icmp_type,
                'code': kwargs.get('code', 0),
                'checksum': kwargs.get('checksum', 0),
                'identifier': kwargs.get('identifier', 0),
                'sequence': kwargs.get('sequence', 0),
            }
        else:
            self.header = {
                'type': icmp_type,
                'code': kwargs.get('code', 0),
                'unused': kwargs.get('unused', 0),
                'sequence': kwargs.get('sequence', 0),
            }

        self.payload = Data(kwargs.get('payload', ""))

    def setup(self):
        icmp_type = input(f"ICMP type (default {self.header['type']}): ").strip()
        if icmp_type.isdigit():
            new_type = int(icmp_type)
            if (new_type in self.ECHO_TYPES) != (self.header['type'] in self.ECHO_TYPES):
                self.__init__(type=new_type)
            else:
                self.header['type'] = new_type

        if self.header['type'] in self.ECHO_TYPES:
            import random
            self.header['identifier'] = random.randint(1, 65535)
            self.header['sequence'] = 1

    def _pack_header(self, checksum: int) -> bytes:
        if self.header['type'] in self.ECHO_TYPES:
            return struct.pack(
                '!BBHHH',
                self.header['type'],
                self.header['code'],
                checksum,
                self.header['identifier'],
                self.header['sequence'],
            )
        return struct.pack(
            '!BBHI',
            self.header['type'],
            self.header['code'],
            checksum,
            self.header['unused'],
        )

    def to_binary(self) -> bytes:
        payload = self.payload.to_binary() or b''

        header = self._pack_header(checksum=0)
        self.header['checksum'] = Utils.checksum(header + payload)
        header = self._pack_header(checksum=self.header['checksum'])

        return header + payload

    def deserializer(self, data: bytes):
        print(f"[DEBUG] ICMP raw bytes: {data[:8].hex()}")
        self.header['type'], self.header['code'], self.header['checksum'] = struct.unpack('!BBH', data[:4])

        if self.header['type'] in self.ECHO_TYPES:
            self.header['identifier'], self.header['sequence'] = struct.unpack('!HH', data[4:8])
        else:
            self.header['unused'] = struct.unpack('!I', data[4:8])[0]

        self.payload = Data(data[8:])
        return self

    def get_socket_info(self):
        """Only relevant if ICMP is ever sent standalone (not wrapped in
        IPv4). When nested, IPv4.get_socket_info() handles the raw
        socket instead."""
        import socket
        return socket.SOCK_RAW, ("", 0)
