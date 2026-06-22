import random
import struct
import socket
import typing

from network import Network
from protocols.protocol import Protocol


class UDP(Protocol):
    TYPE_ID = 17
    HEADER_LENGTH = 8

    def __init__(self, **kwargs):
        super().__init__("UDP")
        self.header: typing.Dict[str, typing.Any] = {
            "src_port": kwargs.get("src_port", random.randint(1025, 65535)),
            "dst_port": kwargs.get("dst_port", 53),
            "checksum": 0,
            "length": 0,
        }
        # set by IPv4.to_binary() before to_binary() runs, since the checksum
        # needs the pseudo-header. only used standalone if UDP is the root.
        self.src_ip = ""
        self.dst_ip = ""
        self.payload = None

    def setup(self):
        port = input(f"Destination port (default {self.header['dst_port']}): ").strip()
        if port.isdigit():
            self.header["dst_port"] = int(port)

    def to_binary(self) -> bytes:
        payload_bin = self.payload.to_binary() if self.payload else b""
        self.header["length"] = self.HEADER_LENGTH + len(payload_bin)

        udp_header = self._pack_header(checksum=0)
        self.header["checksum"] = UDP.udp_checksum(
            self.src_ip, self.dst_ip, udp_header, payload_bin
        )
        udp_header = self._pack_header(checksum=self.header["checksum"])

        return udp_header + payload_bin

    def _pack_header(self, checksum: int) -> bytes:
        return struct.pack(
            "!HHHH",
            self.header["src_port"],
            self.header["dst_port"],
            self.header["length"],
            checksum,
        )

    def deserializer(self, data: bytes) -> Protocol:
        header_data = struct.unpack("!4H", data[:8])
        (
            self.header["src_port"],
            self.header["dst_port"],
            self.header["length"],
            self.header["checksum"],
        ) = header_data

        payload_data = data[8 : self.header["length"]]

        next_proto_class = Protocol.registry.get(self.header["dst_port"])
        if next_proto_class and len(payload_data) > 0:
            self.payload = next_proto_class().deserializer(payload_data)
        else:
            self.payload = None

        return self

    @staticmethod
    def udp_checksum(
        src_ip: str, dst_ip: str, udp_header: bytes, udp_payload: bytes = None
    ) -> int:
        pseudo_header = struct.pack(
            "!4s4sBBH",
            Network.convert_ip_into_bytes(src_ip),
            Network.convert_ip_into_bytes(dst_ip),
            0,
            17,
            len(udp_header) + (len(udp_payload) if udp_payload else 0),
        )
        data = pseudo_header + udp_header + (udp_payload if udp_payload else b"")

        if len(data) % 2:
            data += b"\x00"

        s = sum(struct.unpack(f"!{len(data) // 2}H", data))
        s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xFFFF
        return s if s != 0 else 0xFFFF

    def get_socket_info(self):
        # only matters if UDP is the root protocol on its own —
        # nested under IPv4, IPv4.get_socket_info() handles this instead
        return socket.SOCK_DGRAM, (self.dst_ip, self.header["dst_port"])
