import struct

from protocols.protocol import Protocol


class Ethernet(Protocol):
    TYPE_ID = 3
    BROADCAST_MAC = bytes([0xFF] * 6)
    HEADER_LENGTH = 14  # dst (6) + src (6) + ethertype (2)

    def __init__(self, **kwargs):
        from network import Network

        super().__init__("Ethernet")

        # Track whether the caller explicitly chose an ethertype. If not,
        # to_binary() will derive it automatically from whatever protocol
        # ends up attached as payload (IPv4, ARP, etc) instead of being
        # hardcoded to any one value.
        self._type_explicit = "type" in kwargs

        self.header = {
            "dst_mac_addr": kwargs.get("dst_mac_addr", self.BROADCAST_MAC),
            "src_mac_addr": kwargs.get(
                "src_mac_addr", Network.get_my_mac(Network.get_default_iface())
            ),
            "type": kwargs.get(
                "type", 0x0800
            ),  # sensible default (IPv4); overridden below if not explicit
        }

        self.data = b""
        self.payload = None

    def setup(self):
        current = Ethernet.mac_to_str(self.header["dst_mac_addr"])
        dst = input(
            f"Destination MAC (default {current}, blank for broadcast): "
        ).strip()
        if dst:
            try:
                self.header["dst_mac_addr"] = bytes(int(b, 16) for b in dst.split(":"))
            except (ValueError, IndexError):
                print(f"Couldn't parse '{dst}' as a MAC address, keeping {current}.")

        ethertype = input(
            f"Ethertype override in hex, e.g. 0800 (default: auto from payload, currently {hex(self.header['type'])}): "
        ).strip()
        if ethertype:
            try:
                self.header["type"] = int(ethertype, 16)
                self._type_explicit = True
            except ValueError:
                print(
                    f"Couldn't parse '{ethertype}' as hex, leaving ethertype auto-derived."
                )

    def to_binary(self):
        if self.payload is not None and not self._type_explicit:
            payload_type_id = getattr(self.payload, "TYPE_ID", None)
            if payload_type_id is not None:
                self.header["type"] = payload_type_id

        bin_frame = (
            self.header["dst_mac_addr"]
            + self.header["src_mac_addr"]
            + struct.pack("!H", self.header["type"])
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

        self.data = data[self.HEADER_LENGTH :]
        payload_data = self.data
        self.payload = self._deserialize_payload(payload_data)

        return self

    def _deserialize_payload(self, payload_data: bytes):
        ethertype = self.header["type"]

        if ethertype == 0x0806 and len(payload_data) >= 28:  # ARP
            from protocols.arp import ARP

            return ARP().deserializer(payload_data)

        return None

    def get_socket_info(self):
        """Ethernet frames require a raw L2 socket (AF_PACKET), not the
        AF_INET raw sockets used by IPv4/ICMP. Network.send_and_received
        dispatches on protocol.name == 'Ethernet' before this is ever
        consulted, so this stub is only here in case something calls it
        directly."""
        import socket

        return socket.SOCK_RAW, ("", 0)

    def __str__(self) -> str:
        body = self.format_table(self.name, self.header)
        if self.payload:
            body += "\n" + str(self.payload)
        return body

    @staticmethod
    def mac_to_str(mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes)
