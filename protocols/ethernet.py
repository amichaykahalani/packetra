from protocols.protocol import Protocol
import struct
import uuid

class Ethernet(Protocol):
    def __init__(self):
        super().__init__('Ethernet')
        self.frame = {
            'header' : {
                'dst_mac_addr': [0xFF]*6, #this is broadcast address
                'src_mac_addr': Ethernet.get_mac_addr(),
                'type': 0x0800
            },
            'data': b'',
        }
        self.payload = None

    def to_binary(self) -> bytes:
        # header: dst MAC (6), src MAC (6), EtherType (2)
        bin_frame = struct.pack(
            '!6B6BH',
            *self.frame['header']['dst_mac_addr'],
            *self.frame['header']['src_mac_addr'],
            self.frame['header']['type']
        )

        if self.payload:
            self.frame['data'] = self.payload.to_binary()
            bin_frame += self.frame['data']

        return bin_frame

    def deserializer(self, data: bytes):
        if len(data) < 14:
            raise ValueError("Data too short for Ethernet header")

        self.frame['header']['dst_mac_addr'] = list(data[:6])
        self.frame['header']['src_mac_addr'] = list(data[6:12])
        self.frame['header']['type'] = struct.unpack('!H', data[12:14])[0]

        payload_data = data[14:]
        self.frame['data'] = payload_data
        self.payload = None

        if self.frame['header']['type'] == 0x0806:
            if len(payload_data) >= 28:
                from protocols.arp import ARP
                self.payload = ARP().deserializer(self.frame['data'])

        return self

    def __str__(self):
        return self.ether_pretty_print()

    def ether_pretty_print(self) -> str:
        pretty_protocol: str = """"""
        pretty_protocol += '<-----Ethernet----->\n'
        pretty_protocol += "|\t<-----Frame----->\n"
        for key, value in self.frame.items():
            pretty_protocol += f"|\t|{key}: {value}\n"
        pretty_protocol += "| \t<-----Frame----->\n|\n"
        pretty_protocol += f"|\t{self.payload}"
        pretty_protocol += "|\n<-----Ethernet----->\n"
        return pretty_protocol

    @staticmethod
    def get_mac_addr() -> list[int]:
        mac = uuid.getnode()
        return [(mac >> ele) & 0xff for ele in range(40, -1, -8)]

    @staticmethod
    def mac_to_str(mac_bytes: bytes) -> str:
        return ':'.join(f'{b:02x}' for b in mac_bytes)