from protocols.ethernet import Ethernet
from protocols.protocol import Protocol
import struct

class ARP(Protocol):
    def __init__(self,
                 operation: int = 1,
                 sender_mac: bytes = b"\x00"*6,
                 sender_ip: str = "192.168.1.212",
                 target_mac: bytes = b"\x00"*6,
                 target_ip: str = "192.168.1.149"):

        super().__init__("ARP")
        self.packet = {'hardware_type' : 1,
                       'protocol_type' : 0x0800,
                       'hardware_length' : 6,
                       'protocol_length' : 4,
                       'operation' : operation,
                       'sender_mac' : Ethernet.get_mac_addr(),
                       'sender_ip' : sender_ip,
                       'target_mac' : target_mac,
                       'target_ip' : target_ip}

    def to_binary(self) -> bytes:
        from network import Network
        arp_bin = (struct.pack(
            "!HHBBH",
            self.packet['hardware_type'],
            self.packet['protocol_type'],
            self.packet['hardware_length'],
            self.packet['protocol_length'],
            self.packet['operation']))

        arp_bin += bytes(self.packet['sender_mac'])
        arp_bin += Network.convert_ip_into_bytes(self.packet['sender_ip'])
        arp_bin += self.packet['target_mac']
        arp_bin += Network.convert_ip_into_bytes(self.packet['target_ip'])
        return arp_bin

    def deserializer(self, data: bytes):
        from network import Network
        fields = struct.unpack("!HHBBH6s4s6s4s", data[:28])
        self.packet['hardware_type']= fields[0]
        self.packet['protocol_type'] = fields[1]
        self.packet['hardware_length'] = fields[2]
        self.packet['protocol_length'] = fields[3]
        self.packet['operation'] = fields[4]
        self.packet['sender_mac'] = Ethernet.mac_to_str(fields[5])
        self.packet['sender_ip'] = Network.convert_bytes_into_ip(fields[6])
        self.packet['target_mac'] = Ethernet.mac_to_str(fields[5])
        self.packet['target_ip'] = Network.convert_bytes_into_ip(fields[8])
        return self

    def __str__(self):
        return self.arp_pretty_print()

    def arp_pretty_print(self) -> str:
        pretty_protocol: str = """"""
        pretty_protocol += "<-----ARP Packet----->\n"
        for key, value in self.packet.items():
            pretty_protocol += f"|\t|{key}: {value}\n"
        pretty_protocol += "|\t<-----ARP Packet----->"
        return pretty_protocol


