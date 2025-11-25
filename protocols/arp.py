from protocols.protocol import Protocol
import struct

class ARP(Protocol):
    def __init__(self):
        super().__init__('ARP')
        self.header = {
            'hardware_type': 1,
            'protocol_type': 0,
            'hardware_length' : 0,
            'protocol_length' : 0,
            'operation' : 0,
            'sender_hardware_address' : 0,
            'sender_protocol_address' : 0,
            'target_hardware_address' : 0,
            'target_protocol_address' : 0
        }

    def to_binary(self, *args) -> bytes:
        self.header

