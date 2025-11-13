from Protocol import Protocol
import struct

class UDP(Protocol):
    def __init__(self):
        super().__init__()
        #------------Header------------
        self.header = {
            'src_port' : 12345,
            'dst_port' : 53,
            'checksum' : 0,
            'length' : 0,
        }

    def to_binary(self: Protocol) -> bytes:
        print("udp to binary")
        pkt = struct.pack('!4H', self.header['src_port'], self.header['dst_port'], self.header['checksum'], self.header['length'])
        return pkt

    def deserialize(self, data: bytes) -> Protocol:
        self.header['src_port'], self.header['dst_port'], self.header['checksum'], self.header['length'] = struct.unpack('!4H', data[:8])
        self.payload = struct.unpack(f'{self.header['length'] - 8}s', data[8:])
        return self

    def __str__(self) -> str:
        return f'{self.header['src_port']} : {self.header['dst_port']} : {self.header['checksum']} : {self.header['length']} : {self.payload}'
