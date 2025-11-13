from Protocol import Protocol
import struct

class UDP(Protocol):
    def __init__(self):
        super().__init__('UDP')
        self.src_port = 12345
        self.dst_port = 53
        self.checksum = 0
        self.length = 8

    def to_binary(self):
        print("udp to binary")
        pkt = struct.pack('!4H', self.src_port, self.dst_port, self.checksum, self.length) + self.payload.to_binary()
        return pkt

    def deserialize(self, data: bytes):
        self.src_port, self.dst_port, self.checksum, self.length, self.payload = struct.unpack('!4H', data[:8])
        self.payload = data[8:]
        return self

    def __str__(self):
        return f'{self.src_port} : {self.dst_port} : {self.checksum} : {self.length} : {self.payload}'
