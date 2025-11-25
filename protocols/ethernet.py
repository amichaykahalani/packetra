from protocols.protocol import Protocol
import struct

class Ethernet(Protocol):
    def __init__(self):
        super().__init__('Ethernet')
        self.frame = {
            'preamble' : 0, #--7 bytes
            'sfd' : 0, #--1 byte
            'dst_addr': 0, #--6 bytes
            'src_addr' : 0, #--6 bytes
            'length' : 0, #--2 bytes
            'data' : 0, #--up to 1500 bytes
            'crc' : 0, #--4 bytes
        }

    def to_binary(self) -> bytes:
        bin_frame = struct.pack('!7B1B6B6BH',
                                self.frame['preamble'],
                                self.frame['sfd'],
                                self.frame['dst_addr'],
                                self.frame['src_addr'],
                                self.frame['length'])

        data_length = len(self.frame['length'])
        bin_frame += struct.pack(f'!{data_length}s', self.frame['data'])
        bin_frame += struct.pack('!I', self.frame['crc'])
        return bin_frame

    def deserializer(self, data: bytes):
        self.frame['preamble'], self.frame['sfd'], self.frame['dst_addr'], self.frame['src_addr'], self.frame['length'], = struct.unpack('!7B1B6B6BH', data)
        data_and_crc_length = len(data[22:])
        self.frame['data'] = data[22:data_and_crc_length - 4]
        self.frame['crc'] = data[-4]
        return self

    def __str__(self):
        return (f"Ether(preamble: {self.frame['preamble']},"
                f" sfd: {self.frame['sfd']}, dst_addr: {self.frame['dst_addr']},"
                f" src_addr: {self.frame['src_addr']},"
                f" length: {self.frame['length']},"
                f" data: {self.frame['data']},"
                f" crc: {self.frame['crc']})")


