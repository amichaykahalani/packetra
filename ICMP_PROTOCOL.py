import struct
from BaseProtocol import Protocol

class ICMP(Protocol):
    def __init__(self, **kwargs):
        super().__init__('ICMP')
        self.header  = {'type' : kwargs.get('type', 8),
                        'code' : kwargs.get('code', 0),
                        'checksum' : kwargs.get('checksum', 0),
                        'identifier' : kwargs.get('identifier', 0),
                        'sequence' : kwargs.get('sequence', 0)}

        self.payload = kwargs.get('payload', "")

    def to_binary(self):
        header = struct.pack('!BBHHH',
                             self.header['type'],
                             self.header['code'],
                             0,
                             self.header['identifier'],
                             self.header['sequence'])

        payload = self.payload.encode()
        if payload is None:
            payload = b''

        packet = header + payload

        self.header['checksum'] =  ICMP.checksum(packet)
        header = struct.pack('!BBHHH',
                             self.header['type'],
                             self.header['code'],
                             self.header['checksum'],
                             self.header['identifier'],
                             self.header['sequence'])

        return header + payload

    def deserializer(self, data: bytes):
        self.header['type'], self.header['code'], self.header['checksum'] = struct.unpack('!BBH', data[:4])

        # Echo header only if type 0/8
        if self.header['type'] in (0, 8):
            self.header['identifier'], self.header['sequence'] = struct.unpack('!HH', data[4:8])
            self.payload = data[8:]  # might be empty
        else:
            self.payload = data[4:]  # generic ICMP

        return self

    @staticmethod
    def checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    def __str__(self):
        return f"ICMP({self.header} data:{self.payload})"

