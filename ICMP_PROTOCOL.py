import struct
from BaseProtocol import Protocol
from Message import Data

class ICMP(Protocol):
    def __init__(self, **kwargs):
        super().__init__('ICMP')
        icmp_type = kwargs.get('type', 8)
        if icmp_type in (0, 8):
            self.header  = {'type' : icmp_type,
                            'code' : kwargs.get('code', 0),
                            'checksum' : kwargs.get('checksum', 0),
                            'identifier' : kwargs.get('identifier', 0),
                            'sequence' : kwargs.get('sequence', 0)}

        else:
            self.header = {'type': icmp_type,
                           'code': kwargs.get('code', 0),
                           'unused' : kwargs.get('unused', 0),
                           'sequence': kwargs.get('sequence', 0)}

        self.payload = Data(kwargs.get('payload', ""))

    def to_binary(self):
        if self.header['type'] in (0, 8):
            header = struct.pack('!BBHHH',
                                 self.header['type'],
                                 self.header['code'],
                                 0,
                                 self.header['identifier'],
                                 self.header['sequence'])

        else:
            header = struct.pack('!BBHI',
                                 self.header['type'],
                                 self.header['code'],
                                 0,
                                 self.header['unused'])
        payload = self.payload.to_binary()
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

        if self.header['type'] in (0, 8):
            self.header['identifier'], self.header['sequence'] = struct.unpack('!HH', data[4:8])

        else:
            self.header['unused'] = struct.unpack('!I', data[4:8])[0]

        self.payload = Data(struct.unpack(f'!{len(data[8:])}s', data[8:])[0])
        return self

    @staticmethod
    def checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    def __str__(self):
        if self.header['type'] == 8:
            return f"|\t|\t<------ICMP------>\n{self.pretty_print(tabs=2)}|\t|\t<------ICMP------>"

        elif self.header['type'] == 0:
            return f"<------ICMP------>\n{self.pretty_print()}<------ICMP------>"

        return f"<------ICMP------>\n{self.pretty_print()}|\n|\t<------Payload------> \n{self.payload}\n|\t<------Payload------>\n<------ICMP------>"


