import struct

class ICMP:
    def __init__(self, **kwargs):
        self.header  = {'type' : kwargs.get('icmp_type', 8),
                        'code' : kwargs.get('icmp_code', 0),
                        'checksum' : kwargs.get('icmp_checksum', 0),
                        'identifier' : kwargs.get('icmp_identifier', 0),
                        'sequence' : kwargs.get('icmp_sequence', 0)}

        self.payload = kwargs.get('icmp_payload', None)

    def to_bytes(self):
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

        cs = self.icmp_checksum(packet)
        self.header['checksum'] = cs
        header = struct.pack('!BBHHH',
                             self.header['type'],
                             self.header['code'],
                             self.header['checksum'],
                             self.header['identifier'],
                             self.header['sequence'])

        return header + payload

    def to_string(self, packet):
        ip_header_len = (packet[0] & 0x0F) * 4  # IPv4 header length
        icmp_packet = packet[ip_header_len:]
        self.header['type'], self.header['code'], self.header['checksum'], self.header['identifier'], self.header['sequence'] = struct.unpack("!BBHHH", icmp_packet[:8])
        self.payload = icmp_packet[8:]
        self.payload = self.payload.decode()
        return { **self.header, 'payload' : self.payload }

    def icmp_checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack(f"!{len(data)//2}H", data))

        s = (s & 0xffff) + (s >> 16)

        #print("s:", s)
        #print("~s:", ~s)
        #print("~s & F", ~s & 0xffff)
        return ~s & 0xffff

