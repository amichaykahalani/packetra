import struct
import time
from protocols.protocol import Protocol


class NTP(Protocol):
    TYPE_ID = 123

    def __init__(self, **kwargs):
        super().__init__('NTP')
        mode = kwargs.get('mode', 3)

        if mode in (3, 4):
            self.header = {
                'LI': kwargs.get('LI', 0),
                'VN': kwargs.get('VN', 4),
                'mode': mode,
                'stratum': kwargs.get('stratum', 0),
                'poll': int(kwargs.get('poll', 4)),
                'precision': kwargs.get('precision', -20)
            }

            self.reference_parameters = {
                'root_delay': 0,
                'root_dispersion': 0,
                'reference_ID': 0,
                'reference_timestamp': 0
            }

            now = int(2208988800 + time.time())
            self.timestamps = {
                'originate_timestamp': 0,
                'receive_timestamp': 0,
                'transmit_timestamp': now
            }

        elif mode == 6:  # Control Message
            self.header = {
                'LI': kwargs.get('LI', 0),
                'VN': kwargs.get('VN', 4),
                'mode': 6,
                'opcode': kwargs.get('opcode', 0),
                'sequence': kwargs.get('sequence', 1),
                'status': kwargs.get('status', 0),
                'association_id': kwargs.get('association_id', 0),
                'offset': kwargs.get('offset', 0),
                'count': kwargs.get('count', 0),
                'data': kwargs.get('data', b'')
            }

    def to_binary(self):
        mode = self.header['mode']

        li = self.header['LI']
        vn = self.header['VN']
        mode_bits = mode

        first_byte = (li << 6) | (vn << 3) | mode_bits
        packet = struct.pack("!B", first_byte)

        if mode == 3:
            packet += struct.pack("!BBb",
                                  self.header['stratum'],
                                  self.header['poll'],
                                  self.header['precision'])

            packet += struct.pack("!III",
                                  self.reference_parameters['root_delay'],
                                  self.reference_parameters['root_dispersion'],
                                  self.reference_parameters['reference_ID'])

            packet += NTP.to_ntp_time(self.reference_parameters['reference_timestamp'])

            packet += b''.join([
                NTP.to_ntp_time(self.timestamps['originate_timestamp']),
                NTP.to_ntp_time(self.timestamps['receive_timestamp']),
                NTP.to_ntp_time(self.timestamps['transmit_timestamp']),
            ])

            return packet

        elif mode == 6:
            packet += struct.pack("!BHHHHH",
                                  self.header['opcode'],
                                  self.header['sequence'],
                                  self.header['status'],
                                  self.header['association_id'],
                                  self.header['offset'],
                                  self.header['count'])

            packet += self.header['data']
            return packet

    def deserializer(self, packet: bytes):
        first = packet[0]
        mode = first & 0b111

        self.header['LI'] = (first >> 6) & 0b11
        self.header['VN'] = (first >> 3) & 0b111
        self.header['mode'] = mode

        if mode in (3, 4):
            self.header['stratum'], self.header['poll'], self.header['precision'] = struct.unpack("!BBb", packet[1:4])

            rd, disp, ref_id = struct.unpack("!III", packet[4:16])
            self.reference_parameters['root_delay'] = rd
            self.reference_parameters['root_dispersion'] = disp
            self.reference_parameters['reference_ID'] = ref_id

            self.reference_parameters['reference_timestamp'] = NTP.from_ntp_time(packet[16:24])
            self.timestamps['originate_timestamp'] = NTP.from_ntp_time(packet[24:32])
            self.timestamps['receive_timestamp'] = NTP.from_ntp_time(packet[32:40])
            self.timestamps['transmit_timestamp'] = NTP.from_ntp_time(packet[40:48])

        elif mode == 6:
            opcode = packet[1]
            seq, status, assoc, offset, count = struct.unpack("!HHHHH", packet[2:12])

            self.header.update({
                'opcode': opcode,
                'sequence': seq,
                'status': status,
                'association_id': assoc,
                'offset': offset,
                'count': count,
                'data': packet[12:12+count]
            })

        return self

    @staticmethod
    def to_ntp_time(t):
        seconds = int(t)
        fraction = int((t - seconds) * (2 ** 32))
        return struct.pack('!II', seconds, fraction)

    @staticmethod
    def from_ntp_time(data):
        seconds, fraction = struct.unpack('!II', data)
        return seconds + float(fraction) / 2**32

    def __str__(self) -> str:
        body = self.format_table(self.name, self.header)

        if hasattr(self, 'reference_parameters'):
            body += "\n" + self.format_table("NTP Reference Parameters", self.reference_parameters)

        if hasattr(self, 'timestamps'):
            body += "\n" + self.format_table("NTP Timestamps", self.timestamps)

        if self.payload:
            body += "\n" + str(self.payload)

        return body

    def get_socket_info(self):
        return socket.SOCK_DGRAM, (self.dst_ip, 123)