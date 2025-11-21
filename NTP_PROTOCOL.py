import struct
import time
from BaseProtocol import Protocol

class NTP(Protocol):
    def __init__(self, **kwargs):
        super().__init__('NTP')
        #-----------Header------------
        self.header = {'LI' : kwargs.get('LI', 0),
                  'VN' : kwargs.get('VN', 4),
                  'mode' : kwargs.get('mode', 3),
                  'stratum' : kwargs.get('stratum', 0),
                  'poll' : kwargs.get('poll', 10),
                  'precision' : kwargs.get('precision', 0)}

        #----------Reference Parameters------------
        self.reference_parameters = {'root_delay' : 0,
                     'root_dispersion' : 0,
                     'reference_ID' : 0,
                     'reference_timestamp': 0
        }

        #---------Timestamps--------
        now = 2208988800 + time.time()
        self.timestamps = {'originate_timestamp' : now,
                           'receive_timestamp' : 0,
                           'transmit_timestamp' : 0
        }

    def to_binary(self):
        li = 0b00
        vn = 0b100
        mode = 0b011

        first_byte = (li << 6) | (vn << 3) | mode
        header_bytes = struct.pack('!B', first_byte)
        header_bytes += struct.pack('!2B1b',
                             self.header['stratum'],
                                self.header['poll'],
                                self.header['precision'])

        #------4 bytes------
        reference_bytes = struct.pack('!III',
                           self.reference_parameters['root_delay'],
                           self.reference_parameters['root_dispersion'],
                           self.reference_parameters['reference_ID'])

        reference_bytes += self.to_ntp_time(self.reference_parameters['reference_timestamp'])


        #------24 bytes------
        timestamps_bytes = b''.join([
            NTP.to_ntp_time(self.timestamps['originate_timestamp']),
            NTP.to_ntp_time(self.timestamps['receive_timestamp']),
            NTP.to_ntp_time(self.timestamps['transmit_timestamp']),
        ])

        #-----48 bytes-------
        packet = header_bytes + reference_bytes + timestamps_bytes
        return packet

    def deserializer(self, packet: bytes):
        # ---- Parse first byte ----
        first = packet[0]
        self.header['LI'] = (first >> 6) & 0b11
        self.header['VN'] = (first >> 3) & 0b111
        self.header['mode'] = first & 0b111

        # ---- next bytes ----
        self.header['stratum'], self.header['poll'], self.header['precision'] = struct.unpack("!BBb", packet[1:4])

        # ---- reference parameters ----
        self.reference_parameters['root_delay'], \
            self.reference_parameters['root_dispersion'], \
            self.reference_parameters['reference_ID'] = struct.unpack("!III", packet[4:16])

        # ---- timestamps ----
        self.reference_parameters['reference_timestamp'] = NTP.from_ntp_time(packet[16:24])
        self.timestamps['originate_timestamp'] = NTP.from_ntp_time(packet[24:32])
        self.timestamps['receive_timestamp'] = NTP.from_ntp_time(packet[32:40])
        self.timestamps['transmit_timestamp'] = NTP.from_ntp_time(packet[40:48])

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

    def __str__(self):
        return f"NTP({self.header | self.reference_parameters | self.timestamps})"

