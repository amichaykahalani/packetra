import struct
import time
from Protocol import Protocol

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
        NOW = 2208988800 + time.time()
        self.timestamps = {'originate_timestamp' : NOW,
                           'receive_timestamp' : 0,
                           'transmit_timestamp' : 0
        }

    def to_binary(self):
        LI = 0b00
        VN = 0b100
        MODE = 0b011

        first_byte = (LI << 6) | (VN << 3) | MODE
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
            self.to_ntp_time(self.timestamps['originate_timestamp']),
            self.to_ntp_time(self.timestamps['receive_timestamp']),
            self.to_ntp_time(self.timestamps['transmit_timestamp']),
        ])

        #-----48 bytes-------
        packet = header_bytes + reference_bytes + timestamps_bytes
        print("Sent originate_timestamp:", self.timestamps['originate_timestamp'])
        return packet

    def from_bytes(self, packet):
        _, self.header['stratum'], self.header['poll'], self.header['precision'] = struct.unpack('!3B1b', packet[:4])
        self.reference_parameters['root_delay'], self.reference_parameters['root_dispersion'], self.reference_parameters['reference_ID'] = struct.unpack('!3I', packet[4:16])
        self.reference_parameters['reference_timestamp'] = self.from_ntp_time(packet[16:24])
        self.timestamps['originate_timestamp'] = self.from_ntp_time(packet[24:32])
        self.timestamps['receive_timestamp'] = self.from_ntp_time(packet[32:40])
        self.timestamps['transmit_timestamp'] = self.from_ntp_time(packet[40:48])
        return self.header | self.reference_parameters | self.timestamps

    def to_ntp_time(self, t):
        seconds = int(t)
        fraction = int((t - seconds) * (2 ** 32))
        return struct.pack('!II', seconds, fraction)

    def from_ntp_time(self, data):
        seconds, fraction = struct.unpack('!II', data)
        return seconds + float(fraction) / 2**32


