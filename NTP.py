import struct

class NTP:
    def __init__(self, **kwargs):
        #-----------Header------------
        self.header = {'LI' : kwargs.get('LI', 0),
                  'VN' : kwargs.get('VN', 4),
                  'mode' : kwargs.get('mode', 3),
                  'stratum' : kwargs.get('stratum', 0),
                  'poll' : kwargs.get('poll', 10),
                  'precision' : kwargs.get('precision', 0)}

        #----------Reference Parameters------------
        self.reference_parameters = {'root_delay' : 0,
                     'Root Dispersion' : 0,
                     'Reference ID' : 0,
                     'Reference Timestamp': 0
        }

        #---------Timestamps--------
        self.timestamps = {'Originate Timestamp' : 0,
                           'Receive Timestamp' : 0,
                           'Transmit Timestamp' : 0
        }

    def to_bytes(self):
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
        reference_bytes = struct.pack('!IIId',
                           self.reference_parameters['root_delay'],
                           self.reference_parameters['Root Dispersion'],
                           self.reference_parameters['Reference ID'],
                           self.reference_parameters['Reference Timestamp'])


        #------24 bytes------
        timestamps_bytes = struct.pack('!3d', self.timestamps['Originate Timestamp'],
                                       self.timestamps['Receive Timestamp'],
                                       self.timestamps['Transmit Timestamp'])

        #-----48 bytes-------
        packet = header_bytes + reference_bytes + timestamps_bytes
        return packet





