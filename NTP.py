import struct
import math
import time
from decimal import Decimal, getcontext

class NTP():
    def __init__(self, **kwargs):
        #-----------Header------------
        self.header = {'LI' : kwargs.get('LI', 0),
                  'VN' : kwargs.get('LV', 4),
                  'mode' : kwargs.get('mode', 3),
                  'stratum' : kwargs.get('stratum', 0),
                  'poll' : kwargs.get('poll', 10),
                  'precision' : kwargs.get('precision', NTP.get_precision())}

        #----------info------------
        self.info = {'root_delay' : 0,
                     'Root Dispersion' : 0,
                     'Reference ID' : 0,
                     'Reference Timestamp' : 0
        }

    def to_bytes(self):
        LI = 0b00
        VN = 0b100
        MODE = 0b011

        first_byte = (LI << 6) | (VN << 3) | MODE
        header = struct.pack('!B', first_byte)
        header += struct.pack('!2B1b',
                             self.header['stratum'],
                                self.header['poll'],
                                self.header['precision'])
        #header = header.split(b'\x00')
        #print("".join(str(num) for num in header))
        info = struct.pack('!IIId4d',
                           self.info['root_delay'],
                           self.info['Root Dispersion'],
                           self.info['Reference ID'],
                           self.info['Reference Timestamp'],
                           0, 0, 0, 0)

        print(header + info)
        return header + info

    @staticmethod
    def get_precision():
        getcontext().prec = 50
        start_float = time.perf_counter()
        start_decimal = Decimal(str(start_float))
        end_float = time.perf_counter()
        end_decimal = Decimal(str(end_float))
        delta_d = end_decimal - start_decimal
        return int(math.log(delta_d, 2))
