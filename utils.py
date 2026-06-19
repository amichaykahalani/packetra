import struct


class Utils:

    @staticmethod
    def checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack(f"!{len(data) // 2}H", data))
        s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff