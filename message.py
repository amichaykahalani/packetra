from protocols.protocol import Protocol
import struct

class Data(Protocol):
    def __init__(self, data):
        super().__init__("Message")
        if isinstance(data, str):
            data = data.encode()

        self.data = data
        self.length = len(self.data)

    def to_binary(self):
        return struct.pack(f"!{self.length}s", self.data)

    def deserializer(self, data: bytes):
        self.data = struct.unpack(f"!{len(data)}s", data)[0]
        self.length = len(data)

    def __str__(self):
        try:
            text = self.data.decode('utf-8', errors='replace')
        except Exception:
            text = repr(self.data)
        return self.format_table("Message", {"data": text})