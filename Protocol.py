

class Protocol:
    def __init__(self):
        self.header = None
        self.payload = None

    def to_binary(self) -> bytes:
        pass


    def deserializer(self, data: bytes):
        pass

    def add_protocol(self, protocol):
        self.payload = protocol
        return self

