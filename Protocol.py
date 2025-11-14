

class Protocol:
    def __init__(self, name: str):
        self.header = None
        self.protocol_name = name
        self.payload = None

    def to_binary(self) -> bytes:
        pass


    def deserializer(self, data: bytes):
        pass

    def add_protocol(self, protocol):
        self.payload = protocol
        return self

