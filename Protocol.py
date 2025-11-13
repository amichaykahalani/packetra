

class Protocol:
    def __init__(self, name: str):
        self.protocol_name = name
        self.payload: Protocol = None

    def to_binary(self):
        pass

    def deserializer(self, data: bytes):
        pass

    def add_protocol(self, protocol):
        self.payload = protocol
        return self

