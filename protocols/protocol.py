class Protocol:
    def __init__(self, name: str):
        self.header = None
        self.name = name
        self.payload = None

    def to_binary(self, *args) -> bytes:
        pass


    def deserializer(self, data: bytes):
        pass

    def add_protocol(self, protocol):
        self.payload = protocol
        return self

    def pretty_print(self, tabs: int=0):
        if tabs > 0:
            pretty_header = """"""
            for key, value in self.header.items():
                pretty_header += f"| {(tabs - 1) * '\t'}|\t {key}: {value}\n"

            return pretty_header


        pretty_header = """"""
        for key, value in self.header.items():
            pretty_header += f"| {key}: {value}\n"

        return pretty_header
