from Protocol import Protocol


class IPv4(Protocol):
    def __init__(self):
        super().__init__()
        self.header = {
            'version': 0,
            'IHL': 0,
            'DSCP': 0,
            'ECN': 0,
            'total_length': 0,
            'identification': 0,
            'flags':0,
            'frag_offset': 0,
            'TTL' : 0,
            'Protocol': 0,
            'checksum': 0,
            'src_ip' : 0,
            'dst_ip' : 0
        }