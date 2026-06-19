import logging

logger = logging.getLogger(__name__)


class Protocol:
    """Base class for all packet protocols (ARP, IPv4, UDP, DNS, etc.)."""

    registry = {}

    def __init__(self, name: str):
        self.name = name
        self.header = {}
        self.payload = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        proto_id = getattr(cls, 'TYPE_ID', None)
        if proto_id is not None:
            Protocol.registry[proto_id] = cls
            logger.debug("Registered %s with ID %s", cls.__name__, proto_id)

    def setup(self):
        """Prompt for any user-provided fields. Default: no-op."""
        pass

    def to_binary(self) -> bytes:
        raise NotImplementedError("Subclasses must implement to_binary")

    def deserializer(self, data: bytes):
        raise NotImplementedError("Subclasses must implement deserializer")

    def get_socket_info(self):
        raise NotImplementedError("Subclasses must implement get_socket_info")

    def add_protocol(self, protocol: "Protocol") -> "Protocol":
        self.payload = protocol
        return self

    @staticmethod
    def format_table(title: str, fields: dict) -> str:
        """Renders a dict as a bordered, column-aligned table."""
        if not fields:
            key_width = 0
            val_width = 0
        else:
            key_width = max(len(str(k)) for k in fields.keys())
            val_width = max(len(str(v)) for v in fields.values())

        inner_width = max(key_width + val_width + 3, len(title) + 2)
        border = "+" + "-" * (inner_width + 2) + "+"

        lines = [border, f"| {title.center(inner_width)} |", border]

        for key, value in fields.items():
            key_str = str(key).ljust(key_width)
            val_str = str(value).ljust(val_width)
            row = f"{key_str} : {val_str}"
            lines.append(f"| {row.ljust(inner_width)} |")

        lines.append(border)
        return "\n".join(lines)

    def pretty_print(self, tabs: int = 0) -> str:
        indent = "\t" * tabs

        table = self.format_table(self.name, self.header)

        return "\n".join(
            indent + line
            for line in table.splitlines()
        )

    def __str__(self) -> str:
        body = self.pretty_print()

        if self.payload:
            body += "\n" + str(self.payload)

        return body