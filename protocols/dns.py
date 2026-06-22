import logging
import random
import socket
import struct

from protocols.protocol import Protocol

logger = logging.getLogger(__name__)


class DNS(Protocol):
    TYPE_ID = 53

    RECORD_TYPES = {"IPv4": 1, "Name Server": 2, "IPv6": 28, "ANY": 255}
    RECORD_CLASSES = {"IN": 1}

    # keyed by answer TYPE, used in _decode_rdata
    ANSWER_TYPE_A = 1
    ANSWER_TYPE_CNAME = 5
    ANSWER_TYPE_NS = 6
    ANSWER_TYPE_AAAA = 28

    def __init__(self, domain: str = "", **kwargs):
        super().__init__("DNS")
        self.is_response = kwargs.get("is_response", False)
        self.raw_bytes = None

        self.header = {
            "transaction_id": random.getrandbits(16),
            "flags": 0x0100,
            "QDCOUNT": 1,
            "ANCOUNT": 0,
            "NSCOUNT": 0,
            "ARCOUNT": 0,
        }

        self.question_section = {
            "QNAME": domain,
            "QTYPE": self.RECORD_TYPES.get(
                kwargs.get("record_type"), self.RECORD_TYPES["IPv4"]
            ),
            "QCLASS": self.RECORD_CLASSES.get(
                kwargs.get("class_type"), self.RECORD_CLASSES["IN"]
            ),
        }

        self.answer_section = {}

    @property
    def all_sections(self) -> dict:
        # built fresh each call so it never goes stale after setup() or
        # Builder.edit_fields() mutates a section
        return self.header | self.question_section | self.answer_section

    def setup(self):
        domain = input("Enter domain to query (e.g. google.com): ").strip()
        if domain:
            self.question_section["QNAME"] = domain

    def to_binary(self) -> bytes:
        self.header["QDCOUNT"] = 1

        packet = struct.pack(
            "!HHHHHH",
            self.header["transaction_id"],
            self.header["flags"],
            self.header["QDCOUNT"],
            self.header["ANCOUNT"],
            self.header["NSCOUNT"],
            self.header["ARCOUNT"],
        )

        packet += self.encode_domain(self.question_section["QNAME"])
        packet += struct.pack(
            "!HH", self.question_section["QTYPE"], self.question_section["QCLASS"]
        )

        logger.debug("DNS packet built, total bytes: %d", len(packet))
        self.raw_bytes = packet
        return packet

    def deserializer(self, packet: bytes):
        self.is_response = True
        self.raw_bytes = packet

        offset = self._parse_header(packet)
        offset = self._parse_question(packet, offset)
        self._parse_answer(packet, offset)

        return self

    def _parse_header(self, packet: bytes) -> int:
        header_len = 12
        trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", packet[:header_len]
        )
        self.header = {
            "transaction_id": trans_id,
            "flags": flags,
            "QDCOUNT": qdcount,
            "ANCOUNT": ancount,
            "NSCOUNT": nscount,
            "ARCOUNT": arcount,
        }
        return header_len

    def _parse_question(self, packet: bytes, offset: int) -> int:
        offset, qname_labels = DNS.parse_qname(packet, offset)
        qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
        offset += 4

        self.question_section = {
            "QNAME": ".".join(qname_labels),
            "QTYPE": qtype,
            "QCLASS": qclass,
        }
        return offset

    def _parse_answer(self, packet: bytes, offset: int):
        name, offset = self._parse_answer_name(packet, offset)

        answer_type, answer_class, ttl, rdlength = struct.unpack(
            "!HHIH", packet[offset : offset + 10]
        )
        rdata_offset = offset + 10
        rdata = packet[rdata_offset : rdata_offset + rdlength]

        rdata_value = self._decode_rdata(answer_type, packet, rdata_offset, rdata)

        self.answer_section = {
            "NAME": name,
            "TYPE": answer_type,
            "CLASS": answer_class,
            "TTL": ttl,
            "RDLENGTH": rdlength,
            "RDATA": rdata_value,
        }

    @staticmethod
    def _parse_answer_name(packet: bytes, offset: int) -> tuple[str, int]:
        # handles both a direct name and a compression pointer (0xC0xx)
        raw = struct.unpack("!H", packet[offset : offset + 2])[0]

        if raw & 0xC000 == 0xC000:
            pointer_offset = raw & 0x3FFF
            _, labels = DNS.parse_qname(packet, pointer_offset)
            return ".".join(labels), offset + 2

        offset, labels = DNS.parse_qname(packet, offset)
        return ".".join(labels), offset

    def _decode_rdata(
        self, answer_type: int, packet: bytes, rdata_offset: int, rdata: bytes
    ):
        if answer_type == self.ANSWER_TYPE_A:
            from network import Network

            return Network.get_ip("AF_INET", rdata)

        if answer_type in (self.ANSWER_TYPE_CNAME, self.ANSWER_TYPE_NS):
            _, labels = DNS.parse_qname(packet, rdata_offset)
            return ".".join(labels)

        if answer_type == self.ANSWER_TYPE_AAAA:
            from network import Network

            return Network.get_ip("AF_INET6", rdata)

        return rdata

    @staticmethod
    def encode_domain(domain: str) -> bytes:
        result = b""
        for part in domain.split("."):
            result += bytes([len(part)]) + part.encode()
        return result + b"\x00"

    @staticmethod
    def parse_qname(packet: bytes, offset: int) -> tuple[int, list]:
        labels = []
        jumped = False
        original_offset = offset

        while True:
            length = packet[offset]

            if length & 0xC0 == 0xC0:
                pointer_offset = ((length & 0x3F) << 8) | packet[offset + 1]
                offset = pointer_offset
                jumped = True
                continue
            elif length == 0:
                offset += 1
                break
            else:
                offset += 1
                labels.append(packet[offset : offset + length].decode())
                offset += length

        return (original_offset + 2, labels) if jumped else (offset, labels)

    @staticmethod
    def return_domain_bytes(packet: bytes, offset: int) -> tuple[int, bytes]:
        qname_bytes = b""
        while packet[offset] != 0x00:
            length = packet[offset]
            label = packet[offset + 1 : offset + 1 + length]
            qname_bytes += bytes([length]) + label
            offset += 1 + length

        qname_bytes += b"\x00"
        offset += 1
        return offset, qname_bytes

    def pretty_print(self) -> str:
        parts = [
            self.format_table("DNS Header", self.header),
            self.format_table("Question Section", self.question_section),
        ]
        if self.is_response and self.answer_section:
            parts.append(self.format_table("Answer Section", self.answer_section))
        return "\n".join(parts)

    def _binary_sections(self) -> dict:
        result = {
            "Header": {
                "transaction_id": struct.pack("!H", self.header["transaction_id"]),
                "flags": struct.pack("!H", self.header["flags"]),
                "QDCOUNT": struct.pack("!H", self.header["QDCOUNT"]),
                "ANCOUNT": struct.pack("!H", self.header["ANCOUNT"]),
                "NSCOUNT": struct.pack("!H", self.header["NSCOUNT"]),
                "ARCOUNT": struct.pack("!H", self.header["ARCOUNT"]),
            },
            "Question": {
                "QNAME": self.encode_domain(self.question_section["QNAME"]),
                "QTYPE": struct.pack("!H", self.question_section["QTYPE"]),
                "QCLASS": struct.pack("!H", self.question_section["QCLASS"]),
            },
        }

        if self.is_response and self.answer_section:
            ans = self.answer_section
            result["Answer"] = {
                "NAME": self.encode_domain(ans["NAME"]),
                "TYPE": struct.pack("!H", ans["TYPE"]),
                "CLASS": struct.pack("!H", ans["CLASS"]),
                "TTL": struct.pack("!I", ans["TTL"]),
                "RDLENGTH": struct.pack("!H", ans["RDLENGTH"]),
                "RDATA": self.encode_domain(ans["RDATA"]),
            }

        return result

    def get_socket_info(self):
        # only matters standalone — nested under UDP/IPv4, IPv4 handles the raw socket
        return socket.SOCK_DGRAM, ("8.8.8.8", 53)
