from pprint import pprint
import struct
import random

from Network import Network
from Protocol import Protocol

class DNS(Protocol):
    def __init__(self, domain="", **kwargs):
        super().__init__('DNS')
        self.is_response = kwargs.get('is_response', False)
        self.raw_bytes = None
        concepts_types = {"IPv4" : 1, "Name Server" : 2, "IPv6" : 28, "ANY" : 255}
        concepts_classes = {"IN" : 1}
        if not self.is_response:
            #-----------Header----------
            self.header = {"transaction_id" : random.getrandbits(16),
                           "flags" : 0x0100,
                           "QDCOUNT" : 1,
                           "ANCOUNT" : 0,
                           "NSCOUNT" : 0,
                           "ARCOUNT" : 0}

            #---------Question section-----------
            self.question_section = {"QNAME" : domain,
                                     "QTYPE" : concepts_types.get(kwargs.get('record_type'), concepts_types.get("IPv4")),
                                     "QCLASS" : concepts_classes.get(kwargs.get('class_type'), concepts_classes.get("IN"))}

        else:
            # -----------Header----------
            self.header = {}
            # ---------Question section-----------
            self.question_section = {}
            #---------Answer section------------
            self.answer_section = {}

            self.all_sections = self.header | self.question_section | self.answer_section

    def to_binary(self):
        packet = struct.pack('!HHHHHH',
                          self.header["transaction_id"],
                             self.header["flags"],
                             self.header["QDCOUNT"],
                             self.header["ANCOUNT"],
                             self.header["NSCOUNT"],
                             self.header["ARCOUNT"])

        packet += self.encode_domain(self.question_section['QNAME'])
        packet += struct.pack('!HH',
                           self.question_section['QTYPE'],
                              self.question_section['QCLASS'])

        self.raw_bytes = packet
        return packet

    def deserializer(self, packet):
        self.raw_bytes = packet
        #--------header---------
        offset = 12
        transID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', packet[:offset])
        self.header = {"transaction_id" : transID,
                  "flags" : flags,
                  "QDCOUNT" : QDCOUNT,
                  "ANCOUNT" : ANCOUNT,
                  "NSCOUNT" : NSCOUNT,
                  "ARCOUNT" : ARCOUNT}

        #---------question_section--------
        offset, qname_labels = DNS.parse_qname(packet, 12)
        QNAME = '.'.join(qname_labels)
        QTYPE, QCLASS = struct.unpack('!HH', packet[offset:offset + 4])
        offset += 4

        self.question_section = {'QNAME' : QNAME,
                            'QTYPE' : QTYPE,
                            'QCLASS' : QCLASS}

        #----------answer_section---------
        NAME = struct.unpack('!H', packet[offset:offset + 2])[0]
        if NAME & 0xC000 == 0xC000:
            pointer_offset = NAME & 0x3FFF
            _, labels = DNS.parse_qname(packet, pointer_offset)
            NAME = '.'.join(labels)
            offset += 2
        else:
            offset, labels = DNS.parse_qname(packet, offset)
            NAME = '.'.join(labels)

        TYPE, CLASS, TTL, RDLENGTH = struct.unpack('!HHIH', packet[offset:offset + 10])

        answer_offset = offset + 10
        RDATA = packet[answer_offset:answer_offset + RDLENGTH]
        if TYPE == 1:  # A record
            IP = Network.get_ip('AF_INET', RDATA)

        elif TYPE == 5:  # CNAME record
            _, labels = DNS.parse_qname(packet, answer_offset)
            IP = '.'.join(labels)

        elif TYPE == 6:
            _, labels = DNS.parse_qname(packet, answer_offset)
            IP = '.'.join(labels)

        elif TYPE == 28:
            IP = Network.get_ip('AF_INET6', RDATA)
        else:
            IP = RDATA

        self.answer_section = {"NAME" : NAME,
                          "TYPE" : TYPE,
                          "CLASS" : CLASS,
                          "TTL" : TTL,
                          "RDLENGTH" : RDLENGTH,
                          "RDATA" : IP}

        self.all_sections = self.header | self.question_section | self.answer_section
        return self

    def encode_domain(self, domain):
        parts = domain.split('.')
        result = b''
        for part in parts:
            result += bytes([len(part)]) + part.encode()
        return result + b'\x00'

    @staticmethod
    def parse_qname(packet, offset):
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
                labels.append(packet[offset:offset + length].decode())
                offset += length
        if not jumped:
            return offset, labels
        else:
            return original_offset + 2, labels

    def pretty_print(self, binary=False):
        sections = ["Header", "Question", "Answer"]

        if binary:
            packet_dict = {}

            # Header
            packet_dict["Header"] = {
                "transaction_id": struct.pack('!H', self.header["transaction_id"]),
                "flags": struct.pack('!H', self.header["flags"]),
                "QDCOUNT": struct.pack('!H', self.header["QDCOUNT"]),
                "ANCOUNT": struct.pack('!H', self.header["ANCOUNT"]),
                "NSCOUNT": struct.pack('!H', self.header["NSCOUNT"]),
                "ARCOUNT": struct.pack('!H', self.header["ARCOUNT"]),
            }

            # Question
            packet_dict["Question"] = {
                "QNAME": self.encode_domain(self.question_section["QNAME"]),
                "QTYPE": struct.pack('!H', self.question_section["QTYPE"]),
                "QCLASS": struct.pack('!H', self.question_section["QCLASS"]),
            }

            # Answer (אם יש)
            if self.is_response and self.answer_section:
                ans = self.answer_section
                NAME = self.encode_domain(ans["NAME"])
                packet_dict["Answer"] = {
                    "NAME": NAME,
                    "TYPE": struct.pack('!H', ans["TYPE"]),
                    "CLASS": struct.pack('!H', ans["CLASS"]),
                    "TTL": struct.pack('!I', ans["TTL"]),
                    "RDLENGTH": struct.pack('!H', ans["RDLENGTH"]),
                    "RDATA": self.encode_domain(ans["RDATA"]),
                }

            if self.is_response:
                print("Response Packet:")
            else:
                print("Question Packet:")
            for sec in sections:
                if sec in packet_dict:
                    print(f"-----------{sec} section-----------")
                    pprint(packet_dict[sec])
                    print(f"----------------------" + '-' * len(sec + ' section'))
        else:

            packet = [self.header, self.question_section]
            if self.is_response and self.answer_section:
                packet.append(self.answer_section)
            if self.is_response:
                print("Response Packet:")
            else:
                print("Question Packet:")
            for i, section in enumerate(packet):
                print(f"-----------{sections[i]} section-----------")
                pprint(section)
                print(f"----------------------" + '-' * len(sections[i] + ' section'))
                print()

    @staticmethod
    def return_domain_bytes(packet, offset):
        qname_bytes = b''
        while packet[offset] != 0x00:
            length = packet[offset]
            label = packet[offset + 1: offset + 1 + length]
            qname_bytes += bytes([length]) + label
            offset += 1 + length

        qname_bytes += b'\x00'
        offset += 1
        return offset, qname_bytes

    def __str__(self):
        if self.is_response and self.answer_section:
            return f'DNS({self.header | self.question_section | self.answer_section})'
        else:
            return f'DNS({self.header | self.question_section})'