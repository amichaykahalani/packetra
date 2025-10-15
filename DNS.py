from pprint import pprint
import socket
import struct
import random

class DNS:
    def __init__(self, domain, record_type="IPv4", class_type="IN"):
        concepts_types = {"IPv4" : 1, "Name Server" : 2, "IPv6" : 28, "ANY" : 255}
        concepts_classes = {"IN" : 1}
        #-----------Header----------
        self.header = {"transaction_id" : random.getrandbits(16),
                       "flags" : 0x0100,
                       "QDCOUNT" : 1,
                       "ANCOUNT" : 0,
                       "NSCOUNT" : 0,
                       "ARCOUNT" : 0}

        #---------Question section-----------
        self.question_section = {"QNAME" : domain,
                                 "QTYPE" : concepts_types.get(record_type, concepts_types.get("IPv4")),
                                 "QCLASS" : concepts_classes.get(class_type, concepts_classes.get("IN"))}


    def serializer(self):
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

        return packet

    def deserializer(self, packet):
        #--------header---------
        offset = 12
        transID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', packet[:offset])
        header = {"transaction_id" : transID,
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

        question_section = {'QNAME' : QNAME,
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
            IP = socket.inet_ntop(socket.AF_INET, RDATA)

        elif TYPE == 5:  # CNAME record
            _, labels = DNS.parse_qname(packet, answer_offset)
            IP = '.'.join(labels)

        elif TYPE == 28:
            IP = socket.inet_ntop(socket.AF_INET6, RDATA)
        else:
            IP = RDATA

        answer_section = {"NAME" : NAME,
                          "TYPE" : TYPE,
                          "CLASS" : CLASS,
                          "TTL" : TTL,
                          "RDLENGTH" : RDLENGTH,
                          "RDATA" : IP}

        return header, question_section, answer_section

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
            # אם pointer
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

    def pretty_print(self, packet):
        sections = {1 : "Header",
                    2 : "Question",
                    3 : "Answer",
                    4 : "Authoritative",
                    5 : "Additional", }

        index = 1
        for section in packet:
            print(f"-----------{sections[index]} section-----------")
            pprint(section)
            print(f"-----------------------{'-' * len(sections[index] + 'section')}")
            index += 1
