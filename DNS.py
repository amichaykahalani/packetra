import socket
import struct
import random

class DNS:
    def __init__(self):
        self.transID = random.getrandbits(16)
        self.flags = 0
        self.QDCOUNT = 1
        self.RRCOUNT = 0

    def create_dns_header(self):
        dns_header = struct.pack('!HHHHHH', self.transID, self.flags, self.QDCOUNT, self.RRCOUNT, self.RRCOUNT, self.RRCOUNT)
        return dns_header

    def creat_dns_question(self, domain_name, QTYPE=1, CLASS=1):
        dns_header = self.create_dns_header()
        QNAME = b''
        splited_domain_name = domain_name.split('.')
        for domain in splited_domain_name:
            domain_length = len(domain)
            QNAME += struct.pack('!B', domain_length)
            QNAME += domain.encode('ascii')

        QNAME += b'\x00'
        dns_question = dns_header + QNAME + struct.pack('!HH', QTYPE, CLASS)
        return dns_question

    def sent_dns_question(self, dns_question):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('192.168.1.1', 53))
        sock.send(dns_question)
        data = sock.recv(1024)
        sock.close()
        return data


    @staticmethod
    def return_ip_from_dns_answer(dns_answer):
        trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', dns_answer[:12])
        offset = 12

        for _ in range(qdcount):
            while dns_answer[offset] != 0:
                offset += dns_answer[offset] + 1
            offset += 1 + 4  # הסוף של השם + QTYPE + QCLASS

        ips = []
        for _ in range(ancount):
            if dns_answer[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while dns_answer[offset] != 0:
                    offset += dns_answer[offset] + 1
                offset += 1

            type_, cls, ttl, rdlength = struct.unpack('!HHIH', dns_answer[offset:offset + 10])
            offset += 10

            rdata = dns_answer[offset:offset + rdlength]
            offset += rdlength

            print('type:', type_, end=" | ")
            if type_ == 1:  # A record
                ip = socket.inet_ntop(socket.AF_INET, rdata)
                ips.append(ip)
            elif type_ == 5:  # CNAME record
                cname = DNS.decode_dns_name(rdata)
                print(f"CNAME: {cname}")
            elif type_ == 28:
                ip = socket.inet_ntop(socket.AF_INET6, rdata)
                ips.append(ip)

        return ips if ips else None

    @staticmethod
    def decode_dns_name(rdata):
        labels = []
        offset = 0
        while True:
            length = rdata[offset]
            if length == 0:
                break
            offset += 1
            label = (rdata[offset:offset + length]).decode('ascii')
            labels.append(label)
            offset += length

        return '.'.join(labels)



