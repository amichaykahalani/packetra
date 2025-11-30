from protocols.ethernet import Ethernet
from protocols.protocol import Protocol
import socket
import struct
import fcntl

class Network:

    def __init__(self):
        self.packets = []

    @staticmethod
    def get_ip(family, rdata):
        try:
            if family == 'AF_INET':
                return socket.inet_ntop(socket.AF_INET, rdata)
            elif family == 'AF_INET6':
                return socket.inet_ntop(socket.AF_INET6, rdata)

        except Exception as e:
            return e

    @staticmethod
    def send_and_received(protocol: Protocol) -> Protocol:
        from protocols.ipv4 import IPv4
        from protocols.dns import DNS
        try:

            if protocol.name == 'Ethernet':
                pkt = protocol.to_binary()
                response = Network.create_sock_and_send(pkt, protocol)
                return Ethernet().deserializer(response)

            if protocol.name == 'IPv4':
                pkt = protocol.to_binary()
                response = Network.create_sock_and_send(pkt, protocol)
                return IPv4().deserializer(response)


            elif protocol.name == 'DNS':
                pkt = protocol.to_binary()
                response = Network.create_sock_and_send(pkt, protocol)
                return DNS('www.google.com', is_response=True).deserializer(response)


            else:
                print("something went wrong, protocol not supported")

        except Exception as e:
            print(e)

        print("return protocol")
        return protocol

    @staticmethod
    def create_sock_and_send(pkt, protocol):
        pname = protocol.name
        raw_socket_protocols = ['IPv4'] #I remove the udp from here.
        af_packet_protocols = ['Ethernet', 'ARP']
        is_raw = False
        is_ether = False
        if pname in af_packet_protocols:
            is_ether = True

        if pname in raw_socket_protocols:
            is_raw = True

        if is_ether:
            if pname == 'Ethernet' and protocol.payload and protocol.payload.name == 'ARP':
                ETH_P_ARP = 0x0806
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ARP))
                sock.bind(('ens33', ETH_P_ARP))
                sock.send(pkt)
                while True:
                    response, addr = sock.recvfrom(65535)
                    eth_type = struct.unpack('!H', pkt[12:14])[0]

                    if eth_type == ETH_P_ARP:
                        return response

        if is_raw:
            if pname == 'IPv4':
                try:
                    if protocol.payload.name == 'ICMP':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.settimeout(10)
                        sock.sendto(pkt, (protocol.header['dst_ip'], 0))

                    elif protocol.payload.payload.name == 'DNS':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.settimeout(10)
                        sock.sendto(pkt, ("8.8.8.8", 53))

                    elif protocol.payload.payload.name == 'NTP':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.settimeout(10)
                        sock.sendto(pkt, ("129.159.140.221", 123))

                except Exception as e:
                    print(e)

        elif pname == 'DNS':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(pkt, ("8.8.8.8", 53))

        response, addr = sock.recvfrom(4096)
        sock.close()
        return response


    @staticmethod
    def get_my_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

    @staticmethod
    def convert_ip_into_bytes(ip: str) -> bytes:
       return socket.inet_aton(ip)

    @staticmethod
    def convert_bytes_into_ip(ip: bytes) -> str:
        return socket.inet_ntop(socket.AF_INET, ip)

    @staticmethod
    def get_my_mac(iface: str) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode('utf-8')))
        mac = info[18:24]
        return mac