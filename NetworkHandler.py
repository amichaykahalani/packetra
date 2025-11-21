import socket
from BaseProtocol import Protocol

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
        from IP_PROTOCOL import IP
        from DNS_PROTOCOL import DNS
        try:
            if protocol.name == 'IP':
                pkt = protocol.to_binary()
                response = Network.create_sock_and_send(pkt, protocol)
                return IP().deserializer(response)


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
        from DNS_PROTOCOL import DNS
        pname = protocol.name
        raw_socket_protocols = ['IP', 'UDP']
        udp_socket_protocols = ['DNS', 'NTP']
        is_raw = False
        if pname in raw_socket_protocols:
            is_raw = True

        if is_raw:
            if protocol.name == 'IP':
                try:
                    if protocol.payload.name == 'ICMP':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.settimeout(5.0)
                        sock.sendto(pkt, (protocol.header['dst_ip'], 0))

                    elif protocol.payload.payload.name == 'DNS':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.settimeout(5.0)
                        sock.sendto(pkt, ("8.8.8.8", 53))

                    elif protocol.payload.payload.name == 'NTP':
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.settimeout(5.0)
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