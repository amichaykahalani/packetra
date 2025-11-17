import socket
from Protocol import Protocol

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
            return "Something went wrong"

    @staticmethod
    def send_and_received(protocol: Protocol) -> Protocol:
        try:
            if protocol.protocol_name == 'DNS':
                from DNS import DNS
                pkt = protocol.to_binary()
                print(pkt)
                response = Network.create_sock_and_send(pkt)
                print("response:", response)
                return DNS('www.google.com', is_response=True).deserializer(response)

            elif protocol.protocol_name == 'UDP':
                from DNS import DNS
                from UDP import UDP
                print('type of payload: ', type(protocol.payload))
                pkt = protocol.to_binary() + protocol.payload.to_binary()
                print("pkt: ", pkt)
                response = Network.create_sock_and_send(pkt)
                return UDP().deserializer(response)

            elif protocol.protocol_name == 'IPv4':
                from IPv4 import IPv4
                print('type of payload: ', type(protocol.payload))
                pkt = protocol.to_binary()
                print("pkt: ", pkt)
                response = Network.create_rawsock_and_send(pkt)
                return IPv4().deserializer(response)

            else:
                print("something went wrong, protocol not supported")

        except Exception as e:
            response = b""
            print(e)

        return protocol

    @staticmethod
    def create_sock_and_send(pkt):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        sock.connect(('8.8.8.8', 53))
        print(f"sending data to {('8.8.8.8', 53)}")
        sock.sendall(pkt)
        response = sock.recv(4096)
        print("response:", response)
        sock.close()
        return response

    @staticmethod
    def create_rawsock_and_send(pkt):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.settimeout(5.0)
        sock.connect(('8.8.8.8', 53))
        print(f"sending data to {('8.8.8.8', 53)}")
        sock.sendall(pkt)
        response = sock.recv(4096)
        print("response:", response)
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
        ip_bytes = socket.inet_aton(ip)
        return ip_bytes