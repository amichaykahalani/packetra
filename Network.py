import socket
from Protocol import Protocol


class Network:

    def __init__(self):
        self.packets = []

    """
    @staticmethod
    def send_and_received(data, ip, port, protocol="TCP"):
        protocols = {"TCP": socket.SOCK_STREAM, "UDP": socket.SOCK_DGRAM}
        sock_type = protocols.get(protocol.upper(), socket.SOCK_STREAM)

        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(5.0)

        try:
            if sock_type == socket.SOCK_STREAM:
                sock.connect((ip, port))
                print(f"sending data to {(ip, port)}")
                sock.sendall(data)
                response = sock.recv(4096)

            else:
                sock.sendto(data, (ip, port))
                response, _ = sock.recvfrom(4096)

        except Exception as e:
            response = b""
            print(e)

        finally:
            sock.close()

        return response

    @staticmethod
    def get_ip(family, rdata):
        try:
            if family == 'AF_INET':
                return socket.inet_ntop(socket.AF_INET, rdata)
            elif family == 'AF_INET6':
                return socket.inet_ntop(socket.AF_INET6, rdata)

        except Exception as e:
            return "Something went wrong"

    def sniff(self):
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        while True:
            packet = sniffer.recvfrom(65535)
            self.packets.append(packet)
    """

    @staticmethod
    def send_and_received(protocol: Protocol) -> Protocol:


        try:
            if protocol.protocol_name == 'DNS':
                from DNS import DNS
                pkt = protocol.to_binary()
                print(pkt)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5.0)
                sock.connect(('8.8.8.8', 53))
                print(f"sending data to {('8.8.8.8', 53)}")
                sock.sendall(pkt)
                response = sock.recv(4096)
                print("response:", response)
                return DNS('www.google.com', is_response=True).deserializer(response)

            elif protocol.protocol_name == 'UDP':
                from DNS import DNS
                from UDP import UDP
                pkt = protocol.to_binary()
                print("type of pkt: ", type(pkt))
                print("pkt: ", pkt)
                print(f"sending data to {('UDP', 53)}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5.0)
                sock.connect(('8.8.8.8', 53))
                print(f"sending data to {('8.8.8.8', 53)}")
                sock.sendall(pkt)
                response = sock.recv(4096)
                print("response:", response)
                return UDP().deserializer(response)
            else:
                print("something went wrong, protocol not supported")

        except Exception as e:
            response = b""
            print(e)

        finally:
            sock.close()

        return response

    @staticmethod
    def get_ip(family, rdata):
        try:
            if family == 'AF_INET':
                return socket.inet_ntop(socket.AF_INET, rdata)
            elif family == 'AF_INET6':
                return socket.inet_ntop(socket.AF_INET6, rdata)

        except Exception as e:
            return "Something went wrong"

    def sniff(self):
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        while True:
            packet = sniffer.recvfrom(65535)
            self.packets.append(packet)

if __name__ == "__main__":
    Network.send_and_received = Network.get_ip
    Network.get_ip = Network.get_ip