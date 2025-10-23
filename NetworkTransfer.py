import socket

class NetworkTransfer:

    def __init__(self):
        pass

    @staticmethod
    def send_and_received(data, ip, port, protocol="TCP"):
        protocols = {"TCP": socket.SOCK_STREAM, "UDP": socket.SOCK_DGRAM}
        sock_type = protocols.get(protocol.upper(), socket.SOCK_STREAM)

        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(5.0)

        try:
            if sock_type == socket.SOCK_STREAM:
                sock.connect((ip, port))
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





