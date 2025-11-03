from DNS import DNS
from NTP import NTP
from NetworkTransfer import NetworkTransfer
from pprint import pprint
import socket
from ICMP import ICMP

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.connect(('127.0.0.1', 0))
    sock.settimeout(5.0)
    icmp_request = ICMP(icmp_payload="Hello World")
    packet = icmp_request.to_bytes()
    sock.sendto(packet, ('127.0.0.1', 0))
    answer = sock.recv(1024)
    icmp_answer = ICMP()
    icmp_answer.to_string(answer)
    print(icmp_request.header)
    print(icmp_request.payload)
    print(icmp_answer.header)
    print(icmp_answer.payload)

if __name__ == '__main__':
    main()
