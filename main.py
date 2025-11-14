from Network import Network
from Protocol import Protocol
from DNS import DNS
from UDP import UDP
from IPv4 import IPv4

def main():
    ip = IPv4()
    print(ip.to_binary())
    pkt = UDP().add_protocol(DNS('www.google.com'))
    print('type of packet: ', type(pkt))
    dns_answer = Network.send_and_received(pkt)
    print(dns_answer)
    dns_answer2 = Network.send_and_received(pkt)
    print(type(dns_answer2))


if __name__ == '__main__':
    main()
