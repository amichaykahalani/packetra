from Network import Network
from Protocol import Protocol
from DNS import DNS
from UDP import UDP
from IPv4 import IPv4

def main():
    pkt = IPv4().add_protocol(UDP().add_protocol(DNS('www.google.com')))
    print(type(pkt.payload.payload))
    print('type of packet: ', type(pkt))
    dns_answer = Network.send_and_received(pkt)
    print(dns_answer)


if __name__ == '__main__':
    main()
