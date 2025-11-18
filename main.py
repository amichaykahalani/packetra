from Network import Network
from Protocol import Protocol
from DNS import DNS
from UDP import UDP
from IPv4 import IPv4

def main():
    ip = IPv4()
    udp = UDP()
    dns = DNS('www.google.com')
    pkt = ip.add_protocol(udp.add_protocol(dns))
    ans = Network.send_and_received(pkt)
    print(ans)

if __name__ == '__main__':
    main()
