from protocols.ethernet import Ethernet
from protocols.udp import UDP
from protocols.icmp import ICMP
from protocols.ipv4 import IPv4
from protocols.dns import DNS
from protocols.ntp import NTP
from network import Network

def main():
    pkt = IPv4(dst_ip="8.8.8.8").add_protocol(ICMP())
    ans = Network.send_and_received(pkt)
    print(ans)

if __name__ == '__main__':
    main()