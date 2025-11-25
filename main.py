from protocols.ethernet import Ethernet
from protocols.udp import UDP
from protocols.icmp import ICMP
from protocols.ipv4 import IPv4
from protocols.dns import DNS
from protocols.ntp import NTP
from network import Network

def main():
    icmp_pkt = IPv4(dst_ip="8.8.8.8").add_protocol(ICMP())
    ntp_pkt = IPv4(dst_ip="216.40.34.37").add_protocol(UDP(dst_port=123).add_protocol(NTP()))
    dns_pkt = IPv4(dst_ip="8.8.8.8").add_protocol(UDP(dst_port=53).add_protocol(DNS(domain="google.com")))
    icmp_ans = Network.send_and_received(icmp_pkt)
    ntp_ans = Network.send_and_received(ntp_pkt)
    dns_ans = Network.send_and_received(dns_pkt)
    print(icmp_ans)
    print(ntp_ans)
    print(dns_ans)

if __name__ == '__main__':
    main()