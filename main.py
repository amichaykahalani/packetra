from protocols.ethernet import Ethernet
from protocols.udp import UDP
from protocols.icmp import ICMP
from protocols.ipv4 import IPv4
from protocols.dns import DNS
from protocols.ntp import NTP
from network import Network
from protocols.ethernet import Ethernet
from protocols.arp import ARP

def main():
    eth = Ethernet()
    eth.frame['header']['type'] = 0x0806
    arp_pkt = eth.add_protocol(ARP())
    arp_ans = Network.send_and_received(arp_pkt)
    print(arp_ans)
    ntp_pkt = IPv4(dst_ip="51.17.20.53").add_protocol(UDP(dst_port=123).add_protocol(NTP()))
    dns_pkt = IPv4(dst_ip='8.8.8.8').add_protocol(UDP(dst_port=53).add_protocol(DNS(domain="google.com")))
    ntp_ans = Network.send_and_received(ntp_pkt)
    dns_ans = Network.send_and_received(dns_pkt)
    print(ntp_ans)
    print(dns_ans)

if __name__ == '__main__':
    main()