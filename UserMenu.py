from NetworkHandler import Network
from DNS_PROTOCOL import DNS
from UDP_PROTOCOL import UDP
from IP_PROTOCOL import IP
from NTP_PROTOCOL import NTP
from ICMP_PROTOCOL import ICMP

class Menu:
    def __init__(self):
        pass

    @staticmethod
    def show_menu():
        want_to_exit = False
        while not want_to_exit:
            chosen_protocol = input("which packet you want to send?\n-ICMP\n-DNS\n-NTP\n\nwrite 'Exit' to exit.\nYour answer: ")
            if chosen_protocol == "ICMP":
                want_to_exit = True
                dst_ip = input("Enter destination IP: ")
                pkt = IP(dst_ip=dst_ip).add_protocol(ICMP())
                ans = Network.send_and_received(pkt)
                ans.payload.payload = pkt
                print("\nReceived Packet:")
                print(ans)

            elif chosen_protocol == "DNS":
                want_to_exit = True
                domain_name = input("Enter domain name: ")
                pkt = IP(dst_ip='8.8.8.8').add_protocol(UDP().add_protocol(DNS(domain_name)))
                ans = Network.send_and_received(pkt)
                print("\nReceived Packet:")
                print(ans)

            elif chosen_protocol == "NTP":
                want_to_exit = True
                ntp_pkt = IP(dst_ip="129.159.140.221").add_protocol(UDP(dst_port=123).add_protocol(NTP()))
                ntp_ans = Network.send_and_received(ntp_pkt)
                print("\nReceived Packet:")
                print(ntp_ans)

            else:
                print("Please enter a valid option")


