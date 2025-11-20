from NetworkHandler import Network
from BaseProtocol import Protocol
from DNS_PROTOCOL import DNS
from UDP_PROTOCOL import UDP
from IP_PROTOCOL import IP
from NTP_PROTOCOL import NTP

def main():
    pkt = DNS('www.google.com')
    ntp_pkt = IP(dst_ip="129.159.140.221").add_protocol(UDP(dst_port=123).add_protocol(NTP()))
    ans = Network.send_and_received(pkt)
    ntp_ans = Network.send_and_received(ntp_pkt)
    print(ans)
    print("-----------------------------------")
    print(ntp_ans)

if __name__ == '__main__':
    main()
