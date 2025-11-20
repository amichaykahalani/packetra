from Network import Network
from Protocol import Protocol
from DNS import DNS
from UDP import UDP
from IPv4 import IPv4
from NTP import NTP

def main():
    pkt = IPv4(dst_ip="8.8.8.8").add_protocol(UDP().add_protocol(DNS('www.google.com')))
    ntp_pkt = IPv4(dst_ip="129.159.140.221").add_protocol(UDP(dst_port=123).add_protocol(NTP()))
    ans = Network.send_and_received(pkt)
    ntp_ans = Network.send_and_received(ntp_pkt)
    print(ans)
    print("----------------ntp_ans-------------------")
    print(ntp_ans)

if __name__ == '__main__':
    main()
