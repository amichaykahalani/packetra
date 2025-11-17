from Network import Network
from Protocol import Protocol
from DNS import DNS
from UDP import UDP
from IPv4 import IPv4

def main():
    pkt = DNS('www.google.com')
    ans = Network.send_and_received(pkt)
    print(ans)


if __name__ == '__main__':
    main()
