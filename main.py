from Network import Network
<<<<<<< HEAD
from Protocol import Protocol
from DNS import DNS
from UDP import UDP

def main():
    pkt = UDP().add_protocol(DNS('8.8.8.8'))
    dns_answer = Network.send_and_received(DNS('8.8.8.8'))
    print(dns_answer)
    dns_answer2 = Network.send_and_received(pkt)
    print(type(dns_answer2))
=======

def main():
    pass
>>>>>>> 3846773ce1e7ebe7a3fb21193d33468514d033e4


if __name__ == '__main__':
    main()
