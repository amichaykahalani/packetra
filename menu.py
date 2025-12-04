from attacks import Attack
from builder import Builder
from registry import Registry

class Menu:
    def __init__(self):
        pass

    @staticmethod
    def show():
        registry: Registry = Registry()
        welcome_str: str = (f"Hello! Welcome to Packetra, what would you like to do?\n"
                            f"1. DoS Attack\n"
                            f"2. MITM Attack\n"
                            f"3. Create packets\n")
        print(welcome_str)
        choice: str = input()
        if choice == "1":
            dos_options: dict = {
                1: Attack.udp_flood,
                2: Attack.icmp_flood,
                3: Attack.dns_amplification,
                4: Attack.ntp_amplification
            }
            option_string = (f"Nice. which DoS attack would you like to do?\n"
                             f"1. UDP flood\n"
                             f"2. ICMP Flood\n"
                             f"3. DNS Amplification\n"
                             f"4. NTP Amplification\n")

            print(option_string)
            chosen_option = int(input())
            dos_options.get(chosen_option)()

        elif choice == "2":
            mitm_options: dict = {
                1: Attack.arp_spoofing
            }
            option_string = (f"Nice. which MITM attack would you like to do?\n"
                             f"1. ARP spoof\n")

            print(option_string)
            chosen_option = int(input())
            mitm_options.get(chosen_option)()

        elif choice == "3":
            option_string: str = (f"Nice. what packet would you like to craft?\n"
                                  f"1: DNS\n"
                                  f"2: NTP\n"
                                  f"3: Ethernet\n"
                                  f"4: IPv4\n")

            print(option_string)
            chosen_option = int(input())
            is_raw: bool = False
            if chosen_option in [3, 4]:
                is_raw = True

            protocol = registry.packets.get(chosen_option)()
            Builder.build(protocol, is_raw=is_raw)



