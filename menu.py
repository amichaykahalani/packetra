from attacks import Attack
from builder import Builder
from protocols.protocol import Protocol


class Menu:
    def __init__(self):
        pass

    @staticmethod
    def _prompt_choice(options: dict, title: str) -> int:
        """Print a numbered menu, keep asking until a valid choice is entered."""
        while True:
            print(f"\n{title}")
            for key, value in options.items():
                label = value.__name__ if callable(value) else value
                print(f"  {key}. {label}")

            raw = input("\n> ").strip()

            if not raw.isdigit():
                print("Please enter a number.")
                continue

            choice = int(raw)
            if choice not in options:
                print("Invalid option, try again.")
                continue

            return choice

    @staticmethod
    def show():
        main_options = {
            1: "DoS Attack",
            2: "MITM Attack",
            3: "Create packets",
            4: "Exit",
        }

        while True:
            choice = Menu._prompt_choice(main_options, "Welcome to Packetra! What would you like to do?")

            if choice == 1:
                Menu._run_dos_attack()
            elif choice == 2:
                Menu._run_mitm_attack()
            elif choice == 3:
                Menu._run_packet_builder()
            elif choice == 4:
                print("Goodbye!")
                break

    @staticmethod
    def _run_dos_attack():
        dos_options = {
            1: Attack.udp_flood,
            2: Attack.icmp_flood,
            3: Attack.dns_amplification,
            4: Attack.ntp_amplification,
        }
        choice = Menu._prompt_choice(dos_options, "Which DoS attack would you like to run?")
        dos_options[choice]()

    @staticmethod
    def _run_mitm_attack():
        mitm_options = {
            1: Attack.arp_spoofing,
        }
        choice = Menu._prompt_choice(mitm_options, "Which MITM attack would you like to run?")
        mitm_options[choice]()

    @staticmethod
    def _run_packet_builder():
        registry = Protocol.registry
        choice = Menu._prompt_choice(
            {key: cls.__name__ for key, cls in registry.items()},
            "What packet would you like to craft?"
        )
        protocol_cls = registry[choice]

        NEEDS_ETHERNET_WRAPPER = {2054}

        # Protocols that ride directly inside IPv4 and aren't independently
        # routable — wrap them automatically so the user doesn't have to
        # build IPv4 by hand first just to send a ping or a UDP packet.
        NEEDS_IPV4_WRAPPER = {1, 17}  # ICMP, UDP

        # Protocols that ride inside UDP (and therefore IPv4 -> UDP -> X),
        # keyed by their TYPE_ID with the UDP destination port they need to
        # be addressed to. UDP.deserializer() dispatches replies back to the
        # right class via Protocol.registry[dst_port], so dst_port must match
        # TYPE_ID for the round trip to work.
        NEEDS_IPV4_UDP_WRAPPER = {53: 53, 123: 123}  # DNS, NTP

        if choice in NEEDS_ETHERNET_WRAPPER:
            ethernet = registry[3]()
            ethernet.setup()
            inner = protocol_cls()
            ethernet.payload = inner
            protocol = ethernet
            current_layer = inner

        elif choice in NEEDS_IPV4_WRAPPER:
            ipv4 = registry[2048]()  # IPv4's TYPE_ID
            ipv4.setup()
            inner = protocol_cls()
            ipv4.payload = inner
            protocol = ipv4
            current_layer = inner
        elif choice in NEEDS_IPV4_UDP_WRAPPER:
            ipv4 = registry[2048]()  # IPv4's TYPE_ID
            ipv4.setup()
            udp = registry[17]()  # UDP's TYPE_ID
            udp.header['dst_port'] = NEEDS_IPV4_UDP_WRAPPER[choice]
            inner = protocol_cls()
            udp.payload = inner
            ipv4.payload = udp
            protocol = ipv4
            current_layer = inner
        else:
            protocol = protocol_cls()
            current_layer = protocol

        if hasattr(current_layer, 'setup'):
            current_layer.setup()

        Builder.build(protocol, start_layer=current_layer)