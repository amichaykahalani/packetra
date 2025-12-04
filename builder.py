from protocols.udp import UDP
from protocols.icmp import ICMP
from protocols.ipv4 import IPv4
from protocols.dns import DNS
from protocols.ntp import NTP
from protocols.ethernet import Ethernet
from protocols.arp import ARP
from network import Network
from protocols.protocol import Protocol
from registry import Registry


class Builder:
    def __init__(self):
        pass

    @staticmethod
    def cast_value(original, new_value_str):
        """Convert input to same type as original field."""
        try:
            if isinstance(original, int):
                return int(new_value_str)
            if isinstance(original, float):
                return float(new_value_str)
            if isinstance(original, bool):
                return new_value_str.lower() in ("1", "true", "yes", "y")
            if isinstance(original, list):
                return new_value_str.split(',')
        except Exception:
            pass
        return new_value_str

    @staticmethod
    def edit_fields(structure: dict):
        """Generic editing for any dict-like header."""
        print("\nAvailable fields:")
        for key in structure.keys():
            print("  -", key)

        field = input("\nWhich key you want to change? ")
        if field not in structure:
            print("Invalid key!")
            return

        new_value_str = input(f"What value do you want to put in '{field}'? ")

        original = structure[field]
        structure[field] = Builder.cast_value(original, new_value_str)

    @staticmethod
    def build(protocol: Protocol, is_raw=False):
        registry = Registry()

        # ---------------- RAW IPv4 MODE ----------------
        if is_raw and protocol.name == "IPv4":

            is_payload = input("Do you want to add additional payload? (y/n) ")
            if is_payload != "y":
                return

            another_protocol = input(
                "Which protocol you want to add?\nICMP\nUDP\n"
            )

            # ---------------- ICMP ----------------
            if another_protocol.upper() == "ICMP":
                pkt = protocol.add_protocol(ICMP())
                print(pkt)

                while True:
                    edit = input("Change fields? (y/n) ")
                    if edit != "y":
                        break

                    layer = input("Which layer? (ip/icmp) ")

                    if layer == "ip":
                        Builder.edit_fields(protocol.header)

                    elif layer == "icmp":
                        Builder.edit_fields(protocol.payload.header)

                ans = Network.send_and_received(pkt)
                print(ans)
                return

            # ---------------- UDP ----------------
            if another_protocol.upper() == "UDP":

                proto2 = input("Do you want to add DNS/NTP inside UDP? (y/n) ")
                if proto2 != "y":
                    return

                deeper = input("Which protocol? (DNS/NTP) ")

                # ---------------- DNS ----------------
                if deeper.lower() == "dns":
                    domain = input("Domain (example.com): ")
                    pkt = protocol.add_protocol(
                        UDP(dst_port=53).add_protocol(DNS(domain=domain))
                    )
                    print(pkt)

                    while True:
                        edit = input("Change fields? (y/n) ")
                        if edit != "y":
                            break

                        layer = input("Which layer? (ip/udp/dns) ")

                        if layer == "ip":
                            Builder.edit_fields(protocol.header)

                        elif layer == "udp":
                            Builder.edit_fields(protocol.payload.header)

                        elif layer == "dns":
                            section = input("header or question? ")

                            if section == "header":
                                Builder.edit_fields(protocol.payload.payload.header)
                            else:
                                Builder.edit_fields(protocol.payload.payload.question_section)

                    ans = Network.send_and_received(pkt)
                    print(ans)
                    return

                # ---------------- NTP ----------------
                if deeper.lower() == "ntp":

                    pkt = protocol.add_protocol(
                        UDP(dst_port=123).add_protocol(NTP())
                    )
                    print(pkt)

                    while True:
                        edit = input("Change fields? (y/n) ")
                        if edit != "y":
                            break

                        layer = input("Which layer? (ip/udp/ntp) ")

                        if layer == "ip":
                            Builder.edit_fields(protocol.header)

                        elif layer == "udp":
                            Builder.edit_fields(protocol.payload.header)

                        elif layer == "ntp":
                            part = input("Which part? (header/reference_parameters/timestamps) ")

                            if part == "header":
                                Builder.edit_fields(protocol.payload.payload.header)

                            elif part == "reference_parameters":
                                Builder.edit_fields(protocol.payload.payload.reference_parameters)

                            elif part == "timestamps":
                                Builder.edit_fields(protocol.payload.payload.timestamps)

                    ans = Network.send_and_received(pkt)
                    print("Response:\n", ans)
                    return

        # ---------------- NON-RAW MODE ----------------
        else:
            if protocol.name == "DNS":
                domain = input("Domain: ")
                pkt = DNS(domain=domain)
                ans = Network.send_and_received(pkt)
                print("Response:\n", ans)

            elif protocol.name == "NTP":
                pkt = NTP()
                ans = Network.send_and_received(pkt)
                print("Response:\n", ans)
