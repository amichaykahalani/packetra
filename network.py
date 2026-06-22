import socket
import struct
import fcntl
from protocols.protocol import Protocol


class Network:
    """Manages network communications, protocol-agnostic."""

    @staticmethod
    def send_only(protocol: Protocol) -> None:
        """Send a packet without waiting for a response."""
        pkt = protocol.to_binary()

        if protocol.name == "Ethernet":
            iface = Network.get_default_iface()
            ethertype = protocol.frame["header"]["type"]
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype)
            )
            sock.bind((iface, 0))
            try:
                sock.send(pkt)
            finally:
                sock.close()
            return

        sock_type, dest_addr = protocol.get_socket_info()

        if sock_type == socket.SOCK_RAW:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            sock = socket.socket(socket.AF_INET, sock_type)

        try:
            sock.sendto(pkt, dest_addr)
        finally:
            sock.close()

    @staticmethod
    def send_and_received(protocol: Protocol) -> Protocol:
        """Send a hand-built packet and wait for a response."""
        try:
            pkt = protocol.to_binary()

            if protocol.name == "Ethernet":
                return Network._send_ethernet_raw(protocol, pkt)

            sock_type, dest_addr = protocol.get_socket_info()

            if sock_type == socket.SOCK_RAW:
                return Network._send_and_receive_raw(protocol, pkt, dest_addr)

            sock = socket.socket(socket.AF_INET, sock_type)
            sock.settimeout(10)
            sock.sendto(pkt, dest_addr)
            response, addr = sock.recvfrom(65535)
            sock.close()
            return protocol.deserializer(response)

        except Exception as e:
            print(f"Network error in send_and_received: {e}")
            return protocol

    @staticmethod
    def _send_ethernet_raw(protocol: Protocol, pkt: bytes) -> Protocol:
        """Send/receive raw Ethernet frames via AF_PACKET."""
        iface = Network.get_default_iface()
        ethertype = protocol.header["type"]
        our_mac = protocol.header["src_mac_addr"]

        send_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype)
        )
        send_sock.bind((iface, 0))

        recv_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype)
        )
        recv_sock.bind((iface, 0))
        recv_sock.settimeout(10)

        try:
            send_sock.send(pkt)

            while True:
                response, addr = recv_sock.recvfrom(65535)
                src_mac_in_frame = response[6:12]
                if src_mac_in_frame == our_mac:
                    continue  # loopback, skip
                return protocol.deserializer(response)

        finally:
            send_sock.close()
            recv_sock.close()

    @staticmethod
    def _send_and_receive_raw(
        protocol: Protocol, pkt: bytes, dest_addr: tuple
    ) -> Protocol:
        """Branch by inner protocol to pick the right receive strategy."""
        inner_protocol = getattr(protocol, "payload", None)
        inner_proto_id = protocol.header.get("protocol") if protocol.header else None

        if inner_proto_id == 17 and inner_protocol is not None:  # UDP
            return Network._send_udp_raw(protocol, pkt, dest_addr, inner_protocol)
        elif inner_proto_id == 1:  # ICMP
            return Network._send_icmp_raw(protocol, pkt, dest_addr)
        else:
            return Network._send_raw_only(protocol, pkt, dest_addr)

    @staticmethod
    def _send_udp_raw(
        protocol: Protocol, pkt: bytes, dest_addr: tuple, udp_layer
    ) -> Protocol:
        """Send via raw socket, receive via UDP socket bound to src_port."""
        src_port = udp_layer.header["src_port"]

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.settimeout(10)
        recv_sock.bind(("", src_port))

        try:
            send_sock.sendto(pkt, dest_addr)
            response, addr = recv_sock.recvfrom(65535)

            if udp_layer.payload is not None:
                udp_layer.payload = udp_layer.payload.deserializer(response)
            else:
                udp_layer = udp_layer.deserializer(response)

            return protocol
        finally:
            send_sock.close()
            recv_sock.close()

    @staticmethod
    def _send_icmp_raw(protocol: Protocol, pkt: bytes, dest_addr: tuple) -> Protocol:
        """Send and receive over raw ICMP sockets, filtering by identifier."""
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(10)

        identifier = getattr(protocol.payload, "header", {}).get("identifier")

        try:
            send_sock.sendto(pkt, dest_addr)

            while True:
                response, addr = recv_sock.recvfrom(65535)
                if addr[0] != dest_addr[0]:
                    continue
                if identifier is not None and len(response) >= 26:
                    resp_identifier = struct.unpack("!H", response[24:26])[0]
                    if resp_identifier != identifier:
                        continue
                return protocol.deserializer(response)

        finally:
            send_sock.close()
            recv_sock.close()

    @staticmethod
    def _send_raw_only(protocol: Protocol, pkt: bytes, dest_addr: tuple) -> Protocol:
        """Fallback for unsupported inner protocols."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.settimeout(10)
        try:
            sock.sendto(pkt, dest_addr)
            response, addr = sock.recvfrom(65535)
            return protocol.deserializer(response)
        finally:
            sock.close()

    @staticmethod
    def get_my_ip() -> str:
        """Get local IP by connecting to a public DNS."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    @staticmethod
    def convert_ip_into_bytes(ip: str) -> bytes:
        """Convert dotted-quad IP string to 4 bytes."""
        return socket.inet_aton(ip)

    @staticmethod
    def convert_bytes_into_ip(ip: bytes) -> str:
        """Convert 4-byte network IP to dotted-quad string."""
        return socket.inet_ntop(socket.AF_INET, ip)

    @staticmethod
    def get_my_mac(iface: str) -> bytes:
        """Get MAC address of a network interface via ioctl."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(
            s.fileno(), 0x8927, struct.pack("256s", iface.encode("utf-8"))
        )
        return info[18:24]

    @staticmethod
    def get_ip(family, rdata):
        try:
            if family == "AF_INET":
                return socket.inet_ntop(socket.AF_INET, rdata)
            elif family == "AF_INET6":
                return socket.inet_ntop(socket.AF_INET6, rdata)
        except Exception as e:
            return e

    @staticmethod
    def get_default_iface():
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == "00000000":  # default route
                    return fields[0]
        return "eth0"  # fallback
