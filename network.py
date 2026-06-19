import socket
import struct
import fcntl
from protocols.protocol import Protocol


class Network:
    """
    Manages network communications.
    This class is protocol-agnostic, using the Protocol object's
    own socket requirements to handle data transmission.
    """

    @staticmethod
    def send_and_received(protocol: Protocol) -> Protocol:
        """
        Sends a hand-built packet and waits for a response.

        Packets are sent via a raw IPPROTO_RAW socket (since we build our
        own IP header). Raw send-only sockets aren't bound to anything
        the kernel recognizes as a real listener, so the OS won't deliver
        replies back to them — it'll send "ICMP port unreachable" instead.
        To actually receive a reply, we open a second, separate socket
        appropriate to the inner protocol (UDP or ICMP) just for listening.
        """
        try:
            pkt = protocol.to_binary()

            # Ethernet (and anything riding directly on it, like ARP) has
            # no IP header at all, so it can't go through the AF_INET
            # paths below -- it needs AF_PACKET bound to an interface.
            # Dispatch on this before the generic SOCK_RAW check, since
            # Ethernet.get_socket_info() also reports SOCK_RAW but means
            # something different by it (L2 raw, not AF_INET IPPROTO_RAW).
            if protocol.name == 'Ethernet':
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
        """Send/receive raw Ethernet frames via AF_PACKET, bound to the
        default interface. Used for ARP and any other link-layer
        protocol that has no IP header above it.

        AF_PACKET sockets bound to ETH_P_ALL-style ethertypes will also
        see our own outgoing frame echoed back by the kernel on some
        platforms, so we filter out anything whose source MAC matches
        ours before treating a received frame as the reply.
        """
        iface = Network.get_default_iface()
        ethertype = protocol.header['type']
        our_mac = protocol.header['src_mac_addr']

        send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype))
        send_sock.bind((iface, 0))

        recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype))
        recv_sock.bind((iface, 0))
        recv_sock.settimeout(10)

        try:
            print(f"[DEBUG] Sending {len(pkt)} byte Ethernet frame on {iface}, ethertype {hex(ethertype)}")
            send_sock.send(pkt)

            while True:
                response, addr = recv_sock.recvfrom(65535)
                src_mac_in_frame = response[6:12]
                if src_mac_in_frame == our_mac:
                    continue  # our own outgoing frame looped back, not a real reply
                return protocol.deserializer(response)

        finally:
            send_sock.close()
            recv_sock.close()

    @staticmethod
    def _send_and_receive_raw(protocol: Protocol, pkt: bytes, dest_addr: tuple) -> Protocol:
        """Handles the raw-send case, branching on what the inner protocol
        actually is, since UDP and ICMP need different receive sockets."""
        inner_protocol = getattr(protocol, 'payload', None)
        inner_proto_id = protocol.header.get('protocol') if protocol.header else None

        if inner_proto_id == 17 and inner_protocol is not None:  # UDP
            return Network._send_udp_raw(protocol, pkt, dest_addr, inner_protocol)
        elif inner_proto_id == 1:  # ICMP
            return Network._send_icmp_raw(protocol, pkt, dest_addr)
        else:
            return Network._send_raw_only(protocol, pkt, dest_addr)

    @staticmethod
    def _send_udp_raw(protocol: Protocol, pkt: bytes, dest_addr: tuple, udp_layer) -> Protocol:
        """Send via raw socket, receive via a normal UDP socket bound to
        the same source port so the kernel has a real listener for the
        reply (otherwise it bounces with ICMP port-unreachable)."""
        src_port = udp_layer.header['src_port']

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.settimeout(10)
        recv_sock.bind(('', src_port))

        try:
            print(f"[DEBUG] Sending {len(pkt)} bytes to {dest_addr}, listening on port {src_port}")
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
        """Send and receive both over raw ICMP sockets. ICMP has no ports,
        so the kernel delivers any inbound ICMP traffic on this interface
        to a raw ICMP socket without needing a bound port — we just have
        to make sure the reply we read back is actually ours."""
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(10)

        identifier = getattr(protocol.payload, 'header', {}).get('identifier')

        try:
            print(f"[DEBUG] Sending {len(pkt)} bytes to {dest_addr}")
            send_sock.sendto(pkt, dest_addr)

            while True:
                response, addr = recv_sock.recvfrom(65535)
                print(f"[DEBUG] full IP+ICMP response: {response.hex()}")
                print(f"[DEBUG] response length: {len(response)}")
                # response includes the IP header; ICMP type/code start at byte 20
                if addr[0] != dest_addr[0]:
                    continue
                if identifier is not None and len(response) >= 26:
                    resp_identifier = struct.unpack('!H', response[24:26])[0]
                    if resp_identifier != identifier:
                        continue
                return protocol.deserializer(response)

        finally:
            send_sock.close()
            recv_sock.close()

    @staticmethod
    def _send_raw_only(protocol: Protocol, pkt: bytes, dest_addr: tuple) -> Protocol:
        """Fallback: send via raw socket with no dedicated receive
        strategy (e.g. unsupported inner protocols). Will almost
        certainly time out on the response, but won't crash."""
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
        """Retrieves the local machine's IP address by connecting to a public DNS."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    @staticmethod
    def convert_ip_into_bytes(ip: str) -> bytes:
        """Converts a dotted-quad IP string to 4-byte format."""
        return socket.inet_aton(ip)

    @staticmethod
    def convert_bytes_into_ip(ip: bytes) -> str:
        """Converts 4-byte network IP format to a dotted-quad string."""
        return socket.inet_ntop(socket.AF_INET, ip)

    @staticmethod
    def get_my_mac(iface: str) -> bytes:
        """Uses IOCTL to retrieve the MAC address of a specific network interface."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface.encode('utf-8')))
        return info[18:24]

    @staticmethod
    def get_ip(family, rdata):
        try:
            if family == 'AF_INET':
                return socket.inet_ntop(socket.AF_INET, rdata)
            elif family == 'AF_INET6':
                return socket.inet_ntop(socket.AF_INET6, rdata)
        except Exception as e:
            return e

    @staticmethod
    def get_default_iface():
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == '00000000':  # default route
                    return fields[0]
        return 'eth0'  # fallback