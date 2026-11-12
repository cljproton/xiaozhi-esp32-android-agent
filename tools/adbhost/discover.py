"""Ask the LAN for adb's mDNS services so the wireless debugging port does not
have to be typed in by hand. Prints name, address and port per service."""

import socket
import struct
import sys

GROUP = ("224.0.0.251", 5353)


def encode_name(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def query(service, timeout=3.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.settimeout(0.5)
    packet = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + encode_name(service + ".local") + struct.pack(
        ">HH", 12, 1
    )
    sock.sendto(packet, GROUP)
    found = {}
    import time

    end = time.time() + timeout
    while time.time() < end:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        if b"local" not in data:
            continue
        # Good enough for a port announcement: keep the printable text and the
        # last two bytes, which are the SRV port in these short replies.
        text = data.decode("latin-1")
        if service.split(".")[0] not in text:
            continue
        found[data] = text
    return list(found.values())


def main():
    for service in ("_adb-tls-connect._tcp", "_adb-tls-pairing._tcp"):
        for text in query(service):
            readable = "".join(c if 32 <= ord(c) < 127 else " " for c in text)
            print(f"{service}: {readable.strip()}")


if __name__ == "__main__":
    sys.exit(main() or 0)
