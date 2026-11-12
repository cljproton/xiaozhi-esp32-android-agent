"""Better mDNS query for ADB TLS services."""

import socket
import struct
import sys
import time

GROUP = ("224.0.0.251", 5353)

def encode_name(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"

def decode_name(data, offset):
    """Decode a compressed domain name."""
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:  # Compression pointer
            pointer = struct.unpack(">H", data[offset:offset+2])[0] & 0x3FFF
            offset += 2
            # Recursively decode from pointer
            saved_offset = offset
            offset = pointer
            rest, _ = decode_name(data, offset)
            labels.extend(rest)
            offset = saved_offset
            break
        offset += 1
        labels.append(data[offset:offset+length].decode('latin-1'))
        offset += length
    return labels, offset

def parse_dns(data):
    """Parse DNS response."""
    if len(data) < 12:
        return []
    header = struct.unpack(">HHHHHH", data[:12])
    qdcount, ancount, nscount, arcount = header[2:6]
    offset = 12
    # Skip questions
    for _ in range(qdcount):
        _, offset = decode_name(data, offset)
        offset += 4  # type + class
    results = []
    for _ in range(ancount):
        name_labels, offset = decode_name(data, offset)
        name = ".".join(name_labels)
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        if rtype == 33:  # SRV
            priority, weight, port = struct.unpack(">HHH", rdata[:6])
            target_labels, _ = decode_name(rdata, 6)
            target = ".".join(target_labels)
            results.append({"name": name, "port": port, "target": target, "priority": priority})
        elif rtype == 16:  # TXT
            txt_data = rdata.decode('latin-1', errors='ignore')
            results.append({"name": name, "txt": txt_data})
    return results

def query(service, timeout=3.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.settimeout(0.5)
    packet = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + encode_name(service + ".local") + struct.pack(">HH", 12, 1)
    sock.sendto(packet, GROUP)
    found = {}
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        results = parse_dns(data)
        for r in results:
            key = r.get("name", "") + str(r.get("port", ""))
            found[key] = r
    return list(found.values())

def main():
    for service in ("_adb-tls-connect._tcp", "_adb-tls-pairing._tcp"):
        print(f"\n=== {service} ===")
        for r in query(service):
            if "port" in r:
                print(f"  SRV: {r['name']} -> {r['target']}:{r['port']} (pri={r['priority']})")
            if "txt" in r:
                print(f"  TXT: {r['txt']}")

if __name__ == "__main__":
    main()