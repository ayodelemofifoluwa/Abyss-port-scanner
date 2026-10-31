"""
syn_scan.py - Raw SYN ("half-open") scanning using scapy.

Requires:
  - pip install scapy
  - Root/administrator privileges (raw sockets are a privileged OS operation)
  - On Windows: Npcap must also be installed (https://npcap.com)

How this differs from the connect-scan engine in pyscan.py:
  A normal connect scan (socket.connect_ex) completes the full TCP
  three-way handshake -- SYN, SYN-ACK, ACK -- for every port, whether
  open or closed. That's simple but "loud": every attempt is a fully
  logged connection.

  A SYN scan sends only the first SYN packet and inspects the raw
  reply flags:
    - SYN-ACK back            -> port is open. We then send a RST
                                  instead of completing the handshake,
                                  so the connection never fully forms.
    - RST-ACK back             -> port is closed.
    - No reply at all (timeout)-> port is likely filtered by a firewall.

  This requires crafting raw IP/TCP packets directly, bypassing the
  normal socket API entirely -- which is exactly why it needs raw
  socket privileges (root/admin). Use only on hosts you own or have
  explicit written permission to test.
"""

import os
import socket
import sys

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0  # silence scapy's default packet-print spam
except ImportError:
    SCAPY_AVAILABLE = False


def has_raw_socket_privileges():
    if os.name == "nt":
        # Best-effort check on Windows; scapy will still raise clearly if it fails
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return hasattr(os, "geteuid") and os.geteuid() == 0


def syn_scan_port(target_ip, port, timeout=1.0):
    try:
        service_name = socket.getservbyport(port, "tcp")
    except OSError:
        service_name = "unknown"

    src_port = 40000 + (port % 10000)
    pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")
    response = sr1(pkt, timeout=timeout, verbose=0)

    if response is None:
        return {"port": port, "state": "filtered", "service": service_name}

    if response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK
            rst_pkt = IP(dst=target_ip) / TCP(
                sport=src_port, dport=port, flags="R", seq=response.seq + 1
            )
            sr1(rst_pkt, timeout=timeout, verbose=0)
            return {"port": port, "state": "open", "service": service_name}
        elif flags == 0x14:  # RST-ACK
            return {"port": port, "state": "closed", "service": service_name}

    return {"port": port, "state": "filtered", "service": service_name}


def syn_scan_range(target_ip, ports, timeout=1.0, progress_cb=None):
    """
    Sequential by design: scapy's sr1() is a blocking send/receive per packet,
    and interleaving raw sockets across threads safely needs careful handling
    of the underlying capture handle. This is slower than the connect/async
    engines but stealthier. A real threaded/async raw-socket implementation
    is possible but meaningfully more complex -- worth a dedicated follow-up
    if scan speed on this engine becomes a bottleneck for you.
    """
    results = []
    total = len(ports)
    for i, port in enumerate(ports, start=1):
        result = syn_scan_port(target_ip, port, timeout)
        results.append(result)
        if progress_cb:
            progress_cb(i, total)
    return sorted(results, key=lambda r: r["port"])


if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("[!] scapy is not installed. Run: pip install scapy")
        sys.exit(1)
    if not has_raw_socket_privileges():
        print("[!] SYN scanning needs raw socket privileges.")
        print("    Linux/Mac: sudo python3 syn_scan.py <ip> <ports>")
        print("    Windows:   run as Administrator, with Npcap installed")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("Usage: python3 syn_scan.py <target_ip> <port,port,port-range>")
        sys.exit(1)

    target = sys.argv[1]
    port_spec = sys.argv[2]
    ports = []
    for chunk in port_spec.split(","):
        if "-" in chunk:
            a, b = chunk.split("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(chunk))

    print(f"[*] SYN scanning {target} — {len(ports)} ports")
    for r in syn_scan_range(target, ports):
        if r["state"] == "open":
            print(f"    [+] {r['port']:<6} {r['service']:<12} OPEN")
