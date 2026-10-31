"""
engine_udp.py - UDP port scanning.

UDP has no handshake, so "is it open" is inherently more ambiguous than
TCP. The approach here (the same one real scanners use without raw
sockets):

  1. Send an empty UDP datagram to the port.
  2. If the OS delivers back an ICMP "port unreachable" message, the
     connected UDP socket raises ConnectionRefusedError on the next
     recv - that means the port is CLOSED.
  3. If we get an actual UDP reply, the port is OPEN (something is
     listening and responded).
  4. If nothing comes back within the timeout, the port is reported as
     OPEN|FILTERED - genuinely ambiguous, since both "the service is
     open but only replies to specific payloads" and "a firewall
     silently dropped it" look identical from here. This is the same
     honest ambiguity nmap itself reports for a plain UDP scan.
"""

import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def udp_scan_port(target_ip, port, timeout=1.0):
    try:
        service_name = socket.getservbyport(port, "udp")
    except OSError:
        service_name = "unknown"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target_ip, port))
        sock.send(b"")
        try:
            data, _ = sock.recvfrom(1024)
            banner = data[:128].decode("utf-8", errors="ignore").strip()
            return {"port": port, "state": "open", "service": service_name, "banner": banner}
        except socket.timeout:
            return {"port": port, "state": "open|filtered", "service": service_name, "banner": ""}
        except ConnectionRefusedError:
            return {"port": port, "state": "closed", "service": service_name, "banner": ""}
    except Exception:
        return {"port": port, "state": "closed", "service": service_name, "banner": ""}
    finally:
        sock.close()


def run_udp_scan(target_ip, ports, timeout=1.0, max_workers=100, randomize=True, include_all_states=False):
    port_list = list(ports)
    if randomize:
        random.shuffle(port_list)

    all_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(udp_scan_port, target_ip, p, timeout): p
            for p in port_list
        }
        for future in as_completed(futures):
            all_results.append(future.result())

    all_results.sort(key=lambda r: r["port"])
    if include_all_states:
        return all_results
    return [r for r in all_results if r["state"] in ("open", "open|filtered")]
