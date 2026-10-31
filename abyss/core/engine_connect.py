"""
engine_connect.py - The baseline TCP connect-scan engine.

Uses socket.connect_ex() to complete the full three-way handshake on
every port. Simplest and most compatible engine (no special privileges
needed), but the "loudest": every attempt is a fully logged connection.

Port states reported:
  - open     : connect_ex returned 0
  - closed   : connect_ex returned an error immediately (e.g. RST received)
  - filtered : the connection attempt timed out with no reply at all -
               usually means a firewall silently dropped the packet
"""

import random
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed


# --- Minimal "NSE-lite" protocol probes, keyed by port -----------------

def probe_http(sock, port):
    sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
    return sock.recv(2048)


def probe_https(sock_raw, target_ip, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(sock_raw, server_hostname=target_ip) as tls_sock:
        tls_sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        data = tls_sock.recv(2048)
        return data, ""


def probe_smtp(sock, port):
    # Most SMTP servers greet unprompted, but EHLO gets a fuller feature list
    greeting = sock.recv(1024)
    try:
        sock.send(b"EHLO abyss.local\r\n")
        reply = sock.recv(1024)
        return greeting + reply
    except Exception:
        return greeting


def probe_redis(sock, port):
    sock.send(b"PING\r\n")
    return sock.recv(256)


def probe_generic(sock, port):
    # Many services (SSH, FTP, MySQL) announce a version string unprompted
    return sock.recv(1024)


SCRIPT_TABLE = {
    80: probe_http, 8080: probe_http, 8000: probe_http, 8888: probe_http,
    25: probe_smtp, 587: probe_smtp,
    6379: probe_redis,
}


def scan_single_port(target_ip, port, timeout):
    try:
        service_name = socket.getservbyport(port, "tcp")
    except OSError:
        service_name = "unknown"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = None
    extra = ""

    try:
        try:
            result = sock.connect_ex((target_ip, port))
        except socket.timeout:
            # No reply at all within the timeout window - likely firewall-dropped
            return port, "filtered", service_name, None, ""

        if result != 0:
            return port, "closed", service_name, None, ""

        try:
            if port == 443:
                raw_bytes, extra = probe_https(sock, target_ip, port)
                banner = raw_bytes.decode("utf-8", errors="ignore").split("\r\n")[0]
            elif port in SCRIPT_TABLE:
                raw_bytes = SCRIPT_TABLE[port](sock, port)
                banner = raw_bytes.decode("utf-8", errors="ignore").split("\r\n")[0]
            else:
                raw_bytes = probe_generic(sock, port)
                banner = raw_bytes.decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            banner = "(open, no banner)"
        except ssl.SSLError:
            banner = "(open, TLS handshake failed - non-HTTPS on 443?)"
        except Exception:
            banner = "(open, banner read failed)"

        return port, "open", service_name, banner, extra

    except Exception:
        return port, "closed", service_name, None, ""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run_scan_on_host(target_ip, ports, timeout, max_workers, randomize=True, include_all_states=False):
    """
    By default returns only open ports (list of dicts with port/service/banner/extra).
    With include_all_states=True, returns every scanned port with its state
    (open/closed/filtered) - useful for a full port-state map rather than
    just "what's open".
    """
    port_list = list(ports)
    if randomize:
        random.shuffle(port_list)

    all_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_single_port, target_ip, p, timeout): p
            for p in port_list
        }
        for future in as_completed(futures):
            port, state, service, banner, extra = future.result()
            all_results.append({
                "port": port,
                "state": state,
                "service": service,
                "banner": banner or "",
                "extra": extra,
            })

    all_results.sort(key=lambda r: r["port"])
    if include_all_states:
        return all_results
    return [r for r in all_results if r["state"] == "open"]
