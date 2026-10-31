"""
ports.py - Timing templates and port-list helpers, shared by every engine.
"""

# Timing templates, like nmap's -T0 (paranoid) through -T5 (insane).
# Each maps to (per-connection timeout in seconds, worker/concurrency count).
TIMING_TEMPLATES = {
    0: (5.0, 1),     # paranoid    - one at a time, very patient
    1: (3.0, 5),     # sneaky
    2: (2.0, 20),    # polite
    3: (1.0, 100),   # normal (default)
    4: (0.5, 300),   # aggressive
    5: (0.2, 500),   # insane
}

# A trimmed "top ports" list. Real nmap ships ~1000; this covers the
# services you'll actually run into most often.
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 587, 631, 636, 993,
    995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1900, 2049, 2082, 2083,
    2181, 2375, 2483, 2484, 27017, 27018, 3128, 3268, 3306, 3389, 3690, 4444,
    4500, 5000, 5060, 5222, 5432, 5601, 5672, 5900, 5985, 5986, 6379, 6443,
    6660, 6667, 7001, 8000, 8008, 8009, 8080, 8081, 8088, 8161, 8443, 8888,
    9000, 9042, 9092, 9200, 9418, 9999, 10000, 11211, 27015, 32400, 49152,
]


def parse_ports(port_spec):
    """Accepts 'top100', '22,80,443', '1-1024', or a mix like '22,80,1000-1010'."""
    if port_spec == "top100":
        return list(TOP_100_PORTS)

    ports = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)


# Named scan types, mirroring the common nmap-style workflows.
# Each maps to a port spec and a default engine; both can still be
# overridden explicitly by the caller (CLI flags or web form).
SCAN_TYPES = {
    "basic": {
        "ports": "top100",
        "engine": "connect",
        "label": "Basic Scan",
        "description": "Checks common TCP ports. (This project ships a curated "
                        "~100-port list; nmap's own default list covers ~1000.)",
    },
    "single": {
        "ports": "80",
        "engine": "connect",
        "label": "Single Port Scan",
        "description": "Checks only port 80.",
    },
    "all": {
        "ports": "1-65535",
        "engine": "async",
        "label": "All Ports Scan",
        "description": "Checks every port from 1 to 65535. Defaults to the async "
                        "engine since scanning the full range with threads alone "
                        "is much slower.",
    },
    "udp": {
        "ports": "top100",
        "engine": "udp",
        "label": "UDP Scan",
        "description": "Checks UDP ports instead of TCP. UDP has no handshake, "
                        "so results include an 'open|filtered' state for "
                        "no-response ports - this is inherent to UDP, not a bug.",
    },
}
