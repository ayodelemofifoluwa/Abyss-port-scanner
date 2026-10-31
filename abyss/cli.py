#!/usr/bin/env python3
"""
abyss.cli - Command-line interface for the Abyss port scanner.

Run with:
    python3 -m abyss cli <target> [options]
    (from the project root, the folder that contains the abyss/ package)

Quick scan-type presets (mirrors the common scanning workflows):
    python3 -m abyss cli TARGET --scan-type basic    # top ~100 TCP ports
    python3 -m abyss cli TARGET --scan-type single   # just port 80
    python3 -m abyss cli TARGET --scan-type all       # every port, 1-65535
    python3 -m abyss cli TARGET --scan-type udp       # UDP instead of TCP

Full examples:
    python3 -m abyss cli 192.168.1.10 -p 1-1024
    python3 -m abyss cli 192.168.1.0/24 -p top100 --discover -T4
    python3 -m abyss cli scanme.nmap.org -p 22,80,443 --engine async -oJ out.json
    python3 -m abyss cli scanme.nmap.org --history
    python3 -m abyss cli scanme.nmap.org --diff 3 7
    python3 -m abyss cli scanme.nmap.org --advisories

Engines:
    connect (default) - threaded TCP connect scan, no special privileges
    async             - asyncio scan, much higher concurrency, no special privileges
    udp               - UDP scan, no special privileges (results are inherently
                        more ambiguous than TCP - see --scan-type udp help)
    syn               - raw SYN scan via scapy, requires root/admin + scapy installed

Port states:
    open     - a service is actively accepting connections
    closed   - the port responded, but nothing is listening
    filtered - no reply at all; usually a firewall silently dropped the probe
    (UDP-only) open|filtered - no reply, which for UDP could mean either -
               this ambiguity is inherent to UDP, not a scanning bug

NOT implemented (and why):
    - Real OS fingerprinting and raw SYN scanning both trace back to the
      same limitation: Python's socket module can't forge or inspect raw
      packets on its own. --engine syn reaches for scapy to cross that
      boundary; OS detection here stays a crude TTL guess.
    - Automated credential brute-forcing (testing default logins against
      SSH/FTP/RDP) is deliberately NOT included. That's actively attempting
      to log into systems rather than observing them - a different category
      of tool. Dedicated, purpose-built tools exist for that under proper
      authorization; Abyss stays a recon/reporting tool.
"""

import argparse
import ipaddress
import socket
import sys
import time

from .core import ports as ports_mod
from .core import engine_connect
from .core import engine_async
from .core import engine_udp
from .core import discovery
from .core import output
from .core import advisories
from .storage import db

try:
    from .core import engine_syn
    SYN_ENGINE_AVAILABLE = engine_syn.SCAPY_AVAILABLE
except ImportError:
    SYN_ENGINE_AVAILABLE = False
    engine_syn = None


def build_parser():
    parser = argparse.ArgumentParser(
        prog="abyss cli",
        description="Abyss - an educational, nmap-inspired TCP/UDP port scanner",
    )
    parser.add_argument("target", help="IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("--scan-type", choices=list(ports_mod.SCAN_TYPES.keys()),
                         help="Preset: basic (top ~100 TCP) | single (port 80) | "
                              "all (1-65535) | udp (UDP scan). "
                              "Sets --ports and --engine defaults; either can "
                              "still be overridden explicitly.")
    parser.add_argument("-p", "--ports", default=None,
                         help="Ports: '22,80,443' or '1-1024' or 'top100'. "
                              "Defaults to 'top100', or to whatever --scan-type implies.")
    parser.add_argument("-T", "--timing", type=int, default=3, choices=range(0, 6),
                         help="Timing template 0 (paranoid) - 5 (insane), default 3")
    parser.add_argument("--delay", type=float, default=0.0,
                         help="Fixed delay in seconds before each probe (async engine only). "
                              "WAF/IDS evasion - spreads probes out over time.")
    parser.add_argument("--jitter", type=float, default=0.0,
                         help="Random extra delay 0..jitter seconds added on top of --delay "
                              "(async engine only), so probes don't land at regular intervals.")
    parser.add_argument("--discover", action="store_true",
                         help="Run host discovery first if target is a CIDR range")
    parser.add_argument("--os-guess", action="store_true",
                         help="Attempt a crude TTL-based OS guess per host")
    parser.add_argument("--no-random", action="store_true",
                         help="Scan ports in order instead of shuffled")
    parser.add_argument("--show-all-states", action="store_true",
                         help="Show closed/filtered ports too, not just open ones")
    parser.add_argument("--advisories", action="store_true",
                         help="For each open port's banner, print links to search "
                              "NVD / CVE Details / Exploit-DB for known issues. "
                              "This generates search queries only - it does not "
                              "maintain or claim a local vulnerability database.")
    parser.add_argument("-oJ", "--output-json", help="Write results as JSON to this path")
    parser.add_argument("-oG", "--output-grep", help="Write results in greppable format")
    parser.add_argument("--engine", choices=["connect", "async", "udp", "syn"], default=None,
                         help="connect = threaded TCP connect; async = asyncio, higher "
                              "concurrency; udp = UDP scan; syn = raw SYN scan via scapy, "
                              "requires root/admin. Defaults to 'connect', or to whatever "
                              "--scan-type implies.")
    parser.add_argument("--no-save", action="store_true",
                         help="Don't log this scan to the local SQLite history database")
    parser.add_argument("--history", action="store_true",
                         help="List past scans for this target and exit (no scan run)")
    parser.add_argument("--diff", nargs=2, metavar=("OLD_ID", "NEW_ID"),
                         help="Compare two past scan IDs from the history database and exit")
    return parser


def handle_history(args):
    conn = db.init_db()
    rows = db.list_scans(conn, args.target)
    if not rows:
        print(f"[*] No scan history found for '{args.target}'.")
        return
    print(f"{'ID':<5}{'Target':<25}{'IP':<16}{'Timestamp':<22}{'Duration(s)':<12}Engine")
    for scan_id, target, ip, ts, dur, engine in rows:
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        dur_str = f"{dur:.2f}"
        print(f"{scan_id:<5}{target:<25}{ip:<16}{ts_str:<22}{dur_str:<12}{engine}")


def handle_diff(args):
    conn = db.init_db()
    old_id, new_id = int(args.diff[0]), int(args.diff[1])
    result = db.diff_scans(conn, old_id, new_id)
    print(f"[*] Diff between scan #{old_id} and scan #{new_id}")
    if result["opened"]:
        print("\n  Newly OPEN ports:")
        for port, info in sorted(result["opened"].items()):
            print(f"    + {port}/{info['service']}  {info['banner']}")
    if result["closed"]:
        print("\n  Ports now CLOSED (were open before):")
        for port, info in sorted(result["closed"].items()):
            print(f"    - {port}/{info['service']}")
    if not result["opened"] and not result["closed"]:
        print("\n  No changes detected between these two scans.")


def resolve_targets(args, workers):
    is_cidr = "/" in args.target
    if is_cidr:
        if args.discover:
            return discovery.discover_hosts(args.target, timeout=0.5, concurrency=workers)
        return [str(ip) for ip in ipaddress.ip_network(args.target, strict=False).hosts()]

    try:
        resolved_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve target: {args.target}")
        sys.exit(1)
    return [resolved_ip]


def print_result_row(r):
    state = r.get("state", "open")
    marker = {"open": "[+]", "open|filtered": "[?]"}.get(state, "[-]")
    banner = r.get("banner", "") or ""
    extra = r.get("extra", "") or ""
    print(f"    {marker} {r['port']:<6} {r['service']:<12} {state:<15} {banner}{extra}")


def run_engine_for_host(args, ip, ports, timeout, workers, engine):
    show_all = args.show_all_states

    if engine == "connect":
        results = engine_connect.run_scan_on_host(
            ip, ports, timeout, workers, randomize=not args.no_random,
            include_all_states=show_all,
        )
    elif engine == "async":
        # async engine only reports open ports currently (no filtered/closed
        # distinction - that would need a lower-level rewrite of the probe).
        results = engine_async.run_async_scan(
            ip, ports, timeout=timeout, concurrency=workers * 5,
            delay=args.delay, jitter=args.jitter,
        )
        for r in results:
            r.setdefault("state", "open")
    elif engine == "udp":
        results = engine_udp.run_udp_scan(
            ip, ports, timeout=timeout, max_workers=workers,
            randomize=not args.no_random, include_all_states=show_all,
        )
    else:  # syn
        results = engine_syn.syn_scan_range(ip, ports, timeout=timeout)
        for r in results:
            r.setdefault("banner", "")
        if not show_all:
            results = [r for r in results if r["state"] == "open"]

    for r in results:
        print_result_row(r)

    return results


def print_advisories(open_ports):
    if not open_ports:
        return
    print("\n  Advisory search links (query-based, not a local vulnerability database):")
    for r in open_ports:
        banner = r.get("banner", "")
        service = r.get("service", "unknown")
        links = advisories.get_advisory_links(service, banner)
        print(f"    Port {r['port']} ({service}) — search: \"{links['query_used']}\"")
        print(f"      NVD:         {links['nvd']}")
        print(f"      CVE Details: {links['cve_details']}")
        print(f"      Exploit-DB:  {links['exploit_db']}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.history:
        handle_history(args)
        return

    if args.diff:
        handle_diff(args)
        return

    # Resolve scan-type preset into concrete ports/engine, unless the user
    # explicitly overrode either with -p / --engine.
    preset = ports_mod.SCAN_TYPES.get(args.scan_type) if args.scan_type else None
    port_spec = args.ports or (preset["ports"] if preset else "top100")
    engine = args.engine or (preset["engine"] if preset else "connect")

    if engine == "syn":
        if not SYN_ENGINE_AVAILABLE:
            print("[!] --engine syn requires scapy. Install it with: pip install scapy")
            sys.exit(1)
        if not engine_syn.has_raw_socket_privileges():
            print("[!] --engine syn requires raw socket privileges.")
            print("    Linux/Mac: run with sudo")
            print("    Windows:   run as Administrator (and install Npcap: https://npcap.com)")
            sys.exit(1)

    timeout, workers = ports_mod.TIMING_TEMPLATES[args.timing]
    port_list = ports_mod.parse_ports(port_spec)
    targets = resolve_targets(args, workers)

    if not targets:
        print("[!] No live hosts found.")
        return

    all_results = []
    grand_start = time.time()
    conn = None if args.no_save else db.init_db()

    for ip in targets:
        print(f"\n[*] Scanning {ip} — {len(port_list)} ports — engine={engine} "
              f"timing T{args.timing} (timeout={timeout}s, workers={workers})")

        if args.os_guess:
            print(f"    [OS] {discovery.guess_os_by_ttl(ip)}")

        start = time.time()
        results = run_engine_for_host(args, ip, port_list, timeout, workers, engine)
        duration = time.time() - start

        open_ports = [r for r in results if r.get("state", "open") in ("open", "open|filtered")]
        print(f"    -> {len(open_ports)} open (or open|filtered) port(s) found in {duration:.2f}s")
        all_results.append({"host": ip, "open_ports": open_ports})

        if args.advisories:
            print_advisories(open_ports)

        if conn is not None:
            scan_id = db.save_scan(conn, args.target, ip, duration, engine, open_ports)
            print(f"    [i] Saved as scan #{scan_id} (compare later with: --diff {scan_id} <newer_id>)")

    total_duration = time.time() - grand_start
    print(f"\n[*] Full scan completed in {total_duration:.2f}s across {len(targets)} host(s).")

    if args.output_json:
        output.write_json(all_results, args.output_json)
    if args.output_grep:
        output.write_greppable(all_results, args.output_grep)


if __name__ == "__main__":
    main()
