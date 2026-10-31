"""
output.py - Result writers, mimicking nmap's -oN / -oX / -oG family.
"""

import json


def write_json(all_results, path):
    with open(path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"[*] JSON results written to {path}")


def write_greppable(all_results, path):
    with open(path, "w") as f:
        for host_entry in all_results:
            ip = host_entry["host"]
            ports_str = ", ".join(
                f'{r["port"]}/open/tcp//{r["service"]}//' for r in host_entry["open_ports"]
            )
            f.write(f"Host: {ip}\tPorts: {ports_str}\n")
    print(f"[*] Greppable results written to {path}")
