"""
discovery.py - Host discovery ("ping sweep") and a crude OS guess.

Host discovery here uses TCP probes rather than ICMP, so it works
without root/admin privileges. OS guessing reads the TTL from a system
ping reply - a rough, easily-spoofed signal, not real fingerprinting.
Real fingerprinting reads dozens of TCP/IP stack quirks from raw
packets, which is a much deeper (and privileged) undertaking.
"""

import asyncio
import ipaddress
import platform


async def probe_host(ip, timeout, semaphore):
    async with semaphore:
        probe_ports = [80, 443, 22, 445]
        for port in probe_ports:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return ip, True
            except ConnectionRefusedError:
                # Connection refused means the host rejected it actively (it is up)
                return ip, True
            except Exception:
                continue
        return ip, False


async def async_discover_hosts(
    network_cidr,
    timeout=0.5,
    concurrency=500,
    progress_cb=None,
    result_cb=None,
    cancel_cb=None,
):
    """
    progress_cb(completed, total): called after each host is probed.
    result_cb(ip):                 called the instant a host is found UP.
    cancel_cb() -> bool:           polled between completions; cancels scan if True.
    """
    semaphore = asyncio.Semaphore(concurrency)
    net = ipaddress.ip_network(network_cidr, strict=False)
    candidates = [str(ip) for ip in net.hosts()]

    if not candidates:
        candidates = [str(net.network_address)]

    total = len(candidates)
    tasks = [asyncio.create_task(probe_host(ip, timeout, semaphore)) for ip in candidates]
    up_hosts = []
    completed = 0

    try:
        for coro in asyncio.as_completed(tasks):
            if cancel_cb and cancel_cb():
                break
            ip, is_up = await coro
            completed += 1
            if progress_cb:
                progress_cb(completed, total)
            if is_up:
                up_hosts.append(ip)
                if result_cb:
                    result_cb(ip)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    return sorted(up_hosts, key=lambda x: tuple(int(o) for o in x.split(".")))


def discover_hosts(
    network_cidr,
    timeout=0.5,
    concurrency=500,
    progress_cb=None,
    result_cb=None,
    cancel_cb=None,
):
    """Synchronous wrapper so callers don't need to manage the event loop themselves."""
    return asyncio.run(
        async_discover_hosts(
            network_cidr,
            timeout=timeout,
            concurrency=concurrency,
            progress_cb=progress_cb,
            result_cb=result_cb,
            cancel_cb=cancel_cb,
        )
    )


async def async_guess_os_by_ttl(ip):
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=3.0)
        output = stdout.decode("utf-8", errors="ignore").lower()

        ttl = None
        if "ttl" in output:
            for part in output.split():
                if part.startswith("ttl"):
                    try:
                        ttl = int(part.split("=")[-1])
                    except ValueError:
                        pass

        if ttl is None:
            return "Unknown (no ping reply)"
        if ttl <= 64:
            return f"Likely Linux/Unix/macOS (TTL={ttl})"
        elif ttl <= 128:
            return f"Likely Windows (TTL={ttl})"
        else:
            return f"Likely network device/router (TTL={ttl})"
    except Exception:
        return "Unknown (ping unavailable or blocked)"


def guess_os_by_ttl(ip):
    """Synchronous wrapper for OS guessing."""
    return asyncio.run(async_guess_os_by_ttl(ip))
