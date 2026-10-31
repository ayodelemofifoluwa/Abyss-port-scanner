"""
engine_async.py - asyncio-based scan core.

Why this matters: the threaded engine spawns one OS thread per in-flight
connection attempt. Threads carry real memory/scheduling overhead, so a
few hundred concurrent threads is a practical ceiling. asyncio runs
everything on a single thread with an event loop, switching to the next
task the instant one is waiting on I/O -- so a few thousand concurrent
probes is realistic with a fraction of the memory.
"""

import asyncio
import random
import socket
import ssl


async def probe_port(target_ip, port, timeout, semaphore, delay=0.0, jitter=0.0):
    async with semaphore:
        # WAF/IDS evasion: sleep before probing if delay/jitter are set.
        if delay > 0 or jitter > 0:
            import random as _random
            wait = delay + (_random.random() * jitter)
            await asyncio.sleep(wait)

        try:
            service_name = socket.getservbyport(port, "tcp")
        except OSError:
            service_name = "unknown"

        try:
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = asyncio.open_connection(
                    target_ip, port, ssl=ctx, server_hostname=target_ip
                )
            else:
                conn = asyncio.open_connection(target_ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            return port, False, service_name, None

        banner = None
        try:
            if port in (80, 8080, 8000, 8888):
                writer.write(
                    b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode("utf-8", errors="ignore").split("\r\n")[0].strip()
        except asyncio.TimeoutError:
            banner = "(open, no banner)"
        except Exception:
            banner = "(open, banner read failed)"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return port, True, service_name, banner


async def async_scan(
    target_ip,
    ports,
    timeout=1.0,
    concurrency=500,
    progress_cb=None,
    result_cb=None,
    cancel_cb=None,
    delay=0.0,
    jitter=0.0,
):
    """
    progress_cb(completed, total): called after each port finishes.
    result_cb(entry_dict):         called the instant an OPEN port is found,
                                   so a web frontend can stream results live
                                   instead of waiting for the whole scan.
    cancel_cb() -> bool:           polled between completions; if it returns
                                   True, remaining tasks are cancelled and the
                                   scan returns what it has so far.
    delay/jitter:                  WAF/IDS evasion - delay is a fixed wait
                                   (seconds) before each probe; jitter adds
                                   a random 0..jitter seconds on top, so
                                   probes don't land at regular intervals.
    """
    semaphore = asyncio.Semaphore(concurrency)
    port_list = list(ports)
    random.shuffle(port_list)
    total = len(port_list)

    tasks = [
        asyncio.create_task(probe_port(target_ip, p, timeout, semaphore, delay=delay, jitter=jitter))
        for p in port_list
    ]
    results = []
    completed = 0

    try:
        for coro in asyncio.as_completed(tasks):
            if cancel_cb and cancel_cb():
                break
            port, is_open, service, banner = await coro
            completed += 1
            if progress_cb:
                progress_cb(completed, total)
            if is_open:
                entry = {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "state": "open",
                    "protocol": "tcp",
                }
                results.append(entry)
                if result_cb:
                    result_cb(entry)  # live push
    finally:
        # Ensure no tasks are left running when we exit early (cancellation).
        for t in tasks:
            if not t.done():
                t.cancel()
        # Let cancellations settle without raising.
        await asyncio.gather(*tasks, return_exceptions=True)

    return sorted(results, key=lambda r: r["port"])


def run_async_scan(
    target_ip,
    ports,
    timeout=1.0,
    concurrency=500,
    progress_cb=None,
    result_cb=None,
    cancel_cb=None,
    delay=0.0,
    jitter=0.0,
):
    """Synchronous wrapper so callers don't need to manage the event loop themselves."""
    return asyncio.run(
        async_scan(
            target_ip,
            ports,
            timeout=timeout,
            concurrency=concurrency,
            progress_cb=progress_cb,
            result_cb=result_cb,
            cancel_cb=cancel_cb,
            delay=delay,
            jitter=jitter,
        )
    )
