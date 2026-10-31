#!/usr/bin/env python3
"""
abyss.web.app - The Abyss dashboard.

Run with:
    python3 -m abyss web
    (from the project root, the folder that contains the abyss/ package)

Then open http://127.0.0.1:5000
"""

import collections
import ipaddress
import json
import logging
import os
import random
import socket
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, jsonify, Response, session

from ..core import ports as ports_mod
from ..core import engine_connect
from ..core import engine_async
from ..core import engine_udp
from ..core import discovery
from ..storage import db

app = Flask(__name__)
app.secret_key = os.environ.get("ABYSS_SECRET_KEY", "dev-only-change-this-secret-key")
SERVER_START_TIME = time.time()

# Basic password gate for the Admin Inbox. This is NOT enterprise-grade
# auth - no rate limiting, no hashing, just a plain comparison behind a
# session cookie. Fine for "don't let a random visitor read my contact
# form on my local machine"; not fine for a real public deployment.
# Set your own via: export ABYSS_ADMIN_PASSWORD="something-only-you-know"
ADMIN_PASSWORD = os.environ.get("ABYSS_ADMIN_PASSWORD", "admin123")

# ---------------------------------------------------------------------------
# Structured logging with an in-memory ring buffer, exposed via /api/logs.
# ---------------------------------------------------------------------------
LOG_BUFFER = collections.deque(maxlen=300)


class RingBufferHandler(logging.Handler):
    def emit(self, record):
        LOG_BUFFER.append({
            "timestamp": time.time(),
            "level": record.levelname,
            "message": self.format(record),
        })


_log_handler = RingBufferHandler()
_log_handler.setFormatter(logging.Formatter("%(message)s"))
abyss_logger = logging.getLogger("abyss")
abyss_logger.setLevel(logging.INFO)
abyss_logger.addHandler(_log_handler)

# ---------------------------------------------------------------------------
# Rate limiting - optional. Flask-Limiter isn't a hard dependency (this
# project stays installable with just Flask), so this degrades gracefully:
# if it's not installed, @limiter.limit(...) below becomes a harmless no-op
# decorator instead of crashing the app.
# ---------------------------------------------------------------------------
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(get_remote_address, app=app, default_limits=[])
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False

    class _NoOpLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator

    limiter = _NoOpLimiter()

# In-memory cache for geoip lookups, keyed by IP. Avoids hammering
# ip-api.com's free tier with repeated lookups of the same address.
GEOIP_CACHE = {}

# In-memory scan state, keyed by scan_id. Fine for local/single-user use;
# swap for Redis or a proper table if this ever needs to survive restarts
# or serve more than one person at a time.
SCANS = {}
SCANS_LOCK = threading.Lock()

# Web dashboard intentionally supports connect/async/udp only.
# The syn engine needs root/admin privileges, which a browser session
# shouldn't casually be granted - that one stays CLI-only.
WEB_ENGINES = ("connect", "async", "udp")


def run_scan_job(scan_id, target, port_spec, timing, engine):
    with SCANS_LOCK:
        SCANS[scan_id]["status"] = "running"

    try:
        timeout, workers = ports_mod.TIMING_TEMPLATES[timing]
        port_list = ports_mod.parse_ports(port_spec)

        try:
            resolved_ip = socket.gethostbyname(target)
        except Exception:
            with SCANS_LOCK:
                SCANS[scan_id]["status"] = "error"
                SCANS[scan_id]["error"] = f"Could not resolve target: {target}"
            return

        with SCANS_LOCK:
            SCANS[scan_id]["resolved_ip"] = resolved_ip
            SCANS[scan_id]["total_ports"] = len(port_list)

        start = time.time()

        def push_progress(done, total):
            with SCANS_LOCK:
                SCANS[scan_id]["scanned"] = done

        if engine == "async":
            def push_result(entry):
                with SCANS_LOCK:
                    SCANS[scan_id]["open_ports"].append(entry)

            open_ports = engine_async.run_async_scan(
                resolved_ip, port_list, timeout=timeout,
                concurrency=workers * 5, progress_cb=push_progress, result_cb=push_result,
            )
            for r in open_ports:
                r.setdefault("state", "open")

        elif engine == "udp":
            shuffled = list(port_list)
            random.shuffle(shuffled)
            completed = 0
            open_ports = []
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(engine_udp.udp_scan_port, resolved_ip, p, timeout): p
                    for p in shuffled
                }
                for future in as_completed(futures):
                    completed += 1
                    result = future.result()
                    with SCANS_LOCK:
                        SCANS[scan_id]["scanned"] = completed
                        if result["state"] in ("open", "open|filtered"):
                            SCANS[scan_id]["open_ports"].append(result)
                            open_ports.append(result)

        else:  # connect
            shuffled = list(port_list)
            random.shuffle(shuffled)
            completed = 0
            open_ports = []
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(engine_connect.scan_single_port, resolved_ip, p, timeout): p
                    for p in shuffled
                }
                for future in as_completed(futures):
                    completed += 1
                    port, state, service, banner, extra = future.result()
                    with SCANS_LOCK:
                        SCANS[scan_id]["scanned"] = completed
                        if state == "open":
                            entry = {"port": port, "state": state, "service": service,
                                      "banner": banner or ""}
                            SCANS[scan_id]["open_ports"].append(entry)
                            open_ports.append(entry)

        duration = time.time() - start

        conn = db.init_db()
        saved_id = db.save_scan(conn, target, resolved_ip, duration, engine, open_ports)

        with SCANS_LOCK:
            SCANS[scan_id]["status"] = "done"
            SCANS[scan_id]["duration"] = round(duration, 2)
            SCANS[scan_id]["open_ports"].sort(key=lambda r: r["port"])
            SCANS[scan_id]["saved_scan_id"] = saved_id

        abyss_logger.info(
            f"Scan complete: target={target} resolved={resolved_ip} "
            f"open_ports={len(open_ports)} duration={round(duration, 2)}s saved_as=#{saved_id}"
        )

    except Exception as e:
        with SCANS_LOCK:
            SCANS[scan_id]["status"] = "error"
            SCANS[scan_id]["error"] = str(e)
        abyss_logger.error(f"Scan failed: target={target} error={e}")


@app.route("/")
def index():
    return render_template("index.html", scan_types=ports_mod.SCAN_TYPES)


@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "Abyss",
        "short_name": "Abyss",
        "description": "TCP/UDP port scanning dashboard",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#09090B",
        "theme_color": "#09090B",
        "icons": [
            {"src": "/static/icon.svg", "sizes": "128x128", "type": "image/svg+xml"}
        ],
    })


@app.route("/stats")
def stats():
    """
    Real aggregate numbers for the landing hero's stat cards - deliberately
    NOT mockup/vanity numbers. Pulled straight from the scan history database.
    """
    conn = db.init_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scans")
    total_scans = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT port) FROM results")
    distinct_open_ports = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM results")
    total_open_findings = cur.fetchone()[0]

    uptime_seconds = int(time.time() - SERVER_START_TIME)
    days, rem = divmod(uptime_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    with SCANS_LOCK:
        active_scans = sum(1 for s in SCANS.values() if s["status"] in ("queued", "running"))

    return jsonify({
        "total_scans": total_scans,
        "distinct_open_ports": distinct_open_ports,
        "total_open_findings": total_open_findings,
        "active_scans": active_scans,
        "uptime": f"{days}d {hours}h {minutes}m",
    })


@app.route("/contact", methods=["POST"])
def contact():
    """
    Stores an inquiry locally. There's no SMTP/email service configured here,
    so this does NOT send a real email - it saves the message so you (the
    site owner) can read it later. Wire in real email sending (e.g. via
    Flask-Mail plus your own SMTP credentials) if you want it delivered
    to an inbox instead.
    """
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    message = (data.get("message") or "").strip()

    if not name or not email or not message:
        return jsonify({"error": "Name, email, and message are all required."}), 400

    conn = db.init_db()
    db.save_contact_message(conn, name, email, message)
    return jsonify({"ok": True})


# Alias so the route naming matches the spec exactly. Same behavior as /contact.
@app.route("/api/contact", methods=["POST"])
def api_contact():
    return contact()


def get_local_ip():
    """
    Best-effort local network IP of the machine running this server.
    Note: this is NOT the same as trying to get a *browser client's*
    local IP - modern browsers deliberately block that for privacy
    (the old WebRTC ICE-candidate trick mostly no longer works). Since
    this server runs on your own machine, reporting the server host's
    own local IP is the honest, working equivalent for a locally-run tool.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # doesn't actually send anything, just picks a route
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


@app.route("/network-identity")
def network_identity():
    return jsonify({"local_ip": get_local_ip()})


@app.route("/discover-subnet", methods=["POST"])
@limiter.limit("5/minute")
def discover_subnet():
    """
    Opt-in only - triggered by the 'Scan My Subnet' button, never run
    automatically on page load. Discovers live hosts on the /24 containing
    the server's own local IP, reusing the same TCP-probe discovery logic
    the CLI's --discover flag uses.
    """
    local_ip = get_local_ip()
    try:
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except ValueError:
        return jsonify({"error": "Could not determine local subnet"}), 400

    hosts = discovery.discover_hosts(str(network), timeout=0.4, concurrency=100)

    # Best-effort gateway detection: the conventional .1 address on most
    # consumer/enterprise networks.
    gateway_ip = str(network.network_address + 1)

    def classify_device(ip):
        """
        Heuristic device classification by last-octet pattern - NOT real
        fingerprinting. Real device ID would need ARP + MAC OUI lookup,
        which needs raw-socket privileges this engine doesn't have.
        """
        try:
            last = int(ip.split(".")[-1])
        except (ValueError, IndexError):
            return "device"
        if last in (1, 254):
            return "router"
        if last % 2 == 0:
            return "phone"
        if last % 3 == 0:
            return "pc"
        if last % 5 == 0:
            return "desktop"
        return "tablet"

    devices = [
        {
            "ip": h,
            "type": classify_device(h),
            "is_gateway": h == gateway_ip,
            "is_self": h == local_ip,
        }
        for h in hosts
    ]

    return jsonify({
        "subnet": str(network),
        "hosts_up": hosts,
        "gateway_ip": gateway_ip,
        "local_ip": local_ip,
        "devices": devices,
    })


@app.route("/geoip/<ip>")
def geoip(ip):
    """
    Server-side proxy to ip-api.com (free, no API key needed for basic use).
    Proxied server-side rather than called from the browser to avoid
    CORS complications and to keep the client code simple.

    Cached in-memory by IP so repeated lookups (e.g. rescanning the same
    target) don't hammer ip-api.com's free tier unnecessarily.

    NOTE: this genuinely needs internet access to work. It could not be
    live-tested in the sandbox this was built in (no network egress there) -
    the response shape below matches ip-api.com's documented JSON format,
    but test it for real once you're running this on your own machine.
    """
    if ip in GEOIP_CACHE:
        cached = dict(GEOIP_CACHE[ip])
        cached["_cache_hit"] = True
        return jsonify(cached)

    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        GEOIP_CACHE[ip] = data
        return jsonify(data)
    except Exception as e:
        return jsonify({"status": "fail", "message": str(e)}), 502


@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    password = data.get("password", "")
    if password == ADMIN_PASSWORD:
        session["admin"] = True
        return jsonify({"ok": True})
    return jsonify({"error": "Incorrect password"}), 401


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin", None)
    return jsonify({"ok": True})


@app.route("/api/messages")
def api_messages():
    if not session.get("admin"):
        return jsonify({"error": "Not authenticated"}), 401
    conn = db.init_db()
    return jsonify(db.list_contact_messages(conn))


@app.route("/sw.js")
def service_worker():
    # Minimal service worker: caches the app shell so the dashboard's own
    # page (not scan results, which are live network data) still opens
    # when offline. Registered at the root so its scope covers the whole app.
    js = """
const CACHE_NAME = 'abyss-shell-v1';
const SHELL_URLS = ['/'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_URLS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  // Only cache-serve the app shell itself; always hit the network for
  // /scan, /status, /history, /diff, /export - those are live data.
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.pathname !== '/') {
    return;
  }
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
"""
    return Response(js, mimetype="application/javascript")


@app.route("/scan-types")
def scan_types():
    return jsonify(ports_mod.SCAN_TYPES)


@app.route("/scan", methods=["POST"])
@limiter.limit("5/minute")
def start_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type")
    port_spec = data.get("ports", "").strip()
    timing = int(data.get("timing", 3))
    engine = data.get("engine", "connect")

    if not target:
        return jsonify({"error": "Target is required"}), 400

    if scan_type and scan_type in ports_mod.SCAN_TYPES:
        preset = ports_mod.SCAN_TYPES[scan_type]
        port_spec = port_spec or preset["ports"]
        engine = engine or preset["engine"]
    if not port_spec:
        port_spec = "top100"

    if engine not in WEB_ENGINES:
        return jsonify({"error": f"Web dashboard supports engines: {', '.join(WEB_ENGINES)}. "
                                  f"Use the CLI for --engine syn (needs root)."}), 400

    abyss_logger.info(f"Scan requested: target={target} engine={engine} ports={port_spec}")

    scan_id = str(uuid.uuid4())
    with SCANS_LOCK:
        SCANS[scan_id] = {
            "target": target,
            "status": "queued",
            "scanned": 0,
            "total_ports": 0,
            "open_ports": [],
            "duration": None,
            "error": None,
            "saved_scan_id": None,
        }

    thread = threading.Thread(
        target=run_scan_job, args=(scan_id, target, port_spec, timing, engine), daemon=True
    )
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/status/<scan_id>")
def scan_status(scan_id):
    with SCANS_LOCK:
        state = SCANS.get(scan_id)
        if not state:
            return jsonify({"error": "Unknown scan_id"}), 404
        return jsonify(dict(state))


@app.route("/history")
def history():
    target = request.args.get("target", "").strip()
    conn = db.init_db()
    rows = db.list_scans(conn, target or None)
    result = [
        {"id": r[0], "target": r[1], "ip": r[2], "timestamp": r[3], "duration": r[4], "engine": r[5]}
        for r in rows
    ]
    return jsonify(result)


@app.route("/diff/<int:old_id>/<int:new_id>")
def diff(old_id, new_id):
    conn = db.init_db()
    result = db.diff_scans(conn, old_id, new_id)
    return jsonify(result)


@app.route("/analytics")
def analytics():
    conn = db.init_db()
    return jsonify(db.get_analytics(conn))


@app.route("/history", methods=["DELETE"])
def clear_history():
    conn = db.init_db()
    db.clear_history(conn)
    return jsonify({"ok": True})


@app.route("/export/<int:scan_id>")
def export_scan(scan_id):
    """Download a past scan's results as a JSON file."""
    conn = db.init_db()
    if not db.scan_exists(conn, scan_id):
        return jsonify({"error": "No scan found with that ID"}), 404

    port_map = db.get_scan_ports(conn, scan_id)
    payload = {
        "scan_id": scan_id,
        "results": [
            {"port": port, "service": info["service"], "banner": info["banner"]}
            for port, info in sorted(port_map.items())
        ],
    }
    import json
    body = json.dumps(payload, indent=2)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=abyss_scan_{scan_id}.json"},
    )


@app.route("/api/logs")
def api_logs():
    """Recent structured log entries, newest last - feeds the frontend's terminal/log panel."""
    return jsonify(list(LOG_BUFFER))


@app.route("/healthz")
def healthz():
    """
    Basic health check: uptime, how many scans are actively running/queued,
    and whether SQLite is reachable. Not authenticated - it's meant to be
    hit by monitoring tooling or the frontend's own connectivity check,
    and it doesn't return anything sensitive.
    """
    uptime_seconds = int(time.time() - SERVER_START_TIME)

    with SCANS_LOCK:
        active_threads = sum(1 for s in SCANS.values() if s["status"] in ("queued", "running"))

    try:
        conn = db.init_db()
        conn.execute("SELECT 1")
        sqlite_ok = True
    except Exception:
        sqlite_ok = False

    return jsonify({
        "status": "ok" if sqlite_ok else "degraded",
        "uptime_seconds": uptime_seconds,
        "active_scan_threads": active_threads,
        "sqlite_ok": sqlite_ok,
        "rate_limiting_enabled": RATE_LIMITING_AVAILABLE,
    })


def run_web():
    # use_reloader=False: the auto-reloader restarts the whole process on
    # every file change, and on some Windows setups that restart can get
    # interrupted mid-import and crash. Not needed for normal use anyway -
    # just restart manually after editing code.
    app.run(debug=True, port=5000, use_reloader=False)


if __name__ == "__main__":
    run_web()
