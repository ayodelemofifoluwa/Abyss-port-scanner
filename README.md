# Abyss

An educational, nmap-inspired TCP/UDP port scanner with four scan engines, a
scan history database with differential comparison, advisory-link lookups,
and a full cyberpunk-styled web dashboard (3D interactive globe, live
terminal streaming, Plexus Sphere network topology, 4 themes, analytics
charts, an admin inbox, and more).

Pure Python backend, vanilla HTML/CSS/JS frontend — no build step, no
framework. Three.js and Chart.js load via CDN.

---

## Project Structure

```
abyss/                              <- repo root, run all commands from here
├── README.md                       <- this file
├── LICENSE                         MIT
├── SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md
├── .gitignore
├── .github/
│   ├── ISSUE_TEMPLATE/bug_report.md, feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
├── pyproject.toml                  pip-installable (console scripts: abyss-cli, abyss-web)
├── requirements.txt                flask (+ optional scapy, flask-limiter)
├── scan_history.db                 created automatically on first scan, gitignored
└── abyss/                          the Python package
    ├── __init__.py
    ├── __main__.py                 `python3 -m abyss <cli|web>` dispatcher
    ├── cli.py                      argparse entry point
    ├── core/
    │   ├── ports.py                timing templates (T0-T5), scan-type presets, port-spec parsing
    │   ├── engine_connect.py       threaded TCP connect scan (open/closed/filtered states)
    │   ├── engine_async.py         asyncio TCP scan + --delay/--jitter WAF evasion
    │   ├── engine_udp.py           UDP scan (open/closed/open|filtered)
    │   ├── engine_syn.py           raw SYN scan via scapy (root/admin required)
    │   ├── discovery.py            asyncio host discovery (ping sweep) + TTL-based OS guess
    │   ├── advisories.py           banner → NVD/CVE Details/Exploit-DB search-link generator
    │   └── output.py               JSON / greppable output writers
    ├── storage/
    │   └── db.py                   SQLite (WAL mode): scans, results, contact_messages
    └── web/
        ├── app.py                  Flask app - every route (see below)
        ├── static/icon.svg
        └── templates/
            └── index.html          the entire frontend - landing page + dashboard SPA
```

---

## Setup

```bash
git clone <your-repo-url>
cd abyss
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Optional extras:
```bash
pip install scapy          # only needed for --engine syn (raw SYN scanning)
pip install flask-limiter  # enables real rate limiting on /scan and /discover-subnet
                            # (the app runs fine without it - degrades gracefully to no limiting)
```

Optional environment variables:
```bash
export ABYSS_SECRET_KEY="something-random"               # Flask session signing
export ABYSS_ADMIN_PASSWORD="something-only-you-know"    # Admin Inbox gate (default: admin123)
```

---

## Running it

```bash
# CLI
python3 -m abyss cli scanme.nmap.org --scan-type basic

# Web dashboard
python3 -m abyss web
# -> http://127.0.0.1:5000
```

**Important**: always run via `python3 -m abyss web` and open the URL in a
browser — never double-click `index.html` directly. The page needs the Flask
server behind it for every single feature (scanning, history, the whole
dashboard) to work; opened as a bare file, you'll see nothing but a
"can't reach the server" banner.

---

## CLI Reference

```
python3 -m abyss cli <target> [options]

Scan configuration:
  --scan-type {basic,single,all,udp}   Preset ports+engine (overridable)
  -p, --ports PORTS          '22,80,443' | '1-1024' | 'top100' (default)
  -T, --timing {0-5}         Timing template, T0 paranoid .. T5 insane (default T3)
  --engine {connect,async,udp,syn}     Scan engine (default: connect)
  --delay SECONDS            Fixed delay before each probe (async engine only)
  --jitter SECONDS           Random extra delay 0..jitter on top of --delay (async only)
  --discover                 Host discovery first, if target is a CIDR
  --os-guess                 Crude TTL-based OS guess per host
  --no-random                Scan ports in order instead of shuffled
  --show-all-states          Show closed/filtered too, not just open

Reporting:
  --advisories               Print NVD/CVE Details/Exploit-DB search links per open port
  -oJ, --output-json PATH    Write results as JSON
  -oG, --output-grep PATH    Write results in greppable format

History:
  --no-save                  Don't log this scan to SQLite
  --history                  List past scans for this target and exit
  --diff OLD_ID NEW_ID        Compare two past scans and exit
```

**Port states:** `open` / `closed` / `filtered` (no reply, likely firewall-dropped)
/ `open|filtered` (UDP-only, genuinely ambiguous by protocol nature).

**Engines at a glance:**

| Engine | Privileges | Mechanism |
|---|---|---|
| `connect` | None | Full TCP handshake via `socket.connect_ex()`; distinguishes closed from filtered |
| `async` | None | Same handshake via `asyncio`, much higher concurrency; supports `--delay`/`--jitter` evasion |
| `udp` | None | Empty UDP datagram; refusal → closed, reply → open, silence → `open\|filtered` |
| `syn` | Root/admin + scapy | Raw SYN, reads reply flags, sends RST instead of completing handshake if open |

---

## Web Dashboard Routes (`app.py`)

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Renders the SPA shell |
| `/manifest.json`, `/sw.js` | GET | PWA manifest + service worker (app-shell caching only) |
| `/scan-types` | GET | Scan-type presets for the UI cards |
| `/scan` | POST | Starts a scan in a background thread, returns `scan_id` immediately |
| `/status/<scan_id>` | GET | Polled live for progress + streaming results |
| `/history` | GET / DELETE | List or clear scan history |
| `/diff/<old_id>/<new_id>` | GET | Port-level diff between two scans |
| `/export/<scan_id>` | GET | Download a past scan's results as JSON |
| `/stats`, `/analytics` | GET | Real aggregate numbers for the landing hero and Analytics page |
| `/contact`, `/api/contact` | POST | Saves a contact-form inquiry to SQLite |
| `/api/messages` | GET | Admin-only: lists saved contact messages |
| `/admin/login`, `/admin/logout` | POST | Session-based password gate for the inbox |
| `/network-identity` | GET | Server's own local IP |
| `/discover-subnet` | POST | Opt-in `/24` host discovery, with gateway detection and device-type heuristics |
| `/geoip/<ip>` | GET | Server-side proxy to ip-api.com, in-memory cached |
| `/api/logs` | GET | Recent structured log entries (ring buffer) |
| `/healthz` | GET | Uptime, active scan threads, SQLite health |

Web-supported engines: `connect`, `async`, `udp`. `syn` is CLI-only (needs root/admin).

---

## Frontend Feature Summary

- **Landing page**: interactive 3D globe (drag to rotate with inertia, scroll-wheel zoom, double-click reset), real stat cards (not mockup numbers), fade-in on load, cinematic fade/reposition/fade transition into the dashboard.
- **4 themes**: Dark (default), Light, Blue, Matrix — full palette swaps via CSS variables, persisted in localStorage.
- **Scan view**: scan-type preset cards, live-streaming results table with per-service icons and category badges, click-to-expand banners, copy-to-clipboard, a real-time terminal panel, an activity feed, GeoIP Target Telemetry with a text-scramble reveal animation, a port-convention-based Threat Rank badge (explicitly labeled as a heuristic, not a real vulnerability score).
- **History / Diff / Analytics**: full scan history with per-row export, two-scan port diffing, Chart.js charts (top services, port distribution, duration over time) built from real data.
- **3D Topology**: a per-scan target+ports graph, plus a separate dedicated "Plexus Sphere" ambient visualization (240 nodes, proximity-based connections via one shared buffer for performance).
- **Settings**: theme selector, reduced-motion override, irreversible "Clear All History" with confirmation.
- **Contact + Admin Inbox**: a real contact form saved to SQLite, and a password-gated admin view to read it (session-cookie auth — explicitly documented as not production-grade).
- **Network Identity bar**: persistent across every view (never hidden on mobile — reflows below content instead), shows public/local IP, a Subnet Radar with a real opt-in discovery scan, and an activity ticker built from real scan history.
- **Command palette** (Ctrl+K), **Web Audio synth** (hover blips, scan-start hum, no audio files), **CRT scanline overlay + glitch title effect**, **XSS-hardened** (every server-supplied string passes through a centralized `escapeHtml()` before touching the DOM).

---

## Known, Honestly-Stated Limitations

- `/geoip/<ip>` needs real internet access — built against ip-api.com's documented response shape but could not be live-verified in the sandbox this was built in (no network egress there).
- The SYN engine is sequential, not threaded (scapy's raw sockets don't parallelize as simply as regular sockets).
- OS fingerprinting is a crude TTL guess, not real stack fingerprinting.
- Subnet device-type classification (router/phone/PC/desktop/tablet) is a **heuristic based on the last IP octet**, not real device fingerprinting — real classification would need ARP + MAC OUI lookup, which needs raw-socket privileges this engine doesn't have. This labeling exists to make the Subnet Radar/Plexus visualization informative, not to claim actual device identification.
- No automated credential brute-forcing, and no local CVE database — both deliberate scope decisions (see below).
- No visual/browser testing was possible in the sandbox this was built in (no browser, no WebGL) — all three.js/CSS work was verified via JS syntax checking and logic review, not actual rendering.

---

## Deliberately Out of Scope

- **Automated credential brute-forcing** (testing default logins against SSH/FTP/RDP) — this is actively attempting unauthorized access rather than observing a system, a fundamentally different category of tool than a port scanner.
- **A local hand-maintained CVE/vulnerability database** — goes stale immediately and risks false confidence. The Advisories feature generates search links to NVD/CVE Details/Exploit-DB from detected banners instead.
- **Packet capture / full traffic analysis** — a genuinely different project with its own privilege model.

---

## Publishing to GitHub

```bash
cd abyss
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<your-username>/abyss.git
git push -u origin main
```

The repo already has `.gitignore` (excludes `venv/`, `scan_history.db`,
`__pycache__/`), `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`,
`CODE_OF_CONDUCT.md`, and GitHub issue/PR templates, so it'll look properly
maintained on arrival.

To install it as a real command after cloning:
```bash
pip install -e .
abyss-cli scanme.nmap.org --scan-type basic
abyss-web
```

---

## Deploying it — and why Vercel specifically is the wrong fit

I want to flag this clearly rather than give you instructions that quietly
fail: **Vercel's serverless model is fundamentally incompatible with how
this app works**, for three concrete reasons:

1. **Background threads.** Every scan runs in a background `threading.Thread`
   that the Flask app polls via `/status/<scan_id>`. Vercel's serverless
   functions are stateless and short-lived — they don't keep a thread alive
   between requests, so a scan started in one function invocation would be
   gone by the time the next request polls for it.
2. **SQLite persistence.** `scan_history.db` is a file on disk. Vercel's
   serverless filesystem is ephemeral — it resets on every cold start, so
   your scan history would vanish constantly, and WAL-mode SQLite (which
   this project uses for concurrency safety) needs a real persistent
   filesystem to work correctly at all.
3. **Raw socket / network scanning from a serverless function.** Vercel's
   platform doesn't support the kind of outbound raw socket and arbitrary
   port-connection behavior a scanner needs, and even if it did, you'd be
   port-scanning *from Vercel's infrastructure*, which is likely to violate
   their acceptable use policy.

**What actually fits this project:**

| Platform | Why it works |
|---|---|
| **A VPS** (DigitalOcean, Linode, a home server) | Full control, persistent filesystem, can run `python3 -m abyss web` directly behind nginx/gunicorn |
| **Railway** or **Render** | Support long-running Python processes with persistent disks, much closer to this app's actual needs |
| **Fly.io** | Persistent volumes for SQLite, long-running processes, reasonable free tier |
| **Your own machine** | The simplest option for personal/local use, which is what this project was built for in the first place |

If you specifically want *something* on Vercel — for example, just the
static landing page as a portfolio piece, with scanning disabled — that's
possible but would mean stripping out everything that needs a backend
(which is most of the app). Let me know if that's genuinely what you want
and I'll build a separate static-only variant rather than pretend the full
dashboard works there.

---

## Responsible Use

Only scan hosts you own or have explicit permission to test.
`scanme.nmap.org` is maintained by the nmap project specifically as a safe,
always-permitted target for practicing scans of any kind.
