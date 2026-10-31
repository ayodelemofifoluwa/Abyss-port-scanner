"""
db.py - Scan history storage and differential comparison using SQLite.

Every scan gets logged with its open ports. This lets you answer the
genuinely useful question: "what changed on this host since last time?"
"""

import sqlite3
import time

DB_PATH = "scan_history.db"


def init_db(path=DB_PATH):
    conn = sqlite3.connect(path)
    # Concurrency: WAL lets reads and a writer coexist; busy_timeout avoids
    # "database is locked" when the web dashboard and a scan write at once.
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            resolved_ip TEXT,
            timestamp REAL,
            duration REAL,
            engine TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            banner TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            message TEXT,
            timestamp REAL
        )
    """)
    # Lightweight migrations: add columns to existing DBs if they're missing.
    # This is what makes it safe to drop this file into a repo that already
    # has a scan_history.db from before these columns existed.
    for ddl in (
        "ALTER TABLE results ADD COLUMN state TEXT DEFAULT 'open'",
        "ALTER TABLE results ADD COLUMN protocol TEXT DEFAULT 'tcp'",
    ):
        try:
            conn.execute(ddl)
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    return conn


def save_contact_message(conn, name, email, message):
    conn.execute(
        "INSERT INTO contact_messages (name, email, message, timestamp) VALUES (?, ?, ?, ?)",
        (name, email, message, time.time()),
    )
    conn.commit()


def list_contact_messages(conn):
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, message, timestamp FROM contact_messages ORDER BY timestamp DESC")
    return [
        {"id": row[0], "name": row[1], "email": row[2], "message": row[3], "timestamp": row[4]}
        for row in cur.fetchall()
    ]


def save_scan(conn, target, resolved_ip, duration, engine, open_ports):
    """open_ports: list of dicts with 'port', 'service', 'banner', and
    optionally 'state'/'protocol' keys."""
    default_proto = "udp" if engine == "udp" else "tcp"
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, resolved_ip, timestamp, duration, engine) VALUES (?, ?, ?, ?, ?)",
        (target, resolved_ip, time.time(), duration, engine),
    )
    scan_id = cur.lastrowid
    for r in open_ports:
        cur.execute(
            "INSERT INTO results (scan_id, port, service, banner, state, protocol) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                r["port"],
                r.get("service", "unknown"),
                r.get("banner", ""),
                r.get("state", "open"),
                r.get("protocol", default_proto),
            ),
        )
    conn.commit()
    return scan_id


def get_scan_ports(conn, scan_id):
    cur = conn.cursor()
    cur.execute(
        "SELECT port, service, banner, state, protocol FROM results WHERE scan_id=?",
        (scan_id,),
    )
    return {
        row[0]: {
            "service": row[1],
            "banner": row[2],
            "state": row[3] or "open",
            "protocol": row[4] or "tcp",
        }
        for row in cur.fetchall()
    }


def get_scan_meta(conn, scan_id):
    """Row metadata for a single scan, or None. Used by the export endpoints."""
    cur = conn.cursor()
    cur.execute(
        "SELECT target, resolved_ip, engine, timestamp, duration FROM scans WHERE id=?",
        (scan_id,),
    )
    row = cur.fetchone()
    if not row:
        return None
    return {
        "target": row[0],
        "resolved_ip": row[1],
        "engine": row[2],
        "timestamp": row[3],
        "duration": row[4],
    }


def scan_exists(conn, scan_id):
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,))
    return cur.fetchone() is not None


def list_scans(conn, target=None):
    cur = conn.cursor()
    if target:
        cur.execute(
            "SELECT id, target, resolved_ip, timestamp, duration, engine "
            "FROM scans WHERE target=? ORDER BY timestamp DESC",
            (target,),
        )
    else:
        cur.execute(
            "SELECT id, target, resolved_ip, timestamp, duration, engine "
            "FROM scans ORDER BY timestamp DESC"
        )
    return cur.fetchall()


def diff_scans(conn, scan_id_old, scan_id_new):
    """Returns dict with 'opened', 'closed', 'unchanged' port maps."""
    old_ports = get_scan_ports(conn, scan_id_old)
    new_ports = get_scan_ports(conn, scan_id_new)

    opened = {p: new_ports[p] for p in new_ports if p not in old_ports}
    closed = {p: old_ports[p] for p in old_ports if p not in new_ports}
    unchanged = {p: new_ports[p] for p in new_ports if p in old_ports}

    return {"opened": opened, "closed": closed, "unchanged": unchanged}


def get_analytics(conn):
    """
    Real aggregate data from scan history - every number here comes from
    an actual query, not a placeholder. Used to power the Analytics page's
    charts and stat cards.
    """
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM scans")
    total_scans = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM results")
    total_findings = cur.fetchone()[0]

    cur.execute("SELECT AVG(duration) FROM scans")
    avg_row = cur.fetchone()[0]
    avg_duration = round(avg_row, 3) if avg_row else 0.0

    cur.execute(
        "SELECT service, COUNT(*) as c FROM results "
        "GROUP BY service ORDER BY c DESC LIMIT 10"
    )
    top_services = [{"service": row[0] or "unknown", "count": row[1]} for row in cur.fetchall()]

    cur.execute(
        "SELECT port, COUNT(*) as c FROM results "
        "GROUP BY port ORDER BY c DESC LIMIT 15"
    )
    port_distribution = [{"port": row[0], "count": row[1]} for row in cur.fetchall()]

    cur.execute("SELECT timestamp, duration, engine FROM scans ORDER BY timestamp ASC")
    duration_timeline = [
        {"timestamp": row[0], "duration": row[1], "engine": row[2]} for row in cur.fetchall()
    ]

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "avg_duration": avg_duration,
        "top_services": top_services,
        "port_distribution": port_distribution,
        "duration_timeline": duration_timeline,
    }


def clear_history(conn):
    """Deletes all scan history and results. Irreversible - used by the
    Settings page's 'Clear Scan History' action, which confirms first."""
    conn.execute("DELETE FROM results")
    conn.execute("DELETE FROM scans")
    conn.commit()
