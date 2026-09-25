"""
models.py — Database access layer for SpaceVE-1 MOC
Uses psycopg2 directly (no ORM). Parameterized queries throughout.
INTENTIONAL MISCONFIGURATION: one query uses string formatting (SQL injection target).
"""

import hashlib
import json
import os
import time

import psycopg2
import psycopg2.extras

DB_CONFIG = {
    "host":     os.environ.get("DB_HOST", "192.168.62.20"),
    "port":     int(os.environ.get("DB_PORT", 5432)),
    "dbname":   os.environ.get("DB_NAME", "spaceve1"),
    "user":     os.environ.get("DB_USER", "spaceops"),
    "password": os.environ.get("DB_PASS", "spaceops2024"),
}


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def get_operator(username: str, password: str):
    """
    Authenticate operator.
    MISCONFIGURATION: uses MD5 (not bcrypt/argon2).
    """
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM operators WHERE username=%s AND password_md5=%s AND active=TRUE",
                (username, pwd_hash)
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE operators SET last_login=NOW() WHERE id=%s",
                    (row["id"],)
                )
                conn.commit()
            return dict(row) if row else None


def get_operator_by_username(username: str):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM operators WHERE username=%s", (username,))
            r = cur.fetchone()
            return dict(r) if r else None


def list_operators():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, username, role, clearance, full_name, email, active, last_login FROM operators ORDER BY id")
            return [dict(r) for r in cur.fetchall()]


def create_operator(username, password, role, full_name, email, clearance="UNCLASSIFIED"):
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO operators (username, password_md5, role, clearance, full_name, email) VALUES (%s,%s,%s,%s,%s,%s)",
                (username, pwd_hash, role, clearance, full_name, email)
            )
            conn.commit()


def get_satellites():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM satellites ORDER BY name")
            return [dict(r) for r in cur.fetchall()]


def store_telemetry(tlm: dict):
    """Store one telemetry frame from a satellite."""
    sat_id = tlm.get("satellite_id", "UNKNOWN")
    power  = tlm.get("power", {})
    therm  = tlm.get("thermal", {})
    orb    = tlm.get("orbital", {})
    health = tlm.get("health", {})
    comms  = tlm.get("comms", {})
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO telemetry
                    (satellite_id, battery_soc, battery_v, solar_a, power_w,
                     temp_battery, temp_xpdr, temp_payload, lat, lon, alt_km,
                     eclipse, mode, cpu_pct, mem_pct, rssi_dbm, downlink_db, raw)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                sat_id,
                power.get("battery_soc_pct"),
                power.get("battery_v"),
                power.get("solar_current_a"),
                power.get("power_consumption_w"),
                therm.get("battery_c"),
                therm.get("transponder_c"),
                therm.get("payload_c"),
                orb.get("lat"),
                orb.get("lon"),
                orb.get("alt_km"),
                orb.get("eclipse"),
                tlm.get("mode"),
                health.get("cpu_load_pct"),
                health.get("memory_used_pct"),
                comms.get("uplink_rssi_dbm"),
                comms.get("downlink_margin_db"),
                json.dumps(tlm),
            ))
            conn.commit()


def get_latest_telemetry(satellite_id: str = None):
    """Return latest telemetry per satellite (or for one)."""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if satellite_id:
                cur.execute("""
                    SELECT raw FROM telemetry
                    WHERE satellite_id=%s
                    ORDER BY ts DESC LIMIT 1
                """, (satellite_id,))
                r = cur.fetchone()
                return r["raw"] if r else None
            else:
                cur.execute("""
                    SELECT DISTINCT ON (satellite_id)
                        satellite_id, raw
                    FROM telemetry
                    ORDER BY satellite_id, ts DESC
                """)
                return {r["satellite_id"]: r["raw"] for r in cur.fetchall()}


def get_telemetry_history(satellite_id: str, limit: int = 120):
    """Return recent telemetry rows for plotting."""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ts, battery_soc, battery_v, temp_battery, temp_xpdr,
                       temp_payload, cpu_pct, mem_pct, lat, lon, eclipse, mode
                FROM telemetry
                WHERE satellite_id=%s
                ORDER BY ts DESC LIMIT %s
            """, (satellite_id, limit))
            return [dict(r) for r in cur.fetchall()]


def get_telemetry_history_search(satellite_id: str, search: str):
    """
    INTENTIONAL MISCONFIGURATION: uses string formatting in SQL.
    SQL injection target for training.
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Unsafe: user-controlled `search` goes directly into query
            query = f"SELECT ts, mode, battery_soc FROM telemetry WHERE satellite_id='{satellite_id}' AND mode LIKE '%{search}%' ORDER BY ts DESC LIMIT 50"
            cur.execute(query)
            return [dict(r) for r in cur.fetchall()]


def submit_command(satellite_id, apid, func_code, func_name, raw_hex, level, operator, notes=""):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO commands
                    (satellite_id, apid, func_code, func_name, raw_hex, level, status, submitted_by, notes)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
            """, (satellite_id, apid, func_code, func_name, raw_hex, level, "PENDING", operator, notes))
            cmd_id = cur.fetchone()[0]
            conn.commit()
            # Level 1 commands auto-approve
            if level == 1:
                cur.execute(
                    "UPDATE commands SET status='APPROVED', approved_at=NOW() WHERE id=%s",
                    (cmd_id,)
                )
                conn.commit()
            return cmd_id


def approve_command(cmd_id: int, approver: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE commands SET status='APPROVED', approved_at=NOW() WHERE id=%s AND status='PENDING'",
                (cmd_id,)
            )
            cur.execute(
                "INSERT INTO command_approvals (command_id, approved_by) VALUES (%s,%s)",
                (cmd_id, approver)
            )
            conn.commit()


def get_commands(satellite_id: str = None, limit: int = 50):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if satellite_id:
                cur.execute("""
                    SELECT * FROM commands WHERE satellite_id=%s ORDER BY submitted_at DESC LIMIT %s
                """, (satellite_id, limit))
            else:
                cur.execute("SELECT * FROM commands ORDER BY submitted_at DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]


def get_pending_commands():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM commands WHERE status='PENDING' ORDER BY submitted_at ASC"
            )
            return [dict(r) for r in cur.fetchall()]


def log_audit(operator: str, action: str, resource: str = None, details: dict = None, ip: str = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (operator, action, resource, details, ip_addr) VALUES (%s,%s,%s,%s,%s)",
                (operator, action, resource, json.dumps(details) if details else None, ip)
            )
            conn.commit()


def get_audit_log(limit: int = 200):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]


def create_incident(severity, inc_type, description, source_ip=None, satellite_id=None, operator_id=None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO incidents (severity, type, description, source_ip, satellite_id, operator_id)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (severity, inc_type, description, source_ip, satellite_id, operator_id))
            conn.commit()


def get_incidents(limit: int = 100):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM incidents ORDER BY detected_at DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]
