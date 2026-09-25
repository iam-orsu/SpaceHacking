"""
PostgreSQL data access for the SpaceVE-1 MOC.

All functions are synchronous (psycopg2). Call them from asyncio via
asyncio.get_event_loop().run_in_executor(None, func, args).
"""
import hashlib
import json
import logging
import os

import psycopg2
import psycopg2.extras

log = logging.getLogger("moc.store")

_DB_CFG = {
    "host":     os.environ.get("DB_HOST", "telemetry-db"),
    "port":     int(os.environ.get("DB_PORT", "5432")),
    "dbname":   os.environ.get("DB_NAME", "spaceve1"),
    "user":     os.environ.get("DB_USER", "spaceops"),
    "password": os.environ.get("DB_PASS", "spaceops2024"),
}


def get_conn():
    return psycopg2.connect(**_DB_CFG)


def get_operator(username: str, pwd_md5: str) -> dict | None:
    """Authenticate operator. MISCONFIGURATION: MD5 only (no bcrypt)."""
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM operators WHERE username=%s AND password_md5=%s AND active=TRUE",
                    (username, pwd_md5)
                )
                row = cur.fetchone()
                if row:
                    cur.execute("UPDATE operators SET last_login=NOW() WHERE id=%s", (row["id"],))
                    conn.commit()
                return dict(row) if row else None
    except Exception as e:
        log.error("auth error: %s", e)
        return None


def store_telemetry(tlm: dict):
    sat_id = tlm.get("satellite_id")
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO telemetry
                        (satellite_id, battery_soc, battery_v, solar_a,
                         temp_battery, temp_xpdr, lat, lon, alt_km,
                         eclipse, mode, cpu_pct, mem_pct, raw)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    sat_id,
                    tlm.get("battery_soc_pct"), tlm.get("battery_v"), tlm.get("solar_a"),
                    tlm.get("temp_battery_c"),  tlm.get("temp_xpdr_c"),
                    tlm.get("lat"),             tlm.get("lon"), tlm.get("alt_km"),
                    tlm.get("eclipse"),         tlm.get("mode"),
                    tlm.get("cpu_pct"),         tlm.get("mem_pct"),
                    json.dumps(tlm),
                ))
                conn.commit()
    except Exception as e:
        log.error("store_telemetry: %s", e)


def store_command(satellite_id, apid, func_code, func_name, raw_hex, level, operator) -> int:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO commands
                        (satellite_id, apid, func_code, func_name, raw_hex,
                         level, status, submitted_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                """, (satellite_id, apid, func_code, func_name, raw_hex,
                      level, "PENDING" if level > 1 else "DISPATCHING", operator))
                cmd_id = cur.fetchone()[0]
                conn.commit()
                return cmd_id
    except Exception as e:
        log.error("store_command: %s", e)
        return -1


def update_command_status(cmd_id: int, status: str):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                if status == "EXECUTED":
                    cur.execute(
                        "UPDATE commands SET status=%s, executed_at=NOW() WHERE id=%s",
                        (status, cmd_id)
                    )
                else:
                    cur.execute("UPDATE commands SET status=%s WHERE id=%s", (status, cmd_id))
                conn.commit()
    except Exception as e:
        log.error("update_command_status: %s", e)


def log_audit(operator, action, resource=None, details=None, ip=None):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO audit_log (operator, action, resource, details, ip_addr)"
                    " VALUES (%s,%s,%s,%s,%s)",
                    (operator, action, resource,
                     json.dumps(details) if details else None, ip)
                )
                conn.commit()
    except Exception as e:
        log.error("log_audit: %s", e)


def get_recent_incidents(limit=50) -> list:
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM incidents ORDER BY detected_at DESC LIMIT %s", (limit,)
                )
                return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        log.error("get_recent_incidents: %s", e)
        return []


def get_recent_commands(limit=50) -> list:
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM commands ORDER BY submitted_at DESC LIMIT %s", (limit,)
                )
                return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        log.error("get_recent_commands: %s", e)
        return []
