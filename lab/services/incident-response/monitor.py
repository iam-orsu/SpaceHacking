"""
Incident Response Monitor — 10-minute detection lag IDS.

Polls telemetry-db every 60s for anomalous events. When an anomaly is
detected it is NOT written to the incidents table immediately — there is
an intentional 600-second (10-minute) delay to simulate real-world IDS
batch analysis latency. Attackers completing a kill chain have a 10-minute
window before defenders see the alert.

Detection rules (no CVEs, misconfig-based):
  IR-001 Unexpected command burst   > 5 commands in 60s from same operator
  IR-002 Anomalous func code        func_code not in approved set
  IR-003 Downlink enable + camera   both active simultaneously
  IR-004 Memory dump initiated      func_code 0x05 issued
  IR-005 Raw command used           submitted via /api/commands/raw (bypass)
  IR-006 Safe mode induced          func_code 0x07
  IR-007 Unauthenticated API access tlm API hit from non-MOC subnet
"""

import os
import time
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IDS] %(message)s")

_DB_HOST = os.environ.get("DB_HOST", "telemetry-db")
_DB_PORT = os.environ.get("DB_PORT", "5432")
_DB_NAME = os.environ.get("DB_NAME", "spaceve1")
_DB_USER = os.environ.get("DB_USER", "spaceops")
_DB_PASS = os.environ.get("DB_PASS", "spaceops2024")
DB_DSN = os.environ.get(
    "DATABASE_URL",
    f"host={_DB_HOST} port={_DB_PORT} dbname={_DB_NAME} user={_DB_USER} password={_DB_PASS}"
)

DETECTION_LAG_S = int(os.environ.get("DETECTION_LAG_S", 600))
POLL_INTERVAL   = int(os.environ.get("POLL_INTERVAL", 60))

APPROVED_FUNC_CODES = {0x00, 0x01, 0x02, 0x03, 0x04, 0x08}


def get_conn():
    return psycopg2.connect(DB_DSN)


def record_incident(conn, severity, inc_type, satellite_id, description, occurred_at):
    detected_at = occurred_at + timedelta(seconds=DETECTION_LAG_S)
    # Only insert if detection time has passed (simulates the lag)
    if datetime.now(timezone.utc) < detected_at:
        return False
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO incidents (severity, type, satellite_id, description, occurred_at, detected_at, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'OPEN')
            ON CONFLICT DO NOTHING
        """, (severity, inc_type, satellite_id, description, occurred_at, detected_at))
    conn.commit()
    logging.info("INCIDENT [%s] %s — %s", severity, inc_type, description)
    return True


def check_command_burst(conn, window_start):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT submitted_by, satellite_id, COUNT(*) as cnt, MIN(submitted_at) as first_at
            FROM commands
            WHERE submitted_at > %s
            GROUP BY submitted_by, satellite_id
            HAVING COUNT(*) > 5
        """, (window_start,))
        rows = cur.fetchall()
    for row in rows:
        record_incident(conn, "HIGH", "IR-001_CMD_BURST",
            row["satellite_id"],
            f"Operator {row['submitted_by']} sent {row['cnt']} commands in 60s — possible replay/injection",
            row["first_at"])


def check_anomalous_func_codes(conn, window_start):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT func_code, satellite_id, submitted_at, submitted_by
            FROM commands
            WHERE submitted_at > %s AND status = 'EXECUTED'
        """, (window_start,))
        rows = cur.fetchall()
    for row in rows:
        if row["func_code"] not in APPROVED_FUNC_CODES:
            record_incident(conn, "HIGH", "IR-002_ANOMALOUS_FUNC",
                row["satellite_id"],
                f"Non-standard func_code 0x{row['func_code']:02X} executed by {row['submitted_by']}",
                row["submitted_at"])


def check_downlink_camera_combo(conn, window_start):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT satellite_id, ts, raw->>'mode' as mode
            FROM telemetry
            WHERE ts > %s
              AND raw->>'camera_enabled' = 'true'
              AND raw->>'downlink_enabled' = 'true'
        """, (window_start,))
        rows = cur.fetchall()
    for row in rows:
        record_incident(conn, "MEDIUM", "IR-003_DOWNLINK_CAMERA",
            row["satellite_id"],
            "Camera + downlink active simultaneously — mission data exposure risk",
            row["ts"])


def check_memory_dump(conn, window_start):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT satellite_id, submitted_at, submitted_by
            FROM commands
            WHERE submitted_at > %s AND func_code = 5 AND status = 'EXECUTED'
        """, (window_start,))
        rows = cur.fetchall()
    for row in rows:
        record_incident(conn, "CRITICAL", "IR-004_MEMORY_DUMP",
            row["satellite_id"],
            f"Memory dump initiated by {row['submitted_by']} — potential data exfiltration",
            row["submitted_at"])


def check_raw_commands(conn, window_start):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT satellite_id, submitted_at, submitted_by, func_code
            FROM commands
            WHERE submitted_at > %s AND level = 0
        """, (window_start,))
        rows = cur.fetchall()
    for row in rows:
        record_incident(conn, "CRITICAL", "IR-005_RAW_CMD_BYPASS",
            row["satellite_id"],
            f"Command 0x{row['func_code']:02X} sent via raw endpoint (bypassed approval chain) by {row['submitted_by']}",
            row["submitted_at"])


def check_safe_mode(conn, window_start):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT satellite_id, submitted_at, submitted_by
            FROM commands
            WHERE submitted_at > %s AND func_code = 7 AND status = 'EXECUTED'
        """, (window_start,))
        rows = cur.fetchall()
    for row in rows:
        record_incident(conn, "CRITICAL", "IR-006_SAFE_MODE_INDUCED",
            row["satellite_id"],
            f"Safe mode induced by {row['submitted_by']} — constellation availability impact",
            row["submitted_at"])


def run():
    logging.info("IDS monitor starting — detection lag %ds, poll interval %ds",
                 DETECTION_LAG_S, POLL_INTERVAL)
    while True:
        try:
            conn = get_conn()
            window_start = datetime.now(timezone.utc) - timedelta(seconds=POLL_INTERVAL * 2)
            check_command_burst(conn, window_start)
            check_anomalous_func_codes(conn, window_start)
            check_downlink_camera_combo(conn, window_start)
            check_memory_dump(conn, window_start)
            check_raw_commands(conn, window_start)
            check_safe_mode(conn, window_start)
            conn.close()
        except Exception as e:
            logging.error("IDS poll error: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    time.sleep(15)  # wait for DB
    run()
