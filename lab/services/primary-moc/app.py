#!/usr/bin/env python3
"""
SpaceVE-1 Primary Mission Operations Center — Flask Application

All routes in one file. Run by entrypoint.sh.

Intentional misconfigurations (training targets):
  1. SECRET_KEY is hardcoded and weak (in env var)
  2. No CSRF protection on API endpoints
  3. /api/telemetry/latest accessible without auth
  4. Command level enforcement is advisory (client-controlled)
  5. Telemetry search endpoint has SQL injection
  6. No rate limiting on /login
  7. Error handler leaks stack traces in details field
  8. Admin user creation doesn't require MFA
"""

import json
import os
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from functools import wraps

import psycopg2
from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, session, url_for)

import models

# -----------------------------------------------------------------
# App configuration
# -----------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "spaceve1-weak-secret-key-2024")

MOC_ID      = os.environ.get("MOC_ID", "PRIMARY")
CMD_SAT_A   = os.environ.get("CMD_SAT_A", "192.168.61.100")
CMD_SAT_B   = os.environ.get("CMD_SAT_B", "192.168.61.101")
CMD_SAT_C   = os.environ.get("CMD_SAT_C", "192.168.61.102")
GS1_HOST    = os.environ.get("GS1_HOST", "192.168.61.20")
GS2_HOST    = os.environ.get("GS2_HOST", "192.168.61.21")

SAT_IPS = {
    "SpaceVE-1A": CMD_SAT_A,
    "SpaceVE-1B": CMD_SAT_B,
    "SpaceVE-1C": CMD_SAT_C,
}

SAT_APIDS = {
    "SpaceVE-1A": 0x200,
    "SpaceVE-1B": 0x201,
    "SpaceVE-1C": 0x202,
}

FUNC_CODES = {
    "NOP":              (0x00, 1),
    "CAMERA_ON":        (0x01, 2),
    "CAMERA_OFF":       (0x02, 2),
    "DOWNLINK_ENABLE":  (0x03, 2),
    "DOWNLINK_DISABLE": (0x04, 2),
    "MEMORY_DUMP":      (0x05, 2),
    "REBOOT":           (0x06, 3),
    "SAFING_MODE":      (0x07, 3),
    "NOMINAL_MODE":     (0x08, 1),
    "PAYLOAD_POWER_OFF":(0x0A, 3),
}

# In-memory latest telemetry cache (updated by TLM receiver thread)
tlm_cache: dict = {}
tlm_lock = threading.Lock()

# -----------------------------------------------------------------
# CCSDS packet builder
# -----------------------------------------------------------------

def build_ccsds(apid: int, func_code: int, user_data: bytes = b"", seq: int = 0) -> bytes:
    word0 = (0b000 << 13) | (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1 = (0b11 << 14) | (seq & 0x3FFF)
    data_len = 1 + len(user_data)
    primary = struct.pack(">HHH", word0, word1, data_len)
    sec0 = (func_code & 0x7F) << 1
    ck = 0xFF ^ sec0
    for b in user_data:
        ck ^= b
    return primary + bytes([sec0, ck]) + user_data


def send_ccsds_to_satellite(satellite_id: str, func_code: int) -> bool:
    ip = SAT_IPS.get(satellite_id)
    apid = SAT_APIDS.get(satellite_id, 0x200)
    if not ip:
        return False
    pkt = build_ccsds(apid, func_code)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(pkt, (ip, 1234))
        s.close()
        return True
    except Exception:
        return False

# -----------------------------------------------------------------
# Telemetry receiver (UDP listener)
# -----------------------------------------------------------------

def tlm_receiver():
    """Listen for JSON telemetry from satellites on UDP 5000."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = int(os.environ.get("TLM_LISTEN_PORT", 5000))
    sock.bind(("0.0.0.0", port))
    sock.settimeout(3.0)
    print(f"[MOC] Telemetry receiver on UDP {port}")

    store_counter = {}  # throttle DB writes to 1 per 5 sec per satellite

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            tlm = json.loads(data.decode("utf-8"))
            sat_id = tlm.get("satellite_id", "UNKNOWN")
            with tlm_lock:
                tlm_cache[sat_id] = tlm

            # Write to DB at most every 5 seconds per satellite
            now = time.time()
            if now - store_counter.get(sat_id, 0) >= 5:
                store_counter[sat_id] = now
                try:
                    models.store_telemetry(tlm)
                except Exception:
                    pass
        except socket.timeout:
            pass
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"[MOC] TLM receiver error: {e}")

# -----------------------------------------------------------------
# Auth helpers
# -----------------------------------------------------------------

ROLE_LEVELS = {
    "TELEMETRY_OPS": 1,
    "COMMAND_OPS":   2,
    "PAYLOAD_OPS":   3,
    "SAFETY_OPS":    4,
    "ADMIN":         5,
}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "operator" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(min_role: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "operator" not in session:
                return redirect(url_for("login"))
            role = session.get("role", "TELEMETRY_OPS")
            if ROLE_LEVELS.get(role, 0) < ROLE_LEVELS.get(min_role, 99):
                return jsonify(error="Insufficient clearance"), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def current_op():
    return session.get("operator", "ANONYMOUS")


def current_role():
    return session.get("role", "TELEMETRY_OPS")

# -----------------------------------------------------------------
# Routes: Auth
# -----------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # MISCONFIGURATION: no rate limiting here
        op = models.get_operator(username, password)
        if op:
            session["operator"]  = op["username"]
            session["role"]      = op["role"]
            session["clearance"] = op["clearance"]
            session["full_name"] = op.get("full_name", username)
            models.log_audit(username, "LOGIN", "session", {"ip": request.remote_addr}, request.remote_addr)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if "operator" in session:
        models.log_audit(session["operator"], "LOGOUT", "session")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return redirect(url_for("dashboard"))

# -----------------------------------------------------------------
# Routes: Pages
# -----------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    satellites = models.get_satellites()
    with tlm_lock:
        cache = dict(tlm_cache)
    recent_cmds  = models.get_commands(limit=10)
    recent_inc   = models.get_incidents(limit=5)
    pending_cmds = models.get_pending_commands()
    return render_template("dashboard.html",
        satellites=satellites,
        tlm_cache=cache,
        recent_cmds=recent_cmds,
        recent_inc=recent_inc,
        pending_cmds=pending_cmds,
        moc_id=MOC_ID,
    )


@app.route("/c2/telemetry")
@login_required
def page_telemetry():
    satellites = models.get_satellites()
    sat_id = request.args.get("sat", "SpaceVE-1A")
    history = models.get_telemetry_history(sat_id, limit=120)
    search  = request.args.get("search", "")
    search_results = []
    if search:
        try:
            # Uses the SQL-injectable function intentionally
            search_results = models.get_telemetry_history_search(sat_id, search)
        except Exception as e:
            flash(f"Query error: {e}", "error")
    return render_template("telemetry.html",
        satellites=satellites,
        selected_sat=sat_id,
        history=history,
        search=search,
        search_results=search_results,
    )


@app.route("/c2/command", methods=["GET"])
@login_required
def page_command():
    satellites = models.get_satellites()
    sat_id = request.args.get("sat", "SpaceVE-1A")
    cmds = models.get_commands(sat_id, limit=30)
    pending = models.get_pending_commands()
    return render_template("command.html",
        satellites=satellites,
        selected_sat=sat_id,
        commands=cmds,
        pending=pending,
        func_codes=FUNC_CODES,
        role=current_role(),
    )


@app.route("/c2/mission")
@login_required
def page_mission():
    satellites = models.get_satellites()
    with tlm_lock:
        cache = dict(tlm_cache)
    return render_template("mission.html",
        satellites=satellites,
        tlm_cache=cache,
    )


@app.route("/c2/network")
@login_required
def page_network():
    return render_template("network.html",
        gs1=GS1_HOST, gs2=GS2_HOST,
        sat_a=CMD_SAT_A, sat_b=CMD_SAT_B, sat_c=CMD_SAT_C,
    )


@app.route("/incident-response")
@login_required
def page_incident():
    incidents = models.get_incidents(limit=100)
    audit     = models.get_audit_log(limit=100)
    return render_template("incident.html",
        incidents=incidents,
        audit=audit,
    )


@app.route("/admin")
@role_required("ADMIN")
def page_admin():
    operators = models.list_operators()
    audit     = models.get_audit_log(limit=50)
    return render_template("admin.html",
        operators=operators,
        audit=audit,
    )


@app.route("/admin/users/create", methods=["POST"])
@role_required("ADMIN")
def admin_create_user():
    # MISCONFIGURATION: no MFA, no second confirmation required
    username  = request.form["username"]
    password  = request.form["password"]
    role      = request.form["role"]
    full_name = request.form.get("full_name", "")
    email     = request.form.get("email", "")
    try:
        models.create_operator(username, password, role, full_name, email)
        models.log_audit(current_op(), "CREATE_USER", username, {"role": role}, request.remote_addr)
        flash(f"Operator {username} created", "success")
    except Exception as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("page_admin"))

# -----------------------------------------------------------------
# Routes: API (JSON)
# -----------------------------------------------------------------

@app.route("/api/health")
def api_health():
    return jsonify(status="ok", moc=MOC_ID, ts=time.time())


@app.route("/api/telemetry/latest")
def api_tlm_latest():
    # MISCONFIGURATION: no auth required — "for monitoring dashboards"
    with tlm_lock:
        data = {k: v for k, v in tlm_cache.items()}
    return jsonify(data)


@app.route("/api/telemetry/<satellite_id>")
@login_required
def api_tlm_sat(satellite_id):
    limit = int(request.args.get("limit", 60))
    rows  = models.get_telemetry_history(satellite_id, limit)
    return jsonify(rows)


@app.route("/api/satellites")
@login_required
def api_satellites():
    sats = models.get_satellites()
    with tlm_lock:
        cache = dict(tlm_cache)
    result = []
    for s in sats:
        name = s["name"]
        latest = cache.get(name, {})
        s["latest_tlm"] = latest
        s["in_contact"] = latest.get("comms", {}).get("in_contact_with", [])
        result.append(s)
    return jsonify(result)


@app.route("/api/commands/pending")
@login_required
def api_pending():
    return jsonify(models.get_pending_commands())


@app.route("/api/commands/send", methods=["POST"])
@login_required
def api_send_command():
    """
    Submit a command for execution.
    MISCONFIGURATION: no CSRF token checked.
    MISCONFIGURATION: level is taken from request body (client-controlled).
    """
    data = request.get_json(force=True)
    satellite_id = data.get("satellite_id", "SpaceVE-1A")
    func_name    = data.get("func_name", "NOP")
    notes        = data.get("notes", "")

    if func_name not in FUNC_CODES:
        return jsonify(error=f"Unknown command: {func_name}"), 400

    fc, default_level = FUNC_CODES[func_name]
    # MISCONFIGURATION: client can override the command level
    level = int(data.get("level", default_level))

    apid = SAT_APIDS.get(satellite_id, 0x200)
    pkt  = build_ccsds(apid, fc)
    raw_hex = pkt.hex()

    cmd_id = models.submit_command(
        satellite_id, apid, fc, func_name, raw_hex, level, current_op(), notes
    )

    models.log_audit(
        current_op(), "SUBMIT_CMD", satellite_id,
        {"cmd_id": cmd_id, "func": func_name, "level": level},
        request.remote_addr
    )

    # If approved (level 1 or already auto-approved), execute immediately
    cmd_record = models.get_commands(satellite_id, limit=1)
    if cmd_record and cmd_record[0]["status"] == "APPROVED":
        ok = send_ccsds_to_satellite(satellite_id, fc)
        if ok:
            import psycopg2
            with models.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE commands SET status='EXECUTED', executed_at=NOW() WHERE id=%s", (cmd_id,))
                    conn.commit()

    return jsonify(cmd_id=cmd_id, status="PENDING" if level > 1 else "APPROVED", raw_hex=raw_hex)


@app.route("/api/commands/<int:cmd_id>/approve", methods=["POST"])
@login_required
def api_approve_command(cmd_id):
    """
    Approve a pending command.
    MISCONFIGURATION: only one approval required (should be two for Level 3).
    Any authenticated user can approve (should require SAFETY_OPS or higher).
    """
    models.approve_command(cmd_id, current_op())
    # Find the command and execute it
    with models.get_conn() as conn:
        with conn.cursor(cursor_factory=__import__("psycopg2.extras", fromlist=["RealDictCursor"]).RealDictCursor) as cur:
            cur.execute("SELECT * FROM commands WHERE id=%s", (cmd_id,))
            cmd = cur.fetchone()
    if cmd:
        satellite_id = cmd["satellite_id"]
        fc = cmd["func_code"]
        ok = send_ccsds_to_satellite(satellite_id, fc)
        if ok:
            with models.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE commands SET status='EXECUTED', executed_at=NOW() WHERE id=%s", (cmd_id,))
                    conn.commit()
        models.log_audit(current_op(), "APPROVE_CMD", satellite_id,
                         {"cmd_id": cmd_id, "func": cmd["func_name"]}, request.remote_addr)
        return jsonify(status="EXECUTED" if ok else "APPROVED", cmd_id=cmd_id)
    return jsonify(error="Command not found"), 404


@app.route("/api/commands/raw", methods=["POST"])
@login_required
def api_raw_command():
    """
    Send a raw CCSDS packet hex string directly to a satellite.
    MISCONFIGURATION: no command level check, no approval workflow.
    Authenticated users can bypass the entire approval chain.
    """
    data = request.get_json(force=True)
    satellite_id = data.get("satellite_id", "SpaceVE-1A")
    raw_hex = data.get("hex", "").replace(" ", "")
    ip = SAT_IPS.get(satellite_id)
    if not ip or not raw_hex:
        return jsonify(error="Bad request"), 400
    try:
        pkt = bytes.fromhex(raw_hex)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(pkt, (ip, 1234))
        s.close()
        models.log_audit(current_op(), "RAW_CMD", satellite_id,
                         {"hex": raw_hex[:32]}, request.remote_addr)
        return jsonify(status="sent", bytes=len(pkt))
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.route("/api/incidents")
@login_required
def api_incidents():
    return jsonify(models.get_incidents(50))


@app.route("/api/orbital/<satellite_id>")
@login_required
def api_orbital(satellite_id):
    with tlm_lock:
        tlm = tlm_cache.get(satellite_id, {})
    orb = tlm.get("orbital", {})
    windows = tlm.get("contact_windows", [])
    return jsonify(orbital=orb, contact_windows=windows)


@app.route("/api/network/status")
@login_required
def api_network():
    def check(host, port, proto="tcp"):
        if proto == "tcp":
            try:
                s = socket.create_connection((host, port), timeout=1)
                s.close()
                return "CONNECTED"
            except Exception:
                return "UNREACHABLE"
        return "UNKNOWN"

    return jsonify({
        "primary_moc":    "SELF",
        "backup_moc":     check("192.168.63.11", 5001),
        "telemetry_db":   check("192.168.62.20", 5432),
        "ground_station_alpha": check(GS1_HOST, 4820),
        "ground_station_beta":  check(GS2_HOST, 4820),
        "satellite_a":    check(CMD_SAT_A, 1234, "udp"),
        "satellite_b":    check(CMD_SAT_B, 1234, "udp"),
        "satellite_c":    check(CMD_SAT_C, 1234, "udp"),
        "incident_response": check("192.168.63.30", 6000),
        "prometheus":     check("192.168.63.40", 9090),
        "grafana":        check("192.168.63.41", 3000),
    })


@app.route("/api/audit")
@role_required("SAFETY_OPS")
def api_audit():
    return jsonify(models.get_audit_log(200))

# -----------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return jsonify(error="Forbidden", details=str(e)), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("base.html"), 404


@app.errorhandler(500)
def server_error(e):
    # MISCONFIGURATION: returns stack trace details
    import traceback
    return jsonify(error="Internal server error", details=traceback.format_exc()), 500

# -----------------------------------------------------------------
# Main
# -----------------------------------------------------------------

if __name__ == "__main__":
    # Start telemetry receiver in background
    t = threading.Thread(target=tlm_receiver, daemon=True, name="tlm-receiver")
    t.start()

    print(f"[MOC-{MOC_ID}] Web interface starting on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
