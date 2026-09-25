#!/usr/bin/env python3
"""
SpaceVE-1 Mission Operations Center (MOC) — Lab Server

Web interface for commanding and monitoring the SpaceVE-1 satellite.
Runs on port 8080. Default credentials: admin / admin123.

Intentional misconfigurations modeled from real satellite incidents:
  - Default credentials never changed (NOAA 2014 pattern)
  - Command endpoint accepts requests from any source IP (Viasat pattern)
  - No CSRF protection on command forms
  - Telemetry stored in plaintext on disk
  - Session secret is hardcoded and weak

This is a training target. These are not bugs — they are design choices
that real small satellite programs make.
"""

import os
import json
import socket
import struct
import sqlite3
import threading
import time
from datetime import datetime
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, abort)

app = Flask(__name__)

# Intentionally weak secret key — never changed from environment default
app.secret_key = os.environ.get("SECRET_KEY", "spaceve1-dev-secret-do-not-use-in-prod")

# Configuration — intentionally uses weak defaults
MOC_USERNAME = os.environ.get("MOC_USERNAME", "admin")
MOC_PASSWORD = os.environ.get("MOC_PASSWORD", "admin123")
SATELLITE_IP = os.environ.get("SATELLITE_IP", "192.168.60.100")
SATELLITE_CMD_PORT = int(os.environ.get("SATELLITE_CMD_PORT", 1234))
TLM_LISTEN_PORT = int(os.environ.get("TLM_LISTEN_PORT", 1235))
DB_PATH = "/app/data/moc.db"

# Latest telemetry in memory
latest_tlm = {}
tlm_lock = threading.Lock()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT,
            source_ip TEXT,
            data TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS command_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issued_at TEXT,
            operator TEXT,
            source_ip TEXT,
            apid TEXT,
            func_code TEXT,
            command_name TEXT,
            raw_hex TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_command(operator: str, source_ip: str, apid: str,
                func_code: str, command_name: str, raw_hex: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO command_log
        (issued_at, operator, source_ip, apid, func_code, command_name, raw_hex)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (datetime.utcnow().isoformat(), operator, source_ip,
          apid, func_code, command_name, raw_hex))
    conn.commit()
    conn.close()


def send_raw_udp(payload: bytes) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (SATELLITE_IP, SATELLITE_CMD_PORT))
        s.close()
        return True
    except Exception as e:
        app.logger.error(f"Failed to send command: {e}")
        return False


def build_ccsds_cmd(apid: int, func_code: int, user_data: bytes = b"") -> bytes:
    """
    Build a CCSDS command packet.

    Primary Header (6 bytes):
      [0-1] Version=0, Type=1(cmd), SecHdrFlag=1, APID
      [2-3] SeqFlags=0b11, SeqCount=0
      [4-5] DataLength = len(secondary_header + user_data) - 1

    Secondary Header (2 bytes):
      [6]   FuncCode << 1
      [7]   Checksum

    Checksum: XOR of secondary header byte 0 and all user_data bytes,
              result stored so XOR of all sec_hdr+user_data bytes = 0xFF.
    """
    word0 = (0b000 << 13) | (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1 = (0b11 << 14) | 0
    data_len = 1 + len(user_data)  # secondary header (2 bytes) - 1

    primary = struct.pack(">HHH", word0, word1, data_len)

    sec_byte0 = (func_code & 0x7F) << 1
    checksum_input = bytes([sec_byte0]) + user_data
    cksum = 0xFF
    for b in checksum_input:
        cksum ^= b

    secondary = bytes([sec_byte0, cksum])
    return primary + secondary + user_data


def tlm_receiver():
    """Background thread: receives JSON telemetry from satellite on UDP 1235."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", TLM_LISTEN_PORT))
    sock.settimeout(1.0)
    app.logger.info(f"Telemetry receiver listening on UDP {TLM_LISTEN_PORT}")

    conn = sqlite3.connect(DB_PATH)
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            tlm = json.loads(data.decode("utf-8"))
            with tlm_lock:
                latest_tlm.update(tlm)
                latest_tlm["_received_at"] = datetime.utcnow().isoformat()
                latest_tlm["_source_ip"] = addr[0]
        except socket.timeout:
            continue
        except Exception:
            continue


# ----------------------------------------------------------------
# Routes
# ----------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "moc"})


@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    with tlm_lock:
        tlm = dict(latest_tlm)
    return render_template("dashboard.html", tlm=tlm, user=session["user"])


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # No rate limiting. No lockout. No MFA.
        if username == MOC_USERNAME and password == MOC_PASSWORD:
            session["user"] = username
            session.permanent = True
            return redirect(url_for("index"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/telemetry")
def api_telemetry():
    """Returns latest telemetry as JSON. No auth required."""
    with tlm_lock:
        return jsonify(latest_tlm)


@app.route("/command", methods=["GET", "POST"])
def command():
    """
    Command interface.
    No source IP validation — accepts commands from any IP on the network.
    This models the Viasat/NOAA pattern: trusted network access = command access.
    """
    if "user" not in session:
        return redirect(url_for("login"))

    result = None
    if request.method == "POST":
        cmd_name = request.form.get("command", "")
        source_ip = request.remote_addr

        cmd_map = {
            "CAMERA_ENABLE":    (0x200, 0x10, b""),
            "CAMERA_DISABLE":   (0x200, 0x11, b""),
            "DOWNLINK_ENABLE":  (0x200, 0x20, b""),
            "DOWNLINK_DISABLE": (0x200, 0x21, b""),
            "MEMORY_DUMP_ALL":  (0x200, 0x30, b""),
            "SAMPLE_NOP":       (0x200, 0x00, b""),
            "ES_NOP":           (0x001, 0x00, b""),
            "ES_RESTART_APP":   (0x001, 0x04, b""),
        }

        if cmd_name in cmd_map:
            apid, fc, user_data = cmd_map[cmd_name]
            pkt = build_ccsds_cmd(apid, fc, user_data)
            success = send_raw_udp(pkt)
            log_command(
                operator=session["user"],
                source_ip=source_ip,
                apid=f"0x{apid:03X}",
                func_code=f"0x{fc:02X}",
                command_name=cmd_name,
                raw_hex=pkt.hex()
            )
            result = {
                "success": success,
                "command": cmd_name,
                "apid": f"0x{apid:03X}",
                "func_code": f"0x{fc:02X}",
                "packet_hex": pkt.hex(),
                "source_ip": source_ip,
            }
        else:
            result = {"success": False, "error": f"Unknown command: {cmd_name}"}

    return render_template("command.html", result=result, user=session["user"])


@app.route("/api/command/raw", methods=["POST"])
def api_command_raw():
    """
    Raw CCSDS command injection endpoint.
    Accepts hex-encoded CCSDS packets and forwards directly to satellite.
    No authentication required — source IP is not checked.

    This endpoint exists to support automated commanding from the
    ground station. In a real MOC, this would be protected.
    In our lab, it is not. This is intentional.

    POST body: {"hex": "183200c000011f...", "note": "optional label"}
    """
    data = request.get_json(force=True, silent=True)
    if not data or "hex" not in data:
        return jsonify({"error": "Missing hex field"}), 400

    try:
        pkt = bytes.fromhex(data["hex"])
    except ValueError as e:
        return jsonify({"error": f"Invalid hex: {e}"}), 400

    success = send_raw_udp(pkt)
    log_command(
        operator="api",
        source_ip=request.remote_addr,
        apid="raw",
        func_code="raw",
        command_name=data.get("note", "raw_injection"),
        raw_hex=data["hex"]
    )
    return jsonify({"success": success, "bytes_sent": len(pkt)})


@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM command_log ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return render_template("logs.html", rows=rows, user=session["user"])


if __name__ == "__main__":
    init_db()
    t = threading.Thread(target=tlm_receiver, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8080, debug=False)
