"""
Backup MOC — simplified mirror of primary-moc.

Intentional misconfigurations:
  MC-3b: Same SECRET_KEY as primary-moc — session cookies are interchangeable
         An attacker who forges a session on primary-moc can reuse it here.
  Shares the same PostgreSQL database — all operators, commands, telemetry.
"""

import os
import hashlib
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, session, redirect

app = Flask(__name__)
# intentional: hardcoded, same as primary-moc
app.secret_key = os.environ.get("SECRET_KEY", "spaceve1-weak-secret-key-2024")

DB_DSN = os.environ.get("DATABASE_URL",
    "host=telemetry-db dbname=spaceops user=opsuser password=ops_pass_2024")


def get_conn():
    return psycopg2.connect(DB_DSN)


def md5pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/", methods=["GET"])
def index():
    if "username" not in session:
        return redirect("/login")
    return """
    <html><body style="background:#0a0e27;color:#dde1f0;font-family:'Courier New';padding:20px;">
    <h2>BACKUP MOC — SpaceVE-1</h2>
    <p>Status: STANDBY</p>
    <p>Primary MOC: <a href="http://primary-moc:5000" style="color:#1976D2;">primary-moc:5000</a></p>
    <p>Logged in as: """ + session.get("username", "") + """</p>
    <ul>
      <li><a href="/api/telemetry/latest" style="color:#1976D2;">/api/telemetry/latest (no auth)</a></li>
      <li><a href="/api/commands/history" style="color:#1976D2;">/api/commands/history</a></li>
    </ul>
    </body></html>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            conn = get_conn()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM operators WHERE username=%s AND password_hash=%s AND active=true",
                    (username, md5pw(password))
                )
                op = cur.fetchone()
            conn.close()
            if op:
                session["username"] = op["username"]
                session["role"]     = op["role"]
                return redirect("/")
        except Exception:
            pass
        return "<html><body style='background:#0a0e27;color:#f44336;font-family:monospace;padding:20px;'>AUTH FAILED</body></html>", 401

    return """
    <html><body style="background:#0a0e27;color:#dde1f0;font-family:'Courier New';padding:40px;">
    <h2>BACKUP MOC — Auth</h2>
    <form method=POST>
      <input name=username placeholder=username style="margin:4px;background:#070b1e;border:1px solid #2a2f45;color:#dde1f0;padding:6px 10px;font-family:'Courier New'"><br>
      <input name=password type=password placeholder=password style="margin:4px;background:#070b1e;border:1px solid #2a2f45;color:#dde1f0;padding:6px 10px;font-family:'Courier New'"><br>
      <button type=submit style="margin:4px;background:#1976D2;border:none;color:#fff;padding:6px 20px;cursor:pointer;font-family:'Courier New';">LOGIN</button>
    </form>
    </body></html>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/api/telemetry/latest")
def api_tlm_latest():
    # NO AUTH — same as primary-moc — intentional
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT ON (satellite_id) satellite_id, ts, mode, battery_soc, raw
                FROM telemetry ORDER BY satellite_id, ts DESC
            """)
            rows = cur.fetchall()
        conn.close()
        result = {}
        for row in rows:
            result[row["satellite_id"]] = {
                "mode": row["mode"],
                "ts":   str(row["ts"]),
                "battery_soc": row["battery_soc"],
                **(row["raw"] or {})
            }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/commands/history")
def api_cmd_history():
    if "username" not in session:
        return jsonify({"error": "unauthenticated"}), 401
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, satellite_id, func_code, func_name, level, status,
                       submitted_by, submitted_at
                FROM commands ORDER BY submitted_at DESC LIMIT 50
            """)
            rows = cur.fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows], default=str)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
