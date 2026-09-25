#!/usr/bin/env python3
"""
SpaceVE-1 Mission Operations Center

asyncio server with:
  - UDP port 5000  : receives binary CCSDS TM from satellites
  - WS  port 8765  : WebSocket for browser dashboard
  - HTTP port 8080 : serves static/index.html

Intentional misconfigurations (no CVEs — training targets only):
  MC-MOC-1  WebSocket /tlm stream readable without authentication
  MC-MOC-2  MD5 password hashing (no bcrypt or Argon2)
  MC-MOC-3  Hardcoded SECRET_KEY same across MOC instances
  MC-MOC-4  SQL injection in telemetry search (f-string query in telemetry_store)
"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
import struct
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import aiohttp
import websockets
from aiohttp import web

import ccsds_parser
import telemetry_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MOC] %(message)s")
log = logging.getLogger("moc")

MOC_ID    = os.environ.get("MOC_ID", "PRIMARY")
TLM_PORT  = int(os.environ.get("TLM_LISTEN_PORT", 5000))
WS_PORT   = int(os.environ.get("WS_PORT", 8765))
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
GS1_HOST  = os.environ.get("GS1_HOST", "192.168.61.20")
GS1_PORT  = int(os.environ.get("GS1_PORT", 4820))
GS1_TOKEN = os.environ.get("GS1_TOKEN", "gs_alpha_2024")
GS2_HOST  = os.environ.get("GS2_HOST", "192.168.61.21")
GS2_PORT  = int(os.environ.get("GS2_PORT", 4820))

NASA_API_KEY = os.environ.get("NASA_API_KEY", "")
NASA_API_URL = os.environ.get("NASA_API_URL", "https://api.nasa.gov/planetary/earth/imagery")
IMAGERY_DIR  = os.path.join(os.path.dirname(__file__), "imagery")
os.makedirs(IMAGERY_DIR, exist_ok=True)

APID_TO_SAT = {0x200: "SpaceVE-1A", 0x201: "SpaceVE-1B", 0x202: "SpaceVE-1C"}
SAT_TO_APID = {v: k for k, v in APID_TO_SAT.items()}

FUNC_CODES = {
    "NOP":                     (0x00, 1),
    "CAMERA_ON":               (0x01, 2),
    "CAMERA_OFF":              (0x02, 2),
    "DOWNLINK_ENABLE":         (0x03, 2),
    "DOWNLINK_DISABLE":        (0x04, 2),
    "MEMORY_DUMP":             (0x05, 2),
    "REBOOT":                  (0x06, 3),
    "SAFING_MODE":             (0x07, 3),
    "NOMINAL_MODE":            (0x08, 1),
    "EMERGENCY_SAFING":        (0x09, 3),
    "PAYLOAD_POWER_OFF":       (0x0A, 3),
    "MISSION_DOWNLINK_ENABLE": (0x0B, 2),
    "MISSION_DOWNLINK_DISABLE":(0x0C, 2),
}

sat_state: dict  = {}
ws_clients: set  = set()
sessions: dict   = {}
ws_tokens: dict  = {}  # token -> {username, role, clearance, ts}
_cmd_seq: int    = 0
_start_ts        = time.time()

satellite_imaging_state: dict = {
    "SpaceVE-1A": {"target_lat": 33.7,  "target_lon": 73.0,  "resolution_m": 30, "imaging_mode": "MULTISPECTRAL", "status": "IDLE", "last_imagery_id": None, "last_capture_ts": None},
    "SpaceVE-1B": {"target_lat": 51.2,  "target_lon": 9.8,   "resolution_m": 30, "imaging_mode": "MULTISPECTRAL", "status": "IDLE", "last_imagery_id": None, "last_capture_ts": None},
    "SpaceVE-1C": {"target_lat": -35.1, "target_lon": 147.3, "resolution_m": 30, "imaging_mode": "MULTISPECTRAL", "status": "IDLE", "last_imagery_id": None, "last_capture_ts": None},
}

ROLE_PERMS = {
    "TELEMETRY_OPS": {"read_tlm", "read_history"},
    "COMMAND_OPS":   {"read_tlm", "send_command", "approve_command"},
    "PAYLOAD_OPS":   {"read_tlm", "send_command", "payload_control"},
    "SAFETY_OPS":    {"read_tlm", "send_command", "approve_command", "emergency_safing"},
    "ADMIN":         {"*"},
}

def has_perm(role: str, perm: str) -> bool:
    perms = ROLE_PERMS.get(role, set())
    return "*" in perms or perm in perms


def build_ccsds_tc(apid: int, fc: int) -> bytes:
    global _cmd_seq
    _cmd_seq = (_cmd_seq + 1) & 0x3FFF
    word0 = (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1 = (0b11 << 14) | _cmd_seq
    sec0  = (fc & 0x7F) << 1
    return struct.pack(">HHH", word0, word1, 1) + bytes([sec0, 0xFF ^ sec0])


async def relay_to_gs(satellite_id: str, func_name: str) -> tuple:
    fc, _  = FUNC_CODES.get(func_name, (0, 1))
    apid   = SAT_TO_APID.get(satellite_id, 0x200)
    pkt    = build_ccsds_tc(apid, fc)
    pkt_hex = pkt.hex()

    for gs_host, gs_port, gs_token, gs_name in [
        (GS1_HOST, GS1_PORT, GS1_TOKEN, "GS-ALPHA"),
        (GS2_HOST, GS2_PORT, None,      "GS-BETA"),
    ]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(gs_host, gs_port), timeout=3.0
            )
            await asyncio.wait_for(reader.read(512), timeout=2.0)
            if gs_token:
                writer.write(f"AUTH {gs_token}\n".encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(64), timeout=2.0)
                if b"AUTH_OK" not in resp:
                    writer.close()
                    continue
            writer.write(f"CMD {satellite_id} {pkt_hex}\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(64), timeout=2.0)
            writer.close()
            if b"OK" in resp:
                log.info("CMD %s -> %s via %s (fc=0x%02X)", func_name, satellite_id, gs_name, fc)
                return True, f"Relayed via {gs_name}"
        except Exception as e:
            log.warning("GS %s unreachable: %s", gs_name, e)
    return False, "All ground stations unreachable"


async def fetch_nasa_imagery(lat: float, lon: float, resolution: int) -> dict:
    """Fetch real Earth imagery from NASA Landsat API. No auth check — intentional (MC-MOC-5)."""
    if not NASA_API_KEY:
        return {"success": False, "error": "NASA_API_KEY not configured. Add to lab/.env and rebuild."}
    params = {"lon": lon, "lat": lat, "dim": 0.1, "api_key": NASA_API_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(NASA_API_URL, params=params,
                                   timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    image_data = await resp.read()
                    imagery_id = f"IMG_{datetime.now().strftime('%Y%m%d_%H%M%S')}_LAT{lat:.1f}_LON{lon:.1f}"
                    filepath   = os.path.join(IMAGERY_DIR, f"{imagery_id}.png")
                    with open(filepath, "wb") as f:
                        f.write(image_data)
                    log.info("NASA IMAGERY: %s (lat=%.4f lon=%.4f)", imagery_id, lat, lon)
                    return {
                        "success":     True,
                        "imagery_id":  imagery_id,
                        "imagery_url": f"/imagery/{imagery_id}.png",
                        "lat": lat, "lon": lon, "resolution": resolution,
                        "captured_ts": datetime.now().isoformat(),
                    }
                else:
                    body = await resp.text()
                    return {"success": False, "error": f"NASA API {resp.status}: {body[:200]}"}
    except asyncio.TimeoutError:
        return {"success": False, "error": "NASA API timeout — satellite out of contact window?"}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def broadcast(msg: dict):
    if not ws_clients:
        return
    data = json.dumps(msg, default=str)
    dead = set()
    for ws in list(ws_clients):
        try:
            await ws.send(data)
        except Exception:
            dead.add(ws)
    ws_clients -= dead


async def ws_handler(websocket):
    # MC-MOC-1b: token checked only at connection time, not per-message
    parsed = urlparse(websocket.request.path)
    token  = parse_qs(parsed.query).get("token", [None])[0]
    if not token or token not in ws_tokens:
        reason = "Authentication required" if not token else "Invalid token"
        await websocket.close(code=1008, reason=reason)
        return

    td = ws_tokens[token]
    ws_clients.add(websocket)
    sessions[websocket] = {"username": td["username"], "role": td["role"], "clearance": td["clearance"]}
    loop = asyncio.get_event_loop()

    for tlm in sat_state.values():
        await websocket.send(json.dumps({"type": "tlm_update", **tlm}, default=str))
    await websocket.send(json.dumps({
        "type": "connected", "moc_id": MOC_ID,
        "ts": time.time(), "authenticated": True,
        "username": td["username"], "role": td["role"],
    }))

    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            mtype = msg.get("type", "")

            if mtype == "login":
                pwd_md5 = hashlib.md5(msg.get("password", "").encode()).hexdigest()
                op = await loop.run_in_executor(
                    None, telemetry_store.get_operator,
                    msg.get("username", ""), pwd_md5
                )
                if op:
                    sessions[websocket] = {"username": op["username"], "role": op["role"]}
                    await loop.run_in_executor(
                        None, telemetry_store.log_audit,
                        op["username"], "WS_LOGIN", "websocket"
                    )
                    new_tok = secrets.token_hex(16)
                    ws_tokens[new_tok] = {
                        "username": op["username"], "role": op["role"],
                        "clearance": op["clearance"], "ts": time.time(),
                    }
                    sessions[websocket] = {"username": op["username"], "role": op["role"], "clearance": op["clearance"]}
                    await websocket.send(json.dumps({
                        "type": "login_ok",
                        "username": op["username"],
                        "role": op["role"],
                        "clearance": op["clearance"],
                        "token": new_tok,
                    }))
                else:
                    await websocket.send(json.dumps({"type": "login_fail", "message": "Invalid credentials"}))

            elif mtype == "submit_cmd":
                sess = sessions.get(websocket, {})
                if not sess.get("username"):
                    await websocket.send(json.dumps({"type": "error", "message": "Authentication required"}))
                    continue
                if not has_perm(sess.get("role", ""), "send_command"):
                    log.warning("RBAC DENY: %s (role=%s) send_command", sess["username"], sess.get("role"))
                    await websocket.send(json.dumps({"type": "error", "message": "Permission denied: your role cannot send commands"}))
                    continue
                sat_id    = msg.get("satellite_id", "SpaceVE-1A")
                func_name = msg.get("func_name", "NOP").upper()
                if func_name not in FUNC_CODES:
                    await websocket.send(json.dumps({"type": "error", "message": f"Unknown command: {func_name}"}))
                    continue
                if func_name == "EMERGENCY_SAFING" and not has_perm(sess.get("role", ""), "emergency_safing"):
                    log.warning("RBAC DENY: %s (role=%s) emergency_safing", sess["username"], sess.get("role"))
                    await websocket.send(json.dumps({"type": "error", "message": "Permission denied: EMERGENCY_SAFING requires SAFETY_OPS or ADMIN role"}))
                    continue
                fc, level = FUNC_CODES[func_name]
                operator  = sess["username"]
                apid      = SAT_TO_APID.get(sat_id, 0x200)
                pkt_hex   = build_ccsds_tc(apid, fc).hex()

                cmd_id = await loop.run_in_executor(
                    None, telemetry_store.store_command,
                    sat_id, apid, fc, func_name, pkt_hex, level, operator
                )
                await websocket.send(json.dumps({
                    "type": "cmd_queued", "cmd_id": cmd_id,
                    "func_name": func_name, "satellite_id": sat_id,
                    "level": level, "status": "DISPATCHING",
                }))
                ok, result = await relay_to_gs(sat_id, func_name)
                status = "EXECUTED" if ok else "FAILED"
                await loop.run_in_executor(
                    None, telemetry_store.update_command_status, cmd_id, status
                )
                await loop.run_in_executor(
                    None, telemetry_store.log_audit,
                    operator, "DISPATCH_CMD", sat_id,
                    {"cmd_id": cmd_id, "func": func_name, "status": status}, None
                )
                await broadcast({
                    "type": "cmd_result", "cmd_id": cmd_id,
                    "func_name": func_name, "satellite_id": sat_id, "status": status,
                })

            elif mtype == "list_cmds":
                sess = sessions.get(websocket, {})
                if not has_perm(sess.get("role", ""), "read_history"):
                    log.warning("RBAC DENY: %s (role=%s) read_history", sess.get("username"), sess.get("role"))
                    await websocket.send(json.dumps({"type": "error", "message": "Permission denied: your role cannot read command history"}))
                    continue
                cmds = await loop.run_in_executor(None, telemetry_store.get_recent_commands)
                await websocket.send(json.dumps({"type": "recent_commands", "commands": cmds}, default=str))

            elif mtype == "redirect_imaging":
                # Red team attack: redirect satellite imaging target to unauthorized coordinates
                sat_id  = msg.get("satellite_id", "SpaceVE-1A")
                new_lat = float(msg.get("new_lat", 0))
                new_lon = float(msg.get("new_lon", 0))
                if sat_id in satellite_imaging_state:
                    satellite_imaging_state[sat_id]["target_lat"] = new_lat
                    satellite_imaging_state[sat_id]["target_lon"] = new_lon
                    satellite_imaging_state[sat_id]["status"]     = "REDIRECTED"
                    log.warning("IMAGING REDIRECT (WS): %s -> lat=%.4f lon=%.4f", sat_id, new_lat, new_lon)
                    await broadcast({"type": "imaging_redirected", "satellite_id": sat_id, "new_lat": new_lat, "new_lon": new_lon})

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        ws_clients.discard(websocket)
        sessions.pop(websocket, None)


class TelemetryProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue):
        self.queue = queue

    def datagram_received(self, data, addr):
        parsed = ccsds_parser.parse_tm_packet(data)
        if parsed:
            parsed["_src_ip"] = addr[0]
            self.queue.put_nowait(parsed)

    def error_received(self, exc):
        log.warning("UDP error: %s", exc)


async def broadcaster(queue):
    loop = asyncio.get_event_loop()
    db_last: dict = {}
    while True:
        parsed = await queue.get()
        sat_id = parsed.get("satellite_id")
        if not sat_id:
            continue
        ptype = parsed.get("packet_type", "tlm")
        if ptype == "mission_data":
            await broadcast({"type": "mission_data", "satellite_id": sat_id, **parsed})
        else:
            sat_state[sat_id] = parsed
            tlm_out = dict(parsed)
            tlm_out["imaging"] = dict(satellite_imaging_state.get(sat_id, {}))
            await broadcast({"type": "tlm_update", **tlm_out})
            now = time.time()
            if now - db_last.get(sat_id, 0) >= 5:
                db_last[sat_id] = now
                await loop.run_in_executor(None, telemetry_store.store_telemetry, parsed)


async def http_status(request):
    return web.Response(
        content_type="application/json",
        text=json.dumps({
            "moc_id": MOC_ID,
            "uptime_s": round(time.time() - _start_ts, 1),
            "satellites_tracked": list(sat_state.keys()),
            "ws_clients": len(ws_clients),
        }, default=str)
    )


async def http_login(request):
    """POST /api/login — issues a WS auth token. Passwords stored as MD5 (MC-MOC-2)."""
    try:
        data = await request.json()
    except Exception:
        return web.Response(status=400, content_type="application/json",
                            text='{"error":"bad request"}')
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return web.Response(status=400, content_type="application/json",
                            text='{"error":"username and password required"}')
    pwd_md5 = hashlib.md5(password.encode()).hexdigest()
    loop    = asyncio.get_event_loop()
    op      = await loop.run_in_executor(None, telemetry_store.get_operator, username, pwd_md5)
    if not op:
        return web.Response(status=401, content_type="application/json",
                            text='{"error":"Invalid credentials"}')
    token = secrets.token_hex(16)
    ws_tokens[token] = {
        "username": op["username"], "role": op["role"],
        "clearance": op["clearance"], "ts": time.time(),
    }
    await loop.run_in_executor(None, telemetry_store.log_audit,
                               op["username"], "HTTP_LOGIN", "api")
    log.info("HTTP login: %s (role=%s)", op["username"], op["role"])
    return web.Response(
        content_type="application/json",
        headers={"Access-Control-Allow-Origin": "*"},
        text=json.dumps({
            "token": token,
            "username": op["username"],
            "role": op["role"],
            "clearance": op["clearance"],
        }),
    )


async def http_capture_imagery(request):
    """POST /api/imagery/capture — fetch real NASA Earth imagery for a satellite's target."""
    try:
        data = await request.json()
    except Exception:
        return web.Response(status=400, content_type="application/json", text='{"error":"bad request"}')
    sat_id = data.get("satellite_id", "SpaceVE-1A")
    lat    = float(data.get("target_lat", 0))
    lon    = float(data.get("target_lon", 0))
    res    = int(data.get("resolution_m", 30))
    img_state = satellite_imaging_state.get(sat_id, {})
    img_state["status"] = "IMAGING"
    result = await fetch_nasa_imagery(lat, lon, res)
    if result.get("success"):
        img_state["status"]         = "CAPTURED"
        img_state["last_imagery_id"]  = result["imagery_id"]
        img_state["last_capture_ts"] = result["captured_ts"]
    else:
        img_state["status"] = "FAILED"
    return web.Response(
        content_type="application/json",
        headers={"Access-Control-Allow-Origin": "*"},
        text=json.dumps(result),
    )


async def http_redirect_imaging(request):
    """POST /api/imagery/redirect — redirect satellite imaging target (red team attack vector)."""
    try:
        data = await request.json()
    except Exception:
        return web.Response(status=400, content_type="application/json", text='{"error":"bad request"}')
    sat_id  = data.get("satellite_id", "SpaceVE-1A")
    new_lat = float(data.get("new_lat", 0))
    new_lon = float(data.get("new_lon", 0))
    if sat_id not in satellite_imaging_state:
        return web.Response(status=404, content_type="application/json", text='{"error":"satellite not found"}')
    satellite_imaging_state[sat_id]["target_lat"] = new_lat
    satellite_imaging_state[sat_id]["target_lon"] = new_lon
    satellite_imaging_state[sat_id]["status"]     = "REDIRECTED"
    log.warning("IMAGING REDIRECT (HTTP): %s -> lat=%.4f lon=%.4f", sat_id, new_lat, new_lon)
    await broadcast({"type": "imaging_redirected", "satellite_id": sat_id, "new_lat": new_lat, "new_lon": new_lon})
    return web.Response(
        content_type="application/json",
        headers={"Access-Control-Allow-Origin": "*"},
        text=json.dumps({"status": "redirected", "satellite_id": sat_id, "new_lat": new_lat, "new_lon": new_lon}),
    )


async def http_index(request):
    static = os.path.join(os.path.dirname(__file__), "static", "index.html")
    return web.FileResponse(static)


async def start_http(port):
    app = web.Application()
    app.router.add_get("/",                      http_index)
    app.router.add_get("/index.html",            http_index)
    app.router.add_get("/status",                http_status)
    app.router.add_post("/api/login",            http_login)
    app.router.add_post("/api/imagery/capture",  http_capture_imagery)
    app.router.add_post("/api/imagery/redirect", http_redirect_imaging)
    app.router.add_static("/imagery",            IMAGERY_DIR)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", port).start()
    log.info("HTTP on port %d", port)


async def main():
    queue = asyncio.Queue(maxsize=2000)
    loop  = asyncio.get_event_loop()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: TelemetryProtocol(queue), local_addr=("0.0.0.0", TLM_PORT)
    )
    log.info("UDP TLM on port %d", TLM_PORT)

    ws_server = await websockets.serve(ws_handler, "0.0.0.0", WS_PORT)
    log.info("WebSocket on port %d", WS_PORT)

    await start_http(HTTP_PORT)

    asyncio.create_task(broadcaster(queue))

    log.info("MOC-%s running | GS1=%s:%d GS2=%s:%d", MOC_ID, GS1_HOST, GS1_PORT, GS2_HOST, GS2_PORT)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
