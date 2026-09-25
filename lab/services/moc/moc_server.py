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
import struct
import time

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

APID_TO_SAT = {0x200: "SpaceVE-1A", 0x201: "SpaceVE-1B", 0x202: "SpaceVE-1C"}
SAT_TO_APID = {v: k for k, v in APID_TO_SAT.items()}

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

sat_state: dict = {}
ws_clients: set = set()
sessions: dict  = {}
_cmd_seq: int   = 0
_start_ts       = time.time()


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
    ws_clients.add(websocket)
    sessions[websocket] = {"username": None, "role": None}
    loop = asyncio.get_event_loop()

    # Send current snapshot — NO AUTH REQUIRED (MC-MOC-1)
    for tlm in sat_state.values():
        await websocket.send(json.dumps({"type": "tlm_update", **tlm}, default=str))
    await websocket.send(json.dumps({
        "type": "connected", "moc_id": MOC_ID,
        "ts": time.time(), "authenticated": False
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
                    await websocket.send(json.dumps({
                        "type": "login_ok",
                        "username": op["username"],
                        "role": op["role"],
                        "clearance": op["clearance"],
                    }))
                else:
                    await websocket.send(json.dumps({"type": "login_fail", "message": "Invalid credentials"}))

            elif mtype == "submit_cmd":
                sess = sessions.get(websocket, {})
                if not sess.get("username"):
                    await websocket.send(json.dumps({"type": "error", "message": "Authentication required"}))
                    continue
                sat_id    = msg.get("satellite_id", "SpaceVE-1A")
                func_name = msg.get("func_name", "NOP").upper()
                if func_name not in FUNC_CODES:
                    await websocket.send(json.dumps({"type": "error", "message": f"Unknown command: {func_name}"}))
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
                cmds = await loop.run_in_executor(None, telemetry_store.get_recent_commands)
                await websocket.send(json.dumps({"type": "recent_commands", "commands": cmds}, default=str))

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
            await broadcast({"type": "tlm_update", **parsed})
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


async def http_index(request):
    static = os.path.join(os.path.dirname(__file__), "static", "index.html")
    return web.FileResponse(static)


async def start_http(port):
    app = web.Application()
    app.router.add_get("/",            http_index)
    app.router.add_get("/index.html",  http_index)
    app.router.add_get("/status",      http_status)
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
