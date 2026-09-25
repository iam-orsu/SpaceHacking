#!/usr/bin/env python3
"""
Ground Station Command Gateway — TCP operator console.

Protocol (plain text, newline-terminated):
  AUTH <password>              Authenticate with station password
  SENDCMD <sat> <func_name>   Build CCSDS TC and uplink by name
  CMD <sat> <hex>             Relay raw hex packet with no validation
  LISTCMDS                    Print available function names
  STATUS                      Print station status
  HELP                        Print this list
  QUIT                        Disconnect

Intentional misconfigurations (no CVEs, training targets):
  MC-GS-1  Default password easily guessed (password123)
  MC-GS-2  No source IP filtering — any host on the network can connect
  MC-GS-3  MAINTENANCE_MODE=true disables authentication entirely
  MC-GS-4  CMD command accepts raw CCSDS hex — arbitrary packet injection
  MC-GS-5  Sequence counter replay window is 0x3FFF (no anti-replay)
"""

import logging
import os
import socket
import struct
import threading

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

GS_ID        = os.environ.get("GS_ID", "GS-ALPHA")
GS_LAT       = float(os.environ.get("GS_LAT", "28.5"))
GS_LON       = float(os.environ.get("GS_LON", "-80.5"))
GS_PASSWORD  = os.environ.get("GS_PASSWORD", "password123")
MAINTENANCE  = os.environ.get("MAINTENANCE_MODE", "false").lower() == "true"
LISTEN_PORT  = int(os.environ.get("LISTEN_PORT", 4820))

SAT_IPS = {
    "SpaceVE-1A": os.environ.get("SAT_A_IP", "192.168.61.100"),
    "SpaceVE-1B": os.environ.get("SAT_B_IP", "192.168.61.101"),
    "SpaceVE-1C": os.environ.get("SAT_C_IP", "192.168.61.102"),
}
SAT_APIDS = {"SpaceVE-1A": 0x200, "SpaceVE-1B": 0x201, "SpaceVE-1C": 0x202}

FUNC_CODES = {
    "NOP":              0x00,
    "CAMERA_ON":        0x01,
    "CAMERA_OFF":       0x02,
    "DOWNLINK_ENABLE":  0x03,
    "DOWNLINK_DISABLE": 0x04,
    "MEMORY_DUMP":      0x05,
    "REBOOT":           0x06,
    "SAFING_MODE":      0x07,
    "NOMINAL_MODE":     0x08,
    "PAYLOAD_POWER_OFF":0x0A,
}

_seq: dict  = {}
_seq_lock   = threading.Lock()


def next_seq(sat: str) -> int:
    with _seq_lock:
        n = (_seq.get(sat, 0) + 1) & 0x3FFF
        _seq[sat] = n
        return n


def build_tc(apid: int, fc: int, seq: int) -> bytes:
    word0 = (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1 = (0b11 << 14) | (seq & 0x3FFF)
    sec0  = (fc & 0x7F) << 1
    return struct.pack(">HHH", word0, word1, 1) + bytes([sec0, 0xFF ^ sec0])


def uplink(sat: str, pkt: bytes) -> tuple:
    ip = SAT_IPS.get(sat)
    if not ip:
        return False, f"Unknown satellite: {sat}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt, (ip, 1234))
        sock.close()
        return True, f"OK  {len(pkt)} bytes -> {ip}:1234"
    except Exception as e:
        return False, str(e)


def handle_client(conn: socket.socket, addr: tuple):
    logger = logging.getLogger(f"{GS_ID}.{addr[0]}")
    logger.info("connect from %s", addr[0])

    def send(line: str):
        try:
            conn.sendall((line + "\r\n").encode())
        except Exception:
            pass

    send(f"=== OrsuSpace Ground Station {GS_ID} ===")
    send(f"Location: {GS_LAT:.2f} / {GS_LON:.2f}  |  Maintenance: {MAINTENANCE}")
    if MAINTENANCE:
        send("WARNING: MAINTENANCE MODE ACTIVE — authentication is disabled")
        send("         All uplink commands accepted without credentials")
    else:
        send(f"Authentication required. Send: AUTH <password>")
    send("Type HELP for commands.")
    send("")

    authenticated = MAINTENANCE
    buf = b""

    try:
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line_b, buf = buf.split(b"\n", 1)
                line  = line_b.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                parts = line.split()
                cmd   = parts[0].upper() if parts else ""

                if cmd == "HELP":
                    send("  AUTH <password>")
                    send("  SENDCMD <satellite> <func_name>   build + uplink CCSDS packet")
                    send("  CMD <satellite> <hex>             relay raw hex packet (no validation)")
                    send("  LISTCMDS                          list available function names")
                    send("  STATUS                            station status")
                    send("  QUIT")
                    continue

                if cmd == "STATUS":
                    send(f"GS={GS_ID}  LAT={GS_LAT}  LON={GS_LON}  MAINTENANCE={MAINTENANCE}  AUTH={authenticated}")
                    send(f"Satellites: {' '.join(SAT_IPS.keys())}")
                    continue

                if cmd == "LISTCMDS":
                    for name, fc in FUNC_CODES.items():
                        send(f"  {name:<24} fc=0x{fc:02X}")
                    continue

                if cmd == "QUIT":
                    send("BYE")
                    return

                if cmd == "AUTH":
                    if MAINTENANCE:
                        send("AUTH_IGNORED (maintenance mode)")
                        continue
                    pw = " ".join(parts[1:]) if len(parts) > 1 else ""
                    if pw == GS_PASSWORD:
                        authenticated = True
                        logger.info("authenticated")
                        send("AUTH_OK")
                    else:
                        send("AUTH_FAIL")
                    continue

                if not authenticated:
                    send("ERR NOT_AUTHENTICATED — send: AUTH <password>")
                    continue

                if cmd == "SENDCMD":
                    if len(parts) < 3:
                        send("ERR  Usage: SENDCMD <satellite> <func_name>")
                        continue
                    sat  = parts[1]
                    func = parts[2].upper()
                    fc   = FUNC_CODES.get(func)
                    if fc is None:
                        send(f"ERR  Unknown function '{func}'. Use LISTCMDS.")
                        continue
                    apid = SAT_APIDS.get(sat)
                    if apid is None:
                        send(f"ERR  Unknown satellite '{sat}'")
                        continue
                    seq = next_seq(sat)
                    pkt = build_tc(apid, fc, seq)
                    ok, msg = uplink(sat, pkt)
                    if ok:
                        send(f"OK  CCSDS seq=0x{seq:04X} APID=0x{apid:03X} FC=0x{fc:02X} -> {sat}")
                    else:
                        send(f"ERR  {msg}")

                elif cmd == "CMD":
                    # Raw hex relay — MC-GS-4: no CCSDS validation, allows arbitrary injection
                    if len(parts) < 3:
                        send("ERR  Usage: CMD <satellite> <hex_bytes>")
                        continue
                    sat     = parts[1]
                    hex_str = parts[2]
                    try:
                        pkt = bytes.fromhex(hex_str)
                    except ValueError:
                        send("ERR  Invalid hex string")
                        continue
                    ok, msg = uplink(sat, pkt)
                    send(f"OK  RELAYED {len(pkt)} bytes" if ok else f"ERR  {msg}")

                else:
                    send(f"ERR  Unknown command '{cmd}'. Type HELP.")

    except Exception as e:
        logger.warning("client error: %s", e)
    finally:
        conn.close()
        logger.info("disconnected")


def main():
    logger = logging.getLogger(GS_ID)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(20)
    logger.info("TCP port %d | maintenance=%s | password=%s",
                LISTEN_PORT, MAINTENANCE, GS_PASSWORD)
    logger.info("Source IP filtering: NONE (MC-GS-2)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
