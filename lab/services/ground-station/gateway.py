"""
Ground Station TCP Gateway — CCSDS relay to satellite UDP endpoints.

Listens on TCP 9001. Accepts CCSDS packets from MOC and relays to the
satellite UDP port 8001. Applies credentials check UNLESS
MAINTENANCE_MODE=true (intentional misconfiguration on GS-2).

Intentional misconfigurations:
  MC-7: MAINTENANCE_MODE=true disables auth, allows unauthenticated relay
  Credential leak: AUTH_TOKEN echoed in banner response
"""

import os
import socket
import threading
import struct
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [GS] %(message)s')

GS_NAME        = os.environ.get("GS_NAME", "GS-1")
GS_LAT         = float(os.environ.get("GS_LAT", "28.5"))
GS_LON         = float(os.environ.get("GS_LON", "-80.6"))
AUTH_TOKEN     = os.environ.get("AUTH_TOKEN", "gs1-auth-token-2024")
MAINTENANCE    = os.environ.get("MAINTENANCE_MODE", "false").lower() == "true"
SATELLITE_NETS = {
    "SpaceVE-1A": ("192.168.61.100", 8001),
    "SpaceVE-1B": ("192.168.61.101", 8001),
    "SpaceVE-1C": ("192.168.61.102", 8001),
}
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", 9001))

banner_lines = [
    b"OSA Ground Station TCP Gateway v1.0\r\n",
    f"Station: {GS_NAME}  Lat: {GS_LAT}  Lon: {GS_LON}\r\n".encode(),
    b"Mode: " + (b"MAINTENANCE (AUTH DISABLED)" if MAINTENANCE else b"NORMAL") + b"\r\n",
]
# intentional: token visible in maintenance mode banner
if MAINTENANCE:
    banner_lines.append(f"Auth token (maintenance log): {AUTH_TOKEN}\r\n".encode())

banner_lines.append(b"READY\r\n")


def parse_ccsds_header(data: bytes):
    if len(data) < 6:
        return None, None
    word0, word1, word2 = struct.unpack(">HHH", data[:6])
    apid    = word0 & 0x7FF
    seq_cnt = word1 & 0x3FFF
    length  = word2 + 1
    return apid, length


def relay_to_satellite(sat_name: str, packet: bytes):
    target = SATELLITE_NETS.get(sat_name)
    if not target:
        return False, "Unknown satellite"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(packet, target)
        sock.close()
        logging.info("Relayed %d bytes to %s at %s:%d", len(packet), sat_name, *target)
        return True, "OK"
    except Exception as e:
        return False, str(e)


def handle_client(conn: socket.socket, addr):
    try:
        for line in banner_lines:
            conn.sendall(line)

        authenticated = MAINTENANCE

        buf = b""
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buf += data

            # Simple line-protocol: first non-empty line is auth challenge response
            # Format: AUTH <token>\n  or  CMD <satellite_name> <hex_packet>\n
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue

                if line.startswith(b"AUTH "):
                    token = line[5:].decode().strip()
                    if token == AUTH_TOKEN:
                        authenticated = True
                        conn.sendall(b"AUTH_OK\r\n")
                        logging.info("%s authenticated from %s", GS_NAME, addr)
                    else:
                        conn.sendall(b"AUTH_FAIL\r\n")
                    continue

                if not authenticated:
                    conn.sendall(b"ERR NOT_AUTHENTICATED\r\n")
                    continue

                if line.startswith(b"CMD "):
                    parts = line.split(b" ", 2)
                    if len(parts) < 3:
                        conn.sendall(b"ERR MALFORMED\r\n")
                        continue
                    sat_name = parts[1].decode().strip()
                    try:
                        pkt_hex = parts[2].decode().strip().replace(" ", "")
                        packet  = bytes.fromhex(pkt_hex)
                    except ValueError:
                        conn.sendall(b"ERR BAD_HEX\r\n")
                        continue
                    ok, msg = relay_to_satellite(sat_name, packet)
                    resp = b"OK RELAYED\r\n" if ok else f"ERR {msg}\r\n".encode()
                    conn.sendall(resp)
                elif line == b"STATUS":
                    status = (
                        f"GS={GS_NAME} LAT={GS_LAT} LON={GS_LON} "
                        f"MAINTENANCE={MAINTENANCE}\r\n"
                    ).encode()
                    conn.sendall(status)
                elif line == b"QUIT":
                    conn.sendall(b"BYE\r\n")
                    return
                else:
                    conn.sendall(b"ERR UNKNOWN_CMD\r\n")

    except Exception as e:
        logging.warning("Client %s error: %s", addr, e)
    finally:
        conn.close()


def main():
    logging.info("Starting %s on TCP :%d  maintenance=%s", GS_NAME, LISTEN_PORT, MAINTENANCE)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(10)
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
