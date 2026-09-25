#!/usr/bin/env python3
"""
SpaceVE-1 Ground Station Command Gateway

Listens on TCP 4820 for raw CCSDS command packets.
Forwards them to the satellite (192.168.60.100:1234) via UDP.
No authentication. No source IP verification. No rate limiting.

This models the ground segment misconfiguration described in
research_index.md section 6.3: the ground station accepts commands
from any system on the 192.168.60.0/24 network without verification.

Protocol:
  Client connects to TCP 4820.
  Client sends: 4-byte length prefix (big-endian uint32) + CCSDS packet bytes.
  Server forwards the CCSDS packet to satellite UDP 1234.
  Server responds: 1 byte, 0x01 = forwarded, 0x00 = error.
"""

import os
import socket
import struct
import threading

GS_USERNAME = os.environ.get("GS_USERNAME", "gsoperator")
GS_PASSWORD = os.environ.get("GS_PASSWORD", "password123")
SATELLITE_IP = os.environ.get("SATELLITE_IP", "192.168.60.100")
SATELLITE_CMD_PORT = int(os.environ.get("SATELLITE_CMD_PORT", 1234))
LISTEN_PORT = 4820
STATUS_PORT = 5900


def forward_to_satellite(ccsds_bytes: bytes) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(ccsds_bytes, (SATELLITE_IP, SATELLITE_CMD_PORT))
        s.close()
        return True
    except Exception as e:
        print(f"[GS] Forward failed: {e}")
        return False


def handle_client(conn: socket.socket, addr: tuple):
    src_ip, src_port = addr
    print(f"[GS] Connection from {src_ip}:{src_port}")
    # No source IP check — accepts from any client in network
    try:
        while True:
            # Read 4-byte length prefix
            hdr = b""
            while len(hdr) < 4:
                chunk = conn.recv(4 - len(hdr))
                if not chunk:
                    return
                hdr += chunk

            pkt_len = struct.unpack(">I", hdr)[0]
            if pkt_len < 8 or pkt_len > 4096:
                conn.send(b"\x00")
                continue

            # Read the CCSDS packet
            pkt = b""
            while len(pkt) < pkt_len:
                chunk = conn.recv(pkt_len - len(pkt))
                if not chunk:
                    return
                pkt += chunk

            success = forward_to_satellite(pkt)
            conn.send(b"\x01" if success else b"\x00")
            print(f"[GS] Forwarded {len(pkt)} bytes from {src_ip} -> satellite. OK={success}")

    except Exception as e:
        print(f"[GS] Client error {src_ip}: {e}")
    finally:
        conn.close()


def status_server():
    """Simple TCP status service on port 5900. Default credentials exposed."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", STATUS_PORT))
    srv.listen(5)
    print(f"[GS] Status service on TCP {STATUS_PORT}")
    while True:
        conn, addr = srv.accept()
        conn.send(
            f"SpaceVE-1 Ground Station\r\n"
            f"Satellite: {SATELLITE_IP}:{SATELLITE_CMD_PORT}\r\n"
            f"Operator: {GS_USERNAME}\r\n"
            f"Auth: {GS_USERNAME}:{GS_PASSWORD}\r\n"
            f"\r\n".encode()
        )
        conn.close()


def main():
    print(f"[GS] Ground Station Command Gateway starting")
    print(f"[GS] Forwarding commands to {SATELLITE_IP}:{SATELLITE_CMD_PORT}")
    print(f"[GS] Listening on TCP {LISTEN_PORT}")
    print(f"[GS] Operator credentials: {GS_USERNAME} / {GS_PASSWORD}")
    print(f"[GS] Source IP verification: NONE")

    t = threading.Thread(target=status_server, daemon=True)
    t.start()

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
