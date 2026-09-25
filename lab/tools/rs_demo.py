#!/usr/bin/env python3
"""
rs_demo.py -- Reed-Solomon CCSDS Frame Error Correction Demo

Demonstrates RS(255,223) as used in CCSDS Transfer Frames:
  1. Encode 223 bytes of frame data -> 255 bytes (32 parity appended)
  2. Corrupt up to 16 bytes -> RS detects and corrects them
  3. Attacker path: modify frame data AND re-encode parity -> passes RS check

RS provides error DETECTION and CORRECTION for random bit errors (e.g., deep
space noise). It does NOT authenticate the data. An attacker with MITM access
can modify any bytes as long as they recompute the parity block.

Requires: pip install reedsolo
"""

import sys

try:
    import reedsolo
except ImportError:
    print("Missing dependency. Install with:  pip install reedsolo")
    sys.exit(1)

import argparse
import os
import struct

RS_BLOCK_SIZE    = 255   # CCSDS RS block (bytes)
RS_DATA_SIZE     = 223   # information bytes per block
RS_PARITY_SIZE   = RS_BLOCK_SIZE - RS_DATA_SIZE  # 32 parity bytes


def make_rs_codec() -> reedsolo.RSCodec:
    return reedsolo.RSCodec(RS_PARITY_SIZE)


def encode_frame(data: bytes, codec: reedsolo.RSCodec) -> bytes:
    if len(data) != RS_DATA_SIZE:
        raise ValueError(f"Frame data must be exactly {RS_DATA_SIZE} bytes")
    return bytes(codec.encode(data))   # 255 bytes: data + parity


def decode_frame(block: bytes, codec: reedsolo.RSCodec) -> bytes:
    decoded, _, _ = codec.decode(bytearray(block))
    return bytes(decoded)[:RS_DATA_SIZE]


def corrupt_bytes(block: bytes, positions: list, value: int = 0xAA) -> bytes:
    b = bytearray(block)
    for pos in positions:
        b[pos] = value
    return bytes(b)


def demo_channel_corruption(frame_data: bytes, corrupt_count: int):
    codec = make_rs_codec()
    print(f"\n{'='*60}")
    print("  SCENARIO 1: Channel noise / random bit errors")
    print(f"{'='*60}")
    print(f"  Original frame (first 16 bytes): {frame_data[:16].hex()}")

    encoded = encode_frame(frame_data, codec)
    print(f"  Encoded block ({len(encoded)} bytes): data({RS_DATA_SIZE}) + parity({RS_PARITY_SIZE})")

    positions = list(range(corrupt_count))
    corrupted = corrupt_bytes(encoded, positions)
    print(f"  Corrupted {corrupt_count} bytes at positions {positions}")
    print(f"  Corrupted (first 16): {corrupted[:16].hex()}")

    try:
        recovered = decode_frame(corrupted, codec)
        if recovered == frame_data:
            print(f"  RS CORRECTED: recovered frame matches original")
        else:
            print(f"  RS: recovered but mismatch (unexpected)")
    except reedsolo.ReedSolomonError as e:
        print(f"  RS FAILED: too many errors to correct ({e})")


def demo_attacker_mitm(frame_data: bytes, modified_data: bytes):
    codec = make_rs_codec()
    print(f"\n{'='*60}")
    print("  SCENARIO 2: Attacker MITM — modify data and re-encode parity")
    print(f"{'='*60}")
    print(f"  Original frame  (first 16): {frame_data[:16].hex()}")
    print(f"  Modified frame  (first 16): {modified_data[:16].hex()}")

    orig_encoded     = encode_frame(frame_data, codec)
    attacker_encoded = encode_frame(modified_data, codec)

    print(f"\n  Attacker intercepts the RS block and replaces data + parity:")
    print(f"  Attacker parity: {attacker_encoded[RS_DATA_SIZE:].hex()}")

    try:
        recovered = decode_frame(attacker_encoded, codec)
        match = (recovered == modified_data)
        print(f"\n  Receiver runs RS decode: {'PASS' if match else 'FAIL'}")
        print(f"  Received data (first 16): {recovered[:16].hex()}")
        print(f"  Receiver sees modified frame as valid. RS provides no authentication.")
    except reedsolo.ReedSolomonError as e:
        print(f"  RS decode error: {e}")


def demo_correction_limit():
    codec = make_rs_codec()
    print(f"\n{'='*60}")
    print("  SCENARIO 3: RS correction limits")
    print(f"{'='*60}")
    print(f"  RS(255,223) can correct up to {RS_PARITY_SIZE // 2} byte errors")
    print(f"  (or detect up to {RS_PARITY_SIZE} erasures)")

    frame = bytes(range(RS_DATA_SIZE))
    encoded = encode_frame(frame, codec)

    for count in [1, 8, 16, 17]:
        positions = list(range(count))
        corrupted = corrupt_bytes(encoded, positions)
        try:
            recovered = decode_frame(corrupted, codec)
            status = "CORRECTED" if recovered == frame else "MISMATCH"
        except reedsolo.ReedSolomonError:
            status = "UNCORRECTABLE"
        print(f"  {count:2d} corrupted bytes: {status}")


def main():
    p = argparse.ArgumentParser(description="RS(255,223) CCSDS demo")
    sub = p.add_subparsers(dest="scenario")

    noise = sub.add_parser("noise", help="Channel corruption and RS correction")
    noise.add_argument("--corrupt", type=int, default=8,
                       help="Number of bytes to corrupt (max 16 for correction)")

    mitm = sub.add_parser("mitm", help="MITM attack: modify data, re-encode parity")

    sub.add_parser("limits", help="RS correction limit table")

    sub.add_parser("all", help="Run all three scenarios")

    args = p.parse_args()

    frame_data = bytes(range(RS_DATA_SIZE))
    modified   = bytearray(frame_data)
    modified[0]  = 0xDE
    modified[1]  = 0xAD
    modified[10] = 0xFF
    modified     = bytes(modified)

    if args.scenario == "noise":
        demo_channel_corruption(frame_data, args.corrupt)
    elif args.scenario == "mitm":
        demo_attacker_mitm(frame_data, modified)
    elif args.scenario == "limits":
        demo_correction_limit()
    elif args.scenario == "all" or args.scenario is None:
        demo_channel_corruption(frame_data, 8)
        demo_attacker_mitm(frame_data, modified)
        demo_correction_limit()
    else:
        p.print_help()


if __name__ == "__main__":
    main()
