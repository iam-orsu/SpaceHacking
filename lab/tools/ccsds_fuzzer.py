"""
ccsds_fuzzer.py - Fuzz the CCSDS command port on a satellite or ground station

Usage:
    python3 ccsds_fuzzer.py --target 192.168.61.100:1234 --iterations 200
    python3 ccsds_fuzzer.py --target 192.168.61.21:4820  --mode tcp --iterations 100
    python3 ccsds_fuzzer.py --target 192.168.61.100:1234 --seed 42 --iterations 500

What it does:
    Generates malformed CCSDS TC packets and sends them to the target's command
    port. Logs which packet patterns trigger unexpected responses, connection drops,
    or error messages. Covers:

    1. Valid CCSDS header, random payload           (boundary fuzzing)
    2. Zero-length payload                          (edge case)
    3. Oversize packet (jumbo)                      (buffer handling)
    4. Correct APID, corrupt secondary header       (checksum bypass)
    5. Wrong version bits (not 000)                 (parser validation)
    6. Max sequence counter (0x3FFF = 16383)        (replay/wraparound)
    7. All-zeros packet                             (null input)
    8. All-0xFF packet                              (max byte values)
    9. Random valid-looking APID, random payload    (APID scanning)
   10. Truncated header (< 6 bytes)                 (incomplete packet)

CCSDS TC primary header (6 bytes, big-endian):
    Bits 0-2:   Version (000)
    Bit  3:     Type (1 = TC)
    Bit  4:     Secondary Header Flag
    Bits 5-15:  APID
    Bits 16-17: Sequence Flags (11 = standalone)
    Bits 18-31: Sequence Count
    Bits 32-47: Packet Data Length (payload_len - 1)

CCSDS TC secondary header (2 bytes):
    Bits 0-7:  Function Code
    Bits 8-15: Checksum (XOR of all prior bytes)

Attack relevance:
    - Discover whether satellite CMD parser crashes on malformed input
    - Find function codes not documented in FUNC_NAMES (hidden commands)
    - Identify replay tolerance via sequence counter wrapping
    - MC-GS-4: raw CMD relay means ground station passes fuzzer payloads verbatim
"""

import argparse
import os
import random
import socket
import struct
import time

KNOWN_APIDS = [0x200, 0x201, 0x202]

FUZZ_STRATEGIES = [
    "random_payload",
    "zero_payload",
    "jumbo",
    "corrupt_secondary_hdr",
    "wrong_version",
    "max_seq_counter",
    "all_zeros",
    "all_0xff",
    "random_apid",
    "truncated_header",
]


def build_ccsds_tc(apid, seq, func_code, payload=b""):
    word0    = (1 << 12) | (1 << 11) | (apid & 0x7FF)
    word1    = (0b11 << 14) | (seq & 0x3FFF)
    sec_len  = 2
    data_len = sec_len + len(payload) - 1
    hdr  = struct.pack(">HHH", word0, word1, data_len)
    xsum = 0
    for b in hdr:
        xsum ^= b
    sec  = struct.pack("BB", func_code & 0xFF, xsum ^ func_code)
    return hdr + sec + payload


def fuzz_packet(strategy, apid, seq, rng):
    if strategy == "random_payload":
        size = rng.randint(1, 64)
        return build_ccsds_tc(apid, seq, rng.randint(0, 255), rng.randbytes(size))

    if strategy == "zero_payload":
        return build_ccsds_tc(apid, seq, 0, b"")

    if strategy == "jumbo":
        return build_ccsds_tc(apid, seq, rng.randint(0, 15), rng.randbytes(512))

    if strategy == "corrupt_secondary_hdr":
        pkt = bytearray(build_ccsds_tc(apid, seq, 0, b"\x00\x00\x00\x00"))
        pkt[7] ^= 0xFF
        return bytes(pkt)

    if strategy == "wrong_version":
        pkt = bytearray(build_ccsds_tc(apid, seq, 0))
        pkt[0] = (pkt[0] & 0x1F) | (0b111 << 5)
        return bytes(pkt)

    if strategy == "max_seq_counter":
        return build_ccsds_tc(apid, 0x3FFF, rng.randint(0, 15))

    if strategy == "all_zeros":
        return b"\x00" * 8

    if strategy == "all_0xff":
        return b"\xff" * 8

    if strategy == "random_apid":
        rand_apid = rng.randint(0, 0x7FF)
        return build_ccsds_tc(rand_apid, seq, rng.randint(0, 255))

    if strategy == "truncated_header":
        size = rng.randint(1, 5)
        return os.urandom(size)

    return b""


def send_udp(sock, host, port, data):
    sock.sendto(data, (host, port))
    return None


def send_tcp(host, port, data, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(data)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            resp = b""
        s.close()
        return resp
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return f"ERR:{e}".encode()


def print_hex(data, indent=4):
    sp = " " * indent
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{sp}{i:04X}  {hex_part:<47}  {ascii_part}")


def main():
    parser = argparse.ArgumentParser(
        description="Fuzz CCSDS command port on satellite or ground station",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target",     required=True, help="host:port of target CMD port")
    parser.add_argument("--mode",       default="udp", choices=["udp","tcp"], help="Transport (default: udp)")
    parser.add_argument("--apid",       type=lambda x: int(x,0), default=0x200, help="Base APID (default: 0x200)")
    parser.add_argument("--iterations", type=int, default=100, help="Fuzz iterations (default: 100)")
    parser.add_argument("--seed",       type=int, default=None, help="RNG seed for reproducibility")
    parser.add_argument("--delay",      type=float, default=0.05, help="Seconds between packets (default: 0.05)")
    parser.add_argument("--verbose",    action="store_true", help="Print hex of every packet")
    args = parser.parse_args()

    host, port_str = args.target.rsplit(":", 1)
    port = int(port_str)
    rng  = random.Random(args.seed)

    print(f"[ccsds_fuzzer]")
    print(f"  Target      : {host}:{port}  ({args.mode.upper()})")
    print(f"  Base APID   : 0x{args.apid:03X}")
    print(f"  Iterations  : {args.iterations}")
    print(f"  Seed        : {args.seed if args.seed is not None else 'random'}")
    print()

    results = {s: {"sent": 0, "errors": 0, "responses": []} for s in FUZZ_STRATEGIES}

    udp_sock = None
    if args.mode == "udp":
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(args.iterations):
        strategy = FUZZ_STRATEGIES[i % len(FUZZ_STRATEGIES)]
        pkt      = fuzz_packet(strategy, args.apid, i & 0x3FFF, rng)
        res      = results[strategy]

        try:
            if args.mode == "udp":
                udp_sock.sendto(pkt, (host, port))
                resp = b""
            else:
                resp = send_tcp(host, port, pkt, timeout=1.5)

            res["sent"] += 1
            status = "SENT"

            if resp and not resp.startswith(b"ERR:"):
                res["responses"].append(resp[:80])
                status = f"RESP({len(resp)}b)"
            elif resp and resp.startswith(b"ERR:"):
                res["errors"] += 1
                status = resp.decode(errors="replace")[:40]

        except OSError as e:
            res["errors"] += 1
            status = f"FAIL:{e}"

        print(f"[{i+1:04d}] {strategy:<28}  {len(pkt):>4}B  {status}")
        if args.verbose:
            print_hex(pkt)

        if args.delay:
            time.sleep(args.delay)

    if udp_sock:
        udp_sock.close()

    # Summary
    print()
    print("=" * 60)
    print("FUZZ SUMMARY")
    print("=" * 60)
    total_sent = sum(r["sent"] for r in results.values())
    total_err  = sum(r["errors"] for r in results.values())
    total_resp = sum(len(r["responses"]) for r in results.values())
    print(f"  Total sent      : {total_sent}")
    print(f"  Transport errors: {total_err}")
    print(f"  Responses got   : {total_resp}")
    print()
    for strategy, res in results.items():
        flag = " <-- INTERESTING (got response)" if res["responses"] else ""
        print(f"  {strategy:<28}  sent={res['sent']}  err={res['errors']}{flag}")
        for r in res["responses"][:3]:
            print(f"      response: {r!r}")
    print()
    print("Next steps:")
    print("  - Strategies with responses may indicate accepted/processed malformed packets")
    print("  - Re-run with --seed <N> to reproduce and --verbose to inspect bytes")
    print(f"  - Try: python3 ccsds_fuzzer.py --target {args.target} --mode {args.mode} --seed 0 --iterations 500 --verbose")


if __name__ == "__main__":
    main()
