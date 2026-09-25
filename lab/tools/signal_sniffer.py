#!/usr/bin/env python3
"""
signal_sniffer.py — SpaceVE-1 Network Traffic Sniffer
SpaceVE-1 Lab Attack Tool

Passively captures all lab traffic and identifies:
  - CCSDS command packets (UDP 1234)
  - Telemetry packets (UDP 1235)
  - Ground station traffic (TCP 4820, 5900)
  - MOC web traffic (TCP 8080)

Uses scapy for packet capture. Must be run as root inside the
spacelab network or on the host with access to the Docker bridge interface.

This models the "no encryption on any link" misconfiguration in
research_index.md section 6.1. All SpaceVE-1 traffic is cleartext.

Usage:
  sudo python3 signal_sniffer.py
  sudo python3 signal_sniffer.py --iface br-spacelab
  sudo python3 signal_sniffer.py --pcap capture.pcap
  sudo python3 signal_sniffer.py --count 50
  sudo python3 signal_sniffer.py --filter ccsds

To find the Docker bridge interface name:
  ip link show | grep br-
  docker network inspect spacehacking_spacelab | grep -i gateway

Common Beginner Mistakes:
  - Running without sudo gives "Permission denied" on raw sockets
  - The Docker bridge interface name includes the network name hash
  - Use --filter to focus on one protocol to reduce noise
  - CCSDS packets look like binary; use --decode to parse them
"""

import argparse
import struct
import time

try:
    from scapy.all import sniff, IP, UDP, TCP, Raw, wrpcap
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


CCSDS_CMD_PORT  = 1234
CCSDS_TLM_PORT  = 1235
GS_CMD_PORT     = 4820
GS_STATUS_PORT  = 5900
MOC_PORT        = 8080

SEEN = 0


def decode_ccsds_primary(data: bytes) -> dict:
    if len(data) < 6:
        return {}
    w0, w1, dlen = struct.unpack(">HHH", data[:6])
    return {
        "type":  "CMD" if (w0 >> 12) & 1 else "TLM",
        "apid":  f"0x{w0 & 0x7FF:03X}",
        "seq":   w1 & 0x3FFF,
        "dlen":  dlen,
    }


def decode_ccsds_secondary(data: bytes) -> dict:
    if len(data) < 8:
        return {}
    sec_byte0 = data[6]
    stored_ck = data[7]
    func = (sec_byte0 >> 1) & 0x7F
    ck = 0xFF ^ sec_byte0
    for b in data[8:]:
        ck ^= b
    return {
        "func":           f"0x{func:02X}",
        "checksum_valid": stored_ck == ck,
    }


def handle_packet(pkt, args, pcap_buf: list):
    global SEEN
    SEEN += 1

    ts = time.strftime("%H:%M:%S")
    src_ip = pkt[IP].src if IP in pkt else "?"
    dst_ip = pkt[IP].dst if IP in pkt else "?"
    raw = bytes(pkt[Raw].load) if Raw in pkt else b""

    if args.filter == "ccsds" and UDP not in pkt:
        return

    if UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        if dport == CCSDS_CMD_PORT and (args.filter in ("all", "ccsds")):
            ph = decode_ccsds_primary(raw)
            sh = decode_ccsds_secondary(raw)
            print(f"  [{ts}] CCSDS CMD  {src_ip} -> {dst_ip}:{dport}")
            print(f"         apid={ph.get('apid')} func={sh.get('func')} "
                  f"cksum_ok={sh.get('checksum_valid')} hex={raw.hex()[:32]}")

        elif sport == CCSDS_CMD_PORT and (args.filter in ("all", "ccsds")):
            ph = decode_ccsds_primary(raw)
            print(f"  [{ts}] CCSDS TLM  {src_ip}:{sport} -> {dst_ip}")
            print(f"         apid={ph.get('apid')} len={len(raw)}")

        elif dport == CCSDS_TLM_PORT and (args.filter in ("all", "telemetry")):
            print(f"  [{ts}] TLM JSON   {src_ip} -> {dst_ip}:{dport}")
            print(f"         data={raw[:80].decode('utf-8', errors='replace')}")

    elif TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        if (dport == GS_CMD_PORT or sport == GS_CMD_PORT) and (args.filter in ("all", "gs")):
            print(f"  [{ts}] GS CMD     {src_ip}:{sport} -> {dst_ip}:{dport}  {len(raw)}b")
            if len(raw) >= 4:
                print(f"         hex={raw.hex()[:40]}")

        elif (dport == GS_STATUS_PORT or sport == GS_STATUS_PORT) and (args.filter in ("all", "gs")):
            print(f"  [{ts}] GS STATUS  {src_ip}:{sport} -> {dst_ip}:{dport}")
            if raw:
                print(f"         {raw[:200].decode('utf-8', errors='replace')}")

        elif (dport == MOC_PORT or sport == MOC_PORT) and (args.filter in ("all", "moc")):
            first_line = raw[:100].decode("utf-8", errors="replace").split("\n")[0]
            print(f"  [{ts}] MOC HTTP   {src_ip}:{sport} -> {dst_ip}:{dport}  {first_line}")

    if args.pcap:
        pcap_buf.append(pkt)


def main():
    if not SCAPY_OK:
        print("Error: scapy not installed. Run: pip3 install scapy")
        print("Or: bash lab/scripts/install_tools.sh")
        return

    p = argparse.ArgumentParser(description="SpaceVE-1 network sniffer")
    p.add_argument("--iface",  default=None,    help="Interface to sniff (default: auto)")
    p.add_argument("--count",  type=int, default=0, help="Packets to capture (0=infinite)")
    p.add_argument("--pcap",   default=None,    help="Write packets to pcap file")
    p.add_argument("--filter", default="all",   choices=["all", "ccsds", "telemetry", "gs", "moc"],
                   help="Filter to one protocol type")
    args = p.parse_args()

    pcap_buf = []

    print(f"\n  SpaceVE-1 Signal Sniffer")
    print(f"  Interface: {args.iface or 'auto'}")
    print(f"  Filter: {args.filter}")
    print(f"  Watching: UDP {CCSDS_CMD_PORT}(ccsds), {CCSDS_TLM_PORT}(tlm), "
          f"TCP {GS_CMD_PORT}(gs), {GS_STATUS_PORT}(status), {MOC_PORT}(moc)")
    if args.pcap:
        print(f"  Writing pcap: {args.pcap}")
    print(f"  Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.iface,
            filter="ip",
            prn=lambda pkt: handle_packet(pkt, args, pcap_buf),
            count=args.count or 0,
            store=False,
        )
    except KeyboardInterrupt:
        print(f"\n  Captured {SEEN} packets.")
    except PermissionError:
        print("  Permission denied. Run with sudo.")
    finally:
        if args.pcap and pcap_buf:
            wrpcap(args.pcap, pcap_buf)
            print(f"  Wrote {len(pcap_buf)} packets to {args.pcap}")

    print()


if __name__ == "__main__":
    main()
