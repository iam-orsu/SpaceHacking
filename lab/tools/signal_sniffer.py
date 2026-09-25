#!/usr/bin/env python3
"""
signal_sniffer.py - SpaceVE-1 Network Traffic Sniffer
SpaceVE-1 Lab Attack Tool

Passively captures all lab traffic at the network level and decodes:
  - CCSDS command packets (UDP 1234) - binary PUS-C TC[128,1] format
  - Satellite telemetry (UDP 5000) - binary CCSDS TM, 36-byte payload
  - Ground station traffic (TCP 4820) - plaintext operator commands
  - MOC web traffic (TCP 8080)

Uses scapy for raw packet capture. Must be run as root on the host with
access to the Docker bridge interface, OR from inside a Docker container.

For the Docker bridge interface names:
  ip link show | grep br-
  docker network inspect lab_spacelab-cmd

Common Beginner Mistakes:
  - Running without sudo gives "Permission denied" on raw sockets
  - The Docker bridge interface name changes with the compose project name
  - Use --filter to focus on one protocol to reduce noise
  - Telemetry from satellites goes to UDP 5000 (MOC TLM port), not 1235
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
CCSDS_TLM_PORT  = 5000   # MOC UDP TLM port
GS_CMD_PORT     = 4820
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
    """Decode PUS-C TC secondary header (bytes 6-12)."""
    if len(data) < 13:
        return {}
    import struct
    pus_ver_ack = data[6]
    svc_type    = data[7]
    svc_subtype = data[8]
    source_id   = struct.unpack(">H", data[9:11])[0]
    func_code   = data[11]
    checksum    = data[12]
    ck = 0xFF
    for b in (pus_ver_ack, svc_type, svc_subtype, (source_id >> 8) & 0xFF, source_id & 0xFF, func_code):
        ck ^= b
    return {
        "func":           f"0x{func_code:02X}",
        "svc":            f"{svc_type}/{svc_subtype}",
        "checksum_valid": checksum == ck,
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

        elif dport == CCSDS_TLM_PORT and (args.filter in ("all", "telemetry")):
            ph = decode_ccsds_primary(raw)
            print(f"  [{ts}] CCSDS TLM  {src_ip} -> {dst_ip}:{dport}")
            print(f"         apid={ph.get('apid')} len={len(raw)}")

    elif TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        if (dport == GS_CMD_PORT or sport == GS_CMD_PORT) and (args.filter in ("all", "gs")):
            print(f"  [{ts}] GS CMD     {src_ip}:{sport} -> {dst_ip}:{dport}  {len(raw)}b")
            if raw:
                txt = raw[:200].decode("utf-8", errors="replace").strip()
                print(f"         {txt}")

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
    print(f"  Watching: UDP {CCSDS_CMD_PORT}(ccsds cmd), {CCSDS_TLM_PORT}(tlm), "
          f"TCP {GS_CMD_PORT}(gs), {MOC_PORT}(moc)")
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
