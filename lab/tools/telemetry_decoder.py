#!/usr/bin/env python3
"""
telemetry_decoder.py -- SpaceVE-1 Telemetry Decoder
SpaceVE-1 Lab Attack Tool

Decodes and displays satellite telemetry from the MOC.

Modes:
  --mode status  : Poll MOC /status (no auth required — shows tracked satellites)
  --mode udp     : Listen on UDP 5000 for raw binary CCSDS TM from satellites
                   Must run from inside Docker spacelab-tlm network (192.168.62.0/24)

The MOC WebSocket (ws://localhost:8765) is the main TLM stream.
Use the browser dashboard at http://localhost:8080 for authenticated TLM viewing.

Usage:
  python3 telemetry_decoder.py --mode status
  python3 telemetry_decoder.py --mode udp

Common Beginner Mistakes:
  - /api/telemetry does not exist. Use /status for basic MOC health.
  - UDP port 5000 is NOT exposed to the host (only 8080 and 8765 are).
    Run --mode udp from inside a Docker container on spacelab-tlm network.
  - Binary CCSDS TM is not JSON. The 36-byte payload uses struct format ">8sHHHhHHhhHhhBBH".
"""

import argparse
import socket
import struct
import time

MOC_URL = "http://localhost:8080"
TLM_UDP_PORT = 5000

TLM_FMT  = ">8sHHHhHHhhHhhBBH"
TLM_SIZE = struct.calcsize(TLM_FMT)  # 36 bytes

MODES = {0: "NOMINAL", 1: "SAFE", 2: "CAMERA_ON", 3: "DOWNLINK_ACTIVE", 4: "REBOOT"}
APID_TO_SAT = {0x200: "SpaceVE-1A", 0x201: "SpaceVE-1B", 0x202: "SpaceVE-1C"}


def decode_ccsds_tlm(data: bytes) -> dict | None:
    if len(data) < 6:
        return None
    w0, w1, pkt_data_len = struct.unpack(">HHH", data[:6])
    if (w0 >> 12) & 1:
        return None  # TC not TM
    apid      = w0 & 0x7FF
    seq_count = w1 & 0x3FFF
    payload   = data[6:6 + pkt_data_len + 1]
    sat_id    = APID_TO_SAT.get(apid)
    if not sat_id:
        return None
    if len(payload) < TLM_SIZE:
        return None
    (t_cds, mode_c, bat_soc_pm, bat_mv, solar_ma,
     cpu_pm, mem_pm, lat_cdeg, lon_cdeg, alt_dm,
     t_bat, t_xpdr, flags, cmd_code, cmd_count) = struct.unpack_from(TLM_FMT, payload)
    return {
        "satellite_id":    sat_id,
        "apid":            f"0x{apid:03X}",
        "seq_count":       seq_count,
        "mode":            MODES.get(mode_c, f"UNKNOWN_{mode_c}"),
        "battery_soc_pct": round(bat_soc_pm / 10.0, 1),
        "battery_v":       round(bat_mv / 1000.0, 3),
        "solar_a":         round(solar_ma / 1000.0, 3),
        "cpu_pct":         round(cpu_pm / 10.0, 1),
        "mem_pct":         round(mem_pm / 10.0, 1),
        "lat":             round(lat_cdeg / 100.0, 4),
        "lon":             round(lon_cdeg / 100.0, 4),
        "alt_km":          round(alt_dm / 10.0, 1),
        "temp_battery_c":  round(t_bat / 100.0, 2),
        "temp_xpdr_c":     round(t_xpdr / 100.0, 2),
        "eclipse":                  bool(flags & 1),
        "camera_on":                bool(flags & 2),
        "downlink_enabled":         bool(flags & 4),
        "memory_dump":              bool(flags & 8),
        "mission_downlink_enabled": bool(flags & 16),
        "cmd_count":       cmd_count,
    }


def decode_pretty(tlm: dict, source: str = ""):
    ts = time.strftime("%H:%M:%S")
    print(f"\n  [{ts}] {tlm.get('satellite_id', '?')} APID={tlm.get('apid')} seq={tlm.get('seq_count')}{' from ' + source if source else ''}")
    print(f"  {'-' * 50}")
    for k, v in tlm.items():
        if k in ("satellite_id", "apid"):
            continue
        print(f"    {k:<30} {v}")
    if tlm.get("mission_downlink_enabled"):
        print()
        print(f"  *** MISSION DOWNLINK ACTIVE ***")
        print(f"  *** Mission data is flowing in WS TLM stream — subscribe to ws://localhost:8765 ***")


def mode_status(args):
    try:
        import urllib.request
        url = f"{MOC_URL}/status"
        print(f"\n  Polling MOC status at {url}")
        print(f"  No authentication required.\n")
        count = 0
        while args.count == 0 or count < args.count:
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    import json
                    data = json.loads(r.read().decode())
                    ts = time.strftime("%H:%M:%S")
                    print(f"  [{ts}] MOC status:")
                    print(f"    moc_id:             {data.get('moc_id')}")
                    print(f"    uptime_s:           {data.get('uptime_s')}")
                    print(f"    satellites_tracked: {data.get('satellites_tracked')}")
                    print(f"    ws_clients:         {data.get('ws_clients')}")
            except Exception as e:
                print(f"  Error: {e}")
            count += 1
            if args.count == 0 or count < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    print()


def mode_udp(args):
    print(f"\n  Listening on UDP {TLM_UDP_PORT} for binary CCSDS TM from satellites")
    print(f"  Note: port {TLM_UDP_PORT} is NOT exposed to host — run from inside Docker spacelab-tlm network.")
    print(f"  Packet format: 6-byte CCSDS primary header + 36-byte TLM payload.\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", TLM_UDP_PORT))
    sock.settimeout(5.0)
    count = 0
    try:
        while args.count == 0 or count < args.count:
            try:
                data, addr = sock.recvfrom(4096)
                tlm = decode_ccsds_tlm(data)
                if tlm:
                    decode_pretty(tlm, source=addr[0])
                else:
                    print(f"  Non-TLM packet from {addr[0]} ({len(data)}B): {data[:16].hex()}")
                count += 1
            except socket.timeout:
                print(f"  [{time.strftime('%H:%M:%S')}] Waiting for telemetry...")
    except KeyboardInterrupt:
        pass
    sock.close()
    print()


def main():
    p = argparse.ArgumentParser(description="SpaceVE-1 telemetry decoder")
    p.add_argument("--mode", choices=["status", "udp"], default="status",
                   help="status: poll MOC /status; udp: raw binary CCSDS listener (inside Docker)")
    p.add_argument("--count", type=int, default=5, help="Iterations (0=infinite)")
    p.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds (status mode)")
    args = p.parse_args()

    if args.mode == "status":
        mode_status(args)
    elif args.mode == "udp":
        mode_udp(args)


if __name__ == "__main__":
    main()
