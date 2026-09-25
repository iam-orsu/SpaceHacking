"""
CCSDS Space Packet telemetry parser.

Handles:
  - TM packets from satellites (binary, 32-byte payload)
  - Mission data packets (APID = primary + 0x100, JSON payload, cleartext — intentional)
"""
import json
import struct
from datetime import datetime, timezone

TLM_FMT  = ">IHHHhHHhhHhhBBH"
TLM_SIZE = struct.calcsize(TLM_FMT)  # 32

APID_TO_SAT = {0x200: "SpaceVE-1A", 0x201: "SpaceVE-1B", 0x202: "SpaceVE-1C"}
MISSION_APID_OFFSET = 0x100

MODES = {0: "NOMINAL", 1: "SAFE", 2: "CAMERA_ON", 3: "DOWNLINK_ACTIVE", 4: "REBOOT"}


def parse_tm_packet(data: bytes) -> dict | None:
    if len(data) < 6:
        return None
    w0, w1, pkt_data_len = struct.unpack(">HHH", data[:6])
    if (w0 >> 12) & 1:
        return None  # TC not TM
    apid      = w0 & 0x7FF
    seq_count = w1 & 0x3FFF
    payload   = data[6:6 + pkt_data_len + 1]

    if apid in APID_TO_SAT:
        if len(payload) < TLM_SIZE:
            return None
        return _decode_tlm(APID_TO_SAT[apid], apid, seq_count, payload)

    for primary, sat_id in APID_TO_SAT.items():
        if apid == (primary + MISSION_APID_OFFSET) & 0x7FF:
            return _decode_mission(sat_id, seq_count, payload)

    return None


def _decode_tlm(satellite_id, apid, seq_count, payload) -> dict:
    (t, mode_c, bat_soc_pm, bat_mv, solar_ma,
     cpu_pm, mem_pm, lat_cdeg, lon_cdeg, alt_dm,
     t_bat, t_xpdr, flags, cmd_code, cmd_count) = struct.unpack_from(TLM_FMT, payload)
    return {
        "packet_type":     "tlm",
        "satellite_id":    satellite_id,
        "apid":            apid,
        "seq_count":       seq_count,
        "ts":              datetime.now(timezone.utc).isoformat(),
        "mission_time_s":  t,
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
        "eclipse":         bool(flags & 1),
        "camera_on":       bool(flags & 2),
        "downlink_enabled":bool(flags & 4),
        "memory_dump":     bool(flags & 8),
        "last_cmd_code":   cmd_code,
        "cmd_count":       cmd_count,
    }


def _decode_mission(satellite_id, seq_count, payload) -> dict | None:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return {
        "packet_type":  "mission_data",
        "satellite_id": satellite_id,
        "seq_count":    seq_count,
        "ts":           datetime.now(timezone.utc).isoformat(),
        **data,
    }
