#!/usr/bin/env python3
"""
SpaceVE-1 fallback CCSDS command listener.

Used when the full cFS binary is not available (e.g., build failure).
Accepts CCSDS Space Packet Protocol commands on UDP 1234.
Sends simulated telemetry to the configured MOC address.

This stub implements the exact same authentication model as cFS CI_LAB:
  - No authentication
  - Checksum validation only
  - Any valid CCSDS packet is accepted and logged

CCSDS Primary Header format (6 bytes):
  Byte 0-1: Version(3) | Type(1) | SecHdr(1) | APID(11)
  Byte 2-3: SeqFlags(2) | SeqCount(14)
  Byte 4-5: DataLength (length of data field minus 1)

Command Secondary Header (2 bytes):
  Byte 0:   FunctionCode(7) | Reserved(1)
  Byte 1:   Checksum (XOR of all bytes starting from secondary header)
"""

import socket
import struct
import threading
import time
import os
import json

CMD_PORT = int(os.environ.get("CMD_LISTEN_PORT", 1234))
TLM_DEST = os.environ.get("TLM_DEST_IP", "192.168.60.11")
TLM_PORT = int(os.environ.get("TLM_DEST_PORT", 1235))
SATELLITE_ID = os.environ.get("SATELLITE_ID", "SpaceVE-1")

# Simulated satellite state
state = {
    "mode": "NOMINAL",
    "attitude_yaw": 0.0,
    "attitude_pitch": 0.0,
    "attitude_roll": 0.0,
    "camera_enabled": False,
    "downlink_enabled": False,
    "memory_dump_requested": False,
    "orbit_alt_km": float(os.environ.get("ORBIT_ALT_KM", 400)),
    "battery_pct": 87.3,
    "solar_power_w": 4.2,
    "cmd_count": 0,
    "cmd_err_count": 0,
    "uptime_s": 0,
}

# APID definitions (Application Process Identifiers)
# These map to specific cFS applications
APIDS = {
    0x001: "CFE_ES    (Executive Services)",
    0x002: "CFE_EVS   (Event Services)",
    0x003: "CFE_SB    (Software Bus)",
    0x004: "CFE_TBL   (Table Services)",
    0x005: "CFE_TIME  (Time Services)",
    0x180: "TO_LAB    (Telemetry Output)",
    0x1C3: "CI_LAB    (Command Ingest)",
    0x182: "SCH_LAB   (Scheduler)",
    0x200: "SAMPLE    (SpaceVE-1 Camera App)",
    0x201: "HK_APP    (Housekeeping)",
}

# Commands by APID and function code
COMMANDS = {
    (0x180, 0x00): "TO_LAB_NOP",
    (0x180, 0x01): "TO_LAB_RESET_CTRS",
    (0x180, 0x02): "TO_LAB_ENABLE_OUTPUT",
    (0x200, 0x00): "SAMPLE_NOP",
    (0x200, 0x01): "SAMPLE_RESET_CTRS",
    (0x200, 0x02): "SAMPLE_PROCESS",
    (0x200, 0x10): "CAMERA_ENABLE",
    (0x200, 0x11): "CAMERA_DISABLE",
    (0x200, 0x12): "CAMERA_POINT",
    (0x200, 0x20): "DOWNLINK_ENABLE",
    (0x200, 0x21): "DOWNLINK_DISABLE",
    (0x200, 0x30): "MEMORY_DUMP_ALL",
    (0x001, 0x00): "ES_NOP",
    (0x001, 0x04): "ES_RESTART_APP",
    (0x001, 0x06): "ES_RELOAD_APP",
    (0x001, 0x0B): "ES_WRITE_ALL_SYS_DATA",
}


def compute_ccsds_checksum(data: bytes) -> int:
    """
    Compute CCSDS command checksum.
    XOR of all bytes in secondary header + user data.
    Stored such that XOR of all bytes including checksum byte = 0xFF.
    """
    cksum = 0xFF
    for b in data:
        cksum ^= b
    return cksum


def validate_ccsds_packet(data: bytes) -> tuple:
    """
    Validate a CCSDS command packet.
    Returns (valid: bool, apid: int, func_code: int, error: str)
    """
    if len(data) < 8:
        return False, 0, 0, f"Packet too short: {len(data)} bytes (minimum 8)"

    # Parse primary header
    word0 = struct.unpack_from(">H", data, 0)[0]
    version = (word0 >> 13) & 0x7
    pkt_type = (word0 >> 12) & 0x1
    sec_hdr_flag = (word0 >> 11) & 0x1
    apid = word0 & 0x7FF

    word1 = struct.unpack_from(">H", data, 2)[0]
    seq_flags = (word1 >> 14) & 0x3
    seq_count = word1 & 0x3FFF

    data_len = struct.unpack_from(">H", data, 4)[0]
    expected_total = 6 + data_len + 1

    if len(data) != expected_total:
        return False, apid, 0, \
            f"Length mismatch: header says {expected_total} bytes, got {len(data)}"

    if pkt_type != 1:
        return False, apid, 0, "Not a command packet (Type bit = 0)"

    # Parse secondary header (command codes)
    func_code = (data[6] >> 1) & 0x7F
    stored_checksum = data[7]

    # Validate checksum
    computed = compute_ccsds_checksum(data[6:7])
    if computed != stored_checksum:
        return False, apid, func_code, \
            f"Checksum fail: stored=0x{stored_checksum:02X} computed=0x{computed:02X}"

    return True, apid, func_code, "OK"


def handle_command(data: bytes, src_addr: tuple):
    """Process a received CCSDS command packet."""
    valid, apid, func_code, msg = validate_ccsds_packet(data)

    src_ip, src_port = src_addr
    apid_name = APIDS.get(apid, f"UNKNOWN_APID_0x{apid:03X}")
    cmd_name = COMMANDS.get((apid, func_code), f"UNKNOWN_CMD_0x{func_code:02X}")

    if not valid:
        state["cmd_err_count"] += 1
        print(f"[CMD REJECT] src={src_ip}:{src_port} APID=0x{apid:03X} err={msg}")
        return

    state["cmd_count"] += 1
    print(f"[CMD ACCEPT] src={src_ip}:{src_port} APID=0x{apid:03X}({apid_name}) "
          f"FC=0x{func_code:02X}({cmd_name})")

    # Update state based on command
    if apid == 0x200:
        if func_code == 0x10:
            state["camera_enabled"] = True
            print(f"  -> Camera ENABLED")
        elif func_code == 0x11:
            state["camera_enabled"] = False
            print(f"  -> Camera DISABLED")
        elif func_code == 0x12 and len(data) >= 14:
            yaw = struct.unpack_from(">f", data, 8)[0]
            pitch = struct.unpack_from(">f", data, 12)[0]
            state["attitude_yaw"] = yaw
            state["attitude_pitch"] = pitch
            print(f"  -> Camera pointed to yaw={yaw:.1f} pitch={pitch:.1f}")
        elif func_code == 0x20:
            state["downlink_enabled"] = True
            print(f"  -> Downlink ENABLED — telemetry will include mission data")
        elif func_code == 0x21:
            state["downlink_enabled"] = False
            print(f"  -> Downlink DISABLED")
        elif func_code == 0x30:
            state["memory_dump_requested"] = True
            print(f"  -> MEMORY DUMP REQUESTED — this would exfiltrate all RAM contents")
    elif apid == 0x180 and func_code == 0x02:
        # TO_LAB_ENABLE_OUTPUT — reconfigure telemetry destination
        if len(data) >= 14:
            dest_ip_bytes = data[8:12]
            dest_ip = ".".join(str(b) for b in dest_ip_bytes)
            dest_port = struct.unpack_from(">H", data, 12)[0]
            print(f"  -> Telemetry redirected to {dest_ip}:{dest_port}")


def send_telemetry(sock: socket.socket):
    """Send simulated satellite telemetry to MOC at regular intervals."""
    while True:
        state["uptime_s"] += 1
        state["battery_pct"] = max(10.0, state["battery_pct"] - 0.001)

        tlm = {
            "satellite_id": SATELLITE_ID,
            "uptime_s": state["uptime_s"],
            "mode": state["mode"],
            "attitude": {
                "yaw_deg": state["attitude_yaw"],
                "pitch_deg": state["attitude_pitch"],
                "roll_deg": state["attitude_roll"],
            },
            "camera_enabled": state["camera_enabled"],
            "downlink_enabled": state["downlink_enabled"],
            "orbit_alt_km": state["orbit_alt_km"],
            "battery_pct": round(state["battery_pct"], 1),
            "solar_power_w": state["solar_power_w"],
            "cmd_count": state["cmd_count"],
            "cmd_err_count": state["cmd_err_count"],
            # Mission planning data intentionally included in cleartext telemetry
            # This is the operational misconfiguration from research_index.md section 1.4
            "mission_plan": {
                "next_target_lat": 17.3850,
                "next_target_lon": 78.4867,
                "next_capture_utc": "2026-09-26T04:22:00Z",
                "classification": "UNCLASSIFIED",
            } if state["downlink_enabled"] else None,
        }

        payload = json.dumps(tlm).encode("utf-8")
        try:
            sock.sendto(payload, (TLM_DEST, TLM_PORT))
        except Exception:
            pass

        time.sleep(1)


def main():
    print(f"SpaceVE-1 CCSDS Command Listener (stub mode)")
    print(f"Listening for commands on UDP 0.0.0.0:{CMD_PORT}")
    print(f"Sending telemetry to {TLM_DEST}:{TLM_PORT} every 1 second")
    print("")

    cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd_sock.bind(("0.0.0.0", CMD_PORT))

    tlm_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    tlm_thread = threading.Thread(target=send_telemetry, args=(tlm_sock,), daemon=True)
    tlm_thread.start()

    print("Waiting for commands...")
    while True:
        try:
            data, addr = cmd_sock.recvfrom(4096)
            handle_command(data, addr)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
