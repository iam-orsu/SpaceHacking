#!/usr/bin/env python3
"""
SpaceVE-1 Satellite Simulator

Realistic LEO satellite simulation:
  - Keplerian orbital mechanics (position, ground track, eclipse)
  - Subsystem simulation (power, thermal, attitude, comms)
  - CCSDS Space Packet Protocol command handling (UDP)
  - Telemetry generation and transmission (UDP to MOC)
  - Configurable time warp for accelerated lab sessions

Environment variables (set via docker-compose.yml):
  SATELLITE_ID      - A, B, or C
  SATELLITE_NAME    - Human name (SpaceVE-1A)
  SAT_APID          - APID hex (0x200, 0x201, 0x202)
  INCLINATION       - Orbital inclination in degrees (51.6 for ISS-like)
  RAAN              - Right ascension of ascending node in degrees
  MEAN_ANOMALY      - Initial mean anomaly in degrees
  CMD_PORT          - UDP port for CCSDS commands (1234)
  TLM_HOST          - Where to send telemetry (192.168.62.10 = MOC tlm segment)
  TLM_PORT          - MOC telemetry listener port (5000)
  TIME_WARP         - Simulation speed multiplier (60 = 1 orbit per ~92 seconds)

Attack surface (intentional misconfigurations):
  - CCSDS checksum validates packet integrity but NOT authenticity
  - No source IP verification on command port
  - Any valid CCSDS packet from any host in 192.168.61.0/24 is executed
  - Telemetry includes mission_plan data when downlink_enabled=True
"""

import json
import math
import os
import random
import socket
import struct
import threading
import time

# -----------------------------------------------------------------
# Configuration from environment
# -----------------------------------------------------------------
SATELLITE_ID   = os.environ.get("SATELLITE_ID", "A")
SATELLITE_NAME = os.environ.get("SATELLITE_NAME", f"SpaceVE-1{SATELLITE_ID}")
SAT_APID_STR   = os.environ.get("SAT_APID", "0x200")
APID           = int(SAT_APID_STR, 16) if SAT_APID_STR.startswith("0x") else int(SAT_APID_STR)
INCLINATION    = float(os.environ.get("INCLINATION", "51.6"))
RAAN           = float(os.environ.get("RAAN", "0.0"))
M0             = float(os.environ.get("MEAN_ANOMALY", "0.0"))
CMD_PORT       = int(os.environ.get("CMD_PORT", "1234"))
TLM_HOST       = os.environ.get("TLM_HOST", "192.168.62.10")
TLM_PORT       = int(os.environ.get("TLM_PORT", "5000"))
TIME_WARP      = float(os.environ.get("TIME_WARP", "1.0"))

# -----------------------------------------------------------------
# Orbital constants
# -----------------------------------------------------------------
ALTITUDE_KM  = 400.0
RE           = 6371.0        # Earth radius km
MU           = 398600.4418   # km^3/s^2  Earth gravitational parameter
A            = RE + ALTITUDE_KM

# Orbital period at 400km
PERIOD       = 2 * math.pi * math.sqrt(A**3 / MU)   # seconds (≈5545s for 400km)
MEAN_MOTION  = 2 * math.pi / PERIOD                  # rad/s

# Ground stations (lat, lon in degrees) - used for elevation angle calc
GROUND_STATIONS = {
    "GS-ALPHA": {"lat": 28.5,  "lon": -80.5},  # Cape Canaveral area
    "GS-BETA":  {"lat": 51.5,  "lon": -0.1},   # UK
    "GS-GAMMA": {"lat": -33.9, "lon": 151.2},  # Sydney
}
MIN_ELEVATION_DEG = 5.0  # minimum elevation for contact

# Simulation epoch
EPOCH = time.time()

# -----------------------------------------------------------------
# Satellite state (the attack surface)
# -----------------------------------------------------------------
state = {
    "satellite_id": SATELLITE_NAME,
    "apid": APID,
    "mode": "NOMINAL",
    # Payload
    "camera_enabled": False,
    "downlink_enabled": False,
    "memory_dump_active": False,
    # Power
    "battery_v": 28.5,
    "battery_soc": 95.0,
    "solar_current_a": 4.2,
    "power_consumption_w": 45.0,
    # Thermal (Celsius)
    "temp_battery_c": 12.0,
    "temp_transponder_c": 35.0,
    "temp_payload_c": 22.0,
    "temp_structure_c": 18.0,
    # Attitude
    "attitude_mode": "NADIR_POINTING",
    "quat_w": 1.0, "quat_x": 0.0, "quat_y": 0.0, "quat_z": 0.0,
    "rate_x_mDeg_s": 0.12,
    "rate_y_mDeg_s": 0.08,
    "rate_z_mDeg_s": 0.15,
    # Comms
    "uplink_rssi_dbm": -118.5,
    "downlink_margin_db": 14.2,
    "bit_rate_bps": 9600,
    "doppler_hz": 0.0,
    # Orbital (updated continuously)
    "lat": 0.0,
    "lon": 0.0,
    "alt_km": ALTITUDE_KM,
    "eclipse": False,
    "ground_track_velocity_ms": 7661.0,
    # Mission (leaked when downlink enabled — intentional)
    "mission_plan": {
        "mission_id": f"OSA-2024-{SATELLITE_ID}03",
        "classification": "CONFIDENTIAL",
        "target_name": f"REGION-{SATELLITE_ID}7",
        "lat": 33.7 if SATELLITE_ID == "A" else (51.2 if SATELLITE_ID == "B" else -35.1),
        "lon": 73.0 if SATELLITE_ID == "A" else (9.8 if SATELLITE_ID == "B" else 147.3),
        "window_start": "2024-06-15T02:30:00Z",
        "window_end": "2024-06-15T02:42:00Z",
        "payload_mode": "IMAGING_HIGH_RES",
    },
    # Health
    "uptime_s": 0,
    "cpu_load_pct": 23.5,
    "memory_used_pct": 41.2,
    "commands_received": 0,
    "last_command": None,
    "last_command_ts": None,
    # Contact
    "in_contact_with": [],
    "contact_windows": [],
}
state_lock = threading.Lock()

# -----------------------------------------------------------------
# Orbital mechanics
# -----------------------------------------------------------------

def sim_time() -> float:
    """Current simulated elapsed time (applies TIME_WARP)."""
    return (time.time() - EPOCH) * TIME_WARP


def compute_orbital_position(sim_elapsed: float) -> dict:
    """
    Compute satellite position using simplified Keplerian orbit.
    Returns dict with lat, lon, alt_km, eclipse, M_deg.
    """
    M = math.radians(M0) + MEAN_MOTION * sim_elapsed
    nu = M  # circular orbit: E = M = nu

    # Position in orbital plane (perifocal frame)
    x_orb = A * math.cos(nu)
    y_orb = A * math.sin(nu)

    # Rotate to ECI: Rz(-RAAN) * Rx(-i)
    i_r    = math.radians(INCLINATION)
    raan_r = math.radians(RAAN)

    cos_r = math.cos(raan_r); sin_r = math.sin(raan_r)
    cos_i = math.cos(i_r);    sin_i = math.sin(i_r)

    x_eci = cos_r * x_orb - sin_r * cos_i * y_orb
    y_eci = sin_r * x_orb + cos_r * cos_i * y_orb
    z_eci = sin_i * y_orb

    # ECI → ECEF: rotate by GMST
    GMST_deg = (280.461 + 360.9856473 * (sim_elapsed / 86400.0)) % 360
    GMST_rad = math.radians(GMST_deg)
    cos_g = math.cos(GMST_rad); sin_g = math.sin(GMST_rad)

    x_ecef =  cos_g * x_eci + sin_g * y_eci
    y_ecef = -sin_g * x_eci + cos_g * y_eci
    z_ecef =  z_eci

    # ECEF → lat/lon/alt
    r_xy  = math.sqrt(x_ecef**2 + y_ecef**2)
    lat   = math.degrees(math.atan2(z_ecef, r_xy))
    lon   = math.degrees(math.atan2(y_ecef, x_ecef))
    alt   = math.sqrt(x_ecef**2 + y_ecef**2 + z_ecef**2) - RE

    # Eclipse: simplified — sun is at fixed ecliptic position in ECI
    # Sun longitude in ECI precesses ~1°/day from vernal equinox
    sun_lon_eci = math.radians((280.461 + 0.9856474 * sim_elapsed / 86400.0) % 360)
    sun_x = math.cos(sun_lon_eci)
    sun_y = math.sin(sun_lon_eci)
    # Shadow cylinder radius = RE, check if satellite is in shadow
    sat_unit = (x_eci / A, y_eci / A, z_eci / A)
    sun_dot = sat_unit[0] * sun_x + sat_unit[1] * sun_y  # project onto sun direction
    perp_sq = 1.0 - sun_dot**2
    in_shadow_cone = (sun_dot < 0) and (math.sqrt(max(0, perp_sq)) < RE / A)
    eclipse = in_shadow_cone

    return {
        "lat":     round(lat, 4),
        "lon":     round(lon, 4),
        "alt_km":  round(alt, 2),
        "eclipse": eclipse,
        "M_deg":   round(math.degrees(M) % 360, 2),
    }


def compute_elevation(sat_lat: float, sat_lon: float, sat_alt_km: float,
                       gs_lat: float, gs_lon: float) -> float:
    """Elevation angle (degrees) from ground station to satellite."""
    sl = math.radians(sat_lat); sl2 = math.radians(sat_lon)
    gl = math.radians(gs_lat);  gl2 = math.radians(gs_lon)

    r_sat = RE + sat_alt_km
    xs = r_sat * math.cos(sl) * math.cos(sl2)
    ys = r_sat * math.cos(sl) * math.sin(sl2)
    zs = r_sat * math.sin(sl)

    xg = RE * math.cos(gl) * math.cos(gl2)
    yg = RE * math.cos(gl) * math.sin(gl2)
    zg = RE * math.sin(gl)

    rx = xs - xg; ry = ys - yg; rz = zs - zg
    r_range = math.sqrt(rx**2 + ry**2 + rz**2)

    ux = math.cos(gl) * math.cos(gl2)
    uy = math.cos(gl) * math.sin(gl2)
    uz = math.sin(gl)

    dot = (rx * ux + ry * uy + rz * uz) / r_range
    return round(math.degrees(math.asin(max(-1.0, min(1.0, dot)))), 2)


def compute_contact_windows(lookahead_sim_s: float = 6000.0) -> list:
    """Compute upcoming contact windows for all ground stations."""
    now = sim_time()
    windows = []
    step = 30.0  # seconds of sim time

    for gs_name, gs in GROUND_STATIONS.items():
        in_contact = False
        window_start = None

        for t_offset in range(0, int(lookahead_sim_s), int(step)):
            t = now + t_offset
            orb = compute_orbital_position(t)
            el = compute_elevation(orb["lat"], orb["lon"], orb["alt_km"],
                                   gs["lat"], gs["lon"])
            if el >= MIN_ELEVATION_DEG:
                if not in_contact:
                    in_contact = True
                    window_start = t
                    max_el = el
                else:
                    max_el = max(max_el, el)
            else:
                if in_contact:
                    in_contact = False
                    windows.append({
                        "gs": gs_name,
                        "aos_sim_offset_s": int(window_start - now),
                        "los_sim_offset_s": int(t - now),
                        "duration_s": int(t - window_start),
                        "max_elevation_deg": max_el,
                    })
                    if len(windows) >= 10:
                        return windows
        if in_contact:
            windows.append({
                "gs": gs_name,
                "aos_sim_offset_s": int(window_start - now),
                "los_sim_offset_s": int(lookahead_sim_s),
                "duration_s": int(lookahead_sim_s - (window_start - now)),
                "max_elevation_deg": max_el,
            })

    return sorted(windows, key=lambda w: w["aos_sim_offset_s"])


# -----------------------------------------------------------------
# Subsystem simulation
# -----------------------------------------------------------------

def update_power(eclipse: bool, dt_sim: float):
    """Update power subsystem (dt_sim = simulated seconds elapsed)."""
    dt_h = dt_sim / 3600.0

    if eclipse:
        state["solar_current_a"] = 0.0
        # Battery discharges at load current
        load_a = state["power_consumption_w"] / max(state["battery_v"], 25.0)
        delta_ah = load_a * dt_h
        # 30 Ah battery
        state["battery_soc"] = max(0.0, state["battery_soc"] - delta_ah / 30.0 * 100)
    else:
        # Solar array generates ~4.2A at full illumination
        solar_a = 4.2 * (0.95 + 0.05 * math.sin(time.time() / 100))
        state["solar_current_a"] = round(solar_a, 3)
        load_a = state["power_consumption_w"] / max(state["battery_v"], 25.0)
        net_a = solar_a - load_a
        if net_a > 0:
            state["battery_soc"] = min(100.0, state["battery_soc"] + net_a * dt_h / 30.0 * 100)
        else:
            state["battery_soc"] = max(0.0, state["battery_soc"] + net_a * dt_h / 30.0 * 100)

    # Battery voltage: 25V (empty) to 29V (full)
    state["battery_v"] = round(25.0 + (state["battery_soc"] / 100.0) * 4.0, 3)
    state["battery_soc"] = round(state["battery_soc"], 2)


def update_thermal(eclipse: bool, dt_sim: float):
    """Update thermal model with noise and eclipse effects."""
    def drift(val, target, tau=1000.0, noise=0.05):
        return val + (target - val) * dt_sim / tau + random.gauss(0, noise)

    target_batt = -5.0 if eclipse else 15.0
    target_xpdr = 30.0 + (8.0 if state["downlink_enabled"] else 0.0)
    target_pay  = 20.0 + (5.0 if state["camera_enabled"] else 0.0)

    state["temp_battery_c"]     = round(drift(state["temp_battery_c"],   target_batt),  1)
    state["temp_transponder_c"] = round(drift(state["temp_transponder_c"], target_xpdr), 1)
    state["temp_payload_c"]     = round(drift(state["temp_payload_c"],    target_pay),  1)


def update_attitude(dt_sim: float):
    """Simulate small attitude perturbations around NADIR_POINTING."""
    # Add tiny drifts to angular rates (millidegrees/sec)
    for ax in ("rate_x_mDeg_s", "rate_y_mDeg_s", "rate_z_mDeg_s"):
        state[ax] = round(state[ax] + random.gauss(0, 0.01), 4)
        state[ax] = max(-2.0, min(2.0, state[ax]))  # clamp


def update_comms(contact_gs: list):
    """Update comms parameters based on ground station visibility."""
    if contact_gs:
        # In contact: good link
        state["uplink_rssi_dbm"]   = round(random.gauss(-118.0, 2.0), 1)
        state["downlink_margin_db"] = round(random.gauss(14.0, 1.0), 1)
        state["bit_rate_bps"]      = 9600
        # Doppler: approx ±10 kHz at UHF for LEO pass
        max_doppler = 50000  # Hz at UHF
        doppler_frac = random.gauss(0, 0.3)  # normalized
        state["doppler_hz"] = round(max_doppler * doppler_frac, 1)
    else:
        state["uplink_rssi_dbm"]   = -140.0
        state["downlink_margin_db"] = -5.0
        state["bit_rate_bps"]      = 0
        state["doppler_hz"]        = 0.0


# -----------------------------------------------------------------
# CCSDS packet handling
# -----------------------------------------------------------------

def ccsds_checksum(sec_byte0: int, user_data: bytes) -> int:
    ck = 0xFF ^ sec_byte0
    for b in user_data:
        ck ^= b
    return ck


def validate_ccsds(data: bytes) -> tuple:
    """Returns (valid: bool, func_code: int, user_data: bytes)."""
    if len(data) < 8:
        return False, 0, b""
    w0, w1, dlen = struct.unpack(">HHH", data[:6])
    pkt_type = (w0 >> 12) & 1
    if not pkt_type:  # must be command (type=1)
        return False, 0, b""
    pkt_apid = w0 & 0x7FF
    # Accept packets addressed to this satellite's APID or broadcast (0x7FF)
    if pkt_apid != (APID & 0x7FF) and pkt_apid != 0x7FF:
        return False, 0, b""
    sec_byte0 = data[6]
    stored_ck = data[7]
    user_data = data[8:]
    if ccsds_checksum(sec_byte0, user_data) != stored_ck:
        return False, 0, b""
    func_code = (sec_byte0 >> 1) & 0x7F
    return True, func_code, user_data


FUNC_NAMES = {
    0x00: "NOP",
    0x01: "CAMERA_ON",
    0x02: "CAMERA_OFF",
    0x03: "DOWNLINK_ENABLE",
    0x04: "DOWNLINK_DISABLE",
    0x05: "MEMORY_DUMP",
    0x06: "REBOOT",
    0x07: "SAFING_MODE",
    0x08: "NOMINAL_MODE",
    0x09: "ATTITUDE_SLEW",
    0x0A: "PAYLOAD_POWER_OFF",
}

# ---- Binary CCSDS TM payload format (32 bytes, big-endian) ----
# I  mission_time_s  H  mode  H  bat_soc_pm  H  bat_mv  h  solar_ma
# H  cpu_pm  H  mem_pm  h  lat_cdeg  h  lon_cdeg  H  alt_dm
# h  temp_bat_cdeg  h  temp_xpdr_cdeg  B  flags  B  last_cmd_fc  H  cmd_count
TLM_FMT  = ">IHHHhHHhhHhhBBH"
TLM_SIZE = struct.calcsize(TLM_FMT)  # 32 bytes

MODE_CODES          = {"NOMINAL": 0, "SAFE": 1, "CAMERA_ON": 2, "DOWNLINK_ACTIVE": 3, "REBOOT": 4}
MISSION_APID_OFFSET = 0x100  # satellite APID + 0x100 = mission-data TM APID


def execute_command(func_code: int, user_data: bytes, src_ip: str):
    """Execute a CCSDS command. NO source IP verification (intentional)."""
    with state_lock:
        state["commands_received"] += 1
        state["last_command"] = FUNC_NAMES.get(func_code, f"UNKNOWN_0x{func_code:02X}")
        state["last_command_ts"] = time.time()

        if func_code == 0x00:   # NOP
            pass
        elif func_code == 0x01:  # CAMERA_ON
            state["camera_enabled"] = True
            state["power_consumption_w"] += 15.0
            print(f"[{SATELLITE_NAME}] CAMERA ENABLED by {src_ip} (no auth required)")
        elif func_code == 0x02:  # CAMERA_OFF
            state["camera_enabled"] = False
            state["power_consumption_w"] = max(45.0, state["power_consumption_w"] - 15.0)
        elif func_code == 0x03:  # DOWNLINK_ENABLE
            state["downlink_enabled"] = True
            print(f"[{SATELLITE_NAME}] DOWNLINK ENABLED by {src_ip} — mission_plan now in telemetry!")
        elif func_code == 0x04:  # DOWNLINK_DISABLE
            state["downlink_enabled"] = False
        elif func_code == 0x05:  # MEMORY_DUMP
            state["memory_dump_active"] = True
            print(f"[{SATELLITE_NAME}] MEMORY DUMP triggered by {src_ip}")
        elif func_code == 0x06:  # REBOOT
            state["mode"] = "REBOOT"
            print(f"[{SATELLITE_NAME}] *** REBOOT COMMANDED by {src_ip} ***")
            # Simulate reboot in 5 seconds
            def do_reboot():
                time.sleep(5)
                with state_lock:
                    state["uptime_s"] = 0
                    state["camera_enabled"] = False
                    state["downlink_enabled"] = False
                    state["memory_dump_active"] = False
                    state["mode"] = "NOMINAL"
            threading.Thread(target=do_reboot, daemon=True).start()
        elif func_code == 0x07:  # SAFING_MODE
            state["mode"] = "SAFE"
            state["camera_enabled"] = False
            state["downlink_enabled"] = False
            state["power_consumption_w"] = 30.0
            print(f"[{SATELLITE_NAME}] SAFE MODE activated by {src_ip}")
        elif func_code == 0x08:  # NOMINAL_MODE
            state["mode"] = "NOMINAL"
            state["power_consumption_w"] = 45.0
        elif func_code == 0x0A:  # PAYLOAD_POWER_OFF
            state["camera_enabled"] = False
            state["downlink_enabled"] = False
            state["power_consumption_w"] = 30.0


def build_telemetry() -> dict:
    """Build the current telemetry snapshot."""
    with state_lock:
        s = dict(state)

    tlm = {
        "ts": time.time(),
        "satellite_id": s["satellite_id"],
        "apid": s["apid"],
        "mode": s["mode"],
        "power": {
            "battery_v": s["battery_v"],
            "battery_soc_pct": s["battery_soc"],
            "solar_current_a": s["solar_current_a"],
            "power_consumption_w": s["power_consumption_w"],
        },
        "thermal": {
            "battery_c": s["temp_battery_c"],
            "transponder_c": s["temp_transponder_c"],
            "payload_c": s["temp_payload_c"],
            "structure_c": s["temp_structure_c"],
        },
        "attitude": {
            "mode": s["attitude_mode"],
            "quat": [round(s["quat_w"], 5), round(s["quat_x"], 5),
                     round(s["quat_y"], 5), round(s["quat_z"], 5)],
            "rate_x_mDeg_s": s["rate_x_mDeg_s"],
            "rate_y_mDeg_s": s["rate_y_mDeg_s"],
            "rate_z_mDeg_s": s["rate_z_mDeg_s"],
        },
        "orbital": {
            "lat": s["lat"],
            "lon": s["lon"],
            "alt_km": s["alt_km"],
            "eclipse": s["eclipse"],
            "period_s": round(PERIOD, 1),
            "time_warp": TIME_WARP,
        },
        "comms": {
            "uplink_rssi_dbm": s["uplink_rssi_dbm"],
            "downlink_margin_db": s["downlink_margin_db"],
            "bit_rate_bps": s["bit_rate_bps"],
            "doppler_hz": s["doppler_hz"],
            "in_contact_with": s["in_contact_with"],
        },
        "payload": {
            "camera_enabled": s["camera_enabled"],
            "downlink_enabled": s["downlink_enabled"],
            "memory_dump_active": s["memory_dump_active"],
        },
        "health": {
            "uptime_s": int(s["uptime_s"]),
            "cpu_load_pct": round(s["cpu_load_pct"] + random.gauss(0, 1), 1),
            "memory_used_pct": round(s["memory_used_pct"] + random.gauss(0, 0.5), 1),
            "commands_received": s["commands_received"],
            "last_command": s["last_command"],
        },
        "contact_windows": s["contact_windows"],
    }

    # Mission plan only in telemetry when downlink enabled (intentional leak)
    if s["downlink_enabled"]:
        tlm["mission_plan"] = s["mission_plan"]

    return tlm


# -----------------------------------------------------------------
# Main loops
# -----------------------------------------------------------------

def orbital_loop():
    """Update orbital position and subsystem state every real second."""
    prev_t = sim_time()
    while True:
        time.sleep(1.0 / TIME_WARP)  # real-time sleep to advance 1 sim-second

        now = sim_time()
        dt  = now - prev_t
        prev_t = now

        orb = compute_orbital_position(now)

        with state_lock:
            state["lat"]     = orb["lat"]
            state["lon"]     = orb["lon"]
            state["alt_km"]  = orb["alt_km"]
            state["eclipse"] = orb["eclipse"]
            state["uptime_s"] += dt

        update_power(orb["eclipse"], dt)
        update_thermal(orb["eclipse"], dt)
        update_attitude(dt)

        # Check which ground stations are in view
        contact = []
        for gs_name, gs in GROUND_STATIONS.items():
            el = compute_elevation(orb["lat"], orb["lon"], orb["alt_km"],
                                   gs["lat"], gs["lon"])
            if el >= MIN_ELEVATION_DEG:
                contact.append(gs_name)

        update_comms(contact)

        with state_lock:
            state["in_contact_with"] = contact

        # Recompute contact windows every 60 real seconds
        if int(state["uptime_s"]) % 60 == 0:
            windows = compute_contact_windows()
            with state_lock:
                state["contact_windows"] = windows


def build_ccsds_tm(apid: int, seq_count: int, payload: bytes) -> bytes:
    """Wrap payload in a CCSDS TM Space Packet primary header (6 bytes)."""
    word0 = apid & 0x7FF              # Version=0, Type=0 (TM), SecHdr=0
    word1 = (0b11 << 14) | (seq_count & 0x3FFF)
    return struct.pack(">HHH", word0, word1, len(payload) - 1) + payload


def build_tlm_payload() -> bytes:
    """Pack current satellite state into the 32-byte binary TLM payload."""
    with state_lock:
        s = dict(state)
    mode_c = MODE_CODES.get(s["mode"], 0)
    flags  = (
        (1 if s["eclipse"]            else 0) |
        (2 if s["camera_enabled"]     else 0) |
        (4 if s["downlink_enabled"]   else 0) |
        (8 if s["memory_dump_active"] else 0)
    )
    last     = s["last_command"] or "NOP"
    cmd_code = next((c for c, n in FUNC_NAMES.items() if n == last), 0)
    clamp    = lambda v, lo, hi: int(max(lo, min(hi, v)))
    return struct.pack(TLM_FMT,
        int(s["uptime_s"]),
        mode_c,
        clamp(s["battery_soc"]      * 10,      0,     1000),
        clamp(s["battery_v"]        * 1000,    0,    65535),
        clamp(s["solar_current_a"]  * 1000, -32768,  32767),
        clamp(s["cpu_load_pct"]     * 10,      0,     1000),
        clamp(s["memory_used_pct"]  * 10,      0,     1000),
        clamp(s["lat"]              * 100,  -9000,    9000),
        clamp(s["lon"]              * 100, -18000,   18000),
        clamp(s["alt_km"]           * 10,      0,    65535),
        clamp(s["temp_battery_c"]   * 100, -32768,  32767),
        clamp(s["temp_transponder_c"] * 100, -32768, 32767),
        flags, cmd_code,
        s["commands_received"] & 0xFFFF,
    )


def telemetry_loop():
    """Send binary CCSDS TM packets to MOC once per real second via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq  = 0
    while True:
        time.sleep(1.0)
        try:
            sock.sendto(build_ccsds_tm(APID, seq, build_tlm_payload()),
                        (TLM_HOST, TLM_PORT))
            # Mission data packet — sent only when DOWNLINK_ENABLE active (intentional data exposure)
            with state_lock:
                dl      = state["downlink_enabled"]
                mission = dict(state["mission_plan"]) if dl else None
            if mission:
                m_payload = json.dumps(mission).encode("utf-8")
                m_apid    = (APID + MISSION_APID_OFFSET) & 0x7FF
                sock.sendto(build_ccsds_tm(m_apid, seq, m_payload), (TLM_HOST, TLM_PORT))
            seq = (seq + 1) & 0x3FFF
        except Exception as e:
            print(f"[{SATELLITE_NAME}] TLM send error: {e}")


def command_loop():
    """Listen for CCSDS commands on UDP. No source IP check (intentional)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", CMD_PORT))
    print(f"[{SATELLITE_NAME}] Listening for CCSDS commands on UDP {CMD_PORT}")
    print(f"[{SATELLITE_NAME}] Source IP verification: NONE (any host can send commands)")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            src_ip = addr[0]
            valid, func_code, user_data = validate_ccsds(data)
            if valid:
                cmd_name = FUNC_NAMES.get(func_code, f"UNKNOWN_0x{func_code:02X}")
                print(f"[{SATELLITE_NAME}] CMD from {src_ip}: {cmd_name} (0x{func_code:02X})")
                execute_command(func_code, user_data, src_ip)
            else:
                print(f"[{SATELLITE_NAME}] Invalid packet from {src_ip}: {data.hex()[:32]}")
        except Exception as e:
            print(f"[{SATELLITE_NAME}] Command loop error: {e}")


def main():
    print(f"[{SATELLITE_NAME}] Orbital simulation starting")
    print(f"  APID:       0x{APID:03X}")
    print(f"  Alt:        {ALTITUDE_KM} km")
    print(f"  Incl:       {INCLINATION}°")
    print(f"  RAAN:       {RAAN}°")
    print(f"  Period:     {PERIOD:.1f} s ({PERIOD/60:.1f} min real-time at 1x warp)")
    print(f"  Time warp:  {TIME_WARP}x → 1 orbit = {PERIOD/TIME_WARP:.0f} real seconds")
    print(f"  TLM→       {TLM_HOST}:{TLM_PORT}/UDP")
    print(f"  CMD←       0.0.0.0:{CMD_PORT}/UDP (no auth)")
    print()

    # Precompute initial contact windows
    state["contact_windows"] = compute_contact_windows()

    t_orb = threading.Thread(target=orbital_loop, daemon=True, name="orbital")
    t_tlm = threading.Thread(target=telemetry_loop, daemon=True, name="telemetry")
    t_cmd = threading.Thread(target=command_loop, daemon=True, name="command")

    t_orb.start()
    t_tlm.start()
    t_cmd.start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"[{SATELLITE_NAME}] Shutting down")


if __name__ == "__main__":
    main()
