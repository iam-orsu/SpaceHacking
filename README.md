# SpaceVE-1 Satellite Hacking Lab

## You Are Already Inside

You are an APT operator with a foothold inside OrsuSpace Agency's corporate network.
Initial access is done. You are already in.

Your target: the SpaceVE-1 constellation — three Earth-imaging satellites in low Earth orbit,
collecting CONFIDENTIAL intelligence and transmitting it to a Mission Operations Center.

Control one satellite and you control what it photographs, when it transmits, and who gets the data.
Control all three and you have ended OrsuSpace's Earth observation mission.

**This is not a CTF. There are no flags. Success means controlling satellites.**

---

## Quick Start

```bash
cd lab
docker compose up --build -d
```

Open the target: http://localhost:8080

Read the adversary briefing: `lab/docs/adversary_scenario.md`
Start the attack: `lab/docs/attack_playbook.md`

---

## What You Are Attacking

| System | Address | Weakness |
|--------|---------|----------|
| SpaceVE-1A satellite | 192.168.61.100:1234 UDP | No source IP filter (MC-SAT-1) |
| SpaceVE-1B satellite | 192.168.61.101:1234 UDP | No source IP filter (MC-SAT-1) |
| SpaceVE-1C satellite | 192.168.61.102:1234 UDP | No source IP filter (MC-SAT-1) |
| Ground Station ALPHA | 192.168.61.20:4820 TCP | Default password: gs_alpha_2024 (MC-GS-1) |
| Ground Station BETA | localhost:4820 TCP | Maintenance mode: no auth (MC-GS-3) |
| MOC Dashboard | localhost:8080 HTTP | Entry point — see all satellite state |
| MOC WebSocket | localhost:8765 WS | TLM readable without auth (MC-MOC-1) |
| MOC Imaging API | localhost:8080/api | Redirect endpoint: no auth (MC-MOC-5) |
| Grafana | localhost:3000 | admin / admin (MC-GRF-1) |

---

## Adversary Objectives

Five objectives. They build on each other.

| # | What | Evidence |
|---|------|----------|
| 1 | Read CONFIDENTIAL telemetry without credentials | Mission plan visible in WebSocket stream |
| 2 | Send a command to a satellite | GS-BETA terminal confirms OK |
| 3 | Take a satellite offline | SAFING_MODE — satellite card turns red in dashboard |
| 4 | Redirect imaging target | Footprint moves on Cesium globe |
| 5 | Capture and exfiltrate Earth imagery | NASA Landsat PNG downloaded to disk |

---

## Attack Entry Points

```bash
# 1. Subscribe to TLM — no auth needed
python3 lab/tools/signal_sniffer.py --ws ws://localhost:8765

# 2. Connect to GS-BETA — maintenance mode, no password
nc localhost 4820
> LISTCMDS
> SENDCMD SpaceVE-1A DOWNLINK_ENABLE

# 3. Forge and send CCSDS directly to satellite
python3 lab/tools/ccsds_packet_forge.py --sat SpaceVE-1A --cmd SAFING_MODE --send

# 4. Redirect imaging target (no auth)
curl -s -X POST http://localhost:8080/api/imagery/redirect \
  -H "Content-Type: application/json" \
  -d '{"satellite_id":"SpaceVE-1A","new_lat":-33.87,"new_lon":151.21}'

# 5. Capture Landsat imagery from redirected target
curl -s -X POST http://localhost:8080/api/imagery/capture \
  -H "Content-Type: application/json" \
  -d '{"satellite_id":"SpaceVE-1A","target_lat":-33.87,"target_lon":151.21}'
```

---

## Crown Jewels

Satellites carry CONFIDENTIAL mission plans embedded in their telemetry stream.
When downlink is enabled, this data flows unencrypted over the internal network:

```json
{
  "operation": "SUNSTRIKE",
  "classification": "TOP SECRET//NOFORN",
  "target_name": "AGRA-INDUSTRIAL-COMPLEX",
  "target_description": "High-resolution ISR collection: industrial output capacity assessment",
  "lat": 33.7, "lon": 73.0,
  "collection_requirement": "NTM-ISR-2026-A03",
  "intelligence_value": "HIGH"
}
```

This data is sent unencrypted in the TLM stream when DOWNLINK_ENABLE is active.
Anyone subscribed to ws://localhost:8765 receives it. No credentials required.

---

## Detection Window

The Incident Response System (IRS) runs with a **10-minute detection lag**.

After you trigger SAFING_MODE on a satellite, IDS rule IR-006 fires — but 600 seconds later.
Complete all objectives before the alert appears in the Incidents tab.

The imaging redirect (MC-MOC-5) is not logged at all.

---

## Pentesting Tools

All tools in `lab/tools/`:

| Tool | Use |
|------|-----|
| `signal_sniffer.py` | Subscribe to WebSocket TLM, print all data |
| `telemetry_decoder.py` | Decode raw CCSDS frames |
| `ccsds_packet_forge.py` | Build and send CCSDS telecommand packets |
| `ccsds_fuzzer.py` | Fuzz satellite CMD ports with malformed packets |
| `ground_station_scanner.py` | Enumerate GS banners and command lists |
| `command_injector.py` | Inject commands via GS relay or direct UDP |
| `ccsds_telemetry_spoofer.py` | Spoof TLM frames to MOC |

---

## Network Layout

```
spacelab-cmd   192.168.61.0/24   Command uplink
spacelab-tlm   192.168.62.0/24   Telemetry downlink
spacelab-admin 192.168.63.0/24   Management

MOC bridges all 3 networks (MC-MOC-3) — pivot point once you have MOC access.
```

---

## Documentation

| File | Contents |
|------|----------|
| `lab/docs/adversary_scenario.md` | Full APT scenario: who you are, Day 1-6 timeline, all misconfigs |
| `lab/docs/attack_playbook.md` | Step-by-step attack phases with exact commands |
| `lab/docs/rules_of_engagement.md` | Scope, authorized activities, objective checklist |

---

## Lab Management

```bash
# Start
cd lab && docker compose up --build -d

# Validate services and misconfigs
cd lab && bash scripts/validate_lab.sh

# Reset to clean state
cd lab && bash scripts/reset_lab.sh

# Hard reset (removes images, full rebuild)
cd lab && bash scripts/reset_lab.sh --hard
```

---

## NASA Imagery (Optional)

The Cesium globe lets you capture real Landsat imagery from any satellite's current imaging target.
Get a free API key at https://api.nasa.gov/ and add it to `lab/.env`:

```
NASA_API_KEY=your_key_here
```

Then rebuild the MOC: `docker compose up --build -d moc`
