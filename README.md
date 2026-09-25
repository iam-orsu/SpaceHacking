# SpaceVE-1 Satellite Hacking Lab

A local Docker lab for learning space systems security.
Three satellites, two ground stations, a Mission Operations Center with 3D Earth visualization, and a full set of CCSDS pentesting tools.

**This is a local lab. No VPN, no cloud, no external dependencies.**
Start the lab, attack the satellites directly from localhost.

---

## Quick Start

```bash
cd lab
docker compose up --build -d
```

Then open http://localhost:8080 in your browser.

---

## What is Running

| Container | Role | Address |
|-----------|------|---------|
| spaceve1-sat-a | SpaceVE-1A satellite (CCSDS TM/TC) | 192.168.61.100:1234 UDP |
| spaceve1-sat-b | SpaceVE-1B satellite | 192.168.61.101:1234 UDP |
| spaceve1-sat-c | SpaceVE-1C satellite | 192.168.61.102:1234 UDP |
| spaceve1-gs1 | Ground Station ALPHA (auth required) | 192.168.61.20:4820 TCP |
| spaceve1-gs2 | Ground Station BETA (maintenance mode) | localhost:4820 TCP |
| spaceve1-moc | Mission Operations Center | localhost:8080 HTTP, 8765 WS |
| spaceve1-tlmdb | PostgreSQL telemetry store | 192.168.62.20:5432 |
| spaceve1-irs | Incident Response Monitor (600s lag) | internal |
| spaceve1-prometheus | Metrics | localhost:9090 |
| spaceve1-grafana | Dashboard | localhost:3000 |

---

## Attack Surface

All misconfigurations are intentional. No CVEs.

| ID | Misconfiguration | Where |
|----|-----------------|-------|
| MC-SAT-1 | No source IP filtering on satellite CMD ports | Satellites UDP 1234 |
| MC-GS-1 | Weak default password: `password123` | GS-ALPHA |
| MC-GS-3 | Maintenance mode disables all authentication | GS-BETA port 4820 |
| MC-GS-4 | CMD command relays raw CCSDS hex with no validation | GS-BETA |
| MC-GS-5 | Sequence counter replay window = full 14-bit range | GS-BETA |
| MC-MOC-1 | WebSocket TLM readable without authentication | ws://localhost:8765 |
| MC-MOC-2 | MD5 password hashing in operator database | PostgreSQL |
| MC-MOC-3 | MOC on all 3 networks — defeats segmentation | Docker networks |
| MC-MOC-5 | Imaging redirect endpoint requires no auth | POST /api/imagery/redirect |
| MC-GRF-1 | Grafana default credentials admin/admin | localhost:3000 |

---

## Attack Chain

```
1. nmap -sU -p 1234 192.168.61.0/24           # discover satellite UDP ports
2. nc localhost 4820                            # connect to GS-BETA (no auth)
3. SENDCMD SpaceVE-1A DOWNLINK_ENABLE          # uplink command to satellite
4. python3 tools/signal_sniffer.py             # read TLM from ws://localhost:8765
5. python3 tools/ccsds_packet_forge.py         # forge direct CCSDS TC
6. Send SAFING_MODE to all 3 satellites        # operational impact
7. Redirect imaging targets on Cesium globe    # MC-MOC-5
```

---

## Pentesting Tools

All tools are in `lab/tools/`:

| Tool | Purpose |
|------|---------|
| `ccsds_packet_forge.py` | Build and send CCSDS telecommand packets |
| `ccsds_fuzzer.py` | Fuzz satellite CMD ports with malformed packets |
| `signal_sniffer.py` | Capture telemetry from MOC WebSocket |
| `telemetry_decoder.py` | Decode raw CCSDS telemetry frames |
| `ground_station_scanner.py` | Enumerate GS banners and command lists |
| `command_injector.py` | Inject commands via GS relay or direct UDP |
| `ccsds_telemetry_spoofer.py` | Spoof TLM frames to MOC |

---

## NASA Imagery

The Cesium 3D globe on the MOC dashboard supports live Earth observation via the NASA Landsat API.

1. Get a free API key at https://api.nasa.gov/
2. Add it to `lab/.env`: `NASA_API_KEY=your_key_here`
3. Rebuild: `docker compose up --build -d moc`
4. Open the Globe tab in the dashboard and click Capture on any satellite

The imaging redirect attack (`MC-MOC-5`) lets you change a satellite's imaging target
over an unauthenticated WebSocket or HTTP POST. The footprint jumps on the globe in real time.

---

## Network Layout

```
spacelab-cmd   192.168.61.0/24   Command uplink (GS, satellites)
spacelab-tlm   192.168.62.0/24   Telemetry downlink (satellites -> MOC)
spacelab-admin 192.168.63.0/24   Management (DB, IRS, Prometheus, Grafana)

MOC is on all 3 networks (MC-MOC-3).
```

---

## Lab Management

```bash
# Start
cd lab && docker compose up --build -d

# Validate
cd lab && bash scripts/validate_lab.sh

# Reset (wipe and restart clean)
cd lab && bash scripts/reset_lab.sh

# Hard reset (also removes images — full rebuild next time)
cd lab && bash scripts/reset_lab.sh --hard

# Stop
cd lab && docker compose down
```

---

## Rules of Engagement

See `lab/docs/rules_of_engagement.md`.

All attacks are scoped to the Docker networks listed above.
Do not attack anything outside those ranges.
