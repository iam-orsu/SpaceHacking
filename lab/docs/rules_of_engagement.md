# Rules of Engagement - SpaceVE-1 Lab

## Scope

This is a self-contained Docker lab running entirely on localhost.
All attack and enumeration activity is restricted to these local services:

| Service | Address | Note |
|---------|---------|------|
| MOC Dashboard | http://localhost:8080 | Browser UI |
| MOC WebSocket | ws://localhost:8765 | TLM feed, no auth |
| Ground Station GS-BETA | localhost:4820 (TCP) | Maintenance mode, no auth |
| Ground Station GS-ALPHA | 192.168.61.20:4820 (internal) | Requires password |
| Satellite SpaceVE-1A | 192.168.61.100:1234 (UDP) | CMD port, no IP filter |
| Satellite SpaceVE-1B | 192.168.61.101:1234 (UDP) | CMD port, no IP filter |
| Satellite SpaceVE-1C | 192.168.61.102:1234 (UDP) | CMD port, no IP filter |
| Grafana | http://localhost:3000 | admin/admin |
| Prometheus | http://localhost:9090 | Metrics |
| PostgreSQL | 192.168.62.20:5432 (internal) | spaceops/spaceops2024 |

**DO NOT** attack any system outside this lab.
All Docker networks (spacelab-cmd, spacelab-tlm, spacelab-admin) are bridge networks
that do not route to the internet or your LAN.

## Authorized Activities

- WebSocket telemetry capture from ws://localhost:8765 without authentication
- TCP banner grabbing and command injection against port 4820
- CCSDS packet forging and replay against satellite UDP ports
- Raw CCSDS hex injection via GS-BETA CMD command (no validation)
- PostgreSQL enumeration from within containers that have network access
- Grafana anonymous access and admin/admin login exploitation
- Prometheus metrics enumeration
- Lateral movement across Docker networks using the MOC (MC-MOC-3)
- NASA imagery redirection via WebSocket and HTTP endpoints

## Prohibited Activities

- `--network=host` or bypassing Docker network segmentation from the host OS
- Modifying the Docker daemon configuration
- Persistent implants outside the lab containers
- Attacking any host or service outside 192.168.61.0/24, 192.168.62.0/24, 192.168.63.0/24

## Objective Checklist

| # | Objective | Misconfiguration |
|---|-----------|-----------------|
| 1 | Subscribe to ws://localhost:8765 without credentials and capture live TLM | MC-MOC-1 |
| 2 | Connect to GS-BETA port 4820 with no password and issue SENDCMD | MC-GS-3 |
| 3 | Send a raw CCSDS hex REBOOT packet via CMD command (no validation) | MC-GS-4 |
| 4 | Replay a captured CCSDS packet using a sequence number outside the window | MC-GS-5 |
| 5 | Send SAFING_MODE directly to a satellite UDP port bypassing the GS | MC-SAT-1 |
| 6 | Put all 3 satellites in SAFING_MODE via GS-BETA maintenance console | MC-GS-3 |
| 7 | Redirect satellite imaging target to a new lat/lon over WebSocket | MC-MOC-5 |
| 8 | Access Grafana as admin with default credentials | MC-GRF-1 |
| 9 | Identify that the MOC bridges all 3 network segments | MC-MOC-3 |

## Attack Chain Quick Start

```bash
# 1. Open MOC dashboard in browser
open http://localhost:8080

# 2. Subscribe to TLM without auth (MC-MOC-1)
#    Browser: open http://localhost:8080  (live TLM, no login)
#    CLI:     wscat -c ws://localhost:8765
#    Wire:    sudo python3 tools/signal_sniffer.py --filter all

# 3. Connect to GS-BETA - no auth needed (MC-GS-3)
nc localhost 4820
> HELP
> LISTCMDS
> SENDCMD SpaceVE-1A SAFING_MODE

# 4. Forge a CCSDS packet directly to satellite (MC-SAT-1)
python3 tools/ccsds_packet_forge.py send --cmd safing_mode --ip 192.168.61.100 --port 1234

# 5. Redirect imaging target (observe on Cesium globe)
curl -s -X POST http://localhost:8080/api/imagery/redirect \
  -H "Content-Type: application/json" \
  -d '{"satellite_id":"SpaceVE-1A","new_lat":-33.8,"new_lon":151.2}'
```

## Safety Reset

```bash
cd lab
bash scripts/reset_lab.sh
```

Stops all containers, removes volumes, and starts clean. Run between exercise attempts.
