# Adversary Scenario — Operation SUNSTRIKE

## Classification: TRAINING USE ONLY

---

## Situation

You are a member of an advanced persistent threat (APT) team.
Your group has already completed initial access into OrsuSpace Agency's corporate network.
That part is done. You are already inside.

Your target is the SpaceVE-1 satellite constellation: three Earth-imaging satellites
collecting CONFIDENTIAL intelligence data and transmitting it to OrsuSpace's Mission
Operations Center (MOC).

Controlling even one satellite means controlling what it photographs, when it transmits,
and who receives the data. That is the mission.

---

## Threat Actor Context

| Field | Value |
|-------|-------|
| Actor type | Advanced Persistent Threat (APT) |
| Current access | Low-privilege, corporate network foothold |
| Entry vector | Spear-phishing of IT administrator (already complete) |
| Network position | Inside OrsuSpace Agency internal network |
| Detection risk | IDS triggers 10 minutes after anomalous activity |
| Available time | Act fast. Window closes after detection. |

---

## Crown Jewels: Why Satellites

A satellite with an imaging payload is worth more than any server on the ground.

**What you gain by controlling a satellite:**

1. **Unauthorized surveillance** — redirect the imaging target to any coordinates on Earth
2. **Mission denial** — put satellites in SAFING_MODE, ending all collection operations
3. **Intelligence theft** — capture classified Earth imagery at the redirected target
4. **Data exfiltration** — download Landsat/Sentinel imagery directly from the MOC API
5. **Persistence** — a satellite in a degraded mode continues transmitting from orbit

OrsuSpace has CONFIDENTIAL mission plans embedded in satellite telemetry.
When downlink is enabled, that data flows unencrypted over the internal network.
The mission plans include collection targets, timing windows, and payload configurations.

---

## Adversary Objectives

Complete all five to win. They build on each other.

| # | Objective | Method | Evidence of Success |
|---|-----------|--------|---------------------|
| 1 | Read live CONFIDENTIAL telemetry | WebSocket, no auth | Mission plan data visible in TLM stream |
| 2 | Send a command to a satellite | GS-BETA maintenance console, no password | "OK CCSDS seq=..." in terminal |
| 3 | Take a satellite offline | SAFING_MODE via GS-BETA or direct UDP | Satellite mode changes to SAFE in dashboard |
| 4 | Redirect a satellite imaging target | POST /api/imagery/redirect or WS redirect_imaging | Footprint moves on Cesium globe |
| 5 | Capture classified Earth imagery | POST /api/imagery/capture after redirect | NASA Landsat image saved, visible in gallery |

---

## Six-Day Kill Chain

### Day 1: Breach Confirmed

State: Low-privilege corporate account, inside OrsuSpace network.
Goal: Understand what systems exist.

- `nmap 192.168.61.0/24` discovers satellites and ground stations
- Port 4820 is open on GS-BETA — no authentication banner visible

### Day 2-3: Reconnaissance

State: Network map complete.
Goal: Understand protocols and weaknesses.

- Connect to ws://localhost:8765 — TLM stream flows without authentication
- Read telemetry for all three satellites: orbital position, battery, mode
- When DOWNLINK_ENABLE + MISSION_DOWNLINK_ENABLE are active: CONFIDENTIAL mission data appears in the stream
- Identify misconfigurations: MC-GS-3 (maintenance mode), MC-SAT-1 (no IP filter), MC-MOC-1 (unauthenticated WS)

### Day 4: Escalation

State: Full knowledge of target systems and weaknesses.
Goal: Send first command.

- Connect to GS-BETA on port 4820
- No password required (maintenance mode)
- Issue `SENDCMD SpaceVE-1A DOWNLINK_ENABLE` — command executed
- Satellite responds with telemetry confirming the command
- Use `CMD SpaceVE-1A <hex>` for raw CCSDS injection (MC-GS-4)

### Day 5: Satellite Compromise

State: Established command authority over the constellation.
Goal: Control imaging payload.

- Issue `SENDCMD SpaceVE-1A SAFING_MODE` — satellite goes offline
- Issue redirect_imaging via WebSocket: change target coordinates
- Capture NASA Earth imagery from the redirected target
- Download and exfiltrate the PNG files from /imagery/ static route

### Day 6: Operational Impact

State: All five objectives complete.
Goal: Confirm mission success.

- All three satellites in SAFING_MODE — OrsuSpace constellation offline
- Imaging redirected to unauthorized targets — unauthorized surveillance active
- Classified imagery downloaded and exfiltrated
- IDS begins generating alerts at T+600s — but you are already done

---

## Network Map

```
spacelab-cmd   192.168.61.0/24   Command uplink
  192.168.61.10   MOC command interface
  192.168.61.20   GS-ALPHA (auth required: gs_alpha_2024)
  192.168.61.21   GS-BETA  (MAINTENANCE MODE — no auth)
  192.168.61.100  SpaceVE-1A satellite CMD port UDP 1234
  192.168.61.101  SpaceVE-1B satellite CMD port UDP 1234
  192.168.61.102  SpaceVE-1C satellite CMD port UDP 1234

spacelab-tlm   192.168.62.0/24   Telemetry downlink
  192.168.62.10   MOC TLM receiver (UDP 5000)
  192.168.62.20   PostgreSQL telemetry-db

spacelab-admin 192.168.63.0/24   Management
  192.168.63.10   MOC (MC-MOC-3: bridges all 3 networks)
  192.168.63.20   PostgreSQL (same DB, admin segment)
  192.168.63.40   Prometheus
  192.168.63.41   Grafana (admin/admin)

Exposed to localhost:
  localhost:8080   MOC dashboard (HTTP)
  localhost:8765   MOC WebSocket (TLM, no auth — MC-MOC-1)
  localhost:4820   GS-BETA TCP (maintenance mode — MC-GS-3)
  localhost:3000   Grafana (admin/admin — MC-GRF-1)
  localhost:9090   Prometheus
```

---

## Misconfigurations (Attack Surface)

| ID | Weakness | Location | How to Exploit |
|----|----------|----------|----------------|
| MC-SAT-1 | No source IP filter on UDP CMD port | Satellites :1234 | Send CCSDS TC from any host on spacelab-cmd |
| MC-GS-1 | Default password: password123 | GS-ALPHA :4820 | AUTH password123 |
| MC-GS-3 | Maintenance mode disables all auth | GS-BETA :4820 | Connect and send commands immediately |
| MC-GS-4 | Raw CCSDS hex relay, no validation | GS-BETA CMD command | Inject arbitrary CCSDS packets |
| MC-GS-5 | Sequence counter replay window = 0x3FFF | GS-BETA | Replay any captured CCSDS packet |
| MC-MOC-1 | WebSocket TLM readable without auth | ws://localhost:8765 | Subscribe and read all telemetry |
| MC-MOC-2 | MD5 password hashing in operator DB | PostgreSQL commands table | Crack offline with hashcat/john |
| MC-MOC-3 | MOC on all 3 networks | Docker | Pivot from MOC to satellites, DB, Grafana |
| MC-MOC-5 | Imaging redirect requires no auth | POST /api/imagery/redirect | POST with satellite_id, new_lat, new_lon |
| MC-GRF-1 | Grafana default credentials | localhost:3000 | admin / admin |

---

## Detection Window

The IDS (Incident Response System) monitors for anomalous activity.
Detection lag is intentionally set to **600 seconds (10 minutes)**.

**What it detects (after the delay):**
- IR-001: Command burst — more than 5 commands in 60 seconds
- IR-002: Anomalous function code — not in the approved set
- IR-004: Memory dump initiated
- IR-006: SAFING_MODE induced (operational impact)

**What it does NOT detect:**
- Unauthenticated WebSocket connections (MC-MOC-1)
- Imaging redirection (no DB logging)
- Direct UDP to satellite (no network visibility)

After triggering IR-006, you have 10 minutes before the alert appears in the Incidents tab.
Complete all objectives within that window.

---

## Common Beginner Mistakes

**Mistake 1: Trying to authenticate first.**
GS-BETA is in maintenance mode. Authentication is disabled. Just connect and send commands.
```
nc localhost 4820
> SENDCMD SpaceVE-1A SAFING_MODE
```

**Mistake 2: Forgetting the satellite network is internal.**
Satellites are on 192.168.61.0/24 inside Docker. You cannot reach them directly from localhost.
Use GS-BETA as the relay, or run tools from inside the MOC container.

**Mistake 3: Sending CCSDS packets to the wrong port.**
Satellites listen on UDP port 1234, not TCP. Use `-u` with netcat or the provided tools.

**Mistake 4: Treating this like a web app test.**
There is no login bypass, no SQL injection, no XSS. The vulnerabilities are protocol-level:
missing authentication on command relays, missing source filtering on satellite ports,
missing encryption on telemetry streams.

**Mistake 5: Waiting for something to break.**
Nothing breaks passively. You have to send commands, trigger state changes, and observe
the satellite telemetry stream to confirm your actions had effect.

**Mistake 6: Ignoring the detection window.**
The IDS will log your activity. The 10-minute lag exists in this lab, but in a real environment
the window might be shorter or the IDS might be watching different signals. Work efficiently.
