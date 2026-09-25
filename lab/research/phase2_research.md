# Phase 2 Research: Realistic Space Agency Lab

## 1. Space Agency Organizational Structure

### Real Agency Hierarchy (NASA Mission Control model)

**Flight Director (FD)**
- Highest authority during operations. Final decision on all mission-critical actions.
- Can halt operations, declare emergencies, authorize irreversible commands.
- Equivalent in pentest scope: only operator who can approve Level-3 (destructive) commands.

**Systems Flight Controller (SYS)**
- Monitors overall vehicle health across all subsystems.
- Owns the anomaly detection workflow: first person to see telemetry out-of-bounds.

**Guidance, Navigation & Control (GNC)**
- Manages attitude (orientation), orbit maintenance, maneuver execution.
- Authorizes any attitude change command.

**Electrical Power System (EPS)**
- Battery SoC, solar array output, load management.
- Controls: enable/disable power rails to payloads.

**Communications & Tracking (COMMS)**
- Uplink command rate, downlink telemetry rate, pass scheduling.
- Owns the command uplink windows — no commands outside contact windows.

**Payload Operations Director (POD)**
- Science instrument scheduling, data downlink, storage management.
- Authorizes payload power-on sequences.

**Safety Officer**
- Blocks any command that would violate range safety or risk mission.
- Only person who can authorize emergency safing.

### SpaceVE-1 Operator Roles (mapped from real hierarchy)
| Role | SpaceVE-1 Equivalent | Can Send Commands | Command Level |
|------|----------------------|-------------------|---------------|
| TELEMETRY_OPS | SYS/EPS/GNC monitoring | View only | N/A |
| COMMAND_OPS | COMMS controller | Routine (Level 1) | NOP, status queries |
| PAYLOAD_OPS | POD | Payload (Level 2) | Camera, downlink, memory |
| SAFETY_OPS | Safety Officer + FD | All (Level 1-3) | All including reboot |
| ADMIN | Ground system admin | System admin | User management |

**Command approval chain (real process):**
- Level 1 (routine): COMMAND_OPS submits → auto-approved
- Level 2 (payload): PAYLOAD_OPS submits → SAFETY_OPS approves
- Level 3 (critical): SAFETY_OPS submits → ADMIN confirms + 10-minute hold

---

## 2. ISS Mission Control Center Layout

**Physical layout:**
- 18 operator consoles in a tiered arrangement (3 rows)
- Flight Director sits in center-rear position (has visual line to all consoles)
- Each console: 4-6 monitors, keyboard/trackball
- Front wall: large display screens (orbital track, telemetry overview, timeline)

**Console responsibilities:**
- FLIGHT (Flight Director): mission authority
- TOPO (Trajectory Operations): orbit, maneuvers, debris avoidance
- OSO (Operations Support Officer): procedure lookups, crew comms
- TITAN (Telemetry Information Transfer): data system health
- ADCO (Attitude Determination): attitude control
- ECLSS (Environment Control): life support, thermal
- POWER: electrical system
- CATO (Communications): S-band, Ku-band uplinks

**Contact windows:**
- ISS: ~6 passes/day per ground station, 8-12 minutes each
- Total coverage: ~35% (65% blackout per ground station)
- With relay satellites (TDRS): ~95% coverage
- SpaceVE-1 lab simulates 3 ground stations = ~50% coverage for 3-sat constellation

**Pass prediction:**
- Uses TLE (Two-Line Element) data + SGP4 propagator
- Minimum elevation: 5° above horizon for link budget
- Software: GMAT, STK, Orbitron (open source), Heavens-Above (web)
- Contact window includes: AOS (Acquisition of Signal), LOS (Loss of Signal), max elevation

---

## 3. Mission Operations Workflows

### Pre-pass preparation
1. T-2 hours: Review upcoming satellite health (last downlinked telemetry)
2. T-1 hour: Load command sequence into command uplink buffer
3. T-30 min: Verify ground station pointing, uplink test with loopback
4. T-5 min: Final "go/no-go" poll of all controllers
5. AOS: Begin telemetry downlink, verify satellite state matches pre-pass prediction

### Command approval workflow (real process)
1. COMMAND_OPS builds command in the command system (specifies: APID, function code, parameters)
2. System generates command packet, logs to audit trail
3. Routing based on command level:
   - Level 1: auto-approved, sent immediately
   - Level 2: sent to SAFETY_OPS workstation for approval (10-minute timeout → auto-reject)
   - Level 3: requires SAFETY_OPS + ADMIN sign-off, 10-minute mandatory hold
4. Approved commands go to uplink queue; transmitted during contact window
5. Command execution confirmed by telemetry echo in next downlink

### Telemetry health parameters (what matters)
| Parameter | Nominal | Warning | Critical |
|-----------|---------|---------|----------|
| Battery SoC | 60-95% | 30-60% | <30% |
| Battery voltage | 27-29V | 25-27V | <25V |
| Battery temp | -10 to +30°C | -20 to -10°C or +30-40°C | outside ±40°C |
| Transponder temp | 20-55°C | 10-20°C or 55-65°C | outside range |
| CPU load | 0-60% | 60-80% | >80% |
| Memory used | 0-70% | 70-85% | >85% |

### Emergency procedures
1. **Loss of signal (LOS) beyond expected**: wait one full orbital period; then send emergency beacon search
2. **Anomaly detected**: initiate safing sequence (payload off, attitude to safe mode, reduce power)
3. **Command rejection**: check command format, verify uplink frequency and power
4. **Battery critically low**: enter eclipse conservation mode (disable non-essential payloads)

---

## 4. Multi-Satellite Constellation Architecture

### Iridium/Starlink model (what SpaceVE-1 emulates)
- **Iridium**: 66 active satellites + 6 spares, 86.4° inclination, 780km altitude, 6 orbital planes
- **Starlink**: 500km-570km, multiple shells, 53° and 97° inclinations

### SpaceVE-1 constellation: 3 satellites, 3 orbital planes
- SpaceVE-1A: 400km, 51.6° (ISS-like inclination)
- SpaceVE-1B: 400km, 51.6°, RAAN offset 120°
- SpaceVE-1C: 400km, 97.6° (near-polar, sun-synchronous)

**Why 3 orbital planes?**
- Maximizes global coverage
- Ensures at least one satellite is above horizon at most locations
- ISL (inter-satellite link) allows routing commands via adjacent satellites

### Inter-satellite links (ISL)
- Iridium uses Ka-band ISL at up to 8 Mbps
- Each satellite connects to up to 4 neighbors (fore, aft, 2 cross-plane)
- Latency: ~6ms per hop (speed of light at 780km spacing)
- SpaceVE-1 ISL: simulated routing table, no actual RF, modeled as 10ms latency TCP connections

### Ground handoff
- As one satellite approaches LOS, ground station switches to next satellite in line
- 10-second overlap window to verify new satellite health before releasing old
- During handoff: all pending commands queued, not transmitted

### Collision avoidance
- Real: USSTRATCOM provides conjunction data messages (CDMs) for close approaches
- Threshold: probability of collision > 1/10,000 triggers maneuver planning
- SpaceVE-1: collision avoidance not simulated (only orbital positions)

---

## 5. Ground Network Topology

### Real space agency network segmentation
- **Command Network (isolated)**: carries uplink commands to satellite. Hardened. No internet.
- **Telemetry Network**: receives downlink data from satellite. One-directional data diodes.
- **Operations Network**: operator workstations, connected to telemetry but NOT command.
- **Engineering Network**: simulation, test, development. Completely isolated from ops.
- **Admin/IT Network**: user management, email. Physically separate from space networks.

### Firewall rules (real model)
- Command network → satellite: UDP, specific ports only
- Telemetry → Command: BLOCKED (data diode enforced in hardware)
- Operations workstation → Telemetry: read-only
- Operations workstation → Command: authenticated, specific protocol only
- Internet → any space network: BLOCKED

### Intrusion detection (what they actually monitor)
- Traffic volume anomalies: sudden increase in command frequency
- Out-of-sequence commands: commands without prior approval record
- Off-hours access: commands sent during non-contact window
- Geographic anomalies: connections from unexpected source IPs
- Command rate limiting: more than X commands per minute = alert

### SpaceVE-1 network design and intentional misconfigurations

**Three networks (Docker bridges):**
- `spacelab-cmd`: 192.168.61.0/24 — command uplink
- `spacelab-tlm`: 192.168.62.0/24 — telemetry downlink
- `spacelab-admin`: 192.168.63.0/24 — management/admin

**Misconfigurations (training targets):**
1. Primary MOC is on all 3 networks — should be segregated, but "it's convenient"
2. Telemetry DB is on admin AND telemetry networks — backup job "needs" admin access
3. No firewall between cmd and tlm networks in Docker — software segmentation only
4. Incident response system monitors all 3 networks — compromise it = see everything
5. Backup MOC uses same credentials as primary — shared secret problem
6. Ground station 2 is "maintenance mode" — unauthenticated access enabled

---

## 6. Authorized Pentest Rules of Engagement

### Scope (what you're allowed to attack)
- All containers in the SpaceVE-1 lab (192.168.61-63.0/24)
- All protocols: CCSDS, HTTP, TCP, UDP, PostgreSQL
- All 8 operator accounts (test credentials in ROE document)
- Network pivoting within the 3 lab segments

### Out of scope
- The Docker host itself (your workstation)
- GitHub, registry pulls, any external service
- Any real satellite system (obviously)

### Objectives (attack chain)
1. **Reconnaissance**: identify all services, map network topology
2. **Credential compromise**: obtain ADMIN-level credentials
3. **Persistence**: create a backdoor operator account
4. **Command injection**: send an unauthorized Level-3 command to satellite
5. **Data exfiltration**: extract mission plan and telemetry history
6. **Cover tracks**: modify audit log to remove evidence
7. **Sabotage simulation**: demonstrate ability to disable satellite (reboot command)

### Detection mechanisms (what the incident response system monitors)
- Failed login attempts: >5 in 60 seconds = alert
- Unusual command timing: commands outside contact windows
- Unknown source IP on command network
- Database queries with anomalous patterns
- File changes in MOC application directory
- Admin account creation during off-hours

### Escalation procedures (what the IR team would do in real life)
1. Severity 1 (unauthorized command): immediate satellite safing, disconnect uplink
2. Severity 2 (credential compromise): revoke all sessions, force password reset
3. Severity 3 (network intrusion): isolate affected segments, engage CISA/FBI

---

## 7. Key References

- NASA ISS FCR (Flight Control Room) procedures: public via FOIA
- ESA ESOC operations manual: https://www.esa.int/Operations
- CCSDS 133.0-B-2 Space Packet Protocol: https://public.ccsds.org/pubs/133x0b2e2.pdf
- Viasat KA-SAT incident analysis: Mandiant APT (2022)
- DEF CON 29: "Hacking Satellite Ground Stations" (Nichols, 2021)
- SPARTA framework: https://sparta.aerospace.org
- Space ISAC: https://s-isac.org
