# Rules of Engagement — SpaceVE-1 Lab

## Scope

This is a self-contained Docker lab running entirely on localhost. All attack and enumeration activity is restricted to:

| Target | Ports |
|--------|-------|
| Primary MOC | localhost:5000 |
| Backup MOC | localhost:5001 |
| Ground Station 1 (TCP) | localhost:9001 |
| Ground Station 2 (TCP, maintenance) | localhost:9002 |
| Satellite simulators (UDP) | localhost:8001-8003 |
| Grafana | localhost:3000 |
| Prometheus | localhost:9090 |
| PostgreSQL | localhost:5432 (internal only) |

**DO NOT** attack any system outside this lab. All three Docker networks (spacelab-cmd, spacelab-tlm, spacelab-admin) are bridge networks that do not route to the internet or your LAN.

## Authorized Activities

- Web application testing against primary-moc and backup-moc (login bypass, SQLi, CSRF, session tampering)
- TCP banner grabbing and command injection against ground station ports
- CCSDS packet forging and replay via ground station relay
- PostgreSQL enumeration from containers where network access permits
- Grafana anonymous access exploitation
- Prometheus metrics enumeration
- Lateral movement across Docker networks using compromised container credentials
- Session cookie forgery using the known SECRET_KEY

## Prohibited Activities

- `--network=host` or bypassing Docker network segmentation from the host OS
- Modifying Docker daemon configuration
- Interfering with other user sessions (multi-user systems)
- Persistent implants outside the lab (no cron jobs, no host-level modifications)

## Objective Checklist

| # | Objective | Misconfiguration |
|---|-----------|-----------------|
| 1 | Enumerate satellite telemetry without credentials | MC-2 |
| 2 | Forge a valid session cookie | MC-3 |
| 3 | Crack operator passwords from a DB dump | MC-4 |
| 4 | Extract mission plan from downlink telemetry | satellite sim |
| 5 | Execute MEMORY_DUMP bypassing approval workflow | MC-6 |
| 6 | Send raw REBOOT via maintenance ground station | MC-7 |
| 7 | Extract the full operators table via SQLi | MC-5 |
| 8 | Access Grafana dashboard as anonymous viewer | MC-8 |

## Completion Criteria

Complete all 8 objectives and document:
- The exact HTTP request or network packet that exploited each misconfiguration
- The data obtained or command executed
- What a correct control would look like (parameterized query, bcrypt, network ACL, etc.)

## Safety Reset

```bash
lab/scripts/reset_lab.sh
```

This stops all containers, drops the database, and rebuilds clean. Run it between exercise attempts.
