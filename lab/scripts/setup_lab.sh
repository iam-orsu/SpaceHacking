#!/bin/bash
# setup_lab.sh — SpaceVE-1 Satellite Hacking Lab
#
# Starts the full local lab: 3 satellites, 2 ground stations, MOC dashboard,
# telemetry database, Prometheus, Grafana, incident-response monitor.
#
# Requirements: Docker with compose plugin (docker compose v2)
# Run from the lab directory: cd lab && bash scripts/setup_lab.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ---------------------------------------------------------------- preflight
echo ""
echo "  SpaceVE-1 Satellite Hacking Lab"
echo "  ================================"
echo ""

if ! docker compose version &>/dev/null 2>&1; then
    err "docker compose not found. Install Docker Desktop or Docker Engine with compose plugin."
fi
log "Docker: $(docker --version)"

cd "$LAB_DIR"

if [ ! -f ".env" ]; then
    warn ".env file not found. Copying from .env.example if available..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        log ".env created from .env.example"
    else
        warn "No .env.example found. Creating minimal .env..."
        cat > .env <<'EOF'
DB_PASSWORD=spaceops2024
NASA_API_KEY=
NASA_API_URL=https://api.nasa.gov/planetary/earth/imagery
EOF
        warn "NASA_API_KEY is empty. Cesium imagery capture requires a free key from api.nasa.gov"
    fi
fi

# ---------------------------------------------------------------- build + start
log "Building and starting all services..."
docker compose up --build -d

# ---------------------------------------------------------------- wait for db
log "Waiting for telemetry database..."
for i in $(seq 1 30); do
    if docker exec spaceve1-tlmdb pg_isready -U spaceops -d spaceve1 &>/dev/null; then
        log "Database ready."
        break
    fi
    sleep 2
    echo -n "."
done
echo ""

# ---------------------------------------------------------------- show status
log "Container status:"
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# ---------------------------------------------------------------- access info
echo ""
echo "  ============================================================"
echo "  LAB READY — LOCAL ACCESS ONLY"
echo "  ============================================================"
echo ""
echo "  MOC Dashboard     http://localhost:8080"
echo "  MOC WebSocket     ws://localhost:8765       (no auth — MC-MOC-1)"
echo "  Ground Station    nc localhost 4820         (maintenance mode — MC-GS-3)"
echo "  Grafana           http://localhost:3000      admin / admin  (MC-GRF-1)"
echo "  Prometheus        http://localhost:9090"
echo ""
echo "  Satellite networks (internal — reach from lab containers):"
echo "    spacelab-cmd   192.168.61.0/24  (command uplink)"
echo "    spacelab-tlm   192.168.62.0/24  (telemetry downlink)"
echo "    spacelab-admin 192.168.63.0/24  (management)"
echo ""
echo "  Pentesting tools:  cd lab/tools/"
echo "    ccsds_packet_forge.py    signal_sniffer.py"
echo "    ccsds_fuzzer.py          telemetry_decoder.py"
echo "    ground_station_scanner.py  command_injector.py"
echo "    ccsds_telemetry_spoofer.py"
echo ""
echo "  Attack chain quick-start:"
echo "    1.  nc localhost 4820"
echo "    2.  python3 tools/ccsds_packet_forge.py --sat SpaceVE-1A --cmd SAFING_MODE"
echo "    3.  python3 tools/signal_sniffer.py --ws ws://localhost:8765"
echo ""
echo "  Reset:  bash scripts/reset_lab.sh"
echo "  ============================================================"
echo ""
