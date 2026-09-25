#!/bin/bash
# setup_lab.sh — SpaceVE-1 Lab Setup
#
# Builds and starts all lab containers.
# Run this from the lab/ directory: cd lab && bash scripts/setup_lab.sh
#
# What this does:
#   1. Checks prerequisites (Docker, docker-compose)
#   2. Builds satellite, MOC, and ground-station images
#   3. Starts all three containers in the 192.168.60.0/24 network
#   4. Waits for health checks to pass
#   5. Prints a summary with IPs and credentials
#
# Network layout after setup:
#   192.168.60.10   ground-station   TCP 4820 (command gateway)
#   192.168.60.11   moc              TCP 8080 (web), UDP 1235 (telemetry)
#   192.168.60.50   YOUR MACHINE     (attacker position)
#   192.168.60.100  satellite        UDP 1234 (CCSDS commands)
#
# Time required: 5-15 minutes on first run (builds cFS from source)
# Subsequent runs: under 60 seconds

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

echo ""
echo "  SpaceVE-1 Hacking Lab — Setup"
echo "  ==============================="
echo ""

# ----------------------------------------------------------------
# 1. Prerequisites
# ----------------------------------------------------------------
log "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    err "Docker not found. Install with: curl -fsSL https://get.docker.com | bash"
fi

DOCKER_COMPOSE_CMD=""
if docker compose version &>/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    err "docker compose not found. Install Docker Desktop or 'apt install docker-compose-plugin'"
fi

log "Docker: $(docker --version)"
log "Docker Compose: $($DOCKER_COMPOSE_CMD version --short 2>/dev/null || echo 'ok')"

if ! docker info &>/dev/null; then
    err "Docker daemon not running. Start with: sudo systemctl start docker"
fi

log "Prerequisites OK"
echo ""

# ----------------------------------------------------------------
# 2. Build images
# ----------------------------------------------------------------
log "Building lab images (this takes 5-15 min on first run)..."
log "The satellite image builds NASA cFS from source inside the container."
echo ""

cd "$LAB_DIR"

$DOCKER_COMPOSE_CMD build --progress=plain 2>&1 | \
    grep -E "^(Step|#|DONE|ERROR|=>|---)" || true

log "Build complete."
echo ""

# ----------------------------------------------------------------
# 3. Start containers
# ----------------------------------------------------------------
log "Starting lab containers..."
$DOCKER_COMPOSE_CMD up -d

echo ""
log "Waiting for containers to initialize..."

# Wait for satellite (up to 60s)
for i in $(seq 1 30); do
    if docker inspect --format '{{.State.Health.Status}}' spaceve1-satellite 2>/dev/null \
       | grep -q "healthy"; then
        log "Satellite: healthy"
        break
    fi
    sleep 2
done

# Wait for MOC (up to 60s)
for i in $(seq 1 30); do
    if docker inspect --format '{{.State.Health.Status}}' spaceve1-moc 2>/dev/null \
       | grep -q "healthy"; then
        log "MOC: healthy"
        break
    fi
    sleep 2
done

echo ""

# ----------------------------------------------------------------
# 4. Add /etc/hosts entries if not present
# ----------------------------------------------------------------
if ! grep -q "spacesys.local" /etc/hosts 2>/dev/null; then
    warn "Adding lab hosts to /etc/hosts (requires sudo)..."
    echo "192.168.60.10  groundstation.spacesys.local" | sudo tee -a /etc/hosts
    echo "192.168.60.11  moc.spacesys.local"           | sudo tee -a /etc/hosts
    echo "192.168.60.100 satellite.spacesys.local"      | sudo tee -a /etc/hosts
    log "/etc/hosts updated."
else
    log "/etc/hosts already has spacesys.local entries."
fi

# ----------------------------------------------------------------
# 5. Verify connectivity
# ----------------------------------------------------------------
echo ""
log "Verifying network connectivity..."

check_port() {
    local host=$1 port=$2 proto=${3:-tcp}
    if [ "$proto" = "tcp" ]; then
        timeout 3 bash -c "echo >/dev/$proto/$host/$port" 2>/dev/null && \
            echo -e "  ${GREEN}OK${NC}  $host:$port/tcp" || \
            echo -e "  ${RED}FAIL${NC} $host:$port/tcp"
    fi
}

check_port 192.168.60.11 8080
check_port 192.168.60.10 4820
check_port 192.168.60.10 5900

# ----------------------------------------------------------------
# 6. Summary
# ----------------------------------------------------------------
echo ""
echo "  =============================================="
echo "  LAB READY"
echo "  =============================================="
echo ""
echo "  NETWORK MAP:"
echo "    192.168.60.10   ground-station  TCP 4820 (cmd gateway)"
echo "    192.168.60.11   moc             TCP 8080 (web interface)"
echo "    192.168.60.50   YOUR MACHINE    (attacker)"
echo "    192.168.60.100  satellite       UDP 1234 (CCSDS input)"
echo ""
echo "  CREDENTIALS:"
echo "    MOC web:          admin / admin123"
echo "    Ground station:   gsoperator / password123"
echo ""
echo "  ACCESS:"
echo "    MOC dashboard:    http://192.168.60.11:8080"
echo "    MOC telemetry:    http://192.168.60.11:8080/api/telemetry"
echo "    Raw cmd API:      POST http://192.168.60.11:8080/api/command/raw"
echo "    Ground station:   nc 192.168.60.10 5900"
echo ""
echo "  ATTACK SURFACES:"
echo "    Satellite CCSDS:  UDP 192.168.60.100:1234 (no auth)"
echo "    MOC command API:  POST /api/command/raw (no auth)"
echo "    Ground station:   TCP 192.168.60.10:4820 (no auth)"
echo ""
echo "  VALIDATE: bash scripts/validate_lab.sh"
echo "  STOP:     cd lab && docker compose down"
echo "  RESET:    bash scripts/reset_lab.sh"
echo ""
