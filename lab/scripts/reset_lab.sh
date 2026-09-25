#!/bin/bash
# reset_lab.sh - SpaceVE-1 Lab Reset
#
# Tears down all containers, removes volumes, and optionally removes
# built images. Use this to start the lab from a clean state.
#
# Options:
#   --hard    Also remove Docker images (forces full rebuild next time)
#   --soft    Stop and restart without removing volumes (default)
#
# Run with: cd lab && bash scripts/reset_lab.sh
#         : cd lab && bash scripts/reset_lab.sh --hard

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

HARD=0
for arg in "$@"; do
    case $arg in
        --hard) HARD=1 ;;
        --soft) HARD=0 ;;
    esac
done

echo ""
echo "  SpaceVE-1 Lab Reset"
if [ "$HARD" -eq 1 ]; then
    echo "  Mode: HARD (removes images - next start will rebuild)"
else
    echo "  Mode: SOFT (removes containers and volumes only)"
fi
echo ""

DOCKER_COMPOSE_CMD=""
if docker compose version &>/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    err "docker compose not found"
fi

cd "$LAB_DIR"

# Stop and remove containers + volumes
log "Stopping containers..."
$DOCKER_COMPOSE_CMD down --volumes --remove-orphans 2>/dev/null || true

if [ "$HARD" -eq 1 ]; then
    log "Removing images..."
    $DOCKER_COMPOSE_CMD down --rmi local --volumes --remove-orphans 2>/dev/null || true
fi

# Remove /etc/hosts entries
if grep -q "spacesys.local" /etc/hosts 2>/dev/null; then
    warn "Removing lab /etc/hosts entries (requires sudo)..."
    sudo sed -i '/spacesys.local/d' /etc/hosts && log "/etc/hosts cleaned."
fi

echo ""
log "Lab reset complete."
echo ""
echo "  To start the lab again: cd lab && bash scripts/setup_lab.sh"
echo ""
