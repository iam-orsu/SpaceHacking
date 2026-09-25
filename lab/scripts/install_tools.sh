#!/bin/bash
# install_tools.sh - Attacker VM Tool Installation
#
# Run this on the attacker machine (Ubuntu 22.04) to install all tools
# needed to complete the SpaceVE-1 lab attack chain.
#
# What gets installed:
#   - GNU Radio 3.10        (satellite signal capture and SDR)
#   - Python3 packages      (ccsds, scapy, requests, pwntools)
#   - Wireshark             (protocol analysis)
#   - nmap                  (ground station reconnaissance)
#   - netcat                (raw socket interaction)
#   - curl, jq              (MOC API interaction)
#   - Docker                (if not already installed)
#
# Run with: bash scripts/install_tools.sh
# Time required: 5-10 minutes

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

echo ""
echo "  SpaceVE-1 Lab - Attacker Tool Installation"
echo "  ============================================="
echo ""

if [ "$(lsb_release -rs 2>/dev/null)" != "22.04" ]; then
    warn "This script targets Ubuntu 22.04. Other versions may work but are untested."
fi

# ----------------------------------------------------------------
# System packages
# ----------------------------------------------------------------
log "Updating package lists..."
sudo apt-get update -qq

log "Installing system tools..."
sudo apt-get install -y \
    nmap \
    netcat-openbsd \
    curl \
    jq \
    wireshark \
    tshark \
    tcpdump \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    git \
    hexdump \
    xxd \
    socat \
    net-tools \
    iproute2 \
    iputils-ping \
    2>/dev/null

log "System tools installed."

# ----------------------------------------------------------------
# GNU Radio
# ----------------------------------------------------------------
log "Installing GNU Radio 3.10..."
sudo apt-get install -y gnuradio 2>/dev/null
GR_VERSION=$(gnuradio-config-info --version 2>/dev/null || echo "unknown")
log "GNU Radio version: ${GR_VERSION}"

# ----------------------------------------------------------------
# Python packages
# ----------------------------------------------------------------
log "Installing Python packages..."

pip3 install --quiet --break-system-packages \
    scapy \
    requests \
    pwntools \
    construct \
    colorama \
    tabulate \
    2>/dev/null || \
pip3 install --quiet \
    scapy \
    requests \
    pwntools \
    construct \
    colorama \
    tabulate \
    2>/dev/null

log "Python packages installed."

# ----------------------------------------------------------------
# Docker (if not installed)
# ----------------------------------------------------------------
if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | bash
    sudo usermod -aG docker "$USER"
    warn "Docker installed. You may need to log out and back in for group membership to apply."
    warn "Or run: newgrp docker"
else
    log "Docker already installed: $(docker --version)"
fi

# ----------------------------------------------------------------
# Create lab tool directory
# ----------------------------------------------------------------
TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tools" && pwd)"
log "Lab tools directory: $TOOL_DIR"

# ----------------------------------------------------------------
# Verify installations
# ----------------------------------------------------------------
echo ""
log "Verifying installations..."
echo ""
printf "  %-20s %s\n" "Tool" "Version"
printf "  %-20s %s\n" "----" "-------"

check_tool() {
    local name=$1 cmd=$2
    local ver
    ver=$($cmd 2>/dev/null | head -1) || ver="ERROR"
    printf "  %-20s %s\n" "$name" "$ver"
}

check_tool "nmap"        "nmap --version"
check_tool "python3"     "python3 --version"
check_tool "gnuradio"    "gnuradio-config-info --version"
check_tool "wireshark"   "wireshark --version"
check_tool "tshark"      "tshark --version"
check_tool "scapy"       "python3 -c 'import scapy; print(scapy.__version__)'"
check_tool "pwntools"    "python3 -c 'import pwn; print(pwn.__version__)'"
check_tool "docker"      "docker --version"

echo ""
log "Installation complete."
echo ""
echo "  Next step: cd lab && bash scripts/setup_lab.sh"
echo ""
