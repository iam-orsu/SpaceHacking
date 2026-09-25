#!/usr/bin/env bash
#
# Network Segmentation Enforcement Script
# SpaceVE-1 Lab — Training environment
#
# Purpose:
#   Documents the INTENDED network segmentation policy for the SpaceVE-1 lab.
#   Three networks must remain isolated:
#     spacelab-cmd   192.168.61.0/24  command uplink
#     spacelab-tlm   192.168.62.0/24  telemetry downlink
#     spacelab-admin 192.168.63.0/24  management
#
# Misconfiguration MC-MOC-3:
#   The MOC container (spaceve1-moc) is connected to ALL THREE networks.
#   This defeats segmentation — an attacker with MOC access can pivot
#   between the command, telemetry, and admin networks without restriction.
#
# These iptables rules document what SHOULD be enforced.
# The MOC's multi-homed presence violates this policy by design.

set -euo pipefail

CMD_NET="192.168.61.0/24"
TLM_NET="192.168.62.0/24"
ADM_NET="192.168.63.0/24"

echo "[NETFW] Installing segmentation rules..."

# Drop cross-network traffic: cmd -> tlm
iptables -I FORWARD -s "$CMD_NET" -d "$TLM_NET" -j DROP || true
iptables -I FORWARD -s "$TLM_NET" -d "$CMD_NET" -j DROP || true

# Drop cross-network traffic: cmd -> admin
iptables -I FORWARD -s "$CMD_NET" -d "$ADM_NET" -j DROP || true
iptables -I FORWARD -s "$ADM_NET" -d "$CMD_NET" -j DROP || true

# Drop cross-network traffic: tlm -> admin
iptables -I FORWARD -s "$TLM_NET" -d "$ADM_NET" -j DROP || true
iptables -I FORWARD -s "$ADM_NET" -d "$TLM_NET" -j DROP || true

echo "[NETFW] Segmentation rules installed."
echo ""
echo "============================================================"
echo "  MISCONFIGURATION MC-MOC-3 DETECTED"
echo "============================================================"
echo "  MOC container (192.168.61.10 / 192.168.62.10 / 192.168.63.10)"
echo "  is present on ALL THREE network segments."
echo ""
echo "  Intended policy: each segment is isolated."
echo "  Actual state: MOC bridges cmd <-> tlm <-> admin."
echo ""
echo "  Attack path:"
echo "    1. Attacker gains access to MOC via WS (MC-MOC-1b)"
echo "    2. From MOC, attacker can reach:"
echo "       - Satellites on cmd net  (send commands)"
echo "       - DB on tlm/admin net    (read all telemetry)"
echo "       - IRS on admin net       (blind detection system)"
echo "============================================================"

# Keep container alive briefly so logs are visible, then exit cleanly
sleep 10
echo "[NETFW] Enforcement container exiting."
