#!/bin/bash
echo "[${SATELLITE_NAME:-SAT}] Starting orbital simulation..."
echo "  APID:        ${SAT_APID:-0x200}"
echo "  Inclination: ${INCLINATION:-51.6}°"
echo "  RAAN:        ${RAAN:-0.0}°"
echo "  Time warp:   ${TIME_WARP:-1}x"
echo "  Cmd port:    UDP ${CMD_PORT:-1234}"
echo "  Tlm target:  ${TLM_HOST:-192.168.62.10}:${TLM_PORT:-5000}"
echo ""
exec python3 /sat/satellite_sim.py
