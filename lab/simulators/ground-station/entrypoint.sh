#!/bin/bash
echo "SpaceVE-1 Ground Station starting..."
echo "MOC: ${MOC_IP:-192.168.60.11}:${MOC_PORT:-8080}"
echo "Satellite: ${SATELLITE_IP:-192.168.60.100}:${SATELLITE_CMD_PORT:-1234}"
echo ""
exec python3 /gs/gateway.py
