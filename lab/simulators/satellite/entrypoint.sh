#!/bin/bash
# SpaceVE-1 satellite entrypoint
# Starts cFS flight software and configures telemetry output to MOC

set -e

CFS_BIN_DIR="/cfs/build/exe/cpu1"
TLM_DEST_IP="${TLM_DEST_IP:-192.168.60.11}"
TLM_DEST_PORT="${TLM_DEST_PORT:-1235}"
CMD_LISTEN_PORT="${CMD_LISTEN_PORT:-1234}"

echo "SpaceVE-1 satellite starting..."
echo "Satellite ID: ${SATELLITE_ID:-SpaceVE-1}"
echo "Orbit altitude: ${ORBIT_ALT_KM:-400} km"
echo "Command listen port: UDP ${CMD_LISTEN_PORT}"
echo "Telemetry destination: ${TLM_DEST_IP}:${TLM_DEST_PORT}"
echo ""
echo "SECURITY STATUS:"
echo "  Authentication: NONE (checksum only)"
echo "  Encryption: NONE"
echo "  Source verification: NONE"
echo "  Any valid CCSDS packet will be accepted and executed."
echo ""

if [ -f "${CFS_BIN_DIR}/core-cpu1" ]; then
    echo "Starting cFS flight executive..."
    cd "${CFS_BIN_DIR}"
    exec ./core-cpu1
else
    echo "cFS binary not found at ${CFS_BIN_DIR}/core-cpu1"
    echo "Build may have failed during image creation."
    echo "Starting fallback CCSDS command listener for lab purposes..."
    exec python3 /cfs_stub.py
fi
