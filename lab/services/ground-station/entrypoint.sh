#!/bin/sh
set -e

echo "Ground Station entrypoint: $GS_NAME"
echo "  Lat=$GS_LAT  Lon=$GS_LON"
echo "  Maintenance=$MAINTENANCE_MODE"

exec python /app/gateway.py
