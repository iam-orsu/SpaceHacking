#!/usr/bin/env bash
# verify.sh - SpaceVE-1 lab health check
# Run after deploy.sh start to confirm all services are up.

PASS=0
FAIL=0

check() {
  local label="$1"
  local code="$2"
  if [ "$code" -eq 0 ]; then
    printf "  [PASS] %s\n" "$label"
    PASS=$((PASS + 1))
  else
    printf "  [FAIL] %s\n" "$label"
    FAIL=$((FAIL + 1))
  fi
}

container_running() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^$1$"
}

tcp_open() {
  nc -z -w2 "$1" "$2" 2>/dev/null
}

echo ""
echo "  SpaceVE-1 Lab Health Check"
echo "  ==========================="
echo ""

# 1. MOC container
container_running "spaceve1-moc"
check "Container spaceve1-moc is running" $?

# 2. Satellite containers
docker ps --format '{{.Names}}' 2>/dev/null | grep -q "spaceve1-sat"
check "Satellite containers (spaceve1-sat-a/b/c) are running" $?

# 3. Ground station containers
docker ps --format '{{.Names}}' 2>/dev/null | grep -q "spaceve1-gs"
check "Ground station containers (spaceve1-gs1/gs2) are running" $?

# 4. MOC HTTP port
tcp_open 127.0.0.1 8080
check "localhost:8080 (MOC dashboard) is listening" $?

# 5. MOC WebSocket port
tcp_open 127.0.0.1 8765
check "localhost:8765 (MOC WebSocket TLM) is listening" $?

# 6. Satellite CCSDS UDP port (checked from inside the Docker cmd network via MOC)
# Use Python (guaranteed in the python:3.11-slim MOC image) instead of nc
docker exec spaceve1-moc python -c \
  "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'\x00',('192.168.61.100',1234)); s.close()" \
  2>/dev/null
check "192.168.61.100:1234/udp (SpaceVE-1A CCSDS command port) reachable" $?

# 7. GS-ALPHA TCP command gateway (checked from inside Docker via MOC)
docker exec spaceve1-moc python -c \
  "import socket,sys; s=socket.socket(); s.settimeout(2); s.connect(('192.168.61.20',4820)); s.close()" \
  2>/dev/null
check "192.168.61.20:4820/tcp (GS-ALPHA command gateway) reachable" $?

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "  Lab ready. All $PASS checks passed."
  echo ""
  exit 0
else
  echo "  Warning: $FAIL of $((PASS + FAIL)) checks failed."
  echo "  Run: cd lab && ./deploy.sh start"
  echo "  If containers started recently, wait 10 seconds and run again."
  echo ""
  exit 1
fi
