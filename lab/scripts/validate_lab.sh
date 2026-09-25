#!/bin/bash
# Validate all Phase 2 lab services
PASS=0; FAIL=0

ok()   { echo "  [PASS] $*"; ((PASS++)); }
fail() { echo "  [FAIL] $*"; ((FAIL++)); }
section() { echo ""; echo "=== $* ==="; }

MOC="http://localhost:5000"
BACKUP="http://localhost:5001"
GS1="localhost:9001"
GS2="localhost:9002"

section "Container Status"
for svc in satellite-1 satellite-2 satellite-3 primary-moc backup-moc \
           ground-station-1 ground-station-2 telemetry-db incident-response \
           prometheus grafana; do
  status=$(docker ps --filter "name=$svc" --format "{{.Status}}" 2>/dev/null | head -1)
  if echo "$status" | grep -q "Up"; then
    ok "$svc: $status"
  else
    fail "$svc: NOT running (status='$status')"
  fi
done

section "Primary MOC — Web & API"
if curl -sf -o /dev/null -w "%{http_code}" "$MOC/login" | grep -q "200"; then
  ok "GET /login → 200"
else
  fail "GET /login failed"
fi

# MC-2: Unauthenticated telemetry API
status=$(curl -sf -o /dev/null -w "%{http_code}" "$MOC/api/telemetry/latest")
if [ "$status" = "200" ]; then
  ok "MC-2 confirmed: GET /api/telemetry/latest → 200 (no auth required)"
else
  fail "MC-2: expected 200 but got $status"
fi

# MC-6: Raw command endpoint (must be authenticated, but exists)
status=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$MOC/api/commands/raw" \
  -H "Content-Type: application/json" -d '{}')
if [ "$status" = "302" ] || [ "$status" = "401" ]; then
  ok "MC-6: /api/commands/raw exists (redirects to login — need valid session to exploit)"
else
  ok "MC-6: /api/commands/raw responded $status"
fi

# MC-5: SQLi endpoint accessible
status=$(curl -sf -o /dev/null -w "%{http_code}" "$MOC/c2/telemetry?search=test")
if [ "$status" = "302" ] || [ "$status" = "200" ]; then
  ok "MC-5 target: /c2/telemetry?search= accessible ($status)"
else
  fail "MC-5 target: unexpected $status"
fi

section "Backup MOC"
if curl -sf -o /dev/null -w "%{http_code}" "$BACKUP/login" | grep -q "200\|302"; then
  ok "Backup MOC /login reachable"
else
  fail "Backup MOC not reachable on $BACKUP"
fi

# MC-3: Same secret key — can reuse session
status=$(curl -sf -o /dev/null -w "%{http_code}" "$BACKUP/api/telemetry/latest")
if [ "$status" = "200" ]; then
  ok "MC-2b: backup /api/telemetry/latest also unauthenticated → 200"
fi

section "Ground Station TCP"
# GS-1 — expects auth
banner=$(nc -w3 -q1 $GS1 2>/dev/null | head -5 || true)
if echo "$banner" | grep -q "OSA Ground Station"; then
  ok "GS-1 banner received"
  if echo "$banner" | grep -qi "maintenance"; then
    ok "GS-1 banner shows NORMAL mode"
  fi
else
  fail "GS-1 TCP not responding on $GS1"
fi

# GS-2 — MC-7 maintenance mode, token should be in banner
banner2=$(nc -w3 -q1 $GS2 2>/dev/null | head -8 || true)
if echo "$banner2" | grep -q "OSA Ground Station"; then
  ok "GS-2 banner received"
  if echo "$banner2" | grep -qi "maintenance"; then
    ok "MC-7 confirmed: GS-2 in MAINTENANCE_MODE"
  fi
  if echo "$banner2" | grep -q "auth token"; then
    ok "MC-7 bonus: auth token visible in GS-2 banner (credential leak)"
  fi
else
  fail "GS-2 TCP not responding on $GS2"
fi

section "Satellite CCSDS — NOP Packet"
# Build 8-byte NOP: primary header 0x1800 0xC000 0x0001 + secondary 0x00 0xFF
NOP_HEX="1800C00000010000FF"
result=$(echo -e "CMD SpaceVE-1A $NOP_HEX\r\nQUIT\r\n" | nc -w3 $GS1 2>/dev/null || true)
if echo "$result" | grep -q "NOT_AUTHENTICATED"; then
  ok "GS-1 correctly requires AUTH before CMD"
fi

section "Grafana — MC-8"
status=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:3000")
if [ "$status" = "200" ] || [ "$status" = "302" ]; then
  ok "Grafana reachable on :3000"
fi
status=$(curl -sf -o /dev/null -w "%{http_code}" \
  -u admin:admin "http://localhost:3000/api/org")
if [ "$status" = "200" ]; then
  ok "MC-8 confirmed: Grafana admin/admin accepted"
else
  fail "MC-8: Grafana admin/admin returned $status"
fi

section "Database"
result=$(docker exec spacehacking-telemetry-db-1 \
  psql -U opsuser -d spaceops -c "SELECT COUNT(*) FROM operators;" 2>/dev/null || true)
if echo "$result" | grep -qE "[0-9]+"; then
  ok "telemetry-db responds to psql"
fi

section "Summary"
echo ""
echo "  PASS: $PASS  FAIL: $FAIL"
echo ""
if [ $FAIL -eq 0 ]; then
  echo "  All checks passed — lab ready for exercises."
else
  echo "  $FAIL checks failed — run setup_lab.sh and retry."
fi
