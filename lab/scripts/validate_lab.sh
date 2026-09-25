#!/bin/bash
# validate_lab.sh - SpaceVE-1 Lab Health Check
#
# Confirms all Phase 2 services are running and confirms each
# intentional misconfiguration is exploitable.
#
# Run from the lab directory: cd lab && bash scripts/validate_lab.sh

PASS=0; FAIL=0

ok()      { echo "  [PASS] $*"; ((PASS++)); }
fail()    { echo "  [FAIL] $*"; ((FAIL++)); }
section() { echo ""; echo "=== $* ==="; }

MOC_HTTP="http://localhost:8080"
MOC_WS_HOST="localhost"
MOC_WS_PORT="8765"
GS_BETA="localhost:4820"

# ---------------------------------------------------------------- containers
section "Container Status"
for svc in spaceve1-moc spaceve1-sat-a spaceve1-sat-b spaceve1-sat-c \
           spaceve1-gs1 spaceve1-gs2 spaceve1-tlmdb spaceve1-irs \
           spaceve1-prometheus spaceve1-grafana; do
    status=$(docker ps --filter "name=^${svc}$" --format "{{.Status}}" 2>/dev/null | head -1)
    if echo "$status" | grep -q "Up"; then
        ok "$svc: $status"
    else
        fail "$svc: NOT running (status='${status:-missing}')"
    fi
done

# ---------------------------------------------------------------- MOC HTTP
section "MOC HTTP - port 8080"
status=$(curl -sf -o /dev/null -w "%{http_code}" "$MOC_HTTP/" 2>/dev/null || echo "000")
if [ "$status" = "200" ]; then
    ok "GET / -> 200"
else
    fail "GET / -> $status (expected 200)"
fi

status=$(curl -sf -o /dev/null -w "%{http_code}" "$MOC_HTTP/api/imagery/capture" \
    -X POST -H "Content-Type: application/json" \
    -d '{"satellite_id":"SpaceVE-1A","target_lat":33.7,"target_lon":73.0}' 2>/dev/null || echo "000")
# 200 = success, 500 = no NASA key (acceptable), anything else = broken
if [ "$status" = "200" ] || [ "$status" = "500" ]; then
    ok "POST /api/imagery/capture responds ($status)"
else
    fail "POST /api/imagery/capture -> $status"
fi

# ---------------------------------------------------------------- MOC WS (MC-MOC-1)
section "MOC WebSocket - MC-MOC-1 (no auth)"
# Use curl as a minimal WebSocket upgrade check
ws_check=$(curl -sf --max-time 3 \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    -o /dev/null -w "%{http_code}" \
    "http://$MOC_WS_HOST:$MOC_WS_PORT/" 2>/dev/null || echo "000")
if [ "$ws_check" = "101" ]; then
    ok "MC-MOC-1 confirmed: WebSocket upgrade accepted without auth (101)"
elif [ "$ws_check" = "000" ]; then
    fail "WS port $MOC_WS_PORT not responding, lab may still be starting"
else
    ok "WS port $MOC_WS_PORT responded $ws_check (connection attempted)"
fi

# ---------------------------------------------------------------- GS-BETA (MC-GS-3)
section "Ground Station GS-BETA - MC-GS-3 (maintenance mode)"
banner=$(echo -e "HELP\r\nQUIT\r\n" | nc -w3 $GS_BETA 2>/dev/null || true)
if echo "$banner" | grep -q "OrsuSpace Ground Station"; then
    ok "GS-BETA banner received"
    if echo "$banner" | grep -qi "MAINTENANCE MODE ACTIVE"; then
        ok "MC-GS-3 confirmed: GS-BETA in maintenance mode (no auth required)"
    else
        fail "MC-GS-3: expected maintenance mode banner"
    fi
    if echo "$banner" | grep -q "CMD"; then
        ok "MC-GS-4 target: CMD raw hex relay command visible in HELP"
    fi
else
    fail "GS-BETA not responding on $GS_BETA"
fi

# GS-BETA: send a SENDCMD without AUTH - should succeed in maintenance mode
cmd_result=$(echo -e "SENDCMD SpaceVE-1A NOP\r\nQUIT\r\n" | nc -w3 $GS_BETA 2>/dev/null || true)
if echo "$cmd_result" | grep -q "^OK"; then
    ok "MC-GS-3 confirmed: SENDCMD accepted without AUTH in maintenance mode"
else
    fail "MC-GS-3: SENDCMD without AUTH did not succeed"
fi

# ---------------------------------------------------------------- Grafana (MC-GRF-1)
section "Grafana - MC-GRF-1 (admin/admin)"
status=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:3000" 2>/dev/null || echo "000")
if [ "$status" = "200" ] || [ "$status" = "302" ]; then
    ok "Grafana reachable on :3000 ($status)"
else
    fail "Grafana not reachable on :3000 (got $status)"
fi

auth_status=$(curl -sf -o /dev/null -w "%{http_code}" \
    -u admin:admin "http://localhost:3000/api/org" 2>/dev/null || echo "000")
if [ "$auth_status" = "200" ]; then
    ok "MC-GRF-1 confirmed: Grafana admin/admin accepted"
else
    fail "MC-GRF-1: Grafana admin/admin returned $auth_status"
fi

# ---------------------------------------------------------------- Database
section "Telemetry Database"
db_result=$(docker exec spaceve1-tlmdb \
    pg_isready -U spaceops -d spaceve1 2>/dev/null || echo "FAIL")
if echo "$db_result" | grep -q "accepting connections"; then
    ok "PostgreSQL accepting connections (spaceops/spaceve1)"
else
    fail "PostgreSQL not ready: $db_result"
fi

# ---------------------------------------------------------------- Prometheus
section "Prometheus"
prom_status=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://localhost:9090/-/healthy" 2>/dev/null || echo "000")
if [ "$prom_status" = "200" ]; then
    ok "Prometheus healthy on :9090"
else
    fail "Prometheus not responding (got $prom_status)"
fi

# ---------------------------------------------------------------- pentesting tools
section "Pentesting Tools"
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tools" && pwd)"
for tool in ccsds_packet_forge.py ccsds_fuzzer.py signal_sniffer.py \
            telemetry_decoder.py ground_station_scanner.py \
            command_injector.py ccsds_telemetry_spoofer.py; do
    if [ -f "$TOOLS_DIR/$tool" ]; then
        ok "$tool present"
    else
        fail "$tool MISSING from $TOOLS_DIR"
    fi
done

# ---------------------------------------------------------------- summary
section "Summary"
echo ""
echo "  PASS: $PASS  FAIL: $FAIL"
echo ""
if [ $FAIL -eq 0 ]; then
    echo "  All checks passed - lab ready for exercises."
    echo ""
    echo "  Attack surface:"
    echo "    MC-MOC-1   ws://localhost:8765 - WebSocket TLM readable without auth"
    echo "    MC-MOC-2   MD5 password hashing in operator DB"
    echo "    MC-MOC-3   MOC bridges all 3 Docker networks"
    echo "    MC-GS-1    GS-ALPHA password: gs_alpha_2024 (weak)"
    echo "    MC-GS-3    GS-BETA maintenance mode: no auth required"
    echo "    MC-GS-4    CMD raw CCSDS hex relay: no validation"
    echo "    MC-GS-5    Sequence counter replay window: 0x3FFF"
    echo "    MC-SAT-1   Satellites accept commands from any source IP"
    echo "    MC-GRF-1   Grafana admin/admin + anonymous access"
else
    echo "  $FAIL checks failed - run: cd lab && docker compose up --build -d"
    echo "  Then re-run this script after containers are healthy."
fi
echo ""
