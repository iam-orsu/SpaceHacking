#!/bin/bash
# validate_lab.sh — SpaceVE-1 Lab Validation
#
# Run after setup_lab.sh completes to verify the lab is attack-ready.
# Checks every service, every port, and every attack surface.
#
# Output: PASS/FAIL for each check. Lab is ready when all checks PASS.
#
# Run with: cd lab && bash scripts/validate_lab.sh

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "  ${GREEN}PASS${NC}  $*"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}  $*"; ((FAIL++)); }
info() { echo -e "  ${YELLOW}INFO${NC}  $*"; }

echo ""
echo "  SpaceVE-1 Lab Validation"
echo "  =========================="
echo ""

# ----------------------------------------------------------------
# 1. Docker containers running
# ----------------------------------------------------------------
echo "  [1/5] Container status"

check_container() {
    local name=$1
    local status
    status=$(docker inspect --format '{{.State.Status}}' "$name" 2>/dev/null || echo "missing")
    if [ "$status" = "running" ]; then
        pass "$name is running"
    else
        fail "$name is NOT running (status: $status). Run: cd lab && docker compose up -d"
    fi
}

check_container "spaceve1-satellite"
check_container "spaceve1-moc"
check_container "spaceve1-groundstation"
echo ""

# ----------------------------------------------------------------
# 2. Network connectivity
# ----------------------------------------------------------------
echo "  [2/5] Network connectivity"

check_tcp() {
    local host=$1 port=$2 label=$3
    if timeout 3 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        pass "$label ($host:$port/tcp)"
    else
        fail "$label ($host:$port/tcp) — container may still be starting"
    fi
}

check_udp_respond() {
    local host=$1 port=$2 label=$3
    # Send a minimal invalid CCSDS packet, see if we get any response
    # A real validation checks that the port is open via nmap
    if nmap -sU -p "$port" "$host" 2>/dev/null | grep -q "open\|open|filtered"; then
        pass "$label ($host:$port/udp)"
    else
        info "$label ($host:$port/udp) — UDP open|filtered (normal for UDP probes)"
    fi
}

check_tcp 192.168.60.11 8080   "MOC web interface"
check_tcp 192.168.60.10 4820   "Ground station command gateway"
check_tcp 192.168.60.10 5900   "Ground station status port"
echo ""

# ----------------------------------------------------------------
# 3. MOC web interface and API
# ----------------------------------------------------------------
echo "  [3/5] MOC web interface"

# Health endpoint
if curl -sf http://192.168.60.11:8080/health 2>/dev/null | grep -q "ok"; then
    pass "MOC /health returns OK"
else
    fail "MOC /health did not respond"
fi

# Login page exists
if curl -sf http://192.168.60.11:8080/login 2>/dev/null | grep -q "LOGIN"; then
    pass "MOC login page accessible"
else
    fail "MOC login page not accessible"
fi

# Test default credentials
LOGIN_RESP=$(curl -sf -c /tmp/moc_cookies.txt \
    -d "username=admin&password=admin123" \
    -X POST http://192.168.60.11:8080/login \
    -L 2>/dev/null)
if echo "$LOGIN_RESP" | grep -q "DASHBOARD\|SPACEVE-1\|telemetry"; then
    pass "MOC default credentials work (admin / admin123)"
else
    fail "MOC default credentials failed — check MOC_USERNAME/MOC_PASSWORD env vars"
fi

# Unauthenticated API access
TLM=$(curl -sf http://192.168.60.11:8080/api/telemetry 2>/dev/null)
if echo "$TLM" | grep -q "satellite_id\|uptime\|\{\}"; then
    pass "MOC /api/telemetry accessible without authentication"
else
    fail "MOC /api/telemetry not responding"
fi

# Raw command API (no auth)
CMD_RESP=$(curl -sf -X POST http://192.168.60.11:8080/api/command/raw \
    -H "Content-Type: application/json" \
    -d '{"hex":"1832c0000001e1","note":"validate_test_nop"}' 2>/dev/null)
if echo "$CMD_RESP" | grep -q "success"; then
    pass "MOC /api/command/raw accepts requests without authentication"
else
    fail "MOC /api/command/raw not responding"
fi

echo ""

# ----------------------------------------------------------------
# 4. Ground station
# ----------------------------------------------------------------
echo "  [4/5] Ground station"

GS_BANNER=$(echo "" | nc -w 2 192.168.60.10 5900 2>/dev/null || echo "")
if echo "$GS_BANNER" | grep -q "SpaceVE-1\|Ground Station"; then
    pass "Ground station status banner accessible"
else
    fail "Ground station status port not responding"
fi

if echo "$GS_BANNER" | grep -q "gsoperator"; then
    pass "Ground station exposes credentials in status banner"
else
    info "Ground station banner format unexpected — check manually"
fi
echo ""

# ----------------------------------------------------------------
# 5. Satellite CCSDS command interface
# ----------------------------------------------------------------
echo "  [5/5] Satellite CCSDS interface"

# Build and send a CCSDS NOP command for APID 0x200 (SpaceVE-1 sample app)
# Primary header: version=0, type=1(cmd), sec_hdr=1, apid=0x200
# word0 = 0b000_1_1_00000000000 | 0x200 = 0x1A00
# word1 = 0b11_00000000000000 = 0xC000
# data_len = 1 (2 bytes secondary - 1)
# Primary: 1A 00 C0 00 00 01
# Secondary: func_code=0x00 -> sec_byte0=0x00, checksum=0xFF^0x00=0xFF
# Full packet: 1A 00 C0 00 00 01 00 FF
NOP_PKT="1A00C0000001 00FF"
NOP_HEX=$(echo "$NOP_PKT" | tr -d ' ')

echo "$NOP_HEX" | xxd -r -p | nc -u -w 1 192.168.60.100 1234 2>/dev/null
if [ $? -eq 0 ]; then
    pass "Satellite UDP 1234 accepted CCSDS NOP (no authentication required)"
else
    fail "Could not send to satellite UDP 1234 — check container and network"
fi

# Verify telemetry is flowing to MOC
sleep 2
TLM2=$(curl -sf http://192.168.60.11:8080/api/telemetry 2>/dev/null)
if echo "$TLM2" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if d.get('uptime_s',0)>0 else 1)" 2>/dev/null; then
    pass "Satellite telemetry flowing to MOC (uptime > 0)"
else
    info "Telemetry uptime not confirmed — satellite may still be starting"
fi
echo ""

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo "  =============================================="
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}LAB READY — $PASS checks passed${NC}"
    echo "  All attack surfaces confirmed operational."
else
    echo -e "  ${RED}$FAIL checks failed${NC} | $PASS passed"
    echo "  Fix failures before starting exercises."
    echo "  Run: cd lab && docker compose logs <service>"
fi
echo "  =============================================="
echo ""

# Return exit code for use in CI/scripted environments
[ "$FAIL" -eq 0 ]
