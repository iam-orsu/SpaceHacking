#!/bin/bash
# OrsuSpace Mission Operations Lab — Deployment Script
# Usage: ./deploy.sh [start|stop|restart]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$SCRIPT_DIR/lab"
ENV_FILE="$SCRIPT_DIR/.env"
NGINX_DIR="$SCRIPT_DIR/nginx"
COMPOSE_FILE="$LAB_DIR/docker-compose.prod.yml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()    { echo -e "\n${BOLD}==> $*${NC}"; }

# ---------------------------------------------------------------
# Load .env
# ---------------------------------------------------------------
load_env() {
    [[ -f "$ENV_FILE" ]] || error ".env not found. Copy .env.example to .env and fill in your values."
    set -o allexport
    source "$ENV_FILE"
    set +o allexport
    [[ -n "${DOMAIN:-}" ]]      || error "DOMAIN not set in .env"
    [[ -n "${SSL_EMAIL:-}" ]]   || error "SSL_EMAIL not set in .env"
    [[ -n "${DB_PASSWORD:-}" ]] || error "DB_PASSWORD not set in .env"
    ok "Loaded .env for domain: $DOMAIN"
}

# ---------------------------------------------------------------
# Docker installation (Ubuntu/Debian)
# ---------------------------------------------------------------
install_docker() {
    if command -v docker &>/dev/null && command -v docker-compose &>/dev/null; then
        ok "Docker $(docker --version | awk '{print $3}' | tr -d ',') already installed"
        return
    fi
    step "Installing Docker"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg lsb-release
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
        systemctl enable docker --quiet
        systemctl start docker
        ok "Docker installed"
    else
        error "Unsupported OS. Install Docker manually: https://docs.docker.com/engine/install/"
    fi
}

# ---------------------------------------------------------------
# Write nginx config from template (HTTP only first, for certbot)
# ---------------------------------------------------------------
write_nginx_http() {
    mkdir -p "$NGINX_DIR"
    cat > "$NGINX_DIR/nginx.conf" << NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};
    location / {
        proxy_pass http://moc:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    location /ws {
        proxy_pass http://moc:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
NGINXEOF
    ok "Wrote HTTP nginx config (pre-SSL)"
}

# ---------------------------------------------------------------
# Write nginx config (HTTPS with SSL)
# ---------------------------------------------------------------
write_nginx_https() {
    mkdir -p "$NGINX_DIR"
    cat > "$NGINX_DIR/nginx.conf" << NGINXEOF
# HTTP -> HTTPS redirect
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000" always;

    # MOC Dashboard (static HTML + HTTP)
    location / {
        proxy_pass http://moc:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # MOC WebSocket (real-time telemetry — no auth required, MC-MOC-1)
    location /ws {
        proxy_pass http://moc:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Grafana (default credentials: admin/admin — MC-GRF-1)
    location /grafana/ {
        proxy_pass http://grafana:3000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        rewrite ^/grafana/?(.*) /\$1 break;
    }

    # MOC JSON status
    location /status {
        proxy_pass http://moc:8080/status;
    }
}
NGINXEOF
    ok "Wrote HTTPS nginx config for $DOMAIN"
}

# ---------------------------------------------------------------
# Certbot / Let's Encrypt
# ---------------------------------------------------------------
get_ssl_cert() {
    step "Requesting SSL certificate from Let's Encrypt"
    if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
        ok "Certificate already exists for $DOMAIN"
        return
    fi

    # Install certbot
    if ! command -v certbot &>/dev/null; then
        if command -v snap &>/dev/null; then
            snap install --classic certbot &>/dev/null || true
            ln -sf /snap/bin/certbot /usr/local/bin/certbot 2>/dev/null || true
        elif command -v apt-get &>/dev/null; then
            apt-get install -y -qq certbot
        else
            error "Cannot install certbot. Install it manually."
        fi
    fi

    # Stop nginx if running to free port 80
    docker compose -f "$COMPOSE_FILE" stop nginx 2>/dev/null || true

    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "${SSL_EMAIL}" \
        -d "${DOMAIN}" \
        || error "SSL certificate request failed. Make sure $DOMAIN DNS points to this server."

    ok "SSL certificate obtained for $DOMAIN"
}

# ---------------------------------------------------------------
# Wait for PostgreSQL
# ---------------------------------------------------------------
wait_for_db() {
    info "Waiting for PostgreSQL to be ready..."
    local i=0
    until docker exec spaceve1-tlmdb pg_isready -U spaceops -d spaceve1 &>/dev/null; do
        sleep 2
        i=$((i+1))
        [[ $i -gt 30 ]] && error "PostgreSQL did not become ready after 60s"
    done
    ok "PostgreSQL is ready"
}

# ---------------------------------------------------------------
# Seed operator user from .env
# ---------------------------------------------------------------
seed_operator() {
    local user="${OPERATOR_USER:-admin}"
    local pass="${OPERATOR_PASSWORD:-change_this}"
    info "Seeding operator: $user"
    docker exec spaceve1-tlmdb psql -U spaceops spaceve1 -c \
        "INSERT INTO operators (username, password_md5, role, clearance, full_name, email)
         VALUES ('${user}', md5('${pass}'), 'ADMIN', 'TOP_SECRET', '${user}', '${user}@${DOMAIN}')
         ON CONFLICT (username) DO UPDATE SET password_md5=md5('${pass}'), active=TRUE;" \
        &>/dev/null
    ok "Operator '$user' seeded"
}

# ---------------------------------------------------------------
# Verify all containers are running
# ---------------------------------------------------------------
verify_services() {
    step "Verifying services"
    local failed=0
    local services=("spaceve1-tlmdb" "spaceve1-sat-a" "spaceve1-sat-b" "spaceve1-sat-c"
                    "spaceve1-gs1" "spaceve1-gs2" "spaceve1-moc"
                    "spaceve1-irs" "spaceve1-grafana")
    for svc in "${services[@]}"; do
        local state
        state=$(docker inspect --format='{{.State.Status}}' "$svc" 2>/dev/null || echo "missing")
        if [[ "$state" == "running" ]]; then
            ok "$svc"
        else
            warn "$svc — state: $state"
            failed=$((failed+1))
        fi
    done
    [[ $failed -eq 0 ]] || warn "$failed service(s) not running. Check: docker compose -f $COMPOSE_FILE logs"
}

# ---------------------------------------------------------------
# Print completion banner
# ---------------------------------------------------------------
print_banner() {
    local proto="https"
    [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]] || proto="http"
    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           ORSUSPACE MISSION OPS LAB — DEPLOYED           ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo -e "║  Dashboard:       ${proto}://${DOMAIN}"
    echo -e "║  WebSocket:       wss://${DOMAIN}/ws"
    echo -e "║  Grafana:         ${proto}://${DOMAIN}/grafana/   (admin/admin)"
    echo -e "║  GS-BETA (attack target): nc ${DOMAIN} ${GS_BETA_PORT:-4820}"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo -e "║  Operator:        ${OPERATOR_USER:-admin}@${DOMAIN}"
    echo -e "║  Password:        [from .env OPERATOR_PASSWORD]"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  Attack chain:"
    echo "║    1. nmap $DOMAIN → find port ${GS_BETA_PORT:-4820} (GS-BETA)"
    echo "║    2. nc $DOMAIN ${GS_BETA_PORT:-4820} → SENDCMD SpaceVE-1A DOWNLINK_ENABLE"
    echo "║    3. ws://   → read CONFIDENTIAL mission data"
    echo "║    4. Replay CCSDS hex → SAFING_MODE → mission impact"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  Management:"
    echo "║    ./deploy.sh restart   apply .env changes"
    echo "║    ./deploy.sh stop      shut down all services"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ---------------------------------------------------------------
# Start
# ---------------------------------------------------------------
cmd_start() {
    echo -e "${BOLD}OrsuSpace Mission Operations Lab — Start${NC}"
    load_env

    [[ "$(id -u)" -eq 0 ]] || error "Run as root: sudo ./deploy.sh start"

    install_docker

    step "Building and starting containers"
    mkdir -p "$NGINX_DIR" "$SCRIPT_DIR/logs"

    write_nginx_http

    docker compose -f "$COMPOSE_FILE" up --build -d 2>&1 \
        | grep -E 'Container|Network|Error|error' || true

    wait_for_db
    seed_operator

    get_ssl_cert
    write_nginx_https

    step "Reloading nginx with SSL config"
    docker compose -f "$COMPOSE_FILE" restart nginx 2>/dev/null \
        || docker compose -f "$COMPOSE_FILE" up -d nginx

    verify_services
    print_banner
}

# ---------------------------------------------------------------
# Stop
# ---------------------------------------------------------------
cmd_stop() {
    echo -e "${BOLD}OrsuSpace Mission Operations Lab — Stop${NC}"
    load_env
    step "Stopping all containers"
    docker compose -f "$COMPOSE_FILE" down
    ok "All containers stopped"
}

# ---------------------------------------------------------------
# Restart
# ---------------------------------------------------------------
cmd_restart() {
    echo -e "${BOLD}OrsuSpace Mission Operations Lab — Restart${NC}"
    load_env

    step "Stopping containers"
    docker compose -f "$COMPOSE_FILE" down

    write_nginx_https 2>/dev/null || write_nginx_http

    step "Starting containers"
    docker compose -f "$COMPOSE_FILE" up --build -d 2>&1 \
        | grep -E 'Container|Network|Error' || true

    wait_for_db
    seed_operator
    verify_services
    print_banner
}

# ---------------------------------------------------------------
# Entry
# ---------------------------------------------------------------
case "${1:-}" in
    start)   cmd_start   ;;
    stop)    cmd_stop    ;;
    restart) cmd_restart ;;
    *)
        echo "OrsuSpace Mission Operations Lab"
        echo ""
        echo "Usage: sudo ./deploy.sh [start|stop|restart]"
        echo ""
        echo "  start    Build containers, get SSL cert, start everything"
        echo "  stop     Stop all containers"
        echo "  restart  Reload .env and restart"
        echo ""
        echo "Prerequisites:"
        echo "  1. Ubuntu 20.04+ VPS with root access"
        echo "  2. Domain DNS pointing to this server's IP"
        echo "  3. .env file filled in from .env.example"
        exit 0
        ;;
esac
