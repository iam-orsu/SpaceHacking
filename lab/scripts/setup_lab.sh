#!/bin/bash
# Phase 2 lab setup — multi-network Docker architecture
set -e

COMPOSE_FILE="$(dirname "$0")/../docker-compose.yml"

check_deps() {
  for cmd in docker docker-compose; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "ERROR: $cmd not found. Install Docker + docker-compose."
      exit 1
    fi
  done
  DOCKER_V=$(docker --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
  echo "Docker: $DOCKER_V"
}

print_banner() {
  echo "=================================================="
  echo " Orsu Space Agency — C2 Lab v2.0"
  echo " SpaceVE-1 Constellation — 3 satellites"
  echo " Networks: spacelab-cmd / spacelab-tlm / spacelab-admin"
  echo "=================================================="
}

pull_images() {
  echo "[1/5] Pulling base images..."
  docker pull python:3.11-slim
  docker pull postgres:15-alpine
  docker pull prom/prometheus:latest
  docker pull grafana/grafana:latest
}

build_services() {
  echo "[2/5] Building service images..."
  docker-compose -f "$COMPOSE_FILE" build --parallel
}

create_networks() {
  echo "[3/5] Creating Docker networks..."
  for net in spacelab-cmd spacelab-tlm spacelab-admin; do
    docker network inspect "$net" &>/dev/null || \
      docker network create --driver bridge "$net"
    echo "  $net OK"
  done
}

start_services() {
  echo "[4/5] Starting services..."
  docker-compose -f "$COMPOSE_FILE" up -d

  echo "Waiting for telemetry-db..."
  for i in $(seq 1 30); do
    docker exec spacehacking-telemetry-db-1 pg_isready -U opsuser -d spaceops &>/dev/null && break
    sleep 2
    echo -n "."
  done
  echo " DB ready"
}

print_access() {
  echo "[5/5] Lab ready."
  echo ""
  echo "  Primary MOC:  http://localhost:5000"
  echo "    admin / admin123"
  echo "    telemetry.ops / ops123"
  echo "    command.ops   / ops123"
  echo ""
  echo "  Backup MOC:   http://localhost:5001"
  echo "    (same credentials — shared SECRET_KEY)"
  echo ""
  echo "  Grafana:      http://localhost:3000"
  echo "    admin / admin  (MC-8: default creds)"
  echo "    anonymous viewer also works (MC-8)"
  echo ""
  echo "  Prometheus:   http://localhost:9090"
  echo ""
  echo "  GS-1 TCP:     localhost:9001 (auth required)"
  echo "  GS-2 TCP:     localhost:9002 (MAINTENANCE_MODE — no auth)"
  echo ""
  echo "  Attack surface summary:"
  echo "    MC-1  primary-moc connected to all 3 networks"
  echo "    MC-2  /api/telemetry/latest — unauthenticated"
  echo "    MC-3  Hardcoded SECRET_KEY — forge session cookies"
  echo "    MC-4  MD5 passwords — offline crack from DB dump"
  echo "    MC-5  SQLi in /c2/telemetry?search="
  echo "    MC-6  /api/commands/raw — bypasses approval workflow"
  echo "    MC-7  GS-2 MAINTENANCE_MODE — no auth on backup uplink"
  echo "    MC-8  Grafana admin/admin + anonymous access"
  echo ""
  echo "Run validate_lab.sh to confirm all services are reachable."
}

print_banner
check_deps
pull_images
build_services
create_networks
start_services
print_access
