#!/usr/bin/env bash
# deploy.sh - SpaceVE-1 lab lifecycle manager

set -euo pipefail

cd "$(dirname "$0")"

case "${1:-}" in
  start)
    echo "Starting SpaceVE-1 lab..."
    docker compose up --build -d
    echo ""
    echo "  Lab is up."
    echo "  Dashboard : http://localhost:8080"
    echo "  Grafana   : http://localhost:3000"
    echo "  WS TLM    : ws://localhost:8765"
    echo ""
    echo "  Run ./verify.sh to confirm all services are healthy."
    ;;
  stop)
    echo "Stopping SpaceVE-1 lab..."
    docker compose down
    echo "  Lab stopped."
    ;;
  restart)
    echo "Restarting SpaceVE-1 lab..."
    docker compose restart
    echo "  Lab restarted."
    ;;
  *)
    echo "Usage: ./deploy.sh <start|stop|restart>"
    echo ""
    echo "  start    Build images and start all containers"
    echo "  stop     Stop and remove containers"
    echo "  restart  Restart all running containers"
    exit 1
    ;;
esac
