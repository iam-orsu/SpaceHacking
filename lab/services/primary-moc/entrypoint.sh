#!/bin/bash
echo "[MOC-${MOC_ID:-PRIMARY}] Mission Operations Center starting..."
echo "  DB:      ${DB_HOST:-localhost}:${DB_PORT:-5432}/${DB_NAME:-spaceve1}"
echo "  TLM:     0.0.0.0:${TLM_LISTEN_PORT:-5000}/UDP"
echo "  Web:     0.0.0.0:5000/TCP"
echo "  Sats:    ${CMD_SAT_A} ${CMD_SAT_B} ${CMD_SAT_C}"
echo ""

# Wait for DB
until python3 -c "import psycopg2; psycopg2.connect(host='${DB_HOST}', port='${DB_PORT}', dbname='${DB_NAME}', user='${DB_USER}', password='${DB_PASS}')" 2>/dev/null; do
    echo "[MOC] Waiting for database..."
    sleep 3
done
echo "[MOC] Database connected."

exec python3 /moc/app.py
