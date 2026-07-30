#!/usr/bin/env bash
# Setup test environment for Aplomado scanner
set -euo pipefail

VULHUB_DIR="$(cd "$(dirname "$0")" && pwd)"
APLOMADO_DIR="$(dirname "$VULHUB_DIR")"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Aplomado — Test Environment Setup                 ║"
echo "╚══════════════════════════════════════════════════════╝"

# ── Phase 1: Start vulnerable containers ────────────────────────────
echo ""
echo "▶ Starting vulnerable containers..."
cd "$VULHUB_DIR"
docker compose up -d
echo "  ✓ Containers started"

# Wait for services to be ready
echo "  Waiting for services..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 9001 2>/dev/null && nc -z 127.0.0.1 9002 2>/dev/null; then
        echo "  ✓ All services ready"
        break
    fi
    sleep 2
done

# ── Phase 2: Build & start Aplomado ─────────────────────────────────
echo ""
echo "▶ Starting Aplomado web server (port 8080)..."
cd "$APLOMADO_DIR"

# Ensure CVE database is up to date (background task, may take a while)
echo "  CVE database update will run in background on first start"

# Start the server
echo ""
echo "  Run in a separate terminal:"
echo "    cd $APLOMADO_DIR"
echo "    cargo run -- serve 8080"
echo ""
echo "══════════════════════════════════════════════════════"
echo "  TEST TARGETS"
echo "══════════════════════════════════════════════════════"
echo "  Host: 127.0.0.1"
echo "  Ports:"
echo "    9001 — Apache HTTPD 2.4.49 (CVE-2021-41773)"
echo "    9002 — DVWA / OpenSSL (CVE-2014-0160)"
echo ""
echo "  Open http://localhost:8080 in your browser"
echo "  Create scan: target=127.0.0.1, ports=9001,9002"
echo ""
echo "  Cleanup: docker compose -f $VULHUB_DIR/docker-compose.yml down -v"
