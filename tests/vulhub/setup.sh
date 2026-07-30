#!/usr/bin/env bash
# Setup vulnerable containers for Aplomado scanner testing
set -euo pipefail

VULHUB_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Aplomado — Starting vulnerable containers         ║"
echo "╚══════════════════════════════════════════════════════╝"

cd "$VULHUB_DIR"
docker compose up -d
echo "  ✓ Containers started"

for i in $(seq 1 30); do
    if nc -z 127.0.0.1 9001 2>/dev/null && nc -z 127.0.0.1 9002 2>/dev/null; then
        echo "  ✓ Services ready"
        break
    fi
    sleep 2
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "  TARGETS"
echo "══════════════════════════════════════════════════════"
echo "  127.0.0.1:9001 — Apache 2.4.49 (CVE-2021-41773)"
echo "  127.0.0.1:9002 — DVWA (CVE-2014-0160 Heartbleed)"
echo ""
echo "  Cleanup: docker compose -f $VULHUB_DIR/docker-compose.yml down -v"
