#!/usr/bin/env bash
# Vo!d Deploy Script
# Usage: ./scripts/deploy.sh [--upstream http://your-backend:port]
set -euo pipefail

UPSTREAM="${1:-http://localhost:3000}"
echo "==> Vo!d deploy — upstream: $UPSTREAM"

# ── Check prerequisites ───────────────────────────────────────────
for cmd in docker docker-compose curl; do
  if ! command -v $cmd &>/dev/null; then
    echo "ERROR: $cmd is required but not installed."
    exit 1
  fi
done

KERNEL=$(uname -r | cut -d. -f1-2 | tr -d .)
if [ "$KERNEL" -lt "519" ]; then
  echo "WARNING: Kernel $(uname -r) detected. eBPF XDP requires >= 5.19"
  echo "         eBPF programs will be disabled, software-only mode active."
  EBPF_ENABLED=false
else
  EBPF_ENABLED=true
fi

# ── Generate secrets ──────────────────────────────────────────────
if [ ! -f .env ]; then
  echo "==> Generating .env secrets..."
  cat > .env <<EOF
CHALLENGE_SECRET=$(openssl rand -hex 32)
GRAFANA_PASSWORD=$(openssl rand -base64 16)
UPSTREAM=${UPSTREAM}
EOF
  echo "    .env created"
fi

# ── Download GeoIP databases ──────────────────────────────────────
mkdir -p config/geoip
if [ ! -f config/geoip/GeoLite2-ASN.mmdb ]; then
  echo "==> GeoIP databases not found."
  echo "    Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
  echo "    and place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in config/geoip/"
  echo "    (free registration required)"
fi

# ── Generate self-signed TLS for dev ─────────────────────────────
if [ ! -f config/tls/cert.pem ]; then
  echo "==> Generating self-signed TLS certificate..."
  mkdir -p config/tls
  openssl req -x509 -newkey rsa:4096 -keyout config/tls/key.pem \
    -out config/tls/cert.pem -days 365 -nodes \
    -subj "/CN=void-edge" 2>/dev/null
  echo "    TLS certificate generated (replace with real cert for production)"
fi

mkdir -p models

# ── Update UPSTREAM in docker-compose ────────────────────────────
sed -i "s|UPSTREAM: \"http://origin:3000\"|UPSTREAM: \"${UPSTREAM}\"|g" \
  docker/docker-compose.yml 2>/dev/null || true

# ── Build and start ───────────────────────────────────────────────
echo "==> Building containers..."
docker-compose -f docker/docker-compose.yml build

echo "==> Starting Vo!d stack..."
if [ "$EBPF_ENABLED" = true ]; then
  docker-compose -f docker/docker-compose.yml up -d
else
  docker-compose -f docker/docker-compose.yml up -d \
    --scale ebpf-loader=0
fi

echo ""
echo "============================================"
echo "  Vo!d is running!"
echo "============================================"
echo ""
echo "  Edge Proxy:      http://localhost:8080"
echo "  Behavior Engine: http://localhost:8000 (internal)"
echo "  Grafana:         http://localhost:3001"
echo "  Prometheus:      http://localhost:9090"
echo ""
echo "  To check status:  docker-compose -f docker/docker-compose.yml ps"
echo "  To view logs:     docker-compose -f docker/docker-compose.yml logs -f edge-proxy"
echo "  To stop:          docker-compose -f docker/docker-compose.yml down"
echo ""
echo "  Health check:"
sleep 3
curl -sf http://localhost:8080/__void/health && echo "  Edge proxy: OK" || echo "  Edge proxy: still starting..."
