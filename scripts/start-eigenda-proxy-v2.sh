#!/usr/bin/env bash

set -euo pipefail

# EigenDA V2 Proxy Startup Script
#
# Starts EigenDA V2 proxy with memstore for fast CI tests.
# V2 implements the ALT-DA spec and uses DA certificates (0x01 header byte).
#
# Usage: ./start-eigenda-proxy-v2.sh
#
# The proxy uses memstore (in-memory storage) for testing without requiring
# real EigenDA disperser infrastructure.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NITRO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROXY_BIN="$NITRO_DIR/eigenda-proxy"
LOG_FILE="/tmp/eigenda-proxy-v2.log"

if [ ! -f "$PROXY_BIN" ]; then
  echo "Error: eigenda-proxy binary not found at $PROXY_BIN"
  echo "Please build it from source: cd /tmp/eigenda/api/proxy && make build"
  exit 1
fi

echo "==== Starting EigenDA V2 proxy (local binary) ===="
echo "Binary: $PROXY_BIN"
echo "Log file: $LOG_FILE"
echo "Port: 4242 (Arbitrum RPC)"

# Kill any existing proxy process
pkill -f "eigenda-proxy" || true
sleep 2

# Start the proxy with V2 + Arbitrum configuration
nohup "$PROXY_BIN" \
  --addr=0.0.0.0 \
  --port=6666 \
  --storage.backends-to-enable=V2 \
  --storage.dispersal-backend=V2 \
  --memstore.enabled=true \
  --memstore.expiration=120m \
  --eigenda.eth-rpc=http://localhost:6969 \
  --eigenda.svc-manager-addr=0x0000000000000000000000000000000000000000 \
  --eigenda.cert-verification-disabled=true \
  --eigenda.disperser-rpc=localhost:32003 \
  --eigenda.v2.network=hoodi_testnet \
  --eigenda.v2.eth-rpc=http://localhost:6969 \
  --apis.enabled=arb \
  --arbitrum-da.addr=0.0.0.0 \
  --arbitrum-da.port=4242 \
  > "$LOG_FILE" 2>&1 &

PROXY_PID=$!
echo "Started proxy with PID: $PROXY_PID"

# Wait for proxy to start
sleep 5

# Check if process is still running
if ! kill -0 $PROXY_PID 2>/dev/null; then
  echo "==== Failed to start EigenDA V2 proxy ===="
  echo "Check logs at: $LOG_FILE"
  tail -50 "$LOG_FILE"
  exit 1
fi

echo "==== EigenDA V2 proxy started successfully ===="
echo "PID: $PROXY_PID"
echo "Arbitrum RPC endpoint: http://127.0.0.1:4242"
echo "Logs: tail -f $LOG_FILE"
