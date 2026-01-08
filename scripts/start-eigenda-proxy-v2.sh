#!/usr/bin/env bash

set -euo pipefail

# EigenDA V2 Proxy Startup Script
#
# Starts EigenDA V2 proxy with Arbitrum CustomDA RPC server support.
# V2 implements the ALT-DA spec and uses DA certificates (0x01 header byte).
#
# Usage: ./start-eigenda-proxy-v2.sh
#
# The proxy uses memstore (in-memory storage) for testing without requiring
# real EigenDA disperser infrastructure.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NITRO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PROXY_IMAGE="eigenda-proxy-v2:local"
CONTAINER_NAME="eigenda-proxy-v2-nitro-test-instance"
DOCKERFILE="$NITRO_DIR/Dockerfile.eigenda-proxy-v2"

# Build the Docker image if it doesn't exist
if ! docker image inspect "$PROXY_IMAGE" >/dev/null 2>&1; then
  echo "==== Building EigenDA V2 proxy Docker image ===="
  echo "Dockerfile: $DOCKERFILE"
  docker build -t "$PROXY_IMAGE" -f "$DOCKERFILE" "$NITRO_DIR"
  echo "==== Docker image built successfully ===="
else
  echo "==== Using existing Docker image: $PROXY_IMAGE ===="
fi

echo "==== Starting EigenDA V2 proxy container ===="

# Stop and remove existing container if it exists
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

# Start the proxy with V2 + Arbitrum configuration
# Port 4242 -> Arbitrum RPC server (daprovider_* JSON-RPC methods)
# Port 6666 -> HTTP server (Optimism Alt-DA /put /get endpoints)
docker run -d --name "$CONTAINER_NAME" \
  -p 4242:4242 \
  -p 6666:6666 \
  -e EIGENDA_PROXY_ADDR=0.0.0.0 \
  -e EIGENDA_PROXY_PORT=6666 \
  -e EIGENDA_PROXY_STORAGE_BACKENDS_TO_ENABLE=V2 \
  -e EIGENDA_PROXY_STORAGE_DISPERSAL_BACKEND=V2 \
  -e EIGENDA_PROXY_MEMSTORE_ENABLED=true \
  -e EIGENDA_PROXY_MEMSTORE_EXPIRATION=120m \
  -e EIGENDA_PROXY_EIGENDA_ETH_RPC=http://host.docker.internal:6969 \
  -e EIGENDA_PROXY_EIGENDA_SERVICE_MANAGER_ADDR=0x0000000000000000000000000000000000000000 \
  -e EIGENDA_PROXY_EIGENDA_CERT_VERIFICATION_DISABLED=true \
  -e EIGENDA_PROXY_EIGENDA_DISPERSER_RPC=host.docker.internal:32003 \
  -e EIGENDA_PROXY_EIGENDA_V2_NETWORK=hoodi_testnet \
  -e EIGENDA_PROXY_EIGENDA_V2_ETH_RPC=http://host.docker.internal:6969 \
  -e EIGENDA_PROXY_APIS_TO_ENABLE=arb \
  -e EIGENDA_PROXY_ARB_DA_ADDR=0.0.0.0 \
  -e EIGENDA_PROXY_ARB_DA_PORT=4242 \
  "$PROXY_IMAGE"

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  echo "==== Failed to start EigenDA V2 proxy container ===="
  exit 1
fi

echo "==== EigenDA V2 proxy container started ===="
echo "Container name: $CONTAINER_NAME"
echo "Image: $PROXY_IMAGE"
echo "Arbitrum RPC: http://127.0.0.1:4242"
echo "HTTP server: http://127.0.0.1:6666"
echo ""
echo "Check logs: docker logs $CONTAINER_NAME"
