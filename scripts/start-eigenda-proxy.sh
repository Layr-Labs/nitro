#!/usr/bin/env bash

set -euo pipefail

# EigenDA V2 Proxy Startup Script
#
# Starts EigenDA V2 proxy with memstore for fast CI tests.
# V2 implements the ALT-DA spec and is accessed via DAProvider interface.
#
# Usage: ./start-eigenda-proxy.sh
#
# The proxy uses memstore (in-memory storage) for testing without requiring
# real EigenDA disperser infrastructure.

PROXY_IMAGE="ghcr.io/layr-labs/eigenda-proxy:latest"
CONTAINER_NAME="eigenda-proxy-v2-nitro-test-instance"

echo "==== Pull EigenDA V2 proxy container ===="
docker pull "$PROXY_IMAGE"

echo "==== Starting EigenDA V2 proxy container ===="

# Build docker run command
# V2 uses memstore for fast testing without real disperser
docker run -d --name "$CONTAINER_NAME" \
  -p 4242:6666 \
  -e EIGENDA_PROXY_ADDR=0.0.0.0 \
  -e EIGENDA_PROXY_PORT=6666 \
  -e EIGENDA_PROXY_STORAGE_BACKENDS_TO_ENABLE=V2 \
  -e EIGENDA_PROXY_STORAGE_DISPERSAL_BACKEND=V2 \
  -e EIGENDA_PROXY_MEMSTORE_ENABLED=true \
  -e EIGENDA_PROXY_MEMSTORE_EXPIRATION=120m \
  -e EIGENDA_PROXY_EIGENDA_ETH_RPC=http://localhost:6969 \
  -e EIGENDA_PROXY_EIGENDA_SERVICE_MANAGER_ADDR=0x0000000000000000000000000000000000000000 \
  -e EIGENDA_PROXY_EIGENDA_CERT_VERIFICATION_DISABLED=true \
  -e EIGENDA_PROXY_EIGENDA_DISPERSER_RPC=localhost:32003 \
  -e EIGENDA_PROXY_EIGENDA_V2_NETWORK=holesky_testnet \
  -e EIGENDA_PROXY_EIGENDA_V2_ETH_RPC=http://localhost:6969 \
  -e EIGENDA_PROXY_API_ENABLED=admin \
  "$PROXY_IMAGE"

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  echo "==== Failed to start EigenDA V2 proxy container ===="
  exit 1
fi

echo "==== EigenDA V2 proxy container started ===="
echo "Container name: $CONTAINER_NAME"
echo "Image: $PROXY_IMAGE"
echo "Port: 4242"
