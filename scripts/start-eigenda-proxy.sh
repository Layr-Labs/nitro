#!/usr/bin/env bash

set -euo pipefail

# EigenDA Proxy Startup Script
#
# Usage: ./start-eigenda-proxy.sh [VERSION] [MODE]
#
# VERSION: v1 or v2 (default: v1)
#   - v1: EigenDA V1 with Store() API
#   - v2: EigenDA V2 with ALT-DA spec
#
# MODE: memstore or disperser (default: memstore)
#   - memstore: In-memory storage, no real disperser (fast CI tests)
#     * Uses dummy disperser (localhost:32003)
#     * Good for system tests and CI validation
#     * Tests: go test -tags eigendav2test ./system_tests
#
#   - disperser: Real EigenDA network with blob dispersal (e2e tests)
#     * Connects to real disperser (default: disperser-holesky.eigenda.xyz:443)
#     * Enables arb API for Arbitrum-specific routes
#     * Requires running EigenDA infrastructure or Holesky testnet
#     * Tests: go test -tags eigendav2e2etest ./system_tests
#
# Examples:
#   ./start-eigenda-proxy.sh v1           # V1 with memstore
#   ./start-eigenda-proxy.sh v2           # V2 with memstore (fast CI)
#   ./start-eigenda-proxy.sh v2 disperser # V2 with real disperser (e2e)

# Version parameter: v1 or v2 (default: v1)
VERSION="${1:-v1}"
# Mode parameter: memstore or disperser (default: memstore)
MODE="${2:-memstore}"

# Configuration based on version
case "$VERSION" in
  v1)
    PROXY_IMAGE="ghcr.io/layr-labs/eigenda-proxy:2.3.1"
    CONTAINER_NAME="eigenda-proxy-nitro-test-instance"
    STORAGE_BACKENDS="V1"
    DISPERSAL_BACKEND="V1"
    ;;
  v2)
    # V2 uses latest image (v2.5.0+) with V2 backend support
    # V2 implements OP Alt-DA spec with Optimism routes
    PROXY_IMAGE="ghcr.io/layr-labs/eigenda-proxy:latest"
    CONTAINER_NAME="eigenda-proxy-v2-nitro-test-instance"
    STORAGE_BACKENDS="V2"
    DISPERSAL_BACKEND="V2"
    # Enable admin API for runtime backend switching
    ENABLE_ADMIN_API="true"

    # Mode-specific configuration for V2
    case "$MODE" in
      memstore)
        ENABLE_MEMSTORE="true"
        # For memstore mode, use dummy disperser (data stored in memory)
        DISPERSER_RPC="localhost:32003"
        ;;
      disperser)
        # For disperser mode, connect to real EigenDA network
        ENABLE_MEMSTORE="false"
        # Disperser RPC can be overridden via env var EIGENDA_DISPERSER_RPC
        DISPERSER_RPC="${EIGENDA_DISPERSER_RPC:-disperser-holesky.eigenda.xyz:443}"
        # Enable arb API for Arbitrum-specific routes
        ENABLE_ARB_API="true"
        echo "⚠️  DISPERSER MODE: Connecting to real EigenDA network"
        echo "   Disperser: $DISPERSER_RPC"
        ;;
      *)
        echo "Error: Unknown mode '$MODE'. Use 'memstore' or 'disperser'"
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Error: Unknown version '$VERSION'. Use 'v1' or 'v2'"
    exit 1
    ;;
esac

echo "==== Pull eigenda-proxy $VERSION container ===="
docker pull "$PROXY_IMAGE"

echo "==== Starting eigenda-proxy $VERSION container ===="

# proxy has a bug currently which forces the use of the service manager address
# & eth rpc despite cert verification being disabled.

# Build docker run command
DOCKER_CMD="docker run -d --name $CONTAINER_NAME \
  -p 4242:6666 \
  -e EIGENDA_PROXY_ADDR=0.0.0.0 \
  -e EIGENDA_PROXY_PORT=6666 \
  -e EIGENDA_PROXY_STORAGE_BACKENDS_TO_ENABLE=$STORAGE_BACKENDS \
  -e EIGENDA_PROXY_STORAGE_DISPERSAL_BACKEND=$DISPERSAL_BACKEND \
  -e EIGENDA_PROXY_MEMSTORE_ENABLED=${ENABLE_MEMSTORE:-true} \
  -e EIGENDA_PROXY_MEMSTORE_EXPIRATION=120m \
  -e EIGENDA_PROXY_EIGENDA_ETH_RPC=http://localhost:6969 \
  -e EIGENDA_PROXY_EIGENDA_SERVICE_MANAGER_ADDR=0x0000000000000000000000000000000000000000 \
  -e EIGENDA_PROXY_EIGENDA_CERT_VERIFICATION_DISABLED=true \
  -e EIGENDA_PROXY_EIGENDA_DISPERSER_RPC=${DISPERSER_RPC}"

# Add V2-specific configuration if V2 backend is enabled
if [[ "$STORAGE_BACKENDS" == *"V2"* ]]; then
  # Use holesky_testnet network for default contract addresses
  # This provides all necessary contract addresses automatically
  DOCKER_CMD="$DOCKER_CMD \
    -e EIGENDA_PROXY_EIGENDA_V2_NETWORK=holesky_testnet \
    -e EIGENDA_PROXY_EIGENDA_V2_ETH_RPC=http://localhost:6969"
fi

# Add API configuration for V2 if enabled
if [ "${ENABLE_ADMIN_API:-false}" = "true" ]; then
  if [ "${ENABLE_ARB_API:-false}" = "true" ]; then
    DOCKER_CMD="$DOCKER_CMD -e EIGENDA_PROXY_API_ENABLED=admin,arb"
  else
    DOCKER_CMD="$DOCKER_CMD -e EIGENDA_PROXY_API_ENABLED=admin"
  fi
elif [ "${ENABLE_ARB_API:-false}" = "true" ]; then
  DOCKER_CMD="$DOCKER_CMD -e EIGENDA_PROXY_API_ENABLED=arb"
fi

# Run the container
eval "$DOCKER_CMD $PROXY_IMAGE"

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  echo "==== Failed to start eigenda-proxy $VERSION container ===="
  exit 1
fi

echo "==== eigenda-proxy $VERSION container started ===="
echo "Container name: $CONTAINER_NAME"
echo "Version: $VERSION"
echo "Image: $PROXY_IMAGE"

## TODO - support teardown or embed a docker client wrapper that spins up and tears down resource
# within system tests. Since this is only used by one system test, it's not a large priority atm.
