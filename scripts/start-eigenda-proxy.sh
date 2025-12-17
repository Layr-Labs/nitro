#!/usr/bin/env bash

set -euo pipefail

# Version parameter: v1 or v2 (default: v1)
VERSION="${1:-v1}"

# Configuration based on version
case "$VERSION" in
  v1)
    PROXY_IMAGE="ghcr.io/layr-labs/eigenda-proxy:2.3.1"
    CONTAINER_NAME="eigenda-proxy-nitro-test-instance"
    STORAGE_BACKENDS="V1"
    DISPERSAL_BACKEND="V1"
    APIS_TO_ENABLE="standard"
    ;;
  v2)
    # TODO: Update with actual V2 proxy image tag when available
    PROXY_IMAGE="ghcr.io/layr-labs/eigenda-proxy:3.0.0"
    CONTAINER_NAME="eigenda-proxy-v2-nitro-test-instance"
    # TODO: Confirm V2 backend configuration with EigenDA team
    STORAGE_BACKENDS="V2"
    DISPERSAL_BACKEND="V2"
    # TODO: Confirm if this should be "alt-da", "altda", or "custom-da"
    APIS_TO_ENABLE="alt-da"
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

docker run -d --name "$CONTAINER_NAME" \
  -p 4242:6666 \
  -e EIGENDA_PROXY_ADDR=0.0.0.0 \
  -e EIGENDA_PROXY_PORT=6666 \
  -e EIGENDA_PROXY_STORAGE_BACKENDS_TO_ENABLE="$STORAGE_BACKENDS" \
  -e EIGENDA_PROXY_STORAGE_DISPERSAL_BACKEND="$DISPERSAL_BACKEND" \
  -e EIGENDA_PROXY_APIS_TO_ENABLE="$APIS_TO_ENABLE" \
  -e EIGENDA_PROXY_MEMSTORE_ENABLED=true \
  -e EIGENDA_PROXY_MEMSTORE_EXPIRATION=120m \
  -e EIGENDA_PROXY_EIGENDA_ETH_RPC=http://localhost:6969 \
  -e EIGENDA_PROXY_EIGENDA_SERVICE_MANAGER_ADDR="0x0000000000000000000000000000000000000000" \
  -e EIGENDA_PROXY_EIGENDA_CERT_VERIFICATION_DISABLED=true \
  "$PROXY_IMAGE"

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
