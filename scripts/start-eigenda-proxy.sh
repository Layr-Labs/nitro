echo "Pull eigenda-proxy container"
docker pull  ghcr.io/layr-labs/eigenda-proxy@sha256:10a4762f5c43e9037835617e6ec0b03da34012df87048a363f43b969ab93679b

echo "Tagging image"
docker tag  ghcr.io/layr-labs/eigenda-proxy@sha256:10a4762f5c43e9037835617e6ec0b03da34012df87048a363f43b969ab93679b eigenda-proxy-nitro-test

echo "Start eigenda-proxy container"

docker run -d --name eigenda-proxy-nitro-test \
  -p 4242:6666 \
  -e EIGENDA_PROXY_ADDR=0.0.0.0 \
  -e EIGENDA_PROXY_PORT=6666 \
  -e MEMSTORE_ENABLED=true \
  -e MEMSTORE_EXPIRATION=1m \
  -e EIGENDA_PROXY_TARGET_URL=http://localhost:3000 \
  eigenda-proxy-nitro-test

## TODO - support teardown or embed a docker client wrapper that spins up and tears down resource 
# within system tests. Since this is only used by one system test, it's not a large priority atm.