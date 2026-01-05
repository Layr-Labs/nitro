// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

//go:build eigendav2e2etest
// +build eigendav2e2etest

// Package arbtest contains TRUE end-to-end tests for EigenDA V2 integration with real disperser.
//
// These tests require:
// 1. Running EigenDA infrastructure (disperser, DA nodes) OR connection to Holesky testnet
// 2. Properly configured proxy with arb API enabled
// 3. Real ETH RPC and Service Manager contracts
//
// These tests are separate from the memstore-based tests (eigenda_v2_referenceda_test.go)
// which provide fast feedback on certificate formats and failover logic.
//
// To run these tests:
//   # Start proxy with real disperser
//   ./scripts/start-eigenda-proxy.sh v2 disperser
//
//   # Run e2e tests
//   go test -tags eigendav2e2etest -v ./system_tests -run TestEigenDAV2E2E

package arbtest

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/offchainlabs/nitro/arbnode"
)

const (
	// V2 proxy URL for e2e tests
	proxyV2E2EURL = "http://127.0.0.1:4242"

	// Holesky testnet RPC (can be overridden via env var)
	holeskyRPC = "https://ethereum-holesky-rpc.publicnode.com"
)

// TestEigenDAV2E2EConnectivity verifies the proxy is properly configured for real disperser
func TestEigenDAV2E2EConnectivity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("=== Testing EigenDA V2 E2E Connectivity ===")
	t.Log("This test requires:")
	t.Log("  1. Real EigenDA disperser running (or Holesky testnet)")
	t.Log("  2. Proxy started with: ./scripts/start-eigenda-proxy.sh v2 disperser")
	t.Log("  3. ETH RPC configured (Holesky or local)")

	client := &http.Client{Timeout: 10 * time.Second}

	// Test 1: Proxy health endpoint
	t.Log("--- Test 1: Proxy health check ---")
	req, err := http.NewRequestWithContext(ctx, "GET", proxyV2E2EURL+"/health", nil)
	if err != nil {
		req, err = http.NewRequestWithContext(ctx, "GET", proxyV2E2EURL+"/", nil)
		Require(t, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("❌ EigenDA V2 proxy not reachable at %s: %v\nDid you start it with: ./scripts/start-eigenda-proxy.sh v2 disperser ?", proxyV2E2EURL, err)
	}
	defer resp.Body.Close()

	t.Logf("✅ Proxy reachable at %s (HTTP %d)", proxyV2E2EURL, resp.StatusCode)

	// Test 2: Check arb API is enabled
	t.Log("--- Test 2: Verify arb API enabled ---")
	// The arb API should respond to /put requests with proper auth
	// For now, just verify the endpoint exists (should return 400/401, not 404)
	req, err = http.NewRequestWithContext(ctx, "POST", proxyV2E2EURL+"/put", nil)
	Require(t, err)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("❌ Failed to reach /put endpoint: %v", err)
	}
	defer resp.Body.Close()

	// Should get 400 (bad request) or 401 (unauthorized), NOT 404 (not found)
	if resp.StatusCode == 404 {
		t.Fatal("❌ arb API not enabled! /put endpoint not found.\nMake sure proxy is started with API_ENABLED=admin,arb")
	}

	t.Logf("✅ arb API enabled (status %d for /put)", resp.StatusCode)

	// Test 3: Verify disperser connectivity
	t.Log("--- Test 3: Disperser connectivity ---")
	// TODO: Add actual disperser ping/status check when proxy exposes it
	t.Log("⚠️  Disperser connectivity check not yet implemented")
	t.Log("    Will be tested during actual blob dispersal in integration test")
}

// TestEigenDAV2E2EBlobDispersal tests actual blob dispersal to EigenDA network
func TestEigenDAV2E2EBlobDispersal(t *testing.T) {
	t.Skip("TODO: Implement full blob dispersal test with real EigenDA network")

	// TODO: This test should:
	// 1. Setup L1 chain
	// 2. Configure L2 with EigenDA V2 proxy (disperser mode)
	// 3. Post a batch that triggers blob dispersal
	// 4. Verify blob was dispersed to DA nodes
	// 5. Verify certificate in sequencer inbox
	// 6. Setup second node and verify it can retrieve from DA
	// 7. Verify attestations from quorum
}

// TestEigenDAV2E2EWithRealDisperserFallback tests failover with real disperser
func TestEigenDAV2E2EWithRealDisperserFallback(t *testing.T) {
	t.Skip("TODO: Implement disperser failover test")

	// TODO: This test should:
	// 1. Setup dual DA (EigenDA V2 + ReferenceDA)
	// 2. Configure to use real disperser
	// 3. Test normal operation (should use EigenDA)
	// 4. Simulate disperser failure
	// 5. Verify automatic failover to ReferenceDA
	// 6. Verify mixed certificates in sequencer inbox
}

// TestEigenDAV2E2EHoleskyTestnet tests against Holesky testnet
func TestEigenDAV2E2EHoleskyTestnet(t *testing.T) {
	t.Skip("TODO: Implement Holesky testnet integration test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO: This test should:
	// 1. Connect to Holesky testnet via RPC
	// 2. Use Holesky EigenDA contracts
	// 3. Disperse blobs to Holesky DA network
	// 4. Verify certificate on Holesky L1

	// Verify Holesky RPC is accessible
	client, err := ethclient.DialContext(ctx, holeskyRPC)
	if err != nil {
		t.Skipf("Cannot connect to Holesky RPC: %v", err)
	}
	defer client.Close()

	blockNum, err := client.BlockNumber(ctx)
	if err != nil {
		t.Skipf("Cannot query Holesky: %v", err)
	}

	t.Logf("✅ Connected to Holesky testnet (block: %d)", blockNum)
	t.Log("TODO: Complete Holesky integration test implementation")
}

// TestEigenDAV2E2EFullIntegration is the comprehensive e2e test with real infrastructure
func TestEigenDAV2E2EFullIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Log("=== EigenDA V2 Full E2E Integration Test ===")
	t.Log("Prerequisites:")
	t.Log("  ✓ EigenDA disperser running")
	t.Log("  ✓ EigenDA DA nodes running")
	t.Log("  ✓ Proxy with arb API: ./scripts/start-eigenda-proxy.sh v2 disperser")
	t.Log("  ✓ ETH RPC (Holesky or local geth)")

	// Setup L1 chain
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true).DontParalellise()
	builder.BuildL1(t)

	// Configure L2 to use EigenDA V2 with real disperser
	builder.nodeConfig.EigenDA.Enable = true
	builder.nodeConfig.EigenDA.Rpc = proxyV2E2EURL

	builder.L2Info.GenerateAccount("User2")
	builder.BuildL2OnL1(t)

	// Setup second node for sync testing
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()
	l1NodeConfigB.BlockValidator.Enable = false
	l1NodeConfigB.EigenDA.Enable = true
	l1NodeConfigB.EigenDA.Rpc = proxyV2E2EURL

	nodeBParams := SecondNodeParams{
		nodeConfig: l1NodeConfigB,
		initData:   &builder.L2Info.ArbInitData,
	}
	l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
	defer cleanupB()

	// Test: Post transaction and verify blob dispersal
	t.Log("--- Testing batch posting with real blob dispersal ---")
	checkBatchPosting(t, ctx, builder.L1.Client, builder.L2.Client,
		builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)

	// TODO: Add checks for:
	// - Blob was actually dispersed to DA nodes
	// - Certificate includes valid attestations
	// - Second node retrieved blob from DA network
	// - Verify data availability proofs

	t.Log("✅ Full e2e test completed")
	t.Log("⚠️  Note: Additional verification of DA node storage not yet implemented")

	builder.L2.cleanup()
}
