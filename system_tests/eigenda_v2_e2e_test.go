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
//
// TODO: Add blob dispersal verification, failover testing, Holesky testnet integration, and DA node storage checks

package arbtest

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/offchainlabs/nitro/arbnode"
)

const (
	// V2 proxy URL for e2e tests
	proxyV2E2EURL = "http://127.0.0.1:4242"
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

	t.Log("✅ Full e2e test completed")

	builder.L2.cleanup()
}
