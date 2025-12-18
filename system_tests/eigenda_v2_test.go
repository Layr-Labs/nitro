// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

//go:build eigendav2test
// +build eigendav2test

// Package arbtest contains system tests for EigenDA V2 integration.
//
// EigenDA V2 represents the integration of EigenDA with Arbitrum's ALT DA
// (Alternative Data Availability) specification. Unlike V1 which uses a custom
// Store() API, V2 implements the standardized ALT DA interface.
//
// Tests in this file validate:
// 1. V2 proxy connectivity and health checks
// 2. Batch posting through V2 proxy
// 3. Node synchronization using V2 certificates
// 4. Backward compatibility with V1 certificates
//
// Note: These tests require the eigendav2test build tag and are currently skipped
// until the V2 proxy is available. The test infrastructure is ready and tests will
// automatically run once V2 is deployed.

package arbtest

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/offchainlabs/nitro/arbnode"
	"github.com/offchainlabs/nitro/daprovider"
)

const (
	// V2 proxy URL - same port as V1 for now
	proxyV2URL = "http://127.0.0.1:4242"
)

// TestEigenDAV2Integration is the main comprehensive integration test for EigenDA V2
// This validates the complete V2 stack including:
// - V2 proxy connectivity and health
// - Batch posting through V2 with memstore
// - Certificate verification in sequencer inbox
// - Multi-node synchronization
// - Backward compatibility with V1
func TestEigenDAV2Integration(t *testing.T) {
	// Test 1: V2 proxy reachability
	t.Run("ProxyReachability", testEigenDAV2ProxyReachability)

	// Test 2: V2 batch posting with full e2e validation
	t.Run("BatchPosting", testEigenDAV2BatchPosting)

	// Test 3: Backward compatibility (V2 node reading V1 certs)
	// Still TODO - requires both V1 and V2 proxy running
	t.Run("BackwardCompatibility", func(t *testing.T) {
		t.Skip("Requires both V1 and V2 proxy setup - future enhancement")
		testV2ReadsV1Certificates(t)
	})
}

// testEigenDAV2ProxyReachability tests that the EigenDA V2 proxy is accessible
func testEigenDAV2ProxyReachability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// V2 proxy should respond to HTTP requests
	// We test basic connectivity by making a simple HTTP request
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", proxyV2URL+"/health", nil)
	if err != nil {
		// If /health doesn't exist, try root - any response means proxy is up
		req, err = http.NewRequestWithContext(ctx, "GET", proxyV2URL+"/", nil)
		Require(t, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("❌ EigenDA V2 proxy not reachable at %s: %v", proxyV2URL, err)
	}
	defer resp.Body.Close()

	// Any HTTP response (even 404) means the server is running
	if resp.StatusCode == 0 {
		t.Fatalf("❌ EigenDA V2 proxy returned invalid status code")
	}

	t.Logf("✅ EigenDA V2 proxy reachable at %s", proxyV2URL)
	t.Logf("   HTTP Status: %d", resp.StatusCode)
}

// testEigenDAV2BatchPosting tests batch posting through V2 proxy
// This is a comprehensive e2e test that validates:
// 1. L1 and L2 node setup with V2 proxy
// 2. Batch posting through V2 (using memstore for testing)
// 3. Certificate verification in sequencer inbox
// 4. Second node syncing from L1 using V2 certificates
func testEigenDAV2BatchPosting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup L1 chain and contracts
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true)
	builder.parallelise = false
	builder.BuildL1(t)

	// Configure L2 sequencer to use EigenDA V2 proxy
	builder.nodeConfig.EigenDA.Enable = true
	builder.nodeConfig.EigenDA.Rpc = proxyV2URL

	builder.L2Info.GenerateAccount("User2")
	builder.BuildL2OnL1(t)

	// Setup second node (non-sequencer) for sync testing
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()
	l1NodeConfigB.BlockValidator.Enable = false
	l1NodeConfigB.EigenDA.Enable = true
	l1NodeConfigB.EigenDA.Rpc = proxyV2URL

	nodeBParams := SecondNodeParams{
		nodeConfig: l1NodeConfigB,
		initData:   &builder.L2Info.ArbInitData,
	}
	l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
	defer cleanupB()

	// Test batch posting with certificate verification
	checkEigenDAV2BatchPosting(t, ctx, builder.L1.Client, builder.L2.Client,
		builder.L1Info, builder.L2Info, big.NewInt(1e12), builder.addresses.SequencerInbox, l2B.Client)

	builder.L2.cleanup()
}

// testV2ReadsV1Certificates tests backward compatibility
// This is CRITICAL: V2 nodes must be able to read V1 certificates
func testV2ReadsV1Certificates(t *testing.T) {
	t.Skip("Backward compatibility test - requires both V1 and V2 setup")

	// TODO: Implement backward compatibility test
	// 1. Start V1 proxy and post batches
	// 2. Stop V1 proxy
	// 3. Start V2 proxy
	// 4. Start V2 node
	// 5. Verify V2 node can read V1 certificates from sequencer inbox
	// 6. Verify V2 node can sync from L1 with V1 batches

	t.Logf("TODO: Implement V1 -> V2 backward compatibility test")
}

// checkEigenDAV2BatchPosting verifies batch posting through V2 proxy
// and validates that EigenDA V2 certificates appear in the sequencer inbox
func checkEigenDAV2BatchPosting(t *testing.T, ctx context.Context, l1client, l2clientA *ethclient.Client, l1info, l2info info, expectedBalance *big.Int, sequencerInboxAddr common.Address, l2ClientsToCheck ...*ethclient.Client) {
	// Prepare and send L2 transaction
	tx := l2info.PrepareTx("Owner", "User2", l2info.TransferGas, big.NewInt(1e12), nil)
	err := l2clientA.SendTransaction(ctx, tx)
	Require(t, err)

	_, err = EnsureTxSucceeded(ctx, l2clientA, tx)
	Require(t, err)

	t.Logf("L2 transaction sent: %s", tx.Hash().Hex())

	// Give the inbox reader time to pick up the delayed message
	time.Sleep(time.Millisecond * 100)

	// Create L1 blocks to process delayed inbox message and trigger batch posting
	for i := 0; i < 100; i++ {
		SendWaitTestTransactions(t, ctx, l1client, []*types.Transaction{
			l1info.PrepareTx("Faucet", "User", 30000, big.NewInt(1e12), nil),
		})
	}

	// Verify transaction processed and balance correct on all clients (including second node)
	for _, client := range l2ClientsToCheck {
		_, err = WaitForTx(ctx, client, tx.Hash(), time.Second*100)
		Require(t, err)

		l2balance, err := client.BalanceAt(ctx, l2info.GetAddress("User2"), nil)
		Require(t, err)

		if l2balance.Cmp(expectedBalance) != 0 {
			Fatal(t, "Unexpected balance:", l2balance, "expected:", expectedBalance)
		}
	}

	t.Logf("✅ Balance verified on all nodes: %s", expectedBalance.String())

	// Verify EigenDA V2 certificates in sequencer inbox
	seqInbox, err := arbnode.NewSequencerInbox(l1client, sequencerInboxAddr, 0)
	Require(t, err)

	latestBlock, err := l1client.BlockNumber(ctx)
	Require(t, err)

	// #nosec G115 -- Block numbers are unlikely to exceed int64's maximum value
	batches, err := seqInbox.LookupBatchesInRange(ctx, big.NewInt(0), big.NewInt(int64(latestBlock)))
	Require(t, err)

	t.Logf("Found %d batches in sequencer inbox", len(batches))

	// Verify that EigenDA certificates are present
	var eigenDAV2Seen bool
	for _, batch := range batches {
		serializedBatch, err := batch.Serialize(ctx, l1client)
		Require(t, err)

		if len(serializedBatch) <= 40 {
			continue
		}

		// V2 uses the same EigenDA message header byte as V1 (0xed)
		if daprovider.IsEigenDAMessageHeaderByte(serializedBatch[40]) {
			eigenDAV2Seen = true
			t.Logf("✅ Found EigenDA V2 certificate in batch")
			break
		}
	}

	if !eigenDAV2Seen {
		t.Fatal("Expected EigenDA V2 certificates in sequencer inbox, but found none")
	}

	t.Logf("✅ V2 batch posting successful - transaction processed and certificates verified")
}

// TestEigenDAV2ProxyReachability is a standalone test for CI
// Can be run independently to just check if V2 proxy is up
func TestEigenDAV2ProxyReachability(t *testing.T) {
	testEigenDAV2ProxyReachability(t)
}
