// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

//go:build eigendav2test
// +build eigendav2test

// Package arbtest contains system tests for EigenDA V2 integration.
//
// EigenDA V2 implements the ALT-DA (Alternative Data Availability) spec and is accessed
// through the DAProvider interface (not the legacy EigenDA.Enable config).
//
// These tests validate:
// 1. V2 proxy connectivity through DAProvider interface
// 2. Batch posting using V2 with memstore
// 3. Certificate verification in sequencer inbox
// 4. Multi-node synchronization with V2 certificates

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
	// V2 proxy URL
	proxyV2URL = "http://127.0.0.1:4242"
)

// TestEigenDAV2Integration is the main integration test for EigenDA V2
// This validates V2 through the DAProvider interface (ALT-DA spec)
func TestEigenDAV2Integration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test 1: V2 proxy reachability
	t.Run("ProxyReachability", func(t *testing.T) {
		testEigenDAV2ProxyReachability(t)
	})

	// Test 2: V2 batch posting through DAProvider interface
	t.Run("BatchPosting", func(t *testing.T) {
		testEigenDAV2BatchPosting(t, ctx)
	})
}

// testEigenDAV2ProxyReachability tests that the EigenDA V2 proxy is accessible
func testEigenDAV2ProxyReachability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", proxyV2URL+"/health", nil)
	if err != nil {
		// If /health doesn't exist, try root
		req, err = http.NewRequestWithContext(ctx, "GET", proxyV2URL+"/", nil)
		Require(t, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("EigenDA V2 proxy not reachable at %s: %v", proxyV2URL, err)
	}
	defer resp.Body.Close()

	t.Logf("✅ EigenDA V2 proxy reachable at %s (HTTP %d)", proxyV2URL, resp.StatusCode)
}

// testEigenDAV2BatchPosting tests batch posting through V2 proxy via DAProvider interface
func testEigenDAV2BatchPosting(t *testing.T, ctx context.Context) {
	// Setup L1 chain
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true).DontParalellise()
	builder.BuildL1(t)

	// Configure L2 to use EigenDA V2 through DAProvider interface (ALT-DA spec)
	// NOT using EigenDA.Enable (that's V1) - V2 uses DAProvider
	builder.nodeConfig.DAProvider.Enable = true
	builder.nodeConfig.DAProvider.RPC.URL = proxyV2URL
	builder.nodeConfig.DAProvider.WithWriter = true

	builder.L2Info.GenerateAccount("User2")
	builder.BuildL2OnL1(t)

	// Setup second node for sync testing
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()
	l1NodeConfigB.BlockValidator.Enable = false
	l1NodeConfigB.DAProvider.Enable = true
	l1NodeConfigB.DAProvider.RPC.URL = proxyV2URL

	nodeBParams := SecondNodeParams{
		nodeConfig: l1NodeConfigB,
		initData:   &builder.L2Info.ArbInitData,
	}
	l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
	defer cleanupB()

	// Post transaction and verify
	checkEigenDAV2BatchPosting(t, ctx, builder.L1.Client, builder.L2.Client,
		builder.L1Info, builder.L2Info, big.NewInt(1e12), builder.addresses.SequencerInbox, l2B.Client)

	builder.L2.cleanup()
}

// checkEigenDAV2BatchPosting verifies batch posting through V2 proxy
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

	// Verify transaction processed and balance correct on all clients
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

	// #nosec G115
	batches, err := seqInbox.LookupBatchesInRange(ctx, big.NewInt(0), big.NewInt(int64(latestBlock)))
	Require(t, err)

	t.Logf("Found %d batches in sequencer inbox", len(batches))

	// Verify that EigenDA V2 certificates are present
	var eigenDAV2Seen bool
	for _, batch := range batches {
		serializedBatch, err := batch.Serialize(ctx, l1client)
		Require(t, err)

		if len(serializedBatch) <= 40 {
			continue
		}

		// V2 uses EigenDA message header byte (0xed)
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
func TestEigenDAV2ProxyReachability(t *testing.T) {
	testEigenDAV2ProxyReachability(t)
}
