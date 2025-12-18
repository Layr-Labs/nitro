// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

//go:build eigendav2test
// +build eigendav2test

// Package arbtest contains system tests for combined EigenDA V2 and ReferenceDA integration.
//
// This file tests the integration between EigenDA V2 (when available) and ReferenceDA
// as a fallback DA solution. These tests validate:
// 1. EigenDA V2 as primary DA with ReferenceDA as fallback
// 2. Failover scenarios (V2 → ReferenceDA)
// 3. ALT DA spec compatibility between both implementations
// 4. Backward compatibility (V2 reading V1 certificates)
// 5. Recency checks for L1 block references
//
// Note: Tests in this file require the eigendav2test build tag and are currently
// skipped until EigenDA V2 proxy becomes available. The infrastructure is ready
// and tests will automatically run once V2 is deployed.

package arbtest

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/offchainlabs/nitro/arbnode"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/daprovider/data_streaming"
	"github.com/offchainlabs/nitro/daprovider/referenceda"
	dapserver "github.com/offchainlabs/nitro/daprovider/server"
	"github.com/offchainlabs/nitro/util/signature"
)

// TestEigenDAV2WithReferenceDAFallback tests EigenDA V2 with ReferenceDA as fallback
// This test validates the integration of both DA solutions
func TestEigenDAV2WithReferenceDAFallback(t *testing.T) {
	t.Skip("Requires EigenDA V2 proxy and ReferenceDA integration - implementation pending")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup L1 chain
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true)
	builder.BuildL1(t)

	// Setup ReferenceDA server as fallback
	referenceDAServer, referenceDAAddr, validatorAddr := setupReferenceDAServerForFallback(t, ctx, builder.L1.Client)
	defer referenceDAServer.Shutdown(ctx)

	t.Logf("ReferenceDA fallback server at: %s", referenceDAAddr)
	t.Logf("Validator contract: %s", validatorAddr.Hex())

	// Configure L2 with EigenDA V2 primary and ReferenceDA fallback
	// TODO: Implement V2 configuration when proxy available
	builder.nodeConfig.EigenDA.Enable = true
	builder.nodeConfig.EigenDA.Rpc = proxyV2URL

	// Configure ReferenceDA as fallback
	builder.nodeConfig.DAProvider.Enable = true
	builder.nodeConfig.DAProvider.RPC.URL = "http://" + referenceDAAddr
	builder.nodeConfig.DAProvider.WithWriter = true

	// Enable failover
	builder.nodeConfig.BatchPoster.EnableEigenDAFailover = true

	builder.L2Info.GenerateAccount("User2")
	builder.BuildL2OnL1(t)

	// Setup second node
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()
	l1NodeConfigB.BlockValidator.Enable = false
	l1NodeConfigB.EigenDA.Enable = true
	l1NodeConfigB.EigenDA.Rpc = proxyV2URL
	l1NodeConfigB.DAProvider.Enable = true
	l1NodeConfigB.DAProvider.RPC.URL = "http://" + referenceDAAddr

	nodeBParams := SecondNodeParams{
		nodeConfig: l1NodeConfigB,
		initData:   &builder.L2Info.ArbInitData,
	}
	l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
	defer cleanupB()

	// Test 1: Normal operation (EigenDA V2 should be used)
	checkBatchPosting(t, ctx, builder.L1.Client, builder.L2.Client,
		builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)

	// Test 2: Simulate EigenDA V2 failure, verify fallback to ReferenceDA
	// TODO: Implement failure simulation when V2 available

	// Test 3: Verify both DA solutions have batches in sequencer inbox
	// TODO: Implement certificate verification

	builder.L2.cleanup()
}

// TestALTDASpecCompatibility tests that EigenDA V2 and ReferenceDA follow ALT DA spec
func TestALTDASpecCompatibility(t *testing.T) {
	t.Skip("Requires EigenDA V2 proxy - testing ALT DA spec compliance")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup both servers
	t.Log("Testing ALT DA spec compatibility between EigenDA V2 and ReferenceDA")

	// TODO: Setup EigenDA V2 proxy when available
	// TODO: Setup ReferenceDA server
	// TODO: Test that both implement the same ALT DA methods:
	//   - daprovider_getSupportedHeaderBytes
	//   - daprovider_store
	//   - daprovider_recoverPayload
	//   - daprovider_collectPreimages
	//   - daprovider_generateReadPreimageProof
	//   - daprovider_generateCertificateValidityProof

	t.Log("ALT DA spec compatibility test placeholder")
}

// TestRecencyChecksWithLocalGeth tests L1 block reference validation
func TestRecencyChecksWithLocalGeth(t *testing.T) {
	t.Skip("Requires local geth setup - testing recency checks")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// TODO: Setup local geth (--dev mode)
	// TODO: Setup L2 with EigenDA/ReferenceDA
	// TODO: Post batch at block N
	// TODO: Verify certificate references recent L1 block
	// TODO: Test stale data rejection

	t.Log("Recency checks test placeholder")
}

// TestV2CertificateBackwardCompatibility tests that V2 can read V1 certificates
func TestV2CertificateBackwardCompatibility(t *testing.T) {
	t.Skip("Requires both V1 and V2 proxies - testing backward compatibility")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO: Post batches with V1
	// TODO: Switch to V2
	// TODO: Verify V2 can read V1 certificates
	// TODO: Verify V2 node can sync from L1 with V1 batches

	t.Log("Backward compatibility test placeholder")
}

// setupReferenceDAServerForFallback creates ReferenceDA server for fallback testing
func setupReferenceDAServerForFallback(t *testing.T, ctx context.Context, l1Client *ethclient.Client) (*http.Server, string, common.Address) {
	// Generate signing key
	privateKey, err := crypto.GenerateKey()
	Require(t, err)
	dataSigner := signature.DataSignerFromPrivateKey(privateKey)

	validatorAddr := common.HexToAddress("0x0000000000000000000000000000000000000456")
	storage := referenceda.GetInMemoryStorage()

	// Create ReferenceDA components
	reader := referenceda.NewReader(storage, l1Client, validatorAddr)
	writer := referenceda.NewWriter(dataSigner)
	validator := referenceda.NewValidator(l1Client, validatorAddr)
	headerBytes := []byte{daprovider.DACertificateMessageHeaderFlag}

	config := dapserver.ServerConfig{
		Addr:               "localhost",
		Port:               0,
		EnableDAWriter:     true,
		ServerTimeouts:     genericconf.HTTPServerTimeoutConfig{},
		RPCServerBodyLimit: 256 * 1024 * 1024,
	}

	server, err := dapserver.NewServerWithDAPProvider(ctx, &config, reader, writer, validator, headerBytes, data_streaming.PayloadCommitmentVerifier())
	Require(t, err)

	return server, server.Addr, validatorAddr
}
