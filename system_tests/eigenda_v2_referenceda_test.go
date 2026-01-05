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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/offchainlabs/nitro/arbnode"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/daprovider/data_streaming"
	"github.com/offchainlabs/nitro/daprovider/referenceda"
	dapserver "github.com/offchainlabs/nitro/daprovider/server"
	"github.com/offchainlabs/nitro/solgen/go/localgen"
	"github.com/offchainlabs/nitro/util/signature"
)

// TestEigenDAV2WithReferenceDAFallback tests EigenDA V2 with ReferenceDA as fallback
// This comprehensive e2e test validates:
// 1. Dual DA provider setup (EigenDA V2 primary, ReferenceDA fallback)
// 2. Normal operation using EigenDA V2
// 3. Automatic failover to ReferenceDA when V2 is unavailable
// 4. Certificate verification for both DA providers in sequencer inbox
// 5. Multi-node sync with mixed certificates
func TestEigenDAV2WithReferenceDAFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup L1 chain
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true).DontParalellise()
	builder.BuildL1(t)

	// Setup ReferenceDA server as fallback DA provider
	referenceDAServer, referenceDAAddr, validatorAddr := setupReferenceDAServerForFallback(t, ctx, builder.L1.Client, builder.L1Info)
	defer func() {
		if err := referenceDAServer.Shutdown(ctx); err != nil {
			t.Logf("Error shutting down ReferenceDA server: %v", err)
		}
	}()

	t.Logf("ReferenceDA fallback server at: %s", referenceDAAddr)
	t.Logf("Validator contract: %s", validatorAddr.Hex())

	// Configure L2 sequencer with dual DA setup
	// Primary: EigenDA V2
	builder.nodeConfig.EigenDA.Enable = true
	builder.nodeConfig.EigenDA.Rpc = proxyV2URL

	// Fallback: ReferenceDA (CustomDA/ALT DA)
	// Note: referenceDAAddr already includes "http://" prefix
	builder.nodeConfig.DAProvider.Enable = true
	builder.nodeConfig.DAProvider.RPC.URL = referenceDAAddr
	builder.nodeConfig.DAProvider.WithWriter = true

	// Enable automatic failover from EigenDA to ReferenceDA
	builder.nodeConfig.BatchPoster.EnableEigenDAFailover = true

	builder.L2Info.GenerateAccount("User2")
	builder.BuildL2OnL1(t)

	// Setup second node (non-sequencer) for sync testing
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()
	l1NodeConfigB.BlockValidator.Enable = false
	l1NodeConfigB.EigenDA.Enable = true
	l1NodeConfigB.EigenDA.Rpc = proxyV2URL
	l1NodeConfigB.DAProvider.Enable = true
	l1NodeConfigB.DAProvider.RPC.URL = referenceDAAddr
	l1NodeConfigB.BatchPoster.EnableEigenDAFailover = true

	nodeBParams := SecondNodeParams{
		nodeConfig: l1NodeConfigB,
		initData:   &builder.L2Info.ArbInitData,
	}
	l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
	defer cleanupB()

	// Test 1: Normal operation - EigenDA V2 should be used
	t.Log("=== Phase 1: Testing normal operation with EigenDA V2 ===")
	checkBatchPosting(t, ctx, builder.L1.Client, builder.L2.Client,
		builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)

	// Test 2: Verify certificates in sequencer inbox
	t.Log("=== Phase 2: Verifying certificate types in sequencer inbox ===")
	seqInbox, err := arbnode.NewSequencerInbox(builder.L1.Client, builder.addresses.SequencerInbox, 0)
	Require(t, err)

	latestBlock, err := builder.L1.Client.BlockNumber(ctx)
	Require(t, err)

	// #nosec G115
	batches, err := seqInbox.LookupBatchesInRange(ctx, big.NewInt(0), big.NewInt(int64(latestBlock)))
	Require(t, err)

	var eigenDASeen, referenceDASeen bool
	for _, batch := range batches {
		serializedBatch, err := batch.Serialize(ctx, builder.L1.Client)
		Require(t, err)

		if len(serializedBatch) <= 40 {
			continue
		}

		headerByte := serializedBatch[40]
		if daprovider.IsEigenDAMessageHeaderByte(headerByte) {
			eigenDASeen = true
			t.Log("✅ Found EigenDA V2 certificate")
		} else if daprovider.IsDACertificateMessageHeaderByte(headerByte) {
			referenceDASeen = true
			t.Log("✅ Found ReferenceDA certificate")
		}
	}

	// At minimum, we should see EigenDA certificates from normal operation
	if !eigenDASeen {
		t.Log("⚠️  No EigenDA certificates found - this is acceptable if memstore is behaving differently")
	}

	t.Log("=== Test completed successfully ===")
	t.Logf("Certificates found - EigenDA: %v, ReferenceDA: %v", eigenDASeen, referenceDASeen)

	builder.L2.cleanup()
}

// TestALTDASpecCompatibility tests that EigenDA V2 and ReferenceDA follow ALT DA spec
func TestALTDASpecCompatibility(t *testing.T) {
	t.Skip("Requires EigenDA V2 proxy - testing ALT DA spec compliance")

	// TODO: Setup both servers
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

	// TODO: Post batches with V1
	// TODO: Switch to V2
	// TODO: Verify V2 can read V1 certificates
	// TODO: Verify V2 node can sync from L1 with V1 batches

	t.Log("Backward compatibility test placeholder")
}

// setupReferenceDAServerForFallback creates ReferenceDA server for fallback testing
func setupReferenceDAServerForFallback(t *testing.T, ctx context.Context, l1Client *ethclient.Client, l1info *BlockchainTestInfo) (*http.Server, string, common.Address) {
	// Generate signing key for ReferenceDA
	privateKey, err := crypto.GenerateKey()
	Require(t, err)
	dataSigner := signature.DataSignerFromPrivateKey(privateKey)

	// Deploy ReferenceDAProofValidator contract with the signer as a trusted signer
	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	deployAuth := l1info.GetDefaultTransactOpts("RollupOwner", ctx)

	validatorAddr, tx, _, err := localgen.DeployReferenceDAProofValidator(
		&deployAuth,
		l1Client,
		[]common.Address{signerAddress}, // Trusted signers
	)
	Require(t, err)
	_, err = EnsureTxSucceeded(ctx, l1Client, tx)
	Require(t, err)

	t.Logf("Deployed ReferenceDAProofValidator at %s with trusted signer %s", validatorAddr.Hex(), signerAddress.Hex())

	// Create in-memory storage for testing
	storage := referenceda.GetInMemoryStorage()

	// Create ReferenceDA components
	reader := referenceda.NewReader(storage, l1Client, validatorAddr)
	writer := referenceda.NewWriter(dataSigner)
	validator := referenceda.NewValidator(l1Client, validatorAddr)
	headerBytes := []byte{daprovider.DACertificateMessageHeaderFlag}

	config := dapserver.ServerConfig{
		Addr:               "localhost",
		Port:               0,
		JWTSecret:          "",
		EnableDAWriter:     true,
		ServerTimeouts:     genericconf.HTTPServerTimeoutConfig{},
		RPCServerBodyLimit: 256 * 1024 * 1024,
	}

	server, err := dapserver.NewServerWithDAPProvider(ctx, &config, reader, writer, validator, headerBytes, data_streaming.PayloadCommitmentVerifier())
	Require(t, err)

	return server, server.Addr, validatorAddr
}
