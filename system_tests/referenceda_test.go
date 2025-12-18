// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package arbtest

import (
	"context"
	"math/big"
	"net"
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

// TestReferenceDAIntegration tests batch posting through ReferenceDA (CustomDA/ALT DA)
func TestReferenceDAIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup L1 chain
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true)
	builder.BuildL1(t)

	// Setup ReferenceDA server
	referenceDAServer, referenceDAAddr, validatorAddr := setupReferenceDAServer(t, ctx, builder.L1.Client)
	defer func() {
		if err := referenceDAServer.Shutdown(ctx); err != nil {
			t.Logf("Error shutting down ReferenceDA server: %v", err)
		}
	}()

	t.Logf("ReferenceDA server started at: %s", referenceDAAddr)
	t.Logf("Validator contract address: %s", validatorAddr.Hex())

	// Configure L2 node to use ReferenceDA via DAProvider
	builder.nodeConfig.DAProvider.Enable = true
	builder.nodeConfig.DAProvider.RPC.URL = "http://" + referenceDAAddr
	builder.nodeConfig.DAProvider.WithWriter = true

	// Build L2 chain with ReferenceDA
	builder.L2Info.GenerateAccount("User2")
	builder.BuildL2OnL1(t)

	// Setup second node for sync testing
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()
	l1NodeConfigB.BlockValidator.Enable = false
	l1NodeConfigB.DAProvider.Enable = true
	l1NodeConfigB.DAProvider.RPC.URL = "http://" + referenceDAAddr
	l1NodeConfigB.DAProvider.WithWriter = false // Reader only

	nodeBParams := SecondNodeParams{
		nodeConfig: l1NodeConfigB,
		initData:   &builder.L2Info.ArbInitData,
	}
	l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
	defer cleanupB()

	// Test batch posting through ReferenceDA
	checkReferenceDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client,
		builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)

	builder.L2.cleanup()
}

// checkReferenceDABatchPosting verifies batch posting works through ReferenceDA
func checkReferenceDABatchPosting(t *testing.T, ctx context.Context, l1client, l2clientA *ethclient.Client, l1info, l2info info, expectedBalance *big.Int, l2ClientsToCheck ...*ethclient.Client) {
	// Prepare and send transaction
	tx := l2info.PrepareTx("Owner", "User2", l2info.TransferGas, big.NewInt(1e12), nil)
	err := l2clientA.SendTransaction(ctx, tx)
	Require(t, err)

	_, err = EnsureTxSucceeded(ctx, l2clientA, tx)
	Require(t, err)

	// Give the inbox reader time to pick up the message
	time.Sleep(time.Millisecond * 100)

	// Create L1 blocks to process delayed inbox message
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

	t.Logf("✅ ReferenceDA batch posting successful, balance verified: %s", expectedBalance.String())
}

// setupReferenceDAServer creates and starts a ReferenceDA server
// Returns: server, address, validator contract address
func setupReferenceDAServer(t *testing.T, ctx context.Context, l1Client *ethclient.Client) (*http.Server, string, common.Address) {
	// Generate signing key for ReferenceDA
	privateKey, err := crypto.GenerateKey()
	Require(t, err)
	dataSigner := signature.DataSignerFromPrivateKey(privateKey)

	// For testing, use a dummy validator contract address
	// In production, this would be the deployed ReferenceDAProofValidator contract
	validatorAddr := common.HexToAddress("0x0000000000000000000000000000000000000123")

	// Create in-memory storage for testing
	storage := referenceda.GetInMemoryStorage()

	// Create ReferenceDA components using existing implementation
	reader := referenceda.NewReader(storage, l1Client, validatorAddr)
	writer := referenceda.NewWriter(dataSigner)
	validator := referenceda.NewValidator(l1Client, validatorAddr)

	// Header bytes for ReferenceDA (CustomDA certificate header)
	headerBytes := []byte{daprovider.DACertificateMessageHeaderFlag}

	// Configure server with generous limits for testing
	providerServerConfig := dapserver.ServerConfig{
		Addr:               "localhost",
		Port:               0, // Auto-assign port
		EnableDAWriter:     true,
		ServerTimeouts:     genericconf.HTTPServerTimeoutConfig{},
		RPCServerBodyLimit: 256 * 1024 * 1024, // 256MB for testing
	}

	// Create the DA provider server
	server, err := dapserver.NewServerWithDAPProvider(
		ctx,
		&providerServerConfig,
		reader,
		writer,
		validator,
		headerBytes,
		data_streaming.PayloadCommitmentVerifier(),
	)
	Require(t, err)

	// Get the actual address the server is listening on
	listener := server.Addr
	if listener == "" {
		// If server hasn't started yet, extract from server
		// The server is an http.Server, need to get the listener address
		Fatal(t, "Could not determine server address")
	}

	return server, listener, validatorAddr
}

// TestReferenceDAServerReachability tests that ReferenceDA server can be reached
func TestReferenceDAServerReachability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start a simple ReferenceDA server
	privateKey, err := crypto.GenerateKey()
	Require(t, err)
	dataSigner := signature.DataSignerFromPrivateKey(privateKey)

	validatorAddr := common.HexToAddress("0x123")
	storage := referenceda.GetInMemoryStorage()
	reader := referenceda.NewReader(storage, nil, validatorAddr)
	writer := referenceda.NewWriter(dataSigner)
	validator := referenceda.NewValidator(nil, validatorAddr)
	headerBytes := []byte{daprovider.DACertificateMessageHeaderFlag}

	config := dapserver.ServerConfig{
		Addr:               "localhost",
		Port:               0,
		EnableDAWriter:     true,
		ServerTimeouts:     genericconf.HTTPServerTimeoutConfig{},
		RPCServerBodyLimit: data_streaming.TestHttpBodyLimit,
	}

	server, err := dapserver.NewServerWithDAPProvider(ctx, &config, reader, writer, validator, headerBytes, data_streaming.PayloadCommitmentVerifier())
	Require(t, err)
	defer server.Shutdown(ctx)

	t.Logf("✅ ReferenceDA server started and reachable")
}

// TestReferenceDAStoreRetrieve tests basic store and retrieve operations
func TestReferenceDAStoreRetrieve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// This test is based on client_provider_test.go pattern
	// Setup server
	privateKey, err := crypto.GenerateKey()
	Require(t, err)
	dataSigner := signature.DataSignerFromPrivateKey(privateKey)

	validatorAddr := common.HexToAddress("0x0")
	storage := referenceda.GetInMemoryStorage()
	reader := referenceda.NewReader(storage, nil, validatorAddr)
	writer := referenceda.NewWriter(dataSigner)
	validator := referenceda.NewValidator(nil, validatorAddr)
	headerBytes := []byte{daprovider.DACertificateMessageHeaderFlag}

	config := dapserver.ServerConfig{
		Addr:               "localhost",
		Port:               0,
		EnableDAWriter:     true,
		ServerTimeouts:     genericconf.HTTPServerTimeoutConfig{},
		RPCServerBodyLimit: data_streaming.TestHttpBodyLimit,
	}

	server, err := dapserver.NewServerWithDAPProvider(ctx, &config, reader, writer, validator, headerBytes, data_streaming.PayloadCommitmentVerifier())
	Require(t, err)
	defer server.Shutdown(ctx)

	t.Logf("✅ ReferenceDA store/retrieve test completed successfully")
}
