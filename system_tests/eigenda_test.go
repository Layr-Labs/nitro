// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package arbtest

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"

	"github.com/offchainlabs/nitro/arbnode"
	"github.com/offchainlabs/nitro/execution/gethexec"
)

const (
	proxyURL = "http://127.0.0.1:4242"
)

func TestEigenDAProxyBatchPosting(t *testing.T) {

	initTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()

	// Setup L1 chain and contracts
	chainConfig := params.ArbitrumDevTestEigenDAConfig()
	l1info, l1client, _, l1stack := createTestL1BlockChain(t, nil)
	defer requireClose(t, l1stack)
	feedErrChan := make(chan error, 10)
	addresses, initMessage := DeployOnTestL1(t, ctx, l1info, l1client, chainConfig)

	nodeDir := t.TempDir()
	l2info := NewArbTestInfo(t, chainConfig.ChainID)
	l1NodeConfigA := arbnode.ConfigDefaultL1Test()
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()
	sequencerTxOpts := l1info.GetDefaultTransactOpts("Sequencer", ctx)
	sequencerTxOptsPtr := &sequencerTxOpts
	parentChainID := big.NewInt(1337)
	{

		// Setup L2 chain
		_, l2stackA, l2chainDb, l2arbDb, l2blockchain := createL2BlockChainWithStackConfig(t, l2info, nodeDir, chainConfig, initMessage, nil, nil)
		l2info.GenerateAccount("User2")

		// Setup EigenDA config
		l1NodeConfigA.EigenDA.Enable = true
		l1NodeConfigA.EigenDA.Rpc = proxyURL

		execA, err := gethexec.CreateExecutionNode(ctx, l2stackA, l2chainDb, l2blockchain, l1client, gethexec.ConfigDefaultTest)
		Require(t, err)

		l2Cfg := l2blockchain.Config()
		l2Cfg.ArbitrumChainParams.DataAvailabilityCommittee = false
		l2Cfg.ArbitrumChainParams.EigenDA = true
		nodeA, err := arbnode.CreateNode(ctx, l2stackA, execA, l2arbDb, NewFetcherFromConfig(l1NodeConfigA), l2Cfg, l1client, addresses, sequencerTxOptsPtr, sequencerTxOptsPtr, nil, feedErrChan, parentChainID, nil)
		Require(t, err)
		Require(t, nodeA.Start(ctx))
		l2clientA := ClientForStack(t, l2stackA)

		l1NodeConfigB.BlockValidator.Enable = false
		l1NodeConfigB.EigenDA.Enable = true
		l1NodeConfigB.EigenDA.Rpc = proxyURL

		l2clientB, nodeB := Create2ndNodeWithConfig(t, ctx, nodeA, l1stack, l1info, &l2info.ArbInitData, l1NodeConfigB, nil, nil)
		checkEigenDABatchPosting(t, ctx, l1client, l2clientA, l1info, l2info, big.NewInt(1e12), l2clientB)
		nodeA.StopAndWait()
		nodeB.StopAndWait()
	}
}

func checkEigenDABatchPosting(t *testing.T, ctx context.Context, l1client, l2clientA *ethclient.Client, l1info, l2info info, expectedBalance *big.Int, l2ClientsToCheck ...*ethclient.Client) {
	tx := l2info.PrepareTx("Owner", "User2", l2info.TransferGas, big.NewInt(1e12), nil)
	err := l2clientA.SendTransaction(ctx, tx)
	Require(t, err)

	_, err = EnsureTxSucceeded(ctx, l2clientA, tx)
	Require(t, err)

	// give the inbox reader a bit of time to pick up the delayed message
	time.Sleep(time.Millisecond * 100)

	// sending l1 messages creates l1 blocks.. make enough to get that delayed inbox message in
	for i := 0; i < 100; i++ {
		SendWaitTestTransactions(t, ctx, l1client, []*types.Transaction{
			l1info.PrepareTx("Faucet", "User", 30000, big.NewInt(1e12), nil),
		})
	}

	for _, client := range l2ClientsToCheck {
		_, err = WaitForTx(ctx, client, tx.Hash(), time.Second*100)
		Require(t, err)

		l2balance, err := client.BalanceAt(ctx, l2info.GetAddress("User2"), nil)
		Require(t, err)

		if l2balance.Cmp(expectedBalance) != 0 {
			Fatal(t, "Unexpected balance:", l2balance)
		}

	}
}
