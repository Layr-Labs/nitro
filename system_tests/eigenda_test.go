// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package arbtest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenda-proxy/clients/memconfig_client"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/offchainlabs/nitro/arbnode"
	"github.com/offchainlabs/nitro/arbstate/daprovider"
	"github.com/offchainlabs/nitro/cmd/chaininfo"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/offchainlabs/nitro/daprovider/das"
	"github.com/offchainlabs/nitro/solgen/go/precompilesgen"
	"github.com/offchainlabs/nitro/util/headerreader"
)

const (
	v1Backend     = "v1"
	v1ToV2Backend = "v1-to-v2"
	v2Backend     = "v2"

	// TODO: https://github.com/Layr-Labs/nitro/issues/73
	proxyURLV1     = "http://127.0.0.1:4242"
	proxyURLV1ToV2 = "http://127.0.0.1:4200"
	proxyURLV2     = "http://127.0.0.1:6969"
)

func setEigenDAProxyDispersalBackend(baseURL string, backend string) error {
	url := fmt.Sprintf("%s/admin/eigenda-dispersal-backend", baseURL)

	payload := map[string]string{
		"eigenDADispersalBackend": backend,
	}
}

func TestEigenDAIntegration(t *testing.T) {
	// single threaded test execution since conflicts can happen
	// on proxy memconfig states if ran in parallel.
	// TODO: https://github.com/Layr-Labs/nitro/issues/73

	// 0 - Test that the proxy is reachable
	testEigenDAProxyReachability(t)

	// 1 - Batch posting / derivation
	testEigenDAProxyBatchPosting(t)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("Successfully set dispersal backend to v2. Status: %s", resp.Status)
	} else {
		return fmt.Errorf("server returned non-2xx status: %s", resp.Status)
	}

	return nil
}

func getProxyURL(proxyBackend string) string {
	switch proxyBackend {
	case v1Backend:
		return proxyURLV1

	case v2Backend:
		return proxyURLV2

	case v1ToV2Backend:
		return proxyURLV1ToV2

	default:
		panic("could not determine proxy url from backend: " + proxyBackend)
	}
}

// single threaded test execution since conflicts can happen
// on proxy memconfig states if ran in parallel.
// TODO: https://github.com/Layr-Labs/nitro/issues/73
func TestEigenDAIntegrationV1(t *testing.T) {
	testEigenDAProxyBatchPosting(t, v1Backend)

	testFailOverFromEigenDAToAnyTrust(t, v1Backend)
	testFailOverFromEigenDAToCallData(t, v1Backend)
	testEigenDAIntegrationV1ToV2InsecureMigration(t)
}

func TestEigenDAIntegrationV2(t *testing.T) {
	testEigenDAProxyBatchPosting(t, v2Backend)

	testFailOverFromEigenDAToAnyTrust(t, v2Backend)
	testFailOverFromEigenDAToCallData(t, v2Backend)
}

func testEigenDAIntegrationV1ToV2InsecureMigration(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()

	// Setup L1 chain and contracts
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true)
	builder.BuildL1(t)
	// Setup DAS servers
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()

	{
		builder.nodeConfig.EigenDA.Enable = true
		builder.nodeConfig.EigenDA.Rpc = getProxyURL(v1ToV2Backend)

		// Setup L2 chain
		builder.L2Info.GenerateAccount("User2")
		builder.BuildL2OnL1(t)

		// Setup second node
		l1NodeConfigB.BlockValidator.Enable = false
		l1NodeConfigB.EigenDA.Enable = true
		l1NodeConfigB.EigenDA.Rpc = getProxyURL(v1ToV2Backend)

		nodeBParams := SecondNodeParams{
			nodeConfig: l1NodeConfigB,
			initData:   &builder.L2Info.ArbInitData,
		}
		l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
		checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)

		err := setEigenDAProxyDispersalBackend(getProxyURL(v1ToV2Backend), v2Backend)
		Require(t, err)

		defer setEigenDAProxyDispersalBackend(getProxyURL(v1ToV2Backend), v2Backend)

		checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12*2), l2B.Client)

		seqInbox, err := arbnode.NewSequencerInbox(builder.L1.Client, builder.addresses.SequencerInbox, 0)
		Require(t, err)

		latestBlock, err := builder.L1.Client.BlockNumber(ctx)
		Require(t, err)

		batches, err := seqInbox.LookupBatchesInRange(ctx, big.NewInt(0), big.NewInt(int64(latestBlock)))
		Require(t, err)

		// ensure that sequencer inbox contains both V1 and V2 certificates
		var v1Seen, v2Seen bool = false, false

		for _, batch := range batches {
			serializedBatch, err := batch.Serialize(ctx, builder.L1.Client)
			Require(t, err)

			if len(serializedBatch) <= 40 {
				continue
			}

			if daprovider.IsEigenDAV1HeaderByte(serializedBatch[40]) {
				v1Seen = true
			} else if daprovider.IsEigenDAV2HeaderByte(serializedBatch[40]) {
				v2Seen = true
			}
		}

		if !v1Seen || !v2Seen {
			t.Fatal("expected both v1 and v2 eigenda certs to be seen within Sequencer Inbox")
		}
		cleanupB()

		// build another secondary node to re-trigger derivation pipeline
		l2B, cleanupB = builder.Build2ndNode(t, &nodeBParams)
		checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12*3), l2B.Client)

		builder.L2.cleanup()
	}
}

func testEigenDAProxyBatchPosting(t *testing.T, backend string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()

	// Setup L1 chain and contracts
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true)
	builder.BuildL1(t)
	// Setup DAS servers
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()

	{

		// Setup DAS config
		builder.nodeConfig.EigenDA.Enable = true
		builder.nodeConfig.EigenDA.Rpc = getProxyURL(backend)

		// Setup L2 chain
		builder.L2Info.GenerateAccount("User2")
		builder.BuildL2OnL1(t)

		// Setup second node
		l1NodeConfigB.BlockValidator.Enable = false
		l1NodeConfigB.EigenDA.Enable = true
		l1NodeConfigB.EigenDA.Rpc = getProxyURL(backend)

		nodeBParams := SecondNodeParams{
			nodeConfig: l1NodeConfigB,
			initData:   &builder.L2Info.ArbInitData,
		}
		l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
		checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)

		builder.L2.cleanup()
		cleanupB()
	}
}

func testFailOverFromEigenDAToCallData(t *testing.T, backend string) {
	memCfgClient := memconfig_client.New(
		&memconfig_client.Config{URL: getProxyURL(backend)},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()

	// Setup L1 chain and contracts
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true)
	builder.BuildL1(t)
	// Setup DAS servers
	l1NodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest()

	{

		// Setup DAS config
		builder.nodeConfig.EigenDA.Enable = true
		builder.nodeConfig.EigenDA.Rpc = getProxyURL(backend)
		builder.nodeConfig.BatchPoster.EnableEigenDAFailover = true

		// Setup L2 chain
		builder.L2Info.GenerateAccount("User2")
		builder.BuildL2OnL1(t)

		// Setup second node
		l1NodeConfigB.BlockValidator.Enable = false
		l1NodeConfigB.EigenDA.Enable = true
		l1NodeConfigB.EigenDA.Rpc = getProxyURL(backend)
		l1NodeConfigB.BatchPoster.EnableEigenDAFailover = true

		nodeBParams := SecondNodeParams{
			nodeConfig: l1NodeConfigB,
			initData:   &builder.L2Info.ArbInitData,
		}
		l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)

		// 1 - Ensure that batches can be submitted and read via EigenDA batch posting
		checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)

		// 2 - Cause EigenDA to fail and ensure that the system falls back to anytrust in the presence of 503 eigenda-proxy errors
		memCfg, err := memCfgClient.GetConfig(ctx)
		Require(t, err)

		memCfg.PutReturnsFailoverError = true
		_, err = memCfgClient.UpdateConfig(ctx, memCfg)
		Require(t, err)

		checkBatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12*2), l2B.Client)

		// 3 - Emulate EigenDA becoming healthy again and ensure that the system starts using it for DA
		memCfg.PutReturnsFailoverError = false
		memCfgClient.UpdateConfig(ctx, memCfg)

		checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12*3), l2B.Client)
		builder.L2.cleanup()
		cleanupB()
	}
}

func testFailOverFromEigenDAToAnyTrust(t *testing.T, backend string) {
	initEigenDATest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	memCfgClient := memconfig_client.New(
		&memconfig_client.Config{URL: getProxyURL(backend)},
	)

	// Setup L1 chain and contracts
	builder := NewNodeBuilder(ctx).DefaultConfig(t, true)
	builder.chainConfig = chaininfo.ArbitrumDevTestDASChainConfig()
	builder.BuildL1(t)

	arbSys, _ := precompilesgen.NewArbSys(types.ArbSysAddress, builder.L1.Client)
	l1Reader, err := headerreader.New(ctx, builder.L1.Client, func() *headerreader.Config { return &headerreader.TestConfig }, arbSys)
	Require(t, err)
	l1Reader.Start(ctx)
	defer l1Reader.StopAndWait()

	keyDir, fileDataDir, dbDataDir := t.TempDir(), t.TempDir(), t.TempDir()
	pubkey, _, err := das.GenerateAndStoreKeys(keyDir)
	Require(t, err)

	dbConfig := das.DefaultLocalDBStorageConfig
	dbConfig.Enable = true
	dbConfig.DataDir = dbDataDir

	serverConfig := das.DataAvailabilityConfig{
		Enable: true,

		LocalCache: das.TestCacheConfig,

		LocalFileStorage: das.LocalFileStorageConfig{
			Enable:  true,
			DataDir: fileDataDir,
		},
		LocalDBStorage: dbConfig,

		Key: das.KeyConfig{
			KeyDir: keyDir,
		},

		RequestTimeout: 5 * time.Second,
		// L1NodeURL: normally we would have to set this but we are passing in the already constructed client and addresses to the factory
	}

	daReader, daWriter, signatureVerifier, daHealthChecker, lifecycleManager, err := das.CreateDAComponentsForDaserver(ctx, &serverConfig, l1Reader, &builder.addresses.SequencerInbox)
	Require(t, err)
	defer lifecycleManager.StopAndWaitUntil(time.Second)
	rpcLis, err := net.Listen("tcp", "localhost:0")
	Require(t, err)
	_, err = das.StartDASRPCServerOnListener(ctx, rpcLis, genericconf.HTTPServerTimeoutConfigDefault, genericconf.HTTPServerBodyLimitDefault, daReader, daWriter, daHealthChecker, signatureVerifier)
	Require(t, err)
	restLis, err := net.Listen("tcp", "localhost:0")
	Require(t, err)
	restServer, err := das.NewRestfulDasServerOnListener(restLis, genericconf.HTTPServerTimeoutConfigDefault, daReader, daHealthChecker)
	Require(t, err)

	pubkeyA := pubkey
	authorizeDASKeyset(t, ctx, pubkeyA, builder.L1Info, builder.L1.Client)

	// Set AnyTrust params into L2 node config
	builder.nodeConfig.DataAvailability = das.DataAvailabilityConfig{
		Enable: true,

		// AggregatorConfig set up below
		RequestTimeout: 5 * time.Second,
	}
	beConfigA := das.BackendConfig{
		URL:    "http://" + rpcLis.Addr().String(),
		Pubkey: blsPubToBase64(pubkey),
	}
	builder.nodeConfig.DataAvailability.RPCAggregator = aggConfigForBackend(beConfigA)
	builder.nodeConfig.DataAvailability.RestAggregator = das.DefaultRestfulClientAggregatorConfig
	builder.nodeConfig.DataAvailability.RestAggregator.Enable = true
	builder.nodeConfig.DataAvailability.RestAggregator.Urls = []string{"http://" + restLis.Addr().String()}
	builder.nodeConfig.DataAvailability.ParentChainNodeURL = "none"

	// set EigenDA params into L2 sequencer config
	builder.nodeConfig.EigenDA.Enable = true
	builder.nodeConfig.EigenDA.Rpc = getProxyURL(backend)
	builder.nodeConfig.BatchPoster.EnableEigenDAFailover = true

	// Setup L2 chain
	builder.L2Info = NewArbTestInfo(t, builder.chainConfig.ChainID)
	builder.L2Info.GenerateAccount("User2")
	cleanup := builder.BuildL2OnL1(t)

	defer cleanup()

	// Create node to sync from chain
	childNodeConfigB := arbnode.ConfigDefaultL1NonSequencerTest().WithEigenDATestConfigParams()
	childNodeConfigB.DataAvailability = das.DataAvailabilityConfig{
		Enable: true,

		// AggregatorConfig set up below

		ParentChainNodeURL: "none",
		RequestTimeout:     5 * time.Second,
	}

	childNodeConfigB.BlockValidator.Enable = false
	childNodeConfigB.DataAvailability.Enable = true
	childNodeConfigB.DataAvailability.RestAggregator = das.DefaultRestfulClientAggregatorConfig
	childNodeConfigB.DataAvailability.RestAggregator.Enable = true
	childNodeConfigB.DataAvailability.RestAggregator.Urls = []string{"http://" + restLis.Addr().String()}
	childNodeConfigB.DataAvailability.ParentChainNodeURL = "none"
	childNodeConfigB.EigenDA.Enable = true
	childNodeConfigB.EigenDA.Rpc = getProxyURL(backend)
	childNodeConfigB.BatchPoster.EnableEigenDAFailover = true
	childNodeConfigB.BatchPoster.CheckBatchCorrectness = true

	nodeBParams := SecondNodeParams{
		nodeConfig: childNodeConfigB,
		initData:   &builder.L2Info.ArbInitData,
	}
	l2B, cleanupB := builder.Build2ndNode(t, &nodeBParams)
	defer cleanupB()

	// 1 - Ensure that batches can be submitted and read via EigenDA batch posting
	checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12), l2B.Client)
	// 2 - Cause EigenDA to fail and ensure that the system falls back to anytrust in the presence of 503 eigenda-proxy errors

	memCfg, err := memCfgClient.GetConfig(ctx)
	Require(t, err)

	memCfg.PutReturnsFailoverError = true
	_, err = memCfgClient.UpdateConfig(ctx, memCfg)

	checkBatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12*2), l2B.Client)
	// 3 - Emulate EigenDA becoming healthy again and ensure that the system starts using it for DA

	memCfg.PutReturnsFailoverError = false
	_, err = memCfgClient.UpdateConfig(ctx, memCfg)
	Require(t, err)

	checkEigenDABatchPosting(t, ctx, builder.L1.Client, builder.L2.Client, builder.L1Info, builder.L2Info, big.NewInt(1e12*3), l2B.Client)

	err = restServer.Shutdown()
	Require(t, err)
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

// TestEigenDAProxyReachability tests that the EigenDA proxy is accessible
func testEigenDAProxyReachability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	memCfgClient := memconfig_client.New(&memconfig_client.Config{URL: proxyURL})

	_, err := memCfgClient.GetConfig(ctx)
	if err != nil {
		t.Fatalf("❌ EigenDA proxy not reachable at %s: %v", proxyURL, err)
	}
	t.Logf("✅ EigenDA proxy reachable at %s", proxyURL)
}
