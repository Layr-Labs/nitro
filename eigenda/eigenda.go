package eigenda

import (
	"bytes"
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/offchainlabs/nitro/arbstate/daprovider"
)

var sequencerInboxABI abi.ABI

func init() {
	var err error
	rawABI := `[{"type":"constructor","inputs":[{"name":"_maxDataSize","type":"uint256","internalType":"uint256"},{"name":"reader4844_","type":"address","internalType":"contract IReader4844"},{"name":"eigenDAServiceManager_","type":"address","internalType":"contract IEigenDAServiceManager"},{"name":"eigenDARollupManager_","type":"address","internalType":"contract IRollupManager"},{"name":"_isUsingFeeToken","type":"bool","internalType":"bool"}],"stateMutability":"nonpayable"},{"type":"function","name":"BROTLI_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"DAS_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"DATA_AUTHENTICATED_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"DATA_BLOB_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"EIGENDA_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"HEADER_LENGTH","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"TREE_DAS_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"ZERO_HEAVY_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"addSequencerL2Batch","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"gasRefunder","type":"address","internalType":"contract IGasRefunder"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"addSequencerL2BatchFromBlobs","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"gasRefunder","type":"address","internalType":"contract IGasRefunder"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"addSequencerL2BatchFromEigenDA","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"blobVerificationProof","type":"tuple","internalType":"struct EigenDARollupUtils.BlobVerificationProof","components":[{"name":"batchId","type":"uint32","internalType":"uint32"},{"name":"blobIndex","type":"uint32","internalType":"uint32"},{"name":"batchMetadata","type":"tuple","internalType":"struct IEigenDAServiceManager.BatchMetadata","components":[{"name":"batchHeader","type":"tuple","internalType":"struct IEigenDAServiceManager.BatchHeader","components":[{"name":"blobHeadersRoot","type":"bytes32","internalType":"bytes32"},{"name":"quorumNumbers","type":"bytes","internalType":"bytes"},{"name":"signedStakeForQuorums","type":"bytes","internalType":"bytes"},{"name":"referenceBlockNumber","type":"uint32","internalType":"uint32"}]},{"name":"signatoryRecordHash","type":"bytes32","internalType":"bytes32"},{"name":"confirmationBlockNumber","type":"uint32","internalType":"uint32"}]},{"name":"inclusionProof","type":"bytes","internalType":"bytes"},{"name":"quorumIndices","type":"bytes","internalType":"bytes"}]},{"name":"blobHeader","type":"tuple","internalType":"struct IEigenDAServiceManager.BlobHeader","components":[{"name":"commitment","type":"tuple","internalType":"struct BN254.G1Point","components":[{"name":"X","type":"uint256","internalType":"uint256"},{"name":"Y","type":"uint256","internalType":"uint256"}]},{"name":"dataLength","type":"uint32","internalType":"uint32"},{"name":"quorumBlobParams","type":"tuple[]","internalType":"struct IEigenDAServiceManager.QuorumBlobParam[]","components":[{"name":"quorumNumber","type":"uint8","internalType":"uint8"},{"name":"adversaryThresholdPercentage","type":"uint8","internalType":"uint8"},{"name":"confirmationThresholdPercentage","type":"uint8","internalType":"uint8"},{"name":"chunkLength","type":"uint32","internalType":"uint32"}]}]},{"name":"gasRefunder","type":"address","internalType":"contract IGasRefunder"},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"addSequencerL2BatchFromOrigin","inputs":[{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"bytes","internalType":"bytes"},{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"address","internalType":"contract IGasRefunder"}],"outputs":[],"stateMutability":"pure"},{"type":"function","name":"addSequencerL2BatchFromOrigin","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"gasRefunder","type":"address","internalType":"contract IGasRefunder"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"batchCount","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"batchPosterManager","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"bridge","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IBridge"}],"stateMutability":"view"},{"type":"function","name":"dasKeySetInfo","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"isValidKeyset","type":"bool","internalType":"bool"},{"name":"creationBlock","type":"uint64","internalType":"uint64"}],"stateMutability":"view"},{"type":"function","name":"eigenDARollupManager","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IRollupManager"}],"stateMutability":"view"},{"type":"function","name":"eigenDAServiceManager","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IEigenDAServiceManager"}],"stateMutability":"view"},{"type":"function","name":"forceInclusion","inputs":[{"name":"_totalDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"kind","type":"uint8","internalType":"uint8"},{"name":"l1BlockAndTime","type":"uint64[2]","internalType":"uint64[2]"},{"name":"baseFeeL1","type":"uint256","internalType":"uint256"},{"name":"sender","type":"address","internalType":"address"},{"name":"messageDataHash","type":"bytes32","internalType":"bytes32"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"getKeysetCreationBlock","inputs":[{"name":"ksHash","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"inboxAccs","inputs":[{"name":"index","type":"uint256","internalType":"uint256"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},{"type":"function","name":"initialize","inputs":[{"name":"bridge_","type":"address","internalType":"contract IBridge"},{"name":"maxTimeVariation_","type":"tuple","internalType":"struct ISequencerInbox.MaxTimeVariation","components":[{"name":"delayBlocks","type":"uint256","internalType":"uint256"},{"name":"futureBlocks","type":"uint256","internalType":"uint256"},{"name":"delaySeconds","type":"uint256","internalType":"uint256"},{"name":"futureSeconds","type":"uint256","internalType":"uint256"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"invalidateKeysetHash","inputs":[{"name":"ksHash","type":"bytes32","internalType":"bytes32"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"isBatchPoster","inputs":[{"name":"","type":"address","internalType":"address"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"isSequencer","inputs":[{"name":"","type":"address","internalType":"address"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"isUsingFeeToken","inputs":[],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"isValidKeysetHash","inputs":[{"name":"ksHash","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"maxDataSize","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"maxTimeVariation","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"postUpgradeInit","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"reader4844","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IReader4844"}],"stateMutability":"view"},{"type":"function","name":"removeDelayAfterFork","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"rollup","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IOwnable"}],"stateMutability":"view"},{"type":"function","name":"setBatchPosterManager","inputs":[{"name":"newBatchPosterManager","type":"address","internalType":"address"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setIsBatchPoster","inputs":[{"name":"addr","type":"address","internalType":"address"},{"name":"isBatchPoster_","type":"bool","internalType":"bool"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setIsSequencer","inputs":[{"name":"addr","type":"address","internalType":"address"},{"name":"isSequencer_","type":"bool","internalType":"bool"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setMaxTimeVariation","inputs":[{"name":"maxTimeVariation_","type":"tuple","internalType":"struct ISequencerInbox.MaxTimeVariation","components":[{"name":"delayBlocks","type":"uint256","internalType":"uint256"},{"name":"futureBlocks","type":"uint256","internalType":"uint256"},{"name":"delaySeconds","type":"uint256","internalType":"uint256"},{"name":"futureSeconds","type":"uint256","internalType":"uint256"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setValidKeyset","inputs":[{"name":"keysetBytes","type":"bytes","internalType":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"totalDelayedMessagesRead","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"event","name":"InboxMessageDelivered","inputs":[{"name":"messageNum","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"data","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"event","name":"InboxMessageDeliveredFromOrigin","inputs":[{"name":"messageNum","type":"uint256","indexed":true,"internalType":"uint256"}],"anonymous":false},{"type":"event","name":"InvalidateKeyset","inputs":[{"name":"keysetHash","type":"bytes32","indexed":true,"internalType":"bytes32"}],"anonymous":false},{"type":"event","name":"OwnerFunctionCalled","inputs":[{"name":"id","type":"uint256","indexed":true,"internalType":"uint256"}],"anonymous":false},{"type":"event","name":"SequencerBatchData","inputs":[{"name":"batchSequenceNumber","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"data","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"event","name":"SequencerBatchDelivered","inputs":[{"name":"batchSequenceNumber","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"beforeAcc","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"afterAcc","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"delayedAcc","type":"bytes32","indexed":false,"internalType":"bytes32"},{"name":"afterDelayedMessagesRead","type":"uint256","indexed":false,"internalType":"uint256"},{"name":"timeBounds","type":"tuple","indexed":false,"internalType":"struct IBridge.TimeBounds","components":[{"name":"minTimestamp","type":"uint64","internalType":"uint64"},{"name":"maxTimestamp","type":"uint64","internalType":"uint64"},{"name":"minBlockNumber","type":"uint64","internalType":"uint64"},{"name":"maxBlockNumber","type":"uint64","internalType":"uint64"}]},{"name":"dataLocation","type":"uint8","indexed":false,"internalType":"enum IBridge.BatchDataLocation"}],"anonymous":false},{"type":"event","name":"SetValidKeyset","inputs":[{"name":"keysetHash","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"keysetBytes","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"error","name":"AlreadyInit","inputs":[]},{"type":"error","name":"AlreadyValidDASKeyset","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}]},{"type":"error","name":"BadMaxTimeVariation","inputs":[]},{"type":"error","name":"BadPostUpgradeInit","inputs":[]},{"type":"error","name":"BadSequencerNumber","inputs":[{"name":"stored","type":"uint256","internalType":"uint256"},{"name":"received","type":"uint256","internalType":"uint256"}]},{"type":"error","name":"DataBlobsNotSupported","inputs":[]},{"type":"error","name":"DataTooLarge","inputs":[{"name":"dataLength","type":"uint256","internalType":"uint256"},{"name":"maxDataLength","type":"uint256","internalType":"uint256"}]},{"type":"error","name":"DelayedBackwards","inputs":[]},{"type":"error","name":"DelayedTooFar","inputs":[]},{"type":"error","name":"Deprecated","inputs":[]},{"type":"error","name":"ForceIncludeBlockTooSoon","inputs":[]},{"type":"error","name":"ForceIncludeTimeTooSoon","inputs":[]},{"type":"error","name":"HadZeroInit","inputs":[]},{"type":"error","name":"IncorrectMessagePreimage","inputs":[]},{"type":"error","name":"InitParamZero","inputs":[{"name":"name","type":"string","internalType":"string"}]},{"type":"error","name":"InvalidHeaderFlag","inputs":[{"name":"","type":"bytes1","internalType":"bytes1"}]},{"type":"error","name":"MissingDataHashes","inputs":[]},{"type":"error","name":"NativeTokenMismatch","inputs":[]},{"type":"error","name":"NoSuchKeyset","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}]},{"type":"error","name":"NotBatchPoster","inputs":[]},{"type":"error","name":"NotBatchPosterManager","inputs":[{"name":"","type":"address","internalType":"address"}]},{"type":"error","name":"NotForked","inputs":[]},{"type":"error","name":"NotOrigin","inputs":[]},{"type":"error","name":"NotOwner","inputs":[{"name":"sender","type":"address","internalType":"address"},{"name":"owner","type":"address","internalType":"address"}]}]`

	sequencerInboxABI, err = abi.JSON(bytes.NewReader([]byte(rawABI)))
	if err != nil {
		panic(err)
	}
}

const (
	sequencerMsgOffset = 41
	MaxBatchSize = 2_000_000 // 2MB
)

func IsEigenDAMessageHeaderByte(header byte) bool {
	return hasBits(header, daprovider.EigenDAMessageHeaderFlag)
}

// hasBits returns true if `checking` has all `bits`
func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
}

type EigenDAWriter interface {
	Store(context.Context, []byte) (*EigenDABlobInfo, error)
	Serialize(eigenDABlobInfo *EigenDABlobInfo) ([]byte, error)
}

type EigenDAReader interface {
	QueryBlob(ctx context.Context, cert *EigenDABlobInfo, domainFilter string) ([]byte, error)
}

type EigenDAConfig struct {
	Enable bool   `koanf:"enable"`
	Rpc    string `koanf:"rpc"`
}

type EigenDA struct {
	client *EigenDAProxyClient
}

func NewEigenDA(config *EigenDAConfig) (*EigenDA, error) {
	if !config.Enable {
		return nil, errors.New("EigenDA is not enabled")
	}
	client := NewEigenDAProxyClient(config.Rpc)

	return &EigenDA{
		client: client,
	}, nil
}

// QueryBlob retrieves a blob from EigenDA using the provided EigenDABlobInfo
func (e *EigenDA) QueryBlob(ctx context.Context, cert *EigenDABlobInfo, domainFilter string) ([]byte, error) {
	log.Info("Reading blob from EigenDA", "batchID", cert.BlobVerificationProof.BatchID)
	info, err := cert.ToDisperserBlobInfo()
	if err != nil {
		return nil, err
	}

	data, err := e.client.Get(ctx, info)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Store disperses a blob to EigenDA and returns the appropriate EigenDABlobInfo or certificate values
func (e *EigenDA) Store(ctx context.Context, data []byte) (*EigenDABlobInfo, error) {
	log.Info("Dispersing batch as blob to EigenDA", "dataLength", len(data))
	var blobInfo = &EigenDABlobInfo{}
	cert, err := e.client.Put(ctx, data)
	if err != nil {
		return nil, err
	}

	blobInfo.LoadBlobInfo(cert)

	return blobInfo, nil
}

func (e *EigenDA) Serialize(blobInfo *EigenDABlobInfo) ([]byte, error) {
	return rlp.EncodeToBytes(blobInfo)
}
