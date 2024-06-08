package eigenda

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/offchainlabs/nitro/arbutil"
)

// EigenDAMessageHeaderFlag indicated that the message is a EigenDABlobID which will be used to retrieve data from EigenDA
const EigenDAMessageHeaderFlag byte = 0xed

func IsEigenDAMessageHeaderByte(header byte) bool {
	return hasBits(EigenDAMessageHeaderFlag, header)
}

// hasBits returns true if `checking` has all `bits`
func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
}

type payload struct {
	SequenceNumber           *big.Int
	BlobVerificationProof    *BlobVerificationProof
	BlobHeader               *BlobHeader
	AfterDelayedMessagesRead *big.Int
	GasRefunder              common.Address
	PrevMessageCount         *big.Int
	NewMessageCount          *big.Int
}

type EigenDAWriter interface {
	Store(context.Context, []byte) (*EigenDABlobID, *EigenDABlobInfo, error)
	Serialize(eigenDABlobID *EigenDABlobID) ([]byte, error)
}

type EigenDAReader interface {
	QueryBlob(ctx context.Context, id *EigenDABlobInfo, domainFilter string) ([]byte, error)
}

type EigenDAConfig struct {
	Enable bool   `koanf:"enable"`
	Rpc    string `koanf:"rpc"`
}

func (ec *EigenDAConfig) String() {
	fmt.Println(ec.Enable)
	fmt.Println(ec.Rpc)
}

type EigenDABlobID struct {
	BatchHeaderHash      []byte
	BlobIndex            uint32
	ReferenceBlockNumber uint32
	QuorumIDs            []uint32
}

type EigenDABlobInfo struct {
	BlobHeader            BlobHeader
	BlobVerificationProof BlobVerificationProof
}

type BlobHeader struct {
	Commitment       *G1Point
	DataLength       uint32
	QuorumBlobParams []*QuorumBlobParams
}

type G1Point struct {
	X *big.Int
	Y *big.Int
}

type QuorumBlobParams struct {
	QuorumNumber                    uint8
	AdversaryThresholdPercentage    uint8
	ConfirmationThresholdPercentage uint8
	ChunkLength                     uint32
}

type BlobVerificationProof struct {
	BatchID        uint32        `json:"batchId"`
	BlobIndex      uint32        `json:"blobIndex"`
	BatchMetadata  BatchMetadata `json:"batchMetadata"`
	InclusionProof []byte        `json:"inclusionProof"`
	QuorumIndices  []byte        `json:"quorumIndices"`
}

type BatchMetadata struct {
	BatchHeader             BatchHeader `json:"batchHeader"`
	SignatoryRecordHash     [32]byte    `json:"signatoryRecordHash"`
	ConfirmationBlockNumber uint32      `json:"confirmationBlockNumber"`
}

type BatchHeader struct {
	BlobHeadersRoot       [32]byte `json:"blobHeadersRoot"`
	QuorumNumbers         []byte   `json:"quorumNumbers"`
	SignedStakeForQuorums []byte   `json:"signedStakeForQuorums"`
	ReferenceBlockNumber  uint32   `json:"referenceBlockNumber"`
}

type EigenDA struct {
	client *EigenDAProxyClient
}

func NewEigenDA(proxyServerRpc string) (*EigenDA, error) {
	client := NewEigenDAProxyClient(proxyServerRpc)

	return &EigenDA{
		client: client,
	}, nil
}

// TODO: There should probably be two types of query blob as the
func (e *EigenDA) QueryBlob(ctx context.Context, id *disperser.BlobInfo, domainFilter string) ([]byte, error) {
	data, err := e.client.Get(id, domainFilter)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (e *EigenDA) Store(ctx context.Context, data []byte) (*EigenDABlobInfo, error) {
	var blobInfo *EigenDABlobInfo
	commitment, err := e.client.Put(data)
	if err != nil {
		return nil, err
	}

	blobInfo.loadBlobInfo(commitment)

	return blobInfo, nil
}

func (e *EigenDA) Serialize(blobInfo *EigenDABlobInfo) ([]byte, error) {
	return rlp.EncodeToBytes(blobInfo)
}

func (b *EigenDABlobInfo) loadBlobInfo(disperserBlobInfo *disperser.BlobInfo) {
	b.BlobHeader.Commitment = &G1Point{
		X: new(big.Int).SetBytes(disperserBlobInfo.GetBlobHeader().GetCommitment().GetX()),
		Y: new(big.Int).SetBytes(disperserBlobInfo.GetBlobHeader().GetCommitment().GetY()),
	}

	b.BlobHeader.DataLength = disperserBlobInfo.GetBlobHeader().GetDataLength()

	for _, quorumBlobParam := range disperserBlobInfo.GetBlobHeader().GetBlobQuorumParams() {
		b.BlobHeader.QuorumBlobParams = append(b.BlobHeader.QuorumBlobParams, &QuorumBlobParams{
			QuorumNumber:                    uint8(quorumBlobParam.QuorumNumber),
			AdversaryThresholdPercentage:    uint8(quorumBlobParam.AdversaryThresholdPercentage),
			ConfirmationThresholdPercentage: uint8(quorumBlobParam.ConfirmationThresholdPercentage),
			ChunkLength:                     quorumBlobParam.ChunkLength,
		})
	}

	var signatoryRecordHash [32]byte
	copy(signatoryRecordHash[:], disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetSignatoryRecordHash())

	b.BlobVerificationProof.BatchID = disperserBlobInfo.GetBlobVerificationProof().GetBatchId()
	b.BlobVerificationProof.BlobIndex = disperserBlobInfo.GetBlobVerificationProof().GetBlobIndex()
	b.BlobVerificationProof.BatchMetadata = BatchMetadata{
		BatchHeader:             BatchHeader{},
		SignatoryRecordHash:     signatoryRecordHash,
		ConfirmationBlockNumber: disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetConfirmationBlockNumber(),
	}

	b.BlobVerificationProof.InclusionProof = disperserBlobInfo.GetBlobVerificationProof().GetInclusionProof()
	b.BlobVerificationProof.QuorumIndices = disperserBlobInfo.GetBlobVerificationProof().GetQuorumIndexes()

	//b.BlobVerificationProof.BatchMetadata.BatchHeader.BlobHeadersRoot = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetBatchRoot()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.QuorumNumbers = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetQuorumNumbers()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.SignedStakeForQuorums = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetQuorumSignedPercentages()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.ReferenceBlockNumber = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetReferenceBlockNumber()
}

// new hash format is different now:
// ed + abi.encode

// calldata layout of addSequencerL2BatchFromEigenDA looks like the following:
// 0-4 function signature
// 4-36 sequencer
func RecoverPayloadFromEigenDABatch(ctx context.Context,
	sequencerMsg []byte, // this is literally the calldata of the transaction/
	daReader EigenDAReader,
	preimages map[arbutil.PreimageType]map[common.Hash][]byte,
) ([]byte, error) {
	log.Info("Start recovering payload from eigenda: ", "data", hex.EncodeToString(sequencerMsg))
	var eigenDAPreimages map[common.Hash][]byte
	if preimages != nil {
		if preimages[arbutil.EigenDaPreimageType] == nil {
			preimages[arbutil.EigenDaPreimageType] = make(map[common.Hash][]byte)
		}
		eigenDAPreimages = preimages[arbutil.EigenDaPreimageType]
	}

	blobInfo := ParseSequencerMsg(sequencerMsg)

	// default is binary and we want polynomial so we don't need to open 2 points cc @ethen
	data, err := daReader.QueryBlob(ctx, blobInfo, "polynomial")
	if err != nil {
		log.Error("Failed to query data from EigenDA", "err", err)
		return nil, err
	}

	// record preimage data,
	log.Info("Recording preimage data for EigenDA")
	shaDataHash := sha256.New()
	shaDataHash.Write(blobInfo.BlobHeader.Commitment.X.Bytes())
	shaDataHash.Write(blobInfo.BlobHeader.Commitment.Y.Bytes())
	dataHash := shaDataHash.Sum([]byte{})
	dataHash[0] = 1
	if eigenDAPreimages != nil {
		eigenDAPreimages[common.BytesToHash(dataHash)] = data
	}
	return data, nil
}

// calldata layout of sequencer msg
// [inclusive - exclusive]
// [0 - 4]    Function Selector (4 bytes)
// [4 - 36]   sequenceNumber (uint256)
// [36 - 68]  Offset to BlobVerificationProof (dynamic, calculated based on starting point of the dynamic section)
// [68 - 100] Offset to BlobHeader (dynamic, calculated)
// [100 - 132] afterDelayedMessagesRead (uint256)
// [132 - 164] gasRefunder (address)
// [164 - 196] prevMessageCount (uint256)
// [196 - 228] newMessageCount (uint256)

// BlobVerificationProof START
// [BVP offset - BVP offset + 32]  BlobVerificationProof.batchId (uint32, padded)
// [BVP offset + 32 - BVP offset + 64]  BlobVerificationProof.blobIndex (uint32, padded)
// [BVP offset + 64 - BVP offset + 96]  Offset to BlobVerificationProof.BatchMetadata (from BlobVerificationProof start)
// [BVP offset + 96 - BVP offset + 128]  Offset to BlobVerificationProof.inclusionProof (from BlobVerificationProof start)
// [BVP offset + 128 - BVP offset + 160]  Offset to BlobVerificationProof.quorumIndices (from BlobVerificationProof start)

// BatchMetadata START
// [BatchMeta offset - BatchMeta offset + 32]  Offset to BatchMetadata.batchHeader (from BatchMeta start)
// [BatchMeta offset + 32 - BatchMeta offset + 64]  BatchMetadata.signatoryRecordHash (bytes32)
// [BatchMeta offset + 64 - BatchMeta offset + 96]  BatchMetadata.confirmationBlockNumber (uint32, padded)

// BatchHeader START
// [BatchHeader offset - BatchHeader offset + 32]  BatchHeader.blobHeadersRoot (bytes32)
// [BatchHeader offset + 32 - BatchHeader offset + 64]  offset of BatchHeader.quorumNumbers
// [BatchHeader offset + 64 - BatchHeader offset + 96]  offset of BatchHeader.signedStakeForQuorums
// [BatchHeader offset + 96 - BatchHeader offset + 128]  BatchHeader.referenceBlockNumber (uint32, padded)

// BlobHeader Start
// [BlobHeader offset - BlobHeader offset + 32]  BlobHeader.commitment.X (uint256)
// [BlobHeader offset + 32 - BlobHeader offset + 64]  BlobHeader.commitment.Y (uint256)
// [BlobHeader offset + 64 - BlobHeader offset + 96]  BlobHeader.dataLength (uint32, padded)
// [BlobHeader offset + 96 - BlobHeader offset + 128]  Offset to BlobHeader.quorumBlobParams (from BlobHeader start)

// QuorumBlobParams Start
// Assuming `n` elements in quorumBlobParams
// [QBP Start - QBP Start + 32]  Number of elements in quorumBlobParams
// we only need the first 32 bytes every 32*n bytes in this one

// InclusionProof

func ParseSequencerMsg(calldata []byte) *EigenDABlobInfo {

	// blobVerificationProof := &BlobVerificationProof{}
	// blobHeader := &BlobHeader{}

	// try decoding at the offsets
	// blobVerificationProofOffset, err := convertCalldataToInt(calldata[36:68])
	// if err != nil {
	// 	// todo handle later
	// 	panic(err)
	// }

	// blobVerificationProofOffset += 4

	// blobHeaderOffset, err := convertCalldataToInt(calldata[68:100])
	// if err != nil {
	// 	// todo handle later
	// 	panic(err)
	// }

	sequencerInboxABI := `[ { "inputs": [ { "internalType": "uint256", "name": "_maxDataSize", "type": "uint256" }, { "internalType": "contract IReader4844", "name": "reader4844_", "type": "address" }, { "internalType": "contract IEigenDAServiceManager", "name": "eigenDAServiceManager_", "type": "address" }, { "internalType": "contract IRollupManager", "name": "eigenDARollupManager_", "type": "address" }, { "internalType": "bool", "name": "_isUsingFeeToken", "type": "bool" } ], "stateMutability": "nonpayable", "type": "constructor" }, { "inputs": [], "name": "AlreadyInit", "type": "error" }, { "inputs": [ { "internalType": "bytes32", "name": "", "type": "bytes32" } ], "name": "AlreadyValidDASKeyset", "type": "error" }, { "inputs": [], "name": "BadMaxTimeVariation", "type": "error" }, { "inputs": [], "name": "BadPostUpgradeInit", "type": "error" }, { "inputs": [ { "internalType": "uint256", "name": "stored", "type": "uint256" }, { "internalType": "uint256", "name": "received", "type": "uint256" } ], "name": "BadSequencerNumber", "type": "error" }, { "inputs": [], "name": "DataBlobsNotSupported", "type": "error" }, { "inputs": [ { "internalType": "uint256", "name": "dataLength", "type": "uint256" }, { "internalType": "uint256", "name": "maxDataLength", "type": "uint256" } ], "name": "DataTooLarge", "type": "error" }, { "inputs": [], "name": "DelayedBackwards", "type": "error" }, { "inputs": [], "name": "DelayedTooFar", "type": "error" }, { "inputs": [], "name": "Deprecated", "type": "error" }, { "inputs": [], "name": "ForceIncludeBlockTooSoon", "type": "error" }, { "inputs": [], "name": "ForceIncludeTimeTooSoon", "type": "error" }, { "inputs": [], "name": "HadZeroInit", "type": "error" }, { "inputs": [], "name": "IncorrectMessagePreimage", "type": "error" }, { "inputs": [ { "internalType": "string", "name": "name", "type": "string" } ], "name": "InitParamZero", "type": "error" }, { "inputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "name": "InvalidHeaderFlag", "type": "error" }, { "inputs": [], "name": "MissingDataHashes", "type": "error" }, { "inputs": [], "name": "NativeTokenMismatch", "type": "error" }, { "inputs": [ { "internalType": "bytes32", "name": "", "type": "bytes32" } ], "name": "NoSuchKeyset", "type": "error" }, { "inputs": [], "name": "NotBatchPoster", "type": "error" }, { "inputs": [ { "internalType": "address", "name": "", "type": "address" } ], "name": "NotBatchPosterManager", "type": "error" }, { "inputs": [], "name": "NotForked", "type": "error" }, { "inputs": [], "name": "NotOrigin", "type": "error" }, { "inputs": [ { "internalType": "address", "name": "sender", "type": "address" }, { "internalType": "address", "name": "owner", "type": "address" } ], "name": "NotOwner", "type": "error" }, { "inputs": [], "name": "RollupNotChanged", "type": "error" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "uint256", "name": "messageNum", "type": "uint256" }, { "indexed": false, "internalType": "bytes", "name": "data", "type": "bytes" } ], "name": "InboxMessageDelivered", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "uint256", "name": "messageNum", "type": "uint256" } ], "name": "InboxMessageDeliveredFromOrigin", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "bytes32", "name": "keysetHash", "type": "bytes32" } ], "name": "InvalidateKeyset", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "uint256", "name": "id", "type": "uint256" } ], "name": "OwnerFunctionCalled", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "uint256", "name": "batchSequenceNumber", "type": "uint256" }, { "indexed": false, "internalType": "bytes", "name": "data", "type": "bytes" } ], "name": "SequencerBatchData", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "uint256", "name": "batchSequenceNumber", "type": "uint256" }, { "indexed": true, "internalType": "bytes32", "name": "beforeAcc", "type": "bytes32" }, { "indexed": true, "internalType": "bytes32", "name": "afterAcc", "type": "bytes32" }, { "indexed": false, "internalType": "bytes32", "name": "delayedAcc", "type": "bytes32" }, { "indexed": false, "internalType": "uint256", "name": "afterDelayedMessagesRead", "type": "uint256" }, { "components": [ { "internalType": "uint64", "name": "minTimestamp", "type": "uint64" }, { "internalType": "uint64", "name": "maxTimestamp", "type": "uint64" }, { "internalType": "uint64", "name": "minBlockNumber", "type": "uint64" }, { "internalType": "uint64", "name": "maxBlockNumber", "type": "uint64" } ], "indexed": false, "internalType": "struct IBridge.TimeBounds", "name": "timeBounds", "type": "tuple" }, { "indexed": false, "internalType": "enum IBridge.BatchDataLocation", "name": "dataLocation", "type": "uint8" } ], "name": "SequencerBatchDelivered", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "bytes32", "name": "keysetHash", "type": "bytes32" }, { "indexed": false, "internalType": "bytes", "name": "keysetBytes", "type": "bytes" } ], "name": "SetValidKeyset", "type": "event" }, { "inputs": [], "name": "BROTLI_MESSAGE_HEADER_FLAG", "outputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "DAS_MESSAGE_HEADER_FLAG", "outputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "DATA_AUTHENTICATED_FLAG", "outputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "DATA_BLOB_HEADER_FLAG", "outputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "EIGENDA_MESSAGE_HEADER_FLAG", "outputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "HEADER_LENGTH", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "TREE_DAS_MESSAGE_HEADER_FLAG", "outputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "ZERO_HEAVY_MESSAGE_HEADER_FLAG", "outputs": [ { "internalType": "bytes1", "name": "", "type": "bytes1" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "sequenceNumber", "type": "uint256" }, { "internalType": "bytes", "name": "data", "type": "bytes" }, { "internalType": "uint256", "name": "afterDelayedMessagesRead", "type": "uint256" }, { "internalType": "contract IGasRefunder", "name": "gasRefunder", "type": "address" }, { "internalType": "uint256", "name": "prevMessageCount", "type": "uint256" }, { "internalType": "uint256", "name": "newMessageCount", "type": "uint256" } ], "name": "addSequencerL2Batch", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "sequenceNumber", "type": "uint256" }, { "internalType": "uint256", "name": "afterDelayedMessagesRead", "type": "uint256" }, { "internalType": "contract IGasRefunder", "name": "gasRefunder", "type": "address" }, { "internalType": "uint256", "name": "prevMessageCount", "type": "uint256" }, { "internalType": "uint256", "name": "newMessageCount", "type": "uint256" } ], "name": "addSequencerL2BatchFromBlobs", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "sequenceNumber", "type": "uint256" }, { "components": [ { "internalType": "uint32", "name": "batchId", "type": "uint32" }, { "internalType": "uint32", "name": "blobIndex", "type": "uint32" }, { "components": [ { "components": [ { "internalType": "bytes32", "name": "blobHeadersRoot", "type": "bytes32" }, { "internalType": "bytes", "name": "quorumNumbers", "type": "bytes" }, { "internalType": "bytes", "name": "signedStakeForQuorums", "type": "bytes" }, { "internalType": "uint32", "name": "referenceBlockNumber", "type": "uint32" } ], "internalType": "struct IEigenDAServiceManager.BatchHeader", "name": "batchHeader", "type": "tuple" }, { "internalType": "bytes32", "name": "signatoryRecordHash", "type": "bytes32" }, { "internalType": "uint32", "name": "confirmationBlockNumber", "type": "uint32" } ], "internalType": "struct IEigenDAServiceManager.BatchMetadata", "name": "batchMetadata", "type": "tuple" }, { "internalType": "bytes", "name": "inclusionProof", "type": "bytes" }, { "internalType": "bytes", "name": "quorumIndices", "type": "bytes" } ], "internalType": "struct EigenDARollupUtils.BlobVerificationProof", "name": "blobVerificationProof", "type": "tuple" }, { "components": [ { "components": [ { "internalType": "uint256", "name": "X", "type": "uint256" }, { "internalType": "uint256", "name": "Y", "type": "uint256" } ], "internalType": "struct BN254.G1Point", "name": "commitment", "type": "tuple" }, { "internalType": "uint32", "name": "dataLength", "type": "uint32" }, { "components": [ { "internalType": "uint8", "name": "quorumNumber", "type": "uint8" }, { "internalType": "uint8", "name": "adversaryThresholdPercentage", "type": "uint8" }, { "internalType": "uint8", "name": "confirmationThresholdPercentage", "type": "uint8" }, { "internalType": "uint32", "name": "chunkLength", "type": "uint32" } ], "internalType": "struct IEigenDAServiceManager.QuorumBlobParam[]", "name": "quorumBlobParams", "type": "tuple[]" } ], "internalType": "struct IEigenDAServiceManager.BlobHeader", "name": "blobHeader", "type": "tuple" }, { "internalType": "uint256", "name": "afterDelayedMessagesRead", "type": "uint256" }, { "internalType": "contract IGasRefunder", "name": "gasRefunder", "type": "address" }, { "internalType": "uint256", "name": "prevMessageCount", "type": "uint256" }, { "internalType": "uint256", "name": "newMessageCount", "type": "uint256" } ], "name": "addSequencerL2BatchFromEigenDA", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "bytes", "name": "", "type": "bytes" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "contract IGasRefunder", "name": "", "type": "address" } ], "name": "addSequencerL2BatchFromOrigin", "outputs": [], "stateMutability": "pure", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "sequenceNumber", "type": "uint256" }, { "internalType": "bytes", "name": "data", "type": "bytes" }, { "internalType": "uint256", "name": "afterDelayedMessagesRead", "type": "uint256" }, { "internalType": "contract IGasRefunder", "name": "gasRefunder", "type": "address" }, { "internalType": "uint256", "name": "prevMessageCount", "type": "uint256" }, { "internalType": "uint256", "name": "newMessageCount", "type": "uint256" } ], "name": "addSequencerL2BatchFromOrigin", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "batchCount", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "batchPosterManager", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "bridge", "outputs": [ { "internalType": "contract IBridge", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "bytes32", "name": "", "type": "bytes32" } ], "name": "dasKeySetInfo", "outputs": [ { "internalType": "bool", "name": "isValidKeyset", "type": "bool" }, { "internalType": "uint64", "name": "creationBlock", "type": "uint64" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "eigenDARollupManager", "outputs": [ { "internalType": "contract IRollupManager", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "eigenDAServiceManager", "outputs": [ { "internalType": "contract IEigenDAServiceManager", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "_totalDelayedMessagesRead", "type": "uint256" }, { "internalType": "uint8", "name": "kind", "type": "uint8" }, { "internalType": "uint64[2]", "name": "l1BlockAndTime", "type": "uint64[2]" }, { "internalType": "uint256", "name": "baseFeeL1", "type": "uint256" }, { "internalType": "address", "name": "sender", "type": "address" }, { "internalType": "bytes32", "name": "messageDataHash", "type": "bytes32" } ], "name": "forceInclusion", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "bytes32", "name": "ksHash", "type": "bytes32" } ], "name": "getKeysetCreationBlock", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "index", "type": "uint256" } ], "name": "inboxAccs", "outputs": [ { "internalType": "bytes32", "name": "", "type": "bytes32" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "contract IBridge", "name": "bridge_", "type": "address" }, { "components": [ { "internalType": "uint256", "name": "delayBlocks", "type": "uint256" }, { "internalType": "uint256", "name": "futureBlocks", "type": "uint256" }, { "internalType": "uint256", "name": "delaySeconds", "type": "uint256" }, { "internalType": "uint256", "name": "futureSeconds", "type": "uint256" } ], "internalType": "struct ISequencerInbox.MaxTimeVariation", "name": "maxTimeVariation_", "type": "tuple" } ], "name": "initialize", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "bytes32", "name": "ksHash", "type": "bytes32" } ], "name": "invalidateKeysetHash", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "", "type": "address" } ], "name": "isBatchPoster", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "", "type": "address" } ], "name": "isSequencer", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "isUsingFeeToken", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "bytes32", "name": "ksHash", "type": "bytes32" } ], "name": "isValidKeysetHash", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "maxDataSize", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "maxTimeVariation", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "postUpgradeInit", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "reader4844", "outputs": [ { "internalType": "contract IReader4844", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "removeDelayAfterFork", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "rollup", "outputs": [ { "internalType": "contract IOwnable", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "newBatchPosterManager", "type": "address" } ], "name": "setBatchPosterManager", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "addr", "type": "address" }, { "internalType": "bool", "name": "isBatchPoster_", "type": "bool" } ], "name": "setIsBatchPoster", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "addr", "type": "address" }, { "internalType": "bool", "name": "isSequencer_", "type": "bool" } ], "name": "setIsSequencer", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "components": [ { "internalType": "uint256", "name": "delayBlocks", "type": "uint256" }, { "internalType": "uint256", "name": "futureBlocks", "type": "uint256" }, { "internalType": "uint256", "name": "delaySeconds", "type": "uint256" }, { "internalType": "uint256", "name": "futureSeconds", "type": "uint256" } ], "internalType": "struct ISequencerInbox.MaxTimeVariation", "name": "maxTimeVariation_", "type": "tuple" } ], "name": "setMaxTimeVariation", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "bytes", "name": "keysetBytes", "type": "bytes" } ], "name": "setValidKeyset", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "totalDelayedMessagesRead", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "newEigenDAServiceManager", "type": "address" } ], "name": "updateEigenDAServiceManager", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "updateRollupAddress", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`

	abi, err := abi.JSON(strings.NewReader(sequencerInboxABI))
	if err != nil {
		panic(err)
	}

	method, err := abi.MethodById(calldata[0:4])
	if err != nil {
		panic(err)
	}

	p, err := method.Inputs.Unpack(calldata[4:])
	if err != nil {
		panic(err)
	}

	payload, err := convertToPayload(p)
	if err != nil {
		panic(err)
	}

	// blobVerificationProofOffset, err := convertCalldataToInt(calldata[36:68])
	// if err != nil {
	// 	panic(err)
	// }

	// blobVerificationProofOffset += 4

	// blobHeaderOffset, err := convertCalldataToInt(calldata[68:100])
	// if err != nil {
	// 	panic(err)
	// }

	// blobHeaderOffset += 4
	// blobIndex, err := convertCalldataToInt(calldata[blobVerificationProofOffset+32 : blobVerificationProofOffset+64])

	// batchMetadataOffset, err := convertCalldataToInt(calldata[blobVerificationProofOffset+64 : blobVerificationProofOffset+96])
	// if err != nil {
	// 	panic(err)
	// }

	// batchMetadataOffset += blobVerificationProofOffset

	// batchHeaderOffset, err := convertCalldataToInt(calldata[batchMetadataOffset : batchMetadataOffset+32])
	// if err != nil {
	// 	panic(err)
	// }

	// batchHeaderOffset += batchMetadataOffset
	// blobHeadersRoot := calldata[batchHeaderOffset : batchHeaderOffset+32]
	// referenceBlockNumber, err := convertCalldataToInt(calldata[batchHeaderOffset+96 : batchHeaderOffset+128])

	// quorumBlobParamsOffset, err := convertCalldataToInt(calldata[blobHeaderOffset+96 : blobHeaderOffset+128])
	// if err != nil {
	// 	panic(err)
	// }
	// quorumBlobParamsOffset += blobHeaderOffset

	// numberOfQuorumBlobParams, err := convertCalldataToInt(calldata[quorumBlobParamsOffset : quorumBlobParamsOffset+32])
	// if err != nil {
	// 	panic(err)
	// }

	// quorumIDs := make([]uint32, numberOfQuorumBlobParams)

	// for i := 0; i < numberOfQuorumBlobParams; i++ {
	// 	offset := quorumBlobParamsOffset + 32 + 32*4*i
	// 	quorumID, err := convertCalldataToInt(calldata[offset : offset+32])
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	quorumIDs[i] = uint32(quorumID)
	// }

	// batchHeader := append(blobHeadersRoot, calldata[batchHeaderOffset+96:batchHeaderOffset+128]...)
	// batchHeaderHash := crypto.Keccak256Hash(batchHeader).Bytes()

	// return &EigenDABlobInfo{
	// 	BlobHeader: &BlobHeader{
	// 		Commitment:       &G1Point{},
	// 		DataLength:       uint32(dataLength),
	// 		QuorumBlobParams: quorumBlobParams,
	// 	},
	// }

	return &EigenDABlobInfo{
		BlobVerificationProof: *payload.BlobVerificationProof,
		BlobHeader:            *payload.BlobHeader,
	}

}

func convertToPayload(pa []interface{}) (payload, error) {
	blobVerificationProof := pa[1].(struct {
		BatchId       uint32 `json:"batchId"`
		BlobIndex     uint32 `json:"blobIndex"`
		BatchMetadata struct {
			BatchHeader struct {
				BlobHeadersRoot       [32]uint8 `json:"blobHeadersRoot"`
				QuorumNumbers         []uint8   `json:"quorumNumbers"`
				SignedStakeForQuorums []uint8   `json:"signedStakeForQuorums"`
				ReferenceBlockNumber  uint32    `json:"referenceBlockNumber"`
			} `json:"batchHeader"`
			SignatoryRecordHash     [32]uint8 `json:"signatoryRecordHash"`
			ConfirmationBlockNumber uint32    `json:"confirmationBlockNumber"`
		} `json:"batchMetadata"`
		InclusionProof []uint8 `json:"inclusionProof"`
		QuorumIndices  []uint8 `json:"quorumIndices"`
	})

	blobHeader := pa[2].(struct {
		Commitment struct {
			X *big.Int `json:"X"`
			Y *big.Int `json:"Y"`
		} `json:"commitment"`
		DataLength       uint32 `json:"dataLength"`
		QuorumBlobParams []struct {
			QuorumNumber                    uint8  `json:"quorumNumber"`
			AdversaryThresholdPercentage    uint8  `json:"adversaryThresholdPercentage"`
			ConfirmationThresholdPercentage uint8  `json:"confirmationThresholdPercentage"`
			ChunkLength                     uint32 `json:"chunkLength"`
		} `json:"quorumBlobParams"`
	})

	return payload{
		SequenceNumber: pa[0].(*big.Int),
		BlobVerificationProof: &BlobVerificationProof{
			BatchID:   blobVerificationProof.BatchId,
			BlobIndex: blobVerificationProof.BlobIndex,
			BatchMetadata: BatchMetadata{
				BatchHeader: BatchHeader{
					BlobHeadersRoot:       blobVerificationProof.BatchMetadata.BatchHeader.BlobHeadersRoot,
					QuorumNumbers:         blobVerificationProof.BatchMetadata.BatchHeader.QuorumNumbers,
					SignedStakeForQuorums: blobVerificationProof.BatchMetadata.BatchHeader.SignedStakeForQuorums,
					ReferenceBlockNumber:  blobVerificationProof.BatchMetadata.BatchHeader.ReferenceBlockNumber,
				},
				SignatoryRecordHash:     blobVerificationProof.BatchMetadata.SignatoryRecordHash,
				ConfirmationBlockNumber: blobVerificationProof.BatchMetadata.ConfirmationBlockNumber,
			},
			InclusionProof: blobVerificationProof.InclusionProof,
			QuorumIndices:  blobVerificationProof.QuorumIndices,
		},
		BlobHeader: &BlobHeader{
			Commitment: &G1Point{},
			DataLength: blobHeader.DataLength,
			QuorumBlobParams: func() []*QuorumBlobParams {
				params := make([]*QuorumBlobParams, len(blobHeader.QuorumBlobParams))
				for i, p := range blobHeader.QuorumBlobParams {
					params[i] = &QuorumBlobParams{
						QuorumNumber:                    p.QuorumNumber,
						AdversaryThresholdPercentage:    p.AdversaryThresholdPercentage,
						ConfirmationThresholdPercentage: p.ConfirmationThresholdPercentage,
						ChunkLength:                     p.ChunkLength,
					}
				}
				return params
			}(),
		},
		AfterDelayedMessagesRead: pa[3].(*big.Int),
		GasRefunder:              pa[4].(common.Address),
		PrevMessageCount:         pa[5].(*big.Int),
		NewMessageCount:          pa[6].(*big.Int),
	}, nil
}

// type QuorumBlobParams struct {
// 	QuorumNumber                    uint8
// 	AdversaryThresholdPercentage    uint8
// 	ConfirmationThresholdPercentage uint8
// 	ChunkLength                     uint32
// }

func convertCalldataToInt(calldata []byte) (int, error) {
	num := new(big.Int).SetBytes(calldata)

	if num.IsInt64() {
		return int(num.Uint64()), nil
	}

	fmt.Println(num)

	return 0, errors.New("calldata is not a valid int")
}

// func bytesToUint32Array(b []byte) ([]uint32, error) {
// 	if len(b)%4 != 0 {
// 		return nil, fmt.Errorf("the length of the byte slice must be a multiple of 4")
// 	}

// 	numElements := len(b) / 4
// 	result := make([]uint32, numElements)
// 	for i := 0; i < numElements; i++ {
// 		result[i] = binary.BigEndian.Uint32(b[i*4 : (i+1)*4])
// 	}

// 	return result, nil
// }
