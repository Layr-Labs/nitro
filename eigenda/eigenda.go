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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/offchainlabs/nitro/arbutil"
)

type DisperserBlobInfo struct {
	BlobHeader            DisperserBlobHeader            `json:"blob_header,omitempty"`
	BlobVerificationProof DisperserBlobVerificationProof `json:"blob_verification_proof,omitempty"`
}

type DisperserBlobHeader struct {
	Commitment       G1Commitment      `json:"commitment,omitempty"`
	DataLength       uint32            `json:"data_length,omitempty"`
	BlobQuorumParams []BlobQuorumParam `json:"blob_quorum_params,omitempty"`
}

type G1Commitment struct {
	X []byte `json:"x,omitempty"`
	Y []byte `json:"y,omitempty"`
}

type BlobQuorumParam struct {
	QuorumNumber                    uint32 `json:"quorum_number,omitempty"`
	AdversaryThresholdPercentage    uint32 `json:"adversary_threshold_percentage,omitempty"`
	ConfirmationThresholdPercentage uint32 `json:"confirmation_threshold_percentage,omitempty"`
	ChunkLength                     uint32 `json:"chunk_length,omitempty"`
}

type DisperserBlobVerificationProof struct {
	BatchId        uint32                 `json:"batch_id,omitempty"`
	BlobIndex      uint32                 `json:"blob_index,omitempty"`
	BatchMetadata  DisperserBatchMetadata `json:"batch_metadata,omitempty"`
	InclusionProof []byte                 `json:"inclusion_proof,omitempty"`
	QuorumIndexes  []byte                 `json:"quorum_indexes,omitempty"`
}

type DisperserBatchMetadata struct {
	Fee                     []byte               `json:"fee"`             // bytes
	BatchHeaderHash         []byte               `json:"batchHeaderHash"` // bytes
	BatchHeader             DisperserBatchHeader `json:"batch_header,omitempty"`
	SignatoryRecordHash     []byte               `json:"signatory_record_hash,omitempty"`
	ConfirmationBlockNumber uint32               `json:"confirmation_block_number,omitempty"`
}

type DisperserBatchHeader struct {
	BatchRoot               []byte `json:"batch_root,omitempty"`
	QuorumNumbers           []byte `json:"quorum_numbers,omitempty"`
	QuorumSignedPercentages []byte `json:"quorum_signed_percentages,omitempty"`
	ReferenceBlockNumber    uint32 `json:"reference_block_number,omitempty"`
}

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
	BlobHeader            BlobHeader            `json:"blobHeader"`
	BlobVerificationProof BlobVerificationProof `json:"blobVerificationProof"`
}

type BlobHeader struct {
	Commitment       G1Point            `json:"commitment"`
	DataLength       uint32             `json:"dataLength"`
	QuorumBlobParams []QuorumBlobParams `json:"quorumBlobParams"`
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

// (uint32,uint32,((bytes32,bytes,bytes,uint32),bytes32,uint32),bytes,bytes)
//
//	x     x           x       x    x      x       x        x     x     x
type BlobVerificationProof struct {
	BatchID        uint32        `json:"batchId"`        // uint32
	BlobIndex      uint32        `json:"blobIndex"`      // uint32
	BatchMetadata  BatchMetadata `json:"batchMetadata"`  // nest
	InclusionProof []byte        `json:"inclusionProof"` // bytes
	QuorumIndices  []byte        `json:"quorumIndices"`  // bytes
}

/*
	BatchHeader *BatchHeader `protobuf:"bytes,1,opt,name=batch_header,json=batchHeader,proto3" json:"batch_header,omitempty"`
	// The hash of all public keys of the operators that did not sign the batch.
	SignatoryRecordHash []byte `protobuf:"bytes,2,opt,name=signatory_record_hash,json=signatoryRecordHash,proto3" json:"signatory_record_hash,omitempty"`
	// The fee payment paid by users for dispersing this batch. It's the bytes
	// representation of a big.Int value.
	Fee []byte `protobuf:"bytes,3,opt,name=fee,proto3" json:"fee,omitempty"`
	// The Ethereum block number at which the batch is confirmed onchain.
	ConfirmationBlockNumber uint32 `protobuf:"varint,4,opt,name=confirmation_block_number,json=confirmationBlockNumber,proto3" json:"confirmation_block_number,omitempty"`
	// This is the hash of the ReducedBatchHeader defined onchain, see:
	// https://github.com/Layr-Labs/eigenda/blob/master/contracts/src/interfaces/IEigenDAServiceManager.sol#L43
	// The is the message that the operators will sign their signatures on.
	BatchHeaderHash []byte `protobuf:"bytes,5,opt,name=batch_header_hash,json=batchHeaderHash,proto3" json:"batch_header_hash,omitempty"`


*/

type BatchMetadata struct {
	BatchHeader             BatchHeader `json:"batchHeader"`
	Fee                     []byte      `json:"fee"`                     // bytes
	SignatoryRecordHash     [32]byte    `json:"signatoryRecordHash"`     // bytes32
	ConfirmationBlockNumber uint32      `json:"confirmationBlockNumber"` // uint32
	BatchHeaderHash         []byte      `json:"batchHeaderHash"`         // bytes
}

type BatchHeader struct {
	BlobHeadersRoot       [32]byte `json:"blobHeadersRoot"`
	QuorumNumbers         []byte   `json:"quorumNumbers"`
	SignedStakeForQuorums []byte   `json:"signedStakeForQuorums"`
	ReferenceBlockNumber  uint32   `json:"referenceBlockNumber"`
}

func ConvertEigenDABlobInfoToDisperserBlobInfo(eigenDA *EigenDABlobInfo) DisperserBlobInfo {
	// Convert BlobHeader
	var disperserBlobHeader DisperserBlobHeader
	commitment := G1Commitment{
		X: eigenDA.BlobHeader.Commitment.X.Bytes(),
		Y: eigenDA.BlobHeader.Commitment.Y.Bytes(),
	}
	quorumParams := make([]BlobQuorumParam, len(eigenDA.BlobHeader.QuorumBlobParams))
	for i, qp := range eigenDA.BlobHeader.QuorumBlobParams {
		quorumParams[i] = BlobQuorumParam{
			QuorumNumber:                    uint32(qp.QuorumNumber),
			AdversaryThresholdPercentage:    uint32(qp.AdversaryThresholdPercentage),
			ConfirmationThresholdPercentage: uint32(qp.ConfirmationThresholdPercentage),
			ChunkLength:                     qp.ChunkLength,
		}
	}
	disperserBlobHeader = DisperserBlobHeader{
		Commitment:       commitment,
		DataLength:       eigenDA.BlobHeader.DataLength,
		BlobQuorumParams: quorumParams,
	}

	// Convert BlobVerificationProof
	var disperserBlobVerificationProof DisperserBlobVerificationProof
	if &eigenDA.BlobVerificationProof != nil {
		var disperserBatchMetadata DisperserBatchMetadata
		if &eigenDA.BlobVerificationProof.BatchMetadata != nil {
			metadata := eigenDA.BlobVerificationProof.BatchMetadata
			quorumNumbers := metadata.BatchHeader.QuorumNumbers
			quorumSignedPercentages := metadata.BatchHeader.SignedStakeForQuorums

			disperserBatchMetadata = DisperserBatchMetadata{
				BatchHeader: DisperserBatchHeader{
					BatchRoot:               metadata.BatchHeader.BlobHeadersRoot[:],
					QuorumNumbers:           quorumNumbers,
					QuorumSignedPercentages: quorumSignedPercentages,
					ReferenceBlockNumber:    metadata.BatchHeader.ReferenceBlockNumber,
				},
				BatchHeaderHash:         metadata.BatchHeaderHash,
				Fee:                     metadata.Fee,
				SignatoryRecordHash:     metadata.SignatoryRecordHash[:],
				ConfirmationBlockNumber: metadata.ConfirmationBlockNumber,
			}
		}
		disperserBlobVerificationProof = DisperserBlobVerificationProof{
			BatchId:        eigenDA.BlobVerificationProof.BatchID,
			BlobIndex:      eigenDA.BlobVerificationProof.BlobIndex,
			BatchMetadata:  disperserBatchMetadata,
			InclusionProof: eigenDA.BlobVerificationProof.InclusionProof,
			QuorumIndexes:  eigenDA.BlobVerificationProof.QuorumIndices,
		}
	}

	return DisperserBlobInfo{
		BlobHeader:            disperserBlobHeader,
		BlobVerificationProof: disperserBlobVerificationProof,
	}
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
func (e *EigenDA) QueryBlob(ctx context.Context, cert *EigenDABlobInfo, domainFilter string) ([]byte, error) {
	blobInfo := ConvertEigenDABlobInfoToDisperserBlobInfo(cert)

	data, err := e.client.Get(ctx, &blobInfo, domainFilter)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (e *EigenDA) Store(ctx context.Context, data []byte) (*EigenDABlobInfo, error) {
	log.Info("Storing blob")
	var blobInfo = &EigenDABlobInfo{}
	commitment, err := e.client.Put(ctx, data)
	if err != nil {
		return nil, err
	}

	log.Info("Stored blob", "commitment", hex.EncodeToString(commitment.GetBlobHeader().GetCommitment().GetX()), "y", hex.EncodeToString(commitment.GetBlobHeader().GetCommitment().GetY()))

	blobInfo.loadBlobInfo(commitment)

	return blobInfo, nil
}

func (e *EigenDA) Serialize(blobInfo *EigenDABlobInfo) ([]byte, error) {
	return rlp.EncodeToBytes(blobInfo)
}

func (e *EigenDABlobInfo) SerializeCommitment() ([]byte, error) {
	return append(e.BlobHeader.Commitment.X.Bytes(), e.BlobHeader.Commitment.Y.Bytes()...), nil
}

func (b *EigenDABlobInfo) loadBlobInfo(disperserBlobInfo *disperser.BlobInfo) {
	// dump blob info
	println("BlobInfo: ", disperserBlobInfo.String())

	x := disperserBlobInfo.GetBlobHeader().GetCommitment().GetX()
	y := disperserBlobInfo.GetBlobHeader().GetCommitment().GetY()

	b.BlobHeader = BlobHeader{}

	b.BlobHeader.Commitment = G1Point{
		X: new(big.Int).SetBytes(x),
		Y: new(big.Int).SetBytes(y),
	}

	b.BlobHeader.DataLength = disperserBlobInfo.GetBlobHeader().GetDataLength()

	for _, quorumBlobParam := range disperserBlobInfo.GetBlobHeader().GetBlobQuorumParams() {
		b.BlobHeader.QuorumBlobParams = append(b.BlobHeader.QuorumBlobParams, QuorumBlobParams{
			QuorumNumber:                    uint8(quorumBlobParam.QuorumNumber),
			AdversaryThresholdPercentage:    uint8(quorumBlobParam.AdversaryThresholdPercentage),
			ConfirmationThresholdPercentage: uint8(quorumBlobParam.ConfirmationThresholdPercentage),
			ChunkLength:                     quorumBlobParam.ChunkLength,
		})
	}

	println("Set quorum blob params")
	var signatoryRecordHash [32]byte
	copy(signatoryRecordHash[:], disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetSignatoryRecordHash())

	println("Set signatory record hash")
	b.BlobVerificationProof.BatchID = disperserBlobInfo.GetBlobVerificationProof().GetBatchId()
	b.BlobVerificationProof.BlobIndex = disperserBlobInfo.GetBlobVerificationProof().GetBlobIndex()
	b.BlobVerificationProof.BatchMetadata = BatchMetadata{
		Fee:                     disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetFee(),
		BatchHeaderHash:         disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeaderHash(),
		BatchHeader:             BatchHeader{},
		SignatoryRecordHash:     signatoryRecordHash,
		ConfirmationBlockNumber: disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetConfirmationBlockNumber(),
	}

	// dump fields
	println("BatchID: ", b.BlobVerificationProof.BatchID)
	println("BlobIndex: ", b.BlobVerificationProof.BlobIndex)
	println("ConfirmationBlockNumber: ", b.BlobVerificationProof.BatchMetadata.ConfirmationBlockNumber)

	b.BlobVerificationProof.InclusionProof = disperserBlobInfo.GetBlobVerificationProof().GetInclusionProof()
	b.BlobVerificationProof.QuorumIndices = disperserBlobInfo.GetBlobVerificationProof().GetQuorumIndexes()

	println("Set inclusion proof and quorum indices")

	batchRootSlice := disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetBatchRoot()
	var blobHeadersRoot [32]byte
	copy(blobHeadersRoot[:], batchRootSlice)
	b.BlobVerificationProof.BatchMetadata.BatchHeader.BlobHeadersRoot = blobHeadersRoot

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
	domain string,
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
	data, err := daReader.QueryBlob(ctx, blobInfo, domain)
	if err != nil {
		log.Error("Failed to query data from EigenDA", "err", err)
		return nil, err
	}

	// record preimage data,
	log.Info("Recording preimage data for EigenDA")
	pointer, err := blobInfo.SerializeCommitment()
	if err != nil {
		return nil, err
	}
	shaDataHash := sha256.New()
	shaDataHash.Write(pointer)
	dataHash := shaDataHash.Sum([]byte{})
	dataHash[0] = 1
	if eigenDAPreimages != nil {
		eigenDAPreimages[common.BytesToHash(dataHash)] = data
	}
	return data, nil
}

func ParseSequencerMsg(calldata []byte) *EigenDABlobInfo {
	println("ParseSequencerMsg")
	println(fmt.Sprintf("Calldata %s", hexutil.Encode(calldata)))

	// TODO: Import this via relative path
	sequencerInboxABI := `[{"type":"constructor","inputs":[{"name":"_maxDataSize","type":"uint256","internalType":"uint256"},{"name":"reader4844_","type":"address","internalType":"contract IReader4844"},{"name":"eigenDAServiceManager_","type":"address","internalType":"contract IEigenDAServiceManager"},{"name":"eigenDARollupManager_","type":"address","internalType":"contract IRollupManager"},{"name":"_isUsingFeeToken","type":"bool","internalType":"bool"}],"stateMutability":"nonpayable"},{"type":"function","name":"BROTLI_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"DAS_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"DATA_AUTHENTICATED_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"DATA_BLOB_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"EIGENDA_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"HEADER_LENGTH","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"TREE_DAS_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"ZERO_HEAVY_MESSAGE_HEADER_FLAG","inputs":[],"outputs":[{"name":"","type":"bytes1","internalType":"bytes1"}],"stateMutability":"view"},{"type":"function","name":"addSequencerL2Batch","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"gasRefunder","type":"address","internalType":"contract IGasRefunder"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"addSequencerL2BatchFromBlobs","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"gasRefunder","type":"address","internalType":"contract IGasRefunder"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"addSequencerL2BatchFromEigenDA","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"blobVerificationProof","type":"tuple","internalType":"struct EigenDARollupUtils.BlobVerificationProof","components":[{"name":"batchId","type":"uint32","internalType":"uint32"},{"name":"blobIndex","type":"uint32","internalType":"uint32"},{"name":"batchMetadata","type":"tuple","internalType":"struct IEigenDAServiceManager.BatchMetadata","components":[{"name":"batchHeader","type":"tuple","internalType":"struct IEigenDAServiceManager.BatchHeader","components":[{"name":"blobHeadersRoot","type":"bytes32","internalType":"bytes32"},{"name":"quorumNumbers","type":"bytes","internalType":"bytes"},{"name":"signedStakeForQuorums","type":"bytes","internalType":"bytes"},{"name":"referenceBlockNumber","type":"uint32","internalType":"uint32"}]},{"name":"signatoryRecordHash","type":"bytes32","internalType":"bytes32"},{"name":"confirmationBlockNumber","type":"uint32","internalType":"uint32"}]},{"name":"inclusionProof","type":"bytes","internalType":"bytes"},{"name":"quorumIndices","type":"bytes","internalType":"bytes"}]},{"name":"blobHeader","type":"tuple","internalType":"struct IEigenDAServiceManager.BlobHeader","components":[{"name":"commitment","type":"tuple","internalType":"struct BN254.G1Point","components":[{"name":"X","type":"uint256","internalType":"uint256"},{"name":"Y","type":"uint256","internalType":"uint256"}]},{"name":"dataLength","type":"uint32","internalType":"uint32"},{"name":"quorumBlobParams","type":"tuple[]","internalType":"struct IEigenDAServiceManager.QuorumBlobParam[]","components":[{"name":"quorumNumber","type":"uint8","internalType":"uint8"},{"name":"adversaryThresholdPercentage","type":"uint8","internalType":"uint8"},{"name":"confirmationThresholdPercentage","type":"uint8","internalType":"uint8"},{"name":"chunkLength","type":"uint32","internalType":"uint32"}]}]},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"addSequencerL2BatchFromOrigin","inputs":[{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"bytes","internalType":"bytes"},{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"address","internalType":"contract IGasRefunder"}],"outputs":[],"stateMutability":"pure"},{"type":"function","name":"addSequencerL2BatchFromOrigin","inputs":[{"name":"sequenceNumber","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"},{"name":"afterDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"gasRefunder","type":"address","internalType":"contract IGasRefunder"},{"name":"prevMessageCount","type":"uint256","internalType":"uint256"},{"name":"newMessageCount","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"batchCount","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"batchPosterManager","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"bridge","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IBridge"}],"stateMutability":"view"},{"type":"function","name":"dasKeySetInfo","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"isValidKeyset","type":"bool","internalType":"bool"},{"name":"creationBlock","type":"uint64","internalType":"uint64"}],"stateMutability":"view"},{"type":"function","name":"eigenDARollupManager","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IRollupManager"}],"stateMutability":"view"},{"type":"function","name":"eigenDAServiceManager","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IEigenDAServiceManager"}],"stateMutability":"view"},{"type":"function","name":"forceInclusion","inputs":[{"name":"_totalDelayedMessagesRead","type":"uint256","internalType":"uint256"},{"name":"kind","type":"uint8","internalType":"uint8"},{"name":"l1BlockAndTime","type":"uint64[2]","internalType":"uint64[2]"},{"name":"baseFeeL1","type":"uint256","internalType":"uint256"},{"name":"sender","type":"address","internalType":"address"},{"name":"messageDataHash","type":"bytes32","internalType":"bytes32"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"getKeysetCreationBlock","inputs":[{"name":"ksHash","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"inboxAccs","inputs":[{"name":"index","type":"uint256","internalType":"uint256"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},{"type":"function","name":"initialize","inputs":[{"name":"bridge_","type":"address","internalType":"contract IBridge"},{"name":"maxTimeVariation_","type":"tuple","internalType":"struct ISequencerInbox.MaxTimeVariation","components":[{"name":"delayBlocks","type":"uint256","internalType":"uint256"},{"name":"futureBlocks","type":"uint256","internalType":"uint256"},{"name":"delaySeconds","type":"uint256","internalType":"uint256"},{"name":"futureSeconds","type":"uint256","internalType":"uint256"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"invalidateKeysetHash","inputs":[{"name":"ksHash","type":"bytes32","internalType":"bytes32"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"isBatchPoster","inputs":[{"name":"","type":"address","internalType":"address"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"isSequencer","inputs":[{"name":"","type":"address","internalType":"address"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"isUsingFeeToken","inputs":[],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"isValidKeysetHash","inputs":[{"name":"ksHash","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"maxDataSize","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"maxTimeVariation","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"uint256","internalType":"uint256"},{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"postUpgradeInit","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"reader4844","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IReader4844"}],"stateMutability":"view"},{"type":"function","name":"removeDelayAfterFork","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"rollup","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract IOwnable"}],"stateMutability":"view"},{"type":"function","name":"setBatchPosterManager","inputs":[{"name":"newBatchPosterManager","type":"address","internalType":"address"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setIsBatchPoster","inputs":[{"name":"addr","type":"address","internalType":"address"},{"name":"isBatchPoster_","type":"bool","internalType":"bool"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setIsSequencer","inputs":[{"name":"addr","type":"address","internalType":"address"},{"name":"isSequencer_","type":"bool","internalType":"bool"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setMaxTimeVariation","inputs":[{"name":"maxTimeVariation_","type":"tuple","internalType":"struct ISequencerInbox.MaxTimeVariation","components":[{"name":"delayBlocks","type":"uint256","internalType":"uint256"},{"name":"futureBlocks","type":"uint256","internalType":"uint256"},{"name":"delaySeconds","type":"uint256","internalType":"uint256"},{"name":"futureSeconds","type":"uint256","internalType":"uint256"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setValidKeyset","inputs":[{"name":"keysetBytes","type":"bytes","internalType":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"totalDelayedMessagesRead","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"event","name":"InboxMessageDelivered","inputs":[{"name":"messageNum","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"data","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"event","name":"InboxMessageDeliveredFromOrigin","inputs":[{"name":"messageNum","type":"uint256","indexed":true,"internalType":"uint256"}],"anonymous":false},{"type":"event","name":"InvalidateKeyset","inputs":[{"name":"keysetHash","type":"bytes32","indexed":true,"internalType":"bytes32"}],"anonymous":false},{"type":"event","name":"OwnerFunctionCalled","inputs":[{"name":"id","type":"uint256","indexed":true,"internalType":"uint256"}],"anonymous":false},{"type":"event","name":"SequencerBatchData","inputs":[{"name":"batchSequenceNumber","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"data","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"event","name":"SequencerBatchDelivered","inputs":[{"name":"batchSequenceNumber","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"beforeAcc","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"afterAcc","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"delayedAcc","type":"bytes32","indexed":false,"internalType":"bytes32"},{"name":"afterDelayedMessagesRead","type":"uint256","indexed":false,"internalType":"uint256"},{"name":"timeBounds","type":"tuple","indexed":false,"internalType":"struct IBridge.TimeBounds","components":[{"name":"minTimestamp","type":"uint64","internalType":"uint64"},{"name":"maxTimestamp","type":"uint64","internalType":"uint64"},{"name":"minBlockNumber","type":"uint64","internalType":"uint64"},{"name":"maxBlockNumber","type":"uint64","internalType":"uint64"}]},{"name":"dataLocation","type":"uint8","indexed":false,"internalType":"enum IBridge.BatchDataLocation"}],"anonymous":false},{"type":"event","name":"SetValidKeyset","inputs":[{"name":"keysetHash","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"keysetBytes","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"error","name":"AlreadyInit","inputs":[]},{"type":"error","name":"AlreadyValidDASKeyset","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}]},{"type":"error","name":"BadMaxTimeVariation","inputs":[]},{"type":"error","name":"BadPostUpgradeInit","inputs":[]},{"type":"error","name":"BadSequencerNumber","inputs":[{"name":"stored","type":"uint256","internalType":"uint256"},{"name":"received","type":"uint256","internalType":"uint256"}]},{"type":"error","name":"DataBlobsNotSupported","inputs":[]},{"type":"error","name":"DataTooLarge","inputs":[{"name":"dataLength","type":"uint256","internalType":"uint256"},{"name":"maxDataLength","type":"uint256","internalType":"uint256"}]},{"type":"error","name":"DelayedBackwards","inputs":[]},{"type":"error","name":"DelayedTooFar","inputs":[]},{"type":"error","name":"Deprecated","inputs":[]},{"type":"error","name":"ForceIncludeBlockTooSoon","inputs":[]},{"type":"error","name":"ForceIncludeTimeTooSoon","inputs":[]},{"type":"error","name":"HadZeroInit","inputs":[]},{"type":"error","name":"IncorrectMessagePreimage","inputs":[]},{"type":"error","name":"InitParamZero","inputs":[{"name":"name","type":"string","internalType":"string"}]},{"type":"error","name":"InvalidHeaderFlag","inputs":[{"name":"","type":"bytes1","internalType":"bytes1"}]},{"type":"error","name":"MissingDataHashes","inputs":[]},{"type":"error","name":"NativeTokenMismatch","inputs":[]},{"type":"error","name":"NoSuchKeyset","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}]},{"type":"error","name":"NotBatchPoster","inputs":[]},{"type":"error","name":"NotBatchPosterManager","inputs":[{"name":"","type":"address","internalType":"address"}]},{"type":"error","name":"NotForked","inputs":[]},{"type":"error","name":"NotOrigin","inputs":[]},{"type":"error","name":"NotOwner","inputs":[{"name":"sender","type":"address","internalType":"address"},{"name":"owner","type":"address","internalType":"address"}]}]`

	// TODO - remove use of panics
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

	return &EigenDABlobInfo{
		BlobVerificationProof: *payload.BlobVerificationProof,
		BlobHeader:            *payload.BlobHeader,
	}

}

func convertToPayload(pa []interface{}) (payload, error) {
	println("Converting to payload")

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
				Fee:             []byte{},
				BatchHeaderHash: []byte{},

				SignatoryRecordHash:     blobVerificationProof.BatchMetadata.SignatoryRecordHash,
				ConfirmationBlockNumber: blobVerificationProof.BatchMetadata.ConfirmationBlockNumber,
			},
			InclusionProof: blobVerificationProof.InclusionProof,
			QuorumIndices:  blobVerificationProof.QuorumIndices,
		},
		BlobHeader: &BlobHeader{
			Commitment: G1Point{
				X: blobHeader.Commitment.X,
				Y: blobHeader.Commitment.Y,
			},
			DataLength: blobHeader.DataLength,
			QuorumBlobParams: func() []QuorumBlobParams {
				params := make([]QuorumBlobParams, len(blobHeader.QuorumBlobParams))
				for i, p := range blobHeader.QuorumBlobParams {
					params[i] = QuorumBlobParams{
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
		PrevMessageCount:         pa[4].(*big.Int),
		NewMessageCount:          pa[5].(*big.Int),
	}, nil
}
func convertCalldataToInt(calldata []byte) (int, error) {
	num := new(big.Int).SetBytes(calldata)

	if num.IsInt64() {
		return int(num.Uint64()), nil
	}

	fmt.Println(num)

	return 0, errors.New("calldata is not a valid int")
}
