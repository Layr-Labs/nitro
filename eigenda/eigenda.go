package eigenda

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
	BatchID        uint32
	BlobIndex      uint32
	BatchMetadata  *BatchMetadata
	InclusionProof []byte
	QuorumIndices  []byte
}

type BatchMetadata struct {
	BatchHeader             *BatchHeader
	SignatoryRecordHash     [32]byte
	ConfirmationBlockNumber uint32
}

type BatchHeader struct {
	BlobHeadersRoot       [32]byte
	QuorumNumbers         []byte
	SignedStakeForQuorums []byte
	ReferenceBlockNumber  uint32
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
	b.BlobVerificationProof.BatchMetadata = &BatchMetadata{
		BatchHeader:             &BatchHeader{},
		SignatoryRecordHash:     signatoryRecordHash,
		ConfirmationBlockNumber: disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetConfirmationBlockNumber(),
	}

	b.BlobVerificationProof.InclusionProof = disperserBlobInfo.GetBlobVerificationProof().GetInclusionProof()
	b.BlobVerificationProof.QuorumIndices = disperserBlobInfo.GetBlobVerificationProof().GetQuorumIndexes()

	b.BlobVerificationProof.BatchMetadata.BatchHeader.BlobHeadersRoot = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetBlobHeadersRoot()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.QuorumNumbers = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetQuorumNumbers()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.SignedStakeForQuorums = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetSignedStakeForQuorums()
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
	var eigenDAHashPreimages map[common.Hash][]byte
	if preimages != nil {
		if preimages[arbutil.EigenDAHash] == nil {
			preimages[arbutil.EigenDAHash] = make(map[common.Hash][]byte)
		}
		eigenDAHashPreimages = preimages[arbutil.EigenDAHash]
	}

	blobInfo := ParseSequencerMsg(sequencerMsg)

	batchHeaderHash := crypto.Keccak256Hash(blobInfo.BlobHeader).Bytes()

	log.Info("Data pointer: ", "info", hex.EncodeToString(batchHeaderHash), "index", blobInfo.BlobVerificationProof.BlobIndex)

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
	if eigenDAHashPreimages != nil {
		eigenDAHashPreimages[common.BytesToHash(dataHash)] = data
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
	var blobInfo *EigenDABlobInfo

	var blobVerificationProof *BlobVerificationProof
	var blobHeader *BlobHeader

	// try decoding at the offsets
	blobVerificationProofOffset, err := convertCalldataToInt(calldata[36:68])
	if err != nil {
		// todo handle later
		panic(err)
	}

	blobVerificationProofOffset += 4

	blobHeaderOffset, err := convertCalldataToInt(calldata[68:100])
	if err != nil {
		// todo handle later
		panic(err)
	}

	rlp.DecodeBytes(calldata[blobVerificationProofOffset:blobHeaderOffset], blobVerificationProof) // see if this works???
	rlp.DecodeBytes(calldata[blobHeaderOffset:], blobHeader)

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
		BlobVerificationProof: *blobVerificationProof,
		BlobHeader:            *blobHeader,
	}

}

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
