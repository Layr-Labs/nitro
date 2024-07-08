package eigenda

import (
	"errors"
	"math/big"

	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"golang.org/x/crypto/sha3"
)

/*
	Two rather redundant implementations of the same data structure exist:
	- EigenDABlobInfo: represents the EigenDABlobInfo struct which is encoded in the calldata of the sequencer message for on-chain cert verification
	- DisperserBlobInfo: represents the disperser.BlobInfo struct generated by the grpc disperser protobuf
*/

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

type BlobVerificationProof struct {
	BatchID        uint32        `json:"batchId"`
	BlobIndex      uint32        `json:"blobIndex"`
	BatchMetadata  BatchMetadata `json:"batchMetadata"`
	InclusionProof []byte        `json:"inclusionProof"`
	QuorumIndices  []byte        `json:"quorumIndices"`
}

type BatchMetadata struct {
	BatchHeader             BatchHeader `json:"batchHeader"`
	Fee                     []byte      `json:"fee"`
	SignatoryRecordHash     [32]byte    `json:"signatoryRecordHash"`
	ConfirmationBlockNumber uint32      `json:"confirmationBlockNumber"`
	BatchHeaderHash         []byte      `json:"batchHeaderHash"`
}

type BatchHeader struct {
	BlobHeadersRoot       [32]byte `json:"blobHeadersRoot"`
	QuorumNumbers         []byte   `json:"quorumNumbers"`
	SignedStakeForQuorums []byte   `json:"signedStakeForQuorums"`
	ReferenceBlockNumber  uint32   `json:"referenceBlockNumber"`
}

func (h *DisperserBatchHeader) Encode() ([]byte, error) {
	// The order here has to match the field ordering of ReducedBatchHeader defined in IEigenDAServiceManager.sol
	// ref: https://github.com/Layr-Labs/eigenda/blob/master/contracts/src/interfaces/IEigenDAServiceManager.sol#L43
	batchHeaderType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{
			Name: "blobHeadersRoot",
			Type: "bytes32",
		},
		{
			Name: "referenceBlockNumber",
			Type: "uint32",
		},
	})
	if err != nil {
		return nil, err
	}

	arguments := abi.Arguments{
		{
			Type: batchHeaderType,
		},
	}

	bytes32BatchRoot := [32]byte(h.BatchRoot)

	// cast batch root to bytes32

	s := struct {
		BlobHeadersRoot      [32]byte
		ReferenceBlockNumber uint32
	}{
		BlobHeadersRoot:      bytes32BatchRoot,
		ReferenceBlockNumber: uint32(h.ReferenceBlockNumber),
	}

	bytes, err := arguments.Pack(s)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// GetBatchHeaderHash returns the hash of the reduced BatchHeader that is used to sign the Batch
// ref: https://github.com/Layr-Labs/eigenda/blob/master/contracts/src/libraries/EigenDAHasher.sol#L65
func (h DisperserBatchHeader) GetBatchHeaderHash() ([32]byte, error) {
	headerByte, err := h.Encode()
	if err != nil {
		return [32]byte{}, err
	}

	var headerHash [32]byte
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(headerByte)
	copy(headerHash[:], hasher.Sum(nil)[:32])

	return headerHash, nil
}

// SerializeCommitment serializes the kzg commitment points to a byte slice
func (e *EigenDABlobInfo) SerializeCommitment() ([]byte, error) {
	return append(e.BlobHeader.Commitment.X.Bytes(), e.BlobHeader.Commitment.Y.Bytes()...), nil
}

// loadBlobInfo loads the disperser.BlobInfo struct into the EigenDABlobInfo struct
func (b *EigenDABlobInfo) LoadBlobInfo(disperserBlobInfo *disperser.BlobInfo) {

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

	var signatoryRecordHash [32]byte
	copy(signatoryRecordHash[:], disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetSignatoryRecordHash())

	b.BlobVerificationProof.BatchID = disperserBlobInfo.GetBlobVerificationProof().GetBatchId()
	b.BlobVerificationProof.BlobIndex = disperserBlobInfo.GetBlobVerificationProof().GetBlobIndex()
	b.BlobVerificationProof.BatchMetadata = BatchMetadata{
		Fee:                     disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetFee(),
		BatchHeaderHash:         disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeaderHash(),
		BatchHeader:             BatchHeader{},
		SignatoryRecordHash:     signatoryRecordHash,
		ConfirmationBlockNumber: disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetConfirmationBlockNumber(),
	}

	b.BlobVerificationProof.InclusionProof = disperserBlobInfo.GetBlobVerificationProof().GetInclusionProof()
	b.BlobVerificationProof.QuorumIndices = disperserBlobInfo.GetBlobVerificationProof().GetQuorumIndexes()

	batchRootSlice := disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetBatchRoot()
	var blobHeadersRoot [32]byte
	copy(blobHeadersRoot[:], batchRootSlice)
	b.BlobVerificationProof.BatchMetadata.BatchHeader.BlobHeadersRoot = blobHeadersRoot

	b.BlobVerificationProof.BatchMetadata.BatchHeader.QuorumNumbers = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetQuorumNumbers()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.SignedStakeForQuorums = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetQuorumSignedPercentages()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.ReferenceBlockNumber = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetReferenceBlockNumber()
}

/*
DisperserBlobInfo is a Go struct that represents the disperser.BlobInfo struct
without requiring the overhead of importing the disperser package from core eigenda:
 - https://github.com/Layr-Labs/eigenda/blob/master/api/grpc/disperser/disperser.pb.go
*/

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
	BatchHeader             DisperserBatchHeader `json:"batch_header,omitempty"`
	SignatoryRecordHash     []byte               `json:"signatory_record_hash,omitempty"`
	Fee                     []byte               `json:"fee"`
	ConfirmationBlockNumber uint32               `json:"confirmation_block_number,omitempty"`
	BatchHeaderHash         []byte               `json:"batchHeaderHash"`
}

type DisperserBatchHeader struct {
	BatchRoot               []byte `json:"batch_root,omitempty"`
	QuorumNumbers           []byte `json:"quorum_numbers,omitempty"`
	QuorumSignedPercentages []byte `json:"quorum_signed_percentages,omitempty"`
	ReferenceBlockNumber    uint32 `json:"reference_block_number,omitempty"`
}

/*
Convert EigenDABlobInfo to DisperserBlobInfo struct for compatibility with proxy server expected type
*/
func (e *EigenDABlobInfo) ToDisperserBlobInfo() (*DisperserBlobInfo, error) {
	// Convert BlobHeader
	var disperserBlobHeader DisperserBlobHeader
	commitment := G1Commitment{
		X: e.BlobHeader.Commitment.X.Bytes(),
		Y: e.BlobHeader.Commitment.Y.Bytes(),
	}
	quorumParams := make([]BlobQuorumParam, len(e.BlobHeader.QuorumBlobParams))
	for i, qp := range e.BlobHeader.QuorumBlobParams {
		quorumParams[i] = BlobQuorumParam{
			QuorumNumber:                    uint32(qp.QuorumNumber),
			AdversaryThresholdPercentage:    uint32(qp.AdversaryThresholdPercentage),
			ConfirmationThresholdPercentage: uint32(qp.ConfirmationThresholdPercentage),
			ChunkLength:                     qp.ChunkLength,
		}
	}
	disperserBlobHeader = DisperserBlobHeader{
		Commitment:       commitment,
		DataLength:       e.BlobHeader.DataLength,
		BlobQuorumParams: quorumParams,
	}

	// Convert BlobVerificationProof
	var disperserBlobVerificationProof DisperserBlobVerificationProof
	if &e.BlobVerificationProof != nil {
		var disperserBatchMetadata DisperserBatchMetadata
		if &e.BlobVerificationProof.BatchMetadata != nil {
			metadata := e.BlobVerificationProof.BatchMetadata
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
			BatchId:        e.BlobVerificationProof.BatchID,
			BlobIndex:      e.BlobVerificationProof.BlobIndex,
			BatchMetadata:  disperserBatchMetadata,
			InclusionProof: e.BlobVerificationProof.InclusionProof,
			QuorumIndexes:  e.BlobVerificationProof.QuorumIndices,
		}
	}

	// set batchHeaderHash if not set

	batchHeaderHash, err := disperserBlobVerificationProof.BatchMetadata.BatchHeader.GetBatchHeaderHash()
	if err != nil {
		return nil, err
	}

	disperserBlobVerificationProof.BatchMetadata.BatchHeaderHash = batchHeaderHash[:]

	return &DisperserBlobInfo{
		BlobHeader:            disperserBlobHeader,
		BlobVerificationProof: disperserBlobVerificationProof,
	}, nil
}

// InboxPayload is a structured representation of the calldata used for the EigenDA `addSequencerL2BatchFromEigenDA` method call
// for persisting certificates into the inbox sequence
type InboxPayload struct {
	BlobVerificationProof BlobVerificationProof
	BlobHeader            BlobHeader
}

// Load ingest loads calldata to a payload struct which explicitly defines the parsed
// calldata fields
func (ip *InboxPayload) Load(callDataValues []interface{}) error {
	if len(callDataValues) != 6 {
		return errors.New("calldata does not have the expected number of parameters")
	}

	blobVerificationProof, passed := callDataValues[1].(struct {
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

	if !passed {
		return errors.New("failed to parse blob verification proof")
	}

	blobHeader, passed := callDataValues[2].(struct {
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

	if !passed {
		return errors.New("failed to parse blob header")
	}

	payload := InboxPayload{
		BlobVerificationProof: BlobVerificationProof{
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
		BlobHeader: BlobHeader{
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
	}

	*ip = payload
	return nil
}
