// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE.md

package daprovider

import (
	"context"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"

	"github.com/offchainlabs/nitro/arbutil"
)

type BlobReader interface {
	GetBlobs(
		ctx context.Context,
		batchBlockHash common.Hash,
		versionedHashes []common.Hash,
	) ([]kzg4844.Blob, error)
	Initialize(ctx context.Context) error
}

type PreimagesMap map[arbutil.PreimageType]map[common.Hash][]byte

// PreimageRecorder is used to add (key,value) pair to the map accessed by key = ty of a bigger map, preimages.
// If ty doesn't exist as a key in the preimages map, then it is intialized to map[common.Hash][]byte and then (key,value) pair is added
type PreimageRecorder func(key common.Hash, value []byte, ty arbutil.PreimageType)

// RecordPreimagesTo takes in preimages map and returns a function that can be used
// In recording (hash,preimage) key value pairs into preimages map, when fetching payload through RecoverPayloadFromBatch
func RecordPreimagesTo(preimages PreimagesMap) PreimageRecorder {
	if preimages == nil {
		return nil
	}
	return func(key common.Hash, value []byte, ty arbutil.PreimageType) {
		if preimages[ty] == nil {
			preimages[ty] = make(map[common.Hash][]byte)
		}
		preimages[ty][key] = value
	}
}

var (
	ErrNoBlobReader          = errors.New("blob batch payload was encountered but no BlobReader was configured")
	ErrNoEigenDAReader       = errors.New("eigenda batch payload was encountered but no EigenDA reader was configured")
	ErrInvalidBlobDataFormat = errors.New("blob batch data is not a list of hashes as expected")
	ErrSeqMsgValidation      = errors.New("error validating recovered payload from batch")
)

type KeysetValidationMode uint8

const KeysetValidate KeysetValidationMode = 0
const KeysetPanicIfInvalid KeysetValidationMode = 1
const KeysetDontValidate KeysetValidationMode = 2

// DASMessageHeaderFlag indicates that this data is a certificate for the data availability service,
// which will retrieve the full batch data.
const DASMessageHeaderFlag byte = 0x80

// TreeDASMessageHeaderFlag indicates that this DAS certificate data employs the new merkelization strategy.
// Ignored when DASMessageHeaderFlag is not set.
const TreeDASMessageHeaderFlag byte = 0x08

// L1AuthenticatedMessageHeaderFlag indicates that this message was authenticated by L1. Currently unused.
const L1AuthenticatedMessageHeaderFlag byte = 0x40

// ZeroheavyMessageHeaderFlag indicates that this message is zeroheavy-encoded.
const ZeroheavyMessageHeaderFlag byte = 0x20

// BlobHashesHeaderFlag indicates that this message contains EIP 4844 versioned hashes of the commitments calculated over the blob data for the batch data.
const BlobHashesHeaderFlag byte = L1AuthenticatedMessageHeaderFlag | 0x10 // 0x50

// BrotliMessageHeaderByte indicates that the message is brotli-compressed.
const BrotliMessageHeaderByte byte = 0

// EigenDAMessageHeaderFlag indicates that this message contains EigenDA blob data.
const EigenDAMessageHeaderFlag byte = 0xed

// KnownHeaderBits is all header bits with known meaning to this nitro version
const KnownHeaderBits byte = DASMessageHeaderFlag | TreeDASMessageHeaderFlag | L1AuthenticatedMessageHeaderFlag | ZeroheavyMessageHeaderFlag | BlobHashesHeaderFlag | BrotliMessageHeaderByte | EigenDAMessageHeaderFlag

var DefaultDASRetentionPeriod time.Duration = time.Hour * 24 * 15

// hasBits returns true if `checking` has all `bits`
func hasBits(checking byte, bits byte) bool {
	// NOTE: This is done to mitigate a bug where the
	// bitwise AND between EigenDAMessageHeaderFlag and other flag values would return true
	// when doing the low-level check - resulting in this function to return true
	// from other dapReaders and cause terminal errors since an EigenDA message type
	// would be passed into e.g an AnyTrust reader
	// assuming 0xed for the message header byte is a fundamental design flaw
	if checking == EigenDAMessageHeaderFlag && bits != EigenDAMessageHeaderFlag {
		return false
	}

	return (checking & bits) == bits
}

func IsL1AuthenticatedMessageHeaderByte(header byte) bool {
	return hasBits(header, L1AuthenticatedMessageHeaderFlag)
}

func IsDASMessageHeaderByte(header byte) bool {
	return hasBits(header, DASMessageHeaderFlag)
}

func IsTreeDASMessageHeaderByte(header byte) bool {
	return hasBits(header, TreeDASMessageHeaderFlag)
}

func IsZeroheavyEncodedHeaderByte(header byte) bool {
	return hasBits(header, ZeroheavyMessageHeaderFlag)
}

func IsBlobHashesHeaderByte(header byte) bool {
	return hasBits(header, BlobHashesHeaderFlag)
}

func IsBrotliMessageHeaderByte(b uint8) bool {
	return b == BrotliMessageHeaderByte
}

func IsEigenDAMessageHeaderByte(header byte) bool {
	return hasBits(header, EigenDAMessageHeaderFlag)
}

// IsKnownHeaderByte returns true if the supplied header byte has only known bits
func IsKnownHeaderByte(b uint8) bool {
	return b&^KnownHeaderBits == 0
}
