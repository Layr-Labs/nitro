package eigenda

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbstate/daprovider"
	"github.com/offchainlabs/nitro/arbutil"
)

// NewReaderForEigenDA is generally meant to be only used by nitro.
// DA Providers should implement methods in the Reader interface independently
func NewReaderForEigenDA(reader EigenDAReader) *readerForEigenDA {
	return &readerForEigenDA{readerEigenDA: reader}
}

type readerForEigenDA struct {
	readerEigenDA EigenDAReader
}

func (d *readerForEigenDA) IsValidHeaderByte(headerByte byte) bool {
	return IsEigenDAMessageHeaderByte(headerByte)
}

func (d *readerForEigenDA) RecoverPayloadFromBatch(
	ctx context.Context,
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
	preimageRecorder daprovider.PreimageRecorder,
	validateSeqMsg bool,
) ([]byte, error) {
	println("RecoverPayloadFromBatch: ", hex.EncodeToString(sequencerMsg))
	// offset sequencer message at 41 
	return RecoverPayloadFromEigenDABatch(ctx, sequencerMsg[41:], d.readerEigenDA, preimageRecorder, "polynomial")
}


func RecoverPayloadFromEigenDABatch(ctx context.Context,
	sequencerMsg []byte,
	daReader EigenDAReader,
	preimageRecoder daprovider.PreimageRecorder,
	domain string,
) ([]byte, error) {
	log.Info("Start recovering payload from eigenda: ", "data", hex.EncodeToString(sequencerMsg))

	blobInfo, err := ParseSequencerMsg(sequencerMsg)
	if err != nil {
		log.Error("Failed to parse sequencer message", "err", err)
		return nil, err
	}

	data, err := daReader.QueryBlob(ctx, blobInfo, domain)
	if err != nil {
		log.Error("Failed to query data from EigenDA", "err", err)
		return nil, err
	}

	// record preimage data for EigenDA using the hash of the commitment
	// for lookups in the replay script
	kzgCommit, err := blobInfo.SerializeCommitment()
	if err != nil {
		return nil, err
	}

	println("kzgCommit: ", hex.EncodeToString(kzgCommit))

	shaDataHash := sha256.New()
	shaDataHash.Write(kzgCommit)
	dataHash := shaDataHash.Sum([]byte{})
	dataHash[0] = 1
	if preimageRecoder != nil {
		println("recording preimage for commitment: ", hex.EncodeToString(dataHash))
		preimageRecoder(common.BytesToHash(dataHash), data, arbutil.EigenDaPreimageType)
	}
	return data, nil
}

// ParseSequencerMsg parses the inbox tx calldata into a structured EigenDABlobInfo
func ParseSequencerMsg(calldata []byte) (*EigenDABlobInfo, error) {

	if len(calldata) < 4 {
		return nil, errors.New("calldata is shorter than expected method signature length")
	}

	// TODO: Construct the ABI struct at node initialization
	abi, err := abi.JSON(strings.NewReader(sequencerInboxABI))
	if err != nil {
		return nil, err
	}

	method, err := abi.MethodById(calldata[0:4])
	if err != nil {
		return nil, err
	}

	callDataValues, err := method.Inputs.Unpack(calldata[4:])
	if err != nil {
		return nil, err
	}

	inboxPayload := &InboxPayload{}

	err = inboxPayload.Load(callDataValues)
	if err != nil {
		return nil, err
	}

	return &EigenDABlobInfo{
		BlobVerificationProof: inboxPayload.BlobVerificationProof,
		BlobHeader:            inboxPayload.BlobHeader,
	}, nil

}
