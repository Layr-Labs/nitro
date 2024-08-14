package eigenda

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbstate/daprovider"
	"github.com/offchainlabs/nitro/arbutil"
)

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
	return RecoverPayloadFromEigenDABatch(ctx, sequencerMsg[sequencerMsgOffset:], d.readerEigenDA, preimageRecorder, "binary")
}

func RecoverPayloadFromEigenDABatch(ctx context.Context,
	sequencerMsg []byte,
	daReader EigenDAReader,
	preimageRecoder daprovider.PreimageRecorder,
	domain string,
) ([]byte, error) {

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

	hash, err := blobInfo.PreimageHash()
	if err != nil {
		return nil, err
	}


	if preimageRecoder != nil {
		// iFFT the preimage data
		preimage, err := GenericEncodeBlob(data)
		if err != nil {
			return nil, err
		}
		preimageRecoder(*hash, preimage, arbutil.EigenDaPreimageType)
	}
	return data, nil
}

// ParseSequencerMsg parses the inbox tx calldata into a structured EigenDABlobInfo
func ParseSequencerMsg(calldata []byte) (*EigenDABlobInfo, error) {

	// this should never happen, but just in case
	if len(calldata) < 4 {
		return nil, errors.New("calldata is shorter than expected method signature length")
	}

	method, err := sequencerInboxABI.MethodById(calldata[0:4])
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

func uint32ToBytes(n uint32) []byte {
    bytes := make([]byte, 4)
    binary.BigEndian.PutUint32(bytes, n)
    return bytes
}
