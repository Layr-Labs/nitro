package eigenda

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/offchainlabs/nitro/daprovider"
)

func NewReaderForEigenDA(reader EigenDAReader) *readerForEigenDA {
	return &readerForEigenDA{readerEigenDA: reader}
}

type readerForEigenDA struct {
	readerEigenDA EigenDAReader
}

func (d *readerForEigenDA) IsValidHeaderByte(ctx context.Context, headerByte byte) bool {
	return daprovider.IsEigenDAV1HeaderByte(headerByte) || daprovider.IsEigenDAV2HeaderByte(headerByte)
}

func (d *readerForEigenDA) RecoverPayloadFromBatch(
	ctx context.Context,
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
	preimages daprovider.PreimagesMap,
	validateSeqMsg bool,
) ([]byte, daprovider.PreimagesMap, error) {
	if preimages == nil {
		preimages = make(daprovider.PreimagesMap)
	}
	preimageRecorder := daprovider.RecordPreimagesTo(preimages)
	msg := sequencerMsg[sequencerMsgOffset:]
	if msg[0] == 0x0 {
		return RecoverPayloadFromEigenDAV1Batch(ctx, msg, d.readerEigenDA, preimageRecorder)
	} else {
		return RecoverPayloadFromEigenDAV2Batch(ctx, msg, d.readerEigenDA, preimageRecorder)
	}
	return payload, preimages, err
}

func RecoverPayloadFromEigenDAV2Batch(ctx context.Context,
	sequencerMsg []byte,
	daReader EigenDAReader,
	preimageRecoder daprovider.PreimageRecorder,
) ([]byte, error) {
	data, err := daReader.QueryBlobV2(ctx, sequencerMsg)
	if err != nil {
		log.Error("Failed to query data from EigenDA", "err", err)
		return nil, err
	}

	var v2Cert EigenDAV2Cert
	println(fmt.Sprintf("v2 certificate rlp encoded bytes: %x", sequencerMsg[1:]))
	err = rlp.DecodeBytes(sequencerMsg[1:], &v2Cert)
	if err != nil {
		return nil, err
	}

	if preimageRecoder != nil {
		preimage, err := GenericEncodeBlob(data)
		if err != nil {
			return nil, err
		}
		preimageRecoder(v2Cert.PreimageHash(), preimage, arbutil.EigenDaPreimageType)
	}
	return data, nil
}

func RecoverPayloadFromEigenDAV1Batch(ctx context.Context,
	sequencerMsg []byte,
	daReader EigenDAReader,
	preimageRecoder daprovider.PreimageRecorder,
) ([]byte, error) {
	eigenDAV1Cert, err := ParseSequencerMsg(sequencerMsg)
	if err != nil {
		log.Error("Failed to parse sequencer message", "err", err)
		return nil, err
	}

	data, err := daReader.QueryBlobV1(ctx, eigenDAV1Cert)
	if err != nil {
		log.Error("Failed to query data from EigenDA", "err", err)
		return nil, err
	}

	hash, err := eigenDAV1Cert.PreimageHash()
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

func interfaceToBytesJSON(data interface{}) ([]byte, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// ParseSequencerMsg parses the certificate from the inbox message
func ParseSequencerMsg(abiEncodedCert []byte) (*EigenDAV1Cert, error) {

	spoofedFunc := certDecodeABI.Methods["decodeCert"]

	m := make(map[string]interface{})
	err := spoofedFunc.Inputs.UnpackIntoMap(m, abiEncodedCert)
	if err != nil {
		return nil, err
	}

	b, err := interfaceToBytesJSON(m["cert"])
	if err != nil {
		return nil, err
	}

	// decode to EigenDAV1Cert
	var cert EigenDAV1Cert
	err = json.Unmarshal(b, &cert)

	if err != nil {
		return nil, err
	}

	return &cert, nil

}

func uint32ToBytes(n uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, n)
	return bytes
}
