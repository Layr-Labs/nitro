package eigenda

import (
	"context"
	"encoding/binary"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/util/containers"
)

func NewReaderForEigenDA(reader EigenDAReader) *readerForEigenDA {
	return &readerForEigenDA{readerEigenDA: reader}
}

type readerForEigenDA struct {
	readerEigenDA EigenDAReader
}

func (d *readerForEigenDA) IsValidHeaderByte(ctx context.Context, headerByte byte) bool {
	return daprovider.IsEigenDAMessageHeaderByte(headerByte)
}

// CollectPreimages collects preimages from the DA provider
func (b *readerForEigenDA) CollectPreimages(
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
) containers.PromiseInterface[daprovider.PreimagesResult] {
	promise, ctx := containers.NewPromiseWithContext[daprovider.PreimagesResult](context.Background())
	go func() {
		var preimages daprovider.PreimagesMap
		var preimageRecorder daprovider.PreimageRecorder
		preimages = make(daprovider.PreimagesMap)
		preimageRecorder = daprovider.RecordPreimagesTo(preimages)

		_, err := RecoverPayloadFromEigenDABatch(ctx, sequencerMsg, b.readerEigenDA, preimageRecorder)
		if err != nil {
			promise.ProduceError(err)
		} else {
			promise.Produce(daprovider.PreimagesResult{Preimages: preimages})
		}
	}()
	return promise
}

func (d *readerForEigenDA) RecoverPayload(
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
) containers.PromiseInterface[daprovider.PayloadResult] {
	promise, ctx := containers.NewPromiseWithContext[daprovider.PayloadResult](context.Background())
	go func() {
		payload, err := RecoverPayloadFromEigenDABatch(ctx, sequencerMsg[sequencerMsgOffset:], d.readerEigenDA, nil)
		if err != nil {
			promise.ProduceError(err)
		} else {
			promise.Produce(daprovider.PayloadResult{Payload: payload})
		}
	}()
	return promise
}

func RecoverPayloadFromEigenDABatch(ctx context.Context,
	sequencerMsg []byte,
	daReader EigenDAReader,
	preimageRecoder daprovider.PreimageRecorder,
) ([]byte, error) {

	eigenDAV1Cert, err := ParseSequencerMsg(sequencerMsg)
	if err != nil {
		log.Error("Failed to parse sequencer message", "err", err)
		return nil, err
	}

	data, err := daReader.QueryBlob(ctx, eigenDAV1Cert)
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
