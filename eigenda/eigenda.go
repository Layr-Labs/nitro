package eigenda

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/offchainlabs/nitro/daprovider"
)

const (
	sequencerMsgOffset = 41
	MaxBatchSize       = 16_777_216 // 16MiB
)

func IsEigenDAMessageHeaderByte(header byte) bool {
	return hasBits(header, daprovider.EigenDAV1MessageHeaderFlag)
}

// hasBits returns true if `checking` has all `bits`
func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
}

type EigenDAWriter interface {
	Store(context.Context, []byte) ([]byte, error)
	Serialize(eigenDAV1Cert *EigenDAV1Cert) ([]byte, error)
}

type EigenDAReader interface {
	QueryBlobV1(ctx context.Context, cert *EigenDAV1Cert) ([]byte, error)
	QueryBlobV2(ctx context.Context, daCommit []byte) ([]byte, error)
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

// QueryBlobV1 retrieves a blob from EigenDA using the provided EigenDAV1Cert
func (e *EigenDA) QueryBlobV1(ctx context.Context, cert *EigenDAV1Cert) ([]byte, error) {
	log.Info("Reading blob from EigenDA V1 network", "batchID", cert.BlobVerificationProof.BatchId)
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

func (e *EigenDA) QueryBlobV2(ctx context.Context, daCommit []byte) ([]byte, error) {
	data, err := e.client.GetV2(ctx, daCommit)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Store disperses a blob to EigenDA and returns the appropriate EigenDAV1Cert or certificate values
func (e *EigenDA) Store(ctx context.Context, data []byte) ([]byte, error) {
	log.Info("Dispersing batch as blob to EigenDA", "dataLength", len(data))
	daCommitment, err := e.client.Put(ctx, data)
	if err != nil {
		return nil, err
	}

	return daCommitment, nil
}

func (e *EigenDA) Serialize(cert *EigenDAV1Cert) ([]byte, error) {
	return rlp.EncodeToBytes(cert)
}
