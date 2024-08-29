package eigenda

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/offchainlabs/nitro/arbstate/daprovider"
)

const (
	sequencerMsgOffset = 41
	MaxBatchSize       = 2_000_000 // 2MB
)

func IsEigenDAMessageHeaderByte(header byte) bool {
	return hasBits(header, daprovider.EigenDAMessageHeaderFlag)
}

// hasBits returns true if `checking` has all `bits`
func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
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

// QueryBlob retrieves a blob from EigenDA using the provided EigenDABlobInfo
func (e *EigenDA) QueryBlob(ctx context.Context, cert *EigenDABlobInfo, domainFilter string) ([]byte, error) {
	log.Info("Reading blob from EigenDA", "batchID", cert.BlobVerificationProof.BatchID)
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

// Store disperses a blob to EigenDA and returns the appropriate EigenDABlobInfo or certificate values
func (e *EigenDA) Store(ctx context.Context, data []byte) (*EigenDABlobInfo, error) {
	log.Info("Dispersing batch as blob to EigenDA", "dataLength", len(data))
	var blobInfo = &EigenDABlobInfo{}
	cert, err := e.client.Put(ctx, data)
	if err != nil {
		return nil, err
	}

	blobInfo.LoadBlobInfo(cert)

	return blobInfo, nil
}

func (e *EigenDA) Serialize(blobInfo *EigenDABlobInfo) ([]byte, error) {
	return rlp.EncodeToBytes(blobInfo)
}
