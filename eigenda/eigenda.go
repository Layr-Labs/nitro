package eigenda

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	flag "github.com/spf13/pflag"
)

const (
	sequencerMsgOffset = 41
	MaxBatchSize       = 16_252_897 // largest blob size allowed before payload -> blob padding to 16MiB
)

type EigenDAWriter interface {
	Store(context.Context, []byte) ([]byte, error)
	Serialize(eigenDAV1Cert *EigenDAV1Cert) ([]byte, error)
}

type EigenDAReader interface {
	QueryBlobV1(ctx context.Context, cert *EigenDAV1Cert) ([]byte, error)
	QueryBlobV2(ctx context.Context, daCommit []byte) ([]byte, error)
}

type EigenDAConfig struct {
	Enable bool `koanf:"enable"`
	// ugh why is this called RPC when its a rest endpoint for eigenda-proxy. this should be called something else
	// but this code will soon be nuked so it's not worth introducing a breaking config change
	Rpc string `koanf:"rpc" reload:"hot"`
}

func (cfg *EigenDAConfig) Validate() error {
	if cfg.Enable && strings.TrimSpace(cfg.Rpc) == "" {
		return fmt.Errorf("EigenDA enabled but `rpc` value set for EigenDA Proxy host")
	}

	return nil
}

var DefaultEigenDAConfig = EigenDAConfig{
	Enable: false,
	Rpc:    "",
}

func EigenDAConfigAddOptions(prefix string, f *flag.FlagSet) {
	f.Bool(prefix+".enable", DefaultEigenDAConfig.Enable, "whether or not to activate batch posting and/or message derivation using EigenDA")
	f.String(prefix+".rpc", DefaultEigenDAConfig.Rpc, "url of EigenDA proxy service used to disperse and fetch batches")
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

// QueryBlobV1 retrieves a blob from EigenDAV1 using the provided EigenDAV1Cert
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

// QueryBlobV2 retrieves from EigenDAV2 using the provided daCommit bytes
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
