// Package eigenda provides the legacy V1 EigenDA client interface.
//
// DEPRECATED: This package implements the V1 custom Store() API.
// For V2, use the DAProvider interface which implements the ALT-DA spec.
// Configure with DAProvider.Enable instead of EigenDA.Enable.
package eigenda

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/eigenda-proxy/clients/standard_client"
	"github.com/Layr-Labs/eigenda/api/grpc/disperser"

	"github.com/ethereum/go-ethereum/rlp"
)

type EigenDAProxyClient struct {
	client ProxyClient
}

func NewEigenDAProxyClient(rpcUrl string) *EigenDAProxyClient {
	c := standard_client.New(&standard_client.Config{
		URL: rpcUrl,
	})
	return &EigenDAProxyClient{client: c}
}

// NOTE: This method will be deprecated in the V2 migration release
func (c *EigenDAProxyClient) Put(ctx context.Context, data []byte) (*disperser.BlobInfo, error) {
	cert, err := c.client.SetData(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to set data: %w", err)
	}

	if len(cert) == 0 {
		return nil, fmt.Errorf("received empty certificate from proxy")
	}

	// Check version byte to determine certificate format
	version := cert[0]

	// V2 certificate (version 0x02): Not supported through this V1 legacy interface
	// This check prevents misconfiguration - V2 must use DAProvider.Enable, not EigenDA.Enable
	// If you see this error, update your config to use DAProvider interface for V2
	if version == 0x02 {
		return nil, fmt.Errorf("EigenDA V2 detected but accessed through deprecated V1 interface - use DAProvider.Enable for V2")
	}

	// V1 certificate (version 0x00): decode as disperser.BlobInfo
	var blobInfo disperser.BlobInfo
	err = rlp.DecodeBytes(cert[1:], &blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode V1 blob info: %w", err)
	}

	return &blobInfo, nil
}

func (c *EigenDAProxyClient) Get(ctx context.Context, blobInfo *disperser.BlobInfo) ([]byte, error) {
	commitment, err := rlp.EncodeToBytes(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode blob info: %w", err)
	}

	// TODO: support more strict versioning
	//       this is actually not needed for EigenDA V1
	//       & will be deprecated by V2 integration with Arbitrum ALT DA spec
	commitWithVersion := append([]byte{0x0}, commitment...)

	data, err := c.client.GetData(ctx, commitWithVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	return data, nil
}

// ProxyClient is an interface for communicating with the EigenDA proxy server
type ProxyClient interface {
	Health() error
	GetData(ctx context.Context, cert []byte) ([]byte, error)
	// NOTE: This method will be deprecated in the V2 migration release
	SetData(ctx context.Context, b []byte) ([]byte, error)
}
