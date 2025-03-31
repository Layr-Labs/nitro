package eigenda

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/eigenda-proxy/clients/standard_client"
	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/rlp"
)

type EigenDAProxyClient struct {
	client *standard_client.Client
}

func NewEigenDAProxyClient(rpcUrl string) *EigenDAProxyClient {
	c := standard_client.New(&standard_client.Config{
		URL: rpcUrl,
	})
	return &EigenDAProxyClient{client: c}
}

func (c *EigenDAProxyClient) Put(ctx context.Context, data []byte) ([]byte, error) {
	daCommitment, err := c.client.SetData(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to set data: %w", err)
	}

	return daCommitment, nil
}

func (c *EigenDAProxyClient) GetV2(ctx context.Context, daCommitment []byte) ([]byte, error) {

	data, err := c.client.GetData(ctx, daCommitment)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	return data, nil
}


func (c *EigenDAProxyClient) Get(ctx context.Context, blobInfo *disperser.BlobInfo) ([]byte, error) {
	commitment, err := rlp.EncodeToBytes(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode blob info: %w", err)
	}

	// TODO: support more strict versioning
	commitWithVersion := append([]byte{0x0}, commitment...)

	data, err := c.client.GetData(ctx, commitWithVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	return data, nil
}

