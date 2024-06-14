package eigenda

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

type EigenDAProxyClient struct {
	RPCUrl string
}

func NewEigenDAProxyClient(rpc string) *EigenDAProxyClient {
	return &EigenDAProxyClient{RPCUrl: rpc}
}

// TODO: proper error types
func (c *EigenDAProxyClient) Put(ctx context.Context, data []byte) (*disperser.BlobInfo, error) {
	log.Info("Putting blob EIGENDAPROXYCLIENT", "data", hex.EncodeToString(data))

	body := bytes.NewReader(data)

	log.Info("Creating HTTP POST request", "body", body)

	url := fmt.Sprintf("%s/put/", c.RPCUrl)
	log.Info("Creating HTTP POST request", "url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	log.Info("Sending HTTP POST request", "url", url)
	log.Info("Sending HTTP POST request", "body", body)
	log.Info("Sending HTTP POST request", "req", req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to store data: %s", resp.Status)
	}

	commitment, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var blobInfo disperser.BlobInfo
	cert := commitment[3:]
	err = rlp.DecodeBytes(cert, &blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blob info: %w", err)
	}

	return &blobInfo, nil
}

func (c *EigenDAProxyClient) Get(ctx context.Context, blobInfo *EigenDABlobInfo, domainFilter string) ([]byte, error) {
	commitment, err := rlp.EncodeToBytes(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode blob info: %w", err)
	}

	rpcurl := fmt.Sprintf("%s/get/%s", c.RPCUrl, commitment)

	// if not nil or binary (default) put in the domain filter as a part of the query url
	if domainFilter != "" && domainFilter != "binary" {
		rpcurl = fmt.Sprintf("%s?domain=%s", rpcurl, url.QueryEscape(domainFilter))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rpcurl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve data: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return data, nil
}
