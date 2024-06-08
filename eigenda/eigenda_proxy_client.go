package eigenda

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/rlp"
)

type EigenDAProxyClient struct {
	RPCUrl string
}

func NewEigenDAProxyClient(RPCUrl string) *EigenDAProxyClient {
	return &EigenDAProxyClient{RPCUrl: RPCUrl}
}

// TODO: proper error types
func (c *EigenDAProxyClient) Put(data []byte) (*disperser.BlobInfo, error) {
	var blobInfo *disperser.BlobInfo

	url := fmt.Sprintf("%s/put", c.RPCUrl)
	resp, err := http.Post(url, "text/plain", bytes.NewBuffer([]byte(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to store data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to store data: %s", resp.Status)
	}

	commitment, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	cert := commitment[3:]
	if err != nil {
		return nil, fmt.Errorf("failed to decode commitment: %w", err)
	}

	err = rlp.DecodeBytes(cert, blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blob info: %w", err)
	}

	return blobInfo, nil
}

func (c *EigenDAProxyClient) Get(blobInfo *disperser.BlobInfo, domainFilter string) ([]byte, error) {
	commitment, err := rlp.EncodeToBytes(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode blob info: %w", err)
	}

	rpcurl := fmt.Sprintf("%s/get/%s", c.RPCUrl, commitment)

	// if not nil put in the domain filter as a part of the query url
	if domainFilter != "" {
		rpcurl = fmt.Sprintf("%s?domain=%s", rpcurl, url.QueryEscape(domainFilter))
	}
	resp, err := http.Get(rpcurl)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve data: %s", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return data, nil
}
