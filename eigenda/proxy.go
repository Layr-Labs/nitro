package eigenda

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/rlp"
)

type EigenDAProxyClient struct {
	client ProxyClient
}

func NewEigenDAProxyClient(RPCUrl string) *EigenDAProxyClient {

	c := New(&Config{
		URL: RPCUrl,
	})
	return &EigenDAProxyClient{client: c}
}

func (c *EigenDAProxyClient) Put(ctx context.Context, data []byte) (*disperser.BlobInfo, error) {
	cert, err := c.client.SetData(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to set data: %w", err)
	}

	var blobInfo disperser.BlobInfo
	err = rlp.DecodeBytes(cert[1:], &blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blob info: %w", err)
	}

	return &blobInfo, nil
}

func (c *EigenDAProxyClient) Get(ctx context.Context, blobInfo *DisperserBlobInfo, domainFilter string) ([]byte, error) {
	commitment, err := rlp.EncodeToBytes(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode blob info: %w", err)
	}

	commitWithVersion := append([]byte{0x0}, commitment...)

	data, err := c.client.GetData(ctx, commitWithVersion, StrToDomainType(domainFilter))
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	return data, nil
}

// DomainType is a enumeration type for the different data domains for which a
// blob can exist between
type DomainType uint8

const (
	BinaryDomain DomainType = iota
	PolyDomain
	UnknownDomain
)

func (d DomainType) String() string {
	switch d {
	case BinaryDomain:
		return "binary"
	case PolyDomain:
		return "polynomial"
	default:
		return "unknown"
	}
}

func StrToDomainType(s string) DomainType {
	switch s {
	case "binary":
		return BinaryDomain
	case "polynomial":
		return PolyDomain
	default:
		return UnknownDomain
	}
}

// TODO: Add support for custom http client option
type Config struct {
	Actor string
	URL   string
}

// ProxyClient is an interface for communicating with the EigenDA proxy server
type ProxyClient interface {
	Health() error
	GetData(ctx context.Context, cert []byte, domain DomainType) ([]byte, error)
	SetData(ctx context.Context, b []byte) ([]byte, error)
}

// client is the implementation of ProxyClient
type client struct {
	cfg        *Config
	httpClient *http.Client
}

var _ ProxyClient = (*client)(nil)

func New(cfg *Config) ProxyClient {
	return &client{
		cfg,
		http.DefaultClient,
	}
}

// Health indicates if the server is operational; useful for event based awaits
// when integration testing
func (c *client) Health() error {
	url := c.cfg.URL + "/health"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received bad status code: %d", resp.StatusCode)
	}

	return nil
}

// GetData fetches blob data associated with a DA certificate
func (c *client) GetData(ctx context.Context, comm []byte, domain DomainType) ([]byte, error) {
	url := fmt.Sprintf("%s/get/0x%x?domain=%s&commitment_mode=simple", c.cfg.URL, comm, domain.String())

	if c.cfg.Actor != "" {
		url = fmt.Sprintf("%s&actor=%s", url, c.cfg.Actor)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct http request: %e", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received unexpected response code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SetData writes raw byte data to DA and returns the respective certificate
func (c *client) SetData(ctx context.Context, b []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/put/?commitment_mode=simple", c.cfg.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to store data: %v", resp.StatusCode)
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(b) == 0 {
		return nil, fmt.Errorf("read certificate is empty")
	}

	return b, err
}
