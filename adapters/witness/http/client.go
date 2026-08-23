// Package http is a generic HTTPS ExternalWitness client. It POSTs one JSON
// checkpoint to a configured URL and verifies the JSON receipt it gets back
// under a witness public key the operator configured out of band.
//
// Transport rules follow the headscale adapter: HTTPS is required except on
// a literal loopback IP, redirects are disabled, the response body is
// bounded, and an optional pinned CA replaces the system roots. The wire
// format is deliberately minimal so any party can implement the server side
// from docs/integration-interfaces.md without sharing code with this
// repository.
package http

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
	"time"

	"github.com/DBarr3/AntiFlock/core/integration"
)

const (
	// DefaultMaximumResponse bounds the receipt body.
	DefaultMaximumResponse = 64 * 1024
	// DefaultTimeout bounds one Submit round trip.
	DefaultTimeout = 15 * time.Second
	maximumBearer  = 4096
)

// HTTPDoer is the injected transport seam.
type HTTPDoer interface {
	Do(*nethttp.Request) (*nethttp.Response, error)
}

// Config configures the client.
type Config struct {
	// URL is the absolute endpoint the checkpoint is POSTed to. HTTPS is
	// required unless the host is a literal loopback IP (127.0.0.0/8, ::1).
	URL string
	// WitnessPublicKey verifies receipts. It is mandatory: a witness whose
	// key the operator does not hold cannot produce evidence.
	WitnessPublicKey ed25519.PublicKey
	// PinnedCAPEM, when set, is the only root trusted for the TLS connection.
	PinnedCAPEM []byte
	// BearerToken, when set, is sent as an Authorization header. It is never
	// included in a DryRun plan.
	BearerToken string
	// HTTPClient overrides the transport (tests). When set, PinnedCAPEM and
	// Timeout are the caller's responsibility.
	HTTPClient HTTPDoer
	// Timeout bounds one round trip; zero uses DefaultTimeout.
	Timeout time.Duration
	// MaximumResponseBytes bounds the receipt body; zero uses
	// DefaultMaximumResponse. It may not exceed 1 MiB.
	MaximumResponseBytes int
}

// RequestPlan is a credential-free dry run.
type RequestPlan struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

// Client is the HTTPS witness client.
type Client struct {
	endpoint        *url.URL
	publicKey       ed25519.PublicKey
	bearer          string
	httpClient      HTTPDoer
	maximumResponse int
}

// checkpointDocument is the wire form of a Checkpoint.
type checkpointDocument struct {
	Version    int                    `json:"version"`
	Checkpoint integration.Checkpoint `json:"checkpoint"`
}

// receiptDocument is the wire form of a WitnessReceipt.
type receiptDocument struct {
	WitnessID        string    `json:"witnessId"`
	CheckpointDigest string    `json:"checkpointDigest"`
	WitnessedAt      time.Time `json:"witnessedAt"`
	Signature        string    `json:"signature"`
	KeyID            string    `json:"keyId"`
}

// NewClient validates the configuration and builds a client.
func NewClient(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("%w: witness URL must be absolute and contain no credentials, query, or fragment", integration.ErrInvalidInput)
	}
	if !secureScheme(endpoint) {
		return nil, fmt.Errorf("%w: witness requires HTTPS except on an explicit loopback address", integration.ErrInvalidInput)
	}
	if len(config.WitnessPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: witness public key must be Ed25519", integration.ErrInvalidInput)
	}
	if config.BearerToken != "" && !integration.ValidIdentifierLen(config.BearerToken, maximumBearer) {
		return nil, fmt.Errorf("%w: witness bearer token must be a single canonical value", integration.ErrInvalidInput)
	}
	maximum := config.MaximumResponseBytes
	if maximum <= 0 {
		maximum = DefaultMaximumResponse
	}
	if maximum > 1<<20 {
		return nil, fmt.Errorf("%w: witness response limit is too large", integration.ErrInvalidInput)
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > 5*time.Minute {
		return nil, fmt.Errorf("%w: witness timeout is too large", integration.ErrInvalidInput)
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		transport, err := newTransport(config.PinnedCAPEM)
		if err != nil {
			return nil, err
		}
		httpClient = &nethttp.Client{
			Transport: transport, Timeout: timeout,
			CheckRedirect: func(*nethttp.Request, []*nethttp.Request) error {
				return errors.New("witness redirects are disabled")
			},
		}
	} else if len(config.PinnedCAPEM) != 0 {
		return nil, fmt.Errorf("%w: a pinned CA cannot be applied to an injected HTTP client", integration.ErrInvalidInput)
	}
	return &Client{
		endpoint: endpoint, publicKey: append(ed25519.PublicKey(nil), config.WitnessPublicKey...),
		bearer: config.BearerToken, httpClient: httpClient, maximumResponse: maximum,
	}, nil
}

// secureScheme is the transport guard: HTTPS always; plain HTTP only when the
// host is a loopback address.
func secureScheme(endpoint *url.URL) bool {
	if endpoint.Scheme == "https" {
		return true
	}
	return endpoint.Scheme == "http" && isLoopbackHost(endpoint.Hostname())
}

func newTransport(pinnedCAPEM []byte) (nethttp.RoundTripper, error) {
	transport := nethttp.RoundTripper(nethttp.DefaultTransport)
	base, ok := nethttp.DefaultTransport.(*nethttp.Transport)
	if ok {
		cloned := base.Clone()
		cloned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if len(pinnedCAPEM) != 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pinnedCAPEM) {
				return nil, fmt.Errorf("%w: pinned CA PEM contains no certificates", integration.ErrInvalidInput)
			}
			cloned.TLSClientConfig.RootCAs = pool
		}
		transport = cloned
	} else if len(pinnedCAPEM) != 0 {
		return nil, fmt.Errorf("%w: pinned CA requires the standard transport", integration.ErrInvalidInput)
	}
	return transport, nil
}

// DryRun returns the credential-free request plan.
func (client *Client) DryRun() RequestPlan {
	if client == nil || client.endpoint == nil {
		return RequestPlan{}
	}
	return RequestPlan{Method: nethttp.MethodPost, URL: client.endpoint.String()}
}

// Submit implements integration.ExternalWitness.
func (client *Client) Submit(ctx context.Context, checkpoint integration.Checkpoint) (integration.WitnessReceipt, error) {
	if client == nil || client.endpoint == nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness client is required", integration.ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return integration.WitnessReceipt{}, err
	}
	expectedDigest, err := integration.CheckpointDigest(checkpoint)
	if err != nil {
		return integration.WitnessReceipt{}, err
	}
	body, err := json.Marshal(checkpointDocument{Version: integration.InterfaceVersion, Checkpoint: checkpoint})
	if err != nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: encode checkpoint", integration.ErrInvalidInput)
	}
	request, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, client.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: construct witness request", integration.ErrInvalidInput)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if client.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+client.bearer)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return integration.WitnessReceipt{}, ctxErr
		}
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness request failed", integration.ErrUnavailable)
	}
	if response == nil || response.Body == nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness returned an empty response", integration.ErrUnavailable)
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == nethttp.StatusOK || response.StatusCode == nethttp.StatusCreated:
	case response.StatusCode == nethttp.StatusConflict || response.StatusCode == nethttp.StatusUnprocessableEntity:
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness refused the checkpoint (HTTP %d)", integration.ErrInvalidInput, response.StatusCode)
	case response.StatusCode == nethttp.StatusUnauthorized || response.StatusCode == nethttp.StatusForbidden:
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness rejected the credential (HTTP %d)", integration.ErrUnauthenticated, response.StatusCode)
	case response.StatusCode >= 500 || response.StatusCode == nethttp.StatusTooManyRequests:
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness returned HTTP %d", integration.ErrUnavailable, response.StatusCode)
	default:
		return integration.WitnessReceipt{}, fmt.Errorf("witness returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, int64(client.maximumResponse)+1))
	if err != nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: read witness response", integration.ErrUnavailable)
	}
	if len(content) == 0 || len(content) > client.maximumResponse {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness response is empty or oversized", integration.ErrInvalidReceipt)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document receiptDocument
	if err := decoder.Decode(&document); err != nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: witness response is not a receipt", integration.ErrInvalidReceipt)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return integration.WitnessReceipt{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: receipt signature encoding is invalid", integration.ErrInvalidReceipt)
	}
	receipt := integration.WitnessReceipt{
		WitnessID: document.WitnessID, CheckpointDigest: document.CheckpointDigest,
		WitnessedAt: document.WitnessedAt.UTC(), Signature: signature, KeyID: document.KeyID,
	}
	if receipt.CheckpointDigest != expectedDigest {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: receipt is bound to a different checkpoint", integration.ErrInvalidReceipt)
	}
	if err := integration.VerifyReceipt(receipt, client.publicKey); err != nil {
		return integration.WitnessReceipt{}, err
	}
	return receipt, nil
}

// EncodeReceipt renders a receipt in the wire form this client accepts. A
// server implementation (or a test) uses it to answer a Submit.
func EncodeReceipt(receipt integration.WitnessReceipt) ([]byte, error) {
	return json.Marshal(receiptDocument{
		WitnessID: receipt.WitnessID, CheckpointDigest: receipt.CheckpointDigest, WitnessedAt: receipt.WitnessedAt.UTC(),
		Signature: base64.RawURLEncoding.EncodeToString(receipt.Signature), KeyID: receipt.KeyID,
	})
}

// DecodeCheckpoint parses the wire form this client sends. A server
// implementation uses it to read a Submit body; the version must match.
func DecodeCheckpoint(body []byte) (integration.Checkpoint, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var document checkpointDocument
	if err := decoder.Decode(&document); err != nil {
		return integration.Checkpoint{}, fmt.Errorf("%w: checkpoint body is not valid", integration.ErrInvalidInput)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return integration.Checkpoint{}, err
	}
	if document.Version != integration.InterfaceVersion {
		return integration.Checkpoint{}, fmt.Errorf("%w: checkpoint declares version %d", integration.ErrVersionMismatch, document.Version)
	}
	if err := document.Checkpoint.Validate(); err != nil {
		return integration.Checkpoint{}, err
	}
	return document.Checkpoint, nil
}

// Factory is a Registry factory. Options: "url", "witness-public-key"
// (base64url raw Ed25519 public key), optional "pinned-ca-pem", optional
// "bearer-token".
func Factory(_ context.Context, options integration.Options) (any, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(options["witness-public-key"])
	if err != nil {
		return nil, fmt.Errorf("%w: witness-public-key must be base64url", integration.ErrInvalidInput)
	}
	return NewClient(Config{
		URL: options["url"], WitnessPublicKey: publicKey, PinnedCAPEM: []byte(options["pinned-ca-pem"]), BearerToken: options["bearer-token"],
	})
}

// isLoopbackHost accepts only literal loopback addresses (127.0.0.0/8, ::1).
// A name such as "localhost" goes through the host resolver and is not
// trusted for the plaintext exception.
func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	}
	return fmt.Errorf("%w: document contains trailing data", integration.ErrInvalidReceipt)
}

var _ integration.ExternalWitness = (*Client)(nil)
