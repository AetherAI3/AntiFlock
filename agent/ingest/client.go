// Package ingest submits bounded, already-signed agent telemetry to Core.
package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const maximumBatchEvents = 256
const maximumResponseSize = 1 << 20

type Config struct {
	Endpoint string
	Token string
	HTTP *http.Client
}

type Client struct {
	endpoint string
	token string
	http *http.Client
}

// NewClient only permits plain HTTP to a loopback Core. A remotely reachable
// Core requires HTTPS. HTTPS callers may authenticate with an approved node
// client certificate instead of a bearer token.
func NewClient(config Config) (*Client, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("agent ingest endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if endpoint.Scheme != "https" && endpoint.Scheme != "http" {
		return nil, errors.New("agent ingest endpoint must use https or loopback http")
	}
	if endpoint.Scheme == "http" && !loopbackHost(endpoint.Hostname()) {
		return nil, errors.New("agent ingest requires https outside loopback")
	}
	token := strings.TrimSpace(config.Token)
	if endpoint.Scheme == "http" && len(token) < 32 {
		return nil, errors.New("loopback HTTP agent ingest requires a token of at least 32 bytes")
	}
	if token != "" && len(token) < 32 {
		return nil, errors.New("agent ingest token must contain at least 32 bytes")
	}
	if config.HTTP == nil {
		config.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if config.HTTP.Timeout <= 0 || config.HTTP.Timeout > time.Minute {
		return nil, errors.New("agent ingest HTTP timeout must be between one nanosecond and one minute")
	}
	return &Client{endpoint: strings.TrimRight(endpoint.String(), "/"), token: token, http: config.HTTP}, nil
}

// Submit returns only a durable, rejection-free acknowledgement. Callers retain
// their signed batch whenever this method returns an error.
func (client *Client) Submit(ctx context.Context, input *antiflockv1.SubmitEventBatchRequest) (*antiflockv1.EventBatchAck, error) {
	if client == nil || client.http == nil {
		return nil, errors.New("agent ingest client is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validInput(input); err != nil {
		return nil, err
	}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: false}).Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("encode agent event batch: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint+"/v1/events/batch", bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.New("build agent event submission request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("submit agent event batch: %w", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseSize+1))
	if err != nil || len(content) > maximumResponseSize {
		return nil, errors.New("read bounded Core event batch acknowledgement")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Core rejected agent event batch with HTTP %d", response.StatusCode)
	}
	var output antiflockv1.SubmitEventBatchResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, &output); err != nil {
		return nil, errors.New("decode Core event batch acknowledgement")
	}
	ack := output.GetAck()
	if ack == nil || ack.GetBatchId() != input.GetBatch().GetBatchId() || len(ack.GetRejected()) != 0 {
		return nil, errors.New("Core did not durably accept the complete agent event batch")
	}
	return ack, nil
}

func validInput(input *antiflockv1.SubmitEventBatchRequest) error {
	batch := input.GetBatch()
	if batch == nil || !bounded(batch.GetBatchId(), 128) || !bounded(batch.GetNodeId(), 128) || len(batch.GetEvents()) == 0 || len(batch.GetEvents()) > maximumBatchEvents {
		return errors.New("agent event batch requires bounded batch and node ids and between one and 256 events")
	}
	bootID := ""
	for _, event := range batch.GetEvents() {
		if event == nil || event.GetNodeId() != batch.GetNodeId() || event.GetId() == "" {
			return errors.New("agent event batch contains an invalid scoped event")
		}
		if bootID == "" {
			bootID = event.GetBootId()
		} else if event.GetBootId() != bootID {
			return errors.New("agent event batch must contain one boot id")
		}
	}
	return nil
}

func bounded(value string, maximum int) bool { return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value }
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") { return true }
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
