// Package headscale provides a read-only Headscale control-plane adapter. It
// intentionally exposes no create, move, tag, expire, rename, or delete calls.
package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

const defaultMaximumResponse = 1 << 20

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Config struct {
	BaseURL              string
	APIKey               string
	HTTPClient           HTTPDoer
	ProviderAssociations map[string]string
	IncludeAddresses     bool
	MaximumResponseBytes int
}

// RequestPlan is a credential-free dry run. Authorization headers are never
// included in it or returned from this package.
type RequestPlan struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

type Snapshot struct {
	ObservedAt time.Time
	Peers      []*antiflockv1.MeshPeerObservation
}

type Client struct {
	endpoint             *url.URL
	apiKey               string
	httpClient           HTTPDoer
	providerAssociations map[string]string
	includeAddresses     bool
	maximumResponse      int
}

func NewClient(config Config) (*Client, error) {
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("headscale base URL must be absolute and contain no credentials, query, or fragment")
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && isLoopbackHost(base.Hostname())) {
		return nil, errors.New("headscale requires HTTPS except on an explicit loopback address")
	}
	if config.APIKey == "" || strings.TrimSpace(config.APIKey) != config.APIKey || strings.ContainsAny(config.APIKey, "\r\n") {
		return nil, errors.New("headscale API key is required and must be a single canonical value")
	}
	maximum := config.MaximumResponseBytes
	if maximum <= 0 {
		maximum = defaultMaximumResponse
	}
	if maximum > 16<<20 {
		return nil, errors.New("headscale response limit is too large")
	}
	client := config.HTTPClient
	if client == nil {
		transport := http.RoundTripper(http.DefaultTransport)
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = base.Clone()
		}
		client = &http.Client{
			Transport: transport, Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("headscale redirects are disabled")
			},
		}
	}
	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/node"
	endpoint.RawPath = ""
	associations, err := validatedAssociations(config.ProviderAssociations)
	if err != nil {
		return nil, err
	}
	return &Client{
		endpoint: &endpoint, apiKey: config.APIKey, httpClient: client,
		providerAssociations: associations, includeAddresses: config.IncludeAddresses,
		maximumResponse: maximum,
	}, nil
}

func (client *Client) DryRunListNodes() RequestPlan {
	if client == nil || client.endpoint == nil {
		return RequestPlan{}
	}
	return RequestPlan{Method: http.MethodGet, URL: client.endpoint.String()}
}

// ListNodes performs the sole supported read-only request and maps Headscale
// identities to canonical AntiFlock nodes only when an explicit association is
// present. Control-plane online status is not mislabeled as a verified path or
// a transport handshake.
func (client *Client) ListNodes(ctx context.Context, observedAt time.Time) (*Snapshot, error) {
	if client == nil || client.endpoint == nil {
		return nil, errors.New("headscale client is required")
	}
	if observedAt.IsZero() {
		return nil, errors.New("headscale observation time is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("construct headscale request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.apiKey)
	response, err := client.httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("headscale node query failed")
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("headscale returned an empty response")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("headscale node query returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, int64(client.maximumResponse)+1))
	if err != nil {
		return nil, errors.New("read headscale node response")
	}
	if len(content) == 0 || len(content) > client.maximumResponse {
		return nil, errors.New("headscale node response is empty or oversized")
	}
	var document listNodesResponse
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("headscale node response is not valid JSON")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	result := &Snapshot{ObservedAt: observedAt.UTC(), Peers: make([]*antiflockv1.MeshPeerObservation, 0, len(document.Nodes))}
	seenProviderIDs := make(map[string]struct{}, len(document.Nodes))
	for _, node := range document.Nodes {
		providerID := string(node.ID)
		if strings.TrimSpace(node.NodeKey) != node.NodeKey {
			return nil, errors.New("headscale node key is not canonical")
		}
		if providerID == "" {
			providerID = node.NodeKey
		}
		if providerID == "" {
			continue
		}
		if _, duplicate := seenProviderIDs[providerID]; duplicate {
			return nil, errors.New("headscale response contains duplicate provider node ids")
		}
		seenProviderIDs[providerID] = struct{}{}
		canonicalNodeID, err := associatedNode(client.providerAssociations, providerID, node.NodeKey)
		if err != nil {
			return nil, err
		}
		connection := antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_UNKNOWN
		if !node.Online {
			connection = antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DISCONNECTED
		}
		peer := &antiflockv1.MeshPeerObservation{
			Provider: "headscale", ProviderPeerId: providerID, NodeId: canonicalNodeID,
			ConnectionType: connection, Authorized: canonicalNodeID != "",
		}
		if client.includeAddresses {
			peer.MeshAddresses = normalizedIPs(node.IPAddresses)
		}
		result.Peers = append(result.Peers, peer)
	}
	sort.Slice(result.Peers, func(left, right int) bool {
		return result.Peers[left].ProviderPeerId < result.Peers[right].ProviderPeerId
	})
	return result, nil
}

type listNodesResponse struct {
	Nodes []nodeDocument `json:"nodes"`
}

type nodeDocument struct {
	ID          flexibleID `json:"id"`
	NodeKey     string     `json:"nodeKey"`
	IPAddresses []string   `json:"ipAddresses"`
	Online      bool       `json:"online"`
}

type flexibleID string

func (value *flexibleID) UnmarshalJSON(content []byte) error {
	var text string
	if err := json.Unmarshal(content, &text); err == nil {
		if strings.TrimSpace(text) != text {
			return errors.New("headscale string node id is not canonical")
		}
		*value = flexibleID(text)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(content, &number); err != nil {
		return errors.New("headscale node id must be a string or integer")
	}
	integer, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return errors.New("headscale node id must be an unsigned integer")
	}
	*value = flexibleID(strconv.FormatUint(integer, 10))
	return nil
}

func associatedNode(values map[string]string, providerIDs ...string) (string, error) {
	result := ""
	for _, providerID := range providerIDs {
		if nodeID := values[providerID]; nodeID != "" {
			if result != "" && result != nodeID {
				return "", errors.New("headscale provider identities map to conflicting canonical nodes")
			}
			result = nodeID
		}
	}
	return result, nil
}

func normalizedIPs(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		canonical := ip.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result
}

func validatedAssociations(source map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(source))
	for key, value := range source {
		if key == "" || value == "" || len(key) > 512 || len(value) > 128 || strings.TrimSpace(key) != key || strings.TrimSpace(value) != value {
			return nil, errors.New("headscale provider associations must use canonical bounded identities")
		}
		result[key] = value
	}
	return result, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	}
	return errors.New("headscale node response contains trailing data")
}
