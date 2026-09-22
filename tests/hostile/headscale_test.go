package hostile_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/adapters/mesh/headscale"
)

type scriptedDoer struct {
	status int
	body   []byte
	nilRsp bool
	err    error
}

func (doer scriptedDoer) Do(*http.Request) (*http.Response, error) {
	if doer.err != nil {
		return nil, doer.err
	}
	if doer.nilRsp {
		return nil, nil
	}
	return &http.Response{StatusCode: doer.status, Body: io.NopCloser(bytes.NewReader(doer.body)), Header: http.Header{}}, nil
}

func headscaleClient(t *testing.T, doer headscale.HTTPDoer, maximum int) *headscale.Client {
	t.Helper()
	client, err := headscale.NewClient(headscale.Config{
		BaseURL: "https://headscale.example", APIKey: "fixture-api-key", HTTPClient: doer,
		ProviderAssociations: map[string]string{"1": "node-a"}, MaximumResponseBytes: maximum,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// Invariant: a hostile Headscale control plane cannot make ListNodes return a
// snapshot: oversized, trailing, duplicated, non-canonical, and non-2xx
// responses are errors, and errors never echo response bytes.
func TestHeadscaleListNodesRejectsHostileResponses(t *testing.T) {
	t.Parallel()
	observedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	cases := map[string]scriptedDoer{
		"oversized":                  {status: 200, body: []byte(`{"nodes":[{"id":"1","nodeKey":"` + strings.Repeat("k", 2048) + `"}]}`)},
		"trailing-data":              {status: 200, body: []byte(`{"nodes":[]} {"nodes":[]}`)},
		"trailing-garbage":           {status: 200, body: []byte(`{"nodes":[]}garbage`)},
		"empty":                      {status: 200, body: nil},
		"not-json":                   {status: 200, body: []byte(`<html>`)},
		"duplicate-provider-ids":     {status: 200, body: []byte(`{"nodes":[{"id":"1","nodeKey":"a"},{"id":1,"nodeKey":"b"}]}`)},
		"non-canonical-node-key":     {status: 200, body: []byte(`{"nodes":[{"id":"1","nodeKey":" key "}]}`)},
		"non-canonical-string-id":    {status: 200, body: []byte(`{"nodes":[{"id":" 1","nodeKey":"k"}]}`)},
		"negative-numeric-id":        {status: 200, body: []byte(`{"nodes":[{"id":-1,"nodeKey":"k"}]}`)},
		"float-numeric-id":           {status: 200, body: []byte(`{"nodes":[{"id":1.5,"nodeKey":"k"}]}`)},
		"id-as-object":               {status: 200, body: []byte(`{"nodes":[{"id":{"x":1},"nodeKey":"k"}]}`)},
		"nodes-as-object":            {status: 200, body: []byte(`{"nodes":{"id":"1"}}`)},
		"deeply-nested":              {status: 200, body: []byte(strings.Repeat("[", 100000) + strings.Repeat("]", 100000))},
		"http-500":                   {status: 500, body: []byte(`{"nodes":[]}`)},
		"http-301":                   {status: 301, body: []byte(`{"nodes":[]}`)},
		"http-204":                   {status: 204, body: nil},
		"nil-response":               {nilRsp: true},
		"transport-error":            {err: errors.New("tls: handshake failure with secret material 0xdeadbeef")},
		"online-with-conflicting-map": {status: 200, body: []byte(`{"nodes":[{"id":"1","nodeKey":"1x"}]}`)},
	}
	for name, doer := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := headscaleClient(t, doer, 1024)
			if name == "online-with-conflicting-map" {
				var err error
				client, err = headscale.NewClient(headscale.Config{
					BaseURL: "https://headscale.example", APIKey: "fixture-api-key", HTTPClient: doer,
					ProviderAssociations: map[string]string{"1": "node-a", "1x": "node-b"},
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := client.ListNodes(context.Background(), observedAt)
			if err == nil {
				t.Fatalf("%s: accepted snapshot %#v", name, snapshot)
			}
			if strings.Contains(err.Error(), "deadbeef") || strings.Contains(err.Error(), "<html>") || strings.Contains(err.Error(), "garbage") {
				t.Fatalf("%s: error leaks response bytes: %v", name, err)
			}
		})
	}
}

// Invariant: the control plane's "online" flag is never upgraded to a
// verified path; unknown connection type is the strongest claim allowed, and
// unassociated peers are not authorized.
func TestHeadscaleOnlineFlagIsNotPathEvidence(t *testing.T) {
	t.Parallel()
	client := headscaleClient(t, scriptedDoer{status: 200, body: []byte(`{"nodes":[{"id":"1","nodeKey":"k","online":true},{"id":"2","nodeKey":"z","online":true,"ipAddresses":["100.64.0.1","100.64.0.1","not-an-ip"]}]}`)}, 0)
	snapshot, err := client.ListNodes(context.Background(), time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Peers) != 2 {
		t.Fatalf("peers = %#v", snapshot.Peers)
	}
	for _, peer := range snapshot.Peers {
		if peer.GetConnectionType().String() != "MESH_CONNECTION_TYPE_UNKNOWN" {
			t.Fatalf("online flag upgraded to %v", peer.GetConnectionType())
		}
		if len(peer.GetMeshAddresses()) != 0 {
			t.Fatalf("addresses emitted without IncludeAddresses: %v", peer.GetMeshAddresses())
		}
	}
	if snapshot.Peers[1].GetAuthorized() || snapshot.Peers[1].GetNodeId() != "" {
		t.Fatalf("unassociated peer authorized: %#v", snapshot.Peers[1])
	}
}

// Invariant: client construction refuses credential-bearing, non-HTTPS, or
// malformed endpoints and API keys with line breaks (header injection).
func TestHeadscaleNewClientRejectsHostileConfig(t *testing.T) {
	t.Parallel()
	bad := []headscale.Config{
		{BaseURL: "http://headscale.example", APIKey: "k"},
		{BaseURL: "https://user:pw@headscale.example", APIKey: "k"},
		{BaseURL: "https://headscale.example/?x=1", APIKey: "k"},
		{BaseURL: "https://headscale.example/#f", APIKey: "k"},
		{BaseURL: "https://headscale.example", APIKey: "k\r\nX-Injected: 1"},
		{BaseURL: "https://headscale.example", APIKey: " k"},
		{BaseURL: "https://headscale.example", APIKey: ""},
		{BaseURL: "https://headscale.example", APIKey: "k", MaximumResponseBytes: 17 << 20},
		{BaseURL: "https://headscale.example", APIKey: "k", ProviderAssociations: map[string]string{"": "node"}},
		{BaseURL: "https://headscale.example", APIKey: "k", ProviderAssociations: map[string]string{"1": strings.Repeat("n", 129)}},
	}
	for index, config := range bad {
		if _, err := headscale.NewClient(config); err == nil {
			t.Fatalf("config %d accepted: %#v", index, config)
		}
	}
	client := headscaleClient(t, scriptedDoer{status: 200, body: []byte(`{"nodes":[]}`)}, 0)
	if plan := client.DryRunListNodes(); strings.Contains(plan.URL, "fixture-api-key") {
		t.Fatal("dry run plan leaks the API key")
	}
	if _, err := client.ListNodes(context.Background(), time.Time{}); err == nil {
		t.Fatal("zero observation time accepted")
	}
}
