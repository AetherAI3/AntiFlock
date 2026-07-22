package headscale

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

func TestClientListsOnlyReadOnlyMinimizedNodeMetadata(t *testing.T) {
	t.Parallel()
	const secret = "headscale-test-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/node" {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("authorization header is missing")
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"nodes":[
  {"id":2,"nodeKey":"nodekey:two","ipAddresses":["100.64.0.2"],"online":true,"lastSeen":"2026-07-22T11:59:00Z"},
  {"id":"1","nodeKey":"nodekey:one","ipAddresses":["100.64.0.1"],"online":false}
]}`)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL: server.URL, APIKey: secret, HTTPClient: server.Client(),
		ProviderAssociations: map[string]string{"2": "exit-node"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dryRun := client.DryRunListNodes()
	if dryRun.Method != http.MethodGet || strings.Contains(fmt.Sprintf("%#v", dryRun), secret) {
		t.Fatalf("unsafe dry run = %#v", dryRun)
	}
	snapshot, err := client.ListNodes(context.Background(), time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Peers) != 2 {
		t.Fatalf("peers = %#v", snapshot.Peers)
	}
	peers := map[string]*antiflockv1.MeshPeerObservation{}
	for _, peer := range snapshot.Peers {
		peers[peer.ProviderPeerId] = peer
		if len(peer.MeshAddresses) != 0 {
			t.Fatal("Headscale addresses were exposed without opt-in")
		}
		if peer.LastHandshakeAt != nil || peer.ConnectionType == antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DIRECT || peer.ConnectionType == antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_RELAYED {
			t.Fatal("control-plane metadata was mislabeled as transport verification")
		}
	}
	if got := peers["2"]; got.NodeId != "exit-node" || !got.Authorized || got.ConnectionType != antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_UNKNOWN {
		t.Fatalf("online peer = %#v", got)
	}
	if got := peers["1"]; got.Authorized || got.ConnectionType != antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DISCONNECTED {
		t.Fatalf("offline peer = %#v", got)
	}
}

func TestClientRequiresTLSOutsideLoopbackAndDoesNotLeakProviderErrors(t *testing.T) {
	t.Parallel()
	if _, err := NewClient(Config{BaseURL: "http://192.0.2.1:8080", APIKey: "secret"}); err == nil {
		t.Fatal("non-loopback cleartext Headscale URL was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "provider-internal-secret", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, APIKey: "secret", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListNodes(context.Background(), time.Now().UTC())
	if err == nil || strings.Contains(err.Error(), "provider-internal-secret") {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestClientRejectsOversizedOrTrailingResponses(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"oversized": `{"nodes":[]}` + strings.Repeat(" ", 128),
		"trailing":  `{"nodes":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { fmt.Fprint(writer, body) }))
			defer server.Close()
			maximum := 1 << 20
			if name == "oversized" {
				maximum = 16
			}
			client, err := NewClient(Config{BaseURL: server.URL, APIKey: "secret", HTTPClient: server.Client(), MaximumResponseBytes: maximum})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListNodes(context.Background(), time.Now().UTC()); err == nil {
				t.Fatal("unsafe response was accepted")
			}
		})
	}
}

func TestClientRejectsAmbiguousOrNonCanonicalProviderIdentities(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"whitespace": `{"nodes":[{"id":" 1","nodeKey":"nodekey:one","online":true}]}`,
		"duplicate":  `{"nodes":[{"id":"1","nodeKey":"nodekey:one","online":true},{"id":1,"nodeKey":"nodekey:other","online":false}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { fmt.Fprint(writer, body) }))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL, APIKey: "secret", HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListNodes(context.Background(), time.Now().UTC()); err == nil {
				t.Fatal("ambiguous provider identity was accepted")
			}
		})
	}
	if _, err := NewClient(Config{
		BaseURL: "http://127.0.0.1", APIKey: "secret",
		ProviderAssociations: map[string]string{" nodekey:one": "node-one"},
	}); err == nil {
		t.Fatal("noncanonical provider association was accepted")
	}
}
