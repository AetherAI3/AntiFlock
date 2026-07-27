package ingest_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/ingest"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

func TestSubmitUsesAgentScopeAndFailsOnRejection(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/events/batch" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) {
			t.Fatal("agent credential was not scoped to the request")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(response, "{\"ack\":{\"batchId\":\"batch-1\",\"highestContiguousSequence\":\"1\",\"rejected\":[]}}")
	}))
	defer server.Close()

	client, err := ingest.NewClient(ingest.Config{Endpoint: server.URL, Token: strings.Repeat("a", 32), HTTP: &http.Client{Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := client.Submit(context.Background(), batch())
	if err != nil || ack.GetHighestContiguousSequence() != 1 {
		t.Fatalf("ack=%#v err=%v", ack, err)
	}
}

func TestClientRejectsInsecureRemoteCore(t *testing.T) {
	t.Parallel()
	if _, err := ingest.NewClient(ingest.Config{Endpoint: "http://192.0.2.44:8787", Token: strings.Repeat("a", 32)}); err == nil {
		t.Fatal("insecure non-loopback endpoint was accepted")
	}
}

func batch() *antiflockv1.SubmitEventBatchRequest {
	return &antiflockv1.SubmitEventBatchRequest{Batch: &antiflockv1.EventBatch{
		BatchId: "batch-1", NodeId: "node-1", Events: []*antiflockv1.EventEnvelope{{Id: "event-1", NodeId: "node-1", BootId: "boot-1"}},
	}}
}

func TestClientAllowsCertificateOnlyHTTPSIngest(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Fatal("certificate-only ingest unexpectedly sent a bearer token")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(response, "{\"ack\":{\"batchId\":\"batch-1\",\"highestContiguousSequence\":\"1\",\"rejected\":[]}}")
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = 10 * time.Second
	client, err := ingest.NewClient(ingest.Config{Endpoint: server.URL, HTTP: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(context.Background(), batch()); err != nil {
		t.Fatal(err)
	}
}
