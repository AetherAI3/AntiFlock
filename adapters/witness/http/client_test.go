package http_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	witnesshttp "github.com/DBarr3/AntiFlock/adapters/witness/http"
	"github.com/DBarr3/AntiFlock/core/integration"
	"github.com/DBarr3/AntiFlock/core/integration/conformance"
	"github.com/DBarr3/AntiFlock/core/integration/fake"
)

// witnessHandler is a minimal server-side witness built on the fake, so the
// round trip exercises exactly the documented wire contract.
func witnessHandler(t *testing.T, backend *fake.Witness) nethttp.Handler {
	t.Helper()
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Method != nethttp.MethodPost {
			w.WriteHeader(nethttp.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
		if err != nil {
			w.WriteHeader(nethttp.StatusBadRequest)
			return
		}
		checkpoint, err := witnesshttp.DecodeCheckpoint(body)
		if err != nil {
			w.WriteHeader(nethttp.StatusUnprocessableEntity)
			return
		}
		receipt, err := backend.Submit(r.Context(), checkpoint)
		if errors.Is(err, integration.ErrSequenceRegression) {
			w.WriteHeader(nethttp.StatusConflict)
			return
		}
		if err != nil {
			w.WriteHeader(nethttp.StatusInternalServerError)
			return
		}
		encoded, _ := witnesshttp.EncodeReceipt(receipt)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
	})
}

func tlsServer(t *testing.T, handler nethttp.Handler) (*httptest.Server, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return server, caPEM
}

func checkpoint(sequence uint64) integration.Checkpoint {
	return integration.Checkpoint{
		DeploymentDigest: integration.DigestString("deployment"), AuditHeadDigest: integration.DigestString("head"),
		Sequence: sequence, IssuedAt: time.Date(2026, 8, 23, 12, 0, int(sequence), 0, time.UTC),
	}
}

func TestHTTPWitnessConformanceOverPinnedTLS(t *testing.T) {
	t.Parallel()
	conformance.RunExternalWitness(t, func(t *testing.T) (integration.ExternalWitness, ed25519.PublicKey) {
		backend, err := fake.NewWitness("remote-witness", nil)
		if err != nil {
			t.Fatal(err)
		}
		server, caPEM := tlsServer(t, witnessHandler(t, backend))
		client, err := witnesshttp.NewClient(witnesshttp.Config{URL: server.URL + "/witness", WitnessPublicKey: backend.PublicKey(), PinnedCAPEM: caPEM})
		if err != nil {
			t.Fatal(err)
		}
		return client, backend.PublicKey()
	})
}

func TestHTTPWitnessTransportGuards(t *testing.T) {
	t.Parallel()
	backend, _ := fake.NewWitness("remote-witness", nil)
	key := backend.PublicKey()
	for name, url := range map[string]string{
		"plaintext non-loopback":   "http://203.0.113.5/witness",
		"plaintext named host":     "http://witness.example/witness",
		"credentials in url":       "https://user:pass@witness.example/witness",
		"query":                    "https://witness.example/witness?x=1",
		"relative":                 "/witness",
		"plaintext loopback-alike": "http://127.0.0.1.example/witness",
	} {
		if _, err := witnesshttp.NewClient(witnesshttp.Config{URL: url, WitnessPublicKey: key}); !errors.Is(err, integration.ErrInvalidInput) {
			t.Errorf("%s: NewClient() = %v, want ErrInvalidInput", name, err)
		}
	}
	for _, url := range []string{"http://127.0.0.1:8080/witness", "http://localhost/witness", "http://[::1]/witness", "https://witness.example/witness"} {
		if _, err := witnesshttp.NewClient(witnesshttp.Config{URL: url, WitnessPublicKey: key}); err != nil {
			t.Errorf("%s: NewClient() = %v, want success", url, err)
		}
	}
	if _, err := witnesshttp.NewClient(witnesshttp.Config{URL: "https://witness.example/witness"}); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("missing witness key = %v, want ErrInvalidInput", err)
	}
	if _, err := witnesshttp.NewClient(witnesshttp.Config{URL: "https://witness.example/witness", WitnessPublicKey: key, BearerToken: "tok\nen"}); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("CRLF bearer = %v, want ErrInvalidInput", err)
	}
	if _, err := witnesshttp.NewClient(witnesshttp.Config{URL: "https://witness.example/witness", WitnessPublicKey: key, PinnedCAPEM: []byte("not pem")}); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("bad pinned CA = %v, want ErrInvalidInput", err)
	}
	client, err := witnesshttp.NewClient(witnesshttp.Config{URL: "https://witness.example/witness", WitnessPublicKey: key, BearerToken: "secret-bearer"})
	if err != nil {
		t.Fatal(err)
	}
	if plan := client.DryRun(); plan.Method != nethttp.MethodPost || plan.URL != "https://witness.example/witness" || strings.Contains(plan.URL, "secret") {
		t.Fatalf("DryRun() = %+v", plan)
	}
}

func TestHTTPWitnessRejectsUnpinnedAuthorityAndAcceptsLoopbackPlaintext(t *testing.T) {
	t.Parallel()
	backend, _ := fake.NewWitness("remote-witness", nil)
	server, _ := tlsServer(t, witnessHandler(t, backend))
	unpinned, err := witnesshttp.NewClient(witnesshttp.Config{URL: server.URL, WitnessPublicKey: backend.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unpinned.Submit(context.Background(), checkpoint(1)); !errors.Is(err, integration.ErrUnavailable) {
		t.Fatalf("self-signed server without pin = %v, want ErrUnavailable", err)
	}
	plain := httptest.NewServer(witnessHandler(t, backend))
	t.Cleanup(plain.Close)
	loopback, err := witnesshttp.NewClient(witnesshttp.Config{URL: plain.URL, WitnessPublicKey: backend.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := loopback.Submit(context.Background(), checkpoint(1))
	if err != nil {
		t.Fatalf("loopback plaintext = %v", err)
	}
	if err := integration.VerifyReceiptFor(receipt, checkpoint(1), backend.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPWitnessHostileResponses(t *testing.T) {
	t.Parallel()
	backend, _ := fake.NewWitness("remote-witness", nil)
	impostor, _ := fake.NewWitness("remote-witness", nil)
	type response struct {
		status int
		body   func() []byte
	}
	cases := map[string]struct {
		respond response
		want    error
	}{
		"foreign key": {response{200, func() []byte {
			receipt, _ := impostor.Sign(checkpoint(1))
			encoded, _ := witnesshttp.EncodeReceipt(receipt)
			return encoded
		}}, integration.ErrInvalidReceipt},
		"other checkpoint": {response{200, func() []byte {
			receipt, _ := backend.Sign(checkpoint(2))
			encoded, _ := witnesshttp.EncodeReceipt(receipt)
			return encoded
		}}, integration.ErrInvalidReceipt},
		"trailing data": {response{200, func() []byte {
			receipt, _ := backend.Sign(checkpoint(1))
			encoded, _ := witnesshttp.EncodeReceipt(receipt)
			return append(encoded, []byte(`{"extra":true}`)...)
		}}, integration.ErrInvalidReceipt},
		"unknown field": {response{200, func() []byte {
			receipt, _ := backend.Sign(checkpoint(1))
			encoded, _ := witnesshttp.EncodeReceipt(receipt)
			return append([]byte(`{"nodeId":"node-1",`), encoded[1:]...)
		}}, integration.ErrInvalidReceipt},
		"oversized": {response{200, func() []byte { return []byte(strings.Repeat(" ", witnesshttp.DefaultMaximumResponse+1)) }}, integration.ErrInvalidReceipt},
		"empty":     {response{200, func() []byte { return nil }}, integration.ErrInvalidReceipt},
		"server error": {response{503, func() []byte { return []byte("down") }}, integration.ErrUnavailable},
		"refused":      {response{409, func() []byte { return nil }}, integration.ErrInvalidInput},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server, caPEM := tlsServer(t, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
				w.WriteHeader(testCase.respond.status)
				_, _ = w.Write(testCase.respond.body())
			}))
			client, err := witnesshttp.NewClient(witnesshttp.Config{URL: server.URL, WitnessPublicKey: backend.PublicKey(), PinnedCAPEM: caPEM})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Submit(context.Background(), checkpoint(1)); !errors.Is(err, testCase.want) {
				t.Fatalf("Submit() = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestHTTPWitnessSendsBearerAndHonoursCancel(t *testing.T) {
	t.Parallel()
	backend, _ := fake.NewWitness("remote-witness", nil)
	var seenAuthorization atomic.Value
	server, caPEM := tlsServer(t, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		seenAuthorization.Store(r.Header.Get("Authorization"))
		witnessHandler(t, backend).ServeHTTP(w, r)
	}))
	client, err := witnesshttp.NewClient(witnesshttp.Config{URL: server.URL, WitnessPublicKey: backend.PublicKey(), PinnedCAPEM: caPEM, BearerToken: "witness-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(context.Background(), checkpoint(1)); err != nil {
		t.Fatal(err)
	}
	if got, _ := seenAuthorization.Load().(string); got != "Bearer witness-token" {
		t.Fatalf("Authorization = %q", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Submit(ctx, checkpoint(2)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Submit() = %v", err)
	}
}

func TestHTTPWitnessRegistryFactory(t *testing.T) {
	t.Parallel()
	backend, _ := fake.NewWitness("remote-witness", nil)
	server, caPEM := tlsServer(t, witnessHandler(t, backend))
	registry := integration.NewRegistry()
	if err := registry.Register("https", integration.KindExternalWitness, witnesshttp.Factory); err != nil {
		t.Fatal(err)
	}
	witness, err := registry.NewExternalWitness(context.Background(), "https", integration.Options{
		"url": server.URL, "witness-public-key": base64.RawURLEncoding.EncodeToString(backend.PublicKey()), "pinned-ca-pem": string(caPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Submit(context.Background(), checkpoint(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.NewExternalWitness(context.Background(), "https", integration.Options{"url": "http://203.0.113.5/", "witness-public-key": base64.RawURLEncoding.EncodeToString(backend.PublicKey())}); !errors.Is(err, integration.ErrInvalidInput) {
		t.Fatalf("factory accepted plaintext non-loopback: %v", err)
	}
}
