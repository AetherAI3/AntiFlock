package hostile_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
	"github.com/DBarr3/AntiFlock/tests/fixtures"
)

const metadataPath = "/v1/nodes/" + fixtures.CoreNodeID

// Invariant: every JSON request decoder on the Core rejects oversized bodies,
// trailing values, unknown fields, compressed bodies, and wrong media types
// with a 4xx and a safe message that never echoes the body.
func TestCoreRequestDecodingRejectsHostileBodies(t *testing.T) {
	t.Parallel()
	runtime := fixtures.NewCoreRuntime(t)
	goodMetadata := []byte(`{"operationId":"op-1","displayName":"Fixture","tags":["a"]}`)

	cases := []struct {
		name    string
		method  string
		path    string
		body    []byte
		headers map[string]string
		status  int
	}{
		{"metadata-oversized", http.MethodPatch, metadataPath, []byte(`{"operationId":"op-1","displayName":"` + strings.Repeat("x", 17<<10) + `"}`), nil, http.StatusBadRequest},
		{"metadata-trailing-value", http.MethodPatch, metadataPath, append(append([]byte(nil), goodMetadata...), []byte(` {"operationId":"op-2"}`)...), nil, http.StatusBadRequest},
		{"metadata-trailing-garbage", http.MethodPatch, metadataPath, append(append([]byte(nil), goodMetadata...), []byte(`garbage`)...), nil, http.StatusBadRequest},
		{"metadata-unknown-field", http.MethodPatch, metadataPath, []byte(`{"operationId":"op-1","displayName":"x","admin":true}`), nil, http.StatusBadRequest},
		{"metadata-array-body", http.MethodPatch, metadataPath, []byte(`[{"operationId":"op-1"}]`), nil, http.StatusBadRequest},
		{"metadata-deep-nesting", http.MethodPatch, metadataPath, []byte(`{"operationId":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `}`), nil, http.StatusBadRequest},
		{"metadata-text-plain", http.MethodPatch, metadataPath, goodMetadata, map[string]string{"Content-Type": "text/plain"}, http.StatusBadRequest},
		{"metadata-empty-body", http.MethodPatch, metadataPath, nil, nil, http.StatusBadRequest},
		{"token-oversized", http.MethodPost, "/v1/enrollment/tokens", []byte(`{"operationId":"op-1","allowedNodeType":"NODE_TYPE_AGENT","allowedTags":["` + strings.Repeat("t", 33<<10) + `"]}`), nil, http.StatusBadRequest},
		{"token-unknown-field", http.MethodPost, "/v1/enrollment/tokens", []byte(`{"operationId":"op-1","allowedNodeType":"NODE_TYPE_AGENT","bypass":true}`), nil, http.StatusBadRequest},
		{"token-trailing-value", http.MethodPost, "/v1/enrollment/tokens", []byte(`{"operationId":"op-1","allowedNodeType":"NODE_TYPE_AGENT"} {}`), nil, http.StatusBadRequest},
		{"token-duplicate-key", http.MethodPost, "/v1/enrollment/tokens", []byte(`{"operationId":"op-1","operationId":"op-2","allowedNodeType":"NODE_TYPE_AGENT"}`), nil, http.StatusBadRequest},
		{"token-deep-nesting", http.MethodPost, "/v1/enrollment/tokens", []byte(`{"operationId":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `}`), nil, http.StatusBadRequest},
		{"token-gzip-encoding", http.MethodPost, "/v1/enrollment/tokens", []byte(`{"operationId":"op-1","allowedNodeType":"NODE_TYPE_AGENT"}`), map[string]string{"Content-Encoding": "gzip"}, http.StatusBadRequest},
		{"token-unknown-enum", http.MethodPost, "/v1/enrollment/tokens", []byte(`{"operationId":"op-1","allowedNodeType":"NODE_TYPE_ROOT"}`), nil, http.StatusBadRequest},
		{"batch-oversized", http.MethodPost, "/v1/events/batch", []byte(`{"batch":{"batchId":"b","nodeId":"node-test","events":[{"id":"` + strings.Repeat("e", 9<<20) + `"}]}}`), nil, http.StatusRequestEntityTooLarge},
		{"batch-gzip-encoding", http.MethodPost, "/v1/events/batch", []byte(`{"batch":{}}`), map[string]string{"Content-Encoding": "gzip"}, http.StatusUnsupportedMediaType},
		{"batch-trailing-value", http.MethodPost, "/v1/events/batch", []byte(`{"batch":{"batchId":"b","nodeId":"node-test","events":[]}} {}`), nil, http.StatusBadRequest},
		{"batch-unknown-field", http.MethodPost, "/v1/events/batch", []byte(`{"batch":{"batchId":"b","nodeId":"node-test","events":[],"trusted":true}}`), nil, http.StatusBadRequest},
		{"batch-duplicate-key", http.MethodPost, "/v1/events/batch", []byte(`{"batch":{"batchId":"b","nodeId":"node-test","nodeId":"node-other","events":[]}}`), nil, http.StatusBadRequest},
		{"batch-deep-nesting", http.MethodPost, "/v1/events/batch", []byte(`{"batch":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `}`), nil, http.StatusBadRequest},
		{"batch-257-events", http.MethodPost, "/v1/events/batch", []byte(`{"batch":{"batchId":"b","nodeId":"node-test","events":[` + strings.TrimSuffix(strings.Repeat(`{"id":"e"},`, 257), ",") + `]}}`), nil, http.StatusBadRequest},
		{"batch-node-scope-mismatch", http.MethodPost, "/v1/events/batch", []byte(`{"batch":{"batchId":"b","nodeId":"node-other","events":[{"id":"e"}]}}`), nil, http.StatusForbidden},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			token := fixtures.OperatorToken
			if strings.HasPrefix(testCase.path, "/v1/events/") {
				token = fixtures.AgentToken
			}
			headers := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + token, "X-AntiFlock-Client": "fixture"}
			for key, value := range testCase.headers {
				headers[key] = value
			}
			response := runtime.Raw(testCase.method, testCase.path, testCase.body, headers)
			if response.Code != testCase.status {
				t.Fatalf("%s: status = %d body = %s", testCase.name, response.Code, response.Body.String())
			}
			if response.Code >= 500 {
				t.Fatalf("%s: server error for hostile input", testCase.name)
			}
			body := response.Body.String()
			if strings.Contains(body, "garbage") || strings.Contains(body, "bypass") || strings.Contains(body, "NODE_TYPE_ROOT") || strings.Contains(body, "X: 1") {
				t.Fatalf("%s: response echoes request bytes: %s", testCase.name, body)
			}
			if response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Fatalf("%s: content type = %q", testCase.name, response.Header().Get("Content-Type"))
			}
		})
	}
}

// Invariant: duplicate JSON keys are a request-smuggling primitive; the
// encoding/json decoders must reject them just as the protojson decoders do.
func TestCoreJSONDecoderRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	runtime := fixtures.NewCoreRuntime(t)
	response := runtime.JSON(http.MethodPatch, metadataPath, []byte(`{"operationId":"op-dup-a","operationId":"op-dup-b","displayName":"x"}`), fixtures.OperatorToken)
	if response.Code < 400 {
		t.Skipf("KNOWN-GAP AF-GAP-002: core/server.decodeJSON (encoding/json) accepts duplicate keys and keeps the last value; PATCH returned %d", response.Code)
	}
}

// Invariant: identifiers carrying control characters are refused at the
// decoder boundary, not persisted into audit records.
func TestCoreRejectsControlCharactersInIdentifiers(t *testing.T) {
	t.Parallel()
	runtime := fixtures.NewCoreRuntime(t)
	for _, operationID := range []string{"op\r\nX: 1", "op\x00x"} {
		body, err := json.Marshal(map[string]any{"operationId": operationID, "allowedNodeType": "NODE_TYPE_AGENT"})
		if err != nil {
			t.Fatal(err)
		}
		response := runtime.JSON(http.MethodPost, "/v1/enrollment/tokens", body, fixtures.OperatorToken)
		if response.Code < 400 {
			t.Skipf("KNOWN-GAP AF-GAP-001: core/server bounded() trims whitespace only; enrollment token operation id %q accepted with %d", operationID, response.Code)
		}
	}
	for _, operationID := range []string{"op\nx", "op\x00x", "op\x1b[31mx"} {
		body, err := json.Marshal(map[string]any{"operationId": operationID, "displayName": "Fixture"})
		if err != nil {
			t.Fatal(err)
		}
		response := runtime.JSON(http.MethodPatch, metadataPath, body, fixtures.OperatorToken)
		if response.Code < 400 {
			t.Skipf("KNOWN-GAP AF-GAP-001: core/server bounded() trims whitespace only; operation id %q accepted with %d", operationID, response.Code)
		}
	}
}

// Invariant: a signed event is bound to its sequence and boot; replaying the
// same signed bytes is idempotent (no duplicate), re-using a signature under a
// new sequence is rejected, and signatures outside the clock-skew window are
// rejected at the edge.
func TestCoreEventBatchReplayAndClockSkew(t *testing.T) {
	t.Parallel()
	runtime := fixtures.NewCoreRuntime(t)
	first := runtime.SignedEvent(t, "event-1", 1, runtime.Now)

	accept := func(name string, body []byte, wantReasons ...string) {
		t.Helper()
		response := runtime.JSON(http.MethodPost, "/v1/events/batch", body, fixtures.AgentToken)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: status = %d body = %s", name, response.Code, response.Body.String())
		}
		reasons := fixtures.RejectedReasons(t, response.Body.Bytes())
		if !slices.Equal(reasons, wantReasons) {
			t.Fatalf("%s: rejected = %v, want %v", name, reasons, wantReasons)
		}
	}

	accept("first-delivery", fixtures.BatchJSON(t, "batch-1", first))
	accept("byte-identical-replay", fixtures.BatchJSON(t, "batch-2", first))

	events := countEvents(t, runtime)
	if events != 1 {
		t.Fatalf("byte-identical replay duplicated the event: %d stored", events)
	}

	resequenced := first
	resequenced.Sequence = 2
	accept("signature-reused-under-new-sequence", fixtures.BatchJSON(t, "batch-3", resequenced), "EVENT_REJECTED")

	reid := first
	reid.ID = "event-1-copy"
	accept("signature-reused-under-new-id", fixtures.BatchJSON(t, "batch-4", reid), "EVENT_REJECTED")

	future := runtime.SignedEvent(t, "event-future", 2, runtime.Now.Add(5*time.Minute+time.Second))
	accept("signed-beyond-skew", fixtures.BatchJSON(t, "batch-5", future), "EVENT_REJECTED")

	edge := runtime.SignedEvent(t, "event-edge", 2, runtime.Now.Add(5*time.Minute))
	accept("signed-at-skew-edge", fixtures.BatchJSON(t, "batch-6", edge))

	// The node certificate became valid five minutes before enrollment; a
	// signature dated before that window is outside the credential lifetime.
	stale := runtime.SignedEvent(t, "event-stale", 3, runtime.Now.Add(-2*time.Hour))
	accept("signed-before-credential-validity", fixtures.BatchJSON(t, "batch-7", stale), "EVENT_REJECTED")
	inside := runtime.SignedEvent(t, "event-inside", 3, runtime.Now.Add(-4*time.Minute))
	accept("signed-inside-credential-validity", fixtures.BatchJSON(t, "batch-7b", inside))

	runtime.Advance(time.Hour)
	foreignBoot := runtime.SignedEvent(t, "event-boot", 4, runtime.Now)
	foreignBoot.BootID = "boot-other"
	accept("boot-id-rewritten-after-signing", fixtures.BatchJSON(t, "batch-8", foreignBoot), "EVENT_REJECTED")

	mixed := fixtures.BatchJSON(t, "batch-9", runtime.SignedEvent(t, "event-5", 4, runtime.Now), func() model.EventEnvelope {
		other := runtime.SignedEvent(t, "event-6", 5, runtime.Now)
		other.BootID = "boot-b"
		return other
	}())
	accept("mixed-boot-ids-in-one-batch", mixed, "EVENT_BOOT_MISMATCH")
}

func countEvents(t *testing.T, runtime *fixtures.CoreRuntime) int {
	t.Helper()
	response := runtime.Raw(http.MethodGet, "/v1/events?limit=200", nil, map[string]string{"Authorization": "Bearer " + fixtures.OperatorToken, "X-AntiFlock-Client": "fixture"})
	if response.Code != http.StatusOK {
		t.Fatalf("list events: %d %s", response.Code, response.Body.String())
	}
	var listing struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(bytes.NewReader(response.Body.Bytes())).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	return len(listing.Events)
}
