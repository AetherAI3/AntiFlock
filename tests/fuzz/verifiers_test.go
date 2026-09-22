package fuzz_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/enforcement"
	agentruntime "github.com/DBarr3/AntiFlock/agent/runtime"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/core/policy"
	"github.com/DBarr3/AntiFlock/internal/model"
	"github.com/DBarr3/AntiFlock/tests/fixtures"
	"google.golang.org/protobuf/proto"
)

type emptyInterfaces struct{}

func (emptyInterfaces) Interfaces() ([]net.Interface, error)    { return nil, nil }
func (emptyInterfaces) Addrs(net.Interface) ([]net.Addr, error) { return nil, nil }

// FuzzVerifyPlan: the only plan bytes that verify under the plan key are the
// genuine signed plan (modulo the unsigned Status field).
func FuzzVerifyPlan(f *testing.F) {
	fixture := fixtures.NewDeterministicPlanFixture(f)
	genuine, err := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.Plan)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(genuine)
	f.Add(genuine[:len(genuine)-1])
	f.Add(append([]byte(nil), genuine[1:]...))
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x01, 0x78})
	f.Fuzz(func(t *testing.T, wire []byte) {
		var plan antiflockv1.Plan
		if err := proto.Unmarshal(wire, &plan); err != nil {
			return
		}
		err := policy.VerifyPlan(&plan, fixture.PlanPublicKey, fixture.Now)
		if err != nil {
			return
		}
		canonical := fixtures.ClonePlan(&plan)
		canonical.Status = fixture.Plan.Status
		if !proto.Equal(canonical, fixture.Plan) {
			t.Fatalf("a non-genuine plan verified: %v", &plan)
		}
		if err := model.RejectUnknownFields(&plan); err != nil {
			t.Fatalf("genuine plan verified while carrying unknown fields: %v", err)
		}
	})
}

// FuzzVerifyExecutionResult: only a result signed by the node key verifies,
// and a verified result never carries unknown fields.
func FuzzVerifyExecutionResult(f *testing.F) {
	fixture := fixtures.NewDeterministicPlanFixture(f)
	driver := &fixtures.RecordingDriver{ObservedAt: fixture.Now}
	enforcer := fixture.Enforcer(f, driver, nil, fixtures.EnforcerOptions{})
	result, err := enforcer.Apply(context.Background(), fixture.Plan)
	if err != nil {
		f.Fatal(err)
	}
	genuine, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(genuine)
	f.Add(genuine[:len(genuine)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		var candidate antiflockv1.PlanExecutionResult
		if err := proto.Unmarshal(wire, &candidate); err != nil {
			return
		}
		if err := enforcement.VerifyExecutionResult(&candidate, fixture.NodePublicKey); err != nil {
			return
		}
		if !proto.Equal(&candidate, result) {
			t.Fatalf("a non-genuine execution result verified: %v", &candidate)
		}
	})
}

// FuzzVerifySource: event envelopes decoded from arbitrary wire bytes never
// verify under the node key unless they are the genuine signed event.
func FuzzVerifySource(f *testing.F) {
	_, nodeKey := fixtures.PlanKeys()
	publicKey := nodeKey.Public().(ed25519.PublicKey)
	signedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	payload, _ := proto.Marshal(&antiflockv1.RouteObservation{RouteId: "r", Destination: "0.0.0.0/0"})
	event := model.EventEnvelope{
		ID: "event-1", SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment", NodeID: "node",
		Kind: "network.route_changed", ObservedAt: signedAt, Sequence: 1, BootID: "boot",
		Classification: model.EvidenceDetected, Confidence: 1, Sensitivity: model.SensitivityInternal,
		PayloadTypeURL: "type.googleapis.com/antiflock.v1.RouteObservation", Payload: payload,
	}
	if err := events.SignAt(&event, "node", nodeKey, signedAt); err != nil {
		f.Fatal(err)
	}
	genuineWire, err := model.EventToProto(event)
	if err != nil {
		f.Fatal(err)
	}
	genuine, err := proto.MarshalOptions{Deterministic: true}.Marshal(genuineWire)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(genuine)
	f.Add(genuine[:len(genuine)-8])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		var decoded antiflockv1.EventEnvelope
		if err := proto.Unmarshal(wire, &decoded); err != nil {
			return
		}
		candidate, err := model.EventFromProto(&decoded)
		if err != nil {
			return
		}
		if err := events.VerifySource(candidate, publicKey); err != nil {
			return
		}
		canonical, err := events.CanonicalSourceEnvelope(candidate)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := events.CanonicalSourceEnvelope(event)
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != string(expected) {
			t.Fatalf("a non-genuine event verified: %v", candidate)
		}
	})
}

// FuzzQueueFile: arbitrary queue.json content never panics the loader, and a
// file the loader accepts is one Batch and Inspect can read.
func FuzzQueueFile(f *testing.F) {
	wire, _ := proto.Marshal(&antiflockv1.EventEnvelope{Id: "e1", Sequence: 1, NodeId: "node", BootId: "boot"})
	encoded := base64.RawStdEncoding.EncodeToString(wire)
	seeds := []string{
		`{"schemaVersion":"antiflock.agent-queue/v1","nodeId":"node","lastSequence":1,"events":[{"priority":1,"wire":"` + encoded + `"}]}`,
		`{"schemaVersion":"antiflock.agent-queue/v1","nodeId":"node","lastSequence":0,"events":[]}`,
		`{"schemaVersion":"antiflock.agent-queue/v1","nodeId":"node","lastSequence":1,"events":[{"priority":1,"wire":"!!!!"}]}`,
		`{"schemaVersion":"antiflock.agent-queue/v2","nodeId":"node","lastSequence":0,"events":[]}`,
		`{}`, `[]`, ``, `{"schemaVersion":"antiflock.agent-queue/v1","nodeId":"node","lastSequence":0,"events":[]} {}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		if runtime.GOOS == "windows" {
			t.Skip("ENV-UNAVAILABLE: queue file modes are POSIX permission bits")
		}
		directory := filepath.Join(t.TempDir(), "queue")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "queue.json"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		queue, err := agentruntime.OpenQueue(directory, "node")
		if err != nil {
			if _, inspectErr := agentruntime.InspectQueue(directory, "node"); inspectErr == nil {
				t.Fatal("InspectQueue accepted a file OpenQueue rejected")
			}
			return
		}
		defer queue.Close()
		status, err := agentruntime.InspectQueue(directory, "node")
		if err != nil {
			t.Fatalf("InspectQueue rejected a file OpenQueue accepted: %v", err)
		}
		if status.RetainedEvents > status.MaximumEvents {
			t.Fatalf("retained %d exceeds maximum %d", status.RetainedEvents, status.MaximumEvents)
		}
		batch, err := queue.Batch(context.Background(), 256)
		if err != nil {
			return
		}
		for index, event := range batch {
			if event.GetNodeId() != "node" || event.GetSequence() == 0 || event.GetId() == "" {
				t.Fatalf("batch returned a non-node-scoped event: %v", event)
			}
			if index > 0 && batch[index-1].GetSequence() >= event.GetSequence() {
				t.Fatal("batch not in sequence order")
			}
		}
	})
}

// FuzzCoreRequestDecoding: arbitrary bodies on the Core's JSON decoders never
// produce a 5xx, never echo the body, and always answer with JSON.
func FuzzCoreRequestDecoding(f *testing.F) {
	core := fixtures.NewCoreRuntime(f)
	routes := []struct {
		method, path, token string
	}{
		{http.MethodPatch, "/v1/nodes/" + fixtures.CoreNodeID, fixtures.OperatorToken},
		{http.MethodPost, "/v1/enrollment/tokens", fixtures.OperatorToken},
		{http.MethodPost, "/v1/events/batch", fixtures.AgentToken},
		{http.MethodPost, "/v1/actions/evaluate", fixtures.SDKToken},
		{http.MethodPost, "/v1/posture/report", fixtures.AgentToken},
		{http.MethodPost, "/v1/policies/validate", fixtures.OperatorToken},
		{http.MethodPost, "/v1/watchdogs", fixtures.OperatorToken},
	}
	seeds := []string{
		`{}`, `[]`, `null`, ``, `{"operationId":"op-1","displayName":"x"}`,
		`{"batch":{"batchId":"b","nodeId":"node-test","events":[]}}`,
		`{"action":{"id":"a","applicationId":"aether-code","nodeId":"node-test","actionType":"git.push","destinations":["github.com"],"dataClass":"repository-source","sensitivity":"SENSITIVITY_OPERATOR_PRIVATE","deadline":"2026-07-22T12:05:00Z","operationId":"op"}}`,
		`{"operationId":"op-1","allowedNodeType":"NODE_TYPE_AGENT"}`,
		`{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}`, "{\"operationId\":\"op\x00\"}", `{"x":1}{"y":2}`,
	}
	for index, seed := range seeds {
		f.Add([]byte(seed), uint8(index%len(routes)))
	}
	f.Fuzz(func(t *testing.T, body []byte, route uint8) {
		target := routes[int(route)%len(routes)]
		response := core.JSON(target.method, target.path, body, target.token)
		// 501 is the Core's deliberate CAPABILITY_UNAVAILABLE answer for a surface
		// this fixture does not wire (nano registry); every other 5xx is a crash.
		if response.Code >= 500 && response.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s: 5xx %d for body %q", target.method, target.path, response.Code, body)
		}
		if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s %s: content type %q", target.method, target.path, response.Header().Get("Content-Type"))
		}
		if len(body) >= 16 && response.Code >= 400 && strings.Contains(response.Body.String(), string(body)) {
			t.Fatalf("%s %s: error response echoes the request body", target.method, target.path)
		}
	})
}
