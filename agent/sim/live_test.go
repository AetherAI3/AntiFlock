package sim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	coreevents "github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testLiveOperatorToken = "operator-token-for-live-simulator-test-000000000000"
	testLiveAgentToken    = "agent-token-for-live-simulator-test-000000000000000"
	testLiveSDKToken      = "sdk-token-for-live-simulator-test-00000000000000000"
)

type fakeLiveCore struct {
	t             *testing.T
	mu            sync.Mutex
	server        *httptest.Server
	nodeID        string
	applicationID string
	enrollmentKey ed25519.PublicKey
	enrolled      bool
	approved      bool
	tokenCalls    int
	enrollCalls   int
	approveCalls  int
	events        []model.EventEnvelope
	bootID        string
	highest       uint64
	posture       string
	postureClass  string
	actionID      string
	operationID   string
	decision      string
	audits        map[string][]byte
	auditCalls    int
}

func newFakeLiveCore(t *testing.T, nodeID, applicationID string) *fakeLiveCore {
	t.Helper()
	core := &fakeLiveCore{t: t, nodeID: nodeID, applicationID: applicationID, posture: "UNKNOWN", audits: make(map[string][]byte)}
	core.server = httptest.NewServer(http.HandlerFunc(core.serveHTTP))
	t.Cleanup(core.server.Close)
	return core
}

func (core *fakeLiveCore) serveHTTP(response http.ResponseWriter, request *http.Request) {
	core.mu.Lock()
	defer core.mu.Unlock()
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/v1/overview":
		if !core.requireToken(response, request, testLiveOperatorToken) {
			return
		}
		writeTestJSON(response, http.StatusOK, map[string]any{"deploymentName": "deployment-test"})
	case request.Method == http.MethodGet && request.URL.Path == "/v1/nodes":
		if !core.requireToken(response, request, testLiveOperatorToken) {
			return
		}
		nodes := []any{}
		if core.approved {
			nodes = append(nodes, map[string]any{"id": core.nodeID, "state": "online"})
		}
		writeTestJSON(response, http.StatusOK, map[string]any{"nodes": nodes})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/enrollment/tokens":
		if !core.requireToken(response, request, testLiveOperatorToken) {
			return
		}
		var input antiflockv1.CreateEnrollmentTokenRequest
		decodeTestProto(core.t, request.Body, &input)
		if input.GetAllowedNodeType() != antiflockv1.NodeType_NODE_TYPE_AGENT || input.GetOperationId() == "" {
			http.Error(response, "invalid", http.StatusBadRequest)
			return
		}
		core.tokenCalls++
		raw := bytes.Repeat([]byte{0x42}, 64)
		writeTestProto(response, http.StatusCreated, &antiflockv1.CreateEnrollmentTokenResponse{
			Token:      &antiflockv1.EnrollmentTokenDescriptor{Id: "token-test"},
			TokenValue: "af_enroll_v1." + base64.RawURLEncoding.EncodeToString(raw),
		})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/enrollment/nodes":
		var input antiflockv1.EnrollNodeRequest
		decodeTestProto(core.t, request.Body, &input)
		if input.GetRequestedNodeId() != core.nodeID || input.GetCapabilities() == nil || input.GetCapabilities().GetNodeId() != "" || input.GetCapabilities().GetSignature() != nil {
			http.Error(response, "invalid", http.StatusBadRequest)
			return
		}
		proof, err := enrollment.ProofMessage(&input)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(input.GetPublicKey()), proof, input.GetProofOfPossession()) {
			http.Error(response, "invalid proof", http.StatusBadRequest)
			return
		}
		core.enrollmentKey = append(ed25519.PublicKey(nil), input.GetPublicKey()...)
		core.enrolled = true
		core.enrollCalls++
		writeTestProto(response, http.StatusAccepted, &antiflockv1.EnrollNodeResponse{Enrollment: &antiflockv1.EnrollmentRequest{
			Id: "enrollment-test", Status: antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_PENDING, ProposedNodeId: core.nodeID,
		}})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/enrollment/enrollment-test/approve":
		if !core.requireToken(response, request, testLiveOperatorToken) {
			return
		}
		var input antiflockv1.ApproveEnrollmentRequest
		decodeTestProto(core.t, request.Body, &input)
		if !core.enrolled || input.GetEnrollmentId() != "enrollment-test" || input.GetReasonCode() != "OPERATOR_APPROVED" {
			http.Error(response, "invalid", http.StatusBadRequest)
			return
		}
		core.approved = true
		core.approveCalls++
		writeTestProto(response, http.StatusOK, &antiflockv1.ApproveEnrollmentResponse{Node: &antiflockv1.Node{
			Metadata: &antiflockv1.ResourceMetadata{Id: core.nodeID}, Status: antiflockv1.NodeStatus_NODE_STATUS_ACTIVE,
		}})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/events/batch":
		if !core.requireToken(response, request, testLiveAgentToken) {
			return
		}
		core.handleBatch(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/events":
		if !core.requireToken(response, request, testLiveOperatorToken) {
			return
		}
		writeTestJSON(response, http.StatusOK, map[string]any{"events": core.events, "nextCursor": ""})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/posture/report":
		if !core.requireToken(response, request, testLiveAgentToken) {
			return
		}
		core.handlePosture(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/posture":
		if !core.requireToken(response, request, testLiveOperatorToken) {
			return
		}
		writeTestJSON(response, http.StatusOK, map[string]any{
			"state": core.posture, "nodeId": core.nodeID, "evidenceClass": core.postureClass, "policyRevision": 7,
		})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/actions/evaluate":
		if !core.requireToken(response, request, testLiveSDKToken) {
			return
		}
		core.handleEvaluate(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/actions":
		if !core.requireToken(response, request, testLiveOperatorToken) {
			return
		}
		actions := []any{}
		if core.actionID != "" {
			actions = append(actions, map[string]any{"actionId": core.actionID, "nodeId": core.nodeID, "decision": core.decision})
		}
		writeTestJSON(response, http.StatusOK, map[string]any{"actions": actions})
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/wait"):
		if !core.requireToken(response, request, testLiveSDKToken) {
			return
		}
		writeTestJSON(response, http.StatusOK, map[string]any{"restored": core.posture == "PROTECTED", "snapshot": map[string]any{}})
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/audit"):
		if !core.requireToken(response, request, testLiveSDKToken) {
			return
		}
		core.handleAudit(response, request)
	default:
		http.Error(response, "not found", http.StatusNotFound)
	}
}

func (core *fakeLiveCore) requireToken(response http.ResponseWriter, request *http.Request, token string) bool {
	if request.Header.Get("Authorization") != "Bearer "+token {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (core *fakeLiveCore) handleBatch(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.SubmitEventBatchRequest
	decodeTestProto(core.t, request.Body, &input)
	batch := input.GetBatch()
	if !core.approved || batch.GetNodeId() != core.nodeID || len(batch.GetEvents()) == 0 {
		http.Error(response, "invalid", http.StatusBadRequest)
		return
	}
	for _, wire := range batch.GetEvents() {
		event, err := model.EventFromProto(wire)
		if err != nil || coreevents.VerifySource(event, core.enrollmentKey) != nil || model.ValidateEvidenceAt(event, time.Now().UTC()) != nil {
			http.Error(response, "invalid signed event", http.StatusBadRequest)
			return
		}
		if core.bootID != wire.GetBootId() {
			core.bootID, core.highest = wire.GetBootId(), 0
		}
		if wire.GetSequence() != core.highest+1 {
			http.Error(response, "sequence gap", http.StatusConflict)
			return
		}
		core.highest = wire.GetSequence()
		event.ReceivedAt = time.Now().UTC()
		core.events = append(core.events, event)
	}
	writeTestProto(response, http.StatusOK, &antiflockv1.SubmitEventBatchResponse{Ack: &antiflockv1.EventBatchAck{
		BatchId: batch.GetBatchId(), HighestContiguousSequence: core.highest, ReceivedAt: timestamppb.Now(),
	}})
}

func (core *fakeLiveCore) handlePosture(response http.ResponseWriter, request *http.Request) {
	var input struct {
		NodeID               string   `json:"nodeId"`
		State                string   `json:"state"`
		VerificationEventIDs []string `json:"verificationEventIds"`
	}
	decodeTestJSON(core.t, request.Body, &input)
	if input.NodeID != core.nodeID {
		http.Error(response, "wrong node", http.StatusForbidden)
		return
	}
	if input.State == "PROTECTED" {
		foundMesh, foundDNS := false, false
		for _, id := range input.VerificationEventIDs {
			for _, event := range core.events {
				if event.ID != id || event.Classification != model.EvidenceVerified || model.ValidateEvidenceAt(event, time.Now().UTC()) != nil {
					continue
				}
				switch event.Kind {
				case "mesh.path_changed":
					var payload antiflockv1.MeshPathObservation
					if proto.Unmarshal(event.Payload, &payload) == nil && payload.GetTunnelHealthy() && payload.GetApprovedExitActive() {
						foundMesh = true
					}
				case "network.dns_changed":
					var payload antiflockv1.DnsObservation
					if proto.Unmarshal(event.Payload, &payload) == nil && payload.GetPathVerified() {
						foundDNS = true
					}
				}
			}
		}
		if !foundMesh || !foundDNS {
			http.Error(response, "missing durable verification", http.StatusBadRequest)
			return
		}
		core.postureClass = "VERIFIED"
	} else {
		core.postureClass = "DETECTED"
	}
	core.posture = input.State
	writeTestJSON(response, http.StatusAccepted, map[string]any{"accepted": true})
}

func (core *fakeLiveCore) handleEvaluate(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Action struct {
			ID            string `json:"id"`
			NodeID        string `json:"nodeId"`
			ApplicationID string `json:"applicationId"`
			OperationID   string `json:"operationId"`
		} `json:"action"`
	}
	decodeTestJSON(core.t, request.Body, &input)
	if input.Action.NodeID != core.nodeID || input.Action.ApplicationID != core.applicationID {
		http.Error(response, "scope mismatch", http.StatusForbidden)
		return
	}
	status := http.StatusCreated
	if core.actionID == "" {
		core.actionID, core.operationID = input.Action.ID, input.Action.OperationID
	} else {
		status = http.StatusOK
		if core.actionID != input.Action.ID || core.operationID != input.Action.OperationID {
			http.Error(response, "operation conflict", http.StatusConflict)
			return
		}
	}
	core.decision = "HOLD"
	if core.posture == "PROTECTED" {
		core.decision = "ALLOW"
	}
	writeTestJSON(response, status, map[string]any{
		"decision": core.decision, "actionId": core.actionID, "reasonCodes": []string{"AF-SIMULATION-TEST"},
		"protection": map[string]any{"observedAt": time.Now().UTC().Format(time.RFC3339Nano), "policyRevision": 7},
		"audit":      map[string]any{"policyRevision": 7},
	})
}

func (core *fakeLiveCore) handleAudit(response http.ResponseWriter, request *http.Request) {
	content, err := io.ReadAll(io.LimitReader(request.Body, 64<<10))
	if err != nil {
		core.t.Fatal(err)
	}
	var input liveAuditEvent
	if err := json.Unmarshal(content, &input); err != nil {
		http.Error(response, "invalid", http.StatusBadRequest)
		return
	}
	canonical, _ := json.Marshal(input)
	if existing, exists := core.audits[input.EventID]; exists {
		if !bytes.Equal(existing, canonical) {
			http.Error(response, "audit replay conflict", http.StatusConflict)
			return
		}
		core.auditCalls++
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if input.ActionID != core.actionID || input.RequestID != core.actionID || input.TraceID != core.operationID || input.Decision != core.decision || input.PolicyRevision != 7 {
		http.Error(response, "audit conflict", http.StatusConflict)
		return
	}
	core.audits[input.EventID] = canonical
	core.auditCalls++
	response.WriteHeader(http.StatusNoContent)
}

func writeTestJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeTestProto(response http.ResponseWriter, status int, value proto.Message) {
	content, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(value)
	if err != nil {
		panic(err)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(content)
}

func decodeTestJSON(t *testing.T, reader io.Reader, output any) {
	t.Helper()
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(output); err != nil {
		t.Errorf("decode request: %v", err)
	}
}

func decodeTestProto(t *testing.T, reader io.Reader, output proto.Message) {
	t.Helper()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
		return
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, output); err != nil {
		t.Errorf("decode protobuf request: %v", err)
	}
}

func TestLiveCoffeeShopBootstrapsSignsPersistsReleasesAndVerifies(t *testing.T) {
	nodeID, applicationID := "sim-agent-node", "sim-application"
	core := newFakeLiveCore(t, nodeID, applicationID)
	stateDirectory := t.TempDir()
	config := LiveConfig{
		CoreURL: core.server.URL, OperatorToken: testLiveOperatorToken,
		AgentToken: testLiveAgentToken, SDKToken: testLiveSDKToken,
		NodeID: nodeID, ApplicationID: applicationID, StateDirectory: stateDirectory, DemoMode: true,
	}
	result, err := RunLiveCoffeeShop(context.Background(), config, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.InitialDecision != "HOLD" || result.FinalDecision != "ALLOW" ||
		len(result.ContextEventIDs) != 2 || len(result.VerificationEventIDs) != 2 || len(result.AuditEventIDs) != 5 {
		t.Fatalf("unexpected live result: %#v", result)
	}
	core.mu.Lock()
	if !core.enrolled || !core.approved || core.tokenCalls != 1 || core.enrollCalls != 1 || core.approveCalls != 1 ||
		len(core.events) != 4 || len(core.audits) != 5 || core.auditCalls != 10 {
		core.mu.Unlock()
		t.Fatalf("unexpected Core state after verified flow")
	}
	contextSafe := false
	for _, event := range core.events {
		if event.Kind != "network.wifi_changed" {
			continue
		}
		var wifi antiflockv1.WifiObservation
		contextSafe = event.Classification == model.EvidenceDetected && proto.Unmarshal(event.Payload, &wifi) == nil &&
			wifi.GetSsid() == "" && wifi.GetBssidHash() == "" && wifi.GetTrust() == antiflockv1.NetworkTrust_NETWORK_TRUST_UNTRUSTED &&
			wifi.GetSecurity() == antiflockv1.WifiSecurity_WIFI_SECURITY_OPEN
	}
	core.mu.Unlock()
	if !contextSafe {
		t.Fatal("coffee-shop context exposed or fabricated a Wi-Fi identifier")
	}
	if info, err := os.Stat(stateDirectory); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory permissions = %v, %v", info, err)
	}
	if info, err := os.Stat(stateDirectory + string(os.PathSeparator) + "node.seed"); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("node key permissions = %v, %v", info, err)
	}

	streamContext, cancel := context.WithCancel(context.Background())
	statuses := []string{}
	err = RunLiveStream(streamContext, config, time.Hour, func(event LiveStreamEvent) error {
		statuses = append(statuses, event.Status)
		if event.Status == "heartbeat" {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(statuses) != "[ready heartbeat]" {
		t.Fatalf("stream statuses = %v", statuses)
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.tokenCalls != 1 || core.enrollCalls != 1 || core.approveCalls != 1 || len(core.events) != 9 || core.posture != "PROTECTED" {
		t.Fatalf("stream was not idempotent: token=%d enroll=%d approve=%d events=%d", core.tokenCalls, core.enrollCalls, core.approveCalls, len(core.events))
	}
}
