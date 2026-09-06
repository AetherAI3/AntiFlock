package fixtures

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/config"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/core/findings"
	"github.com/DBarr3/AntiFlock/core/identity"
	"github.com/DBarr3/AntiFlock/core/policy"
	"github.com/DBarr3/AntiFlock/core/posture"
	"github.com/DBarr3/AntiFlock/core/scrambler"
	"github.com/DBarr3/AntiFlock/core/server"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Fixed bearer credentials for the in-process Core. They never leave the test
// process and are not valid anywhere else.
const (
	OperatorToken = "fixture-antiflock-operator-token-with-more-than-thirty-two-bytes"
	SDKToken      = "fixture-antiflock-sdk-token-with-more-than-thirty-two-bytes"
	AgentToken    = "fixture-antiflock-agent-token-with-more-than-thirty-two-bytes"

	// CoreNodeID is the single active node enrolled in the fixture Core.
	CoreNodeID = "node-test"
	// CoreBootID is the boot id the fixture node signs events under.
	CoreBootID = "boot-test"
)

// CoreRuntime is a complete in-process Core: SQLite on a temp dir, a fresh
// deployment identity, one enrolled ACTIVE node whose signing key the test
// holds, and a Server with operator, SDK, and agent credentials.
type CoreRuntime struct {
	Server         *server.Server
	DB             *storage.DB
	Authority      *identity.Authority
	DeploymentID   string
	NodePrivateKey ed25519.PrivateKey
	NodePublicKey  ed25519.PublicKey
	// Now is the frozen server clock; Advance moves it.
	Now   time.Time
	clock *time.Time
}

// NewCoreRuntime builds the fixture Core. It mirrors core/server's own test
// runtime so adversarial suites exercise the production handler stack.
func NewCoreRuntime(tb testing.TB) *CoreRuntime {
	tb.Helper()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	directory := tb.TempDir()
	authority, err := identity.Ensure(filepath.Join(directory, "identity"), now)
	if err != nil {
		tb.Fatal(err)
	}
	database, err := storage.Open(context.Background(), filepath.Join(directory, "core.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = database.Close() })
	nodeSeed := sha256.Sum256([]byte("fixture-core-node-seed"))
	nodePrivateKey := ed25519.NewKeyFromSeed(nodeSeed[:])
	nodePublicKey := nodePrivateKey.Public().(ed25519.PublicKey)
	nodeCertificate, err := authority.IssueNodeCertificate(CoreNodeID, nodePublicKey, now)
	if err != nil {
		tb.Fatal(err)
	}
	capabilities := CoreCapabilities(CoreNodeID, now)
	capabilitiesJSON, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(capabilities)
	if err != nil {
		tb.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("fixture-enrollment-token"))
	if err := database.CreateEnrollmentToken(context.Background(), storage.EnrollmentTokenRecord{
		ID: "fixture-token", Hash: tokenHash[:], ScopeJSON: json.RawMessage(`{}`),
		CreatedByPrincipalID: "fixture", OperationID: "fixture-enrollment",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		tb.Fatal(err)
	}
	if err := database.EnrollNode(context.Background(), tokenHash[:], now, model.Node{
		ID: CoreNodeID, Name: "Fixture node", Type: "NODE_TYPE_AGENT", Platform: "linux", PlatformVersion: "fixture",
		Status: model.NodeActive, Capabilities: capabilitiesJSON, CapabilitiesVerification: "VERIFIED",
		PublicKey: nodePublicKey, CertificatePEM: nodeCertificate, EnrolledAt: now,
	}); err != nil {
		tb.Fatal(err)
	}
	auditService, err := audit.New(database, authority.AuditPrivateKey(), authority.AuditAnchorPath())
	if err != nil {
		tb.Fatal(err)
	}
	eventStore, err := events.New(database, authority)
	if err != nil {
		tb.Fatal(err)
	}
	configuration := config.Default()
	configuration.Storage.Path = filepath.Join(directory, "core.db")
	configuration.Identity.StateDirectory = filepath.Join(directory, "identity")
	policySeed := sha256.Sum256(append([]byte("fixture-policy\x00"), authority.AuditPrivateKey().Seed()...))
	policyCompiler, err := policy.NewCompiler(authority.Deployment.DeploymentID, "policy:fixture", ed25519.NewKeyFromSeed(policySeed[:]))
	if err != nil {
		tb.Fatal(err)
	}
	postureEngine, err := posture.New(configuration.Protection.TelemetryStaleAfter)
	if err != nil {
		tb.Fatal(err)
	}
	findingService, err := findings.New(authority.Deployment.DeploymentID)
	if err != nil {
		tb.Fatal(err)
	}
	scramblerPlanner, err := scrambler.New(5 * time.Minute)
	if err != nil {
		tb.Fatal(err)
	}
	clock := now
	coreServer, err := server.New(server.Options{
		Config: configuration, Database: database, Events: eventStore, Audit: auditService,
		Enrollment:     enrollment.New(database, authority, auditService, configuration.Identity.EnrollmentTokenTTL),
		DeploymentID:   authority.Deployment.DeploymentID,
		PolicyCompiler: policyCompiler, PostureEngine: postureEngine,
		Findings: findingService, Scrambler: scramblerPlanner,
		Credentials: []server.Credential{
			{Token: OperatorToken, PrincipalID: authority.Deployment.OperatorID, Scopes: []string{server.ScopeDashboardRead, server.ScopeOperatorMutate, server.ScopeEnrollmentAdmin, server.ScopeActionsAuthorize}},
			{Token: SDKToken, PrincipalID: "application:aether-code", ApplicationID: "aether-code", NodeID: CoreNodeID, Scopes: []string{server.ScopeActionsExecute}},
			{Token: AgentToken, PrincipalID: "node:" + CoreNodeID, NodeID: CoreNodeID, Scopes: []string{server.ScopeAgentIngest}},
		},
		AuthorizationKey: []byte(SDKToken),
		Version:          "fixture", Clock: func() time.Time { return clock },
	})
	if err != nil {
		tb.Fatal(err)
	}
	return &CoreRuntime{
		Server: coreServer, DB: database, Authority: authority, DeploymentID: authority.Deployment.DeploymentID,
		NodePrivateKey: nodePrivateKey, NodePublicKey: nodePublicKey, Now: now, clock: &clock,
	}
}

// Advance moves the frozen Core clock forward.
func (runtime *CoreRuntime) Advance(duration time.Duration) {
	runtime.Now = runtime.Now.Add(duration)
	*runtime.clock = runtime.Now
}

// Raw sends an arbitrary body with explicit headers through the production
// handler stack and returns the recorded response.
func (runtime *CoreRuntime) Raw(method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	runtime.Server.Handler().ServeHTTP(response, request)
	return response
}

// JSON sends raw JSON bytes as application/json with the given bearer token.
func (runtime *CoreRuntime) JSON(method, path string, body []byte, token string) *httptest.ResponseRecorder {
	headers := map[string]string{"Content-Type": "application/json", "X-AntiFlock-Client": "fixture"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return runtime.Raw(method, path, body, headers)
}

// CoreCapabilities is the VERIFIED manifest recorded for the fixture node.
func CoreCapabilities(nodeID string, now time.Time) *antiflockv1.CapabilityManifest {
	capability := func(key string, operations ...antiflockv1.CapabilityOperation) *antiflockv1.Capability {
		return &antiflockv1.Capability{
			Key: key, Operations: operations,
			SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
			ObservedAt:   timestamppb.New(now),
		}
	}
	return &antiflockv1.CapabilityManifest{
		NodeId: nodeID, Revision: 1, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		Capabilities: []*antiflockv1.Capability{
			capability("firewall.egress.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
			capability("mesh.path.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
			capability("network.route.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
			capability("dns.protected.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		},
	}
}

// SignedEvent builds and signs one DETECTED route-observation event from the
// fixture node at the given sequence, signed at signedAt.
func (runtime *CoreRuntime) SignedEvent(tb testing.TB, id string, sequence uint64, signedAt time.Time) model.EventEnvelope {
	tb.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.RouteObservation{
		RouteId: "route-" + id, Destination: "0.0.0.0/0", Gateway: "192.0.2.1", InterfaceId: "if-" + id,
		DefaultRoute: true, ObservedAt: timestamppb.New(runtime.Now),
	})
	if err != nil {
		tb.Fatal(err)
	}
	event := model.EventEnvelope{
		ID: id, SchemaVersion: "antiflock.event/v1", DeploymentID: runtime.DeploymentID, NodeID: CoreNodeID,
		Kind: "network.route_changed", ObservedAt: runtime.Now, Sequence: sequence, BootID: CoreBootID,
		Classification: model.EvidenceDetected, Confidence: 1, Sensitivity: model.SensitivityInternal,
		PayloadTypeURL: "type.googleapis.com/antiflock.v1.RouteObservation", Payload: payload,
	}
	if err := events.SignAt(&event, CoreNodeID, runtime.NodePrivateKey, signedAt); err != nil {
		tb.Fatal(err)
	}
	return event
}

// BatchJSON encodes signed events as a SubmitEventBatchRequest body.
func BatchJSON(tb testing.TB, batchID string, envelopes ...model.EventEnvelope) []byte {
	tb.Helper()
	wires := make([]*antiflockv1.EventEnvelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		wire, err := model.EventToProto(envelope)
		if err != nil {
			tb.Fatal(err)
		}
		wires = append(wires, wire)
	}
	body, err := protojson.Marshal(&antiflockv1.SubmitEventBatchRequest{Batch: &antiflockv1.EventBatch{
		BatchId: batchID, NodeId: CoreNodeID, Events: wires,
	}})
	if err != nil {
		tb.Fatal(err)
	}
	return body
}

// RejectedReasons extracts the rejected reason codes from a batch ack body.
func RejectedReasons(tb testing.TB, body []byte) []string {
	tb.Helper()
	var ack antiflockv1.SubmitEventBatchResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &ack); err != nil {
		tb.Fatalf("decode batch ack %q: %v", body, err)
	}
	reasons := make([]string, 0)
	for _, rejected := range ack.GetAck().GetRejected() {
		reasons = append(reasons, rejected.GetReasonCode())
	}
	return reasons
}
