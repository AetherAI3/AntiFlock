package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testOperatorToken = "test-antiflock-operator-token-with-more-than-thirty-two-bytes"
	testSDKToken      = "test-antiflock-sdk-token-with-more-than-thirty-two-bytes"
	testAgentToken    = "test-antiflock-agent-token-with-more-than-thirty-two-bytes"
)

type testRuntime struct {
	server       *Server
	db           *storage.DB
	now          time.Time
	clockNow     *time.Time
	deploymentID string
}

func newTestRuntime(t *testing.T) *testRuntime {
	t.Helper()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	authority, err := identity.Ensure(filepath.Join(directory, "identity"), now)
	if err != nil {
		t.Fatal(err)
	}
	database, err := storage.Open(context.Background(), filepath.Join(directory, "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	nodePublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeCertificate, err := authority.IssueNodeCertificate("node-test", nodePublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := testCapabilities("node-test", now)
	capabilitiesJSON, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("server-test-enrollment-token"))
	if err := database.CreateEnrollmentToken(context.Background(), storage.EnrollmentTokenRecord{
		ID: "server-test-token", Hash: tokenHash[:], ScopeJSON: json.RawMessage(`{}`),
		CreatedByPrincipalID: "server-test", OperationID: "server-test-enrollment",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.EnrollNode(context.Background(), tokenHash[:], now, model.Node{
		ID: "node-test", Name: "Test node", Type: "NODE_TYPE_AGENT", Platform: "linux", PlatformVersion: "test",
		Status: model.NodeActive, Capabilities: capabilitiesJSON, CapabilitiesVerification: "VERIFIED",
		PublicKey: nodePublicKey, CertificatePEM: nodeCertificate, EnrolledAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	auditService, err := audit.New(database, authority.AuditPrivateKey(), authority.AuditAnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	eventStore, err := events.New(database, authority)
	if err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	configuration.Storage.Path = filepath.Join(directory, "core.db")
	configuration.Identity.StateDirectory = filepath.Join(directory, "identity")
	policySeed := sha256.Sum256(append([]byte("server-test-policy\x00"), authority.AuditPrivateKey().Seed()...))
	policyCompiler, err := policy.NewCompiler(authority.Deployment.DeploymentID, "policy:test", ed25519.NewKeyFromSeed(policySeed[:]))
	if err != nil {
		t.Fatal(err)
	}
	postureEngine, err := posture.New(configuration.Protection.TelemetryStaleAfter)
	if err != nil {
		t.Fatal(err)
	}
	findingService, err := findings.New(authority.Deployment.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	scramblerPlanner, err := scrambler.New(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clockNow := now
	coreServer, err := New(Options{
		Config: configuration, Database: database, Events: eventStore, Audit: auditService,
		Enrollment:     enrollment.New(database, authority, auditService, configuration.Identity.EnrollmentTokenTTL),
		DeploymentID:   authority.Deployment.DeploymentID,
		PolicyCompiler: policyCompiler, PostureEngine: postureEngine,
		Findings: findingService, Scrambler: scramblerPlanner,
		Credentials: []Credential{
			{Token: testOperatorToken, PrincipalID: authority.Deployment.OperatorID, Scopes: []string{ScopeDashboardRead, ScopeOperatorMutate, ScopeEnrollmentAdmin, ScopeActionsAuthorize}},
			{Token: testSDKToken, PrincipalID: "application:aether-code", ApplicationID: "aether-code", NodeID: "node-test", Scopes: []string{ScopeActionsExecute}},
			{Token: testAgentToken, PrincipalID: "node:node-test", NodeID: "node-test", Scopes: []string{ScopeAgentIngest}},
		},
		AuthorizationKey: []byte(testSDKToken),
		Version:          "test", Clock: func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testRuntime{server: coreServer, db: database, now: now, clockNow: &clockNow, deploymentID: authority.Deployment.DeploymentID}
}

func (runtime *testRuntime) advance(duration time.Duration) {
	runtime.now = runtime.now.Add(duration)
	*runtime.clockNow = runtime.now
}

func (runtime *testRuntime) request(t *testing.T, method, path string, body any, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+testTokenFor(method, path))
		request.Header.Set("X-AntiFlock-Client", "server-test")
	}
	response := httptest.NewRecorder()
	runtime.server.Handler().ServeHTTP(response, request)
	return response
}

func testTokenFor(method, path string) string {
	switch {
	case method == http.MethodPost && strings.HasSuffix(path, "/authorize"):
		return testOperatorToken
	case strings.HasPrefix(path, "/v1/actions/"):
		return testSDKToken
	case path == "/v1/events/batch" || path == "/v1/telemetry/events:submit" || path == "/v1/posture/report":
		return testAgentToken
	default:
		return testOperatorToken
	}
}

func actionBody(now time.Time, id, operationID string) map[string]any {
	return map[string]any{"action": map[string]any{
		"id": id, "applicationId": "aether-code", "nodeId": "node-test",
		"actionType": "git.push", "destinations": []string{"github.com"},
		"dataClass": "repository-source", "sensitivity": "SENSITIVITY_OPERATOR_PRIVATE",
		"deadline": now.Add(5 * time.Minute).Format(time.RFC3339Nano), "operationId": operationID,
	}}
}

func lifecycleBody(eventID, lifecycle, actionID, operationID, decision string, policyRevision any, occurredAt time.Time) map[string]any {
	return map[string]any{
		"eventId": eventID, "lifecycle": lifecycle, "occurredAt": occurredAt.Format(time.RFC3339Nano),
		"actionId": actionID, "requestId": actionID, "decision": decision, "traceId": operationID,
		"policyRevision": policyRevision, "reasonCodes": []string{"AF-SDK-LIFECYCLE-TEST"}, "details": map[string]any{},
	}
}

func postureBody(runtime *testRuntime, state string, observedAt time.Time, policyRevision uint64, eventIDs []string) map[string]any {
	protected := state == "PROTECTED"
	return map[string]any{
		"nodeId": "node-test", "state": state,
		"observedAt":   observedAt.Format(time.RFC3339Nano),
		"validUntil":   observedAt.Add(time.Minute).Format(time.RFC3339Nano),
		"networkTrust": "UNTRUSTED", "meshConnected": protected,
		"approvedExitActive": protected, "dnsProtected": protected, "routeProtected": protected,
		"reasonCodes": []string{}, "policyRevision": policyRevision, "verificationEventIds": eventIDs,
	}
}

func validPolicyBody() map[string]any {
	return map[string]any{"profile": map[string]any{
		"metadata":   map[string]any{"id": "coffee-shop-guard", "revision": 7},
		"apiVersion": "antiflock.policy/v1", "mode": "PROTECTION_MODE_GUARD",
		"mesh": map[string]any{"required": true, "provider": "headscale"},
		"egress": map[string]any{
			"mode": "EGRESS_MODE_TRUSTED_EXIT", "failMode": "FAIL_MODE_CLOSED",
			"allowedExitNodeIds": []string{"exit-test"}, "recoveryDestinations": []string{"core.internal"},
		},
		"dns": map[string]any{
			"mode": "DNS_MODE_PROTECTED", "allowedResolvers": []string{"100.100.100.100"}, "requirePathVerification": true,
		},
		"networks": map[string]any{"requireMeshOnUntrusted": true, "blockOpenWifiWithoutMesh": true},
		"actions": []any{map[string]any{
			"applicationIds": []string{"aether-code"}, "dataClasses": []string{"repository-source"}, "requireProtectedState": true,
		}},
		"telemetry": map[string]any{"flowMetadata": true, "payloadCapture": false, "retentionDays": 14},
	}}
}

func testCapabilities(nodeID string, now time.Time) *antiflockv1.CapabilityManifest {
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

func appendProtectedVerificationEvents(t *testing.T, runtime *testRuntime) []string {
	return appendProtectedVerificationEventsWithDNSBinding(t, runtime, "mesh0", "path-test")
}

func appendProtectedVerificationEventsWithDNSBinding(t *testing.T, runtime *testRuntime, interfaceID, meshPathID string) []string {
	return appendProtectedVerificationEventsWithProvenance(t, runtime, interfaceID, meshPathID, false)
}

func appendProtectedVerificationEventsWithProvenance(t *testing.T, runtime *testRuntime, interfaceID, meshPathID string, simulation bool) []string {
	t.Helper()
	meshPayload, err := proto.Marshal(&antiflockv1.MeshPathObservation{
		PathId: "path-test", Provider: "test-mesh", SourceNodeId: "node-test", DestinationNodeId: "exit-test",
		ConnectionType: antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DIRECT,
		ExitNodeId:     "exit-test", ApprovedExitActive: true, TunnelHealthy: true,
		ObservedAt: timestamppb.New(runtime.now),
	})
	if err != nil {
		t.Fatal(err)
	}
	dnsPayload, err := proto.Marshal(&antiflockv1.DnsObservation{
		ResolverAddresses: []string{"100.100.100.100"}, Source: "agent", PathVerified: true,
		EgressInterfaceId: interfaceID, MeshPathId: meshPathID, ObservedAt: timestamppb.New(runtime.now),
	})
	if err != nil {
		t.Fatal(err)
	}
	routePayload, err := proto.Marshal(&antiflockv1.RouteObservation{
		RouteId: "protected-default", Destination: "0.0.0.0/0", InterfaceId: "mesh0",
		DefaultRoute: true, PolicyRoute: true, ObservedAt: timestamppb.New(runtime.now),
	})
	if err != nil {
		t.Fatal(err)
	}
	egressPayload, err := proto.Marshal(&antiflockv1.FlowObservation{
		FlowId: "protected-egress-probe", Remote: &antiflockv1.FlowEndpoint{Hostname: "github.com", Port: 443},
		Protocol:  antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP,
		Direction: antiflockv1.FlowDirection_FLOW_DIRECTION_OUTBOUND, StartedAt: timestamppb.New(runtime.now),
		EgressInterfaceId: "mesh0", MeshPathId: "path-test",
		Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_INTERNAL,
	})
	if err != nil {
		t.Fatal(err)
	}
	inputs := []struct {
		id, kind, typeURL string
		payload           []byte
	}{
		{"event-mesh-verified", "mesh.path_changed", "type.googleapis.com/antiflock.v1.MeshPathObservation", meshPayload},
		{"event-dns-verified", "network.dns_changed", "type.googleapis.com/antiflock.v1.DnsObservation", dnsPayload},
		{"event-route-protection-verified", "network.route_changed", "type.googleapis.com/antiflock.v1.RouteObservation", routePayload},
		{"event-egress-protection-verified", "flow.started", "type.googleapis.com/antiflock.v1.FlowObservation", egressPayload},
	}
	result := make([]string, 0, len(inputs))
	for index, input := range inputs {
		payloadDigest := sha256.Sum256(input.payload)
		evidenceDigest := sha256.Sum256([]byte(input.id + ":evidence"))
		signedDigest := sha256.Sum256([]byte(input.id + ":signed"))
		verifiedAt, expiresAt := runtime.now, runtime.now.Add(time.Minute)
		attributes := map[string]string{}
		if simulation {
			attributes = map[string]string{"simulation": "true", "methodId": "antiflock.simulation.test.v1"}
		}
		event := model.EventEnvelope{
			ID: input.id, SchemaVersion: "antiflock.event/v1", DeploymentID: runtime.deploymentID, NodeID: "node-test",
			Kind: input.kind, ObservedAt: runtime.now, ReceivedAt: runtime.now, Sequence: uint64(index + 1), BootID: "boot-test",
			Classification: model.EvidenceVerified, Confidence: 1, Sensitivity: model.SensitivityInternal,
			PayloadTypeURL: input.typeURL, Payload: input.payload,
			PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: payloadDigest[:]},
			Evidence: []model.EvidenceReference{{
				ID: input.id + ":evidence", Role: "SUPPORTING", Classification: model.EvidenceVerified,
				SourceType: "LOCAL_SENSOR", Source: "test sensor", ObservedAt: runtime.now,
				LastVerifiedAt: &verifiedAt, ExpiresAt: &expiresAt, Confidence: 1,
				Sensitivity: model.SensitivityInternal, Explanation: "Deterministic verified test measurement.",
				LocationPrecision: "WITHHELD",
				Attributes:        attributes,
				Integrity:         model.IntegrityDigest{Algorithm: "sha256", Digest: evidenceDigest[:]},
			}},
			SourceSignature: model.Signature{
				KeyID: "node-test", Algorithm: "ED25519", Value: make([]byte, 64), SignedAt: runtime.now,
				Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
				SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: signedDigest[:]},
			},
		}
		if inserted, appendErr := runtime.db.AppendEvent(context.Background(), event); appendErr != nil || !inserted {
			t.Fatalf("append verification event %s: inserted=%v err=%v", input.id, inserted, appendErr)
		}
		if _, getErr := runtime.db.GetEvent(context.Background(), input.id); getErr != nil {
			t.Fatalf("read verification event %s: %v", input.id, getErr)
		}
		result = append(result, input.id)
	}
	return result
}

func appendVerifiedPathEvent(t *testing.T, runtime *testRuntime, id, kind, typeURL string, sequence uint64, message proto.Message) {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	evidenceDigest := sha256.Sum256([]byte(id + ":evidence"))
	signedDigest := sha256.Sum256([]byte(id + ":signed"))
	verifiedAt, expiresAt := runtime.now, runtime.now.Add(time.Minute)
	event := model.EventEnvelope{
		ID: id, SchemaVersion: "antiflock.event/v1", DeploymentID: runtime.deploymentID, NodeID: "node-test",
		Kind: kind, ObservedAt: runtime.now, ReceivedAt: runtime.now, Sequence: sequence, BootID: "boot-test",
		Classification: model.EvidenceVerified, Confidence: 1, Sensitivity: model.SensitivityInternal,
		PayloadTypeURL: typeURL, Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: payloadDigest[:]},
		Evidence: []model.EvidenceReference{{
			ID: id + ":evidence", Role: "SUPPORTING", Classification: model.EvidenceVerified,
			SourceType: "LOCAL_SENSOR", Source: "test sensor", ObservedAt: runtime.now,
			LastVerifiedAt: &verifiedAt, ExpiresAt: &expiresAt, Confidence: 1,
			Sensitivity: model.SensitivityInternal, Explanation: "Deterministic verified path measurement.",
			LocationPrecision: "WITHHELD",
			Integrity:         model.IntegrityDigest{Algorithm: "sha256", Digest: evidenceDigest[:]},
		}},
		SourceSignature: model.Signature{
			KeyID: "node-test", Algorithm: "ED25519", Value: make([]byte, 64), SignedAt: runtime.now,
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: signedDigest[:]},
		},
	}
	if inserted, appendErr := runtime.db.AppendEvent(context.Background(), event); appendErr != nil || !inserted {
		t.Fatalf("append path event %s: inserted=%v err=%v", id, inserted, appendErr)
	}
}

func decodeObject(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response %d %q: %v", response.Code, response.Body.String(), err)
	}
	return result
}

func TestAuthenticationHealthAndStrictJSON(t *testing.T) {
	runtime := newTestRuntime(t)
	health := runtime.request(t, http.MethodGet, "/healthz", nil, false)
	if health.Code != http.StatusOK || health.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health response = %d headers=%v", health.Code, health.Header())
	}
	unauthenticated := runtime.request(t, http.MethodGet, "/v1/overview", nil, false)
	if unauthenticated.Code != http.StatusUnauthorized || !strings.Contains(unauthenticated.Body.String(), "UNAUTHENTICATED") {
		t.Fatalf("unauthenticated response = %d %s", unauthenticated.Code, unauthenticated.Body.String())
	}
	authenticated := runtime.request(t, http.MethodGet, "/v1/overview", nil, true)
	if authenticated.Code != http.StatusOK || !strings.Contains(authenticated.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("authenticated response = %d %s", authenticated.Code, authenticated.Body.String())
	}

	body := actionBody(runtime.now, "action-strict", "operation-strict")
	body["unknown"] = true
	unknown := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "unknown field") {
		t.Fatalf("unknown-field response = %d %s", unknown.Code, unknown.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/actions/evaluate", strings.NewReader(`{"action":{}}`))
	request.Header.Set("Authorization", "Bearer "+testSDKToken)
	response := httptest.NewRecorder()
	runtime.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing content type response = %d", response.Code)
	}
	if _, err := newTokenAuthenticator([]Credential{{Token: "short", PrincipalID: "short", Scopes: []string{ScopeDashboardRead}}}, nil); err == nil {
		t.Fatal("short bearer token was accepted")
	}
}

func TestOverviewCapturesSimulationModeAtServerStartup(t *testing.T) {
	t.Setenv("ANTIFLOCK_DEMO_MODE", "true")
	runtime := newTestRuntime(t)
	t.Setenv("ANTIFLOCK_DEMO_MODE", "false")

	overview := decodeObject(t, runtime.request(t, http.MethodGet, "/v1/overview", nil, true))
	if overview["simulation"] != true {
		t.Fatalf("overview simulation provenance = %#v", overview["simulation"])
	}
}

func TestSimulationEvidenceRequiresDemoModeAndPropagatesToDecisions(t *testing.T) {
	t.Run("non-demo Core rejects simulation evidence", func(t *testing.T) {
		t.Setenv("ANTIFLOCK_DEMO_MODE", "false")
		runtime := newTestRuntime(t)
		eventIDs := appendProtectedVerificationEventsWithProvenance(t, runtime, "mesh0", "path-test", true)
		response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("non-demo simulation posture = %d %s", response.Code, response.Body.String())
		}
		overviewResponse := runtime.request(t, http.MethodGet, "/v1/overview", nil, true)
		overview := decodeObject(t, overviewResponse)
		if overviewResponse.Code != http.StatusOK || overview["currentExit"] != "Unknown" || overview["dnsState"] != "UNKNOWN" || overview["exitVerified"] != false {
			t.Fatalf("non-demo projection did not quarantine simulation facts: %d %#v", overviewResponse.Code, overview)
		}
	})

	t.Run("demo Core labels posture and action decision as simulation", func(t *testing.T) {
		t.Setenv("ANTIFLOCK_DEMO_MODE", "true")
		runtime := newTestRuntime(t)
		eventIDs := appendProtectedVerificationEventsWithProvenance(t, runtime, "mesh0", "path-test", true)
		response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true)
		if response.Code != http.StatusAccepted {
			t.Fatalf("demo simulation posture = %d %s", response.Code, response.Body.String())
		}
		posture := decodeObject(t, runtime.request(t, http.MethodGet, "/v1/posture", nil, true))
		if posture["state"] != "PROTECTED" || posture["evidenceProvenance"] != "SIMULATION" {
			t.Fatalf("simulation posture projection = %#v", posture)
		}
		decisionResponse := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", actionBody(runtime.now, "simulation-action", "simulation-operation"), true)
		decision := decodeObject(t, decisionResponse)
		protection, _ := decision["protection"].(map[string]any)
		if decisionResponse.Code != http.StatusCreated || decision["decision"] != "ALLOW" || protection["evidenceProvenance"] != "SIMULATION" {
			t.Fatalf("simulation action decision = %d %#v", decisionResponse.Code, decision)
		}
		overview := decodeObject(t, runtime.request(t, http.MethodGet, "/v1/overview", nil, true))
		if overview["simulation"] != true || overview["evidenceProvenance"] != "SIMULATION" {
			t.Fatalf("simulation overview = %#v", overview)
		}
	})
}

func TestNonDemoCoreRejectsSimulationOnlyEnrollmentBeforeMutation(t *testing.T) {
	t.Setenv("ANTIFLOCK_DEMO_MODE", "false")
	runtime := newTestRuntime(t)
	response := runtime.request(t, http.MethodPost, "/v1/enrollment/nodes", map[string]any{
		"tokenValue": "not-consumed", "requestId": "simulation-enrollment",
		"displayName": "Simulator", "nodeType": "NODE_TYPE_AGENT", "platform": "linux", "platformVersion": "simulation",
		"keyAlgorithm": "ed25519", "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "requestedNodeId": "sim-node",
		"capabilities": map[string]any{"revision": 1, "capabilities": []any{map[string]any{
			"key": "mesh.path.verify", "implementation": "antiflock-sim", "constraints": []string{"simulation-only"},
		}}},
	}, false)
	if response.Code != http.StatusPreconditionFailed || !strings.Contains(response.Body.String(), "SIMULATION_MODE_REQUIRED") {
		t.Fatalf("simulation enrollment = %d %s", response.Code, response.Body.String())
	}
}

func TestCredentialRolesAndBindingsDenyConfusedDeputyCalls(t *testing.T) {
	runtime := newTestRuntime(t)
	for _, test := range []struct {
		path  string
		body  any
		token string
	}{
		{"/v1/actions/evaluate", actionBody(runtime.now, "denied-action", "denied-operation"), testOperatorToken},
		{"/v1/actions/denied/authorize", map[string]any{}, testSDKToken},
		{"/v1/actions/denied/audit", map[string]any{}, testOperatorToken},
		{"/v1/enrollment/tokens", map[string]any{"allowedNodeType": "NODE_TYPE_AGENT", "operationId": "denied-token"}, testSDKToken},
		{"/v1/events/batch", map[string]any{"batch": map[string]any{"batchId": "batch-denied", "nodeId": "node-test", "events": []any{}}}, testOperatorToken},
	} {
		request := httptest.NewRequest(http.MethodPost, test.path, mustJSONReader(t, test.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		runtime.server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "FORBIDDEN") {
			t.Fatalf("confused deputy %s = %d %s", test.path, response.Code, response.Body.String())
		}
	}

	wrongNode := actionBody(runtime.now, "wrong-node-action", "wrong-node-operation")
	wrongNode["action"].(map[string]any)["nodeId"] = "node-other"
	request := httptest.NewRequest(http.MethodPost, "/v1/actions/evaluate", mustJSONReader(t, wrongNode))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testSDKToken)
	response := httptest.NewRecorder()
	runtime.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("node-bound SDK accepted foreign node: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/overview", nil)
	request.Header.Add("Authorization", "Bearer "+testOperatorToken)
	request.Header.Add("Authorization", "Bearer "+testOperatorToken)
	response = httptest.NewRecorder()
	runtime.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate authorization headers accepted: %d", response.Code)
	}
}

func TestCredentialExpiryAndNodeMTLSBinding(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authenticator, err := newTokenAuthenticator([]Credential{{
		Token: testAgentToken, PrincipalID: "node:node-test", NodeID: "node-test",
		Scopes: []string{ScopeAgentIngest}, ExpiresAt: now.Add(-time.Second), RequireMTLS: true,
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events/batch", nil)
	request.Header.Set("Authorization", "Bearer "+testAgentToken)
	if _, ok := authenticator.authenticate(request); ok {
		t.Fatal("expired credential authenticated")
	}
	value := principal{ID: "node:node-test", NodeID: "node-test", RequireMTLS: true}
	if value.validatePeerCertificate(request, "deployment-test") {
		t.Fatal("node principal accepted a missing TLS client certificate")
	}
	leaf := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "node-test", Organization: []string{"deployment-test"}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if !value.validatePeerCertificate(request, "deployment-test") {
		t.Fatal("matching verified node certificate was rejected")
	}
	leaf.Subject.CommonName = "node-other"
	if value.validatePeerCertificate(request, "deployment-test") {
		t.Fatal("foreign node certificate was accepted")
	}
	if _, err := newTokenAuthenticator([]Credential{
		{Token: testAgentToken, PrincipalID: "one", Scopes: []string{ScopeAgentIngest}},
		{Token: testAgentToken, PrincipalID: "two", Scopes: []string{ScopeAgentIngest}},
	}, nil); err == nil {
		t.Fatal("duplicate bearer token was accepted")
	}
}

func mustJSONReader(t *testing.T, value any) io.Reader {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(encoded)
}

func TestActionHoldIdempotencyWaitAndRelease(t *testing.T) {
	runtime := newTestRuntime(t)
	body := actionBody(runtime.now, "action-release", "operation-release")
	first := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
	if first.Code != http.StatusCreated {
		t.Fatalf("first evaluate = %d %s", first.Code, first.Body.String())
	}
	firstObject := decodeObject(t, first)
	if firstObject["decision"] != "HOLD" || firstObject["actionId"] != "action-release" {
		t.Fatalf("unexpected hold decision: %#v", firstObject)
	}
	headAfterFirst, err := runtime.db.GetAuditHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	retry := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
	if retry.Code != http.StatusOK || decodeObject(t, retry)["decision"] != "HOLD" {
		t.Fatalf("retry evaluate = %d %s", retry.Code, retry.Body.String())
	}
	headAfterRetry, _ := runtime.db.GetAuditHead(context.Background())
	if headAfterRetry.Count != headAfterFirst.Count {
		t.Fatalf("idempotent retry appended audit: %d -> %d", headAfterFirst.Count, headAfterRetry.Count)
	}
	listed := runtime.request(t, http.MethodGet, "/v1/actions?decision=HOLD&limit=10", nil, true)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"operationId":"operation-release"`) ||
		strings.Contains(listed.Body.String(), "authorization") {
		t.Fatalf("held action projection = %d %s", listed.Code, listed.Body.String())
	}
	overview := decodeObject(t, runtime.request(t, http.MethodGet, "/v1/overview", nil, true))
	if overview["heldActions"] != float64(1) {
		t.Fatalf("overview held action count = %#v", overview["heldActions"])
	}

	conflicting := actionBody(runtime.now, "another-action", "operation-release")
	conflict := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", conflicting, true)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("operation conflict = %d %s", conflict.Code, conflict.Body.String())
	}

	truth := true
	verificationEventIDs := appendProtectedVerificationEvents(t, runtime)
	report := map[string]any{
		"nodeId": "node-test", "state": "PROTECTED",
		"observedAt":   runtime.now.Add(time.Second).Format(time.RFC3339Nano),
		"validUntil":   runtime.now.Add(2 * time.Minute).Format(time.RFC3339Nano),
		"networkTrust": "UNTRUSTED", "meshConnected": truth,
		"approvedExitActive": truth, "dnsProtected": truth, "routeProtected": truth,
		"reasonCodes": []string{}, "policyRevision": 7, "verificationEventIds": verificationEventIDs,
	}
	posture := runtime.request(t, http.MethodPost, "/v1/posture/report", report, true)
	if posture.Code != http.StatusAccepted {
		t.Fatalf("posture report = %d %s", posture.Code, posture.Body.String())
	}
	wait := runtime.request(t, http.MethodPost, "/v1/actions/action-release/wait", map[string]any{
		"actionId": "action-release", "afterObservedAt": runtime.now.Format(time.RFC3339Nano),
		"deadline": runtime.now.Add(2 * time.Minute).Format(time.RFC3339Nano),
	}, true)
	if wait.Code != http.StatusOK || decodeObject(t, wait)["restored"] != true {
		t.Fatalf("wait response = %d %s", wait.Code, wait.Body.String())
	}
	released := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
	if released.Code != http.StatusOK || decodeObject(t, released)["decision"] != "ALLOW" {
		t.Fatalf("released decision = %d %s", released.Code, released.Body.String())
	}
}

func TestActionEvaluationEnforcesExplicitPolicyScope(t *testing.T) {
	runtime := newTestRuntime(t)
	tests := []struct {
		name, field, value, reason string
	}{
		{"application", "applicationId", "other-app", "AF-ACTION-OUTSIDE-POLICY"},
		{"action type", "actionType", "shell.execute", "AF-ACTION-OUTSIDE-POLICY"},
		{"data class", "dataClass", "credentials", "AF-ACTION-OUTSIDE-POLICY"},
		{"sensitivity", "sensitivity", "SENSITIVITY_RESTRICTED", "AF-ACTION-OUTSIDE-POLICY"},
		{"destination", "destinations", "evil.example", "AF-DESTINATION-OUTSIDE-POLICY"},
		{"case variant", "destinations", "GitHub.com", "AF-DESTINATION-OUTSIDE-POLICY"},
	}
	for index, test := range tests {
		body := actionBody(runtime.now, fmt.Sprintf("policy-action-%d", index), fmt.Sprintf("policy-operation-%d", index))
		action := body["action"].(map[string]any)
		if test.field == "applicationId" {
			runtime.server.actions.protection.ProtectedActions[0].ApplicationIDs = []string{"other-app"}
		} else if test.field == "destinations" {
			action[test.field] = []string{test.value}
		} else {
			action[test.field] = test.value
		}
		response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
		runtime.server.actions.protection.ProtectedActions[0].ApplicationIDs = []string{"aether-code"}
		if response.Code != http.StatusCreated || decodeObject(t, response)["decision"] != "BLOCK" || !strings.Contains(response.Body.String(), test.reason) {
			t.Fatalf("%s policy denial = %d %s", test.name, response.Code, response.Body.String())
		}
	}
	aliasBody := actionBody(runtime.now, "policy-alias", "policy-alias-operation")
	aliasBody["action"].(map[string]any)["sensitivity"] = "CONFIDENTIAL"
	if response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", aliasBody, true); response.Code != http.StatusBadRequest {
		t.Fatalf("noncanonical sensitivity alias = %d %s", response.Code, response.Body.String())
	}
	authorizeDenied := runtime.request(t, http.MethodPost, "/v1/actions/policy-action-4/authorize", map[string]any{
		"actionId": "policy-action-4", "operationId": "policy-operation-4",
		"authorizedDestinations": []string{"evil.example"},
		"expiresAt":              runtime.now.Add(time.Minute).Format(time.RFC3339Nano), "consentReasonCode": "USER_EXPLICIT",
	}, true)
	if authorizeDenied.Code != http.StatusForbidden {
		t.Fatalf("one-time authorization expanded policy scope: %d %s", authorizeDenied.Code, authorizeDenied.Body.String())
	}

	runtime.server.actions.protection.ProtectedActions = nil
	response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", actionBody(runtime.now, "no-policy", "no-policy-operation"), true)
	if response.Code != http.StatusCreated || decodeObject(t, response)["decision"] != "BLOCK" || !strings.Contains(response.Body.String(), "AF-ACTION-OUTSIDE-POLICY") {
		t.Fatalf("missing active policy did not fail closed: %d %s", response.Code, response.Body.String())
	}
}

func TestAllowIsReevaluatedAndExecutionStartRejectsStaleEvidence(t *testing.T) {
	t.Run("same operation is held after posture degrades", func(t *testing.T) {
		runtime := newTestRuntime(t)
		eventIDs := appendProtectedVerificationEvents(t, runtime)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true); response.Code != http.StatusAccepted {
			t.Fatalf("protected posture = %d %s", response.Code, response.Body.String())
		}
		body := actionBody(runtime.now, "fresh-action", "fresh-operation")
		allowed := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
		if allowed.Code != http.StatusCreated || decodeObject(t, allowed)["decision"] != "ALLOW" {
			t.Fatalf("initial allow = %d %s", allowed.Code, allowed.Body.String())
		}
		runtime.advance(time.Second)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "EXPOSED", runtime.now, 7, nil), true); response.Code != http.StatusAccepted {
			t.Fatalf("exposed posture = %d %s", response.Code, response.Body.String())
		}
		listed := runtime.request(t, http.MethodGet, "/v1/actions?limit=10", nil, true)
		if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), `"decision":"ALLOW"`) ||
			!strings.Contains(listed.Body.String(), `"decision":"HOLD"`) || !strings.Contains(listed.Body.String(), `"expiresAt"`) {
			t.Fatalf("stale ALLOW list projection = %d %s", listed.Code, listed.Body.String())
		}
		rechecked := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
		if rechecked.Code != http.StatusOK || decodeObject(t, rechecked)["decision"] != "HOLD" {
			t.Fatalf("re-evaluated decision = %d %s", rechecked.Code, rechecked.Body.String())
		}
	})

	t.Run("execution start rejects expired protection without a new evaluation", func(t *testing.T) {
		runtime := newTestRuntime(t)
		eventIDs := appendProtectedVerificationEvents(t, runtime)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true); response.Code != http.StatusAccepted {
			t.Fatalf("protected posture = %d %s", response.Code, response.Body.String())
		}
		body := actionBody(runtime.now, "start-action", "start-operation")
		allowed := decodeObject(t, runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true))
		auditValue := allowed["audit"].(map[string]any)
		runtime.advance(time.Minute)
		start := map[string]any{
			"eventId": "stale-start", "lifecycle": "SDK_ACTION_EXECUTION_STARTED",
			"occurredAt": runtime.now.Format(time.RFC3339Nano), "actionId": "start-action", "requestId": "start-action",
			"decision": "ALLOW", "traceId": "start-operation", "policyRevision": auditValue["policyRevision"],
			"reasonCodes": []string{"AF-SDK-EXECUTION-START"}, "details": map[string]any{},
		}
		response := runtime.request(t, http.MethodPost, "/v1/actions/start-action/audit", start, true)
		if response.Code != http.StatusConflict {
			t.Fatalf("stale execution start = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("execution start rejects posture degradation after ALLOW", func(t *testing.T) {
		runtime := newTestRuntime(t)
		eventIDs := appendProtectedVerificationEvents(t, runtime)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true); response.Code != http.StatusAccepted {
			t.Fatalf("protected posture = %d %s", response.Code, response.Body.String())
		}
		body := actionBody(runtime.now, "degrade-start-action", "degrade-start-operation")
		allowedResponse := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
		allowed := decodeObject(t, allowedResponse)
		if allowedResponse.Code != http.StatusCreated || allowed["decision"] != "ALLOW" {
			t.Fatalf("initial allow = %d %s", allowedResponse.Code, allowedResponse.Body.String())
		}
		runtime.advance(time.Second)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "EXPOSED", runtime.now, 7, nil), true); response.Code != http.StatusAccepted {
			t.Fatalf("degraded posture = %d %s", response.Code, response.Body.String())
		}
		auditValue := allowed["audit"].(map[string]any)
		start := map[string]any{
			"eventId": "degraded-start", "lifecycle": "SDK_ACTION_EXECUTION_STARTED",
			"occurredAt": runtime.now.Format(time.RFC3339Nano), "actionId": "degrade-start-action", "requestId": "degrade-start-action",
			"decision": "ALLOW", "traceId": "degrade-start-operation", "policyRevision": auditValue["policyRevision"],
			"reasonCodes": []string{"AF-SDK-EXECUTION-START"}, "details": map[string]any{},
		}
		response := runtime.request(t, http.MethodPost, "/v1/actions/degrade-start-action/audit", start, true)
		if response.Code != http.StatusConflict {
			t.Fatalf("degraded execution start = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("deadline wins even if protection recovers later", func(t *testing.T) {
		runtime := newTestRuntime(t)
		body := actionBody(runtime.now, "deadline-action", "deadline-operation")
		body["action"].(map[string]any)["deadline"] = runtime.now.Add(time.Second).Format(time.RFC3339Nano)
		if response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true); response.Code != http.StatusCreated || decodeObject(t, response)["decision"] != "HOLD" {
			t.Fatalf("initial hold = %d %s", response.Code, response.Body.String())
		}
		runtime.advance(2 * time.Second)
		eventIDs := appendProtectedVerificationEvents(t, runtime)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true); response.Code != http.StatusAccepted {
			t.Fatalf("late protected posture = %d %s", response.Code, response.Body.String())
		}
		response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
		if response.Code != http.StatusOK || decodeObject(t, response)["decision"] != "BLOCK" || !strings.Contains(response.Body.String(), "AF-ACTION-DEADLINE-EXPIRED") {
			t.Fatalf("expired held action = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestExecutionLifecycleAndNodeAuthorityFailClosed(t *testing.T) {
	t.Run("blocked and not-started actions cannot claim success", func(t *testing.T) {
		runtime := newTestRuntime(t)
		blockedBody := actionBody(runtime.now, "blocked-lifecycle", "blocked-lifecycle-operation")
		blockedBody["action"].(map[string]any)["actionType"] = "shell.execute"
		blockedResponse := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", blockedBody, true)
		blocked := decodeObject(t, blockedResponse)
		if blockedResponse.Code != http.StatusCreated || blocked["decision"] != "BLOCK" {
			t.Fatalf("blocked action = %d %s", blockedResponse.Code, blockedResponse.Body.String())
		}
		blockedAudit := blocked["audit"].(map[string]any)
		terminal := lifecycleBody(
			"blocked-success", "SDK_ACTION_EXECUTION_SUCCEEDED", "blocked-lifecycle",
			"blocked-lifecycle-operation", "BLOCK", blockedAudit["policyRevision"], runtime.now,
		)
		if response := runtime.request(t, http.MethodPost, "/v1/actions/blocked-lifecycle/audit", terminal, true); response.Code != http.StatusConflict {
			t.Fatalf("blocked action success = %d %s", response.Code, response.Body.String())
		}

		eventIDs := appendProtectedVerificationEvents(t, runtime)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true); response.Code != http.StatusAccepted {
			t.Fatalf("protected posture = %d %s", response.Code, response.Body.String())
		}
		allowedResponse := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", actionBody(runtime.now, "not-started", "not-started-operation"), true)
		allowed := decodeObject(t, allowedResponse)
		terminal = lifecycleBody(
			"not-started-success", "SDK_ACTION_EXECUTION_SUCCEEDED", "not-started",
			"not-started-operation", "ALLOW", allowed["audit"].(map[string]any)["policyRevision"], runtime.now,
		)
		if response := runtime.request(t, http.MethodPost, "/v1/actions/not-started/audit", terminal, true); response.Code != http.StatusConflict {
			t.Fatalf("success before start = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("started decision freezes while exactly one terminal remains auditable", func(t *testing.T) {
		runtime := newTestRuntime(t)
		eventIDs := appendProtectedVerificationEvents(t, runtime)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true); response.Code != http.StatusAccepted {
			t.Fatalf("protected posture = %d %s", response.Code, response.Body.String())
		}
		body := actionBody(runtime.now, "frozen-execution", "frozen-execution-operation")
		allowedResponse := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
		allowed := decodeObject(t, allowedResponse)
		policyRevision := allowed["audit"].(map[string]any)["policyRevision"]
		start := lifecycleBody(
			"frozen-start", "SDK_ACTION_EXECUTION_STARTED", "frozen-execution",
			"frozen-execution-operation", "ALLOW", policyRevision, runtime.now,
		)
		if response := runtime.request(t, http.MethodPost, "/v1/actions/frozen-execution/audit", start, true); response.Code != http.StatusNoContent {
			t.Fatalf("execution start = %d %s", response.Code, response.Body.String())
		}
		runtime.advance(time.Second)
		if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "EXPOSED", runtime.now, 7, nil), true); response.Code != http.StatusAccepted {
			t.Fatalf("exposed posture = %d %s", response.Code, response.Body.String())
		}
		if response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true); response.Code != http.StatusConflict {
			t.Fatalf("started action was mutated by reevaluation: %d %s", response.Code, response.Body.String())
		}
		listed := runtime.request(t, http.MethodGet, "/v1/actions?decision=HOLD&limit=10", nil, true)
		if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "frozen-execution") {
			t.Fatalf("started action projected as pending HOLD: %d %s", listed.Code, listed.Body.String())
		}
		terminal := lifecycleBody(
			"frozen-success", "SDK_ACTION_EXECUTION_SUCCEEDED", "frozen-execution",
			"frozen-execution-operation", "ALLOW", policyRevision, runtime.now,
		)
		if response := runtime.request(t, http.MethodPost, "/v1/actions/frozen-execution/audit", terminal, true); response.Code != http.StatusNoContent {
			t.Fatalf("terminal success = %d %s", response.Code, response.Body.String())
		}
		secondTerminal := lifecycleBody(
			"frozen-failure", "SDK_ACTION_EXECUTION_FAILED", "frozen-execution",
			"frozen-execution-operation", "ALLOW", policyRevision, runtime.now,
		)
		if response := runtime.request(t, http.MethodPost, "/v1/actions/frozen-execution/audit", secondTerminal, true); response.Code != http.StatusConflict {
			t.Fatalf("second terminal = %d %s", response.Code, response.Body.String())
		}
		if response := runtime.request(t, http.MethodPost, "/v1/actions/frozen-execution/audit", terminal, true); response.Code != http.StatusNoContent {
			t.Fatalf("terminal replay = %d %s", response.Code, response.Body.String())
		}
		if response := runtime.request(t, http.MethodPost, "/v1/actions/frozen-execution/audit", start, true); response.Code != http.StatusConflict {
			t.Fatalf("start replay = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("suspension invalidates ordinary and one-time authority", func(t *testing.T) {
		runtime := newTestRuntime(t)
		body := actionBody(runtime.now, "revoked-once", "revoked-once-operation")
		heldResponse := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
		if heldResponse.Code != http.StatusCreated || decodeObject(t, heldResponse)["decision"] != "HOLD" {
			t.Fatalf("initial hold = %d %s", heldResponse.Code, heldResponse.Body.String())
		}
		authorizedResponse := runtime.request(t, http.MethodPost, "/v1/actions/revoked-once/authorize", map[string]any{
			"actionId": "revoked-once", "operationId": "revoked-once-operation",
			"authorizedDestinations": []string{"github.com"},
			"expiresAt":              runtime.now.Add(time.Minute).Format(time.RFC3339Nano), "consentReasonCode": "USER_EXPLICIT",
		}, true)
		authorized := decodeObject(t, authorizedResponse)
		if authorizedResponse.Code != http.StatusOK || authorized["decision"] != "ALLOW_ONCE" {
			t.Fatalf("one-time authorization = %d %s", authorizedResponse.Code, authorizedResponse.Body.String())
		}
		if response := runtime.request(t, http.MethodPost, "/v1/nodes/node-test/suspend", map[string]any{
			"operationId": "action-node-suspend", "reasonCode": "OPERATOR_SUSPENDED",
		}, true); response.Code != http.StatusOK {
			t.Fatalf("node suspension = %d %s", response.Code, response.Body.String())
		}
		if response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true); response.Code != http.StatusOK || decodeObject(t, response)["decision"] != "BLOCK" {
			t.Fatalf("suspended one-time action = %d %s", response.Code, response.Body.String())
		}
		start := lifecycleBody(
			"revoked-start", "SDK_ACTION_EXECUTION_STARTED", "revoked-once", "revoked-once-operation",
			"ALLOW_ONCE", authorized["audit"].(map[string]any)["policyRevision"], runtime.now,
		)
		if response := runtime.request(t, http.MethodPost, "/v1/actions/revoked-once/audit", start, true); response.Code != http.StatusConflict {
			t.Fatalf("suspended grant execution = %d %s", response.Code, response.Body.String())
		}
		if response := runtime.request(t, http.MethodPost, "/v1/nodes/node-test/reactivate", map[string]any{
			"operationId": "action-node-reactivate", "reasonCode": "OPERATOR_REACTIVATED",
		}, true); response.Code != http.StatusOK {
			t.Fatalf("node reactivation = %d %s", response.Code, response.Body.String())
		}
		fresh := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", actionBody(runtime.now, "reactivated-fresh", "reactivated-fresh-operation"), true)
		if fresh.Code != http.StatusCreated || decodeObject(t, fresh)["decision"] != "HOLD" {
			t.Fatalf("reactivation reused stale posture = %d %s", fresh.Code, fresh.Body.String())
		}
	})

	t.Run("deadline is mandatory for durable action projections", func(t *testing.T) {
		runtime := newTestRuntime(t)
		body := actionBody(runtime.now, "missing-deadline", "missing-deadline-operation")
		delete(body["action"].(map[string]any), "deadline")
		if response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true); response.Code != http.StatusBadRequest {
			t.Fatalf("missing action deadline = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestConsentRequiredPolicyNeverAutoAllowsProtectedNanoProposal(t *testing.T) {
	runtime := newTestRuntime(t)
	eventIDs := appendProtectedVerificationEvents(t, runtime)
	if response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true); response.Code != http.StatusAccepted {
		t.Fatalf("protected posture = %d %s", response.Code, response.Body.String())
	}
	action := secureActionRequest{
		ID: "nano-scrambler-proposal", ApplicationID: "antiflock-nano", NodeID: "node-test",
		ActionType: "scrambler.simulate", Destinations: []string{"local://scrambler/simulation"},
		DataClass: "network-control", Sensitivity: "SENSITIVITY_OPERATOR_PRIVATE",
		Deadline: runtime.now.Add(time.Minute).Format(time.RFC3339Nano), OperationID: "nano-scrambler-proposal-operation",
	}
	request := withPrincipal(httptest.NewRequest(http.MethodPost, "/v1/actions/evaluate", nil), principal{
		ID: "application:antiflock-nano", ApplicationID: "antiflock-nano", NodeID: "node-test",
	})
	decision, status, err := runtime.server.actions.evaluate(request.Context(), action)
	if err != nil || status != http.StatusCreated {
		t.Fatalf("evaluate Nano proposal = %d %#v %v", status, decision, err)
	}
	if decision.Decision != "REQUIRE_CONSENT" || decision.Consent == nil ||
		decision.Consent.Scope.ApplicationID != action.ApplicationID ||
		decision.Consent.Scope.ActionType != action.ActionType ||
		!sameStrings(decision.Consent.Scope.Destinations, action.Destinations) {
		t.Fatalf("Nano proposal was not bound to informed consent: %#v", decision)
	}
}

func TestPostureRevisionAndControlEvidenceFailClosed(t *testing.T) {
	t.Run("DNS proof must bind to the same route and mesh path", func(t *testing.T) {
		runtime := newTestRuntime(t)
		eventIDs := appendProtectedVerificationEventsWithDNSBinding(t, runtime, "other-interface", "other-path")
		response := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs), true)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unbound DNS proof was accepted: %d %s", response.Code, response.Body.String())
		}
	})

	runtime := newTestRuntime(t)
	eventIDs := appendProtectedVerificationEvents(t, runtime)
	missingRoute := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs[:2]), true)
	if missingRoute.Code != http.StatusBadRequest {
		t.Fatalf("self-reported route protection was accepted without route evidence: %d %s", missingRoute.Code, missingRoute.Body.String())
	}
	missingEgress := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs[:3]), true)
	if missingEgress.Code != http.StatusBadRequest {
		t.Fatalf("protected posture was accepted without external egress evidence: %d %s", missingEgress.Code, missingEgress.Body.String())
	}
	body := postureBody(runtime, "PROTECTED", runtime.now, 7, eventIDs)
	if response := runtime.request(t, http.MethodPost, "/v1/posture/report", body, true); response.Code != http.StatusAccepted {
		t.Fatalf("fully verified posture = %d %s", response.Code, response.Body.String())
	}
	head, err := runtime.db.GetAuditHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response := runtime.request(t, http.MethodPost, "/v1/posture/report", body, true); response.Code != http.StatusAccepted {
		t.Fatalf("exact posture retry = %d %s", response.Code, response.Body.String())
	}
	retryHead, _ := runtime.db.GetAuditHead(context.Background())
	if retryHead.Count != head.Count {
		t.Fatalf("exact posture retry appended audit: %d -> %d", head.Count, retryHead.Count)
	}

	originalObservedAt := runtime.now
	runtime.advance(time.Second)
	lowerRevision := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "EXPOSED", runtime.now, 6, nil), true)
	if lowerRevision.Code != http.StatusBadRequest {
		t.Fatalf("later lower policy revision was accepted: %d %s", lowerRevision.Code, lowerRevision.Body.String())
	}
	conflict := runtime.request(t, http.MethodPost, "/v1/posture/report", postureBody(runtime, "EXPOSED", originalObservedAt, 7, nil), true)
	if conflict.Code != http.StatusBadRequest {
		t.Fatalf("same revision/time with different facts was accepted: %d %s", conflict.Code, conflict.Body.String())
	}
}

func TestAuthorizeOnceAndLifecycleConsumptionAreIdempotent(t *testing.T) {
	runtime := newTestRuntime(t)
	body := actionBody(runtime.now, "action-once", "operation-once")
	if response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true); response.Code != http.StatusCreated || decodeObject(t, response)["decision"] != "HOLD" {
		t.Fatalf("evaluate = %d %s", response.Code, response.Body.String())
	}
	authorizeBody := map[string]any{
		"actionId": "action-once", "operationId": "operation-once",
		"authorizedDestinations": []string{"github.com"},
		"expiresAt":              runtime.now.Add(4 * time.Minute).Format(time.RFC3339Nano),
		"consentReasonCode":      "USER_EXPLICIT",
	}
	authorized := runtime.request(t, http.MethodPost, "/v1/actions/action-once/authorize", authorizeBody, true)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorize = %d %s", authorized.Code, authorized.Body.String())
	}
	value := decodeObject(t, authorized)
	authorization, ok := value["authorization"].(map[string]any)
	if !ok || !strings.HasPrefix(authorization["token"].(string), "af_grant_v1.") || authorization["remainingUses"] != float64(1) {
		t.Fatalf("authorization response = %#v", value)
	}
	retry := runtime.request(t, http.MethodPost, "/v1/actions/action-once/authorize", authorizeBody, true)
	if retry.Code != http.StatusOK || decodeObject(t, retry)["decision"] != "ALLOW_ONCE" {
		t.Fatalf("authorization retry = %d %s", retry.Code, retry.Body.String())
	}
	reEvaluated := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true)
	reEvaluatedValue := decodeObject(t, reEvaluated)
	reEvaluatedAuthorization, ok := reEvaluatedValue["authorization"].(map[string]any)
	if reEvaluated.Code != http.StatusOK || reEvaluatedValue["decision"] != "ALLOW_ONCE" || !ok ||
		reEvaluatedAuthorization["token"] != authorization["token"] || reEvaluatedAuthorization["remainingUses"] != float64(1) {
		t.Fatalf("SDK re-evaluation after operator authorization = %d %#v", reEvaluated.Code, reEvaluatedValue)
	}
	listed := runtime.request(t, http.MethodGet, "/v1/actions?decision=ALLOW_ONCE", nil, true)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "af_grant_v1.") || strings.Contains(listed.Body.String(), `"token"`) {
		t.Fatalf("action list exposed authorization material = %d %s", listed.Code, listed.Body.String())
	}

	auditBody := map[string]any{
		"eventId": "lifecycle-start-1", "lifecycle": "SDK_ACTION_EXECUTION_STARTED",
		"occurredAt": runtime.now.Add(time.Second).Format(time.RFC3339Nano),
		"actionId":   "action-once", "requestId": "action-once", "decision": "ALLOW_ONCE",
		"traceId": "operation-once", "policyRevision": 0, "reasonCodes": []string{"USER_AUTHORIZED_ONCE"}, "details": map[string]any{},
	}
	consumed := runtime.request(t, http.MethodPost, "/v1/actions/action-once/audit", auditBody, true)
	if consumed.Code != http.StatusNoContent {
		t.Fatalf("consume lifecycle = %d %s", consumed.Code, consumed.Body.String())
	}
	if response := runtime.request(t, http.MethodPost, "/v1/actions/evaluate", body, true); response.Code != http.StatusConflict {
		t.Fatalf("consumed grant evaluate = %d %s", response.Code, response.Body.String())
	}
	if response := runtime.request(t, http.MethodPost, "/v1/actions/action-once/authorize", authorizeBody, true); response.Code != http.StatusConflict {
		t.Fatalf("consumed grant authorize = %d %s", response.Code, response.Body.String())
	}
	consumedList := runtime.request(t, http.MethodGet, "/v1/actions?limit=10", nil, true)
	if consumedList.Code != http.StatusOK || !strings.Contains(consumedList.Body.String(), `"decision":"BLOCK"`) ||
		!strings.Contains(consumedList.Body.String(), "AF-ONE-TIME-GRANT-CONSUMED") || strings.Contains(consumedList.Body.String(), "oneTimeAuthorization") {
		t.Fatalf("consumed grant list projection = %d %s", consumedList.Code, consumedList.Body.String())
	}
	idempotent := runtime.request(t, http.MethodPost, "/v1/actions/action-once/audit", auditBody, true)
	if idempotent.Code != http.StatusConflict {
		t.Fatalf("execution-start replay = %d %s", idempotent.Code, idempotent.Body.String())
	}
	for name, mutate := range map[string]func(map[string]any){
		"lifecycle": func(value map[string]any) { value["lifecycle"] = "SDK_ACTION_EXECUTION_SUCCEEDED" },
		"occurredAt": func(value map[string]any) {
			value["occurredAt"] = runtime.now.Add(2 * time.Second).Format(time.RFC3339Nano)
		},
		"decision": func(value map[string]any) { value["decision"] = "ALLOW" },
		"details":  func(value map[string]any) { value["details"] = map[string]any{"changed": true} },
	} {
		changed := cloneObject(t, auditBody)
		mutate(changed)
		response := runtime.request(t, http.MethodPost, "/v1/actions/action-once/audit", changed, true)
		if response.Code != http.StatusConflict {
			t.Fatalf("changed lifecycle replay %s = %d %s", name, response.Code, response.Body.String())
		}
	}
	future := cloneObject(t, auditBody)
	future["eventId"] = "lifecycle-future"
	future["occurredAt"] = runtime.now.Add(6 * time.Minute).Format(time.RFC3339Nano)
	if response := runtime.request(t, http.MethodPost, "/v1/actions/action-once/audit", future, true); response.Code != http.StatusBadRequest {
		t.Fatalf("future lifecycle = %d %s", response.Code, response.Body.String())
	}
	invalidReason := cloneObject(t, auditBody)
	invalidReason["eventId"] = "lifecycle-invalid-reason"
	invalidReason["reasonCodes"] = []string{"not canonical"}
	if response := runtime.request(t, http.MethodPost, "/v1/actions/action-once/audit", invalidReason, true); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid lifecycle reason = %d %s", response.Code, response.Body.String())
	}
	auditBody["eventId"] = "lifecycle-start-2"
	second := runtime.request(t, http.MethodPost, "/v1/actions/action-once/audit", auditBody, true)
	if second.Code != http.StatusConflict {
		t.Fatalf("second consumption = %d %s", second.Code, second.Body.String())
	}
}

func cloneObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestBearerOnlyAuthenticationAndPostureValidation(t *testing.T) {
	runtime := newTestRuntime(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/nodes", nil)
	request.AddCookie(&http.Cookie{Name: "antiflock_session", Value: testOperatorToken})
	response := httptest.NewRecorder()
	runtime.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("cookie bearer was accepted for GET: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/posture/report", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: "antiflock_session", Value: testOperatorToken})
	response = httptest.NewRecorder()
	runtime.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("cookie bearer was accepted for POST: %d %s", response.Code, response.Body.String())
	}
	invalid := runtime.request(t, http.MethodPost, "/v1/posture/report", map[string]any{
		"nodeId": "node-test", "state": "PROTECTED", "observedAt": runtime.now.Format(time.RFC3339Nano),
		"validUntil": runtime.now.Add(time.Minute).Format(time.RFC3339Nano), "networkTrust": "UNTRUSTED",
		"reasonCodes": []string{}, "policyRevision": 1,
	}, true)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("unverified protected posture = %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestEnrollmentTokenAndPendingEnrollmentRoutes(t *testing.T) {
	runtime := newTestRuntime(t)
	tokenBody := map[string]any{
		"expiresAt":       runtime.now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		"allowedNodeType": "NODE_TYPE_AGENT", "allowedTags": []string{"lab"},
		"operationId": "operation-enrollment-token",
	}
	unauthenticated := runtime.request(t, http.MethodPost, "/v1/enrollment/tokens", tokenBody, false)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated token creation = %d", unauthenticated.Code)
	}
	created := runtime.request(t, http.MethodPost, "/v1/enrollment/tokens", tokenBody, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("token creation = %d %s", created.Code, created.Body.String())
	}
	createdObject := decodeObject(t, created)
	tokenValue, _ := createdObject["tokenValue"].(string)
	if !strings.HasPrefix(tokenValue, "af_enroll_v1.") || strings.Contains(created.Body.String(), "private") {
		t.Fatalf("unexpected enrollment token response: %s", created.Body.String())
	}
	retry := runtime.request(t, http.MethodPost, "/v1/enrollment/tokens", tokenBody, true)
	if retry.Code != http.StatusCreated || decodeObject(t, retry)["tokenValue"] != tokenValue {
		t.Fatalf("token retry = %d %s", retry.Code, retry.Body.String())
	}
	tokenBody["allowedTags"] = []string{"changed"}
	conflict := runtime.request(t, http.MethodPost, "/v1/enrollment/tokens", tokenBody, true)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("token operation conflict = %d %s", conflict.Code, conflict.Body.String())
	}

	// Pre-enrollment is intentionally token-and-PoP authenticated, not API-bearer
	// authenticated. An invalid request reaches bounded validation and fails 400.
	invalidEnrollment := runtime.request(t, http.MethodPost, "/v1/enrollment/nodes", map[string]any{}, false)
	if invalidEnrollment.Code != http.StatusBadRequest {
		t.Fatalf("invalid pending enrollment = %d %s", invalidEnrollment.Code, invalidEnrollment.Body.String())
	}
	pathMismatch := runtime.request(t, http.MethodPost, "/v1/enrollment/pending-1/approve", map[string]any{
		"enrollmentId": "pending-2", "operationId": "approve-op", "reasonCode": "OPERATOR_APPROVED",
	}, true)
	if pathMismatch.Code != http.StatusBadRequest {
		t.Fatalf("approval path mismatch = %d %s", pathMismatch.Code, pathMismatch.Body.String())
	}
}

func TestOperatorNodeMetadataAndImmediateStatusTransitions(t *testing.T) {
	runtime := newTestRuntime(t)
	updated := runtime.request(t, http.MethodPatch, "/v1/nodes/node-test", map[string]any{
		"displayName": "Renamed test node", "tags": []string{"trusted", "lab"}, "operationId": "node-update-1",
	}, true)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), "Renamed test node") || !strings.Contains(updated.Body.String(), "trusted") {
		t.Fatalf("node metadata update = %d %s", updated.Code, updated.Body.String())
	}
	suspended := runtime.request(t, http.MethodPost, "/v1/nodes/node-test/suspend", map[string]any{
		"operationId": "node-suspend-1", "reasonCode": "OPERATOR_SUSPENDED",
	}, true)
	if suspended.Code != http.StatusOK || !strings.Contains(suspended.Body.String(), "NODE_STATUS_SUSPENDED") {
		t.Fatalf("node suspension = %d %s", suspended.Code, suspended.Body.String())
	}
	blockedAgent := runtime.request(t, http.MethodPost, "/v1/posture/report", map[string]any{}, true)
	if blockedAgent.Code != http.StatusForbidden || !strings.Contains(blockedAgent.Body.String(), "NODE_INACTIVE") {
		t.Fatalf("suspended agent access = %d %s", blockedAgent.Code, blockedAgent.Body.String())
	}
	reactivated := runtime.request(t, http.MethodPost, "/v1/nodes/node-test/reactivate", map[string]any{
		"operationId": "node-reactivate-1", "reasonCode": "OPERATOR_REACTIVATED",
	}, true)
	if reactivated.Code != http.StatusOK || !strings.Contains(reactivated.Body.String(), "NODE_STATUS_ACTIVE") {
		t.Fatalf("node reactivation = %d %s", reactivated.Code, reactivated.Body.String())
	}
	revoked := runtime.request(t, http.MethodPost, "/v1/nodes/node-test/revoke", map[string]any{
		"operationId": "node-revoke-1", "reasonCode": "OPERATOR_REVOKED",
	}, true)
	if revoked.Code != http.StatusOK || !strings.Contains(revoked.Body.String(), "NODE_STATUS_REVOKED") {
		t.Fatalf("node revocation = %d %s", revoked.Code, revoked.Body.String())
	}
	blockedAgent = runtime.request(t, http.MethodPost, "/v1/posture/report", map[string]any{}, true)
	if blockedAgent.Code != http.StatusForbidden || !strings.Contains(blockedAgent.Body.String(), "NODE_INACTIVE") {
		t.Fatalf("revoked agent access = %d %s", blockedAgent.Code, blockedAgent.Body.String())
	}
	cannotReactivate := runtime.request(t, http.MethodPost, "/v1/nodes/node-test/reactivate", map[string]any{
		"operationId": "node-reactivate-2", "reasonCode": "OPERATOR_REACTIVATED",
	}, true)
	if cannotReactivate.Code != http.StatusConflict {
		t.Fatalf("revoked node reactivation = %d %s", cannotReactivate.Code, cannotReactivate.Body.String())
	}
}

func TestProjectionAndUnavailableRoutesReturnHonestJSON(t *testing.T) {
	runtime := newTestRuntime(t)
	for _, path := range []string{
		"/readyz", "/v1/nodes", "/v1/topology", "/v1/paths", "/v1/events?limit=10",
		"/v1/findings", "/v1/posture", "/v1/field/reports", "/v1/footprint", "/v1/scrambler/state",
	} {
		authenticated := strings.HasPrefix(path, "/v1/")
		response := runtime.request(t, http.MethodGet, path, nil, authenticated)
		if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) {
			t.Fatalf("projection %s = %d %s", path, response.Code, response.Body.String())
		}
	}
	invalidLimit := runtime.request(t, http.MethodGet, "/v1/events?limit=501", nil, true)
	if invalidLimit.Code != http.StatusBadRequest {
		t.Fatalf("invalid event limit = %d", invalidLimit.Code)
	}
	invalidSimulation := runtime.request(t, http.MethodPost, "/v1/scrambler/simulate", map[string]any{}, true)
	if invalidSimulation.Code != http.StatusBadRequest || !strings.Contains(invalidSimulation.Body.String(), "INVALID_SCRAMBLER_REQUEST") {
		t.Fatalf("invalid simulation = %d %s", invalidSimulation.Code, invalidSimulation.Body.String())
	}
	disabledExecution := runtime.request(t, http.MethodPost, "/v1/scrambler/activate", map[string]any{}, true)
	if disabledExecution.Code != http.StatusPreconditionFailed || !strings.Contains(disabledExecution.Body.String(), "SCRAMBLER_EXECUTION_DISABLED") {
		t.Fatalf("disabled Scrambler execution = %d %s", disabledExecution.Code, disabledExecution.Body.String())
	}
	validation := runtime.request(t, http.MethodPost, "/v1/policies/validate", map[string]any{}, true)
	if validation.Code != http.StatusOK || !strings.Contains(validation.Body.String(), "AF-POLICY-REQUIRED") {
		t.Fatalf("policy validation = %d %s", validation.Code, validation.Body.String())
	}
}

func TestValidPolicyCompileAndBoundedScramblerSimulationRoutes(t *testing.T) {
	runtime := newTestRuntime(t)
	policyBody := validPolicyBody()
	validation := runtime.request(t, http.MethodPost, "/v1/policies/validate", policyBody, true)
	validationObject := decodeObject(t, validation)
	if validation.Code != http.StatusOK || validationObject["valid"] != true || len(validationObject["violations"].([]any)) != 0 {
		t.Fatalf("valid policy validation = %d %#v", validation.Code, validationObject)
	}
	compileBody := cloneObject(t, policyBody)
	compileBody["nodeIds"] = []string{"node-test"}
	compileBody["operationId"] = "compile-coffee-shop-guard"
	compileBody["dryRunOnly"] = false
	compiled := runtime.request(t, http.MethodPost, "/v1/policies/compile", compileBody, true)
	compiledObject := decodeObject(t, compiled)
	plans, plansOK := compiledObject["plans"].([]any)
	violations, violationsOK := compiledObject["violations"].([]any)
	if compiled.Code != http.StatusOK || !plansOK || len(plans) != 1 || !violationsOK || len(violations) != 0 ||
		!strings.Contains(compiled.Body.String(), `"allowedExitNodeIds"`) || !strings.Contains(compiled.Body.String(), `"allowedResolvers"`) {
		t.Fatalf("valid policy compile = %d %#v", compiled.Code, compiledObject)
	}

	simulation := runtime.request(t, http.MethodPost, "/v1/scrambler/simulate", map[string]any{
		"nodeId": "node-test", "operationId": "simulate-exit-change",
		"constraints": map[string]any{
			"allowedDimensions":   []string{"SCRAMBLER_DIMENSION_EXIT_NODE"},
			"approvedExitNodeIds": []string{"exit-test"}, "criticalPeerIds": []string{"core-peer"},
			"requiredDestinations": []string{"core.internal"}, "maximumTransitionLatency": "30s",
		},
	}, true)
	simulationObject := decodeObject(t, simulation)
	simulationValue, simulationOK := simulationObject["simulation"].(map[string]any)
	candidates, candidatesOK := simulationValue["candidates"].([]any)
	if simulation.Code != http.StatusOK || !simulationOK || simulationValue["nodeId"] != "node-test" ||
		!candidatesOK || len(candidates) != 1 || !strings.Contains(simulation.Body.String(), `"stableReference":"exit-test"`) {
		t.Fatalf("valid Scrambler simulation = %d %#v", simulation.Code, simulationObject)
	}
}

func TestTopologyAndCurrentPathUseLatestDurableFactsWithoutInventingAssets(t *testing.T) {
	runtime := newTestRuntime(t)
	verificationEventIDs := appendProtectedVerificationEvents(t, runtime)
	appendVerifiedPathEvent(t, runtime, "event-wifi-verified", "network.wifi_changed",
		"type.googleapis.com/antiflock.v1.WifiObservation", 5, &antiflockv1.WifiObservation{
			Ssid: "coffee-shop", Security: antiflockv1.WifiSecurity_WIFI_SECURITY_WPA2_PERSONAL,
			Trust: antiflockv1.NetworkTrust_NETWORK_TRUST_UNTRUSTED, KnownNetwork: false,
			ObservedAt: timestamppb.New(runtime.now),
		})
	appendVerifiedPathEvent(t, runtime, "event-route-verified", "network.route_changed",
		"type.googleapis.com/antiflock.v1.RouteObservation", 6, &antiflockv1.RouteObservation{
			RouteId: "default-route", Destination: "0.0.0.0/0", Gateway: "192.0.2.1",
			InterfaceId: "wlan0", DefaultRoute: true, ObservedAt: timestamppb.New(runtime.now),
		})
	truth := true
	posture := runtime.request(t, http.MethodPost, "/v1/posture/report", map[string]any{
		"nodeId": "node-test", "state": "PROTECTED",
		"observedAt":   runtime.now.Add(time.Second).Format(time.RFC3339Nano),
		"validUntil":   runtime.now.Add(time.Minute).Format(time.RFC3339Nano),
		"networkTrust": "UNTRUSTED", "meshConnected": truth, "approvedExitActive": truth,
		"dnsProtected": truth, "routeProtected": truth, "reasonCodes": []string{},
		"policyRevision": 8, "verificationEventIds": verificationEventIDs,
	}, true)
	if posture.Code != http.StatusAccepted {
		t.Fatalf("posture report = %d %s", posture.Code, posture.Body.String())
	}
	overviewResponse := runtime.request(t, http.MethodGet, "/v1/overview", nil, true)
	overview := decodeObject(t, overviewResponse)
	environment := overview["environment"].(map[string]any)
	if overviewResponse.Code != http.StatusOK || overview["currentExit"] != "exit-test" || overview["exitVerified"] != true ||
		overview["dnsState"] != "VERIFIED" || environment["trust"] != "UNTRUSTED" ||
		strings.Contains(overviewResponse.Body.String(), "coffee-shop") {
		t.Fatalf("durable overview projection = %d %#v", overviewResponse.Code, overview)
	}
	nodesResponse := runtime.request(t, http.MethodGet, "/v1/nodes", nil, true)
	nodesObject := decodeObject(t, nodesResponse)
	projectedNodes := nodesObject["nodes"].([]any)
	projectedNode := projectedNodes[0].(map[string]any)
	if !strings.Contains(projectedNode["network"].(string), "UNTRUSTED") || projectedNode["meshState"] != "DIRECT" ||
		projectedNode["currentExit"] != "exit-test" || projectedNode["dnsState"] != "VERIFIED" || projectedNode["meshAddress"] != "Unknown" {
		t.Fatalf("durable node projection = %#v", projectedNode)
	}

	topologyResponse := runtime.request(t, http.MethodGet, "/v1/topology", nil, true)
	topology := decodeObject(t, topologyResponse)
	observations, observationsOK := topology["observations"].([]any)
	relationships, relationshipsOK := topology["relationships"].([]any)
	if topologyResponse.Code != http.StatusOK || topology["state"] != "OBSERVED" || !observationsOK || len(observations) != 4 ||
		!relationshipsOK || len(relationships) != 0 {
		t.Fatalf("topology = %d %#v", topologyResponse.Code, topology)
	}
	if !strings.Contains(topologyResponse.Body.String(), `"destinationNodeId":"exit-test"`) ||
		strings.Contains(topologyResponse.Body.String(), `"targetEntityId":"exit-test"`) {
		t.Fatalf("topology did not distinguish observed exit from enrolled asset: %s", topologyResponse.Body.String())
	}

	pathsResponse := runtime.request(t, http.MethodGet, "/v1/paths?nodeId=node-test", nil, true)
	pathsObject := decodeObject(t, pathsResponse)
	paths, pathsOK := pathsObject["paths"].([]any)
	if pathsResponse.Code != http.StatusOK || !pathsOK || len(paths) != 1 {
		t.Fatalf("paths = %d %#v", pathsResponse.Code, pathsObject)
	}
	path := paths[0].(map[string]any)
	hops, hopsOK := path["hops"].([]any)
	if path["state"] != "PROTECTED" || path["completeVisibility"] != true || !hopsOK || len(hops) != 4 {
		t.Fatalf("current path = %#v", path)
	}
	missing := runtime.request(t, http.MethodGet, "/v1/paths?nodeId=node-missing", nil, true)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing node path = %d %s", missing.Code, missing.Body.String())
	}
}

func TestEventBatchRejectsUnknownAndEmptyInput(t *testing.T) {
	runtime := newTestRuntime(t)
	unknown := runtime.request(t, http.MethodPost, "/v1/events/batch", map[string]any{
		"batch": map[string]any{"batchId": "batch-1", "nodeId": "node-test", "events": []any{}, "unexpected": true},
	}, true)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown event batch field = %d %s", unknown.Code, unknown.Body.String())
	}
	empty := runtime.request(t, http.MethodPost, "/v1/events/batch", map[string]any{
		"batch": map[string]any{"batchId": "batch-1", "nodeId": "node-test", "events": []any{}},
	}, true)
	if empty.Code != http.StatusBadRequest || !strings.Contains(empty.Body.String(), "INVALID_EVENT_BATCH") {
		t.Fatalf("empty event batch = %d %s", empty.Code, empty.Body.String())
	}
}

type fakeEventBus struct {
	mu     sync.Mutex
	events []model.EventEnvelope
	wake   chan model.EventEnvelope
}

func (bus *fakeEventBus) Append(_ context.Context, event model.EventEnvelope) (bool, error) {
	bus.mu.Lock()
	bus.events = append(bus.events, event)
	bus.mu.Unlock()
	bus.wake <- event
	return true, nil
}

func (bus *fakeEventBus) ReplayFrom(_ context.Context, cursor storage.ProjectionCursor, limit int) ([]model.EventEnvelope, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	result := make([]model.EventEnvelope, 0, limit)
	for _, event := range bus.events {
		if event.IngestOrdinal > cursor.LastIngestOrdinal {
			result = append(result, event)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (bus *fakeEventBus) Subscribe(_ int) (<-chan model.EventEnvelope, func()) {
	return bus.wake, func() {}
}

func TestSSEReplaysDurableMappedTopics(t *testing.T) {
	runtime := newTestRuntime(t)
	receivedAt := runtime.now.Add(time.Second)
	bus := &fakeEventBus{
		events: []model.EventEnvelope{{ID: "event-node", Kind: "node.heartbeat", ReceivedAt: receivedAt, ObservedAt: receivedAt, NodeID: "node-test", IngestOrdinal: 1}},
		wake:   make(chan model.EventEnvelope, 2),
	}
	runtime.server.events = bus
	httpServer := httptest.NewServer(runtime.server.Handler())
	defer httpServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/v1/stream?topics=node.changed", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testOperatorToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream response = %d %v", response.StatusCode, response.Header)
	}
	scanner := bufio.NewScanner(response.Body)
	lines := make([]string, 0, 3)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	cancel()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "event: node.changed") || !strings.Contains(joined, `"sourceKind":"node.heartbeat"`) || !strings.Contains(joined, "id: ") {
		t.Fatalf("unexpected SSE frame: %s", joined)
	}
}

func TestCursorAndTopicValidation(t *testing.T) {
	cursor := replayCursor{Version: 1, IngestOrdinal: 42, EventID: "event-1"}
	encoded := encodeCursor(cursor)
	request := httptest.NewRequest(http.MethodGet, "/v1/stream?cursor="+encoded, nil)
	request.Header.Set("Last-Event-ID", "different")
	runtime := newTestRuntime(t)
	if _, err := runtime.server.requestCursor(request); err == nil {
		t.Fatal("conflicting stream cursors were accepted")
	}
	if _, err := parseTopics("posture.changed,not.real"); err == nil {
		t.Fatal("unsupported stream topic was accepted")
	}
	if topicForEvent("mesh.path_changed") != "path.changed" || topicForEvent("flow.started") != "" {
		t.Fatal("event topic mapping is incorrect")
	}
}

func TestServeCancelsCleanly(t *testing.T) {
	runtime := newTestRuntime(t)
	runtime.server.config.Server.Listen = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.server.Serve(ctx); err != nil {
		t.Fatalf("cancelled Serve returned error: %v", err)
	}
	ready := runtime.request(t, http.MethodGet, "/readyz", nil, false)
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after shutdown = %d", ready.Code)
	}
}
