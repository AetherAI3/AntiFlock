package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/identity"
	"github.com/DBarr3/AntiFlock/core/storage"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRequestedNodeIdentityIsProofBoundAuditedAndPermanentlyBurned(t *testing.T) {
	t.Parallel()
	fixture := newEnrollmentFixture(t, 5*time.Minute)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := fixture.createToken(t, "token-requested-node-id")
	request := signedEnrollmentRequest(t, token, "request-requested-node-id", publicKey, privateKey, fixture.now)
	request.RequestedNodeId = "demo_agent_node_001"
	resignEnrollmentRequest(t, request, privateKey)
	pending, err := fixture.service.Enroll(fixture.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if pending.ProposedNodeId != request.RequestedNodeId {
		t.Fatalf("proposed node id = %q, want %q", pending.ProposedNodeId, request.RequestedNodeId)
	}
	replay, err := fixture.service.Enroll(fixture.ctx, request)
	if err != nil || replay.Id != pending.Id {
		t.Fatalf("requested-id replay = %#v, %v", replay, err)
	}
	tampered := proto.Clone(request).(*antiflockv1.EnrollNodeRequest)
	tampered.RequestedNodeId = "demo_agent_node_002"
	resignEnrollmentRequest(t, tampered, privateKey)
	if _, err := fixture.service.Enroll(fixture.ctx, tampered); !errors.Is(err, storage.ErrEnrollmentTokenUsed) {
		t.Fatalf("proof-bound requested-id conflict = %v", err)
	}
	if _, err := fixture.service.Deny(fixture.ctx, fixture.authority.Deployment.OperatorID, &antiflockv1.DenyEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "deny-requested-node-id", ReasonCode: "operator_rejected",
	}); err != nil {
		t.Fatal(err)
	}

	secondPublic, secondPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second := signedEnrollmentRequest(t, fixture.createToken(t, "token-reuse-requested-node-id"), "request-reuse-node-id", secondPublic, secondPrivate, fixture.now)
	second.RequestedNodeId = request.RequestedNodeId
	resignEnrollmentRequest(t, second, secondPrivate)
	if _, err := fixture.service.Enroll(fixture.ctx, second); !errors.Is(err, storage.ErrNodeIdentityUsed) {
		t.Fatalf("reuse of denied requested node id = %v", err)
	}

	entries, err := fixture.database.ListAuditEntries(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == "enrollment.requested" && strings.Contains(string(entry.Details), request.RequestedNodeId) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("enrollment.requested audit entry did not expose the proposed requested node id")
	}

	for _, invalid := range []string{"node_system", "UPPERCASE", "node--double", "node_trailing_", fixture.authority.Deployment.DeploymentID} {
		if err := validateRequestedNodeID(invalid, fixture.authority.Deployment.DeploymentID, fixture.authority.Deployment.OperatorID); err == nil {
			t.Fatalf("requested node id %q was accepted", invalid)
		}
	}
}

func TestRequestedNodeIdentityCannotCollideWithAnActiveNode(t *testing.T) {
	t.Parallel()
	fixture := newEnrollmentFixture(t, 5*time.Minute)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first := signedEnrollmentRequest(t, fixture.createToken(t, "token-active-requested-id"), "request-active-node", publicKey, privateKey, fixture.now)
	first.RequestedNodeId = "active_node_identity_001"
	resignEnrollmentRequest(t, first, privateKey)
	pending, err := fixture.service.Enroll(fixture.ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Approve(fixture.ctx, fixture.authority.Deployment.OperatorID, &antiflockv1.ApproveEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "approve-active-requested-id", ReasonCode: "operator_verified",
	}); err != nil {
		t.Fatal(err)
	}

	secondPublic, secondPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second := signedEnrollmentRequest(t, fixture.createToken(t, "token-colliding-active-id"), "request-colliding-active", secondPublic, secondPrivate, fixture.now)
	second.RequestedNodeId = first.RequestedNodeId
	resignEnrollmentRequest(t, second, secondPrivate)
	if _, err := fixture.service.Enroll(fixture.ctx, second); !errors.Is(err, storage.ErrNodeIdentityUsed) {
		t.Fatalf("active node identity collision = %v", err)
	}
}

type enrollmentFixture struct {
	ctx       context.Context
	database  *storage.DB
	authority *identity.Authority
	audit     *audit.Service
	service   *Service
	now       time.Time
}

func newEnrollmentFixture(t *testing.T, tokenTTL time.Duration) *enrollmentFixture {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "antiflock.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	now := time.Date(2026, time.July, 22, 18, 0, 0, 0, time.UTC)
	authority, err := identity.Ensure(filepath.Join(directory, "identity"), now)
	if err != nil {
		t.Fatal(err)
	}
	auditService, err := audit.NewWithKeyring(
		database,
		authority.AuditPrivateKey(),
		authority.HistoricalAuditPublicKeys(),
		authority.AuditAnchorPath(),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &enrollmentFixture{
		ctx: ctx, database: database, authority: authority, audit: auditService,
		now: now,
	}
	fixture.service = New(database, authority, auditService, tokenTTL)
	fixture.service.clock = func() time.Time { return fixture.now }
	return fixture
}

func (fixture *enrollmentFixture) createToken(t *testing.T, operationID string, tags ...string) Token {
	t.Helper()
	token, err := fixture.service.CreateScopedToken(
		fixture.ctx,
		fixture.authority.Deployment.OperatorID,
		operationID,
		TokenScope{AllowedNodeType: antiflockv1.NodeType_NODE_TYPE_AGENT, ApprovedTags: tags},
	)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signedEnrollmentRequest(
	t *testing.T,
	token Token,
	requestID string,
	publicKey ed25519.PublicKey,
	privateKey ed25519.PrivateKey,
	now time.Time,
) *antiflockv1.EnrollNodeRequest {
	t.Helper()
	request := &antiflockv1.EnrollNodeRequest{
		TokenValue: token.TokenValue, RequestId: requestID, DisplayName: "trust-spine-device",
		NodeType: antiflockv1.NodeType_NODE_TYPE_AGENT, Platform: "linux", PlatformVersion: "test",
		KeyAlgorithm: "ed25519", PublicKey: append([]byte(nil), publicKey...),
		Capabilities: &antiflockv1.CapabilityManifest{
			Revision: 1, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			Capabilities: []*antiflockv1.Capability{{
				Key: "network.route.observe", Domain: antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_NETWORK,
				Operations:   []antiflockv1.CapabilityOperation{antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE},
				SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
			}},
		},
	}
	proofMessage, err := ProofMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ProofOfPossession = ed25519.Sign(privateKey, proofMessage)
	return request
}

func resignEnrollmentRequest(t *testing.T, request *antiflockv1.EnrollNodeRequest, privateKey ed25519.PrivateKey) {
	t.Helper()
	request.ProofOfPossession = nil
	proofMessage, err := ProofMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ProofOfPossession = ed25519.Sign(privateKey, proofMessage)
}

func TestEnrollmentDenialIsFinalReplaySafeAndBurnsCredential(t *testing.T) {
	t.Parallel()
	fixture := newEnrollmentFixture(t, 5*time.Minute)
	token := fixture.createToken(t, "token-denial", "trusted")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := signedEnrollmentRequest(t, token, "request-denial", publicKey, privateKey, fixture.now)
	pending, err := fixture.service.Enroll(fixture.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	denial := &antiflockv1.DenyEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "deny-operation", ReasonCode: "operator_rejected",
	}
	denied, err := fixture.service.Deny(fixture.ctx, fixture.authority.Deployment.OperatorID, denial)
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_DENIED || denied.DecisionReasonCode != denial.ReasonCode {
		t.Fatalf("denied enrollment = %#v", denied)
	}
	if _, err := fixture.database.GetNode(fixture.ctx, pending.ProposedNodeId); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("denied enrollment created a node: %v", err)
	}
	replayed, err := fixture.service.Deny(fixture.ctx, fixture.authority.Deployment.OperatorID, denial)
	if err != nil || replayed.Status != antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_DENIED {
		t.Fatalf("exact denial replay = %#v, %v", replayed, err)
	}
	conflictingDenial := proto.Clone(denial).(*antiflockv1.DenyEnrollmentRequest)
	conflictingDenial.ReasonCode = "different_reason"
	if _, err := fixture.service.Deny(fixture.ctx, fixture.authority.Deployment.OperatorID, conflictingDenial); !errors.Is(err, storage.ErrOperationConflict) {
		t.Fatalf("conflicting denial replay error = %v", err)
	}
	if _, err := fixture.service.Deny(fixture.ctx, "different_operator", denial); !errors.Is(err, storage.ErrOperationConflict) {
		t.Fatalf("cross-actor denial replay error = %v", err)
	}
	if _, err := fixture.service.Approve(fixture.ctx, fixture.authority.Deployment.OperatorID, &antiflockv1.ApproveEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "approve-after-denial", ReasonCode: "invalid_transition",
	}); !errors.Is(err, storage.ErrEnrollmentRequestDecided) {
		t.Fatalf("approval after denial error = %v", err)
	}
	idempotentEnrollment, err := fixture.service.Enroll(fixture.ctx, request)
	if err != nil || idempotentEnrollment.Status != antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_DENIED {
		t.Fatalf("enrollment replay after denial = %#v, %v", idempotentEnrollment, err)
	}

	secondToken := fixture.createToken(t, "token-after-denial")
	reusedCredential := signedEnrollmentRequest(t, secondToken, "request-reused-denied-key", publicKey, privateKey, fixture.now)
	if _, err := fixture.service.Enroll(fixture.ctx, reusedCredential); !errors.Is(err, storage.ErrCredentialReused) {
		t.Fatalf("denied credential reuse error = %v", err)
	}
	if err := fixture.audit.Verify(fixture.ctx); err != nil {
		t.Fatalf("verify audit after denial invariants: %v", err)
	}
}

func TestEnrollmentApprovalReplayMustMatchOriginalDecision(t *testing.T) {
	t.Parallel()
	fixture := newEnrollmentFixture(t, 5*time.Minute)
	token := fixture.createToken(t, "token-approval", "alpha", "beta")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := fixture.service.Enroll(fixture.ctx, signedEnrollmentRequest(
		t, token, "request-approval", publicKey, privateKey, fixture.now,
	))
	if err != nil {
		t.Fatal(err)
	}
	approval := &antiflockv1.ApproveEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "approve-operation", ReasonCode: "operator_verified", ApprovedTags: []string{"alpha"},
	}
	node, err := fixture.service.Approve(fixture.ctx, fixture.authority.Deployment.OperatorID, approval)
	if err != nil {
		t.Fatal(err)
	}
	replayedNode, err := fixture.service.Approve(fixture.ctx, fixture.authority.Deployment.OperatorID, approval)
	if err != nil || replayedNode.ID != node.ID {
		t.Fatalf("exact approval replay = %#v, %v", replayedNode, err)
	}
	conflictingReason := proto.Clone(approval).(*antiflockv1.ApproveEnrollmentRequest)
	conflictingReason.ReasonCode = "different_reason"
	if _, err := fixture.service.Approve(fixture.ctx, fixture.authority.Deployment.OperatorID, conflictingReason); !errors.Is(err, storage.ErrOperationConflict) {
		t.Fatalf("conflicting approval reason replay error = %v", err)
	}
	conflictingTags := proto.Clone(approval).(*antiflockv1.ApproveEnrollmentRequest)
	conflictingTags.ApprovedTags = []string{"beta"}
	if _, err := fixture.service.Approve(fixture.ctx, fixture.authority.Deployment.OperatorID, conflictingTags); !errors.Is(err, storage.ErrOperationConflict) {
		t.Fatalf("conflicting approval tags replay error = %v", err)
	}
	if _, err := fixture.service.Approve(fixture.ctx, "different_operator", approval); !errors.Is(err, storage.ErrOperationConflict) {
		t.Fatalf("cross-actor approval replay error = %v", err)
	}
	if err := fixture.audit.Verify(fixture.ctx); err != nil {
		t.Fatalf("verify audit after approval replays: %v", err)
	}
}

func TestEnrollmentExpiryBlocksAdmissionButPreservesExactReplay(t *testing.T) {
	t.Parallel()
	fixture := newEnrollmentFixture(t, 5*time.Minute)
	token := fixture.createToken(t, "token-pending-expiry")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := signedEnrollmentRequest(t, token, "request-pending-expiry", publicKey, privateKey, fixture.now)
	pending, err := fixture.service.Enroll(fixture.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = token.ExpiresAt
	if _, err := fixture.service.Approve(fixture.ctx, fixture.authority.Deployment.OperatorID, &antiflockv1.ApproveEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "approve-expired", ReasonCode: "too_late",
	}); !errors.Is(err, storage.ErrEnrollmentRequestExpired) {
		t.Fatalf("expired approval error = %v", err)
	}
	if _, err := fixture.database.GetNode(fixture.ctx, pending.ProposedNodeId); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("expired enrollment created a node: %v", err)
	}
	exactReplay, err := fixture.service.Enroll(fixture.ctx, request)
	if err != nil || exactReplay.Id != pending.Id {
		t.Fatalf("exact consumed-token replay after expiry = %#v, %v", exactReplay, err)
	}
	conflictingReplay := proto.Clone(request).(*antiflockv1.EnrollNodeRequest)
	conflictingReplay.RequestId = "request-conflict-after-expiry"
	resignEnrollmentRequest(t, conflictingReplay, privateKey)
	if _, err := fixture.service.Enroll(fixture.ctx, conflictingReplay); !errors.Is(err, storage.ErrEnrollmentTokenUsed) {
		t.Fatalf("conflicting consumed-token replay after expiry error = %v", err)
	}
	reuseToken := fixture.createToken(t, "token-reuse-expired-request")
	reusedCredential := signedEnrollmentRequest(t, reuseToken, "request-reuse-expired-key", publicKey, privateKey, fixture.now)
	if _, err := fixture.service.Enroll(fixture.ctx, reusedCredential); !errors.Is(err, storage.ErrCredentialReused) {
		t.Fatalf("expired pending credential reuse error = %v", err)
	}

	unusedToken := fixture.createToken(t, "token-unused-expiry")
	unusedPublic, unusedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unusedRequest := signedEnrollmentRequest(t, unusedToken, "request-unused-expiry", unusedPublic, unusedPrivate, fixture.now)
	fixture.now = unusedToken.ExpiresAt
	if _, err := fixture.service.Enroll(fixture.ctx, unusedRequest); !errors.Is(err, storage.ErrEnrollmentTokenExpired) {
		t.Fatalf("unused expired token enrollment error = %v", err)
	}
	if err := fixture.audit.Verify(fixture.ctx); err != nil {
		t.Fatalf("verify audit after expiry invariants: %v", err)
	}
}
