package enrollment_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	"github.com/DBarr3/AntiFlock/core/identity"
	"github.com/DBarr3/AntiFlock/core/storage"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEnrollmentTokenIsSingleUseAndAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "antiflock.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	authority, err := identity.Ensure(filepath.Join(directory, "identity"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	auditService, err := audit.New(database, authority.AuditPrivateKey(), authority.AuditAnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	service := enrollment.New(database, authority, auditService, time.Minute)
	token, err := service.CreateScopedToken(ctx, authority.Deployment.OperatorID, "token_operation_one", enrollment.TokenScope{
		AllowedNodeType: antiflockv1.NodeType_NODE_TYPE_AGENT,
	})
	if err != nil {
		t.Fatal(err)
	}
	replayedToken, err := service.CreateScopedToken(ctx, authority.Deployment.OperatorID, "token_operation_one", enrollment.TokenScope{
		AllowedNodeType: antiflockv1.NodeType_NODE_TYPE_AGENT,
	})
	if err != nil || replayedToken.ID != token.ID || replayedToken.TokenValue != token.TokenValue {
		t.Fatalf("idempotent token replay = %#v, %v", replayedToken, err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := &antiflockv1.EnrollNodeRequest{
		TokenValue: token.TokenValue, RequestId: "request_one", DisplayName: "test-device",
		NodeType: antiflockv1.NodeType_NODE_TYPE_AGENT, Platform: "linux", PlatformVersion: "test",
		KeyAlgorithm: "ed25519", PublicKey: public,
		Capabilities: &antiflockv1.CapabilityManifest{
			Revision: 1, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			Capabilities: []*antiflockv1.Capability{{
				Key: "network.route.observe", Domain: antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_NETWORK,
				Operations:   []antiflockv1.CapabilityOperation{antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE},
				SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
			}},
		},
	}
	proofMessage, err := enrollment.ProofMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ProofOfPossession = ed25519.Sign(private, proofMessage)
	pending, err := service.Enroll(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		t.Fatalf("enrollment status = %s", pending.Status)
	}
	if _, err := database.GetNode(ctx, pending.ProposedNodeId); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("pending enrollment created an active node: %v", err)
	}
	replayed, err := service.Enroll(ctx, request)
	if err != nil || replayed.Id != pending.Id {
		t.Fatalf("idempotent enrollment replay = %#v, %v", replayed, err)
	}
	conflict := proto.Clone(request).(*antiflockv1.EnrollNodeRequest)
	conflict.RequestId = "request_two"
	conflictProof, err := enrollment.ProofMessage(conflict)
	if err != nil {
		t.Fatal(err)
	}
	conflict.ProofOfPossession = ed25519.Sign(private, conflictProof)
	if _, err := service.Enroll(ctx, conflict); !errors.Is(err, storage.ErrEnrollmentTokenUsed) {
		t.Fatalf("conflicting enrollment replay error = %v", err)
	}
	node, err := service.Approve(ctx, authority.Deployment.OperatorID, &antiflockv1.ApproveEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "approve_one", ReasonCode: "operator_verified",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.CertificatePEM == "" || node.Status != "ACTIVE" {
		t.Fatalf("approved node = %#v", node)
	}
	replayedNode, err := service.Approve(ctx, authority.Deployment.OperatorID, &antiflockv1.ApproveEnrollmentRequest{
		EnrollmentId: pending.Id, OperationId: "approve_one", ReasonCode: "operator_verified",
	})
	if err != nil || replayedNode.ID != node.ID {
		t.Fatalf("idempotent approval replay = %#v, %v", replayedNode, err)
	}
	if err := auditService.Verify(ctx); err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if err := service.SetStatus(ctx, authority.Deployment.OperatorID, node.ID, "SUSPENDED"); err != nil {
		t.Fatal(err)
	}
	stored, err := database.GetNode(ctx, node.ID)
	if err != nil || stored.Status != "SUSPENDED" {
		t.Fatalf("stored node = %#v, %v", stored, err)
	}
	if err := auditService.Verify(ctx); err != nil {
		t.Fatalf("verify audit chain after status change: %v", err)
	}
	if err := service.SetStatus(ctx, authority.Deployment.OperatorID, node.ID, "REVOKED"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetStatus(ctx, authority.Deployment.OperatorID, node.ID, "ACTIVE"); !errors.Is(err, storage.ErrNodeRevoked) {
		t.Fatalf("reactivating revoked node error = %v", err)
	}
	secondToken, err := service.CreateScopedToken(ctx, authority.Deployment.OperatorID, "token_operation_two", enrollment.TokenScope{
		AllowedNodeType: antiflockv1.NodeType_NODE_TYPE_AGENT,
	})
	if err != nil {
		t.Fatal(err)
	}
	reusedKey := proto.Clone(request).(*antiflockv1.EnrollNodeRequest)
	reusedKey.TokenValue = secondToken.TokenValue
	reusedKey.RequestId = "request_reused_revoked_key"
	reusedProof, err := enrollment.ProofMessage(reusedKey)
	if err != nil {
		t.Fatal(err)
	}
	reusedKey.ProofOfPossession = ed25519.Sign(private, reusedProof)
	if _, err := service.Enroll(ctx, reusedKey); !errors.Is(err, storage.ErrCredentialReused) {
		t.Fatalf("reusing revoked credential error = %v", err)
	}
}
