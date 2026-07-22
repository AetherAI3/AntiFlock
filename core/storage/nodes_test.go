package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

func TestNodeEnrollmentLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "nodes.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	now := time.Now().UTC()
	secret := sha256.Sum256([]byte("one-time-secret"))
	if err := database.CreateEnrollmentToken(ctx, storage.EnrollmentTokenRecord{
		ID: "token_one", Hash: secret[:], ScopeJSON: json.RawMessage(`{"allowedPlatforms":["linux"]}`), CreatedByPrincipalID: "operator", OperationID: "operation_one", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	node := model.Node{
		ID: "node_one", Name: "Laptop", Type: "NODE_TYPE_LAPTOP", Platform: "linux", PlatformVersion: "test", Status: model.NodeActive,
		Tags: []string{"gateway"}, Capabilities: json.RawMessage(`{"routes":true}`),
		CapabilitiesVerification: "CLAIMED", PublicKey: []byte("public-key"), CertificatePEM: "certificate", EnrolledAt: now,
	}
	if err := database.EnrollNode(ctx, secret[:], now, node); err != nil {
		t.Fatal(err)
	}
	if err := database.EnrollNode(ctx, secret[:], now, node); !errors.Is(err, storage.ErrEnrollmentTokenUsed) {
		t.Fatalf("reused token error = %v", err)
	}
	stored, err := database.GetNode(ctx, node.ID)
	if err != nil || stored.Name != node.Name || len(stored.Tags) != 1 {
		t.Fatalf("stored node = %#v, %v", stored, err)
	}
	nodes, err := database.ListNodes(ctx)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes = %#v, %v", nodes, err)
	}
	if err := database.SetNodeStatus(ctx, node.ID, model.NodeRevoked, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetNodeStatus(ctx, node.ID, model.NodeActive, now.Add(2*time.Second)); !errors.Is(err, storage.ErrNodeRevoked) {
		t.Fatalf("reactivate revoked node error = %v", err)
	}
	stored, err = database.GetNode(ctx, node.ID)
	if err != nil || stored.Status != model.NodeRevoked || stored.RevokedAt == nil {
		t.Fatalf("revoked node = %#v, %v", stored, err)
	}
	if err := database.SetNodeStatus(ctx, "missing", model.NodeActive, now); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("missing node error = %v", err)
	}
}

func TestEnrollmentRejectsInvalidAndExpiredTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	now := time.Now().UTC()
	expired := sha256.Sum256([]byte("expired"))
	if err := database.CreateEnrollmentToken(ctx, storage.EnrollmentTokenRecord{
		ID: "expired", Hash: expired[:], ScopeJSON: json.RawMessage(`{"allowedPlatforms":["linux"]}`), CreatedByPrincipalID: "operator", OperationID: "operation_expired", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	node := model.Node{ID: "node", Name: "Node", Type: "NODE_TYPE_AGENT", Platform: "linux", PlatformVersion: "test", Status: model.NodeActive, CapabilitiesVerification: "CLAIMED", PublicKey: []byte("key"), CertificatePEM: "cert", EnrolledAt: now}
	if err := database.EnrollNode(ctx, expired[:], now, node); !errors.Is(err, storage.ErrEnrollmentTokenExpired) {
		t.Fatalf("expired token error = %v", err)
	}
	missing := sha256.Sum256([]byte("missing"))
	if err := database.EnrollNode(ctx, missing[:], now, node); !errors.Is(err, storage.ErrEnrollmentTokenInvalid) {
		t.Fatalf("invalid token error = %v", err)
	}
	if _, err := database.GetNode(ctx, "missing"); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("missing node error = %v", err)
	}
	entries, err := database.ListAuditEntries(ctx, 0)
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty audit entries = %#v, %v", entries, err)
	}
	hash, err := database.LastAuditHash(ctx)
	if err != nil || hash != "" {
		t.Fatalf("empty audit hash = %q, %v", hash, err)
	}
}
