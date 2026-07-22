package events_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/core/identity"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fixture struct {
	database   *storage.DB
	store      *events.Store
	authority  *identity.Authority
	node       model.Node
	privateKey ed25519.PrivateKey
	now        time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	database, err := storage.Open(ctx, filepath.Join(directory, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	now := time.Now().UTC().Truncate(time.Microsecond)
	authority, err := identity.Ensure(filepath.Join(directory, "identity"), now)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := authority.IssueNodeCertificate("node_one", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("event-fixture-token"))
	if err := database.CreateEnrollmentToken(ctx, storage.EnrollmentTokenRecord{
		ID: "token_one", Hash: tokenHash[:], CreatedByPrincipalID: "operator", OperationID: "operation_event_fixture",
		ScopeJSON: json.RawMessage(`{"allowedPlatforms":["linux"]}`), CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	node := model.Node{
		ID: "node_one", Name: "Gateway", Type: "NODE_TYPE_AGENT", Platform: "linux", PlatformVersion: "test", Status: model.NodeActive,
		Capabilities: json.RawMessage(`{"version":"antiflock.capabilities/v1"}`), PublicKey: publicKey,
		CapabilitiesVerification: "CLAIMED", CertificatePEM: certificate, EnrolledAt: now,
	}
	if err := database.EnrollNode(ctx, tokenHash[:], now, node); err != nil {
		t.Fatal(err)
	}
	store, err := events.New(database, authority)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{database: database, store: store, authority: authority, node: node, privateKey: privateKey, now: now}
}

func (fixture fixture) event(t *testing.T, id string, sequence uint64) model.EventEnvelope {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.MeshPathObservation{
		PathId: "path_one", Provider: "headscale", SourceNodeId: fixture.node.ID,
		ObservedAt: timestamppb.New(fixture.now),
	})
	if err != nil {
		t.Fatal(err)
	}
	event := model.EventEnvelope{
		ID: id, SchemaVersion: "antiflock.event/v1", DeploymentID: fixture.authority.Deployment.DeploymentID,
		NodeID: fixture.node.ID, Kind: "mesh.connection_lost", ObservedAt: fixture.now,
		Sequence: sequence, BootID: "boot_one", Classification: model.EvidenceDetected, Confidence: 1,
		Sensitivity: model.SensitivityInternal, PayloadTypeURL: "type.googleapis.com/antiflock.v1.MeshPathObservation",
		Payload: payload,
	}
	if err := events.SignAt(&event, fixture.node.ID, fixture.privateKey, fixture.now); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestStorePublishesOnlyInsertedAuthenticatedEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newFixture(t)
	stream, unsubscribe := fixture.store.Subscribe(1)
	defer unsubscribe()
	event := fixture.event(t, "event_one", 1)
	inserted, err := fixture.store.Append(ctx, event)
	if err != nil || !inserted {
		t.Fatalf("append = %v, %v", inserted, err)
	}
	select {
	case received := <-stream:
		if received.ID != event.ID || received.ReceivedAt.IsZero() {
			t.Fatalf("received event = %#v", received)
		}
		node, getErr := fixture.database.GetNode(ctx, fixture.node.ID)
		if getErr != nil || node.LastSeenAt == nil || !node.LastSeenAt.Equal(received.ReceivedAt) {
			t.Fatalf("node last seen = %v, %v; event received = %v", node.LastSeenAt, getErr, received.ReceivedAt)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
	inserted, err = fixture.store.Append(ctx, event)
	if err != nil || inserted {
		t.Fatalf("idempotent append = %v, %v", inserted, err)
	}
	cursor, err := fixture.database.GetProjectionCursor(ctx, events.APIProjection)
	if err != nil || cursor.LastIngestOrdinal == 0 || cursor.LastEventID != event.ID {
		t.Fatalf("durable API projection cursor = %#v, %v", cursor, err)
	}
}

func TestStoreRejectsTamperingAndRevokedSources(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newFixture(t)
	tampered := fixture.event(t, "event_tampered", 1)
	tampered.Payload = json.RawMessage(`{"connected":true}`)
	if _, err := fixture.store.Append(ctx, tampered); err == nil {
		t.Fatal("tampered signed event was accepted")
	}
	if err := fixture.database.SetNodeStatus(ctx, fixture.node.ID, model.NodeRevoked, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Append(ctx, fixture.event(t, "event_revoked", 2)); err == nil {
		t.Fatal("event from revoked node was accepted")
	}
}

func TestSlowSubscriberIsClosedInsteadOfSilentlyDropping(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newFixture(t)
	stream, unsubscribe := fixture.store.Subscribe(1)
	defer unsubscribe()
	if _, err := fixture.store.Append(ctx, fixture.event(t, "event_one", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Append(ctx, fixture.event(t, "event_two", 2)); err != nil {
		t.Fatal(err)
	}
	first, ok := <-stream
	if !ok || first.ID != "event_one" {
		t.Fatalf("buffered event = %#v, open=%v", first, ok)
	}
	if _, ok := <-stream; ok {
		t.Fatal("slow subscriber remained open after overflow")
	}
}

func TestSignRejectsMalformedPrivateKey(t *testing.T) {
	event := model.EventEnvelope{}
	if err := events.Sign(&event, ed25519.PrivateKey{1}); err == nil {
		t.Fatal("malformed signing key was accepted")
	}
	if err := events.VerifySource(event, ed25519.PublicKey{1}); err == nil {
		t.Fatal("malformed verification key was accepted")
	}
}

func TestStoreEnforcesVerifiedEvidenceAtIngestionTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newFixture(t)
	event := fixture.event(t, "event_verified", 1)
	event.Classification = model.EvidenceVerified
	if err := events.SignAt(&event, fixture.node.ID, fixture.privateKey, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Append(ctx, event); err == nil {
		t.Fatal("VERIFIED event without supporting evidence was accepted")
	}

	verifiedAt := fixture.now.Add(-time.Minute)
	expiresAt := fixture.now.Add(time.Hour)
	event.Evidence = []model.EvidenceReference{{
		ID: "evidence_verified", Role: "SUPPORTING", Classification: model.EvidenceVerified,
		SourceType: "LOCAL_SENSOR", Source: "mesh probe", ObservedAt: fixture.now.Add(-2 * time.Minute),
		LastVerifiedAt: &verifiedAt, ExpiresAt: &expiresAt, Confidence: 1,
		Sensitivity: model.SensitivityInternal, Explanation: "independent path verification",
		Integrity: model.IntegrityDigest{Algorithm: "sha256", Digest: bytesOf(3, sha256.Size)},
	}}
	if err := events.SignAt(&event, fixture.node.ID, fixture.privateKey, fixture.now); err != nil {
		t.Fatal(err)
	}
	if inserted, err := fixture.store.Append(ctx, event); err != nil || !inserted {
		t.Fatalf("verified event append = %v, %v", inserted, err)
	}
}

func TestStoreRejectsOversizedWireEnvelope(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	event := fixture.event(t, "event_oversized", 1)
	event.Evidence = make([]model.EvidenceReference, 64)
	for index := range event.Evidence {
		attributes := make(map[string]string, 32)
		for attribute := range 32 {
			attributes[fmt.Sprintf("attribute-%02d", attribute)] = strings.Repeat("v", 1024)
		}
		event.Evidence[index] = model.EvidenceReference{
			ID: fmt.Sprintf("evidence-%02d", index), Role: "CONTEXT", Classification: model.EvidenceDetected,
			SourceType: "LOCAL_SENSOR", Source: "sensor", SourceURI: "https://example.invalid/" + strings.Repeat("u", 2000),
			ObservedAt: fixture.now, Confidence: 1, Sensitivity: model.SensitivityInternal,
			Explanation: strings.Repeat("e", 2048), Attributes: attributes,
		}
	}
	if err := events.SignAt(&event, fixture.node.ID, fixture.privateKey, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Append(context.Background(), event); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized wire error = %v", err)
	}
}

func TestStoreEnforcesSequenceAndBootTransitions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newFixture(t)
	if _, err := fixture.store.Append(ctx, fixture.event(t, "event_gap", 2)); !errors.Is(err, storage.ErrEventSequenceGap) {
		t.Fatalf("first sequence gap error = %v", err)
	}
	if inserted, err := fixture.store.Append(ctx, fixture.event(t, "event_a1", 1)); err != nil || !inserted {
		t.Fatalf("append boot-a sequence 1 = %v, %v", inserted, err)
	}
	if _, err := fixture.store.Append(ctx, fixture.event(t, "event_a3", 3)); !errors.Is(err, storage.ErrEventSequenceGap) {
		t.Fatalf("sequence gap error = %v", err)
	}
	if inserted, err := fixture.store.Append(ctx, fixture.event(t, "event_a2", 2)); err != nil || !inserted {
		t.Fatalf("append boot-a sequence 2 = %v, %v", inserted, err)
	}
	bootB := fixture.event(t, "event_b1", 1)
	bootB.BootID = "boot_two"
	if err := events.SignAt(&bootB, fixture.node.ID, fixture.privateKey, fixture.now); err != nil {
		t.Fatal(err)
	}
	if inserted, err := fixture.store.Append(ctx, bootB); err != nil || !inserted {
		t.Fatalf("append boot-b reset = %v, %v", inserted, err)
	}
	reused := fixture.event(t, "event_reused_boot", 3)
	if _, err := fixture.store.Append(ctx, reused); !errors.Is(err, storage.ErrEventBootRegression) {
		t.Fatalf("reused boot error = %v", err)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
