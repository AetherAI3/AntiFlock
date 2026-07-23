package nano_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/nano"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

func TestStorageCursorStoreSurvivesReopen(t *testing.T) {
	ctx := context.Background(); now := time.Now().UTC(); path := filepath.Join(t.TempDir(), "core.db")
	database, err := storage.Open(ctx, path); if err != nil { t.Fatal(err) }
	enrollNanoCursorNode(t, database, now)
	store, err := nano.NewStorageCursorStore(database, func() time.Time { return now }); if err != nil { t.Fatal(err) }
	digest := "sha256:012345678901234567890123456789012345678901234567890123456789abcd"
	if err := store.Save(ctx, digest, "node-test", nano.Cursor{Initialized: true, NextDueUnix: 42}); err != nil { t.Fatal(err) }
	if err := database.Close(); err != nil { t.Fatal(err) }
	database, err = storage.Open(ctx, path); if err != nil { t.Fatal(err) }; defer database.Close()
	store, err = nano.NewStorageCursorStore(database, func() time.Time { return now }); if err != nil { t.Fatal(err) }
	cursor, err := store.Load(ctx, digest, "node-test")
	if err != nil || !cursor.Initialized || cursor.NextDueUnix != 42 { t.Fatalf("cursor=%#v err=%v", cursor, err) }
}

func enrollNanoCursorNode(t *testing.T, database *storage.DB, now time.Time) {
	t.Helper(); secret := sha256.Sum256([]byte("nano-cursor-token"))
	if err := database.CreateEnrollmentToken(context.Background(), storage.EnrollmentTokenRecord{
		ID: "nano-cursor-token", Hash: secret[:], ScopeJSON: json.RawMessage(`{}`), CreatedByPrincipalID: "operator", OperationID: "nano-cursor-token", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}); err != nil { t.Fatal(err) }
	if err := database.EnrollNode(context.Background(), secret[:], now, model.Node{ID: "node-test", Name: "Test", Type: "NODE_TYPE_AGENT", Platform: "linux", PlatformVersion: "test", Status: model.NodeActive, CapabilitiesVerification: "CLAIMED", PublicKey: []byte("key"), CertificatePEM: "certificate", EnrolledAt: now}); err != nil { t.Fatal(err) }
}
