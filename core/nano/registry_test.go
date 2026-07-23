package nano_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/nano"
	"github.com/DBarr3/AntiFlock/core/storage"
)

func TestRegistryAdmitsImmutableProgramAndRunsFinding(t *testing.T) {
	ctx := context.Background(); now := time.Unix(100, 0).UTC()
	database, err := storage.Open(ctx, filepath.Join(t.TempDir(), "core.db")); if err != nil { t.Fatal(err) }; defer database.Close()
	enrollNanoCursorNode(t, database, now)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader); if err != nil { t.Fatal(err) }
	auditService, err := audit.New(database, privateKey, filepath.Join(t.TempDir(), "audit.anchor")); if err != nil { t.Fatal(err) }
	registry, err := nano.NewRegistry(database, auditService, func() time.Time { return now }); if err != nil { t.Fatal(err) }
	record, err := registry.Admit(ctx, nano.AdmissionRequest{NodeID: "node-test", Source: probeWatch, BindingID: nano.BindingScramblerSimulation, OperationID: "admit-probe-watch", ActorID: "operator-test"})
	if err != nil || record.ProgramDigest == "" { t.Fatalf("record=%#v err=%v", record, err) }
	replay, err := registry.Admit(ctx, nano.AdmissionRequest{NodeID: "node-test", Source: probeWatch, BindingID: nano.BindingScramblerSimulation, OperationID: "admit-probe-watch", ActorID: "operator-test"})
	if err != nil || replay.ID != record.ID { t.Fatalf("replay=%#v err=%v", replay, err) }
	result, err := registry.RunFinding(ctx, record.ID, nano.FindingContext{FindingID: "finding-404", NodeID: "node-test", ReasonCode: "404 probing", Confidence: .91, ObservedUnix: 100})
	if err != nil || len(result.Proposals) != 1 { t.Fatalf("result=%#v err=%v", result, err) }
	programs, err := registry.List(ctx, "node-test")
	if err != nil || len(programs) != 1 || programs[0].Source != probeWatch { t.Fatalf("programs=%#v err=%v", programs, err) }
}
