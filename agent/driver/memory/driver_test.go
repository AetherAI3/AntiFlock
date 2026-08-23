package memory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	"github.com/DBarr3/AntiFlock/agent/driver/conformance"
	"github.com/DBarr3/AntiFlock/agent/driver/memory"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

func fixedClock() func() time.Time {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		now = now.Add(time.Millisecond)
		return now
	}
}

func newDriver(t *testing.T) *memory.Driver {
	t.Helper()
	backing, err := memory.NewBacking(driver.NewMemoryJournal())
	if err != nil {
		t.Fatalf("backing: %v", err)
	}
	instance, err := memory.New(memory.Config{Backing: backing, Clock: fixedClock()})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	return instance
}

func TestConformance(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, func(t *testing.T) driver.Driver { return newDriver(t) })
}

func TestConformanceOverFileJournal(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, func(t *testing.T) driver.Driver {
		journal, err := driver.NewFileJournal(t.TempDir())
		if err != nil {
			t.Fatalf("file journal: %v", err)
		}
		backing, err := memory.NewBacking(journal)
		if err != nil {
			t.Fatalf("backing: %v", err)
		}
		instance, err := memory.New(memory.Config{Backing: backing, Clock: fixedClock()})
		if err != nil {
			t.Fatalf("driver: %v", err)
		}
		return instance
	})
}

func TestCorruptJournalMakesDriverUnavailable(t *testing.T) {
	t.Parallel()
	journal := driver.NewMemoryJournal()
	backing, err := memory.NewBacking(journal)
	if err != nil {
		t.Fatalf("backing: %v", err)
	}
	instance, err := memory.New(memory.Config{Backing: backing, Clock: fixedClock()})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	journal.Corrupt()
	health, err := instance.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if health.Status != driver.HealthUnavailable || len(health.ReasonCodes) != 1 || health.ReasonCodes[0] != driver.ReasonProbeJournalCorrupt {
		t.Fatalf("health = %s %v, want UNAVAILABLE AF-PROBE-JOURNAL-CORRUPT", health.Status, health.ReasonCodes)
	}
	results, err := instance.Probe(context.Background())
	if err != nil || len(results) != 1 || results[0].Health != driver.HealthUnavailable || results[0].RecoveryReady {
		t.Fatalf("probe = %+v (%v), want UNAVAILABLE and not recovery-ready", results, err)
	}
	if _, err := instance.Recover(context.Background()); !errors.Is(err, driver.ErrJournalCorrupt) {
		t.Fatalf("recover over a corrupt journal: err = %v, want ErrJournalCorrupt", err)
	}
	request := validApplyRequest(t)
	if err := request.Validate(); err != nil {
		t.Fatalf("fixture request must be valid so the refusal is due to the journal alone: %v", err)
	}
	before := backing.Rules()
	if _, err := instance.Apply(context.Background(), request); !errors.Is(err, driver.ErrJournalCorrupt) {
		t.Fatalf("valid apply over a corrupt journal: err = %v, want ErrJournalCorrupt", err)
	}
	if len(backing.Rules()) != len(before) {
		t.Fatal("apply over a corrupt journal mutated the fake host")
	}
	rollback := driver.RollbackRequest{PlanID: "plan", PlanRevision: 1, OperationID: "op", OwnershipToken: strings.Repeat("a", 64), Timeout: time.Second}
	if _, err := instance.Rollback(context.Background(), rollback); !errors.Is(err, driver.ErrJournalCorrupt) {
		t.Fatalf("rollback over a corrupt journal: err = %v, want ErrJournalCorrupt", err)
	}
}

func validApplyRequest(t *testing.T) driver.ApplyRequest {
	t.Helper()
	key := driver.ReservationKey{PlanID: "plan", PolicyRevision: 1, PlanRevision: 1, Nonce: "6e", Fingerprint: "fp"}
	digest, err := key.Digest()
	if err != nil {
		t.Fatalf("key digest: %v", err)
	}
	return driver.ApplyRequest{
		PlanID: "plan", PlanRevision: 1, OperationID: "op", Target: "protected-egress",
		Operation:   &antiflockv1.PlanOperation{Id: "op", Type: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, Target: "protected-egress"},
		Reservation: driver.ReservationToken{Key: key, Token: digest, IssuedAt: time.Unix(1, 0)}, Timeout: time.Second,
	}
}

func TestDriverRejectsEmptyRecoveryPathsInProbe(t *testing.T) {
	t.Parallel()
	backing, err := memory.NewBacking(driver.NewMemoryJournal())
	if err != nil {
		t.Fatalf("backing: %v", err)
	}
	instance, err := memory.New(memory.Config{Backing: backing, Clock: fixedClock(), RecoveryPaths: []driver.RecoveryPath{}})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	results, err := instance.Probe(context.Background())
	if err != nil || len(results) != 1 || results[0].RecoveryReady {
		t.Fatalf("probe with no recovery paths = %+v (%v), want RecoveryReady=false", results, err)
	}
}
