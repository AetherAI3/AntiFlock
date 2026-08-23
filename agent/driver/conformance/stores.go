package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
)

// ReservationStoreFactory returns a fresh, empty store with both floors at
// zero.
type ReservationStoreFactory func(t *testing.T) driver.ReservationStore

// JournalFactory returns a fresh, empty journal.
type JournalFactory func(t *testing.T) driver.Journal

// RunReservationStore is the executable contract for driver.ReservationStore
// implementations. A durable store must also pass it after being reopened
// over the same backing; the factory decides what "fresh" means.
func RunReservationStore(t *testing.T, factory ReservationStoreFactory) {
	t.Helper()
	if factory == nil {
		t.Fatal("reservation store factory is required")
	}
	ctx := context.Background()
	key := func(planID string, policy, plan uint64) driver.ReservationKey {
		return driver.ReservationKey{PlanID: planID, PolicyRevision: policy, PlanRevision: plan, Nonce: "6e", Fingerprint: "fp"}
	}

	t.Run("reserve release replay", func(t *testing.T) {
		store := factory(t)
		first, err := store.Reserve(ctx, key("plan-a", 3, 5))
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if first.Replayed || first.Token.Validate() != nil {
			t.Fatalf("fresh reservation = %+v, want new valid token", first)
		}
		if _, err := store.Reserve(ctx, key("plan-a", 3, 5)); !errors.Is(err, driver.ErrAlreadyReserved) {
			t.Fatalf("same key while in progress: err = %v, want ErrAlreadyReserved", err)
		}
		if _, err := store.Reserve(ctx, key("plan-a", 3, 6)); !errors.Is(err, driver.ErrAlreadyReserved) {
			t.Fatalf("same plan id under a new key: err = %v, want ErrAlreadyReserved", err)
		}
		if err := store.Release(ctx, first.Token, driver.StepApply, nil); !errors.Is(err, driver.ErrReservationNotTerminal) {
			t.Fatalf("release at non-terminal step: err = %v, want ErrReservationNotTerminal", err)
		}
		forged := first.Token
		forged.Token = strings.Repeat("0", 64)
		if err := store.Release(ctx, forged, driver.StepCommit, nil); !errors.Is(err, driver.ErrReservationInvalid) {
			t.Fatalf("release with a forged token: err = %v, want ErrReservationInvalid", err)
		}
		result := []byte("signed-result")
		if err := store.Release(ctx, first.Token, driver.StepCommit, result); err != nil {
			t.Fatalf("release: %v", err)
		}
		if err := store.Release(ctx, first.Token, driver.StepCommit, result); err != nil {
			t.Fatalf("idempotent release: %v", err)
		}
		if err := store.Release(ctx, first.Token, driver.StepRollback, result); !errors.Is(err, driver.ErrReservationConflict) {
			t.Fatalf("release with a different terminal: err = %v, want ErrReservationConflict", err)
		}
		if err := store.Release(ctx, first.Token, driver.StepCommit, []byte("other")); !errors.Is(err, driver.ErrReservationConflict) {
			t.Fatalf("release with a different result: err = %v, want ErrReservationConflict", err)
		}
		replay, err := store.Reserve(ctx, key("plan-a", 3, 5))
		if err != nil {
			t.Fatalf("identical redelivery after release: %v", err)
		}
		if !replay.Replayed || replay.Terminal != driver.StepCommit || string(replay.Result) != "signed-result" || replay.Token.Token != first.Token.Token {
			t.Fatalf("redelivery = %+v, want the stored terminal result", replay)
		}
		if _, err := store.Reserve(ctx, key("plan-a", 3, 6)); !errors.Is(err, driver.ErrAlreadyReserved) {
			t.Fatalf("released plan id under a new key: err = %v, want ErrAlreadyReserved", err)
		}
		unknown := first.Token
		unknown.Key.PlanID = "plan-z"
		unknown.Token, _ = unknown.Key.Digest()
		if err := store.Release(ctx, unknown, driver.StepCommit, nil); !errors.Is(err, driver.ErrReservationUnknown) {
			t.Fatalf("release of an unknown token: err = %v, want ErrReservationUnknown", err)
		}
	})

	t.Run("plan revision floor", func(t *testing.T) {
		store := factory(t)
		if _, err := store.Reserve(ctx, key("plan-a", 1, 5)); err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if _, err := store.Reserve(ctx, key("plan-b", 1, 5)); !errors.Is(err, driver.ErrStaleRevision) {
			t.Fatalf("plan revision at floor: err = %v, want ErrStaleRevision", err)
		}
		if _, err := store.Reserve(ctx, key("plan-b", 1, 4)); !errors.Is(err, driver.ErrStaleRevision) {
			t.Fatalf("plan revision below floor: err = %v, want ErrStaleRevision", err)
		}
		if _, err := store.Reserve(ctx, key("plan-b", 1, 6)); err != nil {
			t.Fatalf("plan revision above floor: %v", err)
		}
		floor, err := store.Floor(ctx)
		if err != nil || floor.PlanRevision != 6 || floor.PolicyRevision != 1 {
			t.Fatalf("floor = %+v (%v), want policy 1 plan 6", floor, err)
		}
	})

	t.Run("policy revision floor", func(t *testing.T) {
		store := factory(t)
		if _, err := store.Reserve(ctx, key("plan-a", 7, 1)); err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if _, err := store.Reserve(ctx, key("plan-b", 6, 2)); !errors.Is(err, driver.ErrStaleRevision) {
			t.Fatalf("policy revision below floor: err = %v, want ErrStaleRevision", err)
		}
		if _, err := store.Reserve(ctx, key("plan-b", 7, 2)); err != nil {
			t.Fatalf("policy revision at floor with a newer plan revision: %v", err)
		}
		if _, err := store.Reserve(ctx, key("plan-c", 9, 3)); err != nil {
			t.Fatalf("policy revision above floor: %v", err)
		}
		if _, err := store.Reserve(ctx, key("plan-d", 8, 4)); !errors.Is(err, driver.ErrStaleRevision) {
			t.Fatalf("policy revision below the moved floor: err = %v, want ErrStaleRevision", err)
		}
		floor, err := store.Floor(ctx)
		if err != nil || floor.PolicyRevision != 9 || floor.PlanRevision != 3 {
			t.Fatalf("floor = %+v (%v), want policy 9 plan 3", floor, err)
		}
	})

	t.Run("invalid key and expired context", func(t *testing.T) {
		store := factory(t)
		if _, err := store.Reserve(ctx, key("", 1, 1)); !errors.Is(err, driver.ErrReservationInvalid) {
			t.Fatalf("empty plan id: err = %v, want ErrReservationInvalid", err)
		}
		if _, err := store.Reserve(ctx, key("plan-a", 0, 1)); !errors.Is(err, driver.ErrReservationInvalid) {
			t.Fatalf("zero policy revision: err = %v, want ErrReservationInvalid", err)
		}
		expired, cancel := context.WithDeadline(ctx, time.Unix(0, 0))
		defer cancel()
		if _, err := store.Reserve(expired, key("plan-a", 1, 1)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expired context: err = %v, want DeadlineExceeded", err)
		}
		oversized := make([]byte, driver.MaxReservationResultBytes+1)
		fresh, err := store.Reserve(ctx, key("plan-a", 1, 1))
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := store.Release(ctx, fresh.Token, driver.StepCommit, oversized); !errors.Is(err, driver.ErrInvalidRequest) {
			t.Fatalf("oversized result: err = %v, want ErrInvalidRequest", err)
		}
	})
}

func journalRecord(step driver.Step, at time.Time) driver.JournalRecord {
	return driver.JournalRecord{
		SchemaVersion: driver.ContractVersion, PlanID: "plan", PlanRevision: 1, OperationID: "op", Step: step, At: at,
	}
}

// RunJournal is the executable contract for driver.Journal implementations.
func RunJournal(t *testing.T, factory JournalFactory) {
	t.Helper()
	if factory == nil {
		t.Fatal("journal factory is required")
	}
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	t.Run("begin advance finish", func(t *testing.T) {
		journal := factory(t)
		if err := journal.Begin(ctx, journalRecord(driver.StepCapture, at)); err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := journal.Begin(ctx, journalRecord(driver.StepCapture, at)); !errors.Is(err, driver.ErrJournalActive) {
			t.Fatalf("duplicate begin: err = %v, want ErrJournalActive", err)
		}
		if err := journal.Advance(ctx, journalRecord(driver.StepCapture, at)); !errors.Is(err, driver.ErrJournalOrder) {
			t.Fatalf("advance to same step: err = %v, want ErrJournalOrder", err)
		}
		full := journalRecord(driver.StepApply, at)
		full.Target = "protected-egress"
		full.Reservation = driver.ReservationKey{PlanID: "plan", PolicyRevision: 1, PlanRevision: 1, Nonce: "6e", Fingerprint: "fp"}
		full.OwnershipToken = strings.Repeat("a", 64)
		full.Digest = strings.Repeat("b", 64)
		if err := journal.Advance(ctx, full); err != nil {
			t.Fatalf("advance: %v", err)
		}
		if err := journal.Advance(ctx, journalRecord(driver.StepSimulate, at)); !errors.Is(err, driver.ErrJournalOrder) {
			t.Fatalf("advance backwards: err = %v, want ErrJournalOrder", err)
		}
		inFlight, err := journal.InFlight(ctx)
		if err != nil || len(inFlight) != 1 {
			t.Fatalf("in-flight = %+v (%v), want one APPLY", inFlight, err)
		}
		full.Kind = driver.JournalKindAdvance
		if inFlight[0] != full {
			t.Fatalf("in-flight record = %+v, want %+v (target and reservation must round-trip)", inFlight[0], full)
		}
		if err := journal.Finish(ctx, journalRecord(driver.StepApply, at)); !errors.Is(err, driver.ErrInvalidRequest) {
			t.Fatalf("finish at non-terminal step: err = %v, want ErrInvalidRequest", err)
		}
		if err := journal.Finish(ctx, journalRecord(driver.StepCommit, at)); err != nil {
			t.Fatalf("finish: %v", err)
		}
		if err := journal.Finish(ctx, journalRecord(driver.StepCommit, at)); !errors.Is(err, driver.ErrJournalInactive) {
			t.Fatalf("double finish: err = %v, want ErrJournalInactive", err)
		}
		inFlight, err = journal.InFlight(ctx)
		if err != nil || len(inFlight) != 0 {
			t.Fatalf("in-flight after finish = %+v (%v), want none", inFlight, err)
		}
		records, err := journal.Records(ctx)
		if err != nil || len(records) != 3 {
			t.Fatalf("records = %d (%v), want 3", len(records), err)
		}
	})

	t.Run("advance without begin", func(t *testing.T) {
		journal := factory(t)
		if err := journal.Advance(ctx, journalRecord(driver.StepApply, at)); !errors.Is(err, driver.ErrJournalInactive) {
			t.Fatalf("err = %v, want ErrJournalInactive", err)
		}
	})

	t.Run("invalid record", func(t *testing.T) {
		journal := factory(t)
		for name, mutate := range map[string]func(*driver.JournalRecord){
			"empty plan id":   func(r *driver.JournalRecord) { r.PlanID = "" },
			"bad digest":      func(r *driver.JournalRecord) { r.Digest = "not-hex" },
			"hostile target":  func(r *driver.JournalRecord) { r.Target = "eth0;rm" },
			"bad reservation": func(r *driver.JournalRecord) { r.Reservation = driver.ReservationKey{PlanID: "plan"} },
			"zero time":       func(r *driver.JournalRecord) { r.At = time.Time{} },
		} {
			bad := journalRecord(driver.StepCapture, at)
			mutate(&bad)
			if err := journal.Begin(ctx, bad); !errors.Is(err, driver.ErrInvalidRequest) && !errors.Is(err, driver.ErrUnsafeTarget) && !errors.Is(err, driver.ErrReservationInvalid) {
				t.Fatalf("%s: err = %v, want a validation error", name, err)
			}
		}
		if inFlight, err := journal.InFlight(ctx); err != nil || len(inFlight) != 0 {
			t.Fatalf("invalid records were journalled: %+v (%v)", inFlight, err)
		}
	})

	t.Run("expired context", func(t *testing.T) {
		journal := factory(t)
		expired, cancel := context.WithDeadline(ctx, time.Unix(0, 0))
		defer cancel()
		if err := journal.Begin(expired, journalRecord(driver.StepCapture, at)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want DeadlineExceeded", err)
		}
	})

	t.Run("compaction keeps open entries", func(t *testing.T) {
		journal := factory(t)
		open := journalRecord(driver.StepApply, at)
		open.OperationID = "op-open"
		if err := journal.Begin(ctx, open); err != nil {
			t.Fatalf("begin open: %v", err)
		}
		for i := 0; i < driver.JournalCompactionThreshold/2+2; i++ {
			record := journalRecord(driver.StepCapture, at)
			record.PlanRevision = uint64(i + 1)
			if err := journal.Begin(ctx, record); err != nil {
				t.Fatalf("begin %d: %v", i, err)
			}
			record.Step = driver.StepCommit
			if err := journal.Finish(ctx, record); err != nil {
				t.Fatalf("finish %d: %v", i, err)
			}
		}
		records, err := journal.Records(ctx)
		if err != nil || len(records) > driver.JournalCompactionThreshold {
			t.Fatalf("records after compaction = %d (%v), want <= %d", len(records), err, driver.JournalCompactionThreshold)
		}
		inFlight, err := journal.InFlight(ctx)
		if err != nil || len(inFlight) != 1 || inFlight[0].OperationID != "op-open" {
			t.Fatalf("open entry lost by compaction: %+v (%v)", inFlight, err)
		}
	})
}
