package driver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
)

func TestMemoryReservationStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := driver.NewMemoryReservationStore(5, fixedClock())
	key := driver.ReservationKey{PlanID: "plan-a", PlanRevision: 6, Nonce: "6e", Fingerprint: "fp"}
	token, err := store.Reserve(ctx, key)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := token.Validate(); err != nil {
		t.Fatalf("token invalid: %v", err)
	}
	if _, err := store.Reserve(ctx, key); !errors.Is(err, driver.ErrAlreadyReserved) {
		t.Fatalf("same key: err = %v, want ErrAlreadyReserved", err)
	}
	rekeyed := key
	rekeyed.Nonce = "6f"
	rekeyed.PlanRevision = 7
	if _, err := store.Reserve(ctx, rekeyed); !errors.Is(err, driver.ErrAlreadyReserved) {
		t.Fatalf("same plan id, new key: err = %v, want ErrAlreadyReserved", err)
	}
	if _, err := store.Reserve(ctx, driver.ReservationKey{PlanID: "plan-b", PlanRevision: 6, Nonce: "70", Fingerprint: "fp"}); !errors.Is(err, driver.ErrStaleRevision) {
		t.Fatalf("revision at floor: err = %v, want ErrStaleRevision", err)
	}
	if _, err := store.Reserve(ctx, driver.ReservationKey{PlanID: "plan-b", PlanRevision: 3, Nonce: "70", Fingerprint: "fp"}); !errors.Is(err, driver.ErrStaleRevision) {
		t.Fatalf("revision below floor: err = %v, want ErrStaleRevision", err)
	}
	if floor, err := store.Floor(ctx); err != nil || floor != 6 {
		t.Fatalf("floor = %d (%v), want 6", floor, err)
	}
	if err := store.Release(ctx, token, driver.StepApply); !errors.Is(err, driver.ErrReservationNotTerminal) {
		t.Fatalf("release at non-terminal step: err = %v, want ErrReservationNotTerminal", err)
	}
	forged := token
	forged.Token = "0000"
	if err := store.Release(ctx, forged, driver.StepCommit); !errors.Is(err, driver.ErrReservationInvalid) {
		t.Fatalf("release with a forged token: err = %v, want ErrReservationInvalid", err)
	}
	if err := store.Release(ctx, token, driver.StepCommit); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := store.Release(ctx, token, driver.StepCommit); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	if err := store.Release(ctx, token, driver.StepRollback); !errors.Is(err, driver.ErrReservationUnknown) {
		t.Fatalf("release with a different terminal: err = %v, want ErrReservationUnknown", err)
	}
	if _, err := store.Reserve(ctx, key); !errors.Is(err, driver.ErrAlreadyReserved) {
		t.Fatalf("replay after release: err = %v, want ErrAlreadyReserved", err)
	}
	if _, err := store.Reserve(ctx, driver.ReservationKey{PlanID: "", PlanRevision: 8, Nonce: "70", Fingerprint: "fp"}); !errors.Is(err, driver.ErrReservationInvalid) {
		t.Fatalf("invalid key: err = %v, want ErrReservationInvalid", err)
	}
	expired, cancel := context.WithDeadline(ctx, time.Unix(0, 0))
	defer cancel()
	if _, err := store.Reserve(expired, driver.ReservationKey{PlanID: "plan-c", PlanRevision: 8, Nonce: "70", Fingerprint: "fp"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired context: err = %v, want DeadlineExceeded", err)
	}
}
