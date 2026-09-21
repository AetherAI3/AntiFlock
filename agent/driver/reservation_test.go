package driver_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DBarr3/AntiFlock/agent/driver"
	"github.com/DBarr3/AntiFlock/agent/driver/conformance"
)

func TestMemoryReservationStoreConformance(t *testing.T) {
	t.Parallel()
	conformance.RunReservationStore(t, func(t *testing.T) driver.ReservationStore {
		return driver.NewMemoryReservationStore(0, 0, fixedClock())
	})
}

func TestMemoryReservationStoreStartsAtGivenFloors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := driver.NewMemoryReservationStore(4, 5, fixedClock())
	floor, err := store.Floor(ctx)
	if err != nil || floor.PolicyRevision != 4 || floor.PlanRevision != 5 {
		t.Fatalf("floor = %+v (%v), want policy 4 plan 5", floor, err)
	}
	if _, err := store.Reserve(ctx, driver.ReservationKey{PlanID: "a", PolicyRevision: 3, PlanRevision: 6, Nonce: "6e", Fingerprint: "fp"}); !errors.Is(err, driver.ErrStaleRevision) {
		t.Fatalf("policy below initial floor: err = %v, want ErrStaleRevision", err)
	}
	if _, err := store.Reserve(ctx, driver.ReservationKey{PlanID: "a", PolicyRevision: 4, PlanRevision: 5, Nonce: "6e", Fingerprint: "fp"}); !errors.Is(err, driver.ErrStaleRevision) {
		t.Fatalf("plan at initial floor: err = %v, want ErrStaleRevision", err)
	}
	if _, err := store.Reserve(ctx, driver.ReservationKey{PlanID: "a", PolicyRevision: 4, PlanRevision: 6, Nonce: "6e", Fingerprint: "fp"}); err != nil {
		t.Fatalf("reserve above floors: %v", err)
	}
}

func TestReservationKeyDigestBindsPolicyRevision(t *testing.T) {
	t.Parallel()
	key := driver.ReservationKey{PlanID: "plan", PolicyRevision: 1, PlanRevision: 2, Nonce: "6e", Fingerprint: "fp"}
	first, err := key.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	key.PolicyRevision = 2
	second, err := key.Digest()
	if err != nil || first == second {
		t.Fatalf("digest ignores policy revision (%v)", err)
	}
	key.PolicyRevision = 0
	if _, err := key.Digest(); !errors.Is(err, driver.ErrReservationInvalid) {
		t.Fatalf("zero policy revision: err = %v, want ErrReservationInvalid", err)
	}
}
