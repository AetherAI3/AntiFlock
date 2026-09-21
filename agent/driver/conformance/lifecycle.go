package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
)

// lifecycleHarness is one Lifecycle over a factory driver with in-memory
// orchestration stores. The stores are kept so a "restarted" Lifecycle can be
// built over the same journal, reservations and receipts.
type lifecycleHarness struct {
	driver       driver.Driver
	journal      *driver.MemoryJournal
	reservations *driver.MemoryReservationStore
	receipts     *driver.MemoryReceiptStore
	clock        func() time.Time
	lifecycle    *driver.Lifecycle
}

func conformanceClock() func() time.Time {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		now = now.Add(time.Millisecond)
		return now
	}
}

func newLifecycleHarness(t *testing.T, instance driver.Driver) *lifecycleHarness {
	t.Helper()
	harness := &lifecycleHarness{
		driver: instance, journal: driver.NewMemoryJournal(), reservations: driver.NewMemoryReservationStore(0, 0, nil),
		receipts: driver.NewMemoryReceiptStore(), clock: conformanceClock(),
	}
	harness.lifecycle = harness.newLifecycle(t, instance)
	return harness
}

func (harness *lifecycleHarness) newLifecycle(t *testing.T, instance driver.Driver) *driver.Lifecycle {
	t.Helper()
	lifecycle, err := driver.NewLifecycle(driver.LifecycleConfig{
		Driver: instance, Journal: harness.journal, Reservations: harness.reservations, Receipts: harness.receipts, Clock: harness.clock,
	})
	if err != nil {
		t.Fatalf("lifecycle: %v", err)
	}
	return lifecycle
}

// restart models process death: a fresh Lifecycle over the same durable
// orchestration stores and a reopened driver.
func (harness *lifecycleHarness) restart(t *testing.T) *lifecycleHarness {
	t.Helper()
	reopener, ok := harness.driver.(driver.Reopener)
	if !ok {
		t.Fatal("driver must implement driver.Reopener for lifecycle crash conformance")
	}
	fresh, err := reopener.Reopen()
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	restarted := *harness
	restarted.driver = fresh
	restarted.lifecycle = harness.newLifecycle(t, fresh)
	return &restarted
}

func lifecycleApproval(t *testing.T) driver.Approval {
	t.Helper()
	digest, err := driver.ApprovalDigest(planID, 1, operationID, target, "conformance")
	if err != nil {
		t.Fatalf("approval digest: %v", err)
	}
	return driver.Approval{PlanID: planID, PlanRevision: 1, OperationID: operationID, Target: target, ApproverKind: "conformance", Digest: digest}
}

// driveTo runs the happy path up to and including the named state.
func (harness *lifecycleHarness) driveTo(t *testing.T, until driver.LifecycleState) {
	t.Helper()
	ctx := context.Background()
	steps := []struct {
		state driver.LifecycleState
		run   func() error
	}{
		{driver.StateBegun, func() error {
			return harness.lifecycle.Begin(ctx, driver.PlanRef{PlanID: planID, PlanRevision: 1, OperationID: operationID})
		}},
		{driver.StateCaptured, func() error { _, err := harness.lifecycle.Capture(ctx, scope()); return err }},
		{driver.StateSimulated, func() error { _, err := harness.lifecycle.Simulate(ctx, operation(operationID, target)); return err }},
		{driver.StateApproved, func() error { return harness.lifecycle.Approve(ctx, lifecycleApproval(t)) }},
		{driver.StateReserved, func() error { _, err := harness.lifecycle.Reserve(ctx, reservation(t, 1).Key); return err }},
		{driver.StateApplied, func() error { _, err := harness.lifecycle.Apply(ctx); return err }},
		{driver.StateVerified, func() error { _, err := harness.lifecycle.Verify(ctx); return err }},
		{driver.StateRecorded, func() error { return harness.lifecycle.Record(ctx) }},
		{driver.StateCommitted, func() error { return harness.lifecycle.Commit(ctx) }},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			t.Fatalf("reach %s: %v", step.state, err)
		}
		if got := harness.lifecycle.State(); got != step.state {
			t.Fatalf("state = %s, want %s", got, step.state)
		}
		if step.state == until {
			return
		}
	}
}

func (harness *lifecycleHarness) receiptKinds(t *testing.T) []driver.ReceiptKind {
	t.Helper()
	receipts, err := harness.receipts.List(context.Background(), planID)
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	kinds := make([]driver.ReceiptKind, 0, len(receipts))
	for _, receipt := range receipts {
		kinds = append(kinds, receipt.Kind)
	}
	return kinds
}

func expectKinds(t *testing.T, got, want []driver.ReceiptKind) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("receipt kinds = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("receipt kinds = %v, want %v", got, want)
		}
	}
}

func expectReservationReleased(t *testing.T, harness *lifecycleHarness, terminal driver.Step) {
	t.Helper()
	replay, err := harness.reservations.Reserve(context.Background(), reservation(t, 1).Key)
	if err != nil || !replay.Replayed || replay.Terminal != terminal {
		t.Fatalf("reservation after %s: %+v (%v), want released at %s", terminal, replay, err, terminal)
	}
}

func testLifecycleCommit(t *testing.T, factory Factory) {
	harness := newLifecycleHarness(t, factory(t))
	before := digestOf(t, harness.driver, scope(target))
	harness.driveTo(t, driver.StateCommitted)
	if digestOf(t, harness.driver, scope(target)) == before {
		t.Fatal("lifecycle commit left the host unchanged")
	}
	expectKinds(t, harness.receiptKinds(t), []driver.ReceiptKind{driver.ReceiptKindApply, driver.ReceiptKindVerify, driver.ReceiptKindCommit})
	expectReservationReleased(t, harness, driver.StepCommit)
	if inFlight, err := harness.journal.InFlight(context.Background()); err != nil || len(inFlight) != 0 {
		t.Fatalf("journal in-flight after commit = %+v (%v)", inFlight, err)
	}
	health, err := harness.lifecycle.Health(context.Background())
	if err != nil || health.Status != driver.HealthHealthy {
		t.Fatalf("health after commit = %s (%v), want HEALTHY", health.Status, err)
	}
	report, err := harness.lifecycle.Recover(context.Background())
	if err != nil || len(report.Operations) != 0 {
		t.Fatalf("recover after commit = %+v (%v), want clean", report, err)
	}
}

func testLifecycleRollback(t *testing.T, factory Factory) {
	harness := newLifecycleHarness(t, factory(t))
	before := digestOf(t, harness.driver, scope(target))
	harness.driveTo(t, driver.StateVerified)
	receipt, err := harness.lifecycle.Rollback(context.Background())
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if receipt.AlreadyRolledBack || digestOf(t, harness.driver, scope(target)) != before {
		t.Fatal("lifecycle rollback did not restore the host")
	}
	expectKinds(t, harness.receiptKinds(t), []driver.ReceiptKind{driver.ReceiptKindRollback})
	expectReservationReleased(t, harness, driver.StepRollback)
	if err := harness.lifecycle.Begin(context.Background(), driver.PlanRef{PlanID: "plan-next", PlanRevision: 2, OperationID: operationID}); err != nil {
		t.Fatalf("begin after rollback: %v", err)
	}
}

// testLifecycleCrashRecoverCommit kills the process after the driver applied
// and the lifecycle journalled the receipt but before Verify/Record/Commit.
// Recovery must verify the host and complete the plan.
func testLifecycleCrashRecoverCommit(t *testing.T, factory Factory) {
	harness := newLifecycleHarness(t, factory(t))
	before := digestOf(t, harness.driver, scope(target))
	harness.driveTo(t, driver.StateApplied)
	applied := digestOf(t, harness.driver, scope(target))
	restarted := harness.restart(t)
	health, err := restarted.lifecycle.Health(context.Background())
	if err != nil || health.Status == driver.HealthHealthy {
		t.Fatalf("health with an open lifecycle entry = %s (%v), want not HEALTHY", health.Status, err)
	}
	if err := restarted.lifecycle.Begin(context.Background(), driver.PlanRef{PlanID: "plan-next", PlanRevision: 2, OperationID: operationID}); !errors.Is(err, driver.ErrRecoveryPending) {
		t.Fatalf("begin with recovery pending: err = %v, want ErrRecoveryPending", err)
	}
	report, err := restarted.lifecycle.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(report.Operations) != 1 || !report.Operations[0].Finished || report.Operations[0].Reverted {
		t.Fatalf("recovery = %+v, want one finished, non-reverted operation", report.Operations)
	}
	if len(report.ReasonCodes) != 1 || report.ReasonCodes[0] != driver.ReasonRecoveryCommit {
		t.Fatalf("recovery reason codes = %v, want [%s]", report.ReasonCodes, driver.ReasonRecoveryCommit)
	}
	if digestOf(t, restarted.driver, scope(target)) != applied || applied == before {
		t.Fatal("recovery did not keep the verified apply")
	}
	expectKinds(t, restarted.receiptKinds(t), []driver.ReceiptKind{driver.ReceiptKindApply, driver.ReceiptKindVerify, driver.ReceiptKindCommit})
	expectReservationReleased(t, restarted, driver.StepCommit)
	again, err := restarted.lifecycle.Recover(context.Background())
	if err != nil || len(again.Operations) != 0 {
		t.Fatalf("second recover = %+v (%v), want clean", again, err)
	}
	health, err = restarted.lifecycle.Health(context.Background())
	if err != nil || health.Status != driver.HealthHealthy {
		t.Fatalf("health after recovery = %s (%v), want HEALTHY", health.Status, err)
	}
	if err := restarted.lifecycle.Begin(context.Background(), driver.PlanRef{PlanID: "plan-next", PlanRevision: 2, OperationID: operationID}); err != nil {
		t.Fatalf("begin after recovery: %v", err)
	}
}

// testLifecycleCrashRecoverRollback kills the process inside the driver's
// Apply (host mutated, driver journal open, lifecycle journal at APPLY).
// Recovery must revert the host and release the reservation.
func testLifecycleCrashRecoverRollback(t *testing.T, factory Factory) {
	instance := factory(t)
	crasher, ok := instance.(driver.CrashSimulator)
	if !ok {
		t.Fatal("driver must implement driver.CrashSimulator for lifecycle crash conformance")
	}
	harness := newLifecycleHarness(t, instance)
	before := digestOf(t, harness.driver, scope(target))
	harness.driveTo(t, driver.StateReserved)
	crasher.InjectCrash()
	if _, err := harness.lifecycle.Apply(context.Background()); !errors.Is(err, driver.ErrCrashInjected) {
		t.Fatalf("apply with injected crash: err = %v, want ErrCrashInjected", err)
	}
	if digestOf(t, harness.driver, scope(target)) == before {
		t.Fatal("injected crash did not leave a partial mutation")
	}
	restarted := harness.restart(t)
	report, err := restarted.lifecycle.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(report.Operations) != 1 || !report.Operations[0].Finished || report.Operations[0].Step != driver.StepApply {
		t.Fatalf("recovery = %+v, want one finished APPLY entry", report.Operations)
	}
	if len(report.ReasonCodes) != 1 || report.ReasonCodes[0] != driver.ReasonRecoveryRollback {
		t.Fatalf("recovery reason codes = %v, want [%s]", report.ReasonCodes, driver.ReasonRecoveryRollback)
	}
	if digestOf(t, restarted.driver, scope(target)) != before {
		t.Fatal("recovery did not restore the pre-apply host")
	}
	expectReservationReleased(t, restarted, driver.StepRollback)
	if _, err := restarted.reservations.Reserve(context.Background(), driver.ReservationKey{PlanID: planID, PolicyRevision: 1, PlanRevision: 2, Nonce: "01", Fingerprint: "fp"}); !errors.Is(err, driver.ErrAlreadyReserved) {
		t.Fatalf("replay after recovery: err = %v, want ErrAlreadyReserved", err)
	}
	again, err := restarted.lifecycle.Recover(context.Background())
	if err != nil || len(again.Operations) != 0 {
		t.Fatalf("second recover = %+v (%v), want clean", again, err)
	}
	if err := restarted.lifecycle.Begin(context.Background(), driver.PlanRef{PlanID: "plan-next", PlanRevision: 2, OperationID: operationID}); err != nil {
		t.Fatalf("begin after recovery: %v", err)
	}
}

func testOwnershipToken(t *testing.T, factory Factory) {
	instance := factory(t)
	request := applyRequest(t, 1, target, operation(operationID, target))
	receipt, err := instance.Apply(context.Background(), request)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	want := driver.OwnershipTokenFor(request.PlanID, request.PlanRevision, request.OperationID, request.Target, request.Reservation.Token)
	if receipt.OwnershipToken != want {
		t.Fatalf("ownership token = %s, want OwnershipTokenFor(request) = %s", receipt.OwnershipToken, want)
	}
}
