package driver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	"github.com/DBarr3/AntiFlock/agent/driver/memory"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	planID      = "plan-lifecycle"
	operationID = "guard-egress"
	target      = "protected-egress"
)

func fixedClock() func() time.Time {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		now = now.Add(time.Millisecond)
		return now
	}
}

type fixture struct {
	lifecycle    *driver.Lifecycle
	driver       *memory.Driver
	journal      *driver.MemoryJournal
	reservations *driver.MemoryReservationStore
	receipts     *driver.MemoryReceiptStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clock := fixedClock()
	backing, err := memory.NewBacking(driver.NewMemoryJournal())
	if err != nil {
		t.Fatalf("backing: %v", err)
	}
	instance, err := memory.New(memory.Config{Backing: backing, Clock: clock})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	fix := &fixture{
		driver: instance, journal: driver.NewMemoryJournal(),
		reservations: driver.NewMemoryReservationStore(0, 0, clock), receipts: driver.NewMemoryReceiptStore(),
	}
	fix.lifecycle, err = driver.NewLifecycle(driver.LifecycleConfig{
		Driver: instance, Journal: fix.journal, Reservations: fix.reservations, Receipts: fix.receipts, Clock: clock,
	})
	if err != nil {
		t.Fatalf("lifecycle: %v", err)
	}
	return fix
}

func operation() *antiflockv1.PlanOperation {
	parameters, _ := structpb.NewStruct(map[string]any{"failMode": "CLOSED"})
	return &antiflockv1.PlanOperation{Id: operationID, Type: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, Target: target, Parameters: parameters}
}

func scope() driver.Scope {
	return driver.Scope{OperationType: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL}
}

func ref(revision uint64) driver.PlanRef {
	return driver.PlanRef{PlanID: planID, PlanRevision: revision, OperationID: operationID}
}

func approval(t *testing.T, revision uint64, boundTarget string) driver.Approval {
	t.Helper()
	digest, err := driver.ApprovalDigest(planID, revision, operationID, boundTarget, "operator")
	if err != nil {
		t.Fatalf("approval digest: %v", err)
	}
	return driver.Approval{PlanID: planID, PlanRevision: revision, OperationID: operationID, Target: boundTarget, ApproverKind: "operator", Digest: digest}
}

func key(revision uint64) driver.ReservationKey {
	return driver.ReservationKey{PlanID: planID, PolicyRevision: 1, PlanRevision: revision, Nonce: "01", Fingerprint: "fp"}
}

// drive runs the happy path up to and including the named state.
func drive(t *testing.T, fix *fixture, until driver.LifecycleState) {
	t.Helper()
	ctx := context.Background()
	steps := []struct {
		state driver.LifecycleState
		run   func() error
	}{
		{driver.StateBegun, func() error { return fix.lifecycle.Begin(ctx, ref(1)) }},
		{driver.StateCaptured, func() error { _, err := fix.lifecycle.Capture(ctx, scope()); return err }},
		{driver.StateSimulated, func() error { _, err := fix.lifecycle.Simulate(ctx, operation()); return err }},
		{driver.StateApproved, func() error { return fix.lifecycle.Approve(ctx, approval(t, 1, target)) }},
		{driver.StateReserved, func() error { _, err := fix.lifecycle.Reserve(ctx, key(1)); return err }},
		{driver.StateApplied, func() error { _, err := fix.lifecycle.Apply(ctx); return err }},
		{driver.StateVerified, func() error { _, err := fix.lifecycle.Verify(ctx); return err }},
		{driver.StateRecorded, func() error { return fix.lifecycle.Record(ctx) }},
		{driver.StateCommitted, func() error { return fix.lifecycle.Commit(ctx) }},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			t.Fatalf("reach %s: %v", step.state, err)
		}
		if got := fix.lifecycle.State(); got != step.state {
			t.Fatalf("state after step = %s, want %s", got, step.state)
		}
		if step.state == until {
			return
		}
	}
}

func TestLifecycleHappyPathCommits(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	drive(t, fix, driver.StateCommitted)
	receipts, err := fix.receipts.List(context.Background(), planID)
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	kinds := make([]driver.ReceiptKind, 0, len(receipts))
	for _, receipt := range receipts {
		kinds = append(kinds, receipt.Kind)
	}
	want := []driver.ReceiptKind{driver.ReceiptKindApply, driver.ReceiptKindVerify, driver.ReceiptKindCommit}
	if len(kinds) != len(want) {
		t.Fatalf("receipt kinds = %v, want %v", kinds, want)
	}
	for index := range want {
		if kinds[index] != want[index] {
			t.Fatalf("receipt kinds = %v, want %v", kinds, want)
		}
	}
	inFlight, err := fix.journal.InFlight(context.Background())
	if err != nil || len(inFlight) != 0 {
		t.Fatalf("journal in-flight after commit = %v (%v), want none", inFlight, err)
	}
	if len(fix.driver.Backing().Rules()) != 1 {
		t.Fatalf("fake host rules = %v, want exactly one", fix.driver.Backing().Rules())
	}
	if _, err := fix.lifecycle.Rollback(context.Background()); !errors.Is(err, driver.ErrLifecycleOrder) {
		t.Fatalf("rollback after commit: err = %v, want ErrLifecycleOrder", err)
	}
}

func TestLifecycleEnforcesOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cases := map[string]struct {
		until driver.LifecycleState
		call  func(fix *fixture) error
	}{
		"capture before begin": {driver.StateIdle, func(fix *fixture) error { _, err := fix.lifecycle.Capture(ctx, scope()); return err }},
		"simulate before capture": {driver.StateBegun, func(fix *fixture) error {
			_, err := fix.lifecycle.Simulate(ctx, operation())
			return err
		}},
		"approve before simulate": {driver.StateCaptured, func(fix *fixture) error { return fix.lifecycle.Approve(ctx, approval(t, 1, target)) }},
		"reserve before approve":  {driver.StateSimulated, func(fix *fixture) error { _, err := fix.lifecycle.Reserve(ctx, key(1)); return err }},
		"apply before reserve":    {driver.StateApproved, func(fix *fixture) error { _, err := fix.lifecycle.Apply(ctx); return err }},
		"apply before approve":    {driver.StateSimulated, func(fix *fixture) error { _, err := fix.lifecycle.Apply(ctx); return err }},
		"verify before apply":     {driver.StateReserved, func(fix *fixture) error { _, err := fix.lifecycle.Verify(ctx); return err }},
		"record before verify":    {driver.StateApplied, func(fix *fixture) error { return fix.lifecycle.Record(ctx) }},
		"commit before record":    {driver.StateVerified, func(fix *fixture) error { return fix.lifecycle.Commit(ctx) }},
		"commit before apply":     {driver.StateReserved, func(fix *fixture) error { return fix.lifecycle.Commit(ctx) }},
	}
	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fix := newFixture(t)
			if testCase.until != driver.StateIdle {
				drive(t, fix, testCase.until)
			}
			err := testCase.call(fix)
			if testCase.until == driver.StateIdle {
				if !errors.Is(err, driver.ErrNoActivePlan) {
					t.Fatalf("err = %v, want ErrNoActivePlan", err)
				}
				return
			}
			if !errors.Is(err, driver.ErrLifecycleOrder) {
				t.Fatalf("err = %v, want ErrLifecycleOrder", err)
			}
			if len(fix.driver.Backing().Rules()) != 0 && testCase.until < driver.StateApplied {
				t.Fatal("out-of-order call mutated the host")
			}
		})
	}
}

func TestLifecycleOnePlanAtATime(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	drive(t, fix, driver.StateReserved)
	if err := fix.lifecycle.Begin(context.Background(), driver.PlanRef{PlanID: "plan-other", PlanRevision: 2, OperationID: operationID}); !errors.Is(err, driver.ErrPlanActive) {
		t.Fatalf("begin while active: err = %v, want ErrPlanActive", err)
	}
	if _, err := fix.lifecycle.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if fix.lifecycle.State() != driver.StateRolledBack {
		t.Fatalf("state = %s, want ROLLED_BACK", fix.lifecycle.State())
	}
	if err := fix.lifecycle.Begin(context.Background(), driver.PlanRef{PlanID: "plan-other", PlanRevision: 2, OperationID: operationID}); err != nil {
		t.Fatalf("begin after terminal: %v", err)
	}
}

func TestLifecycleApprovalMustBindExactPlan(t *testing.T) {
	t.Parallel()
	cases := map[string]func(a driver.Approval) driver.Approval{
		"wrong revision": func(a driver.Approval) driver.Approval {
			return approvalFor(t, a.PlanID, 2, a.OperationID, a.Target, a.ApproverKind)
		},
		"wrong target": func(a driver.Approval) driver.Approval {
			return approvalFor(t, a.PlanID, a.PlanRevision, a.OperationID, "other-target", a.ApproverKind)
		},
		"wrong operation": func(a driver.Approval) driver.Approval {
			return approvalFor(t, a.PlanID, a.PlanRevision, "other-op", a.Target, a.ApproverKind)
		},
		"wrong plan": func(a driver.Approval) driver.Approval {
			return approvalFor(t, "plan-other", a.PlanRevision, a.OperationID, a.Target, a.ApproverKind)
		},
		"forged digest": func(a driver.Approval) driver.Approval { a.Target = "other-target"; return a },
		"no approver":   func(a driver.Approval) driver.Approval { a.ApproverKind = ""; return a },
	}
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fix := newFixture(t)
			drive(t, fix, driver.StateSimulated)
			err := fix.lifecycle.Approve(context.Background(), mutate(approval(t, 1, target)))
			if !errors.Is(err, driver.ErrApprovalMismatch) && !errors.Is(err, driver.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrApprovalMismatch or ErrInvalidRequest", err)
			}
			if fix.lifecycle.State() != driver.StateSimulated {
				t.Fatalf("state = %s, want SIMULATED", fix.lifecycle.State())
			}
		})
	}
}

func approvalFor(t *testing.T, planID string, revision uint64, operationID, target, kind string) driver.Approval {
	t.Helper()
	digest, err := driver.ApprovalDigest(planID, revision, operationID, target, kind)
	if err != nil {
		t.Fatalf("approval digest: %v", err)
	}
	return driver.Approval{PlanID: planID, PlanRevision: revision, OperationID: operationID, Target: target, ApproverKind: kind, Digest: digest}
}

func TestLifecycleRefusesHostDrift(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	drive(t, fix, driver.StateReserved)
	other, err := memory.New(memory.Config{Backing: fix.driver.Backing(), Clock: fixedClock()})
	if err != nil {
		t.Fatalf("second driver: %v", err)
	}
	driftKey := driver.ReservationKey{PlanID: "plan-drift", PolicyRevision: 1, PlanRevision: 9, Nonce: "02", Fingerprint: "fp"}
	driftDigest, _ := driftKey.Digest()
	driftOperation := operation()
	driftOperation.Id = "drift"
	driftOperation.Target = "drift-target"
	if _, err := other.Apply(context.Background(), driver.ApplyRequest{
		PlanID: "plan-drift", PlanRevision: 9, OperationID: "drift", Target: "drift-target", Operation: driftOperation,
		Reservation: driver.ReservationToken{Key: driftKey, Token: driftDigest, IssuedAt: time.Unix(1, 0)}, Timeout: time.Second,
	}); err != nil {
		t.Fatalf("drift apply: %v", err)
	}
	if _, err := fix.lifecycle.Apply(context.Background()); !errors.Is(err, driver.ErrHostDrift) {
		t.Fatalf("apply after drift: err = %v, want ErrHostDrift", err)
	}
	if fix.lifecycle.State() != driver.StateFailed {
		t.Fatalf("state = %s, want FAILED", fix.lifecycle.State())
	}
	if _, err := fix.lifecycle.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after drift: %v", err)
	}
}

func TestLifecycleRollbackAfterApplyRestoresAndReleases(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	drive(t, fix, driver.StateVerified)
	receipt, err := fix.lifecycle.Rollback(context.Background())
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if receipt.AlreadyRolledBack || len(fix.driver.Backing().Rules()) != 0 {
		t.Fatalf("rollback did not restore: receipt=%+v rules=%v", receipt, fix.driver.Backing().Rules())
	}
	if replay, err := fix.reservations.Reserve(context.Background(), key(1)); err != nil || !replay.Replayed || replay.Terminal != driver.StepRollback {
		t.Fatalf("re-reserve after rollback = %+v (%v), want replayed ROLLBACK result (replay defense survives rollback)", replay, err)
	}
	receipts, _ := fix.receipts.List(context.Background(), planID)
	if len(receipts) != 1 || receipts[0].Kind != driver.ReceiptKindRollback {
		t.Fatalf("receipts after rollback = %+v, want one ROLLBACK", receipts)
	}
}

func TestLifecycleTimeoutsValidated(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	bad := driver.DefaultStepTimeouts()
	bad.Apply = driver.MaxStepTimeout + time.Second
	if _, err := driver.NewLifecycle(driver.LifecycleConfig{
		Driver: fix.driver, Journal: fix.journal, Reservations: fix.reservations, Receipts: fix.receipts, Clock: fixedClock(), Timeouts: bad,
	}); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("oversized timeout: err = %v, want ErrInvalidRequest", err)
	}
	zero := driver.DefaultStepTimeouts()
	zero.Verify = 0
	if _, err := driver.NewLifecycle(driver.LifecycleConfig{
		Driver: fix.driver, Journal: fix.journal, Reservations: fix.reservations, Receipts: fix.receipts, Clock: fixedClock(), Timeouts: zero,
	}); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("zero timeout: err = %v, want ErrInvalidRequest", err)
	}
	if err := driver.DefaultStepTimeouts().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestLifecycleExpiredContextStopsBeforeMutation(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	drive(t, fix, driver.StateReserved)
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	if _, err := fix.lifecycle.Apply(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("apply with expired context: err = %v, want DeadlineExceeded", err)
	}
	if len(fix.driver.Backing().Rules()) != 0 {
		t.Fatal("expired apply mutated the host")
	}
}

func TestLifecycleRejectsSimulationThatWouldFail(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	drive(t, fix, driver.StateCaptured)
	wrongType := operation()
	wrongType.Type = antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_DNS
	_, err := fix.lifecycle.Simulate(context.Background(), wrongType)
	if !errors.Is(err, driver.ErrSimulationRejected) {
		t.Fatalf("simulate with mismatched type: err = %v, want ErrSimulationRejected", err)
	}
	if fix.lifecycle.State() != driver.StateFailed {
		t.Fatalf("state = %s, want FAILED", fix.lifecycle.State())
	}
	if err := fix.lifecycle.Approve(context.Background(), approval(t, 1, target)); !errors.Is(err, driver.ErrLifecycleOrder) {
		t.Fatalf("approve after failed simulation: err = %v, want ErrLifecycleOrder", err)
	}
}

func TestLifecycleRejectsHostileTargetBeforeJournal(t *testing.T) {
	t.Parallel()
	fix := newFixture(t)
	drive(t, fix, driver.StateCaptured)
	hostile := operation()
	hostile.Target = "eth0;reboot"
	if _, err := fix.lifecycle.Simulate(context.Background(), hostile); !errors.Is(err, driver.ErrUnsafeTarget) {
		t.Fatalf("simulate hostile target: err = %v, want ErrUnsafeTarget", err)
	}
	records, _ := fix.journal.Records(context.Background())
	if len(records) != 1 {
		t.Fatalf("journal records = %d, want only the begin record", len(records))
	}
}
