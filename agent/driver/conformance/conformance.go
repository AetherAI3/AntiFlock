// Package conformance is the executable contract every driver.Driver must
// satisfy. A driver package runs it from its own tests:
//
//	func TestConformance(t *testing.T) {
//		conformance.RunConformance(t, func(t *testing.T) driver.Driver { ... })
//	}
//
// The factory must return a driver over fresh durable state on every call.
// The driver must implement driver.Reopener (a restart over the same durable
// state) and driver.CrashSimulator (process death between mutation and
// journal completion); both are required so crash recovery is proven for
// every driver, not only the reference one.
package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// Factory returns a driver over fresh durable state.
type Factory func(t *testing.T) driver.Driver

// ShellMetacharacterTargets are the hostile targets every driver must reject
// with driver.ErrUnsafeTarget in Simulate, CommandPlan and Apply.
var ShellMetacharacterTargets = []string{
	"eth0;rm", "eth0|cat", "eth0&&x", "$(id)", "`id`", "eth0>out", "eth0<in", "a b", "eth0\n", "eth0\x00", "eth0\x1b[31m",
	"eth0'", "eth0\"", "eth0\\x", "eth0*", "eth0?", "eth0!", "~root", "eth0#c", "(x)", "{x}", "[x]", "café",
}

// RunConformance runs every contract case as a subtest.
func RunConformance(t *testing.T, factory Factory) {
	t.Helper()
	if factory == nil {
		t.Fatal("conformance factory is required")
	}
	cases := []struct {
		name string
		run  func(t *testing.T, factory Factory)
	}{
		{"identity and privilege boundary", testIdentity},
		{"probe validity", testProbe},
		{"simulate is pure", testSimulatePure},
		{"apply then verify", testApplyVerify},
		{"rollback idempotent", testRollbackIdempotent},
		{"crash mid-apply then recover", testCrashRecover},
		{"recover is idempotent and clean", testRecoverIdempotent},
		{"replay reservation rejected", testReservationReplay},
		{"timeouts honoured", testTimeouts},
		{"shell-free targets", testShellFree},
		{"exact target binding", testTargetBinding},
		{"receipt digest stable", testReceiptDigest},
		{"ownership token deterministic", testOwnershipToken},
		{"recovery paths independent of plan", testRecoveryPaths},
		{"lifecycle over factory commits", testLifecycleCommit},
		{"lifecycle over factory rolls back", testLifecycleRollback},
		{"lifecycle crash after apply then recover commits", testLifecycleCrashRecoverCommit},
		{"lifecycle crash inside apply then recover reverts", testLifecycleCrashRecoverRollback},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testCase.run(t, factory)
		})
	}
}

// Fixture helpers shared by the cases.

const (
	planID      = "plan-conformance"
	operationID = "guard-egress"
	target      = "protected-egress"
)

func operation(id, target string) *antiflockv1.PlanOperation {
	parameters, _ := structpb.NewStruct(map[string]any{"simulation": false, "failMode": "CLOSED"})
	return &antiflockv1.PlanOperation{
		Id: id, Type: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, Target: target,
		Description: "conformance fixture", Parameters: parameters,
	}
}

func scope(targets ...string) driver.Scope {
	return driver.Scope{OperationType: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, Targets: targets}
}

func reservation(t *testing.T, revision uint64) driver.ReservationToken {
	t.Helper()
	key := driver.ReservationKey{PlanID: planID, PolicyRevision: 1, PlanRevision: revision, Nonce: "6e6f6e6365", Fingerprint: "fp-" + strings.Repeat("0", 8)}
	digest, err := key.Digest()
	if err != nil {
		t.Fatalf("reservation digest: %v", err)
	}
	return driver.ReservationToken{Key: key, Token: digest, IssuedAt: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}
}

func applyRequest(t *testing.T, revision uint64, requestTarget string, operation *antiflockv1.PlanOperation) driver.ApplyRequest {
	t.Helper()
	return driver.ApplyRequest{
		PlanID: planID, PlanRevision: revision, OperationID: operation.GetId(), Target: requestTarget,
		Operation: operation, Reservation: reservation(t, revision), Timeout: 5 * time.Second,
	}
}

func digestOf(t *testing.T, instance driver.Driver, scope driver.Scope) string {
	t.Helper()
	snapshot, err := instance.Capture(context.Background(), scope)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatalf("snapshot digest: %v", err)
	}
	return digest
}

func mustApply(t *testing.T, instance driver.Driver, revision uint64) driver.ApplyReceipt {
	t.Helper()
	receipt, err := instance.Apply(context.Background(), applyRequest(t, revision, target, operation(operationID, target)))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("apply receipt invalid: %v", err)
	}
	return receipt
}

func testIdentity(t *testing.T, factory Factory) {
	instance := factory(t)
	if strings.TrimSpace(instance.Name()) == "" || strings.TrimSpace(instance.Version()) == "" {
		t.Fatal("driver name and version are required")
	}
	boundary := instance.PrivilegeBoundary()
	if err := boundary.Validate(); err != nil {
		t.Fatalf("privilege boundary invalid: %v", err)
	}
	if !boundary.ShellFree {
		t.Fatal("privilege boundary must be shell-free")
	}
	health, err := instance.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if err := health.Validate(); err != nil {
		t.Fatalf("health report invalid: %v", err)
	}
	if health.Status != driver.HealthHealthy {
		t.Fatalf("fresh driver health = %s, want HEALTHY (%v)", health.Status, health.ReasonCodes)
	}
}

func testProbe(t *testing.T, factory Factory) {
	instance := factory(t)
	before := digestOf(t, instance, scope())
	results, err := instance.Probe(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("probe returned no results")
	}
	for _, result := range results {
		if err := result.Validate(); err != nil {
			t.Fatalf("probe result invalid: %v", err)
		}
		if result.DriverName != instance.Name() || result.DriverVersion != instance.Version() {
			t.Fatalf("probe result names %s/%s, driver is %s/%s", result.DriverName, result.DriverVersion, instance.Name(), instance.Version())
		}
		if _, err := result.Digest(); err != nil {
			t.Fatalf("probe digest: %v", err)
		}
	}
	if after := digestOf(t, instance, scope()); after != before {
		t.Fatal("probe mutated host state")
	}
}

func testSimulatePure(t *testing.T, factory Factory) {
	instance := factory(t)
	snapshot, err := instance.Capture(context.Background(), scope())
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	before, err := snapshot.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	first, err := instance.Simulate(context.Background(), snapshot, operation(operationID, target))
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("simulation invalid: %v", err)
	}
	if !first.WouldSucceed {
		t.Fatalf("simulation predicted failure: %v", first.ReasonCodes)
	}
	if first.SnapshotDigest != before || first.Diff.BeforeDigest != before {
		t.Fatal("simulation is not bound to the captured snapshot")
	}
	if first.Diff.AfterDigest == before {
		t.Fatal("simulation of a new rule predicted no change")
	}
	for _, line := range first.Diff.Lines {
		for _, r := range line {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("diff line contains non-printable byte %q", line)
			}
		}
	}
	second, err := instance.Simulate(context.Background(), snapshot, operation(operationID, target))
	if err != nil {
		t.Fatalf("second simulate: %v", err)
	}
	if second.Diff.AfterDigest != first.Diff.AfterDigest || strings.Join(second.Diff.Lines, "\n") != strings.Join(first.Diff.Lines, "\n") {
		t.Fatal("simulation is not deterministic")
	}
	if after := digestOf(t, instance, scope()); after != before {
		t.Fatal("simulate mutated host state")
	}
}

func testApplyVerify(t *testing.T, factory Factory) {
	instance := factory(t)
	before := digestOf(t, instance, scope(target))
	receipt := mustApply(t, instance, 1)
	if receipt.BeforeDigest != before {
		t.Fatal("apply receipt before-digest does not match the captured host")
	}
	if receipt.AppliedDigest == before {
		t.Fatal("apply reported no change")
	}
	if receipt.PlanID != planID || receipt.PlanRevision != 1 || receipt.OperationID != operationID || receipt.Target != target {
		t.Fatal("apply receipt is not bound to the request")
	}
	if digestOf(t, instance, scope(target)) != receipt.AppliedDigest {
		t.Fatal("host digest after apply does not match the receipt")
	}
	result, err := instance.Verify(context.Background(), receipt)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("verification invalid: %v", err)
	}
	if !result.Verified || result.ObservedDigest != receipt.AppliedDigest {
		t.Fatalf("verification failed: %v", result.ReasonCodes)
	}
	forged := receipt
	forged.OwnershipToken = strings.Repeat("f", 64)
	if _, err := instance.Verify(context.Background(), forged); !errors.Is(err, driver.ErrUnknownOwnership) {
		t.Fatalf("verify with a foreign ownership token: err = %v, want ErrUnknownOwnership", err)
	}
}

func testRollbackIdempotent(t *testing.T, factory Factory) {
	instance := factory(t)
	before := digestOf(t, instance, scope(target))
	receipt := mustApply(t, instance, 1)
	request := driver.RollbackRequest{PlanID: planID, PlanRevision: 1, OperationID: operationID, OwnershipToken: receipt.OwnershipToken, Timeout: 5 * time.Second}
	first, err := instance.Rollback(context.Background(), request)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("rollback receipt invalid: %v", err)
	}
	if first.AlreadyRolledBack {
		t.Fatal("first rollback reported AlreadyRolledBack")
	}
	if first.RestoredDigest != before || digestOf(t, instance, scope(target)) != before {
		t.Fatal("rollback did not restore the captured state")
	}
	second, err := instance.Rollback(context.Background(), request)
	if err != nil {
		t.Fatalf("second rollback: %v", err)
	}
	if !second.AlreadyRolledBack {
		t.Fatal("second rollback did not report AlreadyRolledBack")
	}
	if second.RestoredDigest != before || digestOf(t, instance, scope(target)) != before {
		t.Fatal("second rollback changed host state")
	}
	unknown := request
	unknown.OwnershipToken = strings.Repeat("e", 64)
	if _, err := instance.Rollback(context.Background(), unknown); !errors.Is(err, driver.ErrUnknownOwnership) {
		t.Fatalf("rollback of unknown token: err = %v, want ErrUnknownOwnership", err)
	}
}

func testCrashRecover(t *testing.T, factory Factory) {
	instance := factory(t)
	crasher, ok := instance.(driver.CrashSimulator)
	if !ok {
		t.Fatal("driver must implement driver.CrashSimulator for crash-recovery conformance")
	}
	reopener, ok := instance.(driver.Reopener)
	if !ok {
		t.Fatal("driver must implement driver.Reopener for crash-recovery conformance")
	}
	before := digestOf(t, instance, scope(target))
	crasher.InjectCrash()
	_, err := instance.Apply(context.Background(), applyRequest(t, 1, target, operation(operationID, target)))
	if !errors.Is(err, driver.ErrCrashInjected) {
		t.Fatalf("apply with injected crash: err = %v, want ErrCrashInjected", err)
	}
	if digestOf(t, instance, scope(target)) == before {
		t.Fatal("injected crash did not leave a partial mutation to recover")
	}
	fresh, err := reopener.Reopen()
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	health, err := fresh.Health(context.Background())
	if err != nil {
		t.Fatalf("health after crash: %v", err)
	}
	if health.Status == driver.HealthHealthy {
		t.Fatal("fresh driver reported HEALTHY with an open journal entry")
	}
	report, err := fresh.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("recovery report invalid: %v", err)
	}
	if len(report.Operations) != 1 || !report.Operations[0].Reverted || report.Operations[0].PlanID != planID {
		t.Fatalf("recovery did not revert the in-flight operation: %+v", report.Operations)
	}
	if digestOf(t, fresh, scope(target)) != before {
		t.Fatal("recovery did not restore the pre-apply state")
	}
	health, err = fresh.Health(context.Background())
	if err != nil || health.Status != driver.HealthHealthy {
		t.Fatalf("health after recovery = %s (%v), want HEALTHY", health.Status, err)
	}
	again, err := fresh.Recover(context.Background())
	if err != nil {
		t.Fatalf("second recover: %v", err)
	}
	if len(again.Operations) != 0 {
		t.Fatal("second recover found work; recovery is not idempotent")
	}
}

func testRecoverIdempotent(t *testing.T, factory Factory) {
	instance := factory(t)
	receipt := mustApply(t, instance, 1)
	applied := digestOf(t, instance, scope(target))
	for i := 0; i < 2; i++ {
		report, err := instance.Recover(context.Background())
		if err != nil {
			t.Fatalf("recover %d: %v", i, err)
		}
		if len(report.Operations) != 0 {
			t.Fatalf("recover %d reverted a completed apply: %+v", i, report.Operations)
		}
	}
	if digestOf(t, instance, scope(target)) != applied {
		t.Fatal("recover changed a committed mutation")
	}
	result, err := instance.Verify(context.Background(), receipt)
	if err != nil || !result.Verified {
		t.Fatalf("verify after recover: verified=%v err=%v", result.Verified, err)
	}
}

func testReservationReplay(t *testing.T, factory Factory) {
	instance := factory(t)
	bad := applyRequest(t, 1, target, operation(operationID, target))
	bad.Reservation.Token = strings.Repeat("a", 64)
	if _, err := instance.Apply(context.Background(), bad); !errors.Is(err, driver.ErrReservationInvalid) {
		t.Fatalf("apply with a foreign reservation token: err = %v, want ErrReservationInvalid", err)
	}
	foreign := applyRequest(t, 1, target, operation(operationID, target))
	foreign.Reservation = reservation(t, 2)
	if _, err := instance.Apply(context.Background(), foreign); !errors.Is(err, driver.ErrReservationInvalid) {
		t.Fatalf("apply with a reservation for another revision: err = %v, want ErrReservationInvalid", err)
	}
	RunReservationStore(t, func(t *testing.T) driver.ReservationStore {
		return driver.NewMemoryReservationStore(0, 0, func() time.Time { return time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC) })
	})
}

func testTimeouts(t *testing.T, factory Factory) {
	instance := factory(t)
	before := digestOf(t, instance, scope(target))
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	if _, err := instance.Apply(expired, applyRequest(t, 1, target, operation(operationID, target))); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("apply with an expired context: err = %v, want DeadlineExceeded", err)
	}
	if digestOf(t, instance, scope(target)) != before {
		t.Fatal("apply with an expired context mutated the host")
	}
	if _, err := instance.Capture(expired, scope()); err == nil {
		t.Fatal("capture ignored an expired context")
	}
	if _, err := instance.Recover(expired); err == nil {
		t.Fatal("recover ignored an expired context")
	}
	oversized := applyRequest(t, 1, target, operation(operationID, target))
	oversized.Timeout = driver.MaxOperationTimeout + time.Second
	if _, err := instance.Apply(context.Background(), oversized); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("apply with an oversized timeout: err = %v, want ErrInvalidRequest", err)
	}
}

func testShellFree(t *testing.T, factory Factory) {
	instance := factory(t)
	plan, err := instance.CommandPlan(context.Background(), operation(operationID, target))
	if err != nil {
		t.Fatalf("command plan: %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("command plan invalid: %v", err)
	}
	for _, argument := range plan.Arguments {
		if strings.ContainsAny(argument, " ;|&$`<>(){}[]*?!~'\"\\#") {
			t.Fatalf("command plan argument %q contains shell metacharacters", argument)
		}
	}
	before := digestOf(t, instance, scope())
	snapshot, err := instance.Capture(context.Background(), scope())
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	for _, hostile := range ShellMetacharacterTargets {
		if _, err := instance.CommandPlan(context.Background(), operation(operationID, hostile)); !errors.Is(err, driver.ErrUnsafeTarget) {
			t.Fatalf("command plan accepted hostile target %q: err = %v", hostile, err)
		}
		if _, err := instance.Simulate(context.Background(), snapshot, operation(operationID, hostile)); !errors.Is(err, driver.ErrUnsafeTarget) {
			t.Fatalf("simulate accepted hostile target %q: err = %v", hostile, err)
		}
		if _, err := instance.Apply(context.Background(), applyRequest(t, 1, hostile, operation(operationID, hostile))); !errors.Is(err, driver.ErrUnsafeTarget) {
			t.Fatalf("apply accepted hostile target %q: err = %v", hostile, err)
		}
	}
	if digestOf(t, instance, scope()) != before {
		t.Fatal("hostile targets mutated the host")
	}
}

func testTargetBinding(t *testing.T, factory Factory) {
	instance := factory(t)
	before := digestOf(t, instance, scope())
	mismatched := applyRequest(t, 1, "other-target", operation(operationID, target))
	if _, err := instance.Apply(context.Background(), mismatched); !errors.Is(err, driver.ErrTargetMismatch) {
		t.Fatalf("apply with a target differing from the operation: err = %v, want ErrTargetMismatch", err)
	}
	renamed := applyRequest(t, 1, target, operation(operationID, target))
	renamed.OperationID = "other-operation"
	if _, err := instance.Apply(context.Background(), renamed); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("apply with an operation id differing from the operation: err = %v, want ErrInvalidRequest", err)
	}
	if digestOf(t, instance, scope()) != before {
		t.Fatal("rejected apply mutated the host")
	}
}

func testReceiptDigest(t *testing.T, factory Factory) {
	instance := factory(t)
	receipt := mustApply(t, instance, 1)
	first, err := receipt.Receipt().ContentDigest()
	if err != nil {
		t.Fatalf("receipt digest: %v", err)
	}
	second, err := receipt.Receipt().ContentDigest()
	if err != nil || first != second {
		t.Fatalf("receipt digest is not stable: %s != %s (%v)", first, second, err)
	}
	tampered := receipt
	tampered.AppliedDigest = strings.Repeat("0", 64)
	third, err := tampered.Receipt().ContentDigest()
	if err != nil || third == first {
		t.Fatal("receipt digest did not change with content")
	}
}

func testRecoveryPaths(t *testing.T, factory Factory) {
	instance := factory(t)
	paths, err := instance.RecoveryPaths(context.Background())
	if err != nil {
		t.Fatalf("recovery paths: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("driver reports no independent recovery path; it must refuse to be used for enforcement")
	}
	for _, path := range paths {
		if err := path.Validate(); err != nil {
			t.Fatalf("recovery path invalid: %v", err)
		}
	}
	mustApply(t, instance, 1)
	after, err := instance.RecoveryPaths(context.Background())
	if err != nil {
		t.Fatalf("recovery paths after apply: %v", err)
	}
	if len(after) != len(paths) {
		t.Fatal("applying a plan changed the recovery paths")
	}
	for index := range paths {
		if paths[index] != after[index] {
			t.Fatal("applying a plan changed a recovery path")
		}
	}
}
