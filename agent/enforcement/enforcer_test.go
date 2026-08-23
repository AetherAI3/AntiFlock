package enforcement

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeDriver struct {
	mu                  sync.Mutex
	observedAt          time.Time
	calls               []string
	failedCheck         string
	passWithoutEvidence string
	failedApply         string
	failedRollback      string
}

func (driver *fakeDriver) Check(ctx context.Context, check *antiflockv1.PlanCheck) (CheckObservation, error) {
	if err := ctx.Err(); err != nil {
		return CheckObservation{}, err
	}
	driver.mu.Lock()
	driver.calls = append(driver.calls, "check:"+check.Id)
	driver.mu.Unlock()
	if check.Id == driver.failedCheck {
		return CheckObservation{
			Outcome: antiflockv1.CheckOutcome_CHECK_OUTCOME_FAILED, ReasonCode: "AF-TEST-CHECK-FAILED",
			SafeMessage: "The simulated local check did not match the expected state.", Evidence: []*antiflockv1.EvidenceReference{detectedEvidence(check.Id, driver.observedAt)},
		}, nil
	}
	result := CheckObservation{
		Outcome: antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED, ReasonCode: "AF-TEST-CHECK-PASSED",
		SafeMessage: "The simulated local check matched the expected state.", Evidence: []*antiflockv1.EvidenceReference{detectedEvidence(check.Id, driver.observedAt)},
	}
	if check.Id == driver.passWithoutEvidence {
		result.Evidence = nil
	}
	return result, nil
}

func (driver *fakeDriver) Apply(ctx context.Context, operation *antiflockv1.PlanOperation) (OperationObservation, error) {
	if err := ctx.Err(); err != nil {
		return OperationObservation{}, err
	}
	driver.mu.Lock()
	driver.calls = append(driver.calls, "apply:"+operation.Id)
	driver.mu.Unlock()
	if operation.Id == driver.failedApply {
		return OperationObservation{Succeeded: false, ReasonCode: "AF-TEST-APPLY-FAILED", SafeMessage: "The simulated operation failed."}, nil
	}
	return OperationObservation{Succeeded: true, ReasonCode: "AF-TEST-APPLY-PASSED", SafeMessage: "The simulated operation completed."}, nil
}

func (driver *fakeDriver) Rollback(ctx context.Context, operation *antiflockv1.PlanOperation) (OperationObservation, error) {
	if err := ctx.Err(); err != nil {
		return OperationObservation{}, err
	}
	driver.mu.Lock()
	driver.calls = append(driver.calls, "rollback:"+operation.Id)
	driver.mu.Unlock()
	if operation.Id == driver.failedRollback {
		return OperationObservation{Succeeded: false, ReasonCode: "AF-TEST-ROLLBACK-FAILED", SafeMessage: "The simulated rollback failed."}, nil
	}
	return OperationObservation{Succeeded: true, ReasonCode: "AF-TEST-ROLLBACK-PASSED", SafeMessage: "The simulated rollback completed."}, nil
}

func (driver *fakeDriver) Calls() []string {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return append([]string(nil), driver.calls...)
}

func detectedEvidence(checkID string, observedAt time.Time) *antiflockv1.EvidenceReference {
	return &antiflockv1.EvidenceReference{
		Id: "evidence-" + checkID, Role: antiflockv1.EvidenceRole_EVIDENCE_ROLE_SUPPORTING,
		Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED,
		SourceType:     antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_LOCAL_SENSOR,
		SourceName:     "deterministic-test-driver", ObservedAt: timestamppb.New(observedAt), Confidence: 1,
		Sensitivity:       antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		LocationPrecision: antiflockv1.LocationPrecision_LOCATION_PRECISION_WITHHELD,
		Summary:           "A deterministic in-memory endpoint check observed the simulated state.",
	}
}

type fixture struct {
	plan           *antiflockv1.Plan
	manifest       *antiflockv1.CapabilityManifest
	planPublicKey  ed25519.PublicKey
	planPrivateKey ed25519.PrivateKey
	nodePublicKey  ed25519.PublicKey
	nodePrivateKey ed25519.PrivateKey
	now            time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	planSeed := make([]byte, ed25519.SeedSize)
	nodeSeed := make([]byte, ed25519.SeedSize)
	for index := range planSeed {
		planSeed[index] = byte(index)
		nodeSeed[index] = byte(255 - index)
	}
	planPrivateKey := ed25519.NewKeyFromSeed(planSeed)
	nodePrivateKey := ed25519.NewKeyFromSeed(nodeSeed)
	manifest := fullManifest()
	compiler, err := policy.NewCompiler("deployment", "policy-key", planPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	plan, violations, err := compiler.Compile(validProfile(), "node", 1, manifest)
	if err != nil || len(violations) != 0 {
		t.Fatalf("compile plan: %v, %#v", err, violations)
	}
	return fixture{
		plan: plan, manifest: manifest, planPublicKey: planPrivateKey.Public().(ed25519.PublicKey), planPrivateKey: planPrivateKey,
		nodePublicKey: nodePrivateKey.Public().(ed25519.PublicKey), nodePrivateKey: nodePrivateKey,
		now: plan.CreatedAt.AsTime().Add(time.Second),
	}
}

func (fixture fixture) enforcer(t *testing.T, driver Driver, store StateStore) *Enforcer {
	t.Helper()
	if store == nil {
		store = NewMemoryStateStore(0, 0)
	}
	enforcer, err := New(Config{
		DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key", PlanPublicKey: fixture.planPublicKey,
		NodePrivateKey: fixture.nodePrivateKey, Capabilities: fixture.manifest, Driver: driver, StateStore: store,
		Clock: func() time.Time { return fixture.now }, MaximumEvidenceAge: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return enforcer
}

func TestEnforcerCommitsSignedPlanOnceWithCurrentDetectedEvidence(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	driver := &fakeDriver{observedAt: fixture.now}
	store := NewMemoryStateStore(0, 0)
	enforcer := fixture.enforcer(t, driver, store)
	result, err := enforcer.Apply(context.Background(), fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != antiflockv1.PlanStatus_PLAN_STATUS_COMMITTED || result.ReasonCode != "AF-PLAN-COMMITTED" || len(result.OperationResults) != 4 || len(result.VerificationResults) != 3 {
		t.Fatalf("result = %#v", result)
	}
	if err := VerifyExecutionResult(result, fixture.nodePublicKey); err != nil {
		t.Fatalf("verify plan result: %v", err)
	}
	for _, check := range append(append([]*antiflockv1.CheckResult(nil), result.PreconditionResults...), result.VerificationResults...) {
		for _, evidence := range check.Evidence {
			if evidence.Classification == antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED || evidence.LastVerifiedAt != nil {
				t.Fatal("local detection was upgraded to VERIFIED")
			}
		}
	}
	firstCalls := driver.Calls()
	replayed, err := enforcer.Apply(context.Background(), fixture.plan)
	if err != nil || !proto.Equal(result, replayed) {
		t.Fatalf("idempotent replay = %#v, %v", replayed, err)
	}
	if !slices.Equal(firstCalls, driver.Calls()) {
		t.Fatal("idempotent replay executed the driver twice")
	}
	if policyRevision, planRevision := store.Revisions(); policyRevision != 7 || planRevision != 1 {
		t.Fatalf("stored revisions = %d/%d", policyRevision, planRevision)
	}
	tampered := proto.Clone(result).(*antiflockv1.PlanExecutionResult)
	tampered.ReasonCode = "AF-TAMPERED"
	if err := VerifyExecutionResult(tampered, fixture.nodePublicKey); err == nil {
		t.Fatal("tampered plan result signature was accepted")
	}
}

func TestEnforcerRollsBackInListedOrderAfterVerificationFailure(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	driver := &fakeDriver{observedAt: fixture.now, failedCheck: "verify-route"}
	enforcer := fixture.enforcer(t, driver, nil)
	result, err := enforcer.Apply(context.Background(), fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != antiflockv1.PlanStatus_PLAN_STATUS_ROLLED_BACK || result.ReasonCode != "AF-PLAN-VERIFICATION-FAILED" || len(result.RollbackResults) != 3 {
		t.Fatalf("rollback result = %#v", result)
	}
	wantedTail := []string{"rollback:rollback-dns", "rollback:rollback-route", "rollback:rollback-firewall"}
	calls := driver.Calls()
	if len(calls) < len(wantedTail) || !slices.Equal(calls[len(calls)-len(wantedTail):], wantedTail) {
		t.Fatalf("rollback order = %v", calls)
	}
	if err := VerifyExecutionResult(result, fixture.nodePublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestEnforcerFailsClosedWhenRollbackIsIncomplete(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	driver := &fakeDriver{observedAt: fixture.now, failedApply: "set-route", failedRollback: "rollback-route"}
	enforcer := fixture.enforcer(t, driver, nil)
	result, err := enforcer.Apply(context.Background(), fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != antiflockv1.PlanStatus_PLAN_STATUS_FAILED || result.ReasonCode != "AF-PLAN-ROLLBACK-INCOMPLETE" || len(result.RollbackResults) != 3 {
		t.Fatalf("incomplete rollback = %#v", result)
	}
}

func TestEnforcerRejectsPassedCheckWithoutEvidenceBeforeMutation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	driver := &fakeDriver{observedAt: fixture.now, passWithoutEvidence: "preflight-current-state"}
	enforcer := fixture.enforcer(t, driver, nil)
	result, err := enforcer.Apply(context.Background(), fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != antiflockv1.PlanStatus_PLAN_STATUS_REJECTED || result.ReasonCode != "AF-PLAN-PRECONDITION-FAILED" || len(result.OperationResults) != 0 {
		t.Fatalf("precondition result = %#v", result)
	}
	if got := driver.Calls(); !slices.Equal(got, []string{"check:preflight-current-state"}) {
		t.Fatalf("driver calls = %v", got)
	}
}

func TestEnforcerRejectsWrongTargetAndUnsupportedCapabilitiesWithoutMutation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for name, mutate := range map[string]func(*antiflockv1.Plan, *antiflockv1.CapabilityManifest){
		"target": func(plan *antiflockv1.Plan, _ *antiflockv1.CapabilityManifest) { plan.NodeId = "other-node" },
		"capability": func(_ *antiflockv1.Plan, manifest *antiflockv1.CapabilityManifest) {
			manifest.Capabilities = manifest.Capabilities[:1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan := proto.Clone(fixture.plan).(*antiflockv1.Plan)
			manifest := proto.Clone(fixture.manifest).(*antiflockv1.CapabilityManifest)
			mutate(plan, manifest)
			driver := &fakeDriver{observedAt: fixture.now}
			enforcer, err := New(Config{
				DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key", PlanPublicKey: fixture.planPublicKey,
				NodePrivateKey: fixture.nodePrivateKey, Capabilities: manifest, Driver: driver,
				StateStore: NewMemoryStateStore(0, 0), Clock: func() time.Time { return fixture.now },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := enforcer.Apply(context.Background(), plan)
			if !errors.Is(err, ErrPlanRejected) || result == nil || result.Status != antiflockv1.PlanStatus_PLAN_STATUS_REJECTED {
				t.Fatalf("rejection = %#v, %v", result, err)
			}
			if len(driver.Calls()) != 0 {
				t.Fatal("rejected plan reached the mutation driver")
			}
			if err := VerifyExecutionResult(result, fixture.nodePublicKey); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnforcerRejectsValidlySignedCapabilitySubstitutionWithoutMutation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	plan := proto.Clone(fixture.plan).(*antiflockv1.Plan)
	substitute := func(requirements []*antiflockv1.CapabilityRequirement) {
		for index := range requirements {
			requirements[index] = &antiflockv1.CapabilityRequirement{
				Key: "network.metadata.observe",
				RequiredOperations: []antiflockv1.CapabilityOperation{
					antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE,
				},
				MinimumSupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
			}
		}
	}
	for _, check := range append(append([]*antiflockv1.PlanCheck(nil), plan.Preconditions...), plan.Verifications...) {
		substitute(check.RequiredCapabilities)
	}
	for _, operation := range append(append([]*antiflockv1.PlanOperation(nil), plan.Actions...), plan.Rollback...) {
		substitute(operation.RequiredCapabilities)
	}
	resignPlanForTest(t, plan, fixture.planPrivateKey)
	if err := policy.VerifyPlan(plan, fixture.planPublicKey, fixture.now); err != nil {
		t.Fatalf("substitution fixture is not validly signed: %v", err)
	}
	manifest := proto.Clone(fixture.manifest).(*antiflockv1.CapabilityManifest)
	manifest.Capabilities = append(manifest.Capabilities, &antiflockv1.Capability{
		Key: "network.metadata.observe",
		Operations: []antiflockv1.CapabilityOperation{
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE,
		},
		SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
	})
	verified, err := VerifyPlan(PlanVerificationConfig{
		DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key",
		PlanPublicKey: fixture.planPublicKey, Capabilities: manifest,
		Clock: func() time.Time { return fixture.now },
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Valid || verified.CapabilityCompatible || verified.Executable || verified.ReasonCode != "AF-PLAN-LAYOUT-UNSUPPORTED" {
		t.Fatalf("substituted plan verification = %#v", verified)
	}
	driver := &fakeDriver{observedAt: fixture.now}
	enforcer, err := New(Config{
		DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key", PlanPublicKey: fixture.planPublicKey,
		NodePrivateKey: fixture.nodePrivateKey, Capabilities: manifest, Driver: driver,
		StateStore: NewMemoryStateStore(0, 0), Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := enforcer.Apply(context.Background(), plan)
	if !errors.Is(err, ErrPlanRejected) || result == nil || result.ReasonCode != "AF-PLAN-LAYOUT-UNSUPPORTED" {
		t.Fatalf("substituted plan rejection = %#v, %v", result, err)
	}
	if len(driver.Calls()) != 0 {
		t.Fatal("substituted plan reached the mutation driver")
	}
}

func TestEnforcerRejectsMissingWrongTypedOrUnknownSignedParameters(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	if validation := fixture.enforcer(t, &fakeDriver{observedAt: fixture.now}, nil).validatePlan(fixture.plan, fixture.now); validation != nil {
		t.Fatalf("compiler plan failed endpoint validation: %v", validation)
	}
	for name, mutate := range map[string]func(*antiflockv1.PlanOperation){
		"missing-list": func(operation *antiflockv1.PlanOperation) { delete(operation.Parameters.Fields, "allowedExitNodeIds") },
		"wrong-type": func(operation *antiflockv1.PlanOperation) {
			operation.Parameters.Fields["allowedExitNodeIds"] = structpb.NewStringValue("exit-node")
		},
		"simulation": func(operation *antiflockv1.PlanOperation) {
			operation.Parameters.Fields["simulation"] = structpb.NewBoolValue(true)
		},
		"unknown": func(operation *antiflockv1.PlanOperation) {
			operation.Parameters.Fields["futureUnsafeField"] = structpb.NewStringValue("value")
		},
	} {
		t.Run(name, func(t *testing.T) {
			operation := proto.Clone(fixture.plan.Actions[2]).(*antiflockv1.PlanOperation)
			mutate(operation)
			if validOperationParameters(operation, false, fixture.plan.RecoveryAllowlist) {
				t.Fatal("unsupported signed parameter shape was accepted")
			}
		})
	}
	firewall := proto.Clone(fixture.plan.Actions[0]).(*antiflockv1.PlanOperation)
	firewall.Parameters.Fields["recoveryDestinations"] = structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("different.internal")}})
	if validOperationParameters(firewall, false, fixture.plan.RecoveryAllowlist) {
		t.Fatal("firewall recovery parameters diverged from the signed plan allowlist")
	}
	check := proto.Clone(fixture.plan.Verifications[0]).(*antiflockv1.PlanCheck)
	check.Parameters.Fields["source"] = structpb.NewStringValue("core")
	if validCheckParameters(check) {
		t.Fatal("non-endpoint verification source was accepted")
	}
}

func validProfile() *antiflockv1.ProtectionProfile {
	return &antiflockv1.ProtectionProfile{
		Metadata: &antiflockv1.ResourceMetadata{Id: "coffee-shop", Revision: 7}, ApiVersion: "antiflock.policy/v1",
		Mode: antiflockv1.ProtectionMode_PROTECTION_MODE_GUARD,
		Mesh: &antiflockv1.MeshPolicy{Required: true, Provider: "tailscale"},
		Egress: &antiflockv1.EgressPolicy{
			Mode: antiflockv1.EgressMode_EGRESS_MODE_TRUSTED_EXIT, FailMode: antiflockv1.FailMode_FAIL_MODE_CLOSED,
			AllowedExitNodeIds: []string{"exit-node"}, AllowedDestinations: []string{"github.com"},
			RecoveryDestinations: []string{"core.internal"},
		},
		Dns: &antiflockv1.DnsPolicy{
			Mode: antiflockv1.DnsMode_DNS_MODE_PROTECTED, AllowedResolvers: []string{"9.9.9.9"}, RequirePathVerification: true,
		},
		Networks: &antiflockv1.NetworkPolicy{RequireMeshOnUntrusted: true, BlockOpenWifiWithoutMesh: true},
		Actions: []*antiflockv1.ProtectedActionPolicy{{
			ApplicationIds: []string{"aether-code"}, DataClasses: []string{"repository-source"}, RequireProtectedState: true,
		}},
		Telemetry: &antiflockv1.TelemetryPolicy{FlowMetadata: true, PayloadCapture: false, RetentionDays: 14},
	}
}

func fullManifest() *antiflockv1.CapabilityManifest {
	return &antiflockv1.CapabilityManifest{NodeId: "node", Capabilities: []*antiflockv1.Capability{
		capability("firewall.egress.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		capability("mesh.path.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
		capability("network.route.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		capability("dns.protected.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
	}}
}

func capability(key string, operations ...antiflockv1.CapabilityOperation) *antiflockv1.Capability {
	return &antiflockv1.Capability{
		Key: key, Operations: operations, SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
	}
}
