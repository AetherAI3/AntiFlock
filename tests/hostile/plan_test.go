package hostile_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/enforcement"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
	"github.com/DBarr3/AntiFlock/tests/fixtures"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// applyReason runs the plan through a fresh enforcer and returns the signed
// rejection reason code, or "" when the plan was accepted.
func applyReason(t *testing.T, fixture fixtures.PlanFixture, plan *antiflockv1.Plan, options fixtures.EnforcerOptions) (string, *fixtures.RecordingDriver) {
	t.Helper()
	driver := &fixtures.RecordingDriver{ObservedAt: fixture.Now}
	enforcer := fixture.Enforcer(t, driver, nil, options)
	result, err := enforcer.Apply(context.Background(), plan)
	if err == nil {
		if result.Status != antiflockv1.PlanStatus_PLAN_STATUS_COMMITTED {
			t.Fatalf("accepted plan did not commit: %v", result.Status)
		}
		return "", driver
	}
	if !errors.Is(err, enforcement.ErrPlanRejected) {
		t.Fatalf("unexpected error class: %v", err)
	}
	if result == nil || result.Status != antiflockv1.PlanStatus_PLAN_STATUS_REJECTED {
		t.Fatalf("rejection without a signed REJECTED result: %#v", result)
	}
	if verifyErr := enforcement.VerifyExecutionResult(result, fixture.NodePublicKey); verifyErr != nil {
		t.Fatalf("rejection result is not signed by the node: %v", verifyErr)
	}
	if driver.MutationCalls() != 0 {
		t.Fatalf("rejected plan still mutated the host: %v", driver.Calls())
	}
	return result.ReasonCode, driver
}

// Invariant: every post-signing mutation of a plan is rejected with a signed
// REJECTED result carrying the documented reason code, and the driver is
// never called. The plan key never re-signs; so the only way to reach the
// driver is a byte-identical plan from the policy compiler.
func TestPlanTamperIsRejectedWithDocumentedReasonCodes(t *testing.T) {
	t.Parallel()
	fixture := fixtures.NewPlanFixture(t)

	cases := []struct {
		name   string
		mutate func(plan *antiflockv1.Plan)
		reason string
	}{
		{"signature-stripped", func(plan *antiflockv1.Plan) { plan.Signature = nil }, "AF-PLAN-SIGNER-INVALID"},
		{"signature-key-id-swapped", func(plan *antiflockv1.Plan) { plan.Signature.KeyId = "other-key" }, "AF-PLAN-SIGNER-INVALID"},
		{"signature-value-bit-flip", func(plan *antiflockv1.Plan) { plan.Signature.Value[10] ^= 0x80 }, "AF-PLAN-SIGNATURE-INVALID"},
		{"signed-content-digest-rewrite", func(plan *antiflockv1.Plan) { plan.Signature.SignedContentDigest.Digest[0] ^= 0x01 }, "AF-PLAN-SIGNATURE-INVALID"},
		{"recovery-allowlist-extended", func(plan *antiflockv1.Plan) {
			plan.RecoveryAllowlist = append(plan.RecoveryAllowlist, "attacker.example")
		}, "AF-PLAN-SIGNATURE-INVALID"},
		{"node-retargeted", func(plan *antiflockv1.Plan) { plan.NodeId = "node-2" }, "AF-PLAN-TARGET-MISMATCH"},
		{"deployment-retargeted", func(plan *antiflockv1.Plan) { plan.DeploymentId = "other" }, "AF-PLAN-TARGET-MISMATCH"},
		{"status-rolled-back", func(plan *antiflockv1.Plan) { plan.Status = antiflockv1.PlanStatus_PLAN_STATUS_ROLLED_BACK }, "AF-PLAN-STATUS-INVALID"},
		{"nonce-truncated", func(plan *antiflockv1.Plan) { plan.Nonce = plan.Nonce[:31] }, "AF-PLAN-IDENTITY-INVALID"},
		{"expired", func(plan *antiflockv1.Plan) { plan.ExpiresAt = timestamppb.New(fixture.Now.Add(-time.Second)) }, "AF-PLAN-TIME-INVALID"},
		{"created-in-future", func(plan *antiflockv1.Plan) { plan.CreatedAt = timestamppb.New(fixture.Now.Add(time.Hour)) }, "AF-PLAN-TIME-INVALID"},
		{"signed-at-far-future", func(plan *antiflockv1.Plan) { plan.Signature.SignedAt = timestamppb.New(fixture.Now.Add(6 * time.Minute)) }, "AF-PLAN-SIGNER-INVALID"},
		{"signed-at-before-created", func(plan *antiflockv1.Plan) { plan.Signature.SignedAt = timestamppb.New(plan.CreatedAt.AsTime().Add(-6 * time.Minute)) }, "AF-PLAN-SIGNER-INVALID"},
		{"operation-parameters-fail-open", func(plan *antiflockv1.Plan) {
			plan.Actions[0].Parameters.Fields["failMode"] = structpb.NewStringValue("OPEN")
		}, "AF-PLAN-SIGNATURE-INVALID"},
		{"unknown-wire-field", func(plan *antiflockv1.Plan) {
			plan.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 9999, protowire.VarintType), 1))
		}, "AF-PLAN-WIRE-INVALID"},
		{"dry-run-text-control-chars", func(plan *antiflockv1.Plan) { plan.HumanReadableDryRun = plan.HumanReadableDryRun + "\x1b[31m" }, "AF-PLAN-SIGNATURE-INVALID"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			plan := fixtures.ClonePlan(fixture.Plan)
			testCase.mutate(plan)
			reason, _ := applyReason(t, fixture, plan, fixtures.EnforcerOptions{})
			if reason != testCase.reason {
				t.Fatalf("%s: reason = %q, want %q", testCase.name, reason, testCase.reason)
			}
		})
	}
}

func mustListValue(t *testing.T, values ...string) *structpb.Value {
	t.Helper()
	items := make([]any, 0, len(values))
	for _, value := range values {
		items = append(items, value)
	}
	list, err := structpb.NewList(items)
	if err != nil {
		t.Fatal(err)
	}
	return structpb.NewListValue(list)
}

// Invariant: a plan validly re-signed by a key the agent does not trust is
// rejected as AF-PLAN-SIGNATURE-INVALID even though its signature is
// internally consistent. Provenance, not self-consistency, is the gate.
func TestPlanSignedByForeignKeyIsRejected(t *testing.T) {
	t.Parallel()
	fixture := fixtures.NewPlanFixture(t)
	plan := fixtures.ClonePlan(fixture.Plan)
	plan.RecoveryAllowlist = []string{"attacker.example"}
	plan.Actions[0].Parameters.Fields["recoveryDestinations"] = mustListValue(t, "attacker.example")
	if err := fixtures.ResignPlan(plan, fixtures.PlanKeyID, fixtures.ForeignKey(), fixture.Now); err != nil {
		t.Fatal(err)
	}
	if err := policy.VerifyPlan(plan, fixtures.ForeignKey().Public().(ed25519.PublicKey), fixture.Now); err != nil {
		t.Fatalf("fixture self-check: foreign-signed plan should verify under the foreign key: %v", err)
	}
	reason, _ := applyReason(t, fixture, plan, fixtures.EnforcerOptions{})
	if reason != "AF-PLAN-SIGNATURE-INVALID" {
		t.Fatalf("reason = %q", reason)
	}
}

// Invariant: policy.VerifyPlan enforces the time window independently of the
// enforcer: expired plans and plans created more than five minutes in the
// future fail even with a valid signature.
func TestVerifyPlanWindowEdges(t *testing.T) {
	t.Parallel()
	fixture := fixtures.NewPlanFixture(t)
	created := fixture.Plan.CreatedAt.AsTime()
	expires := fixture.Plan.ExpiresAt.AsTime()
	cases := map[string]struct {
		now  time.Time
		pass bool
	}{
		"one-ns-before-expiry": {expires.Add(-time.Nanosecond), true},
		"at-expiry":            {expires, false},
		"after-expiry":         {expires.Add(time.Second), false},
		"skew-just-inside":     {created.Add(-5 * time.Minute), true},
		"skew-just-outside":    {created.Add(-5*time.Minute - time.Nanosecond), false},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := policy.VerifyPlan(fixture.Plan, fixture.PlanPublicKey, testCase.now)
			if (err == nil) != testCase.pass {
				t.Fatalf("%s: err = %v, want pass=%v", name, err, testCase.pass)
			}
		})
	}
	if err := policy.VerifyPlan(fixture.Plan, fixture.PlanPublicKey[:31], fixture.Now); err == nil {
		t.Fatal("short key accepted")
	}
	if err := policy.VerifyPlan(nil, fixture.PlanPublicKey, fixture.Now); err == nil {
		t.Fatal("nil plan accepted")
	}
}

// Invariant: an oversized plan is rejected before any field is inspected.
// Expected: AF-PLAN-WIRE-INVALID.
func TestOversizedPlanIsRejectedBeforeInspection(t *testing.T) {
	t.Parallel()
	fixture := fixtures.NewPlanFixture(t)
	plan := fixtures.ClonePlan(fixture.Plan)
	plan.HumanReadableDryRun = strings.Repeat("x", 600*1024)
	if proto.Size(plan) <= 512*1024 {
		t.Fatal("fixture is not oversized")
	}
	reason, _ := applyReason(t, fixture, plan, fixtures.EnforcerOptions{})
	if reason != "AF-PLAN-WIRE-INVALID" {
		t.Fatalf("reason = %q", reason)
	}
}
