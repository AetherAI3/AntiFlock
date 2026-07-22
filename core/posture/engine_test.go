package posture_test

import (
	"slices"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/posture"
)

func TestCoffeeShopPostureFailsClosedAndRecoversDeterministically(t *testing.T) {
	t.Parallel()
	engine, err := posture.New(2 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	fact := func(value bool) posture.Fact {
		return posture.Fact{Known: true, Value: value, Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED, Confidence: 1, ObservedAt: now}
	}
	input := posture.Input{
		DeploymentID: "deployment", NodeID: "phone", PolicyID: "coffee-shop", PolicyRevision: 7,
		EvaluatedAt: now, TelemetryAt: now, NetworkTrust: "UNTRUSTED", RequireMeshOnUntrusted: true,
		MeshConnected: fact(false), ApprovedExitActive: fact(false), DNSProtected: fact(false), RouteProtected: fact(false),
	}
	exposed, err := engine.Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	if exposed.State != antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED || exposed.EnforcementState != antiflockv1.EnforcementState_ENFORCEMENT_STATE_HOLDING {
		t.Fatalf("unsafe posture = %s/%s", exposed.State, exposed.EnforcementState)
	}
	codes := make([]string, 0, len(exposed.Reasons))
	for _, reason := range exposed.Reasons {
		codes = append(codes, reason.ReasonCode)
		if reason.Claim.Classification == antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED {
			t.Fatal("self-observed coffee-shop fact was upgraded to VERIFIED")
		}
	}
	if !slices.Contains(codes, posture.ReasonMeshDisconnected) || !slices.Contains(codes, posture.ReasonExitUnverified) {
		t.Fatalf("missing exact failure reasons: %v", codes)
	}
	repeated, err := engine.Evaluate(input)
	if err != nil || repeated.Id != exposed.Id {
		t.Fatalf("deterministic reevaluation = %q, %v", repeated.GetId(), err)
	}
	input.EvaluatedAt = now.Add(time.Second)
	input.TelemetryAt = input.EvaluatedAt
	input.MeshConnected = fact(true)
	input.ApprovedExitActive = fact(true)
	input.DNSProtected = fact(true)
	input.RouteProtected = fact(true)
	input.MeshConnected.ObservedAt = input.EvaluatedAt
	input.ApprovedExitActive.ObservedAt = input.EvaluatedAt
	input.DNSProtected.ObservedAt = input.EvaluatedAt
	input.RouteProtected.ObservedAt = input.EvaluatedAt
	protected, err := engine.Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	if protected.State != antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED || protected.EnforcementState != antiflockv1.EnforcementState_ENFORCEMENT_STATE_ALLOWING {
		t.Fatalf("restored posture = %s/%s", protected.State, protected.EnforcementState)
	}
}

func TestMissingOrStaleTelemetryNeverMeansProtected(t *testing.T) {
	t.Parallel()
	engine, _ := posture.New(time.Minute)
	now := time.Now().UTC()
	for _, telemetryAt := range []time.Time{{}, now.Add(-2 * time.Minute), now} {
		snapshot, err := engine.Evaluate(posture.Input{
			DeploymentID: "deployment", NodeID: "phone", PolicyID: "policy", PolicyRevision: 1,
			EvaluatedAt: now, TelemetryAt: telemetryAt, NetworkTrust: "UNKNOWN",
		})
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.State == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED {
			t.Fatal("missing or stale telemetry produced PROTECTED")
		}
	}
}
