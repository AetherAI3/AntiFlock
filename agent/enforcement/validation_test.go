package enforcement

import (
	"slices"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
)

func TestVerifyPlanSeparatesValidityCapabilityCompatibilityAndExecution(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	config := PlanVerificationConfig{
		DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key",
		PlanPublicKey: fixture.planPublicKey, Capabilities: fixture.manifest,
		Clock: func() time.Time { return fixture.now },
	}
	verified, err := VerifyPlan(config, fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid || !verified.CapabilityCompatible || verified.Executable || verified.ReasonCode != "AF-PLAN-VERIFIED-EXECUTION-DISABLED" {
		t.Fatalf("verification = %#v", verified)
	}

	limited := proto.Clone(fixture.manifest).(*antiflockv1.CapabilityManifest)
	limited.Capabilities = limited.Capabilities[:1]
	config.Capabilities = limited
	verified, err = VerifyPlan(config, fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	wantMissing := []string{"dns.protected.enforce", "mesh.path.enforce", "network.route.enforce"}
	if !verified.Valid || verified.CapabilityCompatible || verified.Executable || verified.ReasonCode != "AF-PLAN-CAPABILITY-UNSUPPORTED" || !slices.Equal(verified.MissingCapabilities, wantMissing) {
		t.Fatalf("limited verification = %#v", verified)
	}
}

func TestVerifyPlanRejectsTamperingWithoutDriverOrReplayState(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	plan := proto.Clone(fixture.plan).(*antiflockv1.Plan)
	plan.HumanReadableDryRun = "tampered"
	verified, err := VerifyPlan(PlanVerificationConfig{
		DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key",
		PlanPublicKey: fixture.planPublicKey, Capabilities: fixture.manifest,
		Clock: func() time.Time { return fixture.now },
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Valid || verified.CapabilityCompatible || verified.Executable || verified.ReasonCode != "AF-PLAN-SIGNATURE-INVALID" {
		t.Fatalf("tampered verification = %#v", verified)
	}
}
