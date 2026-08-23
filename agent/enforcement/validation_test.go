package enforcement

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
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

func TestVerifyPlanRejectsValidlySignedOperatorOutputControls(t *testing.T) {
	t.Parallel()
	for name, malicious := range map[string]string{
		"line-break": "plan_ok\r\nexecutable: true",
		"ansi":       "plan_ok\x1b[2J",
		"bidi":       "plan_ok\u202Edenied",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			plan := proto.Clone(fixture.plan).(*antiflockv1.Plan)
			plan.Id = malicious
			resignPlanForTest(t, plan, fixture.planPrivateKey)
			if err := policy.VerifyPlan(plan, fixture.planPublicKey, fixture.now); err != nil {
				t.Fatalf("malicious fixture is not validly signed: %v", err)
			}
			verified, err := VerifyPlan(PlanVerificationConfig{
				DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key",
				PlanPublicKey: fixture.planPublicKey, Capabilities: fixture.manifest,
				Clock: func() time.Time { return fixture.now },
			}, plan)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Valid || verified.Executable || verified.ReasonCode != "AF-PLAN-IDENTITY-INVALID" {
				t.Fatalf("control-bearing plan verification = %#v", verified)
			}
		})
	}
}

func TestVerifyPlanRejectsValidlySignedCapabilityControl(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	plan := proto.Clone(fixture.plan).(*antiflockv1.Plan)
	plan.Actions[0].RequiredCapabilities[0].Key = "firewall.egress.enforce\x1b[2J"
	resignPlanForTest(t, plan, fixture.planPrivateKey)
	if err := policy.VerifyPlan(plan, fixture.planPublicKey, fixture.now); err != nil {
		t.Fatalf("malicious fixture is not validly signed: %v", err)
	}
	verified, err := VerifyPlan(PlanVerificationConfig{
		DeploymentID: "deployment", NodeID: "node", PlanKeyID: "policy-key",
		PlanPublicKey: fixture.planPublicKey, Capabilities: fixture.manifest,
		Clock: func() time.Time { return fixture.now },
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Valid || verified.Executable || verified.ReasonCode != "AF-PLAN-CAPABILITY-INVALID" {
		t.Fatalf("control-bearing capability verification = %#v", verified)
	}
}

func resignPlanForTest(t *testing.T, plan *antiflockv1.Plan, privateKey ed25519.PrivateKey) {
	t.Helper()
	signature := plan.Signature
	view := proto.Clone(plan).(*antiflockv1.Plan)
	view.Signature = nil
	view.Status = antiflockv1.PlanStatus_PLAN_STATUS_UNSPECIFIED
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	signature.SignedContentDigest.Digest = digest[:]
	algorithm := make([]byte, 4)
	binary.BigEndian.PutUint32(algorithm, uint32(signature.Algorithm))
	seconds := make([]byte, 8)
	binary.BigEndian.PutUint64(seconds, uint64(signature.SignedAt.AsTime().Unix()))
	nanoseconds := make([]byte, 4)
	binary.BigEndian.PutUint32(nanoseconds, uint32(signature.SignedAt.AsTime().Nanosecond()))
	fields := [][]byte{
		[]byte("AntiFlock-Signature-v1"), []byte(signature.Domain), algorithm, []byte("sha256"),
		signature.SignedContentDigest.Digest, seconds, nanoseconds,
	}
	var input []byte
	for _, field := range fields {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(field)))
		input = append(input, length...)
		input = append(input, field...)
	}
	signature.Value = ed25519.Sign(privateKey, input)
}
