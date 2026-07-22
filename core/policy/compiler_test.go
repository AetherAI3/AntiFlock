package policy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
)

func TestCompilerRejectsFailOpenAndBuildsSignedRollbackPlan(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.NewCompiler("deployment", "policy-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	profile := validProfile()
	manifest := &antiflockv1.CapabilityManifest{NodeId: "node", Capabilities: []*antiflockv1.Capability{
		capability("firewall.egress.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		capability("mesh.path.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
		capability("network.route.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		capability("dns.protected.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
	}}
	plan, violations, err := compiler.Compile(profile, "node", 1, manifest)
	if err != nil || len(violations) != 0 {
		t.Fatalf("compile = %#v, %v", violations, err)
	}
	if len(plan.Actions) != 4 || len(plan.Rollback) != 3 || plan.Signature == nil || len(plan.RecoveryAllowlist) == 0 {
		t.Fatalf("incomplete plan = %#v", plan)
	}
	if exits := plan.Actions[2].Parameters.GetFields()["allowedExitNodeIds"].GetListValue().GetValues(); len(exits) != 1 || exits[0].GetStringValue() != "home-gateway" {
		t.Fatalf("compiled route targets = %#v", exits)
	}
	if resolvers := plan.Actions[3].Parameters.GetFields()["allowedResolvers"].GetListValue().GetValues(); len(resolvers) != 1 || resolvers[0].GetStringValue() != "resolver.internal" {
		t.Fatalf("compiled DNS targets = %#v", resolvers)
	}
	if err := policy.VerifyPlan(plan, publicKey, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	originalDryRun := plan.HumanReadableDryRun
	plan.HumanReadableDryRun = "No changes will be made."
	if err := policy.VerifyPlan(plan, publicKey, time.Now().UTC()); err == nil {
		t.Fatal("tampered human-readable dry run was accepted")
	}
	plan.HumanReadableDryRun = originalDryRun
	plan.Actions[0].Target = "tampered"
	if err := policy.VerifyPlan(plan, publicKey, time.Now().UTC()); err == nil {
		t.Fatal("tampered plan was accepted")
	}
	profile = validProfile()
	profile.Egress.FailMode = antiflockv1.FailMode_FAIL_MODE_OPEN
	if violations := policy.Validate(profile); len(violations) == 0 {
		t.Fatal("fail-open profile was accepted")
	}
}

func TestValidateRejectsAmbiguousEnforcementTargets(t *testing.T) {
	for name, mutate := range map[string]func(*antiflockv1.ProtectionProfile){
		"unsupported provider":      func(profile *antiflockv1.ProtectionProfile) { profile.Mesh.Provider = "shell-command" },
		"missing approved exit":     func(profile *antiflockv1.ProtectionProfile) { profile.Egress.AllowedExitNodeIds = nil },
		"missing approved resolver": func(profile *antiflockv1.ProtectionProfile) { profile.Dns.AllowedResolvers = nil },
		"duplicate recovery destination": func(profile *antiflockv1.ProtectionProfile) {
			profile.Egress.RecoveryDestinations = []string{"core.internal", "core.internal"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(profile)
			if violations := policy.Validate(profile); len(violations) == 0 {
				t.Fatal("ambiguous enforcement policy was accepted")
			}
		})
	}
}

func validProfile() *antiflockv1.ProtectionProfile {
	return &antiflockv1.ProtectionProfile{
		Metadata: &antiflockv1.ResourceMetadata{Id: "coffee-shop", Revision: 7}, ApiVersion: "antiflock.policy/v1",
		Mode: antiflockv1.ProtectionMode_PROTECTION_MODE_GUARD,
		Mesh: &antiflockv1.MeshPolicy{Required: true, Provider: "tailscale"},
		Egress: &antiflockv1.EgressPolicy{
			Mode: antiflockv1.EgressMode_EGRESS_MODE_TRUSTED_EXIT, FailMode: antiflockv1.FailMode_FAIL_MODE_CLOSED,
			AllowedExitNodeIds: []string{"home-gateway"}, RecoveryDestinations: []string{"core.internal"},
		},
		Dns:       &antiflockv1.DnsPolicy{Mode: antiflockv1.DnsMode_DNS_MODE_PROTECTED, AllowedResolvers: []string{"resolver.internal"}, RequirePathVerification: true},
		Networks:  &antiflockv1.NetworkPolicy{RequireMeshOnUntrusted: true, BlockOpenWifiWithoutMesh: true},
		Actions:   []*antiflockv1.ProtectedActionPolicy{{ApplicationIds: []string{"aether-code"}, DataClasses: []string{"repository-source"}, RequireProtectedState: true}},
		Telemetry: &antiflockv1.TelemetryPolicy{FlowMetadata: true, PayloadCapture: false, RetentionDays: 14},
	}
}

func capability(key string, operations ...antiflockv1.CapabilityOperation) *antiflockv1.Capability {
	return &antiflockv1.Capability{Key: key, Operations: operations, SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL}
}
