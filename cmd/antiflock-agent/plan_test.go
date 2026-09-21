package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DBarr3/AntiFlock/agent/enforcement"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestPlanVerifyReportsValidButNonExecutableInJSONAndHumanModes(t *testing.T) {
	t.Parallel()
	arguments := writePlanVerificationFixture(t)
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), append([]string{"plan", "verify"}, arguments...), &stdout, &stderr); err != nil {
		t.Fatalf("verify plan: %v; stderr=%s", err, stderr.String())
	}
	var output planVerificationOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if !output.Valid || !output.CapabilityCompatible || output.Executable || output.Mode != "verify-only-no-host-mutation" || len(output.Drivers) != 5 {
		t.Fatalf("verification output = %#v", output)
	}
	for _, driver := range output.Drivers {
		if driver.Available {
			t.Fatalf("driver was misleadingly available: %#v", driver)
		}
	}
	stdout.Reset()
	stderr.Reset()
	humanArguments := append(append([]string(nil), arguments...), "--format", "human")
	if err := run(context.Background(), append([]string{"plan", "verify"}, humanArguments...), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "executable: false") || !strings.Contains(stdout.String(), "recovery: unavailable") {
		t.Fatalf("human verification output = %s", stdout.String())
	}
}

func TestPlanVerifyReturnsNonzeroForTamperedTargetAfterWritingStructuredResult(t *testing.T) {
	t.Parallel()
	arguments := writePlanVerificationFixture(t)
	var planPath string
	for index := range arguments {
		if arguments[index] == "--plan" {
			planPath = arguments[index+1]
			break
		}
	}
	content, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	plan := &antiflockv1.Plan{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(content, plan); err != nil {
		t.Fatal(err)
	}
	plan.NodeId = "other-node"
	content, err = (protojson.MarshalOptions{UseProtoNames: true}).Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = run(context.Background(), append([]string{"plan", "verify"}, arguments...), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "AF-PLAN-TARGET-MISMATCH") {
		t.Fatalf("tampered target result = %v", err)
	}
	var output planVerificationOutput
	if decodeErr := json.Unmarshal(stdout.Bytes(), &output); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if output.Valid || output.Executable || output.ReasonCode != "AF-PLAN-TARGET-MISMATCH" {
		t.Fatalf("tampered target output = %#v", output)
	}
}

func TestPlanVerifyHumanOutputEscapesExternalIdentifiers(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	writePlanVerificationHuman(&output, planVerificationOutput{
		PlanVerification: &enforcement.PlanVerification{
			PlanID:              "plan_ok\r\nexecutable: true\x1b[2J\u202E",
			MissingCapabilities: []string{"dns.ok\x1b[31m", "mesh.ok\r\nforged"},
		},
	})
	text := output.String()
	if strings.ContainsAny(text, "\r\x1b\u202E") || strings.Contains(text, "\nexecutable: true") ||
		!strings.Contains(text, `\r\n`) || !strings.Contains(text, `\x1b`) || !strings.Contains(text, `\u202e`) {
		t.Fatalf("human output did not neutralize external identifiers: %q", text)
	}
}

func writePlanVerificationFixture(t *testing.T) []string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := planTestManifest()
	compiler, err := policy.NewCompiler("deployment", "policy-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	plan, violations, err := compiler.Compile(planTestProfile(), "node", 1, manifest)
	if err != nil || len(violations) != 0 {
		t.Fatalf("compile plan: %v %#v", err, violations)
	}
	directory := t.TempDir()
	planPath := filepath.Join(directory, "plan.json")
	manifestPath := filepath.Join(directory, "capabilities.json")
	keyPath := filepath.Join(directory, "policy.pem")
	planJSON, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(plan)
	manifestJSON, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(manifest)
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		planPath:     planJSON,
		manifestPath: manifestJSON,
		keyPath:      pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"--plan", planPath, "--deployment-id", "deployment", "--node-id", "node", "--plan-key-id", "policy-key", "--plan-public-key", keyPath, "--capabilities", manifestPath}
}

func planTestManifest() *antiflockv1.CapabilityManifest {
	return &antiflockv1.CapabilityManifest{NodeId: "node", Capabilities: []*antiflockv1.Capability{
		planTestCapability("firewall.egress.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		planTestCapability("mesh.path.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
		planTestCapability("network.route.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		planTestCapability("dns.protected.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
	}}
}

func planTestCapability(key string, operations ...antiflockv1.CapabilityOperation) *antiflockv1.Capability {
	return &antiflockv1.Capability{Key: key, Operations: operations, SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL}
}

func planTestProfile() *antiflockv1.ProtectionProfile {
	return &antiflockv1.ProtectionProfile{
		Metadata: &antiflockv1.ResourceMetadata{Id: "plan-test", Revision: 1}, ApiVersion: "antiflock.policy/v1",
		Mode:      antiflockv1.ProtectionMode_PROTECTION_MODE_GUARD,
		Mesh:      &antiflockv1.MeshPolicy{Required: true, Provider: "tailscale"},
		Egress:    &antiflockv1.EgressPolicy{Mode: antiflockv1.EgressMode_EGRESS_MODE_TRUSTED_EXIT, FailMode: antiflockv1.FailMode_FAIL_MODE_CLOSED, AllowedExitNodeIds: []string{"exit-node"}, RecoveryDestinations: []string{"127.0.0.1"}},
		Dns:       &antiflockv1.DnsPolicy{Mode: antiflockv1.DnsMode_DNS_MODE_PROTECTED, AllowedResolvers: []string{"9.9.9.9"}, RequirePathVerification: true},
		Networks:  &antiflockv1.NetworkPolicy{RequireMeshOnUntrusted: true, BlockOpenWifiWithoutMesh: true},
		Actions:   []*antiflockv1.ProtectedActionPolicy{{ApplicationIds: []string{"test-app"}, DataClasses: []string{"test-data"}, RequireProtectedState: true}},
		Telemetry: &antiflockv1.TelemetryPolicy{PayloadCapture: false, RetentionDays: 1},
	}
}
