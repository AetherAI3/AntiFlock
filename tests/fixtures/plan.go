package fixtures

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/enforcement"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// DeploymentID, NodeID, and PlanKeyID are the fixed identities bound into
	// every fixture plan and enforcer.
	DeploymentID = "deployment"
	NodeID       = "node"
	PlanKeyID    = "policy-key"

	planDomain      = "antiflock.plan.v1"
	signaturePrefix = "AntiFlock-Signature-v1"
)

// PlanFixture is a signed, enforceable plan plus every key needed to verify,
// re-sign, or impersonate it.
type PlanFixture struct {
	Plan           *antiflockv1.Plan
	Manifest       *antiflockv1.CapabilityManifest
	PlanPrivateKey ed25519.PrivateKey
	PlanPublicKey  ed25519.PublicKey
	NodePrivateKey ed25519.PrivateKey
	NodePublicKey  ed25519.PublicKey
	// Now is one second after the plan was created; enforcers built from the
	// fixture observe this instant unless the caller overrides the clock.
	Now time.Time
}

// PlanKeys returns the deterministic plan-signing and node keys.
func PlanKeys() (planKey, nodeKey ed25519.PrivateKey) {
	planSeed := make([]byte, ed25519.SeedSize)
	nodeSeed := make([]byte, ed25519.SeedSize)
	for index := range planSeed {
		planSeed[index] = byte(index)
		nodeSeed[index] = byte(255 - index)
	}
	return ed25519.NewKeyFromSeed(planSeed), ed25519.NewKeyFromSeed(nodeSeed)
}

// ForeignKey is a deterministic Ed25519 key that is neither the plan key nor
// the node key; it models a signer the agent does not trust.
func ForeignKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index*7 + 3)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// FullManifest is the self-declared node manifest that satisfies every
// compiler requirement at FULL support.
func FullManifest() *antiflockv1.CapabilityManifest {
	return &antiflockv1.CapabilityManifest{NodeId: NodeID, Capabilities: []*antiflockv1.Capability{
		Capability("firewall.egress.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		Capability("mesh.path.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
		Capability("network.route.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		Capability("dns.protected.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
	}}
}

// Capability builds one FULL-support capability declaration.
func Capability(key string, operations ...antiflockv1.CapabilityOperation) *antiflockv1.Capability {
	return &antiflockv1.Capability{
		Key: key, Operations: operations, SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
	}
}

// ValidProfile returns the reference coffee-shop protection profile at the
// given policy revision.
func ValidProfile(revision uint64) *antiflockv1.ProtectionProfile {
	return &antiflockv1.ProtectionProfile{
		Metadata: &antiflockv1.ResourceMetadata{Id: "coffee-shop", Revision: revision}, ApiVersion: "antiflock.policy/v1",
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

// CompilePlan compiles and signs a plan with the deterministic plan key.
func CompilePlan(tb testing.TB, policyRevision, planRevision uint64, manifest *antiflockv1.CapabilityManifest) *antiflockv1.Plan {
	tb.Helper()
	planKey, _ := PlanKeys()
	compiler, err := policy.NewCompiler(DeploymentID, PlanKeyID, planKey)
	if err != nil {
		tb.Fatal(err)
	}
	plan, violations, err := compiler.Compile(ValidProfile(policyRevision), NodeID, planRevision, manifest)
	if err != nil || len(violations) != 0 {
		tb.Fatalf("compile plan: %v, %#v", err, violations)
	}
	return plan
}

// NewPlanFixture compiles policy revision 7, plan revision 1.
func NewPlanFixture(tb testing.TB) PlanFixture {
	tb.Helper()
	planKey, nodeKey := PlanKeys()
	manifest := FullManifest()
	plan := CompilePlan(tb, 7, 1, manifest)
	return PlanFixture{
		Plan: plan, Manifest: manifest,
		PlanPrivateKey: planKey, PlanPublicKey: planKey.Public().(ed25519.PublicKey),
		NodePrivateKey: nodeKey, NodePublicKey: nodeKey.Public().(ed25519.PublicKey),
		Now: plan.CreatedAt.AsTime().Add(time.Second),
	}
}

// EnforcerOptions override the defaults used by PlanFixture.Enforcer.
type EnforcerOptions struct {
	Manifest *antiflockv1.CapabilityManifest
	Clock    func() time.Time
}

// Enforcer builds an enforcer bound to the fixture identities. A nil store
// gets a fresh MemoryStateStore at revisions 0/0.
func (fixture PlanFixture) Enforcer(tb testing.TB, driver enforcement.Driver, store enforcement.StateStore, options EnforcerOptions) *enforcement.Enforcer {
	tb.Helper()
	if store == nil {
		store = enforcement.NewMemoryStateStore(0, 0)
	}
	manifest := options.Manifest
	if manifest == nil {
		manifest = fixture.Manifest
	}
	clock := options.Clock
	if clock == nil {
		clock = func() time.Time { return fixture.Now }
	}
	enforcer, err := enforcement.New(enforcement.Config{
		DeploymentID: DeploymentID, NodeID: NodeID, PlanKeyID: PlanKeyID, PlanPublicKey: fixture.PlanPublicKey,
		NodePrivateKey: fixture.NodePrivateKey, Capabilities: manifest, Driver: driver, StateStore: store,
		Clock: clock, MaximumEvidenceAge: 2 * time.Minute,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return enforcer
}

// ClonePlan deep-copies a plan so a test can mutate it freely.
func ClonePlan(plan *antiflockv1.Plan) *antiflockv1.Plan {
	return proto.Clone(plan).(*antiflockv1.Plan)
}

// ResignPlan re-signs a (possibly mutated) plan with the supplied key using
// the deterministic signing profile from docs/signing-contracts.md. It lets
// tests produce plans that are cryptographically valid yet semantically
// hostile (replayed nonce, rewound revision, foreign signer).
func ResignPlan(plan *antiflockv1.Plan, keyID string, key ed25519.PrivateKey, signedAt time.Time) error {
	if plan == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("plan and Ed25519 key are required")
	}
	view := proto.Clone(plan).(*antiflockv1.Plan)
	view.Signature = nil
	view.Status = antiflockv1.PlanStatus_PLAN_STATUS_UNSPECIFIED
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	signature := &antiflockv1.Signature{
		KeyId: keyID, Algorithm: antiflockv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
		SignedAt: timestamppb.New(signedAt.UTC()), Encoding: antiflockv1.SignatureEncoding_SIGNATURE_ENCODING_PROTOBUF_DETERMINISTIC_V1,
		SignedContentDigest: &antiflockv1.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]}, Domain: planDomain,
	}
	algorithm := make([]byte, 4)
	binary.BigEndian.PutUint32(algorithm, uint32(signature.Algorithm))
	seconds := make([]byte, 8)
	binary.BigEndian.PutUint64(seconds, uint64(signature.SignedAt.AsTime().Unix()))
	nanoseconds := make([]byte, 4)
	binary.BigEndian.PutUint32(nanoseconds, uint32(signature.SignedAt.AsTime().Nanosecond()))
	fields := [][]byte{[]byte(signaturePrefix), []byte(signature.Domain), algorithm, []byte("sha256"), signature.SignedContentDigest.Digest, seconds, nanoseconds}
	var input []byte
	for _, field := range fields {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(field)))
		input = append(input, length...)
		input = append(input, field...)
	}
	signature.Value = ed25519.Sign(key, input)
	plan.Signature = signature
	return nil
}

// RecordingDriver is an in-memory enforcement.Driver that records every call
// and never touches the host. It passes every check with DETECTED evidence.
type RecordingDriver struct {
	mu         sync.Mutex
	ObservedAt time.Time
	calls      []string
	FailCheck  string
	FailApply  string
}

// Check implements enforcement.Driver.
func (driver *RecordingDriver) Check(ctx context.Context, check *antiflockv1.PlanCheck) (enforcement.CheckObservation, error) {
	if err := ctx.Err(); err != nil {
		return enforcement.CheckObservation{}, err
	}
	driver.record("check:" + check.Id)
	outcome := antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED
	reason := "AF-FIXTURE-CHECK-PASSED"
	if check.Id == driver.FailCheck {
		outcome = antiflockv1.CheckOutcome_CHECK_OUTCOME_FAILED
		reason = "AF-FIXTURE-CHECK-FAILED"
	}
	return enforcement.CheckObservation{
		Outcome: outcome, ReasonCode: reason, SafeMessage: "Deterministic fixture check.",
		Evidence: []*antiflockv1.EvidenceReference{DetectedEvidence(check.Id, driver.ObservedAt)},
	}, nil
}

// Apply implements enforcement.Driver.
func (driver *RecordingDriver) Apply(ctx context.Context, operation *antiflockv1.PlanOperation) (enforcement.OperationObservation, error) {
	if err := ctx.Err(); err != nil {
		return enforcement.OperationObservation{}, err
	}
	driver.record("apply:" + operation.Id)
	if operation.Id == driver.FailApply {
		return enforcement.OperationObservation{Succeeded: false, ReasonCode: "AF-FIXTURE-APPLY-FAILED", SafeMessage: "Deterministic fixture failure."}, nil
	}
	return enforcement.OperationObservation{Succeeded: true, ReasonCode: "AF-FIXTURE-APPLY-PASSED", SafeMessage: "Deterministic fixture apply."}, nil
}

// Rollback implements enforcement.Driver.
func (driver *RecordingDriver) Rollback(ctx context.Context, operation *antiflockv1.PlanOperation) (enforcement.OperationObservation, error) {
	if err := ctx.Err(); err != nil {
		return enforcement.OperationObservation{}, err
	}
	driver.record("rollback:" + operation.Id)
	return enforcement.OperationObservation{Succeeded: true, ReasonCode: "AF-FIXTURE-ROLLBACK-PASSED", SafeMessage: "Deterministic fixture rollback."}, nil
}

func (driver *RecordingDriver) record(call string) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.calls = append(driver.calls, call)
}

// Calls returns a copy of the recorded call log.
func (driver *RecordingDriver) Calls() []string {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return append([]string(nil), driver.calls...)
}

// MutationCalls counts apply and rollback calls, i.e. every call that would
// have mutated a real host.
func (driver *RecordingDriver) MutationCalls() int {
	count := 0
	for _, call := range driver.Calls() {
		if len(call) > 6 && (call[:6] == "apply:" || call[:9] == "rollback:") {
			count++
		}
	}
	return count
}

// DetectedEvidence returns fresh DETECTED local-sensor evidence for a check.
func DetectedEvidence(checkID string, observedAt time.Time) *antiflockv1.EvidenceReference {
	return &antiflockv1.EvidenceReference{
		Id: "evidence-" + checkID, Role: antiflockv1.EvidenceRole_EVIDENCE_ROLE_SUPPORTING,
		Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED,
		SourceType:     antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_LOCAL_SENSOR,
		SourceName:     "deterministic-fixture-driver", ObservedAt: timestamppb.New(observedAt), Confidence: 1,
		Sensitivity:       antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		LocationPrecision: antiflockv1.LocationPrecision_LOCATION_PRECISION_WITHHELD,
		Summary:           "A deterministic in-memory endpoint check observed the simulated state.",
	}
}
