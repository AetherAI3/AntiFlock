package capability

import (
	"slices"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

const enforceKey = "firewall.nftables.enforce"

var (
	opObserve  = antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE
	opEnforce  = antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE
	opRollback = antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK
	levelFull  = antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL
	levelPart  = antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_PARTIAL
	levelExp   = antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_EXPERIMENTAL
	levelUnsup = antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSUPPORTED
	levelNone  = antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSPECIFIED
)

type readinessCase struct {
	name          string
	probe         func(*driver.ProbeResult)
	manifest      func(*Manifest)
	requirement   *antiflockv1.CapabilityRequirement
	now           time.Time
	compatible    bool
	driverReady   bool
	recoveryReady bool
	codes         []string
	manifestCodes []string
}

func TestEvaluateTable(t *testing.T) {
	t.Parallel()
	cases := []readinessCase{
		{
			name:        "ok on every axis",
			requirement: requirement(enforceKey, levelFull, opEnforce, opRollback),
			compatible:  true, driverReady: true, recoveryReady: true,
			codes: []string{ReasonOK},
		},
		{
			name:        "partial minimum accepts full",
			requirement: requirement(enforceKey, levelPart, opObserve),
			compatible:  true, driverReady: true, recoveryReady: true,
			codes: []string{ReasonOK},
		},
		{
			name:        "missing key",
			requirement: requirement("dns.resolver.enforce", levelFull, opEnforce),
			codes:       []string{ReasonMissing},
		},
		{
			name:        "support level too low",
			probe:       func(p *driver.ProbeResult) { p.SupportLevel = levelPart },
			requirement: requirement(enforceKey, levelFull, opEnforce),
			codes:       []string{ReasonSupportLevel},
		},
		{
			name:        "experimental does not satisfy full",
			probe:       func(p *driver.ProbeResult) { p.SupportLevel = levelExp },
			requirement: requirement(enforceKey, levelFull, opEnforce),
			codes:       []string{ReasonSupportLevel},
		},
		{
			name:        "full does not satisfy experimental",
			requirement: requirement(enforceKey, levelExp, opEnforce),
			codes:       []string{ReasonSupportLevel},
		},
		{
			name:        "unsupported minimum accepts anything specified",
			requirement: requirement(enforceKey, levelUnsup, opEnforce),
			compatible:  true, driverReady: true, recoveryReady: true,
			codes: []string{ReasonOK},
		},
		{
			name:        "operation missing",
			probe:       func(p *driver.ProbeResult) { p.Operations = []antiflockv1.CapabilityOperation{opObserve} },
			requirement: requirement(enforceKey, levelFull, opObserve, opEnforce),
			codes:       []string{ReasonOperationMissing},
		},
		{
			name: "support level and operation both reported",
			probe: func(p *driver.ProbeResult) {
				p.SupportLevel = levelPart
				p.Operations = []antiflockv1.CapabilityOperation{opObserve}
			},
			requirement: requirement(enforceKey, levelFull, opEnforce),
			codes:       []string{ReasonSupportLevel, ReasonOperationMissing},
		},
		{
			name:          "manifest expired at the exact boundary",
			requirement:   requirement(enforceKey, levelFull, opEnforce),
			now:           testNow.Add(time.Hour),
			codes:         []string{ReasonExpired},
			manifestCodes: []string{ReasonExpired},
		},
		{
			name:        "health degraded",
			probe:       func(p *driver.ProbeResult) { p.Health = driver.HealthDegraded },
			requirement: requirement(enforceKey, levelFull, opEnforce),
			compatible:  true,
			codes:       []string{ReasonHealthDegraded},
		},
		{
			name:        "health unavailable",
			probe:       func(p *driver.ProbeResult) { p.Health = driver.HealthUnavailable; p.RecoveryReady = false },
			requirement: requirement(enforceKey, levelFull, opEnforce),
			compatible:  true,
			codes:       []string{ReasonHealthUnavailable, ReasonRecoveryNotReady},
		},
		{
			name:        "health unknown",
			probe:       func(p *driver.ProbeResult) { p.Health = driver.HealthUnknown; p.RecoveryReady = false },
			requirement: requirement(enforceKey, levelFull, opEnforce),
			compatible:  true,
			codes:       []string{ReasonHealthUnknown, ReasonRecoveryNotReady},
		},
		{
			name:        "recovery not ready",
			probe:       func(p *driver.ProbeResult) { p.RecoveryReady = false },
			requirement: requirement(enforceKey, levelFull, opEnforce),
			compatible:  true, driverReady: true,
			codes: []string{ReasonRecoveryNotReady},
		},
		{
			name:        "nil requirement",
			requirement: nil,
			codes:       []string{ReasonRequirementInvalid},
		},
		{
			name:        "requirement without operations",
			requirement: requirement(enforceKey, levelFull),
			codes:       []string{ReasonRequirementInvalid},
		},
		{
			name:        "requirement with unspecified minimum",
			requirement: requirement(enforceKey, levelNone, opEnforce),
			codes:       []string{ReasonRequirementInvalid},
		},
		{
			name:        "requirement with unspecified operation",
			requirement: requirement(enforceKey, levelFull, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_UNSPECIFIED),
			codes:       []string{ReasonRequirementInvalid},
		},
		{
			name:          "manifest expired",
			requirement:   requirement(enforceKey, levelFull, opEnforce),
			now:           testNow.Add(2 * time.Hour),
			codes:         []string{ReasonExpired},
			manifestCodes: []string{ReasonExpired},
		},
		{
			name:          "manifest not yet valid",
			requirement:   requirement(enforceKey, levelFull, opEnforce),
			now:           testNow.Add(-time.Hour),
			codes:         []string{ReasonNotYetValid},
			manifestCodes: []string{ReasonNotYetValid},
		},
		{
			name:          "manifest schema invalid",
			manifest:      func(m *Manifest) { m.Capabilities[0].ProbeDigest = "00" },
			requirement:   requirement(enforceKey, levelFull, opEnforce),
			codes:         []string{ReasonSchema},
			manifestCodes: []string{ReasonSchema},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			probe := healthyProbe(enforceKey, "nftables")
			if testCase.probe != nil {
				testCase.probe(&probe)
			}
			manifest := testManifest(t, probe)
			if testCase.manifest != nil {
				testCase.manifest(manifest)
			}
			now := testCase.now
			if now.IsZero() {
				now = testNow
			}
			readiness := Evaluate(manifest, []*antiflockv1.CapabilityRequirement{testCase.requirement}, now)
			if len(readiness.Verdicts) != 1 {
				t.Fatalf("expected one verdict, got %d", len(readiness.Verdicts))
			}
			verdict := readiness.Verdicts[0]
			if verdict.Compatible != testCase.compatible || verdict.DriverReady != testCase.driverReady || verdict.RecoveryReady != testCase.recoveryReady {
				t.Fatalf("verdict %+v, want compatible=%v driverReady=%v recoveryReady=%v", verdict, testCase.compatible, testCase.driverReady, testCase.recoveryReady)
			}
			if !slices.Equal(verdict.ReasonCodes, testCase.codes) {
				t.Fatalf("codes %v, want %v", verdict.ReasonCodes, testCase.codes)
			}
			if !slices.Equal(readiness.ReasonCodes, testCase.manifestCodes) {
				t.Fatalf("manifest codes %v, want %v", readiness.ReasonCodes, testCase.manifestCodes)
			}
			if readiness.AllCompatible != testCase.compatible || readiness.AllDriverReady != testCase.driverReady || readiness.AllRecoveryReady != testCase.recoveryReady {
				t.Fatalf("aggregates %+v disagree with the single verdict", readiness)
			}
			if readiness.Expired != slices.Contains(testCase.manifestCodes, ReasonExpired) {
				t.Fatalf("Expired=%v disagrees with manifest codes %v", readiness.Expired, testCase.manifestCodes)
			}
		})
	}
}

func TestEvaluateVerdictsAreIndependent(t *testing.T) {
	t.Parallel()
	degraded := healthyProbe("dns.resolver.enforce", "resolver")
	degraded.Domain = antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_DNS
	degraded.Health = driver.HealthDegraded
	manifest := testManifest(t, healthyProbe(enforceKey, "nftables"), degraded)
	readiness := Evaluate(manifest, []*antiflockv1.CapabilityRequirement{
		requirement(enforceKey, levelFull, opEnforce),
		requirement("dns.resolver.enforce", levelFull, opEnforce),
		requirement("missing.key", levelFull, opEnforce),
	}, testNow)
	if len(readiness.Verdicts) != 3 {
		t.Fatalf("expected 3 verdicts, got %d", len(readiness.Verdicts))
	}
	if !readiness.Verdicts[0].RecoveryReady || readiness.Verdicts[1].DriverReady || readiness.Verdicts[2].Compatible {
		t.Fatalf("verdicts are not independent: %+v", readiness.Verdicts)
	}
	if readiness.Verdicts[1].Health != driver.HealthDegraded {
		t.Fatalf("verdict health %v is not the probe health", readiness.Verdicts[1].Health)
	}
	if readiness.AllCompatible || readiness.AllDriverReady || readiness.AllRecoveryReady || readiness.Expired {
		t.Fatalf("aggregates must fail when any verdict fails: %+v", readiness)
	}
}

func TestEvaluateEmptyRequirementsFailsClosed(t *testing.T) {
	t.Parallel()
	readiness := Evaluate(testManifest(t), nil, testNow)
	if readiness.AllCompatible || readiness.AllDriverReady || readiness.AllRecoveryReady || len(readiness.Verdicts) != 0 {
		t.Fatalf("empty requirements must not be satisfied: %+v", readiness)
	}
	if !slices.Equal(readiness.ReasonCodes, []string{ReasonRequirementInvalid}) {
		t.Fatalf("codes %v", readiness.ReasonCodes)
	}
}

func TestEvaluateNilManifestFailsClosed(t *testing.T) {
	t.Parallel()
	readiness := Evaluate(nil, []*antiflockv1.CapabilityRequirement{requirement(enforceKey, levelFull, opEnforce)}, testNow)
	if readiness.AllCompatible || len(readiness.Verdicts) != 1 || !slices.Equal(readiness.Verdicts[0].ReasonCodes, []string{ReasonSchema}) {
		t.Fatalf("nil manifest was not rejected: %+v", readiness)
	}
}

func TestEvaluateDoesNotMutateInputs(t *testing.T) {
	t.Parallel()
	manifest := testManifest(t)
	before, _ := manifest.DigestHex()
	requirements := []*antiflockv1.CapabilityRequirement{requirement(enforceKey, levelFull, opEnforce)}
	Evaluate(manifest, requirements, testNow)
	after, _ := manifest.DigestHex()
	if before != after || len(requirements[0].RequiredOperations) != 1 {
		t.Fatal("Evaluate mutated its inputs")
	}
}
