package driver

import (
	"errors"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

func validResult() ProbeResult {
	probedAt := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	return ProbeResult{
		SchemaVersion: ProbeSchemaVersion,
		Key:           "firewall.nftables.enforce",
		Domain:        antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_FIREWALL,
		Operations: []antiflockv1.CapabilityOperation{
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY,
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE,
		},
		SupportLevel:  antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
		DriverName:    "nftables",
		DriverVersion: "0.1.0",
		Health:        HealthHealthy,
		RecoveryReady: true,
		ReasonCodes:   []string{ReasonProbeOK},
		Constraints:   []string{"isolated-table-only"},
		ProbedAt:      probedAt,
		ExpiresAt:     probedAt.Add(10 * time.Minute),
	}
}

// pinnedDigest is the digest of validResult() at ProbeSchemaVersion 1. It is
// pinned so an accidental change to the digest layout fails this test instead
// of silently re-identifying every stored manifest and receipt.
const pinnedDigest = "10a87041bb92a1a22b2b1d9e245fc01654f6c7b12faa57d854586e7eec372b0a"

func TestProbeResultValidateAcceptsCanonicalResult(t *testing.T) {
	t.Parallel()
	if err := validResult().Validate(); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
}

func TestProbeResultValidateRejectsEveryInvariantBreach(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*ProbeResult){
		"schema":               func(r *ProbeResult) { r.SchemaVersion = 2 },
		"empty key":            func(r *ProbeResult) { r.Key = "" },
		"upper key":            func(r *ProbeResult) { r.Key = "Firewall.nftables" },
		"dotted key":           func(r *ProbeResult) { r.Key = "firewall..nftables" },
		"long key":             func(r *ProbeResult) { r.Key = strings.Repeat("a", MaxProbeKeyLength+1) },
		"domain":               func(r *ProbeResult) { r.Domain = antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_UNSPECIFIED },
		"unknown domain":       func(r *ProbeResult) { r.Domain = antiflockv1.CapabilityDomain(999) },
		"no operations":        func(r *ProbeResult) { r.Operations = nil },
		"duplicate operations": func(r *ProbeResult) { r.Operations = append(r.Operations, r.Operations[0]) },
		"unspecified op":       func(r *ProbeResult) { r.Operations = []antiflockv1.CapabilityOperation{0} },
		"support level":        func(r *ProbeResult) { r.SupportLevel = 0 },
		"driver name":          func(r *ProbeResult) { r.DriverName = "nf tables" },
		"driver version ctrl":  func(r *ProbeResult) { r.DriverVersion = "0.1\x1b[31m" },
		"health range":         func(r *ProbeResult) { r.Health = HealthUnavailable + 1 },
		"recovery unavailable": func(r *ProbeResult) { r.Health = HealthUnavailable },
		"recovery unknown":     func(r *ProbeResult) { r.Health = HealthUnknown },
		"no reasons":           func(r *ProbeResult) { r.ReasonCodes = nil },
		"bad reason":           func(r *ProbeResult) { r.ReasonCodes = []string{"ok"} },
		"lower reason":         func(r *ProbeResult) { r.ReasonCodes = []string{"AF-probe-ok"} },
		"too many reasons":     func(r *ProbeResult) { r.ReasonCodes = make([]string, MaxProbeReasonCodes+1) },
		"constraint bidi":      func(r *ProbeResult) { r.Constraints = []string{"\u202etable"} },
		"constraint empty":     func(r *ProbeResult) { r.Constraints = []string{""} },
		"zero probed":          func(r *ProbeResult) { r.ProbedAt = time.Time{} },
		"zero expires":         func(r *ProbeResult) { r.ExpiresAt = time.Time{} },
		"expires before":       func(r *ProbeResult) { r.ExpiresAt = r.ProbedAt },
		"validity":             func(r *ProbeResult) { r.ExpiresAt = r.ProbedAt.Add(MaxProbeValidity + time.Second) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validResult()
			mutate(&result)
			err := result.Validate()
			if !errors.Is(err, ErrProbeInvalid) {
				t.Fatalf("expected ErrProbeInvalid, got %v", err)
			}
			if _, err := result.Digest(); !errors.Is(err, ErrProbeInvalid) {
				t.Fatalf("digest of invalid result must fail closed, got %v", err)
			}
		})
	}
}

func TestProbeResultDigestIsOrderIndependentAndContentBound(t *testing.T) {
	t.Parallel()
	base := validResult()
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest != pinnedDigest {
		t.Fatalf("digest layout changed: got %s, pinned %s", baseDigest, pinnedDigest)
	}
	reordered := validResult()
	reordered.Operations = []antiflockv1.CapabilityOperation{reordered.Operations[1], reordered.Operations[0]}
	reorderedDigest, err := reordered.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest != reorderedDigest {
		t.Fatalf("digest changed with slice order: %s != %s", baseDigest, reorderedDigest)
	}
	changed := validResult()
	changed.RecoveryReady = false
	changedDigest, err := changed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == baseDigest {
		t.Fatal("digest ignored recovery readiness")
	}
	later := validResult()
	later.ProbedAt = later.ProbedAt.Add(time.Nanosecond)
	laterDigest, err := later.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if laterDigest == baseDigest {
		t.Fatal("digest ignored probe timestamp")
	}
}

func TestProbeResultExpired(t *testing.T) {
	t.Parallel()
	result := validResult()
	if result.Expired(result.ExpiresAt.Add(-time.Second)) {
		t.Fatal("not yet expired")
	}
	if !result.Expired(result.ExpiresAt) {
		t.Fatal("expiry boundary must be expired")
	}
}

func TestHealthStatusString(t *testing.T) {
	t.Parallel()
	want := map[HealthStatus]string{HealthUnknown: "UNKNOWN", HealthHealthy: "HEALTHY", HealthDegraded: "DEGRADED", HealthUnavailable: "UNAVAILABLE", HealthStatus(9): "UNKNOWN"}
	for status, text := range want {
		if status.String() != text {
			t.Fatalf("%d => %q, want %q", status, status.String(), text)
		}
	}
}
