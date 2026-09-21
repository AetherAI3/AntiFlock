package capability

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

const (
	testNodeID      = "node-0001"
	testPolicyKeyID = "policy-key-1"
)

var testNow = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

// testKey derives a deterministic Ed25519 key from a seed byte so fixtures are
// stable across runs and fuzz seeds.
func testKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	raw := make([]byte, ed25519.SeedSize)
	for index := range raw {
		raw[index] = seed + byte(index)
	}
	private := ed25519.NewKeyFromSeed(raw)
	return private.Public().(ed25519.PublicKey), private
}

func healthyProbe(key string, driverName string) driver.ProbeResult {
	return driver.ProbeResult{
		SchemaVersion: driver.ProbeSchemaVersion,
		Key:           key,
		Domain:        antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_FIREWALL,
		Operations: []antiflockv1.CapabilityOperation{
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE,
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE,
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY,
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK,
		},
		SupportLevel:  antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL,
		DriverName:    driverName,
		DriverVersion: "0.1.0",
		Health:        driver.HealthHealthy,
		RecoveryReady: true,
		ReasonCodes:   []string{driver.ReasonProbeOK},
		Constraints:   []string{"isolated-table-only"},
		ProbedAt:      testNow.Add(-time.Minute),
		ExpiresAt:     testNow.Add(time.Hour),
	}
}

type staticProber struct {
	results []driver.ProbeResult
	err     error
	block   bool
}

func (prober staticProber) Probe(ctx context.Context) ([]driver.ProbeResult, error) {
	if prober.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return prober.results, prober.err
}

func testManifest(t testing.TB, probes ...driver.ProbeResult) *Manifest {
	t.Helper()
	if len(probes) == 0 {
		probes = []driver.ProbeResult{healthyProbe("firewall.nftables.enforce", "nftables")}
	}
	entries := make([]Entry, 0, len(probes))
	expiresAt := testNow.Add(MaxManifestValidity)
	for _, probe := range probes {
		entry, err := EntryFromProbe(probe)
		if err != nil {
			t.Fatalf("entry from probe: %v", err)
		}
		entries = append(entries, entry)
		if entry.ExpiresAt.Before(expiresAt) {
			expiresAt = entry.ExpiresAt
		}
	}
	return &Manifest{
		SchemaVersion: SchemaVersion,
		NodeID:        testNodeID,
		Revision:      7,
		IssuedAt:      testNow.Add(-30 * time.Second),
		ExpiresAt:     expiresAt,
		Capabilities:  entries,
		PolicyKeyID:   testPolicyKeyID,
	}
}

func signedManifest(t testing.TB, probes ...driver.ProbeResult) *Manifest {
	t.Helper()
	manifest := testManifest(t, probes...)
	_, private := testKey(1)
	if err := manifest.Sign(private); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return manifest
}

func manifestJSON(t testing.TB, manifest *Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func writeFixture(t testing.TB, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func defaultLoadOptions() LoadOptions {
	public, _ := testKey(1)
	return LoadOptions{ExpectedNodeID: testNodeID, NodePublicKey: public, Now: testNow}
}

func requirement(key string, minimum antiflockv1.CapabilitySupportLevel, operations ...antiflockv1.CapabilityOperation) *antiflockv1.CapabilityRequirement {
	return &antiflockv1.CapabilityRequirement{Key: key, RequiredOperations: operations, MinimumSupportLevel: minimum}
}

func loadCode(t testing.TB, err error) string {
	t.Helper()
	var loadErr *LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("expected *LoadError, got %v", err)
	}
	return loadErr.Code
}

func discoveryCode(t testing.TB, err error) string {
	t.Helper()
	var discoveryErr *DiscoveryError
	if !errors.As(err, &discoveryErr) {
		t.Fatalf("expected *DiscoveryError, got %v", err)
	}
	return discoveryErr.Code
}
