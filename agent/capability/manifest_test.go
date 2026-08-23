package capability

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// pinnedManifestDigest pins the digest of testManifest() at SchemaVersion 1 so
// an accidental layout change fails loudly instead of re-identifying every
// signed manifest.
const pinnedManifestDigest = "f6617c57f238da14b466a8c2be0014f82c24f2514fcc1da088f268c72d7a57b5"

func TestManifestDigestIsDeterministicAndOrderIndependent(t *testing.T) {
	t.Parallel()
	first := testManifest(t, healthyProbe("a.one", "nftables"), healthyProbe("b.two", "nftables"))
	second := testManifest(t, healthyProbe("b.two", "nftables"), healthyProbe("a.one", "nftables"))
	firstDigest, err := first.DigestHex()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.DigestHex()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("entry order changed the digest: %s vs %s", firstDigest, secondDigest)
	}
	again, _ := first.DigestHex()
	if again != firstDigest {
		t.Fatal("digest is not stable across calls")
	}
}

func TestManifestDigestIsPinned(t *testing.T) {
	t.Parallel()
	digest, err := testManifest(t).DigestHex()
	if err != nil {
		t.Fatal(err)
	}
	if digest != pinnedManifestDigest {
		t.Fatalf("manifest digest layout changed: got %s want %s", digest, pinnedManifestDigest)
	}
}

func TestManifestDigestCoversEveryField(t *testing.T) {
	t.Parallel()
	base, _ := testManifest(t).DigestHex()
	mutations := map[string]func(*Manifest){
		"node":        func(m *Manifest) { m.NodeID = "node-0002" },
		"revision":    func(m *Manifest) { m.Revision++ },
		"issued":      func(m *Manifest) { m.IssuedAt = m.IssuedAt.Add(time.Second) },
		"expires":     func(m *Manifest) { m.ExpiresAt = m.ExpiresAt.Add(-time.Second) },
		"policy":      func(m *Manifest) { m.PolicyKeyID = "policy-key-2" },
		"attestation": func(m *Manifest) { m.AttestationRef = "tpm2:pcr-quote:abc" },
		"entry": func(m *Manifest) {
			probe := healthyProbe("firewall.nftables.enforce", "nftables")
			probe.Health = driver.HealthDegraded
			entry, _ := EntryFromProbe(probe)
			m.Capabilities[0] = entry
		},
	}
	for name, mutate := range mutations {
		manifest := testManifest(t)
		mutate(manifest)
		digest, err := manifest.DigestHex()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest == base {
			t.Fatalf("%s: mutation did not change the digest", name)
		}
	}
}

func TestManifestSignAndVerify(t *testing.T) {
	t.Parallel()
	manifest := signedManifest(t)
	public, _ := testKey(1)
	if err := manifest.Verify(public); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if manifest.Signature.KeyID != testNodeID {
		t.Fatalf("signature key id %q is not the node id", manifest.Signature.KeyID)
	}
	wrongPublic, _ := testKey(2)
	if err := manifest.Verify(wrongPublic); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("foreign key verified: %v", err)
	}
	manifest.Signature.Value[0] ^= 0x01
	if err := manifest.Verify(public); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered signature verified: %v", err)
	}
}

func TestManifestVerifyRejectsUnsignedAndForeignKeyID(t *testing.T) {
	t.Parallel()
	public, _ := testKey(1)
	unsigned := testManifest(t)
	if err := unsigned.Verify(public); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("unsigned manifest verified: %v", err)
	}
	signed := signedManifest(t)
	signed.Signature.KeyID = "node-0002"
	if err := signed.Verify(public); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("foreign key id accepted: %v", err)
	}
	signed = signedManifest(t)
	signed.Signature.Algorithm = "rsa"
	if err := signed.Verify(public); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("unsupported algorithm accepted: %v", err)
	}
}

func TestManifestSignatureDoesNotSurviveContentChange(t *testing.T) {
	t.Parallel()
	manifest := signedManifest(t)
	manifest.Revision++
	public, _ := testKey(1)
	if err := manifest.Verify(public); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("signature survived a revision change: %v", err)
	}
}

func TestManifestValidateRejections(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Manifest){
		"nil schema":      func(m *Manifest) { m.SchemaVersion = 2 },
		"empty node":      func(m *Manifest) { m.NodeID = "" },
		"node whitespace": func(m *Manifest) { m.NodeID = "node 1" },
		"node unicode":    func(m *Manifest) { m.NodeID = "node\u202e1" },
		"zero revision":   func(m *Manifest) { m.Revision = 0 },
		"zero issued":     func(m *Manifest) { m.IssuedAt = time.Time{} },
		"expires before":  func(m *Manifest) { m.ExpiresAt = m.IssuedAt },
		"validity":        func(m *Manifest) { m.ExpiresAt = m.IssuedAt.Add(MaxManifestValidity + time.Second) },
		"no entries":      func(m *Manifest) { m.Capabilities = nil },
		"duplicate entry": func(m *Manifest) { m.Capabilities = append(m.Capabilities, m.Capabilities[0]) },
		"entry expires before manifest": func(m *Manifest) {
			m.ExpiresAt = m.Capabilities[0].ExpiresAt.Add(time.Second)
		},
		"digest mismatch":    func(m *Manifest) { m.Capabilities[0].ProbeDigest = strings.Repeat("0", 64) },
		"entry content":      func(m *Manifest) { m.Capabilities[0].Health = 99 },
		"policy key":         func(m *Manifest) { m.PolicyKeyID = "" },
		"attestation":        func(m *Manifest) { m.AttestationRef = "tpm2:\x01" },
		"attestation length": func(m *Manifest) { m.AttestationRef = strings.Repeat("a", MaxAttestationRefLength+1) },
		"signature length": func(m *Manifest) {
			m.Signature = &Signature{KeyID: testNodeID, Algorithm: SignatureAlgorithm, Value: []byte{1}}
		},
	}
	for name, mutate := range cases {
		manifest := testManifest(t)
		mutate(manifest)
		if err := manifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("%s: expected ErrManifestInvalid, got %v", name, err)
		}
	}
	var nilManifest *Manifest
	if err := nilManifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("nil manifest validated: %v", err)
	}
}

func TestManifestToProtoProjectsProbeFactsIntoConstraints(t *testing.T) {
	t.Parallel()
	manifest := signedManifest(t, healthyProbe("b.two", "nftables"), healthyProbe("a.one", "nftables"))
	wire, err := manifest.ToProto()
	if err != nil {
		t.Fatal(err)
	}
	if wire.NodeId != testNodeID || wire.Revision != 7 || wire.Signature != nil {
		t.Fatalf("unexpected wire header: %+v", wire)
	}
	if len(wire.Capabilities) != 2 || wire.Capabilities[0].Key != "a.one" || wire.Capabilities[1].Key != "b.two" {
		t.Fatalf("wire capabilities are not sorted by key: %+v", wire.Capabilities)
	}
	capability := wire.Capabilities[0]
	if capability.Implementation != "nftables" || capability.ImplementationVersion != "0.1.0" ||
		capability.Domain != antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_FIREWALL ||
		capability.SupportLevel != antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL ||
		len(capability.Operations) != 4 || capability.ObservedAt == nil {
		t.Fatalf("wire capability fields are not projected: %+v", capability)
	}
	want := []string{"isolated-table-only", ConstraintProbeDigest + "=" + manifest.Capabilities[1].ProbeDigest, ConstraintHealth + "=HEALTHY", ConstraintRecoveryReady + "=true"}
	if !slices.Equal(capability.Constraints, want) {
		t.Fatalf("constraints %v, want %v", capability.Constraints, want)
	}
}

func TestManifestToProtoFailsClosedOnInvalidManifest(t *testing.T) {
	t.Parallel()
	manifest := testManifest(t)
	manifest.Capabilities = nil
	if _, err := manifest.ToProto(); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("invalid manifest projected: %v", err)
	}
}

func TestEntryRoundTripsProbe(t *testing.T) {
	t.Parallel()
	probe := healthyProbe("firewall.nftables.enforce", "nftables")
	entry, err := EntryFromProbe(probe)
	if err != nil {
		t.Fatal(err)
	}
	back := entry.Probe()
	want, _ := probe.Digest()
	got, err := back.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got != want || entry.ProbeDigest != want {
		t.Fatalf("round trip changed the probe digest: %s vs %s", got, want)
	}
	probe.Key = ""
	if _, err := EntryFromProbe(probe); !errors.Is(err, driver.ErrProbeInvalid) {
		t.Fatalf("invalid probe produced an entry: %v", err)
	}
}
