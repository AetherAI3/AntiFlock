package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func testCheckpoint() Checkpoint {
	return Checkpoint{
		DeploymentDigest: DigestString("deployment"), AuditHeadDigest: DigestString("head-7"),
		Sequence: 7, IssuedAt: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC), NodeCountBucket: NodeCountSmall,
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func TestCheckpointValidateRejectsEveryMalformedField(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Checkpoint){
		"raw deployment id": func(c *Checkpoint) { c.DeploymentDigest = "deployment-1" },
		"uppercase digest":  func(c *Checkpoint) { c.AuditHeadDigest = "ABCDEF" + c.AuditHeadDigest[6:] },
		"zero sequence":     func(c *Checkpoint) { c.Sequence = 0 },
		"zero time":         func(c *Checkpoint) { c.IssuedAt = time.Time{} },
		"exact node count":  func(c *Checkpoint) { c.NodeCountBucket = "42" },
	}
	for name, mutate := range cases {
		checkpoint := testCheckpoint()
		mutate(&checkpoint)
		if err := checkpoint.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: Validate() = %v, want ErrInvalidInput", name, err)
		}
	}
	if err := testCheckpoint().Validate(); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
}

func TestCheckpointDigestIsDeterministicAndFieldSensitive(t *testing.T) {
	t.Parallel()
	first, err := CheckpointDigest(testCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	second, _ := CheckpointDigest(testCheckpoint())
	if first != second || !ValidDigest(first) {
		t.Fatalf("digest not deterministic: %q vs %q", first, second)
	}
	changed := testCheckpoint()
	changed.IssuedAt = changed.IssuedAt.In(time.FixedZone("x", 3600))
	same, _ := CheckpointDigest(changed)
	if same != first {
		t.Fatal("time zone presentation changed the digest")
	}
	changed.Sequence++
	different, _ := CheckpointDigest(changed)
	if different == first {
		t.Fatal("sequence change did not change the digest")
	}
}

func TestReceiptSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	public, private := testKey(t)
	other, _ := testKey(t)
	digest, _ := CheckpointDigest(testCheckpoint())
	receipt, err := SignReceipt(WitnessReceipt{WitnessID: "witness-a", CheckpointDigest: digest, WitnessedAt: time.Now()}, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceiptFor(receipt, testCheckpoint(), public); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	if err := VerifyReceipt(receipt, other); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("wrong key: %v, want ErrInvalidReceipt", err)
	}
	tampered := receipt
	tampered.WitnessedAt = tampered.WitnessedAt.Add(time.Second)
	if err := VerifyReceipt(tampered, public); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("tampered time: %v, want ErrInvalidReceipt", err)
	}
	tampered = receipt
	tampered.KeyID = "witness:" + DigestString("other")
	if err := VerifyReceipt(tampered, public); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("substituted key id: %v, want ErrInvalidReceipt", err)
	}
	tampered = receipt
	tampered.Signature = append([]byte(nil), receipt.Signature...)
	tampered.Signature[0] ^= 1
	if err := VerifyReceipt(tampered, public); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("flipped signature: %v, want ErrInvalidReceipt", err)
	}
	otherCheckpoint := testCheckpoint()
	otherCheckpoint.Sequence = 8
	if err := VerifyReceiptFor(receipt, otherCheckpoint, public); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("receipt accepted for a different checkpoint: %v", err)
	}
	if _, err := SignReceipt(WitnessReceipt{WitnessID: "bad id", CheckpointDigest: digest, WitnessedAt: time.Now()}, private); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("non-canonical witness id signed: %v", err)
	}
}

func TestDecisionSignVerifyAndImmutability(t *testing.T) {
	t.Parallel()
	public, private := testKey(t)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	decision, err := SignDecision(Decision{
		DecisionID: "decision-1", ActionDigest: DigestString("action"), NodeDigest: DigestString("node"),
		Type: DecisionHold, ReasonCodes: []string{"AF-PROTECTION-NOT-VERIFIED"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecision(decision, public); err != nil {
		t.Fatalf("valid decision rejected: %v", err)
	}
	mutated := decision
	mutated.Type = DecisionAllow
	if err := VerifyDecision(mutated, public); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("consumer-side mutation accepted: %v", err)
	}
	mutated = decision
	mutated.ReasonCodes = []string{"AF-PROTECTION-NOT-VERIFIED", "AF-X"}
	if err := VerifyDecision(mutated, public); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("reason code addition accepted: %v", err)
	}
	unsorted := decision
	unsorted.ReasonCodes = []string{"B", "A"}
	if _, err := ComputeDecisionDigest(unsorted); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsorted reason codes accepted: %v", err)
	}
	if _, err := SignDecision(Decision{DecisionID: "d", ActionDigest: DigestString("a"), NodeDigest: DigestString("n"), Type: DecisionBlock, ReasonCodes: []string{"AF-X"}, IssuedAt: now, ExpiresAt: now}, private); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expiry equal to issue accepted: %v", err)
	}
}

func TestIdentifierAndDigestValidation(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", " x", "x\n", "héllo", "a b"} {
		if ValidIdentifier(bad) {
			t.Errorf("ValidIdentifier(%q) = true", bad)
		}
	}
	if !ValidIdentifier("audit:abc-1_2.3") {
		t.Fatal("canonical identifier rejected")
	}
	if ValidDigest(DigestString("x")[:63]) || ValidDigest("G"+DigestString("x")[1:]) {
		t.Fatal("malformed digest accepted")
	}
	credential := Credential{Kind: CredentialBearer, Value: "secret-token-value"}
	if got := credential.String(); got != "Credential{Kind:bearer Value:<redacted>}" {
		t.Fatalf("credential String() leaked or changed: %q", got)
	}
	if err := (Credential{Kind: "oauth-access-token", Value: "x"}).Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("provider-specific credential kind accepted: %v", err)
	}
	if err := (Credential{Kind: CredentialCertificateFingerprint, Value: "not-hex"}).Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-digest fingerprint accepted: %v", err)
	}
}
