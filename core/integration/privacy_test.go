package integration

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// fieldSpec pins one allowed field: its name and its Go type.
type fieldSpec struct {
	name string
	kind string
}

// assertExactFields fails when value's struct has any field outside the
// allowlist, is missing an allowed field, or changes an allowed field's type.
// Adding a field to an outbound type is a privacy decision: it must be made
// here, deliberately, with the threat model open.
func assertExactFields(t *testing.T, value any, allowed []fieldSpec) {
	t.Helper()
	typ := reflect.TypeOf(value)
	if typ.Kind() != reflect.Struct {
		t.Fatalf("%s is not a struct", typ)
	}
	actual := make([]fieldSpec, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		actual = append(actual, fieldSpec{name: field.Name, kind: field.Type.String()})
	}
	if !reflect.DeepEqual(actual, allowed) {
		t.Fatalf("%s fields changed\n got: %v\nwant: %v\nthis is a privacy boundary: update docs/integration-interfaces.md and this allowlist together", typ, actual, allowed)
	}
	for _, field := range actual {
		lower := strings.ToLower(field.name)
		for _, forbidden := range []string{"nodeid", "label", "address", "payload", "body", "content", "telemetry", "email", "name"} {
			if lower == forbidden || (strings.Contains(lower, forbidden) && !strings.HasSuffix(lower, "digest")) {
				t.Fatalf("%s has a forbidden field %q (raw identifiers and content never cross a seam)", typ, field.name)
			}
		}
	}
}

func TestCheckpointFieldAllowlist(t *testing.T) {
	t.Parallel()
	assertExactFields(t, Checkpoint{}, []fieldSpec{
		{"DeploymentDigest", "string"},
		{"AuditHeadDigest", "string"},
		{"Sequence", "uint64"},
		{"IssuedAt", "time.Time"},
		{"NodeCountBucket", "integration.NodeCountBucket"},
	})
}

func TestWitnessReceiptFieldAllowlist(t *testing.T) {
	t.Parallel()
	assertExactFields(t, WitnessReceipt{}, []fieldSpec{
		{"WitnessID", "string"},
		{"CheckpointDigest", "string"},
		{"WitnessedAt", "time.Time"},
		{"Signature", "[]uint8"},
		{"KeyID", "string"},
	})
}

func TestPrincipalFieldAllowlist(t *testing.T) {
	t.Parallel()
	assertExactFields(t, Principal{}, []fieldSpec{
		{"SubjectDigest", "string"},
		{"Scopes", "[]string"},
		{"ExpiresAt", "time.Time"},
	})
}

func TestEventFieldAllowlist(t *testing.T) {
	t.Parallel()
	assertExactFields(t, Event{}, []fieldSpec{
		{"ID", "string"},
		{"Kind", "string"},
		{"EvidenceClass", "integration.EvidenceClass"},
		{"OccurredAt", "time.Time"},
		{"TrustEnvelopeDigest", "string"},
		{"PayloadDigest", "string"},
	})
}

func TestFindingSummaryFieldAllowlist(t *testing.T) {
	t.Parallel()
	assertExactFields(t, FindingSummary{}, []fieldSpec{
		{"ID", "string"},
		{"Severity", "integration.FindingSeverity"},
		{"Status", "integration.FindingStatus"},
		{"EvidenceClass", "integration.EvidenceClass"},
		{"Digest", "string"},
		{"UpdatedAt", "time.Time"},
	})
}

func TestDecisionFieldAllowlist(t *testing.T) {
	t.Parallel()
	assertExactFields(t, Decision{}, []fieldSpec{
		{"DecisionID", "string"},
		{"ActionDigest", "string"},
		{"NodeDigest", "string"},
		{"Type", "integration.DecisionType"},
		{"ReasonCodes", "[]string"},
		{"IssuedAt", "time.Time"},
		{"ExpiresAt", "time.Time"},
		{"DecisionDigest", "string"},
		{"KeyID", "string"},
		{"Signature", "[]uint8"},
	})
}

func TestRecoveryClaimFieldAllowlist(t *testing.T) {
	t.Parallel()
	assertExactFields(t, RecoveryClaim{}, []fieldSpec{
		{"DeploymentDigest", "string"},
		{"NodeDigest", "string"},
		{"RecoveryPathDigest", "string"},
		{"Operation", "integration.RecoveryOperation"},
		{"ClaimedAt", "time.Time"},
		{"Nonce", "string"},
	})
}

func TestRecoveryVerdictCarriesNoAuthorization(t *testing.T) {
	t.Parallel()
	assertExactFields(t, RecoveryVerdict{}, []fieldSpec{
		{"VerifierID", "string"},
		{"Nonce", "string"},
		{"Class", "integration.VerdictClass"},
		{"Reachable", "bool"},
		{"ObservedAt", "time.Time"},
	})
	typ := reflect.TypeOf(RecoveryVerdict{})
	for index := 0; index < typ.NumField(); index++ {
		lower := strings.ToLower(typ.Field(index).Name)
		for _, forbidden := range []string{"author", "approv", "allow", "grant", "permit"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("RecoveryVerdict field %q reads as authorization; a verdict is evidence only", typ.Field(index).Name)
			}
		}
	}
}

func TestCheckpointJSONNeverCarriesRawIdentifiers(t *testing.T) {
	t.Parallel()
	const rawDeployment = "deployment-raw-identifier-7f3a"
	checkpoint := Checkpoint{
		DeploymentDigest: DigestString(rawDeployment), AuditHeadDigest: DigestString("head"),
		Sequence: 7, IssuedAt: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC), NodeCountBucket: BucketNodeCount(42),
	}
	digest, err := CheckpointDigest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(digest, rawDeployment) || checkpoint.DeploymentDigest == rawDeployment {
		t.Fatal("raw deployment identifier leaked into the checkpoint")
	}
	if checkpoint.NodeCountBucket != NodeCountMedium {
		t.Fatalf("bucket = %q, want %q", checkpoint.NodeCountBucket, NodeCountMedium)
	}
}
