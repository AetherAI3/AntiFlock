package publicsurface_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/adapters/publicsurface"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/footprint"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFixturesAreDeterministicDigestOnlyReportedSimulation(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	collector, err := footprint.NewCollector(func() time.Time { return now }, publicsurface.NewFixtureProviders()...)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		providerID footprint.ProviderID
		assetType  antiflockv1.FootprintAssetType
		related    antiflockv1.FootprintAssetType
		relation   antiflockv1.FootprintRelationshipType
	}{
		{"Shodan-style exposure", footprint.ProviderShodanFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_SERVICE, antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_EXPOSES_SERVICE},
		{"broker registry", footprint.ProviderBrokerFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_DATA_BROKER_RECORD, antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_ASSOCIATED_PUBLICLY},
		{"paste reference", footprint.ProviderPasteFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_BREACH_REFERENCE, antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_REFERENCED_IN_BREACH},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			asset := verifiedAsset(now, test.assetType)
			query := footprint.Query{ProviderID: test.providerID, PrincipalID: "operator-one", Asset: asset, MaximumResults: 1}
			first := collect(t, collector, query)
			second := collect(t, collector, query)
			if len(first) != 1 || len(second) != 1 || first[0].ID != second[0].ID ||
				first[0].SuggestedResponse.ID != second[0].SuggestedResponse.ID ||
				!proto.Equal(first[0].RelatedAsset, second[0].RelatedAsset) || !proto.Equal(first[0].Relationship, second[0].Relationship) {
				t.Fatalf("fixture output is not deterministic: %#v %#v", first, second)
			}
			observation := first[0]
			evidence := observation.Relationship.GetEvidence()[0]
			if observation.EvidenceProvenance != antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION ||
				observation.RelatedAsset.Type != test.related || observation.Relationship.Type != test.relation ||
				observation.Relationship.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_REPORTED ||
				evidence.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_REPORTED ||
				evidence.SourceName == "" || evidence.SourceUri == "" || evidence.SourceLicense == "" ||
				len(evidence.Summary) > footprint.MaxSummaryBytes || len(evidence.SourceUri) > footprint.MaxSourceURIBytes ||
				evidence.Integrity.GetAlgorithm() != "sha256" || len(evidence.Integrity.GetDigest()) != 32 ||
				evidence.Attributes["content_mode"] != "DIGEST_ONLY" || evidence.Attributes["evidence_provenance"] != "SIMULATION" ||
				observation.RelatedAsset.DisplayValue != "[redacted]" || !observation.SuggestedResponse.Reversible ||
				!observation.SuggestedResponse.RequiresSecureActionGate || observation.SuggestedResponse.ExecutionEnabled {
				t.Fatalf("unsafe fixture observation = %#v", observation)
			}
		})
	}
}

func TestFixturesNeverReturnRawTargetPasteOrUnrelatedPII(t *testing.T) {
	const (
		rawTarget    = "operator.secret+tag@example.test"
		rawPaste     = "password=hunter2; token=private-token"
		unrelatedPII = "Unrelated Person, 555-0100"
	)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	collector, err := footprint.NewCollector(func() time.Time { return now }, publicsurface.NewFixtureProviders()...)
	if err != nil {
		t.Fatal(err)
	}
	asset := verifiedAsset(now, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS)
	asset.DisplayValue = rawTarget
	for _, providerID := range []footprint.ProviderID{footprint.ProviderBrokerFixture, footprint.ProviderPasteFixture} {
		observations := collect(t, collector, footprint.Query{ProviderID: providerID, PrincipalID: "operator-one", Asset: asset, MaximumResults: 1})
		encoded, err := json.Marshal(observations)
		if err != nil {
			t.Fatal(err)
		}
		text := string(encoded)
		for _, forbidden := range []string{rawTarget, rawPaste, unrelatedPII, "hunter2", "private-token", "555-0100"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("fixture output leaked forbidden raw content %q: %s", forbidden, text)
			}
		}
	}
}

func TestFixtureCannotBeCalledOutsideOwnershipVerifyingCollector(t *testing.T) {
	provider, err := publicsurface.NewFixtureProvider(footprint.ProviderShodanFixture)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = provider.Observe(ctx, footprint.ProviderRequest{
		Target: footprint.ProviderTarget{
			AssetID: "asset-one", AssetType: antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS,
			NormalizedValueHash: "sha256:" + strings.Repeat("a", 64),
		},
		MaximumResults: 1, ObservedAt: time.Now().UTC(),
	})
	if !errors.Is(err, footprint.ErrUnauthorizedTarget) {
		t.Fatalf("direct fixture call error = %v", err)
	}
}

func collect(t *testing.T, collector *footprint.Collector, query footprint.Query) []footprint.Observation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observations, err := collector.Collect(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	return observations
}

func verifiedAsset(now time.Time, assetType antiflockv1.FootprintAssetType) *antiflockv1.FootprintAsset {
	return &antiflockv1.FootprintAsset{
		Metadata: &antiflockv1.ResourceMetadata{Id: "asset-one", Revision: 1}, Type: assetType,
		DisplayValue: "private display", NormalizedValueHash: "sha256:" + strings.Repeat("a", 64),
		Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		Ownership: &antiflockv1.OwnershipVerification{
			Id: "verification-one", Method: antiflockv1.OwnershipVerificationMethod_OWNERSHIP_VERIFICATION_METHOD_OPERATOR_DECLARATION,
			Status:                antiflockv1.OwnershipVerificationStatus_OWNERSHIP_VERIFICATION_STATUS_VERIFIED,
			AuthorizedPrincipalId: "operator-one", VerifiedAt: timestamppb.New(now.Add(-time.Minute)),
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	}
}
