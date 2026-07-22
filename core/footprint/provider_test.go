package footprint_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/footprint"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stubProvider struct {
	descriptor footprint.ProviderDescriptor
	observe    func(context.Context, footprint.ProviderRequest) ([]footprint.ProviderResult, error)
}

func (provider *stubProvider) Descriptor() footprint.ProviderDescriptor { return provider.descriptor }

func (provider *stubProvider) Observe(ctx context.Context, request footprint.ProviderRequest) ([]footprint.ProviderResult, error) {
	return provider.observe(ctx, request)
}

func TestCollectorRejectsUnverifiedExpiredAndWrongPrincipalTargets(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	provider := validStub(t, func(_ context.Context, request footprint.ProviderRequest) ([]footprint.ProviderResult, error) {
		return []footprint.ProviderResult{validShodanResult(t, request.Target)}, nil
	})
	collector, err := footprint.NewCollector(func() time.Time { return now }, provider)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*antiflockv1.FootprintAsset){
		"pending": func(asset *antiflockv1.FootprintAsset) {
			asset.Ownership.Status = antiflockv1.OwnershipVerificationStatus_OWNERSHIP_VERIFICATION_STATUS_PENDING
		},
		"expired": func(asset *antiflockv1.FootprintAsset) {
			asset.Ownership.ExpiresAt = timestamppb.New(now)
		},
		"wrong principal": func(asset *antiflockv1.FootprintAsset) {
			asset.Ownership.AuthorizedPrincipalId = "someone-else"
		},
		"revoked": func(asset *antiflockv1.FootprintAsset) {
			asset.Ownership.RevokedAt = timestamppb.New(now.Add(-time.Minute))
		},
	} {
		t.Run(name, func(t *testing.T) {
			asset := verifiedAsset(now, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS)
			mutate(asset)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := collector.Collect(ctx, footprint.Query{
				ProviderID: footprint.ProviderShodanFixture, PrincipalID: "operator-one",
				Asset: asset, MaximumResults: 1,
			})
			if !errors.Is(err, footprint.ErrUnauthorizedTarget) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestProviderAndAssetTypeAllowlistIsExact(t *testing.T) {
	if !footprint.ProviderSupportsAsset(footprint.ProviderShodanFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS) ||
		footprint.ProviderSupportsAsset(footprint.ProviderShodanFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_DOMAIN) ||
		!footprint.ProviderSupportsAsset(footprint.ProviderBrokerFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS) ||
		footprint.ProviderSupportsAsset(footprint.ProviderBrokerFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PHONE_NUMBER) ||
		!footprint.ProviderSupportsAsset(footprint.ProviderPasteFixture, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS) ||
		footprint.ProviderSupportsAsset("shodan", antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS) {
		t.Fatal("provider/asset allowlist accepted an unapproved pair")
	}
	unknown := &stubProvider{descriptor: footprint.ProviderDescriptor{ID: "shodan"}, observe: func(context.Context, footprint.ProviderRequest) ([]footprint.ProviderResult, error) { return nil, nil }}
	if _, err := footprint.NewCollector(time.Now, unknown); !errors.Is(err, footprint.ErrUnsupportedProvider) {
		t.Fatalf("unknown provider error = %v", err)
	}
}

func TestCollectorEnforcesDeadlineResultAndFieldBudgets(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	asset := verifiedAsset(now, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS)
	query := footprint.Query{ProviderID: footprint.ProviderShodanFixture, PrincipalID: "operator-one", Asset: asset, MaximumResults: 1}
	provider := validStub(t, func(_ context.Context, request footprint.ProviderRequest) ([]footprint.ProviderResult, error) {
		return []footprint.ProviderResult{validShodanResult(t, request.Target)}, nil
	})
	collector, err := footprint.NewCollector(func() time.Time { return now }, provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(context.Background(), query); !errors.Is(err, footprint.ErrBudgetExceeded) {
		t.Fatalf("missing deadline error = %v", err)
	}
	longContext, longCancel := context.WithTimeout(context.Background(), footprint.MaxProviderDeadline+time.Second)
	defer longCancel()
	if _, err := collector.Collect(longContext, query); !errors.Is(err, footprint.ErrBudgetExceeded) {
		t.Fatalf("long deadline error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tooMany := query
	tooMany.MaximumResults = footprint.MaxResults + 1
	if _, err := collector.Collect(ctx, tooMany); !errors.Is(err, footprint.ErrBudgetExceeded) {
		t.Fatalf("result request budget error = %v", err)
	}

	for name, mutate := range map[string]func(*footprint.ProviderResult){
		"summary": func(result *footprint.ProviderResult) {
			result.Summary = "Synthetic " + strings.Repeat("x", footprint.MaxSummaryBytes)
		},
		"source URI": func(result *footprint.ProviderResult) {
			result.SourceURI = "antiflock-fixture://shodan-exposure/" + strings.Repeat("x", footprint.MaxSourceURIBytes)
		},
	} {
		t.Run(name, func(t *testing.T) {
			badProvider := validStub(t, func(_ context.Context, request footprint.ProviderRequest) ([]footprint.ProviderResult, error) {
				result := validShodanResult(t, request.Target)
				mutate(&result)
				return []footprint.ProviderResult{result}, nil
			})
			badCollector, err := footprint.NewCollector(func() time.Time { return now }, badProvider)
			if err != nil {
				t.Fatal(err)
			}
			callContext, callCancel := context.WithTimeout(context.Background(), time.Second)
			defer callCancel()
			if _, err := badCollector.Collect(callContext, query); !errors.Is(err, footprint.ErrInvalidResult) {
				t.Fatalf("oversized provider field error = %v", err)
			}
		})
	}

	overflowProvider := validStub(t, func(_ context.Context, request footprint.ProviderRequest) ([]footprint.ProviderResult, error) {
		result := validShodanResult(t, request.Target)
		return []footprint.ProviderResult{result, result}, nil
	})
	overflowCollector, err := footprint.NewCollector(func() time.Time { return now }, overflowProvider)
	if err != nil {
		t.Fatal(err)
	}
	overflowContext, overflowCancel := context.WithTimeout(context.Background(), time.Second)
	defer overflowCancel()
	if _, err := overflowCollector.Collect(overflowContext, query); !errors.Is(err, footprint.ErrBudgetExceeded) {
		t.Fatalf("provider result budget error = %v", err)
	}
}

func TestCollectorMaterializesReportedSimulationAndReversibleSuggestion(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	provider := validStub(t, func(_ context.Context, request footprint.ProviderRequest) ([]footprint.ProviderResult, error) {
		return []footprint.ProviderResult{validShodanResult(t, request.Target)}, nil
	})
	collector, err := footprint.NewCollector(func() time.Time { return now }, provider)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observations, err := collector.Collect(ctx, footprint.Query{
		ProviderID: footprint.ProviderShodanFixture, PrincipalID: "operator-one",
		Asset: verifiedAsset(now, antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS), MaximumResults: 1,
	})
	if err != nil || len(observations) != 1 {
		t.Fatalf("observations = %#v, error = %v", observations, err)
	}
	observation := observations[0]
	evidence := observation.Relationship.GetEvidence()[0]
	if observation.EvidenceProvenance != antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION ||
		observation.Relationship.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_REPORTED ||
		evidence.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_REPORTED ||
		evidence.Attributes["evidence_provenance"] != "SIMULATION" ||
		evidence.Attributes["content_mode"] != "DIGEST_ONLY" || evidence.SourceLicense == "" ||
		evidence.Integrity.GetAlgorithm() != "sha256" || len(evidence.Integrity.GetDigest()) != 32 {
		t.Fatalf("unsafe evidence projection = %#v", observation)
	}
	response := observation.SuggestedResponse
	if !response.Reversible || !response.RequiresSecureActionGate || response.ExecutionEnabled {
		t.Fatalf("unsafe suggested response = %#v", response)
	}
}

func validStub(t *testing.T, observe func(context.Context, footprint.ProviderRequest) ([]footprint.ProviderResult, error)) *stubProvider {
	t.Helper()
	return &stubProvider{
		descriptor: footprint.ProviderDescriptor{
			ID:         footprint.ProviderShodanFixture,
			AssetTypes: []antiflockv1.FootprintAssetType{antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS},
			Provenance: antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION,
			SourceType: antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_PUBLIC_DATASET,
			SourceName: "Synthetic Shodan-style test fixture", SourceLicense: "CC0-1.0 synthetic fixture",
		},
		observe: observe,
	}
}

func validShodanResult(t *testing.T, target footprint.ProviderTarget) footprint.ProviderResult {
	t.Helper()
	uri, err := footprint.CanonicalSourceURI(footprint.ProviderShodanFixture, target.AssetID, "exposed-service-443")
	if err != nil {
		t.Fatal(err)
	}
	return footprint.ProviderResult{
		Key:              "exposed-service-443",
		RelatedAssetType: antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_SERVICE,
		RelationshipType: antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_EXPOSES_SERVICE,
		RelatedValueHash: hashValue("related"), Confidence: 0.88,
		Summary: "Synthetic exposed-service metadata contains digest-only fixture values.", SourceURI: uri,
		Attributes: map[string]string{
			"banner_digest": hashValue("banner"), "product_family": "https", "service_port": "443", "transport": "tcp",
		},
		SuggestedResponseKind: footprint.ResponseStageServiceHardening,
		SuggestedResponse:     "Synthetic suggestion: stage a reversible service-hardening plan for Secure Action review.",
		TTL:                   time.Hour,
	}
}

func verifiedAsset(now time.Time, assetType antiflockv1.FootprintAssetType) *antiflockv1.FootprintAsset {
	return &antiflockv1.FootprintAsset{
		Metadata: &antiflockv1.ResourceMetadata{Id: "asset-one", Revision: 1},
		Type:     assetType, DisplayValue: "operator-private-value", NormalizedValueHash: hashValue("operator-private-value"),
		Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		Ownership: &antiflockv1.OwnershipVerification{
			Id: "verification-one", Method: antiflockv1.OwnershipVerificationMethod_OWNERSHIP_VERIFICATION_METHOD_OPERATOR_DECLARATION,
			Status:                antiflockv1.OwnershipVerificationStatus_OWNERSHIP_VERIFICATION_STATUS_VERIFIED,
			AuthorizedPrincipalId: "operator-one", VerifiedAt: timestamppb.New(now.Add(-time.Minute)),
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	}
}

func hashValue(value string) string {
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if value == "related" {
		return "sha256:" + strings.Repeat("1", 64)
	}
	if value == "banner" {
		return "sha256:" + strings.Repeat("2", 64)
	}
	return "sha256:" + digest
}
