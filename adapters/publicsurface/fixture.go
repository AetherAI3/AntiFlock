// Package publicsurface provides offline public-surface adapters. The locked
// reference release includes deterministic fixtures only: it performs no
// network I/O and never retrieves raw banners, broker records, or paste data.
package publicsurface

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/footprint"
)

const fixtureLicense = "CC0-1.0 synthetic fixture"

type FixtureProvider struct {
	id footprint.ProviderID
}

func NewFixtureProvider(id footprint.ProviderID) (*FixtureProvider, error) {
	if id != footprint.ProviderShodanFixture && id != footprint.ProviderBrokerFixture && id != footprint.ProviderPasteFixture {
		return nil, footprint.ErrUnsupportedProvider
	}
	return &FixtureProvider{id: id}, nil
}

func NewFixtureProviders() []footprint.Provider {
	return []footprint.Provider{
		&FixtureProvider{id: footprint.ProviderShodanFixture},
		&FixtureProvider{id: footprint.ProviderBrokerFixture},
		&FixtureProvider{id: footprint.ProviderPasteFixture},
	}
}

func (provider *FixtureProvider) Descriptor() footprint.ProviderDescriptor {
	if provider == nil {
		return footprint.ProviderDescriptor{}
	}
	descriptor := footprint.ProviderDescriptor{
		ID:            provider.id,
		Provenance:    antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION,
		SourceType:    antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_PUBLIC_DATASET,
		SourceLicense: fixtureLicense,
	}
	switch provider.id {
	case footprint.ProviderShodanFixture:
		descriptor.AssetTypes = []antiflockv1.FootprintAssetType{
			antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS,
		}
		descriptor.SourceName = "Synthetic Shodan-style exposure fixture"
	case footprint.ProviderBrokerFixture:
		descriptor.AssetTypes = []antiflockv1.FootprintAssetType{
			antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS,
		}
		descriptor.SourceName = "Synthetic public broker-registry fixture"
	case footprint.ProviderPasteFixture:
		descriptor.AssetTypes = []antiflockv1.FootprintAssetType{
			antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS,
		}
		descriptor.SourceName = "Synthetic paste-reference fixture"
	}
	return descriptor
}

func (provider *FixtureProvider) Observe(ctx context.Context, request footprint.ProviderRequest) ([]footprint.ProviderResult, error) {
	if provider == nil || ctx == nil {
		return nil, errors.New("public-surface fixture provider and context are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := footprint.ValidateProviderRequest(provider.id, request); err != nil {
		return nil, err
	}
	var result footprint.ProviderResult
	switch provider.id {
	case footprint.ProviderShodanFixture:
		result = shodanResult(request.Target)
	case footprint.ProviderBrokerFixture:
		result = brokerResult(request.Target)
	case footprint.ProviderPasteFixture:
		result = pasteResult(request.Target)
	default:
		return nil, footprint.ErrUnsupportedProvider
	}
	uri, err := footprint.CanonicalSourceURI(provider.id, request.Target.AssetID, result.Key)
	if err != nil {
		return nil, err
	}
	result.SourceURI = uri
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []footprint.ProviderResult{result}, nil
}

func shodanResult(target footprint.ProviderTarget) footprint.ProviderResult {
	return footprint.ProviderResult{
		Key:              "exposed-service-443",
		RelatedAssetType: antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_SERVICE,
		RelationshipType: antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_EXPOSES_SERVICE,
		RelatedValueHash: fixtureDigest("shodan-related-service", target.NormalizedValueHash, "tcp", "443", "https"),
		Confidence:       0.88,
		Summary:          "Synthetic exposed-service metadata matched the verified public-IP digest; no address or banner is retained.",
		Attributes: map[string]string{
			"banner_digest":  fixtureDigest("shodan-banner", target.NormalizedValueHash),
			"product_family": "https",
			"service_port":   "443",
			"transport":      "tcp",
		},
		SuggestedResponseKind: footprint.ResponseStageServiceHardening,
		SuggestedResponse:     "Synthetic suggestion: stage a rollback-capable service-hardening plan for Secure Action review.",
		TTL:                   24 * time.Hour,
	}
}

func brokerResult(target footprint.ProviderTarget) footprint.ProviderResult {
	return footprint.ProviderResult{
		Key:              "broker-association",
		RelatedAssetType: antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_DATA_BROKER_RECORD,
		RelationshipType: antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_ASSOCIATED_PUBLICLY,
		RelatedValueHash: fixtureDigest("broker-related-record", target.NormalizedValueHash),
		Confidence:       0.82,
		Summary:          "Synthetic broker-registry association matched the verified email digest; no broker record or unrelated identity is retained.",
		Attributes: map[string]string{
			"record_reference_digest": fixtureDigest("broker-record-reference", target.NormalizedValueHash),
			"registry_category":       "people-search",
		},
		SuggestedResponseKind: footprint.ResponseStageBrokerOptOut,
		SuggestedResponse:     "Synthetic suggestion: stage a cancelable broker opt-out request for Secure Action review.",
		TTL:                   24 * time.Hour,
	}
}

func pasteResult(target footprint.ProviderTarget) footprint.ProviderResult {
	return footprint.ProviderResult{
		Key:              "paste-reference",
		RelatedAssetType: antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_BREACH_REFERENCE,
		RelationshipType: antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_REFERENCED_IN_BREACH,
		RelatedValueHash: fixtureDigest("paste-related-reference", target.NormalizedValueHash),
		Confidence:       0.79,
		Summary:          "Synthetic paste-reference metadata matched the verified email digest; raw paste content and unrelated identifiers are never retained.",
		Attributes: map[string]string{
			"content_digest": fixtureDigest("paste-content", target.NormalizedValueHash),
			"reference_kind": "credential-mention",
		},
		SuggestedResponseKind: footprint.ResponseStageCredentialReview,
		SuggestedResponse:     "Synthetic suggestion: stage a reversible credential-review plan for Secure Action review.",
		TTL:                   6 * time.Hour,
	}
}

func fixtureDigest(domain string, values ...string) string {
	hasher := sha256.New()
	fmt.Fprintf(hasher, "AntiFlock-Public-Surface-Fixture-v1\x00%s", domain)
	for _, value := range values {
		fmt.Fprintf(hasher, "\x00%s", value)
	}
	return fmt.Sprintf("sha256:%x", hasher.Sum(nil))
}
