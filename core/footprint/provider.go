// Package footprint defines the fail-closed boundary between verified operator
// assets and read-only public-surface providers. Providers receive opaque
// identifiers and digests only; they cannot accept free-form lookup values or
// caller-selected URLs through this contract.
package footprint

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MaxProviderDeadline = 5 * time.Second
	MaxResults          = 16
	MaxSummaryBytes     = 512
	MaxSourceURIBytes   = 1024
	MaxSourceNameBytes  = 128
	MaxSourceLicense    = 128
	MaxAttributes       = 12
)

type ProviderID string

const (
	ProviderShodanFixture ProviderID = "fixture.shodan-exposure.v1"
	ProviderBrokerFixture ProviderID = "fixture.broker-registry.v1"
	ProviderPasteFixture  ProviderID = "fixture.paste-reference.v1"
)

type SuggestedResponseKind string

const (
	ResponseStageServiceHardening SuggestedResponseKind = "stage-service-hardening"
	ResponseStageBrokerOptOut     SuggestedResponseKind = "stage-broker-opt-out"
	ResponseStageCredentialReview SuggestedResponseKind = "stage-credential-review"
)

var (
	ErrUnsupportedProvider = errors.New("unsupported public-surface provider")
	ErrUnauthorizedTarget  = errors.New("public-surface target is not currently verified for the operator")
	ErrBudgetExceeded      = errors.New("public-surface query exceeds a safety budget")
	ErrInvalidResult       = errors.New("public-surface provider returned an invalid result")
)

type ProviderDescriptor struct {
	ID            ProviderID
	AssetTypes    []antiflockv1.FootprintAssetType
	Provenance    antiflockv1.EvidenceProvenance
	SourceType    antiflockv1.EvidenceSourceType
	SourceName    string
	SourceLicense string
}

// ProviderTarget deliberately excludes FootprintAsset.DisplayValue and any
// URL. A provider sees only a local opaque ID and a canonical digest after the
// collector has verified the asset belongs to the requesting principal.
type ProviderTarget struct {
	AssetID             string
	AssetType           antiflockv1.FootprintAssetType
	NormalizedValueHash string
}

type ProviderRequest struct {
	Target         ProviderTarget
	MaximumResults int
	ObservedAt     time.Time
	authorization  *providerRequestAuthorization
}

type providerRequestAuthorization struct{}

var collectorAuthorization = &providerRequestAuthorization{}

type SuggestedResponse struct {
	ID                       string
	Kind                     SuggestedResponseKind
	Summary                  string
	Reversible               bool
	RequiresSecureActionGate bool
	ExecutionEnabled         bool
}

// ProviderResult is intentionally metadata-only. RelatedValueHash and digest
// attributes must be canonical SHA-256 values; no raw paste, banner, broker
// record, or unrelated personal data is representable by the approved fixture
// contracts.
type ProviderResult struct {
	Key                   string
	RelatedAssetType      antiflockv1.FootprintAssetType
	RelationshipType      antiflockv1.FootprintRelationshipType
	RelatedValueHash      string
	Confidence            float32
	Summary               string
	SourceURI             string
	Attributes            map[string]string
	SuggestedResponseKind SuggestedResponseKind
	SuggestedResponse     string
	TTL                   time.Duration
}

type Provider interface {
	Descriptor() ProviderDescriptor
	Observe(context.Context, ProviderRequest) ([]ProviderResult, error)
}

type Query struct {
	ProviderID     ProviderID
	PrincipalID    string
	Asset          *antiflockv1.FootprintAsset
	MaximumResults int
}

// Observation is a validated, digest-only projection grounded in the
// FootprintAsset, FootprintRelationship, and EvidenceReference protobufs.
type Observation struct {
	ID                 string
	ProviderID         ProviderID
	EvidenceProvenance antiflockv1.EvidenceProvenance
	RelatedAsset       *antiflockv1.FootprintAsset
	Relationship       *antiflockv1.FootprintRelationship
	SuggestedResponse  SuggestedResponse
}

type Collector struct {
	clock       func() time.Time
	providers   map[ProviderID]Provider
	descriptors map[ProviderID]ProviderDescriptor
}

type providerContract struct {
	targetType       antiflockv1.FootprintAssetType
	relatedType      antiflockv1.FootprintAssetType
	relationshipType antiflockv1.FootprintRelationshipType
	responseKind     SuggestedResponseKind
	sourceHost       string
	requiredAttrs    map[string]func(string) bool
}

var providerContracts = map[ProviderID]providerContract{
	ProviderShodanFixture: {
		targetType:       antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_IP_ADDRESS,
		relatedType:      antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_PUBLIC_SERVICE,
		relationshipType: antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_EXPOSES_SERVICE,
		responseKind:     ResponseStageServiceHardening,
		sourceHost:       "shodan-exposure",
		requiredAttrs: map[string]func(string) bool{
			"banner_digest": isSHA256,
			"product_family": func(value string) bool {
				return value == "https" || value == "ssh" || value == "vpn" || value == "mail"
			},
			"service_port": func(value string) bool {
				port, err := strconv.ParseUint(value, 10, 16)
				return err == nil && port > 0
			},
			"transport": func(value string) bool { return value == "tcp" || value == "udp" },
		},
	},
	ProviderBrokerFixture: {
		targetType:       antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS,
		relatedType:      antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_DATA_BROKER_RECORD,
		relationshipType: antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_ASSOCIATED_PUBLICLY,
		responseKind:     ResponseStageBrokerOptOut,
		sourceHost:       "broker-registry",
		requiredAttrs: map[string]func(string) bool{
			"record_reference_digest": isSHA256,
			"registry_category": func(value string) bool {
				return value == "people-search" || value == "marketing-directory"
			},
		},
	},
	ProviderPasteFixture: {
		targetType:       antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_EMAIL_ADDRESS,
		relatedType:      antiflockv1.FootprintAssetType_FOOTPRINT_ASSET_TYPE_BREACH_REFERENCE,
		relationshipType: antiflockv1.FootprintRelationshipType_FOOTPRINT_RELATIONSHIP_TYPE_REFERENCED_IN_BREACH,
		responseKind:     ResponseStageCredentialReview,
		sourceHost:       "paste-reference",
		requiredAttrs: map[string]func(string) bool{
			"content_digest": isSHA256,
			"reference_kind": func(value string) bool {
				return value == "credential-mention" || value == "identifier-mention"
			},
		},
	},
}

func NewCollector(clock func() time.Time, providers ...Provider) (*Collector, error) {
	if clock == nil || len(providers) == 0 {
		return nil, errors.New("footprint collector requires a clock and at least one provider")
	}
	collector := &Collector{
		clock: clock, providers: make(map[ProviderID]Provider, len(providers)),
		descriptors: make(map[ProviderID]ProviderDescriptor, len(providers)),
	}
	for _, provider := range providers {
		if provider == nil {
			return nil, errors.New("footprint provider is nil")
		}
		descriptor := provider.Descriptor()
		contract, allowed := providerContracts[descriptor.ID]
		if !allowed {
			return nil, ErrUnsupportedProvider
		}
		if _, duplicate := collector.providers[descriptor.ID]; duplicate {
			return nil, errors.New("duplicate public-surface provider")
		}
		if len(descriptor.AssetTypes) != 1 || descriptor.AssetTypes[0] != contract.targetType ||
			descriptor.Provenance != antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION ||
			descriptor.SourceType != antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_PUBLIC_DATASET ||
			!safeText(descriptor.SourceName, MaxSourceNameBytes) ||
			!safeText(descriptor.SourceLicense, MaxSourceLicense) {
			return nil, fmt.Errorf("%w: provider descriptor", ErrInvalidResult)
		}
		descriptor.AssetTypes = append([]antiflockv1.FootprintAssetType(nil), descriptor.AssetTypes...)
		collector.providers[descriptor.ID] = provider
		collector.descriptors[descriptor.ID] = descriptor
	}
	return collector, nil
}

func ProviderSupportsAsset(providerID ProviderID, assetType antiflockv1.FootprintAssetType) bool {
	contract, found := providerContracts[providerID]
	return found && contract.targetType == assetType
}

// CanonicalSourceURI returns the only URI shape accepted from deterministic
// fixture providers. Neither the caller nor a provider can select a remote URL.
func CanonicalSourceURI(providerID ProviderID, assetID, resultKey string) (string, error) {
	contract, found := providerContracts[providerID]
	if !found || !opaqueID(assetID, 128) || !slug(resultKey, 64) {
		return "", ErrUnsupportedProvider
	}
	value := fmt.Sprintf("antiflock-fixture://%s/%s/%s", contract.sourceHost, assetID, resultKey)
	if len(value) > MaxSourceURIBytes {
		return "", ErrBudgetExceeded
	}
	return value, nil
}

func (collector *Collector) Collect(ctx context.Context, query Query) ([]Observation, error) {
	if collector == nil || collector.clock == nil || ctx == nil {
		return nil, errors.New("footprint collector and context are required")
	}
	if err := validateDeadline(ctx); err != nil {
		return nil, err
	}
	provider, found := collector.providers[query.ProviderID]
	if !found {
		return nil, ErrUnsupportedProvider
	}
	if query.MaximumResults < 1 || query.MaximumResults > MaxResults {
		return nil, ErrBudgetExceeded
	}
	now := collector.clock().UTC()
	if now.IsZero() {
		return nil, errors.New("footprint clock returned zero time")
	}
	target, err := authorizedTarget(query.PrincipalID, query.Asset, query.ProviderID, now)
	if err != nil {
		return nil, err
	}
	results, err := provider.Observe(ctx, ProviderRequest{
		Target: target, MaximumResults: query.MaximumResults, ObservedAt: now,
		authorization: collectorAuthorization,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("public-surface provider query failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(results) > query.MaximumResults || len(results) > MaxResults {
		return nil, ErrBudgetExceeded
	}
	descriptor := collector.descriptors[query.ProviderID]
	observations := make([]Observation, 0, len(results))
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		observation, err := materializeObservation(descriptor, target, result, now)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[observation.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate observation", ErrInvalidResult)
		}
		seen[observation.ID] = struct{}{}
		observations = append(observations, observation)
	}
	sort.Slice(observations, func(left, right int) bool { return observations[left].ID < observations[right].ID })
	return observations, nil
}

// ValidateProviderRequest lets an adapter reject direct calls that bypass the
// ownership-verifying Collector. The authorization marker cannot be created by
// packages implementing Provider.
func ValidateProviderRequest(providerID ProviderID, request ProviderRequest) error {
	if request.authorization != collectorAuthorization || !ProviderSupportsAsset(providerID, request.Target.AssetType) ||
		!opaqueID(request.Target.AssetID, 128) || !isSHA256(request.Target.NormalizedValueHash) ||
		request.MaximumResults < 1 || request.MaximumResults > MaxResults || request.ObservedAt.IsZero() {
		return ErrUnauthorizedTarget
	}
	return nil
}

func authorizedTarget(principalID string, asset *antiflockv1.FootprintAsset, providerID ProviderID, now time.Time) (ProviderTarget, error) {
	if !opaqueID(principalID, 128) || asset == nil || asset.Metadata == nil || !opaqueID(asset.Metadata.Id, 128) ||
		!ProviderSupportsAsset(providerID, asset.Type) || !isSHA256(asset.NormalizedValueHash) {
		return ProviderTarget{}, ErrUnauthorizedTarget
	}
	ownership := asset.Ownership
	if ownership == nil || ownership.Status != antiflockv1.OwnershipVerificationStatus_OWNERSHIP_VERIFICATION_STATUS_VERIFIED ||
		ownership.Method == antiflockv1.OwnershipVerificationMethod_OWNERSHIP_VERIFICATION_METHOD_UNSPECIFIED ||
		ownership.AuthorizedPrincipalId != principalID || ownership.RevokedAt != nil ||
		!validAtOrBefore(ownership.VerifiedAt, now) || !validAfter(ownership.ExpiresAt, now) {
		return ProviderTarget{}, ErrUnauthorizedTarget
	}
	return ProviderTarget{AssetID: asset.Metadata.Id, AssetType: asset.Type, NormalizedValueHash: asset.NormalizedValueHash}, nil
}

func materializeObservation(descriptor ProviderDescriptor, target ProviderTarget, result ProviderResult, now time.Time) (Observation, error) {
	contract := providerContracts[descriptor.ID]
	if !validResult(contract, descriptor.ID, target, result) {
		return Observation{}, ErrInvalidResult
	}
	digest := observationDigest(descriptor, target, result)
	observationID := fmt.Sprintf("observation_%x", digest[:16])
	relatedID := stableID("asset", string(descriptor.ID), target.AssetID, result.Key, result.RelatedValueHash)
	evidenceID := fmt.Sprintf("evidence_%x", digest[16:])
	responseID := stableID("response", observationID, string(result.SuggestedResponseKind))
	expiresAt := now.Add(result.TTL)
	attributes := make(map[string]string, len(result.Attributes)+3)
	for key, value := range result.Attributes {
		attributes[key] = value
	}
	attributes["content_mode"] = "DIGEST_ONLY"
	attributes["evidence_provenance"] = "SIMULATION"
	attributes["provider_id"] = string(descriptor.ID)
	evidence := &antiflockv1.EvidenceReference{
		Id: evidenceID, Role: antiflockv1.EvidenceRole_EVIDENCE_ROLE_SUPPORTING,
		Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_REPORTED,
		SourceType:     descriptor.SourceType, SourceName: descriptor.SourceName, SourceUri: result.SourceURI,
		ObservedAt: timestamppb.New(now), ReceivedAt: timestamppb.New(now), LastVerifiedAt: timestamppb.New(now),
		ExpiresAt: timestamppb.New(expiresAt), Confidence: result.Confidence,
		Sensitivity:       antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		LocationPrecision: antiflockv1.LocationPrecision_LOCATION_PRECISION_WITHHELD,
		Summary:           result.Summary,
		Integrity:         &antiflockv1.IntegrityDigest{Algorithm: "sha256", Digest: append([]byte(nil), digest[:]...)},
		SourceLicense:     descriptor.SourceLicense, Attributes: attributes,
	}
	related := &antiflockv1.FootprintAsset{
		Metadata: &antiflockv1.ResourceMetadata{
			Id: relatedID, Revision: 1, CreatedAt: timestamppb.New(now), UpdatedAt: timestamppb.New(now),
			Labels: map[string]string{"content_mode": "DIGEST_ONLY", "provider_id": string(descriptor.ID)},
		},
		Type: result.RelatedAssetType, DisplayValue: "[redacted]", NormalizedValueHash: result.RelatedValueHash,
		Sensitivity:   antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		Evidence:      []*antiflockv1.EvidenceReference{proto.Clone(evidence).(*antiflockv1.EvidenceReference)},
		LastCheckedAt: timestamppb.New(now),
	}
	relationship := &antiflockv1.FootprintRelationship{
		Metadata: &antiflockv1.ResourceMetadata{
			Id: observationID, Revision: 1, CreatedAt: timestamppb.New(now), UpdatedAt: timestamppb.New(now),
			Labels: map[string]string{"content_mode": "DIGEST_ONLY", "provider_id": string(descriptor.ID)},
		},
		SourceAssetId: target.AssetID, TargetAssetId: relatedID, Type: result.RelationshipType,
		Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_REPORTED, Confidence: result.Confidence,
		Evidence: []*antiflockv1.EvidenceReference{evidence}, FirstSeenAt: timestamppb.New(now),
		LastSeenAt: timestamppb.New(now), ExpiresAt: timestamppb.New(expiresAt),
	}
	return Observation{
		ID: observationID, ProviderID: descriptor.ID,
		EvidenceProvenance: antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION,
		RelatedAsset:       related, Relationship: relationship,
		SuggestedResponse: SuggestedResponse{
			ID: responseID, Kind: result.SuggestedResponseKind, Summary: result.SuggestedResponse,
			Reversible: true, RequiresSecureActionGate: true, ExecutionEnabled: false,
		},
	}, nil
}

func validResult(contract providerContract, providerID ProviderID, target ProviderTarget, result ProviderResult) bool {
	expectedURI, err := CanonicalSourceURI(providerID, target.AssetID, result.Key)
	if err != nil || result.SourceURI != expectedURI || len(result.SourceURI) > MaxSourceURIBytes {
		return false
	}
	parsed, err := url.Parse(result.SourceURI)
	if err != nil || parsed.Scheme != "antiflock-fixture" || parsed.Host != contract.sourceHost || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if result.RelatedAssetType != contract.relatedType || result.RelationshipType != contract.relationshipType ||
		result.SuggestedResponseKind != contract.responseKind || !isSHA256(result.RelatedValueHash) ||
		math.IsNaN(float64(result.Confidence)) || math.IsInf(float64(result.Confidence), 0) ||
		result.Confidence < 0 || result.Confidence > 1 || !safeFixtureSummary(result.Summary, MaxSummaryBytes) ||
		!safeFixtureSummary(result.SuggestedResponse, MaxSummaryBytes) || result.TTL <= 0 || result.TTL > 7*24*time.Hour {
		return false
	}
	if len(result.Attributes) != len(contract.requiredAttrs) || len(result.Attributes)+3 > MaxAttributes {
		return false
	}
	for key, validator := range contract.requiredAttrs {
		value, present := result.Attributes[key]
		if !present || !validator(value) {
			return false
		}
	}
	return true
}

func observationDigest(descriptor ProviderDescriptor, target ProviderTarget, result ProviderResult) [sha256.Size]byte {
	hasher := sha256.New()
	writeDigestField(hasher, "AntiFlock-Public-Surface-Observation-v1")
	writeDigestField(hasher, string(descriptor.ID))
	writeDigestField(hasher, target.AssetID)
	writeDigestField(hasher, strconv.FormatInt(int64(target.AssetType), 10))
	writeDigestField(hasher, target.NormalizedValueHash)
	writeDigestField(hasher, result.Key)
	writeDigestField(hasher, strconv.FormatInt(int64(result.RelatedAssetType), 10))
	writeDigestField(hasher, strconv.FormatInt(int64(result.RelationshipType), 10))
	writeDigestField(hasher, result.RelatedValueHash)
	writeDigestField(hasher, strconv.FormatUint(uint64(math.Float32bits(result.Confidence)), 10))
	writeDigestField(hasher, result.Summary)
	writeDigestField(hasher, result.SourceURI)
	writeDigestField(hasher, descriptor.SourceName)
	writeDigestField(hasher, descriptor.SourceLicense)
	writeDigestField(hasher, string(result.SuggestedResponseKind))
	writeDigestField(hasher, result.SuggestedResponse)
	writeDigestField(hasher, strconv.FormatInt(int64(result.TTL), 10))
	keys := make([]string, 0, len(result.Attributes))
	for key := range result.Attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeDigestField(hasher, key)
		writeDigestField(hasher, result.Attributes[key])
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

type digestWriter interface{ Write([]byte) (int, error) }

func writeDigestField(writer digestWriter, value string) {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(value)))
	_, _ = writer.Write(length)
	_, _ = writer.Write([]byte(value))
}

func stableID(prefix string, values ...string) string {
	hasher := sha256.New()
	writeDigestField(hasher, "AntiFlock-Public-Surface-ID-v1")
	writeDigestField(hasher, prefix)
	for _, value := range values {
		writeDigestField(hasher, value)
	}
	return fmt.Sprintf("%s_%x", prefix, hasher.Sum(nil)[:16])
}

func validateDeadline(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, present := ctx.Deadline()
	if !present {
		return ErrBudgetExceeded
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	if remaining > MaxProviderDeadline {
		return ErrBudgetExceeded
	}
	return nil
}

func validAtOrBefore(value *timestamppb.Timestamp, now time.Time) bool {
	return value != nil && value.CheckValid() == nil && !value.AsTime().After(now)
}

func validAfter(value *timestamppb.Timestamp, now time.Time) bool {
	return value != nil && value.CheckValid() == nil && value.AsTime().After(now)
}

func opaqueID(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func slug(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func isSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func safeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func safeFixtureSummary(value string, maximum int) bool {
	return safeText(value, maximum) && strings.HasPrefix(value, "Synthetic ") &&
		!strings.Contains(value, "@") && !strings.Contains(value, "://")
}
