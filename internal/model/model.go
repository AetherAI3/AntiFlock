package model

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

type EvidenceClass string

const (
	EvidenceDetected  EvidenceClass = "DETECTED"
	EvidenceVerified  EvidenceClass = "VERIFIED"
	EvidenceReported  EvidenceClass = "REPORTED"
	EvidenceInferred  EvidenceClass = "INFERRED"
	EvidenceSuspected EvidenceClass = "SUSPECTED"
	EvidenceUnknown   EvidenceClass = "UNKNOWN"
)

func (s Sensitivity) Valid() bool {
	return slices.Contains([]Sensitivity{
		SensitivityPublic,
		SensitivityInternal,
		SensitivityOperatorPrivate,
		SensitivityRestricted,
		SensitivitySecret,
	}, s)
}

func (c EvidenceClass) Valid() bool {
	return slices.Contains([]EvidenceClass{
		EvidenceDetected,
		EvidenceVerified,
		EvidenceReported,
		EvidenceInferred,
		EvidenceSuspected,
		EvidenceUnknown,
	}, c)
}

type Sensitivity string

const (
	SensitivityPublic          Sensitivity = "PUBLIC"
	SensitivityInternal        Sensitivity = "INTERNAL"
	SensitivityOperatorPrivate Sensitivity = "OPERATOR_PRIVATE"
	SensitivityRestricted      Sensitivity = "RESTRICTED"
	SensitivitySecret          Sensitivity = "SECRET"
)

type ProtectionStatus string

const (
	ProtectionProtected   ProtectionStatus = "PROTECTED"
	ProtectionDegraded    ProtectionStatus = "DEGRADED"
	ProtectionSuspicious  ProtectionStatus = "SUSPICIOUS"
	ProtectionExposed     ProtectionStatus = "EXPOSED"
	ProtectionUnknown     ProtectionStatus = "UNKNOWN"
	ProtectionUnavailable ProtectionStatus = "UNAVAILABLE"
)

type EvidenceReference struct {
	ID                string            `json:"id"`
	Role              string            `json:"role,omitempty"`
	Classification    EvidenceClass     `json:"classification"`
	SourceType        string            `json:"sourceType,omitempty"`
	Source            string            `json:"source"`
	SourceURI         string            `json:"sourceUri,omitempty"`
	ObservedAt        time.Time         `json:"observedAt"`
	ReceivedAt        *time.Time        `json:"receivedAt,omitempty"`
	LastVerifiedAt    *time.Time        `json:"lastVerifiedAt,omitempty"`
	ExpiresAt         *time.Time        `json:"expiresAt,omitempty"`
	Confidence        float32           `json:"confidence"`
	Sensitivity       Sensitivity       `json:"sensitivity,omitempty"`
	LocationPrecision string            `json:"locationPrecision,omitempty"`
	Explanation       string            `json:"explanation"`
	Integrity         IntegrityDigest   `json:"integrity,omitempty"`
	SourceLicense     string            `json:"sourceLicense,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
}

type IntegrityDigest struct {
	Algorithm string `json:"algorithm"`
	Digest    []byte `json:"digest"`
}

type Signature struct {
	KeyID               string          `json:"keyId"`
	Algorithm           string          `json:"algorithm"`
	Value               []byte          `json:"value"`
	SignedAt            time.Time       `json:"signedAt"`
	Encoding            string          `json:"encoding"`
	SignedContentDigest IntegrityDigest `json:"signedContentDigest"`
	Domain              string          `json:"domain"`
}

type EventEnvelope struct {
	ID              string              `json:"id"`
	SchemaVersion   string              `json:"schemaVersion"`
	DeploymentID    string              `json:"deploymentId"`
	NodeID          string              `json:"nodeId"`
	Kind            string              `json:"kind"`
	ObservedAt      time.Time           `json:"observedAt"`
	ReceivedAt      time.Time           `json:"receivedAt"`
	Sequence        uint64              `json:"sequence"`
	BootID          string              `json:"bootId"`
	Classification  EvidenceClass       `json:"classification"`
	Confidence      float32             `json:"confidence"`
	Sensitivity     Sensitivity         `json:"sensitivity"`
	PayloadTypeURL  string              `json:"payloadTypeUrl"`
	Payload         []byte              `json:"payload"`
	Evidence        []EvidenceReference `json:"evidence,omitempty"`
	CorrelationID   string              `json:"correlationId,omitempty"`
	CausationID     string              `json:"causationId,omitempty"`
	PayloadDigest   IntegrityDigest     `json:"payloadDigest"`
	SourceSignature Signature           `json:"sourceSignature"`
	IngestOrdinal   uint64              `json:"ingestOrdinal,omitempty"`
}

func (event EventEnvelope) ValidateSourceContent() error {
	if !boundedString(event.ID, 128) {
		return errors.New("event id is required")
	}
	if event.SchemaVersion != "antiflock.event/v1" {
		return errors.New("event schema version must be antiflock.event/v1")
	}
	if !boundedString(event.DeploymentID, 128) {
		return errors.New("event deployment id is required")
	}
	if !boundedString(event.NodeID, 128) {
		return errors.New("event node id is required")
	}
	if !boundedString(event.Kind, 128) || !strings.Contains(event.Kind, ".") {
		return errors.New("event kind must be a namespaced value")
	}
	if event.ObservedAt.IsZero() {
		return errors.New("event observed time is required")
	}
	if err := validateProtoTime(event.ObservedAt, "event observed time"); err != nil {
		return err
	}
	if event.ObservedAt.Before(time.Unix(0, -1<<63).UTC()) || event.ObservedAt.After(time.Unix(0, 1<<63-1).UTC()) {
		return errors.New("event observed time is outside the durable cursor range")
	}
	if event.Sequence == 0 {
		return errors.New("event sequence must be positive")
	}
	if event.Sequence > uint64(1<<63-1) {
		return errors.New("event sequence exceeds durable storage range")
	}
	if !boundedString(event.BootID, 128) {
		return errors.New("event boot id is required")
	}
	if !event.Classification.Valid() {
		return fmt.Errorf("invalid evidence classification %q", event.Classification)
	}
	if math.IsNaN(float64(event.Confidence)) || math.IsInf(float64(event.Confidence), 0) || event.Confidence < 0 || event.Confidence > 1 {
		return errors.New("event confidence must be between 0 and 1")
	}
	if !event.Sensitivity.Valid() {
		return fmt.Errorf("invalid event sensitivity %q", event.Sensitivity)
	}
	if !boundedString(event.PayloadTypeURL, 256) {
		return errors.New("event payload type URL is required")
	}
	if !optionalBoundedString(event.CorrelationID, 128) || !optionalBoundedString(event.CausationID, 128) {
		return errors.New("event correlation and causation ids must be canonical and at most 128 bytes")
	}
	if err := validateEventPayload(event.Kind, event.PayloadTypeURL, event.Payload, event.Sensitivity); err != nil {
		return err
	}
	if event.PayloadDigest.Algorithm != "sha256" || len(event.PayloadDigest.Digest) != sha256.Size {
		return errors.New("event payload digest must be SHA-256")
	}
	payloadDigest := sha256.Sum256(event.Payload)
	if subtle.ConstantTimeCompare(payloadDigest[:], event.PayloadDigest.Digest) != 1 {
		return errors.New("event payload digest does not match the payload")
	}
	if len(event.Evidence) > 64 {
		return errors.New("event evidence exceeds 64 references")
	}
	for index, evidence := range event.Evidence {
		if !boundedString(evidence.ID, 128) || !validEvidenceRole(evidence.Role) || !validEvidenceSource(evidence.SourceType) {
			return fmt.Errorf("evidence %d requires an id, role, and source type", index)
		}
		if !evidence.Classification.Valid() {
			return fmt.Errorf("evidence %d has invalid classification %q", index, evidence.Classification)
		}
		if math.IsNaN(float64(evidence.Confidence)) || math.IsInf(float64(evidence.Confidence), 0) || evidence.Confidence < 0 || evidence.Confidence > 1 {
			return fmt.Errorf("evidence %d confidence must be between 0 and 1", index)
		}
		if !boundedString(evidence.Source, 256) || !boundedString(evidence.Explanation, 2048) || evidence.ObservedAt.IsZero() {
			return fmt.Errorf("evidence %d requires source and explanation", index)
		}
		if !optionalBoundedString(evidence.SourceURI, 2048) || !optionalBoundedString(evidence.SourceLicense, 256) {
			return fmt.Errorf("evidence %d has an invalid source URI or license", index)
		}
		if !validLocationPrecision(evidence.LocationPrecision) {
			return fmt.Errorf("evidence %d has invalid location precision %q", index, evidence.LocationPrecision)
		}
		if err := validateProtoTime(evidence.ObservedAt, fmt.Sprintf("evidence %d observed time", index)); err != nil {
			return err
		}
		for field, value := range map[string]*time.Time{
			"received": evidence.ReceivedAt, "last verified": evidence.LastVerifiedAt, "expires": evidence.ExpiresAt,
		} {
			if value != nil {
				if err := validateProtoTime(*value, fmt.Sprintf("evidence %d %s time", index, field)); err != nil {
					return err
				}
			}
		}
		if evidence.Integrity.Algorithm != "" || len(evidence.Integrity.Digest) != 0 {
			if evidence.Integrity.Algorithm != "sha256" || len(evidence.Integrity.Digest) != sha256.Size {
				return fmt.Errorf("evidence %d integrity must be SHA-256", index)
			}
		}
		if !evidence.Sensitivity.Valid() || sensitivityRank(event.Sensitivity) < sensitivityRank(evidence.Sensitivity) {
			return fmt.Errorf("evidence %d sensitivity exceeds its event envelope", index)
		}
		if evidence.ExpiresAt != nil && !evidence.ExpiresAt.After(evidence.ObservedAt) {
			return fmt.Errorf("evidence %d expiry must follow observation", index)
		}
		if evidence.LastVerifiedAt != nil && evidence.LastVerifiedAt.Before(evidence.ObservedAt) {
			return fmt.Errorf("evidence %d verification predates observation", index)
		}
		if len(evidence.Attributes) > 32 {
			return fmt.Errorf("evidence %d has too many attributes", index)
		}
		for key, value := range evidence.Attributes {
			if !boundedString(key, 128) || !boundedString(value, 1024) {
				return fmt.Errorf("evidence %d has an oversized attribute", index)
			}
		}
	}
	return nil
}

func boundedString(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func optionalBoundedString(value string, maximum int) bool {
	return value == "" || boundedString(value, maximum)
}

func validLocationPrecision(value string) bool {
	return slices.Contains([]string{"", "WITHHELD", "REGION", "CITY", "NEIGHBORHOOD", "BLOCK", "EXACT"}, value)
}

func validEvidenceRole(value string) bool {
	return slices.Contains([]string{"SUPPORTING", "CONTRADICTING", "CONTEXT"}, value)
}

func validEvidenceSource(value string) bool {
	return slices.Contains([]string{
		"LOCAL_SENSOR", "AUTHORIZED_GATEWAY", "PROVIDER_API", "PUBLIC_RECORD", "PUBLIC_DATASET",
		"COMMUNITY_REPORT", "TRUSTED_REVIEWER", "DETERMINISTIC_RULE", "OPERATOR_DECLARATION",
	}, value)
}

func sensitivityRank(value Sensitivity) int {
	return map[Sensitivity]int{
		SensitivityPublic: 1, SensitivityInternal: 2, SensitivityOperatorPrivate: 3,
		SensitivityRestricted: 4, SensitivitySecret: 5,
	}[value]
}

func (event EventEnvelope) Validate() error {
	if err := event.ValidateSourceContent(); err != nil {
		return err
	}
	if err := event.SourceSignature.Validate(); err != nil {
		return fmt.Errorf("event source signature: %w", err)
	}
	return nil
}

func (signature Signature) Validate() error {
	if strings.TrimSpace(signature.KeyID) == "" {
		return errors.New("key id is required")
	}
	if signature.Algorithm != "ED25519" {
		return errors.New("algorithm must be ED25519")
	}
	if len(signature.Value) != 64 {
		return errors.New("Ed25519 signature must be 64 bytes")
	}
	if signature.SignedAt.IsZero() {
		return errors.New("signed time is required")
	}
	if signature.Encoding != "PROTOBUF_DETERMINISTIC_V1" {
		return errors.New("encoding must be PROTOBUF_DETERMINISTIC_V1")
	}
	if signature.Domain != "antiflock.event.v1" {
		return errors.New("domain must be antiflock.event.v1")
	}
	if signature.SignedContentDigest.Algorithm != "sha256" || len(signature.SignedContentDigest.Digest) != sha256.Size {
		return errors.New("signed content digest must be SHA-256")
	}
	return nil
}

type NodeStatus string

const (
	NodeActive    NodeStatus = "ACTIVE"
	NodeSuspended NodeStatus = "SUSPENDED"
	NodeRevoked   NodeStatus = "REVOKED"
)

type Node struct {
	ID                       string          `json:"id"`
	Name                     string          `json:"name"`
	Type                     string          `json:"type"`
	Platform                 string          `json:"platform"`
	PlatformVersion          string          `json:"platformVersion"`
	Status                   NodeStatus      `json:"status"`
	Tags                     []string        `json:"tags"`
	Capabilities             json.RawMessage `json:"capabilities"`
	CapabilitiesVerification string          `json:"capabilitiesVerification"`
	PublicKey                []byte          `json:"-"`
	CertificatePEM           string          `json:"certificatePem,omitempty"`
	EnrolledAt               time.Time       `json:"enrolledAt"`
	LastSeenAt               *time.Time      `json:"lastSeenAt,omitempty"`
	RevokedAt                *time.Time      `json:"revokedAt,omitempty"`
	LastPolicyRevision       uint64          `json:"lastPolicyRevision"`
}

type AuditEntry struct {
	Sequence     uint64          `json:"sequence"`
	ID           string          `json:"id"`
	KeyID        string          `json:"keyId"`
	OccurredAt   time.Time       `json:"occurredAt"`
	ActorType    string          `json:"actorType"`
	ActorID      string          `json:"actorId"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resourceType"`
	ResourceID   string          `json:"resourceId"`
	Outcome      string          `json:"outcome"`
	Details      json.RawMessage `json:"details"`
	PreviousHash string          `json:"previousHash"`
	EntryHash    string          `json:"entryHash"`
	Signature    string          `json:"signature"`
}

type FindingSeverity string

const (
	SeverityInfo     FindingSeverity = "INFO"
	SeverityLow      FindingSeverity = "LOW"
	SeverityMedium   FindingSeverity = "MEDIUM"
	SeverityHigh     FindingSeverity = "HIGH"
	SeverityCritical FindingSeverity = "CRITICAL"
)

type Finding struct {
	ID                string              `json:"id"`
	RuleID            string              `json:"ruleId"`
	NodeID            string              `json:"nodeId"`
	Status            string              `json:"status"`
	Severity          FindingSeverity     `json:"severity"`
	Classification    EvidenceClass       `json:"classification"`
	Confidence        float32             `json:"confidence"`
	Title             string              `json:"title"`
	Condition         string              `json:"condition"`
	Consequence       string              `json:"consequence"`
	CurrentFact       string              `json:"currentFact"`
	ExpectedFact      string              `json:"expectedFact"`
	Explanation       string              `json:"explanation"`
	RecommendedAction string              `json:"recommendedAction"`
	FalsePositiveNote string              `json:"falsePositiveNote"`
	Evidence          []EvidenceReference `json:"evidence"`
	OpenedAt          time.Time           `json:"openedAt"`
	UpdatedAt         time.Time           `json:"updatedAt"`
	ResolvedAt        *time.Time          `json:"resolvedAt,omitempty"`
}

type ProtectionSnapshot struct {
	NodeID             string           `json:"nodeId"`
	Status             ProtectionStatus `json:"status"`
	EvaluatedAt        time.Time        `json:"evaluatedAt"`
	NetworkTrust       string           `json:"networkTrust"`
	MeshConnected      *bool            `json:"meshConnected"`
	ApprovedExitActive *bool            `json:"approvedExitActive"`
	DNSProtected       *bool            `json:"dnsProtected"`
	RouteProtected     *bool            `json:"routeProtected"`
	TelemetryFresh     bool             `json:"telemetryFresh"`
	ReasonCodes        []string         `json:"reasonCodes"`
	FindingIDs         []string         `json:"findingIds"`
	PolicyRevision     uint64           `json:"policyRevision"`
}

type Entity struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	DisplayName string          `json:"displayName"`
	Attributes  json.RawMessage `json:"attributes"`
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
}

type Relationship struct {
	ID             string              `json:"id"`
	SourceEntityID string              `json:"sourceEntityId"`
	TargetEntityID string              `json:"targetEntityId"`
	Type           string              `json:"type"`
	Classification EvidenceClass       `json:"classification"`
	Confidence     float32             `json:"confidence"`
	FirstSeen      time.Time           `json:"firstSeen"`
	LastSeen       time.Time           `json:"lastSeen"`
	Evidence       []EvidenceReference `json:"evidence"`
}

type Check struct {
	Kind     string          `json:"kind" yaml:"kind"`
	Expected json.RawMessage `json:"expected" yaml:"expected"`
}

type PlanAction struct {
	Kind       string          `json:"kind" yaml:"kind"`
	Parameters json.RawMessage `json:"parameters" yaml:"parameters"`
	Risk       string          `json:"risk" yaml:"risk"`
}

type Plan struct {
	ID            string       `json:"id"`
	Revision      uint64       `json:"revision"`
	NodeID        string       `json:"nodeId"`
	CreatedAt     time.Time    `json:"createdAt"`
	ExpiresAt     time.Time    `json:"expiresAt"`
	Preconditions []Check      `json:"preconditions"`
	Actions       []PlanAction `json:"actions"`
	Verifications []Check      `json:"verifications"`
	Rollback      []PlanAction `json:"rollback"`
	Signature     string       `json:"signature"`
}

type DecisionType string

const (
	DecisionAllow          DecisionType = "ALLOW"
	DecisionHold           DecisionType = "HOLD"
	DecisionBlock          DecisionType = "BLOCK"
	DecisionRequireConsent DecisionType = "REQUIRE_CONSENT"
	DecisionAllowOnce      DecisionType = "ALLOW_ONCE"
)

type SecureActionRequest struct {
	RequestID     string    `json:"requestId"`
	ApplicationID string    `json:"applicationId"`
	ActionType    string    `json:"actionType"`
	Destinations  []string  `json:"destinations"`
	DataClass     string    `json:"dataClass"`
	Sensitivity   string    `json:"sensitivity"`
	Deadline      time.Time `json:"deadline"`
}

type SecureActionDecision struct {
	ActionID      string             `json:"actionId"`
	Decision      DecisionType       `json:"decision"`
	Protection    ProtectionSnapshot `json:"protection"`
	ReasonCodes   []string           `json:"reasonCodes"`
	Authorization string             `json:"authorization,omitempty"`
	ExpiresAt     *time.Time         `json:"expiresAt,omitempty"`
}
