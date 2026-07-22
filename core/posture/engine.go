package posture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ReasonTelemetryUnavailable = "AF-TELEMETRY-UNAVAILABLE"
	ReasonTelemetryStale       = "AF-TELEMETRY-STALE"
	ReasonMeshDisconnected     = "AF-MESH-DISCONNECTED"
	ReasonExitUnverified       = "AF-EGRESS-EXIT-UNVERIFIED"
	ReasonDNSUnprotected       = "AF-DNS-UNPROTECTED"
	ReasonRouteUnprotected     = "AF-ROUTE-UNPROTECTED"
	ReasonNetworkTrustUnknown  = "AF-NETWORK-TRUST-UNKNOWN"
	ReasonProtected            = "AF-PROTECTION-VERIFIED"
)

type Fact struct {
	Known          bool
	Value          bool
	Classification antiflockv1.EvidenceClass
	Confidence     float32
	ObservedAt     time.Time
	Explanation    string
}

type Input struct {
	DeploymentID           string
	NodeID                 string
	PolicyID               string
	PolicyRevision         uint64
	EvaluatedAt            time.Time
	TelemetryAt            time.Time
	NetworkTrust           string
	RequireMeshOnUntrusted bool
	MeshConnected          Fact
	ApprovedExitActive     Fact
	DNSProtected           Fact
	RouteProtected         Fact
}

type Engine struct {
	staleAfter time.Duration
}

func New(staleAfter time.Duration) (*Engine, error) {
	if staleAfter <= 0 || staleAfter > 30*time.Minute {
		return nil, errors.New("posture telemetry freshness must be between zero and 30 minutes")
	}
	return &Engine{staleAfter: staleAfter}, nil
}

func (engine *Engine) Evaluate(input Input) (*antiflockv1.ProtectionSnapshot, error) {
	if engine == nil {
		return nil, errors.New("posture engine is required")
	}
	if input.DeploymentID == "" || input.NodeID == "" || input.PolicyID == "" || input.PolicyRevision == 0 {
		return nil, errors.New("posture deployment, node, policy, and revision are required")
	}
	if input.EvaluatedAt.IsZero() {
		return nil, errors.New("posture evaluation time is required")
	}
	input.EvaluatedAt = input.EvaluatedAt.UTC()
	state := antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED
	reasons := make([]*antiflockv1.PostureReason, 0, 4)
	confidence := float32(1)

	if input.TelemetryAt.IsZero() {
		state = antiflockv1.ProtectionState_PROTECTION_STATE_UNKNOWN
		reasons = append(reasons, reason(ReasonTelemetryUnavailable, state, "No current endpoint telemetry is available.", "Fresh signed endpoint telemetry is required.", antiflockv1.EvidenceClass_EVIDENCE_CLASS_UNKNOWN, 0))
	} else if age := input.EvaluatedAt.Sub(input.TelemetryAt.UTC()); age < -5*time.Minute || age > engine.staleAfter {
		state = antiflockv1.ProtectionState_PROTECTION_STATE_UNKNOWN
		reasons = append(reasons, reason(ReasonTelemetryStale, state, "The latest endpoint telemetry is outside the freshness window.", "Fresh signed endpoint telemetry is required.", antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED, 1))
	}
	if input.NetworkTrust != "TRUSTED" && input.NetworkTrust != "UNTRUSTED" {
		if state == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED {
			state = antiflockv1.ProtectionState_PROTECTION_STATE_UNKNOWN
		}
		reasons = append(reasons, reason(ReasonNetworkTrustUnknown, antiflockv1.ProtectionState_PROTECTION_STATE_UNKNOWN,
			"The current network trust classification is unknown.", "The network must be classified before protection can be verified.",
			antiflockv1.EvidenceClass_EVIDENCE_CLASS_UNKNOWN, 0))
		confidence = 0
	}

	checks := []struct {
		required bool
		fact     Fact
		code     string
		current  string
		expected string
	}{
		{input.NetworkTrust == "UNTRUSTED" && input.RequireMeshOnUntrusted, input.MeshConnected, ReasonMeshDisconnected, "The approved private mesh is not connected.", "The approved private mesh must be connected on an untrusted network."},
		{input.NetworkTrust == "UNTRUSTED", input.ApprovedExitActive, ReasonExitUnverified, "The approved exit path is not active and verified.", "Traffic must use an approved verified exit on an untrusted network."},
		{input.NetworkTrust == "UNTRUSTED", input.DNSProtected, ReasonDNSUnprotected, "DNS protection is not active and verified.", "DNS must use the protected path on an untrusted network."},
		{input.NetworkTrust == "UNTRUSTED", input.RouteProtected, ReasonRouteUnprotected, "The protected route is not active and verified.", "The protected route must be active on an untrusted network."},
	}
	requiredFacts, allRequiredFactsVerified := 0, true
	for _, check := range checks {
		if !check.required {
			continue
		}
		requiredFacts++
		if !check.fact.Known {
			if state == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED {
				state = antiflockv1.ProtectionState_PROTECTION_STATE_UNKNOWN
			}
			reasons = append(reasons, reason(check.code, antiflockv1.ProtectionState_PROTECTION_STATE_UNKNOWN, "The control state is unknown.", check.expected, antiflockv1.EvidenceClass_EVIDENCE_CLASS_UNKNOWN, 0))
			confidence = 0
			continue
		}
		if !validFact(check.fact, input.EvaluatedAt, engine.staleAfter) {
			return nil, fmt.Errorf("posture fact %s is invalid", check.code)
		}
		if check.fact.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED {
			allRequiredFactsVerified = false
		}
		confidence = minConfidence(confidence, check.fact.Confidence)
		if !check.fact.Value {
			state = antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED
			reasons = append(reasons, reason(check.code, state, check.current, check.expected, check.fact.Classification, check.fact.Confidence))
		}
	}
	if state == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED {
		classification := antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED
		if requiredFacts > 0 && allRequiredFactsVerified {
			classification = antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED
		}
		reasons = append(reasons, reason(ReasonProtected, state, "Mesh, approved exit, DNS, and route checks meet the active policy.", "All required path controls must remain verified.", classification, confidence))
	}
	sort.Slice(reasons, func(left, right int) bool { return reasons[left].ReasonCode < reasons[right].ReasonCode })
	validUntil := input.EvaluatedAt.Add(engine.staleAfter)
	snapshot := &antiflockv1.ProtectionSnapshot{
		Id: snapshotID(input, state, reasons), DeploymentId: input.DeploymentID, NodeId: input.NodeID,
		PolicyId: input.PolicyID, PolicyRevision: input.PolicyRevision, State: state,
		EnforcementState: enforcementFor(state), EvaluatedAt: timestamppb.New(input.EvaluatedAt),
		ValidUntil: timestamppb.New(validUntil), Reasons: reasons, Confidence: confidence,
		RecommendedResponse: recommendation(state),
	}
	return snapshot, nil
}

func validFact(fact Fact, now time.Time, staleAfter time.Duration) bool {
	if fact.Classification == antiflockv1.EvidenceClass_EVIDENCE_CLASS_UNSPECIFIED ||
		math.IsNaN(float64(fact.Confidence)) || math.IsInf(float64(fact.Confidence), 0) ||
		fact.Confidence < 0 || fact.Confidence > 1 || fact.ObservedAt.IsZero() {
		return false
	}
	age := now.Sub(fact.ObservedAt.UTC())
	return age >= -5*time.Minute && age <= staleAfter
}

func reason(code string, state antiflockv1.ProtectionState, current, expected string, class antiflockv1.EvidenceClass, confidence float32) *antiflockv1.PostureReason {
	return &antiflockv1.PostureReason{
		RuleId: "antiflock.guard.v1", ReasonCode: code, ContributedState: state,
		CurrentFact: current, ExpectedFact: expected,
		Claim: &antiflockv1.EvidenceClaim{
			Id: "claim_" + code, ReasonCode: code, Statement: current,
			Classification: class, Confidence: confidence, Explanation: current,
			RecommendedResponse: recommendation(state),
		},
	}
}

func snapshotID(input Input, state antiflockv1.ProtectionState, reasons []*antiflockv1.PostureReason) string {
	hasher := sha256.New()
	fmt.Fprintf(hasher, "%s\x00%s\x00%s\x00%d\x00%d\x00%s", input.DeploymentID, input.NodeID, input.PolicyID, input.PolicyRevision, state, input.EvaluatedAt.UTC().Format(time.RFC3339Nano))
	for _, value := range reasons {
		fmt.Fprintf(hasher, "\x00%s", value.ReasonCode)
	}
	return "posture_" + hex.EncodeToString(hasher.Sum(nil)[:16])
}

func minConfidence(left, right float32) float32 {
	if right < left {
		return right
	}
	return left
}

func enforcementFor(state antiflockv1.ProtectionState) antiflockv1.EnforcementState {
	if state == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED {
		return antiflockv1.EnforcementState_ENFORCEMENT_STATE_ALLOWING
	}
	return antiflockv1.EnforcementState_ENFORCEMENT_STATE_HOLDING
}

func recommendation(state antiflockv1.ProtectionState) string {
	if state == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED {
		return "Continue monitoring the verified path."
	}
	return "Hold protected egress until the required path controls are restored and verified."
}
