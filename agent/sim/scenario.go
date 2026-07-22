// Package sim provides deterministic, non-privileged acceptance scenarios.
package sim

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/actions"
	"github.com/DBarr3/AntiFlock/core/posture"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ScenarioSchemaVersion = "antiflock.simulation/v1"
	CoffeeShopScenarioID  = "coffee-shop-route-loss-and-recovery"
)

// AuditStep is a simulation-only, hash-chained audit projection. EvidenceClass
// remains explicit so a local detection cannot be mistaken for VERIFIED proof.
type AuditStep struct {
	Sequence         uint64   `json:"sequence"`
	OccurredAt       string   `json:"occurredAt"`
	Kind             string   `json:"kind"`
	ProtectionState  string   `json:"protectionState,omitempty"`
	EnforcementState string   `json:"enforcementState,omitempty"`
	ActionDecision   string   `json:"actionDecision,omitempty"`
	ReasonCodes      []string `json:"reasonCodes,omitempty"`
	EvidenceClass    string   `json:"evidenceClass"`
	SafeDescription  string   `json:"safeDescription"`
	PreviousHash     string   `json:"previousHash,omitempty"`
	EntryHash        string   `json:"entryHash"`
}

type Result struct {
	SchemaVersion        string      `json:"schemaVersion"`
	ScenarioID           string      `json:"scenarioId"`
	Simulation           bool        `json:"simulation"`
	StartedAt            string      `json:"startedAt"`
	NodeID               string      `json:"nodeId"`
	PolicyID             string      `json:"policyId"`
	PolicyRevision       uint64      `json:"policyRevision"`
	Timeline             []AuditStep `json:"timeline"`
	FinalProtectionState string      `json:"finalProtectionState"`
	FinalActionDecision  string      `json:"finalActionDecision"`
	AuditRoot            string      `json:"auditRoot"`
}

// RunCoffeeShop evaluates the locked route-loss, action-hold, recovery, and
// release flow using the real deterministic posture and action-gate code. It
// performs no network calls or host mutation.
func RunCoffeeShop(start time.Time) (*Result, error) {
	if start.IsZero() {
		return nil, errors.New("simulation start time is required")
	}
	start = start.UTC()
	if timestamppb.New(start).CheckValid() != nil {
		return nil, errors.New("simulation start time is outside the protobuf range")
	}
	engine, err := posture.New(2 * time.Minute)
	if err != nil {
		return nil, err
	}
	gate, err := actions.New(actions.Policy{
		NodeIDs: []string{"simulated-phone"}, ApplicationIDs: []string{"aether-code"}, ActionTypes: []string{"git.push"},
		DataClasses: []string{"repository-source"}, Sensitivities: []string{"SENSITIVITY_OPERATOR_PRIVATE"},
		AllowedDestinations: []string{"github.com"}, AllowOneTimeBypass: false, OneTimeBypassTTL: 5 * time.Minute,
	}, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		return nil, err
	}
	fact := func(value bool, observedAt time.Time) posture.Fact {
		return posture.Fact{
			Known: true, Value: value, Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED,
			Confidence: 1, ObservedAt: observedAt, Explanation: "Deterministic local simulation fact.",
		}
	}
	input := posture.Input{
		DeploymentID: "simulation-deployment", NodeID: "simulated-phone", PolicyID: "coffee-shop-guard", PolicyRevision: 7,
		EvaluatedAt: start, TelemetryAt: start, NetworkTrust: "UNTRUSTED", RequireMeshOnUntrusted: true,
		MeshConnected: fact(false, start), ApprovedExitActive: fact(false, start),
		DNSProtected: fact(false, start), RouteProtected: fact(false, start),
	}
	exposed, err := engine.Evaluate(input)
	if err != nil {
		return nil, err
	}
	exposed.EvidenceProvenance = antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION
	if err := ensureEvidenceHonesty(exposed); err != nil {
		return nil, err
	}
	action := &antiflockv1.SecureActionRequest{
		Id: "simulated-sensitive-action", ApplicationId: "aether-code", NodeId: input.NodeID,
		ActionType: "git.push", Destinations: []string{"github.com"}, DataClass: "repository-source",
		Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		Deadline:    timestamppb.New(start.Add(90 * time.Second)), OperationId: "simulated-operation",
	}
	held, err := gate.Evaluate(action, exposed, start.Add(time.Second))
	if err != nil {
		return nil, err
	}

	recoveredAt := start.Add(10 * time.Second)
	input.EvaluatedAt = recoveredAt
	input.TelemetryAt = recoveredAt
	input.MeshConnected = fact(true, recoveredAt)
	input.ApprovedExitActive = fact(true, recoveredAt)
	input.DNSProtected = fact(true, recoveredAt)
	input.RouteProtected = fact(true, recoveredAt)
	protected, err := engine.Evaluate(input)
	if err != nil {
		return nil, err
	}
	protected.EvidenceProvenance = antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_SIMULATION
	if err := ensureEvidenceHonesty(protected); err != nil {
		return nil, err
	}
	allowed, err := gate.Evaluate(action, protected, recoveredAt.Add(time.Second))
	if err != nil {
		return nil, err
	}

	result := &Result{
		SchemaVersion: ScenarioSchemaVersion, ScenarioID: CoffeeShopScenarioID, Simulation: true,
		StartedAt: start.Format(time.RFC3339Nano), NodeID: input.NodeID, PolicyID: input.PolicyID, PolicyRevision: input.PolicyRevision,
	}
	appendStep := func(at time.Time, kind string, snapshot *antiflockv1.ProtectionSnapshot, decision *antiflockv1.SecureActionDecision, description string) error {
		step := AuditStep{
			Sequence: uint64(len(result.Timeline) + 1), OccurredAt: at.UTC().Format(time.RFC3339Nano), Kind: kind,
			EvidenceClass: "DETECTED", SafeDescription: description,
		}
		if snapshot != nil {
			step.ProtectionState = trimEnum(snapshot.State.String(), "PROTECTION_STATE_")
			step.EnforcementState = trimEnum(snapshot.EnforcementState.String(), "ENFORCEMENT_STATE_")
			step.ReasonCodes = snapshotReasons(snapshot)
		}
		if decision != nil {
			step.ActionDecision = trimEnum(decision.Decision.String(), "SECURE_ACTION_DECISION_TYPE_")
			step.ReasonCodes = append([]string(nil), decision.ReasonCodes...)
			sort.Strings(step.ReasonCodes)
		}
		if len(result.Timeline) != 0 {
			step.PreviousHash = result.Timeline[len(result.Timeline)-1].EntryHash
		}
		hash, err := hashStep(step)
		if err != nil {
			return err
		}
		step.EntryHash = hash
		result.Timeline = append(result.Timeline, step)
		return nil
	}
	steps := []struct {
		at          time.Time
		kind        string
		snapshot    *antiflockv1.ProtectionSnapshot
		decision    *antiflockv1.SecureActionDecision
		description string
	}{
		{start, "network.wifi_changed", exposed, nil, "The simulated phone joined an untrusted network; no location or Wi-Fi identifier was recorded."},
		{start.Add(time.Second), "mesh.connection_lost", exposed, nil, "Local metadata detected loss of the approved path; this does not allege interception."},
		{start.Add(2 * time.Second), "action.held", exposed, held, "The integrated sensitive action was held while protection was not established."},
		{recoveredAt, "mesh.path_changed", protected, nil, "Local deterministic checks detected restored mesh, exit, route, and DNS state; evidence remains DETECTED."},
		{recoveredAt.Add(time.Second), "action.allowed", protected, allowed, "The held action was reevaluated and allowed after the protected state returned."},
	}
	for _, step := range steps {
		if err := appendStep(step.at, step.kind, step.snapshot, step.decision, step.description); err != nil {
			return nil, err
		}
	}
	result.FinalProtectionState = trimEnum(protected.State.String(), "PROTECTION_STATE_")
	result.FinalActionDecision = trimEnum(allowed.Decision.String(), "SECURE_ACTION_DECISION_TYPE_")
	result.AuditRoot = result.Timeline[len(result.Timeline)-1].EntryHash
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

func (result *Result) Validate() error {
	if result == nil || result.SchemaVersion != ScenarioSchemaVersion || result.ScenarioID != CoffeeShopScenarioID || !result.Simulation || len(result.Timeline) == 0 {
		return errors.New("simulation result identity is invalid")
	}
	previousHash := ""
	seenHeld, seenAllowed := false, false
	var lastTime time.Time
	for index, step := range result.Timeline {
		if step.Sequence != uint64(index+1) || step.PreviousHash != previousHash || step.EvidenceClass != "DETECTED" {
			return fmt.Errorf("simulation audit step %d has invalid ordering or evidence class", index+1)
		}
		occurredAt, err := time.Parse(time.RFC3339Nano, step.OccurredAt)
		if err != nil || (!lastTime.IsZero() && occurredAt.Before(lastTime)) {
			return fmt.Errorf("simulation audit step %d has invalid time", index+1)
		}
		expectedHash, err := hashStep(step)
		if err != nil || expectedHash != step.EntryHash {
			return fmt.Errorf("simulation audit step %d failed hash verification", index+1)
		}
		if step.ActionDecision == "HOLD" {
			seenHeld = true
		}
		if step.ActionDecision == "ALLOW" {
			if !seenHeld {
				return errors.New("simulation allowed the action before recording its hold")
			}
			seenAllowed = true
		}
		previousHash = step.EntryHash
		lastTime = occurredAt
	}
	if !seenHeld || !seenAllowed || result.FinalProtectionState != "PROTECTED" || result.FinalActionDecision != "ALLOW" || result.AuditRoot != previousHash {
		return errors.New("simulation did not complete the fail-closed recovery flow")
	}
	return nil
}

func ensureEvidenceHonesty(snapshot *antiflockv1.ProtectionSnapshot) error {
	if snapshot == nil {
		return errors.New("simulation posture snapshot is required")
	}
	for _, reason := range snapshot.Reasons {
		if reason != nil && reason.Claim != nil && reason.Claim.Classification == antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED {
			return errors.New("simulation cannot fabricate VERIFIED evidence")
		}
	}
	return nil
}

func snapshotReasons(snapshot *antiflockv1.ProtectionSnapshot) []string {
	result := make([]string, 0, len(snapshot.Reasons))
	for _, reason := range snapshot.Reasons {
		if reason != nil && reason.ReasonCode != "" {
			result = append(result, reason.ReasonCode)
		}
	}
	sort.Strings(result)
	return result
}

func hashStep(step AuditStep) (string, error) {
	step.EntryHash = ""
	encoded, err := json.Marshal(step)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("AntiFlock-Simulation-Audit-v1\x00"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func trimEnum(value, prefix string) string { return strings.TrimPrefix(value, prefix) }
