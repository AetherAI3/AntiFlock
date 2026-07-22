package actions_test

import (
	"bytes"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/actions"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestActionGateHoldsUntilProtectedAndScopesOneTimeConsent(t *testing.T) {
	t.Parallel()
	policy := actions.Policy{
		NodeIDs: []string{"phone"}, ApplicationIDs: []string{"aether-code"}, ActionTypes: []string{"git.push"},
		DataClasses: []string{"repository-source"}, Sensitivities: []string{"SENSITIVITY_OPERATOR_PRIVATE"},
		AllowedDestinations: []string{"github.com"}, AllowOneTimeBypass: true, OneTimeBypassTTL: 5 * time.Minute,
	}
	gate, err := actions.New(policy, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policy.ApplicationIDs[0] = "mutated-after-construction"
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	request := &antiflockv1.SecureActionRequest{
		Id: "action", ApplicationId: "aether-code", NodeId: "phone", ActionType: "git.push",
		Destinations: []string{"github.com"}, DataClass: "repository-source",
		Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		Deadline:    timestamppb.New(now.Add(time.Minute)), OperationId: "operation",
	}
	snapshot := &antiflockv1.ProtectionSnapshot{
		NodeId: "phone", PolicyRevision: 7, State: antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED,
		EvidenceProvenance: antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_LIVE,
		EvaluatedAt:        timestamppb.New(now), ValidUntil: timestamppb.New(now.Add(time.Minute)),
		Reasons: []*antiflockv1.PostureReason{{ReasonCode: "AF-MESH-DISCONNECTED"}},
	}
	held, err := gate.Evaluate(request, snapshot, now)
	if err != nil || held.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_HOLD || held.ExpiresAt == nil {
		t.Fatalf("held decision = %#v, %v", held, err)
	}
	expiredRequest := proto.Clone(request).(*antiflockv1.SecureActionRequest)
	expiredRequest.Id = "expired-action"
	expiredRequest.OperationId = "expired-operation"
	expiredRequest.Deadline = timestamppb.New(now.Add(-time.Second))
	expired, err := gate.Evaluate(expiredRequest, snapshot, now)
	if err != nil || expired.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_BLOCK {
		t.Fatalf("expired decision = %#v, %v", expired, err)
	}
	if _, authorizeErr := gate.AuthorizeOnce(expiredRequest, expired, expiredRequest.Destinations, now.Add(time.Minute), now, true); authorizeErr == nil {
		t.Fatal("expired action received one-time authorization")
	}
	if _, err := gate.AuthorizeOnce(request, held, []string{"attacker.example"}, now.Add(time.Minute), now, true); err == nil {
		t.Fatal("mismatched one-time authorization scope was accepted")
	}
	mutatedPrior := proto.Clone(held).(*antiflockv1.SecureActionDecision)
	mutatedPrior.Protection.PolicyRevision++
	if _, authorizeErr := gate.AuthorizeOnce(request, mutatedPrior, request.Destinations, now.Add(time.Minute), now, true); authorizeErr == nil {
		t.Fatal("mutated prior protection snapshot was accepted")
	}
	for name, mutate := range map[string]func(*antiflockv1.SecureActionRequest){
		"application": func(value *antiflockv1.SecureActionRequest) { value.ApplicationId = "attacker-app" },
		"node":        func(value *antiflockv1.SecureActionRequest) { value.NodeId = "attacker-node" },
		"operation":   func(value *antiflockv1.SecureActionRequest) { value.OperationId = "attacker-operation" },
		"action type": func(value *antiflockv1.SecureActionRequest) { value.ActionType = "shell.execute" },
		"data class":  func(value *antiflockv1.SecureActionRequest) { value.DataClass = "credentials" },
		"sensitivity": func(value *antiflockv1.SecureActionRequest) {
			value.Sensitivity = antiflockv1.Sensitivity_SENSITIVITY_RESTRICTED
		},
	} {
		t.Run("one-time consent rejects changed "+name, func(t *testing.T) {
			changed := proto.Clone(request).(*antiflockv1.SecureActionRequest)
			mutate(changed)
			if _, authorizeErr := gate.AuthorizeOnce(changed, held, changed.Destinations, now.Add(time.Minute), now, true); authorizeErr == nil {
				t.Fatal("changed request was authorized from an unrelated prior decision")
			}
		})
	}
	once, err := gate.AuthorizeOnce(request, held, request.Destinations, now.Add(time.Minute), now, true)
	if err != nil || once.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_ALLOW_ONCE || once.Authorization == "" {
		t.Fatalf("one-time decision = %#v, %v", once, err)
	}
	snapshot.State = antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED
	snapshot.EvaluatedAt = timestamppb.New(now.Add(time.Second))
	allowed, err := gate.Evaluate(request, snapshot, now.Add(time.Second))
	if err != nil || allowed.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_ALLOW || allowed.Authorization != "" {
		t.Fatalf("restored decision = %#v, %v", allowed, err)
	}
	unknownSnapshot := proto.Clone(snapshot).(*antiflockv1.ProtectionSnapshot)
	unknownSnapshot.EvidenceProvenance = antiflockv1.EvidenceProvenance_EVIDENCE_PROVENANCE_UNKNOWN
	unknown, err := gate.Evaluate(request, unknownSnapshot, now.Add(time.Second))
	if err != nil || unknown.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_HOLD {
		t.Fatalf("unknown-provenance decision = %#v, %v", unknown, err)
	}
	futureSnapshot := proto.Clone(snapshot).(*antiflockv1.ProtectionSnapshot)
	futureSnapshot.EvidenceProvenance = antiflockv1.EvidenceProvenance(99)
	future, err := gate.Evaluate(request, futureSnapshot, now.Add(time.Second))
	if err != nil || future.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_HOLD {
		t.Fatalf("unrecognized-provenance decision = %#v, %v", future, err)
	}
	futureSensitivity := proto.Clone(request).(*antiflockv1.SecureActionRequest)
	futureSensitivity.Sensitivity = antiflockv1.Sensitivity(99)
	if _, evaluateErr := gate.Evaluate(futureSensitivity, snapshot, now.Add(time.Second)); evaluateErr == nil {
		t.Fatal("unrecognized sensitivity was accepted")
	}
	for name, mutate := range map[string]func(*antiflockv1.SecureActionRequest){
		"node":        func(value *antiflockv1.SecureActionRequest) { value.NodeId = "attacker-node" },
		"action type": func(value *antiflockv1.SecureActionRequest) { value.ActionType = "shell.execute" },
		"sensitivity": func(value *antiflockv1.SecureActionRequest) {
			value.Sensitivity = antiflockv1.Sensitivity_SENSITIVITY_RESTRICTED
		},
	} {
		t.Run(name+" is outside policy", func(t *testing.T) {
			changed := proto.Clone(request).(*antiflockv1.SecureActionRequest)
			mutate(changed)
			changedSnapshot := proto.Clone(snapshot).(*antiflockv1.ProtectionSnapshot)
			changedSnapshot.NodeId = changed.NodeId
			blocked, evaluateErr := gate.Evaluate(changed, changedSnapshot, now.Add(time.Second))
			if evaluateErr != nil || blocked.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_BLOCK {
				t.Fatalf("outside-policy decision = %#v, %v", blocked, evaluateErr)
			}
		})
	}
}
