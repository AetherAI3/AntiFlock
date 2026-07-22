package actions_test

import (
	"bytes"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/actions"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestActionGateHoldsUntilProtectedAndScopesOneTimeConsent(t *testing.T) {
	t.Parallel()
	gate, err := actions.New(actions.Policy{
		ApplicationIDs: []string{"aether-code"}, DataClasses: []string{"repository-source"},
		AllowedDestinations: []string{"github.com"}, AllowOneTimeBypass: true, OneTimeBypassTTL: 5 * time.Minute,
	}, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	request := &antiflockv1.SecureActionRequest{
		Id: "action", ApplicationId: "aether-code", NodeId: "phone", ActionType: "git.push",
		Destinations: []string{"github.com"}, DataClass: "repository-source",
		Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		Deadline:    timestamppb.New(now.Add(time.Minute)), OperationId: "operation",
	}
	snapshot := &antiflockv1.ProtectionSnapshot{
		NodeId: "phone", PolicyRevision: 7, State: antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED,
		EvaluatedAt: timestamppb.New(now), ValidUntil: timestamppb.New(now.Add(time.Minute)),
		Reasons: []*antiflockv1.PostureReason{{ReasonCode: "AF-MESH-DISCONNECTED"}},
	}
	held, err := gate.Evaluate(request, snapshot, now)
	if err != nil || held.Decision != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_HOLD || held.ExpiresAt == nil {
		t.Fatalf("held decision = %#v, %v", held, err)
	}
	if _, err := gate.AuthorizeOnce(request, held, []string{"attacker.example"}, now.Add(time.Minute), now, true); err == nil {
		t.Fatal("mismatched one-time authorization scope was accepted")
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
}
