package actions

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Policy struct {
	ApplicationIDs      []string
	DataClasses         []string
	AllowedDestinations []string
	AllowOneTimeBypass  bool
	OneTimeBypassTTL    time.Duration
}

type Gate struct {
	policy Policy
	key    []byte
}

func New(policy Policy, authorizationKey []byte) (*Gate, error) {
	if len(authorizationKey) < 32 {
		return nil, errors.New("action authorization key must contain at least 32 bytes")
	}
	if policy.OneTimeBypassTTL <= 0 || policy.OneTimeBypassTTL > 15*time.Minute {
		return nil, errors.New("one-time bypass TTL must be positive and no more than 15 minutes")
	}
	return &Gate{policy: policy, key: append([]byte(nil), authorizationKey...)}, nil
}

func (gate *Gate) Evaluate(request *antiflockv1.SecureActionRequest, snapshot *antiflockv1.ProtectionSnapshot, now time.Time) (*antiflockv1.SecureActionDecision, error) {
	if gate == nil || request == nil || snapshot == nil {
		return nil, errors.New("action request and protection snapshot are required")
	}
	if request.Id == "" || request.OperationId == "" || request.ApplicationId == "" || request.NodeId == "" || request.ActionType == "" || request.DataClass == "" || len(request.Destinations) == 0 {
		return nil, errors.New("action request contains empty required fields")
	}
	if request.NodeId != snapshot.NodeId || snapshot.PolicyRevision == 0 || snapshot.EvaluatedAt == nil || snapshot.ValidUntil == nil || snapshot.EvaluatedAt.CheckValid() != nil || snapshot.ValidUntil.CheckValid() != nil {
		return nil, errors.New("protection snapshot is not valid for the action node")
	}
	if !containsOrUnrestricted(gate.policy.ApplicationIDs, request.ApplicationId) || !containsOrUnrestricted(gate.policy.DataClasses, request.DataClass) {
		return decision(request, snapshot, antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_BLOCK, []string{"AF-ACTION-OUTSIDE-POLICY"}, now, time.Time{}), nil
	}
	for _, destination := range request.Destinations {
		if !containsOrUnrestricted(gate.policy.AllowedDestinations, destination) {
			return decision(request, snapshot, antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_BLOCK, []string{"AF-DESTINATION-OUTSIDE-POLICY"}, now, time.Time{}), nil
		}
	}
	deadline := now.Add(30 * time.Second)
	if request.Deadline != nil {
		if err := request.Deadline.CheckValid(); err != nil {
			return nil, errors.New("action deadline is invalid")
		}
		deadline = request.Deadline.AsTime().UTC()
	}
	if !deadline.After(now) {
		return decision(request, snapshot, antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_BLOCK, []string{"AF-ACTION-DEADLINE-EXPIRED"}, now, time.Time{}), nil
	}
	if snapshot.State == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED && snapshot.ValidUntil.AsTime().After(now) {
		return decision(request, snapshot, antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_ALLOW, reasonCodes(snapshot), now, time.Time{}), nil
	}
	expiresAt := deadline
	if maximum := now.Add(2 * time.Minute); expiresAt.After(maximum) {
		expiresAt = maximum
	}
	reasons := reasonCodes(snapshot)
	if len(reasons) == 0 {
		reasons = []string{"AF-PROTECTION-NOT-VERIFIED"}
	}
	return decision(request, snapshot, antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_HOLD, reasons, now, expiresAt), nil
}

func (gate *Gate) AuthorizeOnce(
	request *antiflockv1.SecureActionRequest,
	prior *antiflockv1.SecureActionDecision,
	authorizedDestinations []string,
	expiresAt, now time.Time,
	explicitConsent bool,
) (*antiflockv1.SecureActionDecision, error) {
	if gate == nil || request == nil || prior == nil || prior.Protection == nil {
		return nil, errors.New("action request and prior decision are required")
	}
	if !gate.policy.AllowOneTimeBypass || !explicitConsent {
		return nil, errors.New("an enabled policy and explicit operator consent are required")
	}
	if prior.ActionId != request.Id || !slices.Contains([]antiflockv1.SecureActionDecisionType{
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_HOLD,
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_BLOCK,
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_REQUIRE_CONSENT,
	}, prior.Decision) {
		return nil, errors.New("prior action decision is not eligible for one-time consent")
	}
	if !sameStrings(request.Destinations, authorizedDestinations) {
		return nil, errors.New("authorized destinations do not exactly match the action scope")
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(gate.policy.OneTimeBypassTTL)) {
		return nil, errors.New("one-time authorization expiry is outside policy")
	}
	result := decision(request, prior.Protection, antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_ALLOW_ONCE, []string{"AF-USER-AUTHORIZED-ONCE"}, now, expiresAt)
	result.Authorization = gate.authorization(request, expiresAt)
	return result, nil
}

func decision(request *antiflockv1.SecureActionRequest, snapshot *antiflockv1.ProtectionSnapshot, kind antiflockv1.SecureActionDecisionType, reasons []string, now, expiresAt time.Time) *antiflockv1.SecureActionDecision {
	status := map[antiflockv1.SecureActionDecisionType]antiflockv1.SecureActionStatus{
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_ALLOW:           antiflockv1.SecureActionStatus_SECURE_ACTION_STATUS_ALLOWED,
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_HOLD:            antiflockv1.SecureActionStatus_SECURE_ACTION_STATUS_HELD,
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_BLOCK:           antiflockv1.SecureActionStatus_SECURE_ACTION_STATUS_BLOCKED,
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_REQUIRE_CONSENT: antiflockv1.SecureActionStatus_SECURE_ACTION_STATUS_HELD,
		antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_ALLOW_ONCE:      antiflockv1.SecureActionStatus_SECURE_ACTION_STATUS_BYPASSED,
	}[kind]
	result := &antiflockv1.SecureActionDecision{
		ActionId: request.Id, Decision: kind, Status: status, Protection: snapshot,
		ReasonCodes: append([]string(nil), reasons...),
	}
	if !expiresAt.IsZero() {
		result.ExpiresAt = timestamppb.New(expiresAt.UTC())
	}
	if kind != antiflockv1.SecureActionDecisionType_SECURE_ACTION_DECISION_TYPE_ALLOW {
		result.UserMessage = "Protection is not currently verified for this action."
		result.RecommendedResponse = "Restore and verify the protected path, or use an explicitly scoped one-time authorization if policy permits."
	}
	_ = now
	return result
}

func (gate *Gate) authorization(request *antiflockv1.SecureActionRequest, expiresAt time.Time) string {
	destinations := append([]string(nil), request.Destinations...)
	sort.Strings(destinations)
	payload, _ := json.Marshal(struct {
		ActionID      string   `json:"actionId"`
		ApplicationID string   `json:"applicationId"`
		NodeID        string   `json:"nodeId"`
		OperationID   string   `json:"operationId"`
		Destinations  []string `json:"destinations"`
		ExpiresAt     string   `json:"expiresAt"`
		Uses          int      `json:"uses"`
	}{request.Id, request.ApplicationId, request.NodeId, request.OperationId, destinations, expiresAt.UTC().Format(time.RFC3339Nano), 1})
	mac := hmac.New(sha256.New, gate.key)
	mac.Write(payload)
	return "af_grant_v1." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func containsOrUnrestricted(values []string, wanted string) bool {
	return len(values) == 0 || slices.Contains(values, wanted)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func reasonCodes(snapshot *antiflockv1.ProtectionSnapshot) []string {
	result := make([]string, 0, len(snapshot.Reasons))
	for _, reason := range snapshot.Reasons {
		if reason != nil && reason.ReasonCode != "" {
			result = append(result, reason.ReasonCode)
		}
	}
	sort.Strings(result)
	return result
}
