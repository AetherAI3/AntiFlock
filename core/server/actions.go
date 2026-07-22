package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/config"
	"github.com/DBarr3/AntiFlock/core/findings"
	postureengine "github.com/DBarr3/AntiFlock/core/posture"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var validActionAuditLifecycles = []string{
	"SDK_DECISION_RECEIVED",
	"SDK_HOLD_WAIT_STARTED",
	"SDK_PROTECTION_RESTORED",
	"SDK_CONSENT_DECLINED",
	"SDK_ACTION_EXECUTION_STARTED",
	"SDK_ACTION_EXECUTION_SUCCEEDED",
	"SDK_ACTION_EXECUTION_FAILED",
}

var validActionAuditDecisions = []string{"ALLOW", "HOLD", "BLOCK", "REQUIRE_CONSENT", "ALLOW_ONCE"}

type actionGate struct {
	database         database
	audit            *audit.Service
	deploymentID     string
	protection       config.ProtectionConfig
	postureEngine    *postureengine.Engine
	findings         *findings.Service
	authorizationKey []byte
	clock            func() time.Time

	mu       sync.RWMutex
	postures map[string]postureReport
	updated  chan struct{}
}

func newActionGate(
	database database,
	auditService *audit.Service,
	deploymentID string,
	protection config.ProtectionConfig,
	authorizationKey []byte,
	postureEngine *postureengine.Engine,
	findingService *findings.Service,
	clock func() time.Time,
) (*actionGate, error) {
	if database == nil || auditService == nil || postureEngine == nil || findingService == nil || deploymentID == "" {
		return nil, errors.New("action gate database, audit, posture, findings, and deployment id are required")
	}
	if len(authorizationKey) < 32 {
		return nil, errors.New("one-time authorization key must contain at least 32 bytes")
	}
	return &actionGate{
		database: database, audit: auditService, deploymentID: deploymentID,
		protection: protection, postureEngine: postureEngine, findings: findingService,
		authorizationKey: append([]byte(nil), authorizationKey...), clock: clock,
		postures: make(map[string]postureReport), updated: make(chan struct{}),
	}, nil
}

func (gate *actionGate) list(ctx context.Context, decision string, limit int) ([]secureActionListItem, error) {
	records, err := gate.database.ListSecureActions(ctx, decision, limit)
	if err != nil {
		return nil, err
	}
	now := gate.clock().UTC()
	result := make([]secureActionListItem, 0, len(records))
	for _, record := range records {
		var request secureActionRequest
		var committed decisionView
		if err := json.Unmarshal(record.RequestJSON, &request); err != nil {
			return nil, errors.New("stored secure action request is invalid")
		}
		if err := json.Unmarshal(record.DecisionJSON, &committed); err != nil {
			return nil, errors.New("stored secure action decision is invalid")
		}
		item := secureActionListItem{
			ActionID: record.ID, OperationID: record.OperationID, ApplicationID: record.ApplicationID,
			NodeID: request.NodeID, Decision: record.Decision,
			ReasonCodes: append([]string(nil), committed.ReasonCodes...), Protection: committed.Protection,
			Scope: secureActionScopeView{
				ActionType: request.ActionType, Destinations: append([]string(nil), request.Destinations...),
				DataClass: request.DataClass, Sensitivity: request.Sensitivity, Deadline: request.Deadline,
			},
			ExpiresAt: committed.ExpiresAt, CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339Nano),
			UpdatedAt: record.UpdatedAt.UTC().Format(time.RFC3339Nano),
		}
		if gate.protection.AllowOneTimeBypass && slices.Contains([]string{"HOLD", "REQUIRE_CONSENT", "BLOCK"}, record.Decision) {
			maximum := now.Add(gate.protection.OneTimeBypassTTL)
			if deadline, parseErr := time.Parse(time.RFC3339Nano, request.Deadline); parseErr == nil && deadline.Before(maximum) {
				maximum = deadline
			}
			item.OneTimeAuthorization = &oneTimeAuthorizationOptions{
				Enabled: maximum.After(now), MaximumExpiresAt: maximum.UTC().Format(time.RFC3339Nano),
				ConsentReasonCode: "USER_EXPLICIT",
			}
		}
		result = append(result, item)
	}
	return result, nil
}

func (server *Server) handleListActions(response http.ResponseWriter, request *http.Request) {
	limit := 100
	if value := request.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 200 {
			writeAPIError(response, http.StatusBadRequest, "INVALID_LIMIT", "Action limit must be between 1 and 200.", "", false)
			return
		}
		limit = parsed
	}
	decision := strings.ToUpper(strings.TrimSpace(request.URL.Query().Get("decision")))
	if decision != "" && !slices.Contains(validActionAuditDecisions, decision) {
		writeAPIError(response, http.StatusBadRequest, "INVALID_DECISION", "Action decision filter is unsupported.", "", false)
		return
	}
	actions, err := server.actions.list(request.Context(), decision, limit)
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"actions": actions})
}

func (gate *actionGate) evaluate(ctx context.Context, request secureActionRequest) (decisionView, int, error) {
	if !principalFromContext(ctx).allowsAction(request) {
		return decisionView{}, http.StatusForbidden, errors.New("credential scope does not match the secure action")
	}
	deadline, err := gate.validateAction(request)
	if err != nil {
		return decisionView{}, http.StatusBadRequest, err
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return decisionView{}, http.StatusInternalServerError, err
	}
	existing, err := gate.database.GetSecureActionByOperationID(ctx, request.OperationID)
	if err == nil {
		if !existing.RequestMatches(canonical) {
			return decisionView{}, http.StatusConflict, storage.ErrSecureActionConflict
		}
		decision, decodeErr := decodeStoredDecision(existing, request, gate.authorizationKey)
		if decodeErr != nil {
			return decisionView{}, http.StatusInternalServerError, decodeErr
		}
		// A held action is a durable identity, not a frozen verdict. Once a newer
		// protected snapshot is available, re-evaluation releases that same action.
		if decision.Decision == "HOLD" {
			now := gate.clock().UTC()
			posture := gate.posture(request.NodeID, now)
			priorObserved, _ := time.Parse(time.RFC3339Nano, decision.Protection.ObservedAt)
			currentObserved, _ := time.Parse(time.RFC3339Nano, posture.ObservedAt)
			if posture.State == "PROTECTED" && currentObserved.After(priorObserved) {
				released := gate.decisionBase(request, posture, "ALLOW", posture.ReasonCodes, now)
				encoded, marshalErr := json.Marshal(released)
				if marshalErr != nil {
					return decisionView{}, http.StatusInternalServerError, marshalErr
				}
				existing.Decision, existing.DecisionJSON, existing.UpdatedAt, existing.ReleasedAt = "ALLOW", encoded, now, &now
				actor := principalFromContext(ctx)
				_, updateErr := gate.audit.AppendWithMutation(ctx, audit.AppendRequest{
					ActorType: "PRINCIPAL", ActorID: actor.ID, Action: "secure_action.release",
					ResourceType: "secure_action", ResourceID: request.ID, Outcome: "ALLOW",
					Details: map[string]any{"operationId": request.OperationID, "policyRevision": posture.PolicyRevision},
				}, gate.database.UpdateSecureActionMutation(existing))
				if updateErr != nil {
					return decisionView{}, http.StatusInternalServerError, updateErr
				}
				return released, http.StatusOK, nil
			}
		}
		return decision, http.StatusOK, nil
	}
	if !errors.Is(err, storage.ErrSecureActionNotFound) {
		return decisionView{}, http.StatusInternalServerError, err
	}

	now := gate.clock().UTC()
	posture := gate.posture(request.NodeID, now)
	decision := gate.decide(request, posture, deadline, now)
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		return decisionView{}, http.StatusInternalServerError, err
	}
	record := storage.SecureActionRecord{
		ID: request.ID, RequestID: request.ID, ApplicationID: request.ApplicationID, OperationID: request.OperationID,
		Decision: decision.Decision, RequestJSON: canonical, DecisionJSON: decisionJSON,
		CreatedAt: now, UpdatedAt: now,
	}
	actor := principalFromContext(ctx)
	_, err = gate.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "PRINCIPAL", ActorID: actor.ID, Action: "secure_action.evaluate",
		ResourceType: "secure_action", ResourceID: request.ID, Outcome: decision.Decision,
		Details: map[string]any{"operationId": request.OperationID, "reasonCodes": decision.ReasonCodes},
	}, gate.database.CreateSecureActionMutation(record))
	if err != nil {
		// Another identical retry may have won the unique request-id race.
		replayed, replayErr := gate.database.GetSecureActionByOperationID(ctx, request.OperationID)
		if replayErr == nil && replayed.RequestMatches(canonical) {
			stored, decodeErr := decodeStoredDecision(replayed, request, gate.authorizationKey)
			return stored, http.StatusOK, decodeErr
		}
		return decisionView{}, http.StatusInternalServerError, err
	}
	return decision, http.StatusCreated, nil
}

func (gate *actionGate) authorize(ctx context.Context, actionID string, request authorizeRequest) (decisionView, int, error) {
	if request.ActionID != actionID || !bounded(actionID, 128) || !bounded(request.OperationID, 128) {
		return decisionView{}, http.StatusBadRequest, errors.New("action and operation ids are required and must match the route")
	}
	if request.ConsentReasonCode != "USER_EXPLICIT" {
		return decisionView{}, http.StatusBadRequest, errors.New("explicit user consent is required")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil {
		return decisionView{}, http.StatusBadRequest, errors.New("authorization expiry must be an RFC3339 timestamp")
	}
	now := gate.clock().UTC()
	maximumExpiry := now.Add(gate.protection.OneTimeBypassTTL)
	if !expiresAt.After(now) || expiresAt.After(maximumExpiry) {
		return decisionView{}, http.StatusBadRequest, errors.New("authorization expiry exceeds the one-time bypass window")
	}
	if !gate.protection.AllowOneTimeBypass {
		return decisionView{}, http.StatusForbidden, errors.New("one-time bypass is disabled by policy")
	}
	record, err := gate.database.GetSecureAction(ctx, actionID)
	if errors.Is(err, storage.ErrSecureActionNotFound) {
		return decisionView{}, http.StatusNotFound, err
	}
	if err != nil {
		return decisionView{}, http.StatusInternalServerError, err
	}
	var original secureActionRequest
	if err := json.Unmarshal(record.RequestJSON, &original); err != nil {
		return decisionView{}, http.StatusInternalServerError, errors.New("stored secure action request is invalid")
	}
	actionDeadline, err := time.Parse(time.RFC3339Nano, original.Deadline)
	if err != nil {
		return decisionView{}, http.StatusInternalServerError, errors.New("stored secure action deadline is invalid")
	}
	if expiresAt.After(actionDeadline) {
		return decisionView{}, http.StatusBadRequest, errors.New("authorization expiry exceeds the secure action deadline")
	}
	if !principalFromContext(ctx).allowsAction(original) {
		return decisionView{}, http.StatusForbidden, errors.New("credential scope does not match the secure action")
	}
	if original.OperationID != request.OperationID || !sameStrings(original.Destinations, request.AuthorizedDestinations) {
		return decisionView{}, http.StatusConflict, errors.New("authorization scope does not match the held action")
	}
	if record.Decision == "ALLOW_ONCE" {
		decision, decodeErr := decodeStoredDecision(record, original, gate.authorizationKey)
		if decodeErr != nil {
			return decisionView{}, http.StatusInternalServerError, decodeErr
		}
		if decision.ExpiresAt != expiresAt.UTC().Format(time.RFC3339Nano) {
			return decisionView{}, http.StatusConflict, errors.New("authorization retry changed the expiry")
		}
		return decision, http.StatusOK, nil
	}
	if record.Decision != "HOLD" && record.Decision != "REQUIRE_CONSENT" && record.Decision != "BLOCK" {
		return decisionView{}, http.StatusConflict, errors.New("the action is not eligible for a one-time authorization")
	}
	posture := gate.posture(original.NodeID, now)
	decision := gate.decisionBase(original, posture, "ALLOW_ONCE", []string{"USER_AUTHORIZED_ONCE"}, now)
	decision.ExpiresAt = expiresAt.UTC().Format(time.RFC3339Nano)
	decision.Authorization = gate.authorization(original, expiresAt, now)
	persisted := decision
	if persisted.Authorization != nil {
		copy := *persisted.Authorization
		copy.Token = ""
		persisted.Authorization = &copy
	}
	decisionJSON, err := json.Marshal(persisted)
	if err != nil {
		return decisionView{}, http.StatusInternalServerError, err
	}
	record.Decision = decision.Decision
	record.DecisionJSON = decisionJSON
	record.UpdatedAt = now
	record.BypassExpiresAt = &expiresAt
	actor := principalFromContext(ctx)
	_, err = gate.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "PRINCIPAL", ActorID: actor.ID, Action: "secure_action.authorize_once",
		ResourceType: "secure_action", ResourceID: actionID, Outcome: "ALLOW_ONCE",
		Details: map[string]any{"operationId": request.OperationID, "expiresAt": decision.ExpiresAt},
	}, gate.database.UpdateSecureActionMutation(record))
	if err != nil {
		return decisionView{}, http.StatusInternalServerError, err
	}
	return decision, http.StatusOK, nil
}

func (gate *actionGate) appendLifecycleAudit(ctx context.Context, actionID string, request auditEventRequest) (int, error) {
	if request.ActionID != actionID || !bounded(request.EventID, 128) || !bounded(request.RequestID, 128) ||
		!bounded(request.TraceID, 128) || !slices.Contains(validActionAuditLifecycles, request.Lifecycle) ||
		!slices.Contains(validActionAuditDecisions, request.Decision) {
		return http.StatusBadRequest, errors.New("action audit event is invalid")
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, request.OccurredAt)
	now := gate.clock().UTC()
	if err != nil || occurredAt.After(now.Add(5*time.Minute)) {
		return http.StatusBadRequest, errors.New("action audit occurrence time must be RFC3339 and within the allowed clock skew")
	}
	if len(request.ReasonCodes) == 0 || len(request.ReasonCodes) > 32 || len(request.Details) > 32 {
		return http.StatusBadRequest, errors.New("action audit event exceeds metadata limits")
	}
	seenReasons := make(map[string]struct{}, len(request.ReasonCodes))
	for _, reason := range request.ReasonCodes {
		if !validReasonCode(reason) {
			return http.StatusBadRequest, errors.New("action audit reason code is invalid")
		}
		if _, duplicate := seenReasons[reason]; duplicate {
			return http.StatusBadRequest, errors.New("action audit reason codes must be unique")
		}
		seenReasons[reason] = struct{}{}
	}
	sort.Strings(request.ReasonCodes)
	request.OccurredAt = occurredAt.UTC().Format(time.RFC3339Nano)
	if request.Details == nil {
		request.Details = map[string]any{}
	}
	canonical, err := json.Marshal(request)
	if err != nil || len(canonical) > 32<<10 {
		return http.StatusBadRequest, errors.New("action audit metadata is invalid or too large")
	}
	digest := sha256.Sum256(canonical)
	if existing, err := gate.database.GetSecureActionAuditEvent(ctx, request.EventID); err == nil {
		if existing.ActionID != actionID || !bytes.Equal(existing.RequestDigest, digest[:]) {
			return http.StatusConflict, storage.ErrSecureActionAuditConflict
		}
		return http.StatusNoContent, nil
	} else if !errors.Is(err, storage.ErrSecureActionNotFound) {
		return http.StatusInternalServerError, err
	}
	record, err := gate.database.GetSecureAction(ctx, actionID)
	if errors.Is(err, storage.ErrSecureActionNotFound) {
		return http.StatusNotFound, err
	} else if err != nil {
		return http.StatusInternalServerError, err
	}
	var original secureActionRequest
	if err := json.Unmarshal(record.RequestJSON, &original); err != nil {
		return http.StatusInternalServerError, errors.New("stored secure action request is invalid")
	}
	if !principalFromContext(ctx).allowsAction(original) {
		return http.StatusForbidden, errors.New("credential scope does not match the secure action")
	}
	if request.RequestID != record.RequestID || request.TraceID != record.OperationID || request.Decision != record.Decision ||
		occurredAt.Before(record.CreatedAt.Add(-5*time.Minute)) {
		return http.StatusConflict, errors.New("action audit event does not match the committed action decision")
	}
	var committedDecision decisionView
	if err := json.Unmarshal(record.DecisionJSON, &committedDecision); err != nil {
		return http.StatusInternalServerError, errors.New("stored secure action decision is invalid")
	}
	if request.PolicyRevision != committedDecision.Audit.PolicyRevision {
		return http.StatusConflict, errors.New("action audit policy revision does not match the committed decision")
	}
	actor := principalFromContext(ctx)
	_, err = gate.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "APPLICATION", ActorID: actor.ID, Action: "secure_action." + strings.ToLower(request.Lifecycle),
		ResourceType: "secure_action", ResourceID: actionID, Outcome: request.Decision,
		Details: map[string]any{
			"eventId": request.EventID, "requestId": request.RequestID, "traceId": request.TraceID,
			"policyRevision": request.PolicyRevision, "reasonCodes": request.ReasonCodes, "metadata": request.Details,
		},
	}, gate.database.AppendSecureActionLifecycleMutation(
		request.EventID, actionID, request.Lifecycle, digest[:], occurredAt.UTC(), now,
	))
	if err != nil {
		if existing, replayErr := gate.database.GetSecureActionAuditEvent(ctx, request.EventID); replayErr == nil {
			if existing.ActionID == actionID && bytes.Equal(existing.RequestDigest, digest[:]) {
				return http.StatusNoContent, nil
			}
			return http.StatusConflict, storage.ErrSecureActionAuditConflict
		}
		if errors.Is(err, storage.ErrOneTimeGrantConsumed) {
			return http.StatusConflict, err
		}
		return http.StatusInternalServerError, err
	}
	return http.StatusNoContent, nil
}

func validReasonCode(value string) bool {
	if !bounded(value, 128) {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '_' || character == '-' || character == '.')) {
			continue
		}
		return false
	}
	return true
}

func (gate *actionGate) wait(ctx context.Context, actionID string, request waitRequest) (protectionView, bool, int, error) {
	if !bounded(actionID, 128) || (request.ActionID != "" && request.ActionID != actionID) {
		return protectionView{}, false, http.StatusBadRequest, errors.New("action id is required")
	}
	record, err := gate.database.GetSecureAction(ctx, actionID)
	if errors.Is(err, storage.ErrSecureActionNotFound) {
		return protectionView{}, false, http.StatusNotFound, err
	}
	if err != nil {
		return protectionView{}, false, http.StatusInternalServerError, err
	}
	var original secureActionRequest
	if err := json.Unmarshal(record.RequestJSON, &original); err != nil {
		return protectionView{}, false, http.StatusInternalServerError, err
	}
	if !principalFromContext(ctx).allowsAction(original) {
		return protectionView{}, false, http.StatusForbidden, errors.New("credential scope does not match the secure action")
	}
	after, err := time.Parse(time.RFC3339Nano, request.AfterObservedAt)
	if err != nil {
		return protectionView{}, false, http.StatusBadRequest, errors.New("afterObservedAt must be RFC3339")
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.Deadline)
	if err != nil {
		return protectionView{}, false, http.StatusBadRequest, errors.New("wait deadline must be RFC3339")
	}
	if maximum := gate.clock().UTC().Add(10 * time.Minute); deadline.After(maximum) {
		return protectionView{}, false, http.StatusBadRequest, errors.New("wait deadline exceeds ten minutes")
	}
	for {
		now := gate.clock().UTC()
		posture, update := gate.postureAndUpdate(original.NodeID, now)
		observed, _ := time.Parse(time.RFC3339Nano, posture.ObservedAt)
		if posture.State == "PROTECTED" && observed.After(after) {
			return posture, true, http.StatusOK, nil
		}
		if !deadline.After(now) {
			return posture, false, http.StatusOK, nil
		}
		timer := time.NewTimer(deadline.Sub(now))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return protectionView{}, false, 0, ctx.Err()
		case <-update:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			posture := gate.posture(original.NodeID, gate.clock().UTC())
			return posture, false, http.StatusOK, nil
		}
	}
}

func (gate *actionGate) reportPosture(ctx context.Context, report postureReport) error {
	now := gate.clock().UTC()
	if err := validatePostureReport(report, now, gate.protection.TelemetryStaleAfter); err != nil {
		return err
	}
	evidenceClass := antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED
	evidenceValidUntil := time.Time{}
	if report.State == "PROTECTED" {
		var err error
		evidenceValidUntil, err = gate.validateProtectedEvidence(ctx, report, now)
		if err != nil {
			return err
		}
		report.EvidenceClass = "VERIFIED"
		evidenceClass = antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED
	} else {
		report.EvidenceClass = "DETECTED"
	}
	snapshot, err := gate.postureEngine.Evaluate(postureengine.Input{
		DeploymentID: gate.deploymentID, NodeID: report.NodeID, PolicyID: "active-protection-profile",
		PolicyRevision: report.PolicyRevision, EvaluatedAt: mustParsePostureTime(report.ObservedAt),
		TelemetryAt: mustParsePostureTime(report.ObservedAt), NetworkTrust: report.NetworkTrust,
		RequireMeshOnUntrusted: gate.protection.RequireMeshOnUntrusted,
		MeshConnected:          postureFact(report.MeshConnected, evidenceClass, report.ObservedAt),
		ApprovedExitActive:     postureFact(report.ApprovedExitActive, evidenceClass, report.ObservedAt),
		DNSProtected:           postureFact(report.DNSProtected, evidenceClass, report.ObservedAt),
		RouteProtected:         postureFact(report.RouteProtected, evidenceClass, report.ObservedAt),
	})
	if err != nil {
		return err
	}
	derivedState := strings.TrimPrefix(snapshot.GetState().String(), "PROTECTION_STATE_")
	if (derivedState == "PROTECTED") != (report.State == "PROTECTED") {
		return errors.New("posture state is inconsistent with the reported control facts")
	}
	report.State = derivedState
	validUntil := snapshot.GetValidUntil().AsTime().UTC()
	reportedValidUntil := mustParsePostureTime(report.ValidUntil)
	if reportedValidUntil.Before(validUntil) {
		validUntil = reportedValidUntil
	}
	if !evidenceValidUntil.IsZero() && evidenceValidUntil.Before(validUntil) {
		validUntil = evidenceValidUntil
	}
	snapshot.ValidUntil = timestamppb.New(validUntil)
	report.ValidUntil = validUntil.Format(time.RFC3339Nano)
	report.Confidence = snapshot.GetConfidence()
	report.ReasonCodes = report.ReasonCodes[:0]
	for _, reason := range snapshot.GetReasons() {
		report.ReasonCodes = append(report.ReasonCodes, reason.GetReasonCode())
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	existing, exists := gate.postures[report.NodeID]
	if exists {
		existingTime, _ := time.Parse(time.RFC3339Nano, existing.ObservedAt)
		incomingTime, _ := time.Parse(time.RFC3339Nano, report.ObservedAt)
		if incomingTime.Before(existingTime) || (incomingTime.Equal(existingTime) && report.PolicyRevision < existing.PolicyRevision) {
			return errors.New("posture report regresses the current snapshot")
		}
	}
	actor := principalFromContext(ctx)
	if _, err := gate.audit.Append(ctx, audit.AppendRequest{
		ActorType: "NODE", ActorID: actor.ID, Action: "posture.report",
		ResourceType: "node", ResourceID: report.NodeID, Outcome: report.State,
		Details: map[string]any{
			"policyRevision": report.PolicyRevision, "reasonCodes": report.ReasonCodes,
			"verificationEventIds": report.VerificationEventIDs, "evidenceClass": report.EvidenceClass,
		},
	}); err != nil {
		return err
	}
	if _, err := gate.findings.ApplySnapshot(snapshot); err != nil {
		return err
	}
	gate.postures[report.NodeID] = report
	close(gate.updated)
	gate.updated = make(chan struct{})
	return nil
}

func (gate *actionGate) posture(nodeID string, now time.Time) protectionView {
	view, _ := gate.postureAndUpdate(nodeID, now)
	return view
}

func (gate *actionGate) allPostures(now time.Time) []protectionView {
	gate.mu.RLock()
	nodeIDs := make([]string, 0, len(gate.postures))
	for nodeID := range gate.postures {
		nodeIDs = append(nodeIDs, nodeID)
	}
	gate.mu.RUnlock()
	sort.Strings(nodeIDs)
	result := make([]protectionView, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		result = append(result, gate.posture(nodeID, now))
	}
	return result
}

func (gate *actionGate) postureAndUpdate(nodeID string, now time.Time) (protectionView, <-chan struct{}) {
	gate.mu.RLock()
	report, exists := gate.postures[nodeID]
	update := gate.updated
	gate.mu.RUnlock()
	if !exists {
		return unknownPosture(nodeID, now, "AF-POSTURE-UNAVAILABLE"), update
	}
	validUntil, err := time.Parse(time.RFC3339Nano, report.ValidUntil)
	observedAt, observedErr := time.Parse(time.RFC3339Nano, report.ObservedAt)
	if err != nil || observedErr != nil || !validUntil.After(now) || now.Sub(observedAt) > gate.protection.TelemetryStaleAfter {
		return unknownPosture(nodeID, now, "AF-TELEMETRY-STALE"), update
	}
	return report.view(), update
}

func unknownPosture(nodeID string, now time.Time, reason string) protectionView {
	return protectionView{
		State: "UNKNOWN", ObservedAt: now.UTC().Format(time.RFC3339Nano),
		ValidUntil: now.UTC().Format(time.RFC3339Nano), NetworkTrust: "UNKNOWN",
		ReasonCodes: []string{reason}, NodeID: nodeID, EvidenceClass: "UNKNOWN",
	}
}

func (gate *actionGate) decide(request secureActionRequest, posture protectionView, deadline, now time.Time) decisionView {
	if !deadline.After(now) {
		return gate.decisionBase(request, posture, "BLOCK", []string{"AF-ACTION-DEADLINE-EXPIRED"}, now)
	}
	if posture.State == "PROTECTED" {
		return gate.decisionBase(request, posture, "ALLOW", posture.ReasonCodes, now)
	}
	expiresAt := deadline
	if maximum := now.Add(2 * time.Minute); expiresAt.After(maximum) {
		expiresAt = maximum
	}
	decision := gate.decisionBase(request, posture, "HOLD", posture.ReasonCodes, now)
	decision.ExpiresAt = expiresAt.UTC().Format(time.RFC3339Nano)
	decision.Hold = &holdView{ReleaseWhen: "PROTECTION_RESTORED", ExpiresAt: decision.ExpiresAt}
	return decision
}

func (gate *actionGate) decisionBase(request secureActionRequest, posture protectionView, decision string, reasons []string, now time.Time) decisionView {
	if reasons == nil {
		reasons = []string{}
	}
	return decisionView{
		Decision: decision, ActionID: request.ID, Protection: posture,
		ReasonCodes: append([]string(nil), reasons...),
		Audit: auditMetadata{
			TraceID: request.OperationID, DecisionID: fmt.Sprintf("%s:%s:%s", request.OperationID, decision, request.ID),
			PolicyRevision: posture.PolicyRevision, EvaluatedAt: now.UTC().Format(time.RFC3339Nano),
			AgentID: request.NodeID, EvidenceClass: evidenceClassFor(posture),
		},
	}
}

func (gate *actionGate) validateAction(request secureActionRequest) (time.Time, error) {
	if !bounded(request.ID, 128) || !bounded(request.ApplicationID, 128) || !bounded(request.NodeID, 128) ||
		!bounded(request.ActionType, 128) || !bounded(request.DataClass, 128) || !bounded(request.OperationID, 128) {
		return time.Time{}, errors.New("secure action identifiers and type fields are required")
	}
	if len(request.Destinations) == 0 || len(request.Destinations) > 32 {
		return time.Time{}, errors.New("secure action requires between one and 32 destinations")
	}
	seenDestinations := make(map[string]struct{}, len(request.Destinations))
	for _, destination := range request.Destinations {
		if !bounded(destination, 512) {
			return time.Time{}, errors.New("secure action destination is invalid")
		}
		if _, exists := seenDestinations[destination]; exists {
			return time.Time{}, errors.New("secure action destinations must be unique")
		}
		seenDestinations[destination] = struct{}{}
	}
	if !slices.Contains([]string{
		"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED",
		"SENSITIVITY_PUBLIC", "SENSITIVITY_INTERNAL", "SENSITIVITY_OPERATOR_PRIVATE", "SENSITIVITY_RESTRICTED",
	}, request.Sensitivity) {
		return time.Time{}, errors.New("secure action sensitivity is invalid")
	}
	deadline := gate.clock().UTC().Add(30 * time.Second)
	if request.Deadline != "" {
		var err error
		deadline, err = time.Parse(time.RFC3339Nano, request.Deadline)
		if err != nil {
			return time.Time{}, errors.New("secure action deadline must be RFC3339")
		}
	}
	if deadline.After(gate.clock().UTC().Add(24 * time.Hour)) {
		return time.Time{}, errors.New("secure action deadline exceeds 24 hours")
	}
	return deadline.UTC(), nil
}

func validatePostureReport(report postureReport, now time.Time, staleAfter time.Duration) error {
	if !bounded(report.NodeID, 128) || !slices.Contains([]string{"PROTECTED", "DEGRADED", "SUSPICIOUS", "EXPOSED", "UNKNOWN", "UNAVAILABLE"}, report.State) ||
		!slices.Contains([]string{"TRUSTED", "UNTRUSTED", "UNKNOWN"}, report.NetworkTrust) {
		return errors.New("posture report contains an invalid node, state, or network trust")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, report.ObservedAt)
	if err != nil || observedAt.After(now.Add(5*time.Minute)) {
		return errors.New("posture observedAt is invalid")
	}
	if staleAfter <= 0 {
		return errors.New("posture telemetry freshness policy is invalid")
	}
	validUntil, err := time.Parse(time.RFC3339Nano, report.ValidUntil)
	if err != nil || !validUntil.After(observedAt) || validUntil.After(observedAt.Add(staleAfter)) {
		return errors.New("posture validUntil is invalid")
	}
	if report.State == "PROTECTED" && (report.MeshConnected == nil || !*report.MeshConnected || report.ApprovedExitActive == nil || !*report.ApprovedExitActive || report.DNSProtected == nil || !*report.DNSProtected) {
		return errors.New("protected posture requires verified mesh, exit, and DNS controls")
	}
	if report.State == "PROTECTED" && (report.RouteProtected == nil || !*report.RouteProtected) {
		return errors.New("protected posture requires a verified protected route")
	}
	if report.PolicyRevision == 0 {
		return errors.New("posture policy revision is required")
	}
	if len(report.ReasonCodes) > 32 {
		return errors.New("posture report has too many reason codes")
	}
	if len(report.VerificationEventIDs) > 8 {
		return errors.New("posture report has too many verification events")
	}
	return nil
}

func postureFact(value *bool, class antiflockv1.EvidenceClass, observedAt string) postureengine.Fact {
	if value == nil {
		return postureengine.Fact{}
	}
	return postureengine.Fact{
		Known: true, Value: *value, Classification: class, Confidence: 1,
		ObservedAt: mustParsePostureTime(observedAt),
	}
}

func mustParsePostureTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed.UTC()
}

func (gate *actionGate) validateProtectedEvidence(ctx context.Context, report postureReport, now time.Time) (time.Time, error) {
	if len(report.VerificationEventIDs) < 2 {
		return time.Time{}, errors.New("protected posture requires durable mesh and DNS verification events")
	}
	seen := make(map[string]struct{}, len(report.VerificationEventIDs))
	meshVerified, dnsVerified := false, false
	validUntil := now.Add(gate.protection.TelemetryStaleAfter)
	for _, eventID := range report.VerificationEventIDs {
		if !bounded(eventID, 128) {
			return time.Time{}, errors.New("posture verification event id is invalid")
		}
		if _, duplicate := seen[eventID]; duplicate {
			return time.Time{}, errors.New("posture verification event ids must be unique")
		}
		seen[eventID] = struct{}{}
		event, err := gate.database.GetEvent(ctx, eventID)
		if err != nil {
			return time.Time{}, errors.New("posture verification event is not durably available")
		}
		if event.DeploymentID != gate.deploymentID || event.NodeID != report.NodeID || event.Classification != model.EvidenceVerified ||
			now.Sub(event.ObservedAt) > gate.protection.TelemetryStaleAfter || event.ObservedAt.After(now.Add(5*time.Minute)) {
			return time.Time{}, errors.New("posture verification event is stale, unverified, or belongs to another node")
		}
		if err := model.ValidateEvidenceAt(event, now); err != nil {
			return time.Time{}, errors.New("posture verification event no longer has fresh verified evidence")
		}
		if eventFreshUntil := event.ObservedAt.Add(gate.protection.TelemetryStaleAfter); eventFreshUntil.Before(validUntil) {
			validUntil = eventFreshUntil
		}
		for _, evidence := range event.Evidence {
			if evidence.ExpiresAt != nil && evidence.ExpiresAt.Before(validUntil) {
				validUntil = evidence.ExpiresAt.UTC()
			}
		}
		switch event.Kind {
		case "mesh.path_changed", "mesh.exit_changed":
			var observation antiflockv1.MeshPathObservation
			if err := proto.Unmarshal(event.Payload, &observation); err != nil || !observation.GetTunnelHealthy() || !observation.GetApprovedExitActive() {
				return time.Time{}, errors.New("mesh posture verification event does not establish a healthy approved exit")
			}
			meshVerified = true
		case "network.dns_changed":
			var observation antiflockv1.DnsObservation
			if err := proto.Unmarshal(event.Payload, &observation); err != nil || !observation.GetPathVerified() {
				return time.Time{}, errors.New("DNS posture verification event does not establish a verified path")
			}
			dnsVerified = true
		default:
			return time.Time{}, errors.New("posture verification event kind is not an enforcement input")
		}
	}
	if !meshVerified || !dnsVerified {
		return time.Time{}, errors.New("protected posture requires verified mesh, approved exit, and DNS path evidence")
	}
	if !validUntil.After(now) {
		return time.Time{}, errors.New("posture verification evidence has expired")
	}
	return validUntil, nil
}

func decodeStoredDecision(record storage.SecureActionRecord, request secureActionRequest, key []byte) (decisionView, error) {
	var decision decisionView
	if err := json.Unmarshal(record.DecisionJSON, &decision); err != nil {
		return decisionView{}, errors.New("stored secure action decision is invalid")
	}
	if decision.Decision == "ALLOW_ONCE" && (decision.Authorization == nil || decision.Authorization.Token == "") {
		expiresAt, err := time.Parse(time.RFC3339Nano, decision.ExpiresAt)
		if err != nil {
			return decisionView{}, errors.New("stored authorization expiry is invalid")
		}
		issuedAt, parseErr := time.Parse(time.RFC3339Nano, decision.Audit.EvaluatedAt)
		if parseErr != nil {
			return decisionView{}, errors.New("stored authorization issue time is invalid")
		}
		decision.Authorization = makeAuthorization(key, request, expiresAt, issuedAt)
	}
	return decision, nil
}

func (gate *actionGate) authorization(request secureActionRequest, expiresAt, issuedAt time.Time) *authorizationView {
	return makeAuthorization(gate.authorizationKey, request, expiresAt, issuedAt)
}

func makeAuthorization(key []byte, request secureActionRequest, expiresAt, issuedAt time.Time) *authorizationView {
	destinations := append([]string(nil), request.Destinations...)
	sort.Strings(destinations)
	payload, _ := json.Marshal(map[string]any{
		"actionId": request.ID, "applicationId": request.ApplicationID, "nodeId": request.NodeID,
		"operationId": request.OperationID, "actionType": request.ActionType,
		"destinations": destinations, "expiresAt": expiresAt.UTC().Format(time.RFC3339Nano), "uses": 1,
	})
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	token := "af_grant_v1." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return &authorizationView{
		GrantID: request.ID + ":" + request.OperationID, Token: token,
		Scope: authorizationScope{
			ID: request.ID, ApplicationID: request.ApplicationID, NodeID: request.NodeID,
			OperationID: request.OperationID, ActionType: request.ActionType,
			Destinations: append([]string(nil), request.Destinations...),
		},
		IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), RemainingUses: 1,
	}
}

func evidenceClassFor(posture protectionView) string {
	if posture.EvidenceClass != "" {
		return posture.EvidenceClass
	}
	return "UNKNOWN"
}

func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
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
