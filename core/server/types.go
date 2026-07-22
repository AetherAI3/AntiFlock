package server

import (
	"context"
	"time"

	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

const (
	defaultMaxBodyBytes = int64(1 << 20)
	defaultRequestLimit = 128
)

type database interface {
	Health(context.Context) error
	VerifyEventRetentionTombstones(context.Context) error
	ListNodes(context.Context) ([]model.Node, error)
	GetNode(context.Context, string) (model.Node, error)
	GetEvent(context.Context, string) (model.EventEnvelope, error)
	ListLatestEventsForNode(context.Context, string, []string) ([]model.EventEnvelope, error)
	GetNodeEventState(context.Context, string) (storage.NodeEventState, error)
	GetSecureAction(context.Context, string) (storage.SecureActionRecord, error)
	GetSecureActionByRequestID(context.Context, string) (storage.SecureActionRecord, error)
	GetSecureActionByOperationID(context.Context, string) (storage.SecureActionRecord, error)
	ListSecureActions(context.Context, string, int) ([]storage.SecureActionRecord, error)
	CountSecureActionsByDecision(context.Context, string) (int, error)
	CreateSecureActionMutation(storage.SecureActionRecord) storage.AuditedMutation
	UpdateSecureActionMutation(storage.SecureActionRecord) storage.AuditedMutation
	GetSecureActionAuditEvent(context.Context, string) (storage.SecureActionAuditEventRecord, error)
	AppendSecureActionLifecycleMutation(string, string, string, []byte, time.Time, time.Time) storage.AuditedMutation
}

type eventBus interface {
	Append(context.Context, model.EventEnvelope) (bool, error)
	ReplayFrom(context.Context, storage.ProjectionCursor, int) ([]model.EventEnvelope, error)
	Subscribe(int) (<-chan model.EventEnvelope, func())
}

type secureActionRequest struct {
	ID            string   `json:"id"`
	ApplicationID string   `json:"applicationId"`
	NodeID        string   `json:"nodeId"`
	ActionType    string   `json:"actionType"`
	Destinations  []string `json:"destinations"`
	DataClass     string   `json:"dataClass"`
	Sensitivity   string   `json:"sensitivity"`
	Deadline      string   `json:"deadline"`
	OperationID   string   `json:"operationId"`
}

type evaluateRequest struct {
	Action secureActionRequest `json:"action"`
}

type authorizeRequest struct {
	ActionID               string   `json:"actionId"`
	OperationID            string   `json:"operationId"`
	AuthorizedDestinations []string `json:"authorizedDestinations"`
	ExpiresAt              string   `json:"expiresAt"`
	ConsentReasonCode      string   `json:"consentReasonCode"`
}

type waitRequest struct {
	ActionID        string `json:"actionId"`
	AfterObservedAt string `json:"afterObservedAt"`
	Deadline        string `json:"deadline"`
}

type auditEventRequest struct {
	EventID        string         `json:"eventId"`
	Lifecycle      string         `json:"lifecycle"`
	OccurredAt     string         `json:"occurredAt"`
	ActionID       string         `json:"actionId"`
	RequestID      string         `json:"requestId"`
	Decision       string         `json:"decision"`
	TraceID        string         `json:"traceId"`
	PolicyRevision uint64         `json:"policyRevision"`
	ReasonCodes    []string       `json:"reasonCodes"`
	Details        map[string]any `json:"details,omitempty"`
}

type protectionView struct {
	State              string   `json:"state"`
	ObservedAt         string   `json:"observedAt"`
	ValidUntil         string   `json:"validUntil,omitempty"`
	NetworkTrust       string   `json:"networkTrust"`
	MeshConnected      *bool    `json:"meshConnected"`
	ApprovedExitActive *bool    `json:"approvedExitActive"`
	DNSProtected       *bool    `json:"dnsProtected"`
	RouteProtected     *bool    `json:"routeProtected"`
	ReasonCodes        []string `json:"reasonCodes"`
	PolicyRevision     uint64   `json:"policyRevision"`
	NodeID             string   `json:"nodeId"`
	EvidenceClass      string   `json:"evidenceClass"`
	Confidence         float32  `json:"confidence"`
}

type auditMetadata struct {
	TraceID        string `json:"traceId"`
	DecisionID     string `json:"decisionId"`
	PolicyRevision uint64 `json:"policyRevision"`
	EvaluatedAt    string `json:"evaluatedAt"`
	AgentID        string `json:"agentId"`
	EvidenceClass  string `json:"evidenceClass"`
}

type decisionView struct {
	Decision      string             `json:"decision"`
	ActionID      string             `json:"actionId"`
	Protection    protectionView     `json:"protection"`
	ReasonCodes   []string           `json:"reasonCodes"`
	ExpiresAt     string             `json:"expiresAt,omitempty"`
	UserMessage   string             `json:"userMessage,omitempty"`
	Authorization *authorizationView `json:"authorization,omitempty"`
	Hold          *holdView          `json:"hold,omitempty"`
	Consent       *consentView       `json:"consent,omitempty"`
	Audit         auditMetadata      `json:"audit"`
}

type holdView struct {
	ReleaseWhen string `json:"releaseWhen"`
	ExpiresAt   string `json:"expiresAt"`
}

type consentView struct {
	Prompt    string             `json:"prompt"`
	ExpiresAt string             `json:"expiresAt"`
	Scope     authorizationScope `json:"scope"`
}

type authorizationScope struct {
	ID            string   `json:"id"`
	ApplicationID string   `json:"applicationId"`
	NodeID        string   `json:"nodeId"`
	OperationID   string   `json:"operationId"`
	ActionType    string   `json:"actionType"`
	Destinations  []string `json:"destinations"`
}

type authorizationView struct {
	GrantID       string             `json:"grantId"`
	Token         string             `json:"token"`
	Scope         authorizationScope `json:"scope"`
	IssuedAt      string             `json:"issuedAt"`
	ExpiresAt     string             `json:"expiresAt"`
	RemainingUses int                `json:"remainingUses"`
}

type secureActionListItem struct {
	ActionID             string                       `json:"actionId"`
	OperationID          string                       `json:"operationId"`
	ApplicationID        string                       `json:"applicationId"`
	NodeID               string                       `json:"nodeId"`
	Decision             string                       `json:"decision"`
	ReasonCodes          []string                     `json:"reasonCodes"`
	Scope                secureActionScopeView        `json:"scope"`
	Protection           protectionView               `json:"protection"`
	ExpiresAt            string                       `json:"expiresAt,omitempty"`
	CreatedAt            string                       `json:"createdAt"`
	UpdatedAt            string                       `json:"updatedAt"`
	OneTimeAuthorization *oneTimeAuthorizationOptions `json:"oneTimeAuthorization,omitempty"`
}

type secureActionScopeView struct {
	ActionType   string   `json:"actionType"`
	Destinations []string `json:"destinations"`
	DataClass    string   `json:"dataClass"`
	Sensitivity  string   `json:"sensitivity"`
	Deadline     string   `json:"deadline"`
}

type oneTimeAuthorizationOptions struct {
	Enabled           bool   `json:"enabled"`
	MaximumExpiresAt  string `json:"maximumExpiresAt"`
	ConsentReasonCode string `json:"consentReasonCode"`
}

type postureReport struct {
	NodeID               string   `json:"nodeId"`
	State                string   `json:"state"`
	ObservedAt           string   `json:"observedAt"`
	ValidUntil           string   `json:"validUntil"`
	NetworkTrust         string   `json:"networkTrust"`
	MeshConnected        *bool    `json:"meshConnected"`
	ApprovedExitActive   *bool    `json:"approvedExitActive"`
	DNSProtected         *bool    `json:"dnsProtected"`
	RouteProtected       *bool    `json:"routeProtected"`
	ReasonCodes          []string `json:"reasonCodes"`
	PolicyRevision       uint64   `json:"policyRevision"`
	VerificationEventIDs []string `json:"verificationEventIds,omitempty"`
	EvidenceClass        string   `json:"-"`
	Confidence           float32  `json:"-"`
}

func (report postureReport) view() protectionView {
	return protectionView{
		State: report.State, ObservedAt: report.ObservedAt, ValidUntil: report.ValidUntil,
		NetworkTrust: report.NetworkTrust, MeshConnected: report.MeshConnected,
		ApprovedExitActive: report.ApprovedExitActive, DNSProtected: report.DNSProtected,
		RouteProtected: report.RouteProtected,
		ReasonCodes:    append([]string(nil), report.ReasonCodes...), PolicyRevision: report.PolicyRevision,
		NodeID: report.NodeID, EvidenceClass: report.EvidenceClass, Confidence: report.Confidence,
	}
}

type replayCursor struct {
	Version       uint32 `json:"version"`
	IngestOrdinal uint64 `json:"ingestOrdinal"`
	EventID       string `json:"eventId"`
}
