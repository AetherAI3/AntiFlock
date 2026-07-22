package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/identity"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/id"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	enrollmentTokenPrefix = "af_enroll_v1."
	enrollmentTokenDomain = "AntiFlock-Enrollment-Token-v1"
	enrollmentProofDomain = "AntiFlock-Enrollment-PoP-v1"
	maximumEnrollmentWire = 256 * 1024
	maximumTokenTTL       = 15 * time.Minute
)

type Service struct {
	database  *storage.DB
	authority *identity.Authority
	audit     *audit.Service
	tokenTTL  time.Duration
	clock     func() time.Time
}

type Token struct {
	ID         string     `json:"id"`
	TokenValue string     `json:"tokenValue"`
	Scope      TokenScope `json:"scope"`
	ExpiresAt  time.Time  `json:"expiresAt"`
}

type TokenScope struct {
	AllowedNodeType antiflockv1.NodeType `json:"allowedNodeType"`
	ApprovedTags    []string             `json:"approvedTags"`
}

func New(database *storage.DB, authority *identity.Authority, auditService *audit.Service, tokenTTL time.Duration) *Service {
	return &Service{
		database: database, authority: authority, audit: auditService, tokenTTL: tokenTTL,
		clock: func() time.Time { return time.Now().UTC() },
	}
}

func (service *Service) CreateToken(ctx context.Context, actorID string) (Token, error) {
	return service.CreateScopedToken(ctx, actorID, id.New("operation"), TokenScope{AllowedNodeType: antiflockv1.NodeType_NODE_TYPE_AGENT})
}

func (service *Service) CreateScopedToken(ctx context.Context, actorID, operationID string, scope TokenScope) (Token, error) {
	if service == nil || service.database == nil || service.authority == nil || service.audit == nil {
		return Token{}, errors.New("enrollment service dependencies are required")
	}
	if service.tokenTTL <= 0 || service.tokenTTL > maximumTokenTTL {
		return Token{}, errors.New("enrollment token TTL must be positive and no more than 15 minutes")
	}
	if strings.TrimSpace(actorID) == "" || strings.TrimSpace(operationID) == "" {
		return Token{}, errors.New("enrollment actor and operation id are required")
	}
	if err := scope.Validate(); err != nil {
		return Token{}, err
	}
	rawToken, err := service.authority.DeriveEnrollmentToken(actorID, operationID)
	if err != nil {
		return Token{}, err
	}
	tokenValue := enrollmentTokenPrefix + base64.RawURLEncoding.EncodeToString(rawToken)
	digest := tokenDigest(rawToken)
	if existing, lookupErr := service.database.GetEnrollmentTokenByOperation(ctx, operationID); lookupErr == nil {
		return resolveTokenOperation(existing, actorID, scope, tokenValue, digest)
	} else if !errors.Is(lookupErr, storage.ErrEnrollmentTokenInvalid) {
		return Token{}, lookupErr
	}
	now := service.clock()
	token := Token{ID: id.New("enroll"), TokenValue: tokenValue, Scope: scope, ExpiresAt: now.Add(service.tokenTTL)}
	scopeJSON, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(&antiflockv1.EnrollmentTokenDescriptor{
		Id: token.ID, CreatedAt: timeToProto(now), ExpiresAt: timeToProto(token.ExpiresAt),
		CreatedByPrincipalId: actorID, AllowedNodeType: scope.AllowedNodeType, AllowedTags: scope.ApprovedTags,
		Status: antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
	})
	if err != nil {
		return Token{}, fmt.Errorf("encode enrollment token scope: %w", err)
	}
	record := storage.EnrollmentTokenRecord{
		ID: token.ID, Hash: digest, ScopeJSON: scopeJSON, CreatedByPrincipalID: actorID,
		OperationID: operationID, CreatedAt: now, ExpiresAt: token.ExpiresAt,
	}
	if _, err := service.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: actorID, Action: "enrollment.token_created",
		ResourceType: "enrollment_token", ResourceID: token.ID, Outcome: "success",
		Details: map[string]any{"expiresAt": token.ExpiresAt, "allowedNodeType": scope.AllowedNodeType.String(), "approvedTags": scope.ApprovedTags, "operationId": operationID},
	}, service.database.CreateEnrollmentTokenMutation(record)); err != nil {
		if errors.Is(err, storage.ErrOperationConflict) {
			existing, lookupErr := service.database.GetEnrollmentTokenByOperation(ctx, operationID)
			if lookupErr != nil {
				return Token{}, lookupErr
			}
			return resolveTokenOperation(existing, actorID, scope, tokenValue, digest)
		}
		return Token{}, err
	}
	return token, nil
}

func resolveTokenOperation(record storage.EnrollmentTokenRecord, actorID string, scope TokenScope, tokenValue string, digest []byte) (Token, error) {
	var descriptor antiflockv1.EnrollmentTokenDescriptor
	if err := protojson.Unmarshal(record.ScopeJSON, &descriptor); err != nil {
		return Token{}, fmt.Errorf("decode enrollment token operation: %w", err)
	}
	if record.CreatedByPrincipalID != actorID || descriptor.AllowedNodeType != scope.AllowedNodeType ||
		!slices.Equal(descriptor.AllowedTags, scope.ApprovedTags) || subtle.ConstantTimeCompare(record.Hash, digest) != 1 {
		return Token{}, storage.ErrOperationConflict
	}
	return Token{ID: record.ID, TokenValue: tokenValue, Scope: scope, ExpiresAt: record.ExpiresAt}, nil
}

func (service *Service) Enroll(ctx context.Context, request *antiflockv1.EnrollNodeRequest) (*antiflockv1.EnrollmentRequest, error) {
	if service == nil || service.database == nil || service.authority == nil || service.audit == nil {
		return nil, errors.New("enrollment service dependencies are required")
	}
	now := service.clock()
	if err := validateRequest(request, now); err != nil {
		return nil, err
	}
	rawToken, err := parseToken(request.TokenValue)
	if err != nil {
		return nil, err
	}
	tokenHash := tokenDigest(rawToken)
	record, err := service.database.GetEnrollmentToken(ctx, tokenHash, now)
	if err != nil {
		return nil, err
	}
	var descriptor antiflockv1.EnrollmentTokenDescriptor
	if err := protojson.Unmarshal(record.ScopeJSON, &descriptor); err != nil {
		return nil, fmt.Errorf("decode enrollment token scope: %w", err)
	}
	if descriptor.AllowedNodeType != request.NodeType {
		return nil, fmt.Errorf("node type %q is outside enrollment token scope", request.NodeType.String())
	}
	if err := validateRequestedNodeID(
		request.GetRequestedNodeId(),
		service.authority.Deployment.DeploymentID,
		service.authority.Deployment.OperatorID,
	); err != nil {
		return nil, err
	}
	proofMessage, err := ProofMessage(request)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(request.PublicKey), proofMessage, request.ProofOfPossession) {
		return nil, errors.New("enrollment proof of possession is invalid")
	}
	if record.ConsumedAt != nil {
		replay, replayErr := service.database.ResolveEnrollmentRequestReplay(ctx, tokenHash, request.RequestId, proofMessage)
		if replayErr != nil {
			return nil, replayErr
		}
		return enrollmentRequestToProto(replay)
	}
	if err := validateCSR(request); err != nil {
		return nil, err
	}
	if err := validateCapabilities(request.Capabilities, now); err != nil {
		return nil, err
	}
	capabilities, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(request.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("encode capability claims: %w", err)
	}
	proposedNodeID := request.GetRequestedNodeId()
	if proposedNodeID == "" {
		proposedNodeID = id.New("node")
	}
	enrollmentRecord := storage.EnrollmentRequestRecord{
		ID: id.New("enrollment_request"), TokenID: record.ID, RequestID: request.RequestId,
		RequestDigest: append([]byte(nil), proofMessage...), Status: "PENDING", ProposedNodeID: proposedNodeID,
		DisplayName: request.DisplayName, NodeType: request.NodeType.String(), Platform: request.Platform,
		PlatformVersion: request.PlatformVersion, PublicKey: append([]byte(nil), request.PublicKey...),
		CapabilitiesJSON: capabilities, AllowedTags: append([]string(nil), descriptor.AllowedTags...),
		RequestedAt: now, ExpiresAt: record.ExpiresAt,
	}
	if _, err := service.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "node", ActorID: enrollmentRecord.ProposedNodeID, Action: "enrollment.requested", ResourceType: "enrollment_request",
		ResourceID: enrollmentRecord.ID, Outcome: "pending_operator_approval",
		Details: map[string]any{"requestId": request.RequestId, "name": request.DisplayName, "nodeType": request.NodeType.String(), "platform": request.Platform, "proposedNodeId": enrollmentRecord.ProposedNodeID, "requestedNodeId": request.GetRequestedNodeId(), "capabilitiesVerification": "CLAIMED"},
	}, service.database.SubmitEnrollmentRequestMutation(tokenHash, now, enrollmentRecord)); err != nil {
		if errors.Is(err, storage.ErrEnrollmentTokenUsed) {
			replay, replayErr := service.database.ResolveEnrollmentRequestReplay(ctx, tokenHash, request.RequestId, proofMessage)
			if replayErr != nil {
				return nil, replayErr
			}
			return enrollmentRequestToProto(replay)
		}
		return nil, err
	}
	return enrollmentRequestToProto(enrollmentRecord)
}

func (service *Service) Approve(ctx context.Context, actorID string, request *antiflockv1.ApproveEnrollmentRequest) (model.Node, error) {
	if service == nil || service.database == nil || service.authority == nil || service.audit == nil {
		return model.Node{}, errors.New("enrollment service dependencies are required")
	}
	if request == nil || !validBoundedText(actorID, 128) || !validBoundedText(request.EnrollmentId, 128) ||
		!validBoundedText(request.OperationId, 128) || !validBoundedText(request.ReasonCode, 128) {
		return model.Node{}, errors.New("approval requires bounded actor, enrollment, operation, and reason identifiers")
	}
	if len(request.ApprovedTags) > 32 {
		return model.Node{}, errors.New("approval exceeds 32 tags")
	}
	record, err := service.database.GetEnrollmentRequest(ctx, request.EnrollmentId)
	if err != nil {
		return model.Node{}, err
	}
	if record.Status == "APPROVED" && record.DecisionOperationID == request.OperationId && record.NodeID != "" {
		if record.DecidedByPrincipalID != actorID || record.DecisionReasonCode != request.ReasonCode ||
			!slices.Equal(record.ApprovedTags, request.ApprovedTags) {
			return model.Node{}, storage.ErrOperationConflict
		}
		return service.database.GetNode(ctx, record.NodeID)
	}
	if record.Status != "PENDING" {
		return model.Node{}, storage.ErrEnrollmentRequestDecided
	}
	if !service.clock().Before(record.ExpiresAt) {
		return model.Node{}, storage.ErrEnrollmentRequestExpired
	}
	allowed := make(map[string]struct{}, len(record.AllowedTags))
	for _, tag := range record.AllowedTags {
		allowed[tag] = struct{}{}
	}
	seen := make(map[string]struct{}, len(request.ApprovedTags))
	for _, tag := range request.ApprovedTags {
		if !validBoundedText(tag, 64) {
			return model.Node{}, errors.New("approved tags must be bounded canonical values")
		}
		if _, ok := allowed[tag]; !ok {
			return model.Node{}, fmt.Errorf("approved tag %q is outside token scope", tag)
		}
		if _, duplicate := seen[tag]; duplicate {
			return model.Node{}, fmt.Errorf("approved tag %q is duplicated", tag)
		}
		seen[tag] = struct{}{}
	}
	now := service.clock()
	certificate, err := service.authority.IssueNodeCertificate(record.ProposedNodeID, ed25519.PublicKey(record.PublicKey), now)
	if err != nil {
		return model.Node{}, err
	}
	node := model.Node{
		ID: record.ProposedNodeID, Name: record.DisplayName, Type: record.NodeType, Platform: record.Platform,
		PlatformVersion: record.PlatformVersion, Status: model.NodeActive, Tags: append([]string(nil), request.ApprovedTags...),
		Capabilities: append([]byte(nil), record.CapabilitiesJSON...), CapabilitiesVerification: "CLAIMED",
		PublicKey: append([]byte(nil), record.PublicKey...), CertificatePEM: certificate, EnrolledAt: now,
	}
	if _, err := service.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: actorID, Action: "node.enrolled", ResourceType: "node",
		ResourceID: node.ID, Outcome: "success",
		Details: map[string]any{"enrollmentId": record.ID, "nodeId": node.ID, "operationId": request.OperationId, "reasonCode": request.ReasonCode, "approvedTags": request.ApprovedTags},
	}, service.database.ApproveEnrollmentRequestMutation(
		record.ID, actorID, request.OperationId, request.ReasonCode, request.ApprovedTags, now, node,
	)); err != nil {
		return model.Node{}, err
	}
	return node, nil
}

func (service *Service) Deny(ctx context.Context, actorID string, request *antiflockv1.DenyEnrollmentRequest) (*antiflockv1.EnrollmentRequest, error) {
	if service == nil || service.database == nil || service.audit == nil {
		return nil, errors.New("enrollment service dependencies are required")
	}
	if request == nil || !validBoundedText(actorID, 128) || !validBoundedText(request.EnrollmentId, 128) ||
		!validBoundedText(request.OperationId, 128) || !validBoundedText(request.ReasonCode, 128) {
		return nil, errors.New("denial requires bounded actor, enrollment, operation, and reason identifiers")
	}
	record, err := service.database.GetEnrollmentRequest(ctx, request.EnrollmentId)
	if err != nil {
		return nil, err
	}
	if record.Status == "DENIED" && record.DecisionOperationID == request.OperationId {
		if record.DecidedByPrincipalID != actorID || record.DecisionReasonCode != request.ReasonCode {
			return nil, storage.ErrOperationConflict
		}
		return enrollmentRequestToProto(record)
	}
	if record.Status != "PENDING" {
		return nil, storage.ErrEnrollmentRequestDecided
	}
	now := service.clock()
	if _, err := service.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: actorID, Action: "enrollment.denied", ResourceType: "enrollment_request",
		ResourceID: record.ID, Outcome: "denied",
		Details: map[string]any{"operationId": request.OperationId, "reasonCode": request.ReasonCode},
	}, service.database.DenyEnrollmentRequestMutation(
		record.ID, actorID, request.OperationId, request.ReasonCode, now,
	)); err != nil {
		return nil, err
	}
	return enrollmentRequestToProto(storage.EnrollmentRequestRecord{
		ID: record.ID, TokenID: record.TokenID, RequestID: record.RequestID, RequestDigest: record.RequestDigest,
		Status: "DENIED", ProposedNodeID: record.ProposedNodeID, DisplayName: record.DisplayName, NodeType: record.NodeType,
		Platform: record.Platform, PlatformVersion: record.PlatformVersion, PublicKey: record.PublicKey,
		CapabilitiesJSON: record.CapabilitiesJSON, AllowedTags: record.AllowedTags, RequestedAt: record.RequestedAt,
		ExpiresAt: record.ExpiresAt, DecisionReasonCode: request.ReasonCode, DecisionOperationID: request.OperationId,
		DecidedByPrincipalID: actorID, DecidedAt: &now,
	})
}

func enrollmentRequestToProto(record storage.EnrollmentRequestRecord) (*antiflockv1.EnrollmentRequest, error) {
	var capabilities antiflockv1.CapabilityManifest
	if err := protojson.Unmarshal(record.CapabilitiesJSON, &capabilities); err != nil {
		return nil, fmt.Errorf("decode enrollment capabilities: %w", err)
	}
	status, ok := antiflockv1.EnrollmentStatus_value["ENROLLMENT_STATUS_"+record.Status]
	if !ok {
		return nil, fmt.Errorf("unknown enrollment status %q", record.Status)
	}
	nodeType, ok := antiflockv1.NodeType_value[record.NodeType]
	if !ok {
		return nil, fmt.Errorf("unknown enrollment node type %q", record.NodeType)
	}
	return &antiflockv1.EnrollmentRequest{
		Id: record.ID, TokenId: record.TokenID, Status: antiflockv1.EnrollmentStatus(status),
		ProposedNodeId: record.ProposedNodeID, DisplayName: record.DisplayName,
		NodeType: antiflockv1.NodeType(nodeType), PublicKey: append([]byte(nil), record.PublicKey...),
		Capabilities: &capabilities, RequestedAt: timeToProto(record.RequestedAt), ExpiresAt: timeToProto(record.ExpiresAt),
		DecisionReasonCode: record.DecisionReasonCode,
	}, nil
}

func (service *Service) SetStatus(ctx context.Context, actorID, nodeID string, status model.NodeStatus) error {
	return service.SetStatusWithReason(ctx, actorID, nodeID, status, "", "")
}

func (service *Service) SetStatusWithReason(ctx context.Context, actorID, nodeID string, status model.NodeStatus, operationID, reasonCode string) error {
	if !validBoundedText(actorID, 128) || !validBoundedText(nodeID, 128) ||
		(status != model.NodeActive && status != model.NodeSuspended && status != model.NodeRevoked) {
		return errors.New("invalid node status")
	}
	if (operationID == "") != (reasonCode == "") || (operationID != "" && (!validBoundedText(operationID, 128) || !validBoundedText(reasonCode, 128))) {
		return errors.New("node status operation and reason identifiers must be provided together")
	}
	now := service.clock()
	_, err := service.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: actorID, Action: "node.status_changed", ResourceType: "node",
		ResourceID: nodeID, Outcome: "success", Details: map[string]any{"status": status, "operationId": operationID, "reasonCode": reasonCode},
	}, service.database.SetNodeStatusMutation(nodeID, status, now))
	return err
}

func (service *Service) UpdateMetadata(ctx context.Context, actorID, nodeID, name string, tags []string) error {
	return service.UpdateMetadataWithOperation(ctx, actorID, nodeID, name, tags, "")
}

func (service *Service) UpdateMetadataWithOperation(ctx context.Context, actorID, nodeID, name string, tags []string, operationID string) error {
	if !validBoundedText(actorID, 128) || !validBoundedText(nodeID, 128) || !validBoundedText(name, 128) {
		return errors.New("actor id, node id, and node name are required bounded values")
	}
	if operationID != "" && !validBoundedText(operationID, 128) {
		return errors.New("node metadata operation id is invalid")
	}
	if err := (TokenScope{AllowedNodeType: antiflockv1.NodeType_NODE_TYPE_AGENT, ApprovedTags: tags}).Validate(); err != nil {
		return err
	}
	_, err := service.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: actorID, Action: "node.metadata_updated", ResourceType: "node",
		ResourceID: nodeID, Outcome: "success", Details: map[string]any{"name": name, "tags": tags, "operationId": operationID},
	}, service.database.UpdateNodeMetadataMutation(nodeID, name, tags))
	return err
}

func (scope TokenScope) Validate() error {
	if _, known := antiflockv1.NodeType_name[int32(scope.AllowedNodeType)]; !known || scope.AllowedNodeType == antiflockv1.NodeType_NODE_TYPE_UNSPECIFIED {
		return errors.New("enrollment scope requires an allowed node type")
	}
	if len(scope.ApprovedTags) > 32 {
		return errors.New("enrollment scope exceeds 32 approved tags")
	}
	seen := make(map[string]struct{}, len(scope.ApprovedTags))
	totalBytes := 0
	for _, tag := range scope.ApprovedTags {
		if !validBoundedText(tag, 64) || strings.ContainsAny(tag, " \t\r\n") {
			return errors.New("approved enrollment tags must be bounded non-whitespace values")
		}
		totalBytes += len(tag)
		if totalBytes > 2048 {
			return errors.New("approved enrollment tags exceed 2048 bytes")
		}
		if _, exists := seen[tag]; exists {
			return fmt.Errorf("approved enrollment tag %q is duplicated", tag)
		}
		seen[tag] = struct{}{}
	}
	return nil
}

// ProofMessage returns the exact digest signed by the enrolling endpoint. It
// uses only fields present in the canonical EnrollNodeRequest.
func ProofMessage(request *antiflockv1.EnrollNodeRequest) ([]byte, error) {
	if request == nil {
		return nil, errors.New("enrollment request is required")
	}
	clone := proto.Clone(request).(*antiflockv1.EnrollNodeRequest)
	clone.ProofOfPossession = nil
	if err := rejectUnknown(clone.ProtoReflect()); err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("encode enrollment proof transcript: %w", err)
	}
	preimage := appendLengthPrefixed(nil, []byte(enrollmentProofDomain))
	preimage = appendLengthPrefixed(preimage, encoded)
	digest := sha256.Sum256(preimage)
	return digest[:], nil
}

func validateRequest(request *antiflockv1.EnrollNodeRequest, now time.Time) error {
	if request == nil {
		return errors.New("enrollment request is required")
	}
	if proto.Size(request) > maximumEnrollmentWire {
		return errors.New("enrollment request exceeds the size limit")
	}
	if err := model.RejectUnknownFields(request); err != nil {
		return fmt.Errorf("enrollment request: %w", err)
	}
	if _, err := parseToken(request.TokenValue); err != nil {
		return err
	}
	if !validBoundedText(request.RequestId, 128) || !validBoundedText(request.DisplayName, 128) {
		return errors.New("request id and display name are required bounded UTF-8 values")
	}
	if _, known := antiflockv1.NodeType_name[int32(request.NodeType)]; !known || request.NodeType == antiflockv1.NodeType_NODE_TYPE_UNSPECIFIED {
		return errors.New("node type is required")
	}
	if !validBoundedText(request.Platform, 32) || !validBoundedText(request.PlatformVersion, 128) {
		return errors.New("platform and platform version are required bounded UTF-8 values")
	}
	if !slices.Contains([]string{"linux", "android", "windows", "darwin", "ios", "router"}, request.Platform) {
		return fmt.Errorf("unsupported node platform %q", request.Platform)
	}
	if request.KeyAlgorithm != "ed25519" {
		return errors.New("key_algorithm must be exact lowercase ed25519")
	}
	if len(request.PublicKey) != ed25519.PublicKeySize || len(request.ProofOfPossession) != ed25519.SignatureSize {
		return errors.New("enrollment requires a 32-byte Ed25519 public key and 64-byte proof")
	}
	if request.Capabilities == nil {
		return errors.New("capability manifest is required")
	}
	return validateCapabilities(request.Capabilities, now)
}

func validateRequestedNodeID(nodeID, deploymentID, operatorID string) error {
	if nodeID == "" {
		return nil
	}
	if len(nodeID) < 8 || len(nodeID) > 128 || nodeID == deploymentID || nodeID == operatorID {
		return errors.New("requested_node_id is not an available canonical node identity")
	}
	previousDelimiter := false
	for index, character := range []byte(nodeID) {
		delimiter := character == '_' || character == '-'
		if (character >= 'a' && character <= 'z') || (index > 0 && character >= '0' && character <= '9') ||
			(index > 0 && delimiter && !previousDelimiter) {
			previousDelimiter = delimiter
			continue
		}
		return errors.New("requested_node_id must use lowercase ASCII letters, digits, underscores, or hyphens and begin with a letter")
	}
	if previousDelimiter {
		return errors.New("requested_node_id must not end with a delimiter")
	}
	reserved := map[string]struct{}{
		"all": {}, "core": {}, "local": {}, "operator": {}, "system": {}, "unknown": {}, "unavailable": {},
		"node_all": {}, "node_core": {}, "node_local": {}, "node_operator": {}, "node_system": {}, "node_unknown": {}, "node_unavailable": {},
	}
	if _, exists := reserved[nodeID]; exists {
		return errors.New("requested_node_id is reserved")
	}
	return nil
}

func validateCapabilities(manifest *antiflockv1.CapabilityManifest, now time.Time) error {
	if manifest == nil {
		return errors.New("capability manifest is required")
	}
	if len(manifest.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("capability manifest contains unknown protobuf fields")
	}
	if manifest.NodeId != "" || manifest.Signature != nil {
		return errors.New("initial enrollment capabilities must have empty node_id and signature and are recorded as CLAIMED")
	}
	if manifest.Revision == 0 || len(manifest.Capabilities) == 0 {
		return errors.New("capability manifest requires a positive revision and at least one capability")
	}
	issuedAt, err := protoTime(manifest.IssuedAt, "capability issued_at")
	if err != nil || issuedAt.After(now.Add(5*time.Minute)) {
		return errors.New("capability issued_at is invalid or exceeds allowed clock skew")
	}
	expiresAt, err := protoTime(manifest.ExpiresAt, "capability expires_at")
	if err != nil || !expiresAt.After(now) || !expiresAt.After(issuedAt) {
		return errors.New("capability expires_at must be after issuance and current time")
	}
	seen := make(map[string]struct{}, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		if capability == nil || !validBoundedText(capability.Key, 128) || !strings.Contains(capability.Key, ".") || capability.Domain == antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_UNSPECIFIED || capability.SupportLevel == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSPECIFIED || len(capability.Operations) == 0 {
			return errors.New("capability entries require a namespaced key, domain, operation, and support level")
		}
		if _, exists := seen[capability.Key]; exists {
			return fmt.Errorf("capability key %q is duplicated", capability.Key)
		}
		seen[capability.Key] = struct{}{}
		for _, operation := range capability.Operations {
			if operation == antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_UNSPECIFIED {
				return fmt.Errorf("capability %q contains an unspecified operation", capability.Key)
			}
		}
		if capability.ObservedAt != nil {
			observedAt, err := protoTime(capability.ObservedAt, "capability observed_at")
			if err != nil || observedAt.After(now.Add(5*time.Minute)) {
				return fmt.Errorf("capability %q observed_at is invalid", capability.Key)
			}
		}
	}
	return nil
}

func validateCSR(request *antiflockv1.EnrollNodeRequest) error {
	if len(request.CertificateSigningRequestDer) == 0 {
		return nil
	}
	csr, err := x509.ParseCertificateRequest(request.CertificateSigningRequestDer)
	if err != nil || csr.CheckSignature() != nil {
		return errors.New("certificate signing request is invalid")
	}
	publicKey, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || subtle.ConstantTimeCompare(publicKey, request.PublicKey) != 1 {
		return errors.New("certificate signing request key does not match public_key")
	}
	if len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || len(csr.EmailAddresses) != 0 || len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 {
		return errors.New("caller-controlled CSR names and extensions are not accepted")
	}
	return nil
}

func parseToken(value string) ([]byte, error) {
	if !strings.HasPrefix(value, enrollmentTokenPrefix) {
		return nil, errors.New("enrollment token has an invalid version prefix")
	}
	encoded := strings.TrimPrefix(value, enrollmentTokenPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 64 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("enrollment token must contain canonical unpadded base64url for 64 bytes")
	}
	return raw, nil
}

func tokenDigest(raw []byte) []byte {
	payload := make([]byte, 0, len(enrollmentTokenDomain)+1+len(raw))
	payload = append(payload, enrollmentTokenDomain...)
	payload = append(payload, 0)
	payload = append(payload, raw...)
	digest := sha256.Sum256(payload)
	return digest[:]
}

func appendLengthPrefixed(destination, value []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(value)))
	destination = append(destination, length...)
	return append(destination, value...)
}

func validBoundedText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return strings.TrimSpace(value) == value
}

func protoTime(value *timestamppb.Timestamp, field string) (time.Time, error) {
	if value == nil {
		return time.Time{}, fmt.Errorf("%s is required", field)
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", field, err)
	}
	return value.AsTime().UTC(), nil
}

func timeToProto(value time.Time) *timestamppb.Timestamp {
	return timestamppb.New(value.UTC())
}

func rejectUnknown(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return errors.New("enrollment proof transcript contains unknown protobuf fields")
	}
	var nestedErr error
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if descriptor.IsMap() && descriptor.MapValue().Kind() == protoreflect.MessageKind {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				nestedErr = rejectUnknown(item.Message())
				return nestedErr == nil
			})
		} else if descriptor.IsList() && descriptor.Kind() == protoreflect.MessageKind {
			for index, list := 0, value.List(); index < list.Len() && nestedErr == nil; index++ {
				nestedErr = rejectUnknown(list.Get(index).Message())
			}
		} else if descriptor.Kind() == protoreflect.MessageKind {
			nestedErr = rejectUnknown(value.Message())
		}
		return nestedErr == nil
	})
	return nestedErr
}
