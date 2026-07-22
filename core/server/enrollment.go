package server

import (
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (server *Server) handleCreateEnrollmentToken(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.CreateEnrollmentTokenRequest
	if err := decodeProtoJSON(response, request, &input, 32<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", "Enrollment token request is invalid.", input.GetOperationId(), false)
		return
	}
	if !bounded(input.GetOperationId(), 128) || input.GetAllowedNodeType() == antiflockv1.NodeType_NODE_TYPE_UNSPECIFIED || len(input.GetAllowedTags()) > 32 {
		writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", "Enrollment operation, node type, and tags are invalid.", input.GetOperationId(), false)
		return
	}
	now := server.clock().UTC()
	if input.GetExpiresAt() != nil {
		requested := input.GetExpiresAt().AsTime()
		expected := now.Add(server.config.Identity.EnrollmentTokenTTL)
		if !requested.After(now) || requested.After(expected.Add(2*time.Second)) || requested.Before(expected.Add(-2*time.Second)) {
			writeAPIError(response, http.StatusBadRequest, "INVALID_EXPIRY", "Enrollment token expiry must match the configured short-lived TTL.", input.GetOperationId(), false)
			return
		}
	}
	actor := principalFromContext(request.Context())
	token, err := server.enrollment.CreateScopedToken(request.Context(), actor.ID, input.GetOperationId(), enrollment.TokenScope{
		AllowedNodeType: input.GetAllowedNodeType(), ApprovedTags: append([]string(nil), input.GetAllowedTags()...),
	})
	if err != nil {
		server.writeDomainError(response, statusForEnrollmentError(err), err, input.GetOperationId())
		return
	}
	result := &antiflockv1.CreateEnrollmentTokenResponse{
		Token: &antiflockv1.EnrollmentTokenDescriptor{
			Id: token.ID, CreatedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(token.ExpiresAt),
			CreatedByPrincipalId: actor.ID, AllowedNodeType: token.Scope.AllowedNodeType,
			AllowedTags: append([]string(nil), token.Scope.ApprovedTags...), Status: antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		},
		TokenValue: token.TokenValue,
	}
	writeProtoJSON(response, http.StatusCreated, result)
}

func (server *Server) handleEnrollNode(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.EnrollNodeRequest
	if err := decodeProtoJSON(response, request, &input, 256<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_ENROLLMENT", "Enrollment request is invalid.", "", false)
		return
	}
	enrollmentRequest, err := server.enrollment.Enroll(request.Context(), &input)
	if err != nil {
		server.writeDomainError(response, statusForEnrollmentError(err), err, input.GetRequestId())
		return
	}
	result := &antiflockv1.EnrollNodeResponse{Enrollment: enrollmentRequest, AgentEndpoint: server.config.Server.PublicBaseURL}
	if enrollmentRequest.GetStatus() == antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		node, getErr := server.database.GetNode(request.Context(), enrollmentRequest.GetProposedNodeId())
		if getErr != nil {
			server.writeDomainError(response, http.StatusInternalServerError, getErr, input.GetRequestId())
			return
		}
		wireNode, certificateDER, convertErr := enrolledNodeToProto(node, server.deploymentID)
		if convertErr != nil {
			server.writeDomainError(response, http.StatusInternalServerError, convertErr, input.GetRequestId())
			return
		}
		result.Node, result.NodeCertificateChainDer = wireNode, certificateDER
	}
	writeProtoJSON(response, http.StatusAccepted, result)
}

func (server *Server) handleApproveEnrollment(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.ApproveEnrollmentRequest
	if err := decodeProtoJSON(response, request, &input, 32<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", "Enrollment approval is invalid.", input.GetOperationId(), false)
		return
	}
	if input.GetEnrollmentId() != request.PathValue("id") {
		writeAPIError(response, http.StatusBadRequest, "RESOURCE_MISMATCH", "Enrollment id does not match the route.", input.GetOperationId(), false)
		return
	}
	actor := principalFromContext(request.Context())
	node, err := server.enrollment.Approve(request.Context(), actor.ID, &input)
	if err != nil {
		server.writeDomainError(response, statusForEnrollmentError(err), err, input.GetOperationId())
		return
	}
	wireNode, certificateDER, err := enrolledNodeToProto(node, server.deploymentID)
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, input.GetOperationId())
		return
	}
	writeProtoJSON(response, http.StatusOK, &antiflockv1.ApproveEnrollmentResponse{
		Node: wireNode, NodeCertificateChainDer: certificateDER, AgentEndpoint: server.config.Server.PublicBaseURL,
	})
}

func (server *Server) handleDenyEnrollment(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.DenyEnrollmentRequest
	if err := decodeProtoJSON(response, request, &input, 16<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", "Enrollment denial is invalid.", input.GetOperationId(), false)
		return
	}
	if input.GetEnrollmentId() != request.PathValue("id") {
		writeAPIError(response, http.StatusBadRequest, "RESOURCE_MISMATCH", "Enrollment id does not match the route.", input.GetOperationId(), false)
		return
	}
	actor := principalFromContext(request.Context())
	enrollmentRequest, err := server.enrollment.Deny(request.Context(), actor.ID, &input)
	if err != nil {
		server.writeDomainError(response, statusForEnrollmentError(err), err, input.GetOperationId())
		return
	}
	writeProtoJSON(response, http.StatusOK, &antiflockv1.DenyEnrollmentResponse{Enrollment: enrollmentRequest})
}

type updateNodeMetadataRequest struct {
	DisplayName string   `json:"displayName"`
	Tags        []string `json:"tags"`
	OperationID string   `json:"operationId"`
}

type nodeStatusRequest struct {
	OperationID string `json:"operationId"`
	ReasonCode  string `json:"reasonCode"`
}

func (server *Server) handleUpdateNodeMetadata(response http.ResponseWriter, request *http.Request) {
	var input updateNodeMetadataRequest
	if err := decodeJSON(response, request, &input, 16<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", safeDecodeMessage(err), "", false)
		return
	}
	nodeID := request.PathValue("id")
	if !bounded(nodeID, 128) || !bounded(input.OperationID, 128) {
		writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", "Node and operation ids are required.", input.OperationID, false)
		return
	}
	actor := principalFromContext(request.Context())
	if err := server.enrollment.UpdateMetadataWithOperation(request.Context(), actor.ID, nodeID, input.DisplayName, input.Tags, input.OperationID); err != nil {
		server.writeDomainError(response, statusForNodeMutationError(err), err, input.OperationID)
		return
	}
	server.writeNodeMutationResponse(response, request, nodeID, input.OperationID)
}

func (server *Server) handleNodeStatus(target model.NodeStatus) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		var input nodeStatusRequest
		if err := decodeJSON(response, request, &input, 8<<10); err != nil {
			writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", safeDecodeMessage(err), "", false)
			return
		}
		nodeID := request.PathValue("id")
		if !bounded(nodeID, 128) || !bounded(input.OperationID, 128) || !validReasonCode(input.ReasonCode) {
			writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", "Node status change requires canonical node, operation, and reason identifiers.", input.OperationID, false)
			return
		}
		current, err := server.database.GetNode(request.Context(), nodeID)
		if err != nil {
			server.writeDomainError(response, statusForNodeMutationError(err), err, input.OperationID)
			return
		}
		validTransition := (target == model.NodeSuspended && current.Status == model.NodeActive) ||
			(target == model.NodeActive && current.Status == model.NodeSuspended) ||
			(target == model.NodeRevoked && (current.Status == model.NodeActive || current.Status == model.NodeSuspended))
		if !validTransition {
			writeAPIError(response, http.StatusConflict, "INVALID_NODE_TRANSITION", "The requested node status transition is not allowed.", input.OperationID, false)
			return
		}
		actor := principalFromContext(request.Context())
		if err := server.enrollment.SetStatusWithReason(request.Context(), actor.ID, nodeID, target, input.OperationID, input.ReasonCode); err != nil {
			server.writeDomainError(response, statusForNodeMutationError(err), err, input.OperationID)
			return
		}
		server.writeNodeMutationResponse(response, request, nodeID, input.OperationID)
	}
}

func (server *Server) writeNodeMutationResponse(response http.ResponseWriter, request *http.Request, nodeID, operationID string) {
	node, err := server.database.GetNode(request.Context(), nodeID)
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, operationID)
		return
	}
	wireNode, _, err := enrolledNodeToProto(node, server.deploymentID)
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, operationID)
		return
	}
	writeProtoJSON(response, http.StatusOK, &antiflockv1.UpdateNodeResponse{Node: wireNode})
}

func statusForNodeMutationError(err error) int {
	switch {
	case errors.Is(err, storage.ErrNodeNotFound):
		return http.StatusNotFound
	case errors.Is(err, storage.ErrNodeRevoked), errors.Is(err, storage.ErrOperationConflict):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

func decodeProtoJSON(response http.ResponseWriter, request *http.Request, message proto.Message, maximum int64) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	if encoding := request.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return errors.New("content encoding is unsupported")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximum)
	content, err := io.ReadAll(request.Body)
	if err != nil {
		return err
	}
	return (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, message)
}

func writeProtoJSON(response http.ResponseWriter, status int, message proto.Message) {
	content, err := (protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: false}).Marshal(message)
	if err != nil {
		writeAPIError(response, http.StatusInternalServerError, "INTERNAL", "Core could not encode its response.", "", true)
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_, _ = response.Write(append(content, '\n'))
}

func enrolledNodeToProto(node model.Node, deploymentID string) (*antiflockv1.Node, []byte, error) {
	nodeType, ok := antiflockv1.NodeType_value[node.Type]
	if !ok {
		return nil, nil, errors.New("stored node type is invalid")
	}
	var capabilities antiflockv1.CapabilityManifest
	if err := protojson.Unmarshal(node.Capabilities, &capabilities); err != nil {
		return nil, nil, errors.New("stored node capabilities are invalid")
	}
	block, _ := pem.Decode([]byte(node.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("stored node certificate is invalid")
	}
	status := antiflockv1.NodeStatus_NODE_STATUS_ACTIVE
	if node.Status == model.NodeSuspended {
		status = antiflockv1.NodeStatus_NODE_STATUS_SUSPENDED
	} else if node.Status == model.NodeRevoked {
		status = antiflockv1.NodeStatus_NODE_STATUS_REVOKED
	}
	labels := make(map[string]string, len(node.Tags))
	for _, tag := range node.Tags {
		labels[tag] = "true"
	}
	return &antiflockv1.Node{
		Metadata:     &antiflockv1.ResourceMetadata{Id: node.ID, Revision: node.LastPolicyRevision, Labels: labels},
		DeploymentId: deploymentID, Type: antiflockv1.NodeType(nodeType), Status: status,
		DisplayName: node.Name, Platform: node.Platform, PlatformVersion: node.PlatformVersion,
		Credential: &antiflockv1.CredentialMetadata{
			Id: node.ID + ":credential", SubjectId: node.ID, KeyId: node.ID,
			KeyAlgorithm: "ED25519", PublicKey: append([]byte(nil), node.PublicKey...),
			Status: antiflockv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE, IssuedAt: timestamppb.New(node.EnrolledAt),
		},
		Capabilities: &capabilities, EnrolledAt: timestamppb.New(node.EnrolledAt), LastPolicyRevision: node.LastPolicyRevision,
	}, block.Bytes, nil
}

func statusForEnrollmentError(err error) int {
	switch {
	case errors.Is(err, storage.ErrEnrollmentTokenInvalid):
		return http.StatusUnauthorized
	case errors.Is(err, storage.ErrEnrollmentTokenExpired), errors.Is(err, storage.ErrEnrollmentRequestExpired):
		return http.StatusGone
	case errors.Is(err, storage.ErrEnrollmentTokenUsed), errors.Is(err, storage.ErrEnrollmentRequestDecided), errors.Is(err, storage.ErrOperationConflict), errors.Is(err, storage.ErrNodeIdentityUsed):
		return http.StatusConflict
	case errors.Is(err, storage.ErrEnrollmentRequestNotFound), errors.Is(err, storage.ErrNodeNotFound):
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}
