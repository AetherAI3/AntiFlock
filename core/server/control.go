package server

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
	"github.com/DBarr3/AntiFlock/core/scrambler"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maximumControlRequestBytes = int64(512 << 10)

func (server *Server) handleValidatePolicy(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.ValidatePolicyRequest
	if err := decodeProtoJSON(response, request, &input, maximumControlRequestBytes); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_POLICY_REQUEST", "Policy validation input is not valid protobuf JSON.", "", false)
		return
	}
	violations := policy.Validate(input.GetProfile())
	writeProtoJSON(response, http.StatusOK, &antiflockv1.ValidatePolicyResponse{
		Valid: len(violations) == 0, Violations: violations,
	})
}

func (server *Server) handleCompilePolicy(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.CompilePolicyRequest
	if err := decodeProtoJSON(response, request, &input, maximumControlRequestBytes); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_POLICY_REQUEST", "Policy compilation input is not valid protobuf JSON.", "", false)
		return
	}
	if !bounded(input.GetOperationId(), 128) || len(input.GetNodeIds()) == 0 || len(input.GetNodeIds()) > 128 {
		writeAPIError(response, http.StatusBadRequest, "INVALID_POLICY_SCOPE", "Compilation requires an operation id and between one and 128 target nodes.", input.GetOperationId(), false)
		return
	}
	seen := make(map[string]struct{}, len(input.GetNodeIds()))
	for _, nodeID := range input.GetNodeIds() {
		if !bounded(nodeID, 128) {
			writeAPIError(response, http.StatusBadRequest, "INVALID_POLICY_SCOPE", "A target node id is invalid.", input.GetOperationId(), false)
			return
		}
		if _, duplicate := seen[nodeID]; duplicate {
			writeAPIError(response, http.StatusBadRequest, "INVALID_POLICY_SCOPE", "Target node ids must be unique.", input.GetOperationId(), false)
			return
		}
		seen[nodeID] = struct{}{}
	}
	violations := policy.Validate(input.GetProfile())
	if len(violations) != 0 {
		writeProtoJSON(response, http.StatusOK, &antiflockv1.CompilePolicyResponse{Violations: violations})
		return
	}

	plans := make([]*antiflockv1.Plan, 0, len(input.GetNodeIds()))
	for _, nodeID := range input.GetNodeIds() {
		node, err := server.database.GetNode(request.Context(), nodeID)
		if err != nil {
			if err == storage.ErrNodeNotFound {
				violations = append(violations, controlViolation("AF-NODE-NOT-FOUND", "nodeIds."+nodeID, "The target node is not enrolled."))
				continue
			}
			server.writeDomainError(response, http.StatusInternalServerError, err, input.GetOperationId())
			return
		}
		if node.Status != model.NodeActive {
			violations = append(violations, controlViolation("AF-NODE-INACTIVE", "nodeIds."+nodeID, "The target node is not active."))
			continue
		}
		var capabilities antiflockv1.CapabilityManifest
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(node.Capabilities, &capabilities); err != nil {
			violations = append(violations, controlViolation("AF-CAPABILITY-MANIFEST-INVALID", "nodeIds."+nodeID, "The target node capability manifest is invalid."))
			continue
		}
		if capabilities.GetNodeId() == "" {
			capabilities.NodeId = nodeID
		}
		if capabilities.GetNodeId() != nodeID {
			violations = append(violations, controlViolation("AF-CAPABILITY-NODE-MISMATCH", "nodeIds."+nodeID, "The capability manifest belongs to another node."))
			continue
		}
		if node.CapabilitiesVerification != "VERIFIED" && !input.GetDryRunOnly() {
			violations = append(violations, controlViolation("AF-CAPABILITY-UNVERIFIED", "nodeIds."+nodeID, "Only a dry-run may use capabilities that have not been verified."))
			continue
		}
		plan, nodeViolations, err := server.policy.Compile(input.GetProfile(), nodeID, node.LastPolicyRevision+1, &capabilities)
		if err != nil {
			server.writeDomainError(response, http.StatusBadRequest, err, input.GetOperationId())
			return
		}
		for _, violation := range nodeViolations {
			violation.Field = "nodeIds." + nodeID + "." + violation.GetField()
			violations = append(violations, violation)
		}
		if plan != nil {
			plans = append(plans, plan)
		}
	}
	writeProtoJSON(response, http.StatusOK, &antiflockv1.CompilePolicyResponse{Plans: plans, Violations: violations})
}

func controlViolation(code, field, message string) *antiflockv1.PolicyViolation {
	return &antiflockv1.PolicyViolation{ReasonCode: code, Field: field, SafeMessage: message}
}

func (server *Server) handleFindings(response http.ResponseWriter, request *http.Request) {
	nodeID := strings.TrimSpace(request.URL.Query().Get("nodeId"))
	if nodeID != "" && !bounded(nodeID, 128) {
		writeAPIError(response, http.StatusBadRequest, "INVALID_NODE", "Finding node id is invalid.", "", false)
		return
	}
	statuses := make([]antiflockv1.FindingStatus, 0)
	if values := request.URL.Query()["status"]; len(values) != 0 {
		if len(values) > 5 {
			writeAPIError(response, http.StatusBadRequest, "INVALID_FINDING_STATUS", "Too many finding statuses were requested.", "", false)
			return
		}
		for _, value := range values {
			name := "FINDING_STATUS_" + strings.ToUpper(strings.TrimSpace(value))
			encoded, ok := antiflockv1.FindingStatus_value[name]
			if !ok || encoded == 0 {
				writeAPIError(response, http.StatusBadRequest, "INVALID_FINDING_STATUS", "A finding status is unsupported.", "", false)
				return
			}
			statuses = append(statuses, antiflockv1.FindingStatus(encoded))
		}
	}
	writeProtoJSON(response, http.StatusOK, &antiflockv1.ListFindingsResponse{
		Findings: server.findings.List(nodeID, statuses...),
	})
}

func (server *Server) handleSimulateScrambler(response http.ResponseWriter, request *http.Request) {
	if !server.config.Scrambler.SimulationEnabled {
		writeAPIError(response, http.StatusPreconditionFailed, "SCRAMBLER_SIMULATION_DISABLED", "Scrambler simulation is disabled by configuration.", "", false)
		return
	}
	var input antiflockv1.SimulateScramblerRequest
	if err := decodeProtoJSON(response, request, &input, maximumControlRequestBytes); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_SCRAMBLER_REQUEST", "Scrambler simulation input is not valid protobuf JSON.", "", false)
		return
	}
	if !bounded(input.GetNodeId(), 128) || !bounded(input.GetOperationId(), 128) {
		writeAPIError(response, http.StatusBadRequest, "INVALID_SCRAMBLER_REQUEST", "Scrambler simulation requires node and operation ids.", input.GetOperationId(), false)
		return
	}
	node, err := server.database.GetNode(request.Context(), input.GetNodeId())
	if err != nil {
		status := http.StatusInternalServerError
		if err == storage.ErrNodeNotFound {
			status = http.StatusNotFound
		}
		server.writeDomainError(response, status, err, input.GetOperationId())
		return
	}
	if node.Status != model.NodeActive {
		writeAPIError(response, http.StatusConflict, "NODE_INACTIVE", "Scrambler cannot simulate against an inactive node.", input.GetOperationId(), false)
		return
	}
	current := server.scramblerState(node.ID, node.EnrolledAt)
	simulation, err := server.scrambler.Simulate(node.ID, input.GetOperationId(), current, input.GetConstraints(), server.clock().UTC())
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "SCRAMBLER_SIMULATION_INVALID", err.Error(), input.GetOperationId(), false)
		return
	}
	writeProtoJSON(response, http.StatusOK, &antiflockv1.SimulateScramblerResponse{Simulation: simulation})
}

func (server *Server) handleActivateScrambler(response http.ResponseWriter, request *http.Request) {
	var input antiflockv1.ActivateScramblerRequest
	if err := decodeProtoJSON(response, request, &input, 64<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_SCRAMBLER_REQUEST", "Scrambler activation input is not valid protobuf JSON.", "", false)
		return
	}
	_, err := server.scrambler.Activate(&input)
	if err == scrambler.ErrExecutionDisabled {
		writeAPIError(response, http.StatusPreconditionFailed, "SCRAMBLER_EXECUTION_DISABLED", "Scrambler execution is outside the locked release boundary; simulation remains available.", input.GetOperationId(), false)
		return
	}
	if err != nil {
		server.writeDomainError(response, http.StatusBadRequest, err, input.GetOperationId())
		return
	}
	writeAPIError(response, http.StatusInternalServerError, "INTERNAL", "Core did not receive a Scrambler transition.", input.GetOperationId(), true)
}

func (server *Server) scramblerState(nodeID string, activeSince time.Time) *antiflockv1.ScramblerState {
	digest := sha256.Sum256([]byte(fmt.Sprintf("AntiFlock-Scrambler-State-v1\x00%s\x00%s", server.deploymentID, nodeID)))
	return &antiflockv1.ScramblerState{
		Id: fmt.Sprintf("state_%x", digest[:16]), NodeId: nodeID,
		LifecycleState: antiflockv1.ScramblerLifecycleState_SCRAMBLER_LIFECYCLE_STATE_IDLE,
		ActiveSince:    timestamppb.New(activeSince.UTC()), ReasonCodes: []string{"AF-SCRAMBLER-SIMULATION-ONLY"},
	}
}
