package server

import (
	"net/http"
	"strings"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/nano"
	"github.com/DBarr3/AntiFlock/core/storage"
)

type admitWatchdogRequest struct {
	NodeID string `json:"nodeId"`
	Source string `json:"source"`
	BindingID string `json:"bindingId"`
	OperationID string `json:"operationId"`
}

type runWatchdogRequest struct {
	FindingID string `json:"findingId"`
	NodeID string `json:"nodeId"`
	ReasonCode string `json:"reasonCode"`
	Confidence float64 `json:"confidence"`
	ObservedUnix int64 `json:"observedUnix"`
}

type watchdogView struct {
	ID string `json:"id"`
	NodeID string `json:"nodeId"`
	Name string `json:"name"`
	ProgramDigest string `json:"programDigest"`
	BindingID string `json:"bindingId"`
	Status storage.NanoWatchdogStatus `json:"status"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func (server *Server) handleListWatchdogs(response http.ResponseWriter, request *http.Request) {
	if server.nano == nil { server.handleUnavailable(response, request); return }
	nodeID := strings.TrimSpace(request.URL.Query().Get("nodeId"))
	if nodeID == "" { writeAPIError(response, http.StatusBadRequest, "INVALID_ARGUMENT", "nodeId is required.", "", false); return }
	values, err := server.nano.List(request.Context(), nodeID)
	if err != nil { server.writeDomainError(response, http.StatusBadRequest, err, ""); return }
	result := make([]watchdogView, 0, len(values)); for _, value := range values { result = append(result, projectWatchdog(value)) }
	writeJSON(response, http.StatusOK, map[string]any{"watchdogs": result})
}

func (server *Server) handleAdmitWatchdog(response http.ResponseWriter, request *http.Request) {
	if server.nano == nil { server.handleUnavailable(response, request); return }
	var body admitWatchdogRequest
	if err := decodeJSON(response, request, &body, 80<<10); err != nil { writeAPIError(response, http.StatusBadRequest, "INVALID_JSON", safeDecodeMessage(err), "", false); return }
	caller := principalFromContext(request.Context())
	record, err := server.nano.Admit(request.Context(), nano.AdmissionRequest{
		NodeID: body.NodeID, Source: body.Source, BindingID: nano.BindingID(body.BindingID), OperationID: body.OperationID, ActorID: caller.ID,
	})
	if err != nil { server.writeDomainError(response, http.StatusBadRequest, err, body.OperationID); return }
	writeJSON(response, http.StatusCreated, projectWatchdog(record))
}

func (server *Server) handleRunWatchdog(response http.ResponseWriter, request *http.Request) {
	if server.nano == nil { server.handleUnavailable(response, request); return }
	var body runWatchdogRequest
	if err := decodeJSON(response, request, &body, 32<<10); err != nil { writeAPIError(response, http.StatusBadRequest, "INVALID_JSON", safeDecodeMessage(err), "", false); return }
	result, err := server.nano.RunFinding(request.Context(), request.PathValue("id"), nano.FindingContext{
		FindingID: body.FindingID, NodeID: body.NodeID, ReasonCode: body.ReasonCode, Confidence: body.Confidence, ObservedUnix: body.ObservedUnix,
	})
	if err != nil { server.writeDomainError(response, http.StatusBadRequest, err, ""); return }
	writeJSON(response, http.StatusOK, result)
}

// handleRunWatchdogOpenFindings accepts no caller-supplied findings. It runs
// only current OPEN Core findings through the admitted, proposal-only program.
func (server *Server) handleRunWatchdogOpenFindings(response http.ResponseWriter, request *http.Request) {
	if server.nano == nil { server.handleUnavailable(response, request); return }
	findings := server.findings.List("", antiflockv1.FindingStatus_FINDING_STATUS_OPEN)
	contexts := make([]nano.FindingContext, 0, len(findings))
	for _, finding := range findings {
		if finding == nil || finding.GetMetadata() == nil || finding.GetLastSeenAt() == nil { continue }
		contexts = append(contexts, nano.FindingContext{
			FindingID: finding.GetMetadata().GetId(), NodeID: finding.GetNodeId(), ReasonCode: finding.GetReasonCode(),
			Confidence: float64(finding.GetClaim().GetConfidence()), ObservedUnix: finding.GetLastSeenAt().AsTime().UTC().Unix(),
		})
	}
	result, err := server.nano.RunOpenFindings(request.Context(), request.PathValue("id"), contexts)
	if err != nil { server.writeDomainError(response, http.StatusBadRequest, err, ""); return }
	writeJSON(response, http.StatusOK, result)
}

func projectWatchdog(record storage.NanoWatchdogProgramRecord) watchdogView {
	return watchdogView{ID: record.ID, NodeID: record.NodeID, Name: record.Name, ProgramDigest: record.ProgramDigest, BindingID: record.BindingID, Status: record.Status, CreatedAt: record.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), UpdatedAt: record.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00")}
}

