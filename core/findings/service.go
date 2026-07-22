package findings

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	deploymentID string
	mu           sync.RWMutex
	byID         map[string]*antiflockv1.Finding
}

func New(deploymentID string) (*Service, error) {
	if strings.TrimSpace(deploymentID) == "" {
		return nil, errors.New("finding deployment id is required")
	}
	return &Service{deploymentID: deploymentID, byID: make(map[string]*antiflockv1.Finding)}, nil
}

// ApplySnapshot deterministically opens, refreshes, and resolves findings from
// posture reasons. It preserves the reason's evidence class and never turns a
// route failure into a claim of monitoring or surveillance.
func (service *Service) ApplySnapshot(snapshot *antiflockv1.ProtectionSnapshot) ([]*antiflockv1.FindingTransition, error) {
	if service == nil || snapshot == nil || snapshot.DeploymentId != service.deploymentID || snapshot.NodeId == "" || snapshot.PolicyId == "" || snapshot.EvaluatedAt == nil || snapshot.EvaluatedAt.CheckValid() != nil {
		return nil, errors.New("valid deployment-bound posture snapshot is required")
	}
	now := snapshot.EvaluatedAt.AsTime().UTC()
	active := make(map[string]struct{})
	var transitions []*antiflockv1.FindingTransition
	service.mu.Lock()
	defer service.mu.Unlock()
	for _, reason := range snapshot.Reasons {
		if reason == nil || reason.ReasonCode == "" || reason.Claim == nil || reason.ContributedState == antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED {
			continue
		}
		id := findingID(snapshot.NodeId, snapshot.PolicyId, reason.RuleId, reason.ReasonCode)
		active[id] = struct{}{}
		existing := service.byID[id]
		if existing == nil {
			finding := &antiflockv1.Finding{
				Metadata:     &antiflockv1.ResourceMetadata{Id: id, Revision: 1, CreatedAt: timestamppb.New(now), UpdatedAt: timestamppb.New(now)},
				DeploymentId: service.deploymentID, NodeId: snapshot.NodeId, PolicyId: snapshot.PolicyId,
				RuleId: reason.RuleId, ReasonCode: reason.ReasonCode, Severity: severity(reason.ContributedState),
				Status: antiflockv1.FindingStatus_FINDING_STATUS_OPEN, Title: title(reason.ReasonCode),
				Condition: reason.CurrentFact, Consequence: "Protected traffic may not use the policy-approved path.",
				CurrentFact: reason.CurrentFact, ExpectedFact: reason.ExpectedFact,
				Claim: proto.Clone(reason.Claim).(*antiflockv1.EvidenceClaim), FirstSeenAt: timestamppb.New(now), LastSeenAt: timestamppb.New(now),
			}
			service.byID[id] = finding
			transitions = append(transitions, transition(id, antiflockv1.FindingStatus_FINDING_STATUS_UNSPECIFIED, antiflockv1.FindingStatus_FINDING_STATUS_OPEN, reason.ReasonCode, now))
			continue
		}
		from := existing.Status
		existing.Status = antiflockv1.FindingStatus_FINDING_STATUS_OPEN
		existing.Severity = severity(reason.ContributedState)
		existing.CurrentFact, existing.ExpectedFact = reason.CurrentFact, reason.ExpectedFact
		existing.Claim = proto.Clone(reason.Claim).(*antiflockv1.EvidenceClaim)
		existing.LastSeenAt, existing.ResolvedAt, existing.ResolutionReasonCode = timestamppb.New(now), nil, ""
		existing.Metadata.Revision++
		existing.Metadata.UpdatedAt = timestamppb.New(now)
		if from != existing.Status {
			transitions = append(transitions, transition(id, from, existing.Status, reason.ReasonCode, now))
		}
	}
	for id, finding := range service.byID {
		if finding.NodeId != snapshot.NodeId || finding.PolicyId != snapshot.PolicyId || finding.Status == antiflockv1.FindingStatus_FINDING_STATUS_RESOLVED {
			continue
		}
		if _, remains := active[id]; remains {
			continue
		}
		from := finding.Status
		finding.Status = antiflockv1.FindingStatus_FINDING_STATUS_RESOLVED
		finding.ResolvedAt, finding.LastSeenAt = timestamppb.New(now), timestamppb.New(now)
		finding.ResolutionReasonCode = "AF-CONTROL-RESTORED"
		finding.Metadata.Revision++
		finding.Metadata.UpdatedAt = timestamppb.New(now)
		transitions = append(transitions, transition(id, from, finding.Status, finding.ResolutionReasonCode, now))
	}
	sort.Slice(transitions, func(left, right int) bool { return transitions[left].FindingId < transitions[right].FindingId })
	return transitions, nil
}

func (service *Service) List(nodeID string, statuses ...antiflockv1.FindingStatus) []*antiflockv1.Finding {
	service.mu.RLock()
	defer service.mu.RUnlock()
	var result []*antiflockv1.Finding
	for _, finding := range service.byID {
		if nodeID != "" && finding.NodeId != nodeID {
			continue
		}
		if len(statuses) != 0 {
			matched := false
			for _, status := range statuses {
				matched = matched || finding.Status == status
			}
			if !matched {
				continue
			}
		}
		result = append(result, proto.Clone(finding).(*antiflockv1.Finding))
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Metadata.Id < result[right].Metadata.Id })
	return result
}

func findingID(nodeID, policyID, ruleID, reasonCode string) string {
	return fmt.Sprintf("finding:%s:%s:%s:%s", nodeID, policyID, ruleID, reasonCode)
}

func transition(id string, from, to antiflockv1.FindingStatus, reason string, at time.Time) *antiflockv1.FindingTransition {
	return &antiflockv1.FindingTransition{FindingId: id, FromStatus: from, ToStatus: to, ReasonCode: reason, OccurredAt: timestamppb.New(at)}
}

func severity(state antiflockv1.ProtectionState) antiflockv1.FindingSeverity {
	if state == antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED {
		return antiflockv1.FindingSeverity_FINDING_SEVERITY_HIGH
	}
	return antiflockv1.FindingSeverity_FINDING_SEVERITY_MEDIUM
}

func title(reasonCode string) string {
	titles := map[string]string{
		"AF-MESH-DISCONNECTED":      "Private mesh disconnected",
		"AF-EGRESS-EXIT-UNVERIFIED": "Approved exit is not verified",
		"AF-DNS-UNPROTECTED":        "Protected DNS is unavailable",
		"AF-ROUTE-UNPROTECTED":      "Protected route is unavailable",
	}
	if value := titles[reasonCode]; value != "" {
		return value
	}
	return "Protection policy condition detected"
}
