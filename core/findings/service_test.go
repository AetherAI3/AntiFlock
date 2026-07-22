package findings_test

import (
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/findings"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectionPreservesEvidenceHonestyAndResolves(t *testing.T) {
	t.Parallel()
	service, _ := findings.New("deployment")
	now := time.Now().UTC()
	snapshot := &antiflockv1.ProtectionSnapshot{
		DeploymentId: "deployment", NodeId: "phone", PolicyId: "coffee-shop", EvaluatedAt: timestamppb.New(now),
		State: antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED,
		Reasons: []*antiflockv1.PostureReason{{
			RuleId: "guard", ReasonCode: "AF-MESH-DISCONNECTED", ContributedState: antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED,
			CurrentFact: "The approved private mesh is not connected.", ExpectedFact: "The mesh must be connected.",
			Claim: &antiflockv1.EvidenceClaim{Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED, Confidence: 1, Statement: "Mesh disconnected"},
		}},
	}
	transitions, err := service.ApplySnapshot(snapshot)
	if err != nil || len(transitions) != 1 {
		t.Fatalf("open transitions = %#v, %v", transitions, err)
	}
	open := service.List("phone", antiflockv1.FindingStatus_FINDING_STATUS_OPEN)
	if len(open) != 1 || open[0].Claim.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED {
		t.Fatalf("finding = %#v", open)
	}
	if strings.Contains(strings.ToLower(open[0].Title+open[0].Condition), "surveillance") {
		t.Fatal("route failure was overstated as surveillance")
	}
	snapshot.State = antiflockv1.ProtectionState_PROTECTION_STATE_PROTECTED
	snapshot.Reasons = nil
	snapshot.EvaluatedAt = timestamppb.New(now.Add(time.Second))
	if transitions, err = service.ApplySnapshot(snapshot); err != nil || len(transitions) != 1 || transitions[0].ToStatus != antiflockv1.FindingStatus_FINDING_STATUS_RESOLVED {
		t.Fatalf("resolve transitions = %#v, %v", transitions, err)
	}
}

func TestUnknownReasonUsesHonestNonemptyTitle(t *testing.T) {
	service, err := findings.New("deployment")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, err = service.ApplySnapshot(&antiflockv1.ProtectionSnapshot{
		DeploymentId: "deployment", NodeId: "phone", PolicyId: "policy",
		EvaluatedAt: timestamppb.New(now), State: antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED,
		Reasons: []*antiflockv1.PostureReason{{
			RuleId: "additive", ReasonCode: "AF-ADDITIVE-REASON",
			ContributedState: antiflockv1.ProtectionState_PROTECTION_STATE_EXPOSED,
			CurrentFact:      "An additive policy condition was detected.", ExpectedFact: "The condition should be cleared.",
			Claim: &antiflockv1.EvidenceClaim{Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED, Confidence: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	values := service.List("phone", antiflockv1.FindingStatus_FINDING_STATUS_OPEN)
	if len(values) != 1 || values[0].Title != "Protection policy condition detected" {
		t.Fatalf("unexpected fallback finding %#v", values)
	}
}
