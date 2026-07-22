package scrambler_test

import (
	"errors"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/scrambler"
)

func TestSimulationIsDeterministicAndCannotExecute(t *testing.T) {
	t.Parallel()
	planner, err := scrambler.New(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	state := &antiflockv1.ScramblerState{Id: "state", NodeId: "node", LifecycleState: antiflockv1.ScramblerLifecycleState_SCRAMBLER_LIFECYCLE_STATE_IDLE}
	constraints := &antiflockv1.ScramblerConstraints{
		AllowedDimensions:   []antiflockv1.ScramblerDimension{antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_EXIT_NODE},
		ApprovedExitNodeIds: []string{"exit-b", "exit-a"}, OperatorConsentRequired: true,
	}
	first, err := planner.Simulate("node", "operation", state, constraints, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := planner.Simulate("node", "operation", state, constraints, now)
	if err != nil || second.Id != first.Id || len(first.Candidates) != 2 || first.Candidates[0].Id != second.Candidates[0].Id {
		t.Fatalf("deterministic simulations differ: %#v %#v %v", first, second, err)
	}
	if _, err := planner.Activate(&antiflockv1.ActivateScramblerRequest{SimulationId: first.Id, CandidateId: first.Candidates[0].Id, OperatorConsent: true}); !errors.Is(err, scrambler.ErrExecutionDisabled) {
		t.Fatalf("activation error = %v", err)
	}
}

func TestSimulationRejectsUnimplementedAndAmbiguousDimensions(t *testing.T) {
	planner, _ := scrambler.New(time.Minute)
	now := time.Now().UTC()
	state := &antiflockv1.ScramblerState{Id: "state", NodeId: "node"}
	for name, constraints := range map[string]*antiflockv1.ScramblerConstraints{
		"relay is not implemented": {AllowedDimensions: []antiflockv1.ScramblerDimension{antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_RELAY_PREFERENCE}},
		"duplicate dimension": {AllowedDimensions: []antiflockv1.ScramblerDimension{
			antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_EXIT_NODE,
			antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_EXIT_NODE,
		}, ApprovedExitNodeIds: []string{"exit"}},
		"missing exits":          {AllowedDimensions: []antiflockv1.ScramblerDimension{antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_EXIT_NODE}},
		"duplicate DNS profiles": {AllowedDimensions: []antiflockv1.ScramblerDimension{antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_DNS_PROFILE}, ApprovedDnsProfileIds: []string{"dns", "dns"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := planner.Simulate("node", "operation", state, constraints, now); err == nil {
				t.Fatal("unsafe Scrambler simulation was accepted")
			}
		})
	}
}
