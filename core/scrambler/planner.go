package scrambler

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrExecutionDisabled = errors.New("scrambler execution is disabled; simulation is the supported release boundary")

type Planner struct {
	ttl time.Duration
}

func New(ttl time.Duration) (*Planner, error) {
	if ttl <= 0 || ttl > 15*time.Minute {
		return nil, errors.New("scrambler simulation TTL must be positive and no more than 15 minutes")
	}
	return &Planner{ttl: ttl}, nil
}

func (planner *Planner) Simulate(nodeID, operationID string, current *antiflockv1.ScramblerState, constraints *antiflockv1.ScramblerConstraints, now time.Time) (*antiflockv1.ScramblerSimulation, error) {
	if planner == nil || !bounded(nodeID, 128) || !bounded(operationID, 128) || current == nil || current.NodeId != nodeID || !bounded(current.Id, 128) || constraints == nil {
		return nil, errors.New("node, operation, current state, and constraints are required")
	}
	if len(constraints.AllowedDimensions) == 0 || len(constraints.AllowedDimensions) > 4 {
		return nil, errors.New("scrambler simulation requires between one and four dimensions")
	}
	seenDimensions := make(map[antiflockv1.ScramblerDimension]struct{}, len(constraints.AllowedDimensions))
	for _, dimension := range constraints.AllowedDimensions {
		if dimension != antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_EXIT_NODE &&
			dimension != antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_DNS_PROFILE {
			return nil, fmt.Errorf("scrambler dimension %s is outside the simulation boundary", dimension)
		}
		if _, duplicate := seenDimensions[dimension]; duplicate {
			return nil, errors.New("scrambler dimensions must be unique")
		}
		seenDimensions[dimension] = struct{}{}
	}
	maximumLatency := 30 * time.Second
	if constraints.MaximumTransitionLatency != nil {
		if err := constraints.MaximumTransitionLatency.CheckValid(); err != nil || constraints.MaximumTransitionLatency.AsDuration() <= 0 || constraints.MaximumTransitionLatency.AsDuration() > 5*time.Minute {
			return nil, errors.New("maximum transition latency is invalid")
		}
		maximumLatency = constraints.MaximumTransitionLatency.AsDuration()
	}
	exits := append([]string(nil), constraints.ApprovedExitNodeIds...)
	dnsProfiles := append([]string(nil), constraints.ApprovedDnsProfileIds...)
	if slices.Contains(constraints.AllowedDimensions, antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_EXIT_NODE) {
		if !validUniqueStrings(exits, 1, 16, 128) {
			return nil, errors.New("exit-node simulation requires bounded unique approved exits")
		}
	} else if len(exits) != 0 {
		return nil, errors.New("approved exits require the exit-node simulation dimension")
	} else {
		exits = []string{"unchanged"}
	}
	if slices.Contains(constraints.AllowedDimensions, antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_DNS_PROFILE) {
		if !validUniqueStrings(dnsProfiles, 1, 16, 128) {
			return nil, errors.New("DNS-profile simulation requires bounded unique approved profiles")
		}
	} else if len(dnsProfiles) != 0 {
		return nil, errors.New("approved DNS profiles require the DNS-profile simulation dimension")
	} else {
		dnsProfiles = []string{"unchanged"}
	}
	if !validUniqueStrings(constraints.CriticalPeerIds, 0, 64, 128) || !validUniqueStrings(constraints.RequiredDestinations, 0, 64, 512) {
		return nil, errors.New("scrambler verification targets must be unique and bounded")
	}
	sort.Strings(exits)
	sort.Strings(dnsProfiles)
	if len(exits)*len(dnsProfiles) > 64 {
		return nil, errors.New("scrambler candidate cross-product exceeds 64")
	}
	simulationID := stableID("simulation", nodeID, current.Id, operationID)
	candidates := make([]*antiflockv1.ScramblerCandidate, 0, len(exits)*len(dnsProfiles))
	for _, exitID := range exits {
		for _, dnsID := range dnsProfiles {
			values := make([]*antiflockv1.ScramblerStateValue, 0, 2)
			if exitID != "unchanged" {
				parameters, _ := structpb.NewStruct(map[string]any{"approved": true, "simulation": true})
				values = append(values, &antiflockv1.ScramblerStateValue{Dimension: antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_EXIT_NODE, StableReference: exitID, Parameters: parameters})
			}
			if dnsID != "unchanged" {
				parameters, _ := structpb.NewStruct(map[string]any{"approved": true, "simulation": true})
				values = append(values, &antiflockv1.ScramblerStateValue{Dimension: antiflockv1.ScramblerDimension_SCRAMBLER_DIMENSION_DNS_PROFILE, StableReference: dnsID, Parameters: parameters})
			}
			estimated := 5 * time.Second
			status := antiflockv1.ScramblerCandidateStatus_SCRAMBLER_CANDIDATE_STATUS_PROPOSED
			var rejection []string
			if estimated > maximumLatency || len(values) == 0 {
				status = antiflockv1.ScramblerCandidateStatus_SCRAMBLER_CANDIDATE_STATUS_REJECTED
				rejection = []string{"AF-SCRAMBLER-NO-SAFE-CHANGE"}
			}
			candidates = append(candidates, &antiflockv1.ScramblerCandidate{
				Id: stableID("candidate", simulationID, exitID, dnsID), PreviousStateId: current.Id,
				ProposedValues: values, Status: status, RejectionReasonCodes: rejection,
				EstimatedDisruption: durationpb.New(estimated),
			})
		}
	}
	return &antiflockv1.ScramblerSimulation{
		Id: simulationID, NodeId: nodeID, CurrentStateId: current.Id,
		Constraints: proto.Clone(constraints).(*antiflockv1.ScramblerConstraints), Candidates: candidates, SimulatedAt: timestamppb.New(now.UTC()),
		ExpiresAt: timestamppb.New(now.UTC().Add(planner.ttl)),
	}, nil
}

func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func validUniqueStrings(values []string, minimum, maximum, maximumLength int) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !bounded(value, maximumLength) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (planner *Planner) Activate(*antiflockv1.ActivateScramblerRequest) (*antiflockv1.ScramblerTransition, error) {
	return nil, ErrExecutionDisabled
}

func stableID(prefix string, values ...string) string {
	hasher := sha256.New()
	fmt.Fprintf(hasher, "AntiFlock-Scrambler-v1\x00%s", prefix)
	for _, value := range values {
		fmt.Fprintf(hasher, "\x00%s", value)
	}
	return fmt.Sprintf("%s_%x", prefix, hasher.Sum(nil)[:16])
}
