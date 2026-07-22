package nano

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type BindingID string

const (
	BindingScramblerSimulation BindingID = "scrambler-simulation-v1"
	BindingFixtureShodan       BindingID = "fixture-shodan-query-v1"
	BindingFixtureBroker       BindingID = "fixture-broker-query-v1"
	BindingFixturePaste        BindingID = "fixture-paste-query-v1"
	BindingCountermeasurePlan  BindingID = "countermeasure-plan-v1"
)

type proposalBinding struct {
	ActionType  string
	Destination string
	DataClass   string
}

var admittedBindings = map[BindingID]proposalBinding{
	BindingScramblerSimulation: {ActionType: "scrambler.simulate", Destination: "local://scrambler/simulation", DataClass: "network-control"},
	BindingFixtureShodan:       {ActionType: "watchdog.public_surface.query", Destination: "provider://fixture-shodan", DataClass: "owned-public-surface"},
	BindingFixtureBroker:       {ActionType: "watchdog.public_surface.query", Destination: "provider://fixture-broker-registry", DataClass: "owned-public-surface"},
	BindingFixturePaste:        {ActionType: "watchdog.public_surface.query", Destination: "provider://fixture-paste-reference", DataClass: "owned-public-surface"},
	BindingCountermeasurePlan:  {ActionType: "watchdog.countermeasure.plan", Destination: "local://countermeasure/plan", DataClass: "owned-public-surface"},
}

// SecureActionProposal is the only outward value Nano can produce. It mirrors
// the existing gate request but carries no payload and performs no action.
type SecureActionProposal struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"applicationId"`
	NodeID        string    `json:"nodeId"`
	ActionType    string    `json:"actionType"`
	Destinations  []string  `json:"destinations"`
	DataClass     string    `json:"dataClass"`
	Sensitivity   string    `json:"sensitivity"`
	Deadline      string    `json:"deadline"`
	OperationID   string    `json:"operationId"`
	BindingID     BindingID `json:"bindingId"`
	ProgramDigest string    `json:"programDigest"`
	InputDigest   string    `json:"inputDigest"`
}

func BuildProposals(
	result EvaluationResult,
	bindingID BindingID,
	programDigest, inputDigest, nodeID, deadline string,
) ([]SecureActionProposal, error) {
	binding, found := admittedBindings[bindingID]
	if !found || !digestString(programDigest) || !digestString(inputDigest) || !opaque(nodeID) {
		return nil, ErrAdmissionDenied
	}
	deadlineValue, err := time.Parse(time.RFC3339Nano, deadline)
	if err != nil {
		return nil, errors.New("Nano proposal deadline must be RFC3339")
	}
	proposals := make([]SecureActionProposal, 0)
	for index, intent := range result.Intents {
		if intent.Action == "OBSERVE" {
			continue
		}
		if intent.Action != "EXECUTE" || !deadlineValue.After(time.Unix(intent.Timestamp, 0).UTC()) {
			return nil, ErrAdmissionDenied
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf(
			"AntiFlock-Nano-Proposal-v1\x00%s\x00%s\x00%s\x00%d\x00%d",
			programDigest, inputDigest, bindingID, intent.Timestamp, index,
		)))
		suffix := hex.EncodeToString(digest[:16])
		proposals = append(proposals, SecureActionProposal{
			ID: "nano-action-" + suffix, ApplicationID: "antiflock-nano", NodeID: nodeID,
			ActionType: binding.ActionType, Destinations: []string{binding.Destination},
			DataClass: binding.DataClass, Sensitivity: "SENSITIVITY_OPERATOR_PRIVATE",
			Deadline: deadlineValue.UTC().Format(time.RFC3339Nano), OperationID: "nano-operation-" + suffix,
			BindingID: bindingID, ProgramDigest: programDigest, InputDigest: inputDigest,
		})
	}
	return proposals, nil
}

func digestString(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func opaque(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func BindingDigest(bindingID BindingID) (string, error) {
	binding, found := admittedBindings[bindingID]
	if !found {
		return "", ErrAdmissionDenied
	}
	value := strings.Join([]string{string(bindingID), "antiflock-nano", binding.ActionType,
		binding.Destination, binding.DataClass, "SENSITIVITY_OPERATOR_PRIVATE", strconv.Itoa(1)}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
