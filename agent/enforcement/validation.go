package enforcement

import (
	"crypto/ed25519"
	"errors"
	"sort"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
)

const PlanVerificationSchemaVersion = "antiflock.plan-verification/v1"

// PlanVerificationConfig pins the identity and signing boundary used to inspect
// a plan. Verification is deliberately non-mutating: it never reserves replay
// state, runs a host check, or invokes an enforcement driver.
type PlanVerificationConfig struct {
	DeploymentID  string
	NodeID        string
	PlanKeyID     string
	PlanPublicKey ed25519.PublicKey
	Capabilities  *antiflockv1.CapabilityManifest
	Clock         func() time.Time
}

// PlanVerification reports cryptographic/structural validity separately from
// declared capability compatibility. Neither value proves that host drivers or
// recovery are installed, healthy, or authorized to execute.
type PlanVerification struct {
	SchemaVersion        string   `json:"schemaVersion"`
	PlanID               string   `json:"planId,omitempty"`
	NodeID               string   `json:"nodeId"`
	DeploymentID         string   `json:"deploymentId"`
	Valid                bool     `json:"valid"`
	CapabilityCompatible bool     `json:"capabilityCompatible"`
	Executable           bool     `json:"executable"`
	ReasonCode           string   `json:"reasonCode"`
	SafeMessage          string   `json:"safeMessage"`
	MissingCapabilities  []string `json:"missingCapabilities,omitempty"`
	HumanReadableDryRun  string   `json:"humanReadableDryRun,omitempty"`
}

// VerifyPlan inspects a signed plan without crossing the mutation boundary.
// Executable is always false in this API because driver/recovery readiness and
// operator authorization are intentionally outside cryptographic validation.
func VerifyPlan(config PlanVerificationConfig, input *antiflockv1.Plan) (*PlanVerification, error) {
	if !safePlanToken(config.DeploymentID) || !safePlanToken(config.NodeID) || !safePlanToken(config.PlanKeyID) {
		return nil, errors.New("plan verification requires deployment, node, and policy signing key ids")
	}
	if len(config.PlanPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("plan verification requires an Ed25519 policy public key")
	}
	if config.Capabilities == nil || config.Capabilities.NodeId != config.NodeID {
		return nil, errors.New("plan verification requires a node-bound capability manifest")
	}
	if err := model.RejectUnknownFields(config.Capabilities); err != nil {
		return nil, errors.New("capability manifest contains unknown fields")
	}
	if input == nil {
		return nil, errors.New("plan is required")
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	plan := proto.Clone(input).(*antiflockv1.Plan)
	result := &PlanVerification{
		SchemaVersion: PlanVerificationSchemaVersion,
		PlanID:        plan.Id, NodeID: config.NodeID, DeploymentID: config.DeploymentID,
		Executable: false,
	}
	verifier := &Enforcer{
		deploymentID:  config.DeploymentID,
		nodeID:        config.NodeID,
		planKeyID:     config.PlanKeyID,
		planPublicKey: append(ed25519.PublicKey(nil), config.PlanPublicKey...),
		capabilities:  proto.Clone(config.Capabilities).(*antiflockv1.CapabilityManifest),
	}
	if validation := verifier.validatePlanMode(plan, clock().UTC(), false); validation != nil {
		result.ReasonCode = validation.reasonCode
		result.SafeMessage = "The signed plan failed local verification and cannot be executed."
		return result, nil
	}
	result.Valid = true
	result.HumanReadableDryRun = plan.HumanReadableDryRun
	result.MissingCapabilities = verifier.missingCapabilities(plan)
	result.CapabilityCompatible = len(result.MissingCapabilities) == 0
	if !result.CapabilityCompatible {
		result.ReasonCode = "AF-PLAN-CAPABILITY-UNSUPPORTED"
		result.SafeMessage = "The plan is valid, but this node does not declare every required capability. Execution remains disabled."
		return result, nil
	}
	result.ReasonCode = "AF-PLAN-VERIFIED-EXECUTION-DISABLED"
	result.SafeMessage = "The plan is valid and capability-compatible. Host execution remains disabled until independently verified drivers, recovery, and operator authorization are present."
	return result, nil
}

func (enforcer *Enforcer) missingCapabilities(plan *antiflockv1.Plan) []string {
	missing := make(map[string]struct{})
	inspect := func(requirements []*antiflockv1.CapabilityRequirement) {
		for _, requirement := range requirements {
			if requirement == nil || !enforcer.supportsAll([]*antiflockv1.CapabilityRequirement{requirement}) {
				key := "invalid-capability-requirement"
				if requirement != nil && requirement.Key != "" {
					key = requirement.Key
				}
				missing[key] = struct{}{}
			}
		}
	}
	for _, check := range append(append([]*antiflockv1.PlanCheck(nil), plan.Preconditions...), plan.Verifications...) {
		if check != nil {
			inspect(check.RequiredCapabilities)
		}
	}
	for _, operation := range append(append([]*antiflockv1.PlanOperation(nil), plan.Actions...), plan.Rollback...) {
		if operation != nil {
			inspect(operation.RequiredCapabilities)
		}
	}
	result := make([]string, 0, len(missing))
	for key := range missing {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
