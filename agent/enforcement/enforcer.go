// Package enforcement implements the endpoint side of AntiFlock's signed plan
// transaction. OS mutation is delegated to a least-privilege Driver; this
// package owns validation, ordering, verification, replay defense, and rollback.
package enforcement

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/policy"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maximumPlanBytes      = 512 * 1024
	maximumPlanItems      = 64
	maximumStepTimeout    = 2 * time.Minute
	resultSignatureDomain = "antiflock.plan-result.v1"
	signatureProtocol     = "AntiFlock-Signature-v1"
	defaultMaxEvidenceAge = 2 * time.Minute
)

var (
	ErrPlanReplay     = errors.New("plan replay or revision conflict")
	ErrPlanInProgress = errors.New("plan execution is already in progress")
	ErrPlanRejected   = errors.New("plan was rejected")
)

// CheckObservation is supplied by a local deterministic check implementation.
// The enforcer validates its evidence before a required pass can commit.
type CheckObservation struct {
	Outcome     antiflockv1.CheckOutcome
	ReasonCode  string
	SafeMessage string
	Evidence    []*antiflockv1.EvidenceReference
}

// OperationObservation contains no raw command output. A Driver must sanitize
// provider and operating-system errors before setting SafeMessage.
type OperationObservation struct {
	Succeeded   bool
	ReasonCode  string
	SafeMessage string
}

// Driver is the only mutation boundary. Tests and simulations should provide
// an in-memory implementation; production implementations belong in isolated,
// least-privilege platform adapters.
type Driver interface {
	Check(context.Context, *antiflockv1.PlanCheck) (CheckObservation, error)
	Apply(context.Context, *antiflockv1.PlanOperation) (OperationObservation, error)
	Rollback(context.Context, *antiflockv1.PlanOperation) (OperationObservation, error)
}

// Reservation is the replay-safe identity of executable plan content.
type Reservation struct {
	PlanID         string
	Fingerprint    string
	PolicyRevision uint64
	PlanRevision   uint64
}

// StateStore atomically reserves a monotonic plan before mutation and records
// its terminal signed result. MemoryStateStore is only for tests and simulation;
// Linux enforcement should use FileStateStore so replay defense survives restart.
type StateStore interface {
	Reserve(context.Context, Reservation) (*antiflockv1.PlanExecutionResult, error)
	Complete(context.Context, *antiflockv1.PlanExecutionResult) error
}

type memoryRecord struct {
	reservation Reservation
	result      *antiflockv1.PlanExecutionResult
}

type MemoryStateStore struct {
	mu                 sync.Mutex
	lastPolicyRevision uint64
	lastPlanRevision   uint64
	records            map[string]memoryRecord
}

func NewMemoryStateStore(lastPolicyRevision, lastPlanRevision uint64) *MemoryStateStore {
	return &MemoryStateStore{
		lastPolicyRevision: lastPolicyRevision, lastPlanRevision: lastPlanRevision,
		records: make(map[string]memoryRecord),
	}
}

func (store *MemoryStateStore) Reserve(ctx context.Context, reservation Reservation) (*antiflockv1.PlanExecutionResult, error) {
	if store == nil {
		return nil, errors.New("plan state store is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.records[reservation.PlanID]; ok {
		if existing.reservation != reservation {
			return nil, ErrPlanReplay
		}
		if existing.result == nil {
			return nil, ErrPlanInProgress
		}
		return proto.Clone(existing.result).(*antiflockv1.PlanExecutionResult), nil
	}
	if reservation.PlanID == "" || reservation.Fingerprint == "" || reservation.PolicyRevision == 0 || reservation.PlanRevision == 0 ||
		reservation.PolicyRevision < store.lastPolicyRevision || reservation.PlanRevision <= store.lastPlanRevision {
		return nil, ErrPlanReplay
	}
	store.lastPolicyRevision = reservation.PolicyRevision
	store.lastPlanRevision = reservation.PlanRevision
	store.records[reservation.PlanID] = memoryRecord{reservation: reservation}
	return nil, nil
}

func (store *MemoryStateStore) Complete(ctx context.Context, result *antiflockv1.PlanExecutionResult) error {
	if store == nil || result == nil || result.PlanId == "" {
		return errors.New("terminal plan result is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[result.PlanId]
	if !ok || record.reservation.PlanRevision != result.PlanRevision {
		return errors.New("plan result has no matching reservation")
	}
	if record.result != nil {
		if proto.Equal(record.result, result) {
			return nil
		}
		return ErrPlanReplay
	}
	record.result = proto.Clone(result).(*antiflockv1.PlanExecutionResult)
	store.records[result.PlanId] = record
	return nil
}

func (store *MemoryStateStore) Revisions() (uint64, uint64) {
	if store == nil {
		return 0, 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lastPolicyRevision, store.lastPlanRevision
}

type Config struct {
	DeploymentID       string
	NodeID             string
	PlanKeyID          string
	PlanPublicKey      ed25519.PublicKey
	NodeKeyID          string
	NodePrivateKey     ed25519.PrivateKey
	Capabilities       *antiflockv1.CapabilityManifest
	Driver             Driver
	StateStore         StateStore
	Clock              func() time.Time
	MaximumEvidenceAge time.Duration
	RollbackTimeout    time.Duration
}

type Enforcer struct {
	deploymentID       string
	nodeID             string
	planKeyID          string
	planPublicKey      ed25519.PublicKey
	nodeKeyID          string
	nodePrivateKey     ed25519.PrivateKey
	capabilities       *antiflockv1.CapabilityManifest
	driver             Driver
	store              StateStore
	clock              func() time.Time
	maximumEvidenceAge time.Duration
	rollbackTimeout    time.Duration
	mu                 sync.Mutex
}

func New(config Config) (*Enforcer, error) {
	if strings.TrimSpace(config.DeploymentID) == "" || strings.TrimSpace(config.NodeID) == "" || strings.TrimSpace(config.PlanKeyID) == "" {
		return nil, errors.New("enforcer deployment, node, and policy signing key id are required")
	}
	if len(config.PlanPublicKey) != ed25519.PublicKeySize || len(config.NodePrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("enforcer plan and node keys must be Ed25519")
	}
	if config.NodeKeyID == "" {
		config.NodeKeyID = config.NodeID
	}
	if config.NodeKeyID != config.NodeID {
		return nil, errors.New("enforcer node signing key id must match the node id")
	}
	if config.Capabilities == nil || config.Capabilities.NodeId != config.NodeID || config.Driver == nil {
		return nil, errors.New("enforcer requires node-bound capabilities and a driver")
	}
	if err := model.RejectUnknownFields(config.Capabilities); err != nil {
		return nil, fmt.Errorf("capability manifest: %w", err)
	}
	if config.StateStore == nil {
		return nil, errors.New("enforcer requires an explicit replay state store")
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.MaximumEvidenceAge == 0 {
		config.MaximumEvidenceAge = defaultMaxEvidenceAge
	}
	if config.MaximumEvidenceAge < time.Second || config.MaximumEvidenceAge > 30*time.Minute {
		return nil, errors.New("maximum evidence age must be between one second and 30 minutes")
	}
	if config.RollbackTimeout == 0 {
		config.RollbackTimeout = time.Minute
	}
	if config.RollbackTimeout < time.Second || config.RollbackTimeout > 5*time.Minute {
		return nil, errors.New("rollback timeout must be between one second and five minutes")
	}
	return &Enforcer{
		deploymentID: config.DeploymentID, nodeID: config.NodeID, planKeyID: config.PlanKeyID,
		planPublicKey: append(ed25519.PublicKey(nil), config.PlanPublicKey...), nodeKeyID: config.NodeKeyID,
		nodePrivateKey: append(ed25519.PrivateKey(nil), config.NodePrivateKey...),
		capabilities:   proto.Clone(config.Capabilities).(*antiflockv1.CapabilityManifest),
		driver:         config.Driver, store: config.StateStore, clock: config.Clock,
		maximumEvidenceAge: config.MaximumEvidenceAge, rollbackTimeout: config.RollbackTimeout,
	}, nil
}

// Apply executes one plan serially. Invalid plans return a signed REJECTED
// result together with ErrPlanRejected; transaction failures are represented
// by a terminal signed result and do not expose raw driver errors.
func (enforcer *Enforcer) Apply(ctx context.Context, input *antiflockv1.Plan) (*antiflockv1.PlanExecutionResult, error) {
	if enforcer == nil || ctx == nil {
		return nil, errors.New("enforcer and context are required")
	}
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()

	if input == nil {
		return nil, errors.New("plan is required")
	}
	plan := proto.Clone(input).(*antiflockv1.Plan)
	now := enforcer.clock().UTC()
	result := &antiflockv1.PlanExecutionResult{PlanId: plan.Id, NodeId: enforcer.nodeID, PlanRevision: plan.Revision}
	if validationErr := enforcer.validatePlan(plan, now); validationErr != nil {
		terminal, signErr := enforcer.finish(result, antiflockv1.PlanStatus_PLAN_STATUS_REJECTED, validationErr.reasonCode, now)
		if signErr != nil {
			return nil, signErr
		}
		return terminal, fmt.Errorf("%w: %s", ErrPlanRejected, validationErr.reasonCode)
	}

	reservation := Reservation{
		PlanID: plan.Id, Fingerprint: planFingerprint(plan),
		PolicyRevision: plan.PolicyRevision, PlanRevision: plan.Revision,
	}
	existing, err := enforcer.store.Reserve(ctx, reservation)
	if err != nil {
		reason := "AF-PLAN-STATE-UNAVAILABLE"
		if errors.Is(err, ErrPlanReplay) {
			reason = "AF-PLAN-REPLAY"
		} else if errors.Is(err, ErrPlanInProgress) {
			reason = "AF-PLAN-IN-PROGRESS"
		}
		terminal, signErr := enforcer.finish(result, antiflockv1.PlanStatus_PLAN_STATUS_REJECTED, reason, now)
		if signErr != nil {
			return nil, signErr
		}
		return terminal, fmt.Errorf("%w: %s", ErrPlanRejected, reason)
	}
	if existing != nil {
		if existing.GetPlanId() != plan.GetId() || existing.GetPlanRevision() != plan.GetRevision() || existing.GetNodeId() != enforcer.nodeID ||
			VerifyExecutionResult(existing, enforcer.nodePrivateKey.Public().(ed25519.PublicKey)) != nil {
			return nil, errors.New("persisted plan result failed signature or reservation validation")
		}
		return existing, nil
	}

	for _, check := range plan.Preconditions {
		checkResult := enforcer.runCheck(ctx, check)
		result.PreconditionResults = append(result.PreconditionResults, checkResult)
		if check.Required && checkResult.Outcome != antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED {
			return enforcer.complete(ctx, result, antiflockv1.PlanStatus_PLAN_STATUS_REJECTED, "AF-PLAN-PRECONDITION-FAILED")
		}
	}
	for _, operation := range plan.Actions {
		operationResult := enforcer.runOperation(ctx, operation, false)
		result.OperationResults = append(result.OperationResults, operationResult)
		if !operationResult.Succeeded {
			return enforcer.rollback(ctx, plan, result, "AF-PLAN-ACTION-FAILED")
		}
	}
	for _, check := range plan.Verifications {
		checkResult := enforcer.runCheck(ctx, check)
		result.VerificationResults = append(result.VerificationResults, checkResult)
		if check.Required && checkResult.Outcome != antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED {
			return enforcer.rollback(ctx, plan, result, "AF-PLAN-VERIFICATION-FAILED")
		}
	}
	return enforcer.complete(ctx, result, antiflockv1.PlanStatus_PLAN_STATUS_COMMITTED, "AF-PLAN-COMMITTED")
}

type validationError struct{ reasonCode string }

func (err *validationError) Error() string { return err.reasonCode }

func reject(reason string) *validationError { return &validationError{reasonCode: reason} }

func (enforcer *Enforcer) validatePlan(plan *antiflockv1.Plan, now time.Time) *validationError {
	return enforcer.validatePlanMode(plan, now, true)
}

func (enforcer *Enforcer) validatePlanMode(plan *antiflockv1.Plan, now time.Time, requireCapabilities bool) *validationError {
	if proto.Size(plan) > maximumPlanBytes || model.RejectUnknownFields(plan) != nil {
		return reject("AF-PLAN-WIRE-INVALID")
	}
	if plan.DeploymentId != enforcer.deploymentID || plan.NodeId != enforcer.nodeID {
		return reject("AF-PLAN-TARGET-MISMATCH")
	}
	if plan.Id == "" || plan.PolicyId == "" || plan.PolicyRevision == 0 || plan.Revision == 0 || len(plan.Nonce) != sha256.Size {
		return reject("AF-PLAN-IDENTITY-INVALID")
	}
	if plan.Status != antiflockv1.PlanStatus_PLAN_STATUS_SIGNED && plan.Status != antiflockv1.PlanStatus_PLAN_STATUS_DELIVERED {
		return reject("AF-PLAN-STATUS-INVALID")
	}
	if plan.CreatedAt == nil || plan.ExpiresAt == nil || plan.CreatedAt.CheckValid() != nil || plan.ExpiresAt.CheckValid() != nil ||
		plan.CreatedAt.AsTime().After(now) || !plan.ExpiresAt.AsTime().After(now) || !plan.ExpiresAt.AsTime().After(plan.CreatedAt.AsTime()) {
		return reject("AF-PLAN-TIME-INVALID")
	}
	if plan.Signature == nil || plan.Signature.KeyId != enforcer.planKeyID || plan.Signature.SignedAt == nil || plan.Signature.SignedAt.CheckValid() != nil ||
		plan.Signature.SignedAt.AsTime().Before(plan.CreatedAt.AsTime().Add(-5*time.Minute)) || plan.Signature.SignedAt.AsTime().After(now.Add(5*time.Minute)) ||
		!plan.ExpiresAt.AsTime().After(plan.Signature.SignedAt.AsTime()) {
		return reject("AF-PLAN-SIGNER-INVALID")
	}
	if err := policy.VerifyPlan(plan, enforcer.planPublicKey, now); err != nil {
		return reject("AF-PLAN-SIGNATURE-INVALID")
	}
	if len(plan.RecoveryAllowlist) == 0 || len(plan.RecoveryAllowlist) > 32 {
		return reject("AF-PLAN-RECOVERY-INVALID")
	}
	for _, destination := range plan.RecoveryAllowlist {
		if destination == "" || len(destination) > 512 || strings.TrimSpace(destination) != destination || strings.ContainsAny(destination, "\r\n\x00") {
			return reject("AF-PLAN-RECOVERY-INVALID")
		}
	}
	if plan.Sensitivity == antiflockv1.Sensitivity_SENSITIVITY_UNSPECIFIED ||
		plan.HumanReadableDryRun == "" || len(plan.HumanReadableDryRun) > 4096 || strings.TrimSpace(plan.HumanReadableDryRun) != plan.HumanReadableDryRun ||
		len(plan.Preconditions) == 0 || len(plan.Actions) == 0 || len(plan.Verifications) == 0 || len(plan.Rollback) == 0 ||
		len(plan.Preconditions) > maximumPlanItems || len(plan.Actions) > maximumPlanItems || len(plan.Verifications) > maximumPlanItems || len(plan.Rollback) > maximumPlanItems {
		return reject("AF-PLAN-STRUCTURE-INVALID")
	}
	if !validPlanLayout(plan) {
		return reject("AF-PLAN-LAYOUT-UNSUPPORTED")
	}
	ids := make(map[string]struct{})
	for _, checkSet := range []struct {
		items []*antiflockv1.PlanCheck
		phase antiflockv1.CheckPhase
	}{{plan.Preconditions, antiflockv1.CheckPhase_CHECK_PHASE_PRECONDITION}, {plan.Verifications, antiflockv1.CheckPhase_CHECK_PHASE_VERIFICATION}} {
		for _, check := range checkSet.items {
			if check == nil || check.Id == "" || check.Phase != checkSet.phase || check.CheckType == "" || check.Parameters == nil || !validTimeout(check.Timeout) {
				return reject("AF-PLAN-CHECK-INVALID")
			}
			if !validCheckParameters(check) {
				return reject("AF-PLAN-CHECK-PARAMETERS-INVALID")
			}
			if _, duplicate := ids[check.Id]; duplicate {
				return reject("AF-PLAN-DUPLICATE-ID")
			}
			ids[check.Id] = struct{}{}
			if requireCapabilities && !enforcer.supportsAll(check.RequiredCapabilities) {
				return reject("AF-PLAN-CAPABILITY-UNSUPPORTED")
			}
		}
	}
	for operationSetIndex, operationSet := range [][]*antiflockv1.PlanOperation{plan.Actions, plan.Rollback} {
		for _, operation := range operationSet {
			if operation == nil || operation.Id == "" || operation.Type == antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_UNSPECIFIED || operation.Target == "" || operation.Parameters == nil || !validTimeout(operation.Timeout) {
				return reject("AF-PLAN-OPERATION-INVALID")
			}
			if _, duplicate := ids[operation.Id]; duplicate {
				return reject("AF-PLAN-DUPLICATE-ID")
			}
			ids[operation.Id] = struct{}{}
			if !validOperationParameters(operation, operationSetIndex == 1, plan.RecoveryAllowlist) {
				return reject("AF-PLAN-OPERATION-PARAMETERS-INVALID")
			}
			if requireCapabilities && !enforcer.supportsAll(operation.RequiredCapabilities) {
				return reject("AF-PLAN-CAPABILITY-UNSUPPORTED")
			}
		}
	}
	return nil
}

func validPlanLayout(plan *antiflockv1.Plan) bool {
	if len(plan.Preconditions) != 1 || len(plan.Actions) != 4 || len(plan.Verifications) != 3 || len(plan.Rollback) != 3 {
		return false
	}
	if plan.Preconditions[0] == nil || plan.Preconditions[0].Id != "preflight-current-state" || plan.Preconditions[0].CheckType != "state.capture" || !plan.Preconditions[0].Required {
		return false
	}
	checks := []struct {
		id   string
		kind string
	}{{"verify-mesh", "mesh.connected"}, {"verify-route", "route.egress"}, {"verify-dns", "dns.path"}}
	for index, expected := range checks {
		check := plan.Verifications[index]
		if check == nil || check.Id != expected.id || check.CheckType != expected.kind || !check.Required {
			return false
		}
	}
	operations := []struct {
		id     string
		kind   antiflockv1.PlanOperationType
		target string
	}{
		{"guard-egress", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, "protected-egress"},
		{"connect-mesh", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_MESH, ""},
		{"set-route", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_ROUTE, "approved-egress"},
		{"set-dns", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_DNS, "protected-dns"},
	}
	for index, expected := range operations {
		operation := plan.Actions[index]
		if operation == nil || operation.Id != expected.id || operation.Type != expected.kind || (expected.target != "" && operation.Target != expected.target) {
			return false
		}
	}
	rollbacks := []struct {
		id     string
		kind   antiflockv1.PlanOperationType
		target string
	}{
		{"rollback-dns", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_DNS, "captured:dns"},
		{"rollback-route", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_ROUTE, "captured:route"},
		{"rollback-firewall", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, "captured:firewall"},
	}
	for index, expected := range rollbacks {
		operation := plan.Rollback[index]
		if operation == nil || operation.Id != expected.id || operation.Type != expected.kind || operation.Target != expected.target {
			return false
		}
	}
	return true
}

func validCheckParameters(check *antiflockv1.PlanCheck) bool {
	if check == nil || !exactFields(check.Parameters, "source") {
		return false
	}
	source, ok := stringField(check.Parameters, "source")
	if !ok || source != "endpoint" {
		return false
	}
	switch check.Phase {
	case antiflockv1.CheckPhase_CHECK_PHASE_PRECONDITION:
		return check.CheckType == "state.capture"
	case antiflockv1.CheckPhase_CHECK_PHASE_VERIFICATION:
		return check.CheckType == "mesh.connected" || check.CheckType == "route.egress" || check.CheckType == "dns.path"
	default:
		return false
	}
}

func validOperationParameters(operation *antiflockv1.PlanOperation, rollback bool, recoveryAllowlist []string) bool {
	if operation == nil || operation.Parameters == nil {
		return false
	}
	simulation, simulationOK := boolField(operation.Parameters, "simulation")
	failMode, failModeOK := stringField(operation.Parameters, "failMode")
	if !simulationOK || simulation || !failModeOK || failMode != "CLOSED" {
		return false
	}
	if rollback {
		return exactFields(operation.Parameters, "simulation", "failMode")
	}
	switch operation.Type {
	case antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL:
		if operation.Target != "protected-egress" || !exactFields(operation.Parameters, "simulation", "failMode", "allowedDestinations", "recoveryDestinations") {
			return false
		}
		_, allowedOK := stringListField(operation.Parameters, "allowedDestinations", 0, 32, 512)
		recovery, recoveryOK := stringListField(operation.Parameters, "recoveryDestinations", 1, 32, 512)
		return allowedOK && recoveryOK && slices.Equal(recovery, recoveryAllowlist)
	case antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_MESH:
		return slices.Contains([]string{"auto", "tailscale", "headscale", "wireguard"}, operation.Target) && exactFields(operation.Parameters, "simulation", "failMode")
	case antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_ROUTE:
		if operation.Target != "approved-egress" || !exactFields(operation.Parameters, "simulation", "failMode", "allowedExitNodeIds") {
			return false
		}
		_, ok := stringListField(operation.Parameters, "allowedExitNodeIds", 1, 32, 128)
		return ok
	case antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_DNS:
		if operation.Target != "protected-dns" || !exactFields(operation.Parameters, "simulation", "failMode", "allowedResolvers") {
			return false
		}
		_, ok := stringListField(operation.Parameters, "allowedResolvers", 1, 16, 512)
		return ok
	default:
		return false
	}
}

func exactFields(parameters *structpb.Struct, names ...string) bool {
	if parameters == nil || len(parameters.Fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, exists := parameters.Fields[name]; !exists {
			return false
		}
	}
	return true
}

func boolField(parameters *structpb.Struct, name string) (bool, bool) {
	value := parameters.GetFields()[name]
	if value == nil {
		return false, false
	}
	typed, ok := value.Kind.(*structpb.Value_BoolValue)
	if !ok {
		return false, false
	}
	return typed.BoolValue, true
}

func stringField(parameters *structpb.Struct, name string) (string, bool) {
	value := parameters.GetFields()[name]
	if value == nil {
		return "", false
	}
	typed, ok := value.Kind.(*structpb.Value_StringValue)
	if !ok {
		return "", false
	}
	return typed.StringValue, true
}

func stringListField(parameters *structpb.Struct, name string, minimum, maximum, maximumLength int) ([]string, bool) {
	value := parameters.GetFields()[name]
	if value == nil {
		return nil, false
	}
	typed, ok := value.Kind.(*structpb.Value_ListValue)
	if !ok || typed.ListValue == nil || len(typed.ListValue.Values) < minimum || len(typed.ListValue.Values) > maximum {
		return nil, false
	}
	result := make([]string, 0, len(typed.ListValue.Values))
	seen := make(map[string]struct{}, len(typed.ListValue.Values))
	for _, item := range typed.ListValue.Values {
		text, ok := item.Kind.(*structpb.Value_StringValue)
		if !ok || text.StringValue == "" || len(text.StringValue) > maximumLength || strings.TrimSpace(text.StringValue) != text.StringValue || strings.ContainsAny(text.StringValue, "\r\n\x00") {
			return nil, false
		}
		if _, duplicate := seen[text.StringValue]; duplicate {
			return nil, false
		}
		seen[text.StringValue] = struct{}{}
		result = append(result, text.StringValue)
	}
	return result, true
}

func validTimeout(value interface {
	CheckValid() error
	AsDuration() time.Duration
}) bool {
	if value == nil || value.CheckValid() != nil {
		return false
	}
	duration := value.AsDuration()
	return duration > 0 && duration <= maximumStepTimeout
}

func (enforcer *Enforcer) supportsAll(requirements []*antiflockv1.CapabilityRequirement) bool {
	if len(requirements) == 0 {
		return false
	}
	for _, requirement := range requirements {
		if requirement == nil || requirement.Key == "" || len(requirement.RequiredOperations) == 0 || requirement.MinimumSupportLevel == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSPECIFIED {
			return false
		}
		matched := false
		for _, capability := range enforcer.capabilities.Capabilities {
			if capability == nil || capability.Key != requirement.Key || !supportSatisfies(capability.SupportLevel, requirement.MinimumSupportLevel) {
				continue
			}
			matched = true
			for _, operation := range requirement.RequiredOperations {
				if operation == antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_UNSPECIFIED || !slices.Contains(capability.Operations, operation) {
					matched = false
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func supportSatisfies(actual, minimum antiflockv1.CapabilitySupportLevel) bool {
	switch minimum {
	case antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSUPPORTED:
		return actual != antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSPECIFIED
	case antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_PARTIAL:
		return actual == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_PARTIAL || actual == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL
	case antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL:
		return actual == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL
	case antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_EXPERIMENTAL:
		return actual == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_EXPERIMENTAL
	default:
		return false
	}
}

func (enforcer *Enforcer) runCheck(parent context.Context, check *antiflockv1.PlanCheck) *antiflockv1.CheckResult {
	ctx, cancel := context.WithTimeout(parent, check.Timeout.AsDuration())
	defer cancel()
	observation, err := safelyCheck(ctx, enforcer.driver, proto.Clone(check).(*antiflockv1.PlanCheck))
	if err == nil {
		err = ctx.Err()
	}
	checkedAt := enforcer.clock().UTC()
	result := &antiflockv1.CheckResult{CheckId: check.Id, CheckedAt: timestamppb.New(checkedAt)}
	if err != nil {
		result.Outcome = antiflockv1.CheckOutcome_CHECK_OUTCOME_UNKNOWN
		result.ReasonCode = "AF-CHECK-UNAVAILABLE"
		result.SafeMessage = "The endpoint check could not produce a trustworthy result."
		return result
	}
	result.Outcome = observation.Outcome
	result.ReasonCode = safeReason(observation.ReasonCode, defaultCheckReason(observation.Outcome))
	result.SafeMessage = safeMessage(observation.SafeMessage, defaultCheckMessage(observation.Outcome))
	for _, evidence := range observation.Evidence {
		if !validEvidence(evidence, checkedAt) {
			result.Outcome = antiflockv1.CheckOutcome_CHECK_OUTCOME_UNKNOWN
			result.ReasonCode = "AF-CHECK-EVIDENCE-INVALID"
			result.SafeMessage = "The endpoint check returned invalid evidence."
			result.Evidence = nil
			return result
		}
		result.Evidence = append(result.Evidence, proto.Clone(evidence).(*antiflockv1.EvidenceReference))
	}
	if result.Outcome == antiflockv1.CheckOutcome_CHECK_OUTCOME_UNSPECIFIED ||
		(result.Outcome == antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED && !enforcer.hasCurrentSupportingEvidence(result.Evidence, checkedAt)) {
		result.Outcome = antiflockv1.CheckOutcome_CHECK_OUTCOME_UNKNOWN
		result.ReasonCode = "AF-CHECK-EVIDENCE-MISSING"
		result.SafeMessage = "The endpoint check did not provide current supporting evidence."
	}
	if check.Required && result.Outcome == antiflockv1.CheckOutcome_CHECK_OUTCOME_SKIPPED {
		result.Outcome = antiflockv1.CheckOutcome_CHECK_OUTCOME_UNKNOWN
		result.ReasonCode = "AF-CHECK-REQUIRED-SKIPPED"
		result.SafeMessage = "A required endpoint check was skipped."
	}
	return result
}

func safelyCheck(ctx context.Context, driver Driver, check *antiflockv1.PlanCheck) (result CheckObservation, err error) {
	defer func() {
		if recover() != nil {
			result = CheckObservation{}
			err = errors.New("driver check panicked")
		}
	}()
	return driver.Check(ctx, check)
}

func (enforcer *Enforcer) hasCurrentSupportingEvidence(evidence []*antiflockv1.EvidenceReference, now time.Time) bool {
	for _, item := range evidence {
		if item.Role != antiflockv1.EvidenceRole_EVIDENCE_ROLE_SUPPORTING ||
			(item.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED && item.Classification != antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED) ||
			item.ObservedAt == nil {
			continue
		}
		age := now.Sub(item.ObservedAt.AsTime().UTC())
		if age < -5*time.Minute || age > enforcer.maximumEvidenceAge {
			continue
		}
		switch item.SourceType {
		case antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_LOCAL_SENSOR,
			antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_AUTHORIZED_GATEWAY,
			antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_PROVIDER_API,
			antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_DETERMINISTIC_RULE:
			return true
		}
	}
	return false
}

func validEvidence(evidence *antiflockv1.EvidenceReference, now time.Time) bool {
	if evidence == nil || proto.Size(evidence) > 64*1024 || model.RejectUnknownFields(evidence) != nil ||
		evidence.Id == "" || evidence.Role == antiflockv1.EvidenceRole_EVIDENCE_ROLE_UNSPECIFIED ||
		evidence.Classification == antiflockv1.EvidenceClass_EVIDENCE_CLASS_UNSPECIFIED || evidence.SourceType == antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_UNSPECIFIED ||
		evidence.SourceName == "" || evidence.Summary == "" || evidence.ObservedAt == nil || evidence.ObservedAt.CheckValid() != nil ||
		evidence.Sensitivity == antiflockv1.Sensitivity_SENSITIVITY_UNSPECIFIED || math.IsNaN(float64(evidence.Confidence)) || math.IsInf(float64(evidence.Confidence), 0) ||
		evidence.Confidence < 0 || evidence.Confidence > 1 {
		return false
	}
	if evidence.Integrity != nil && (evidence.Integrity.Algorithm != "sha256" || len(evidence.Integrity.Digest) != sha256.Size) {
		return false
	}
	if evidence.ExpiresAt != nil && (evidence.ExpiresAt.CheckValid() != nil || !evidence.ExpiresAt.AsTime().After(now)) {
		return false
	}
	if evidence.Classification == antiflockv1.EvidenceClass_EVIDENCE_CLASS_VERIFIED {
		if evidence.LastVerifiedAt == nil || evidence.LastVerifiedAt.CheckValid() != nil || evidence.LastVerifiedAt.AsTime().After(now.Add(5*time.Minute)) ||
			evidence.LastVerifiedAt.AsTime().Before(evidence.ObservedAt.AsTime()) || evidence.Integrity == nil {
			return false
		}
	}
	return true
}

func (enforcer *Enforcer) runOperation(parent context.Context, operation *antiflockv1.PlanOperation, rollback bool) *antiflockv1.OperationResult {
	startedAt := enforcer.clock().UTC()
	ctx, cancel := context.WithTimeout(parent, operation.Timeout.AsDuration())
	defer cancel()
	observation, err := safelyOperate(ctx, enforcer.driver, proto.Clone(operation).(*antiflockv1.PlanOperation), rollback)
	if err == nil {
		err = ctx.Err()
	}
	completedAt := enforcer.clock().UTC()
	result := &antiflockv1.OperationResult{
		OperationId: operation.Id, StartedAt: timestamppb.New(startedAt), CompletedAt: timestamppb.New(completedAt),
	}
	if err != nil {
		result.Succeeded = false
		result.ReasonCode = "AF-OPERATION-FAILED"
		result.SafeMessage = "The endpoint operation did not complete successfully."
		return result
	}
	result.Succeeded = observation.Succeeded
	if observation.Succeeded {
		result.ReasonCode = safeReason(observation.ReasonCode, "AF-OPERATION-SUCCEEDED")
		result.SafeMessage = safeMessage(observation.SafeMessage, "The endpoint operation completed.")
	} else {
		result.ReasonCode = safeReason(observation.ReasonCode, "AF-OPERATION-FAILED")
		result.SafeMessage = safeMessage(observation.SafeMessage, "The endpoint operation did not complete successfully.")
	}
	return result
}

func safelyOperate(ctx context.Context, driver Driver, operation *antiflockv1.PlanOperation, rollback bool) (result OperationObservation, err error) {
	defer func() {
		if recover() != nil {
			result = OperationObservation{}
			err = errors.New("driver operation panicked")
		}
	}()
	if rollback {
		return driver.Rollback(ctx, operation)
	}
	return driver.Apply(ctx, operation)
}

func (enforcer *Enforcer) rollback(parent context.Context, plan *antiflockv1.Plan, result *antiflockv1.PlanExecutionResult, originalReason string) (*antiflockv1.PlanExecutionResult, error) {
	rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(parent), enforcer.rollbackTimeout)
	defer cancel()
	rollbackComplete := true
	for _, operation := range plan.Rollback {
		operationResult := enforcer.runOperation(rollbackContext, operation, true)
		result.RollbackResults = append(result.RollbackResults, operationResult)
		if !operationResult.Succeeded {
			rollbackComplete = false
		}
	}
	if !rollbackComplete {
		return enforcer.complete(parent, result, antiflockv1.PlanStatus_PLAN_STATUS_FAILED, "AF-PLAN-ROLLBACK-INCOMPLETE")
	}
	return enforcer.complete(parent, result, antiflockv1.PlanStatus_PLAN_STATUS_ROLLED_BACK, originalReason)
}

func (enforcer *Enforcer) complete(ctx context.Context, result *antiflockv1.PlanExecutionResult, status antiflockv1.PlanStatus, reason string) (*antiflockv1.PlanExecutionResult, error) {
	terminal, err := enforcer.finish(result, status, reason, enforcer.clock().UTC())
	if err != nil {
		return nil, err
	}
	persistContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), enforcer.rollbackTimeout)
	defer cancel()
	if err := enforcer.store.Complete(persistContext, terminal); err != nil {
		return terminal, fmt.Errorf("persist terminal plan result: %w", err)
	}
	return terminal, nil
}

func (enforcer *Enforcer) finish(result *antiflockv1.PlanExecutionResult, status antiflockv1.PlanStatus, reason string, completedAt time.Time) (*antiflockv1.PlanExecutionResult, error) {
	result.Status = status
	result.ReasonCode = reason
	result.CompletedAt = timestamppb.New(completedAt.UTC())
	if err := SignExecutionResult(result, enforcer.nodeKeyID, enforcer.nodePrivateKey, completedAt.UTC()); err != nil {
		return nil, err
	}
	return result, nil
}

func safeReason(value, fallback string) string {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || !strings.HasPrefix(value, "AF-") || strings.ContainsAny(value, "\r\n\x00") {
		return fallback
	}
	return value
}

func safeMessage(value, fallback string) string {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return fallback
	}
	return value
}

func defaultCheckReason(outcome antiflockv1.CheckOutcome) string {
	switch outcome {
	case antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED:
		return "AF-CHECK-PASSED"
	case antiflockv1.CheckOutcome_CHECK_OUTCOME_FAILED:
		return "AF-CHECK-FAILED"
	case antiflockv1.CheckOutcome_CHECK_OUTCOME_SKIPPED:
		return "AF-CHECK-SKIPPED"
	default:
		return "AF-CHECK-UNKNOWN"
	}
}

func defaultCheckMessage(outcome antiflockv1.CheckOutcome) string {
	if outcome == antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED {
		return "The endpoint check passed with current supporting evidence."
	}
	return "The endpoint check did not establish the required state."
}

func planFingerprint(plan *antiflockv1.Plan) string {
	if plan == nil || plan.Signature == nil || plan.Signature.SignedContentDigest == nil {
		return ""
	}
	return hex.EncodeToString(plan.Signature.SignedContentDigest.Digest)
}

// SignExecutionResult applies the deterministic protobuf signing contract for
// antiflock.plan-result.v1. It mutates only NodeSignature.
func SignExecutionResult(result *antiflockv1.PlanExecutionResult, keyID string, privateKey ed25519.PrivateKey, signedAt time.Time) error {
	if result == nil || result.PlanId == "" || result.NodeId == "" || result.PlanRevision == 0 || result.CompletedAt == nil || result.CompletedAt.CheckValid() != nil {
		return errors.New("complete plan result identity and timestamp are required")
	}
	if keyID == "" || len(privateKey) != ed25519.PrivateKeySize || signedAt.IsZero() {
		return errors.New("plan result signing requires an Ed25519 node key")
	}
	view := proto.Clone(result).(*antiflockv1.PlanExecutionResult)
	view.NodeSignature = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	if err != nil {
		return fmt.Errorf("encode signable plan result: %w", err)
	}
	digest := sha256.Sum256(encoded)
	signature := &antiflockv1.Signature{
		KeyId: keyID, Algorithm: antiflockv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
		SignedAt: timestamppb.New(signedAt.UTC()), Encoding: antiflockv1.SignatureEncoding_SIGNATURE_ENCODING_PROTOBUF_DETERMINISTIC_V1,
		SignedContentDigest: &antiflockv1.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]}, Domain: resultSignatureDomain,
	}
	input, err := signatureInput(signature)
	if err != nil {
		return err
	}
	signature.Value = ed25519.Sign(privateKey, input)
	result.NodeSignature = signature
	return nil
}

func VerifyExecutionResult(result *antiflockv1.PlanExecutionResult, publicKey ed25519.PublicKey) error {
	if result == nil || result.NodeSignature == nil || len(publicKey) != ed25519.PublicKeySize || result.NodeSignature.KeyId != result.NodeId {
		return errors.New("plan result and node Ed25519 key are required")
	}
	if model.RejectUnknownFields(result) != nil {
		return errors.New("plan result contains unknown fields")
	}
	view := proto.Clone(result).(*antiflockv1.PlanExecutionResult)
	signature := view.NodeSignature
	view.NodeSignature = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if signature.SignedContentDigest == nil || subtle.ConstantTimeCompare(digest[:], signature.SignedContentDigest.Digest) != 1 {
		return errors.New("plan result signed-content digest mismatch")
	}
	input, err := signatureInput(signature)
	if err != nil || !ed25519.Verify(publicKey, input, signature.Value) {
		return errors.New("plan result signature verification failed")
	}
	return nil
}

func signatureInput(signature *antiflockv1.Signature) ([]byte, error) {
	if signature == nil || signature.Algorithm != antiflockv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519 ||
		signature.Encoding != antiflockv1.SignatureEncoding_SIGNATURE_ENCODING_PROTOBUF_DETERMINISTIC_V1 || signature.Domain != resultSignatureDomain ||
		signature.SignedAt == nil || signature.SignedAt.CheckValid() != nil || signature.SignedContentDigest == nil ||
		signature.SignedContentDigest.Algorithm != "sha256" || len(signature.SignedContentDigest.Digest) != sha256.Size {
		return nil, errors.New("unsupported plan result signature profile")
	}
	algorithm := make([]byte, 4)
	binary.BigEndian.PutUint32(algorithm, uint32(signature.Algorithm))
	seconds := make([]byte, 8)
	binary.BigEndian.PutUint64(seconds, uint64(signature.SignedAt.AsTime().Unix()))
	nanoseconds := make([]byte, 4)
	binary.BigEndian.PutUint32(nanoseconds, uint32(signature.SignedAt.AsTime().Nanosecond()))
	fields := [][]byte{
		[]byte(signatureProtocol), []byte(signature.Domain), algorithm, []byte("sha256"),
		signature.SignedContentDigest.Digest, seconds, nanoseconds,
	}
	var result []byte
	for _, field := range fields {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(field)))
		result = append(result, length...)
		result = append(result, field...)
	}
	return result, nil
}
