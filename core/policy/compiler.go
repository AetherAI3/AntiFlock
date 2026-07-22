package policy

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	policyAPIVersion = "antiflock.policy/v1"
	planDomain       = "antiflock.plan.v1"
	signaturePrefix  = "AntiFlock-Signature-v1"
)

type Compiler struct {
	deploymentID string
	keyID        string
	key          ed25519.PrivateKey
	clock        func() time.Time
}

func NewCompiler(deploymentID, keyID string, key ed25519.PrivateKey) (*Compiler, error) {
	if deploymentID == "" || keyID == "" || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("policy compiler requires deployment, key id, and Ed25519 signing key")
	}
	return &Compiler{deploymentID: deploymentID, keyID: keyID, key: key, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func Validate(profile *antiflockv1.ProtectionProfile) []*antiflockv1.PolicyViolation {
	var violations []*antiflockv1.PolicyViolation
	add := func(code, field, message string) {
		violations = append(violations, &antiflockv1.PolicyViolation{ReasonCode: code, Field: field, SafeMessage: message})
	}
	if profile == nil {
		add("AF-POLICY-REQUIRED", "profile", "A protection profile is required.")
		return violations
	}
	if proto.Size(profile) > 256*1024 || model.RejectUnknownFields(profile) != nil {
		add("AF-POLICY-WIRE-INVALID", "profile", "The profile contains unsupported or oversized wire data.")
		return violations
	}
	if profile.Metadata == nil || profile.Metadata.Id == "" || profile.Metadata.Revision == 0 {
		add("AF-POLICY-METADATA", "metadata", "Policy id and positive revision are required.")
	}
	if profile.ApiVersion != policyAPIVersion {
		add("AF-POLICY-VERSION", "apiVersion", "The policy API version is unsupported.")
	}
	if profile.Mode != antiflockv1.ProtectionMode_PROTECTION_MODE_GUARD {
		add("AF-POLICY-MODE", "mode", "The first release requires Guard mode.")
	}
	if profile.Mesh == nil || !profile.Mesh.Required {
		add("AF-POLICY-MESH", "mesh.required", "The private mesh must be required.")
	} else if !slices.Contains([]string{"auto", "tailscale", "headscale", "wireguard"}, NormalizeDestination(profile.Mesh.Provider)) {
		add("AF-POLICY-MESH-PROVIDER", "mesh.provider", "A supported private-mesh provider is required.")
	}
	if profile.Egress == nil || profile.Egress.FailMode != antiflockv1.FailMode_FAIL_MODE_CLOSED {
		add("AF-POLICY-FAIL-CLOSED", "egress.failMode", "Protected egress must fail closed.")
	} else {
		if profile.Egress.Mode != antiflockv1.EgressMode_EGRESS_MODE_MESH && profile.Egress.Mode != antiflockv1.EgressMode_EGRESS_MODE_TRUSTED_EXIT {
			add("AF-POLICY-EGRESS", "egress.mode", "Protected egress must use the mesh or an approved exit.")
		}
		if profile.Egress.Mode == antiflockv1.EgressMode_EGRESS_MODE_TRUSTED_EXIT && !validUniqueValues(profile.Egress.AllowedExitNodeIds, 1, 32, 128) {
			add("AF-POLICY-EXITS", "egress.allowedExitNodeIds", "Trusted-exit mode requires a bounded, unique approved-exit list.")
		}
		if len(profile.Egress.RecoveryDestinations) == 0 || len(profile.Egress.RecoveryDestinations) > 32 {
			add("AF-POLICY-RECOVERY", "egress.recoveryDestinations", "A bounded recovery allowlist is required.")
		} else if !validUniqueValues(profile.Egress.RecoveryDestinations, 1, 32, 512) {
			add("AF-POLICY-RECOVERY-VALUES", "egress.recoveryDestinations", "Recovery destinations must be non-empty, unique, and bounded.")
		}
	}
	if profile.Dns == nil || profile.Dns.Mode != antiflockv1.DnsMode_DNS_MODE_PROTECTED || !profile.Dns.RequirePathVerification {
		add("AF-POLICY-DNS", "dns", "DNS must use and verify the protected path.")
	} else if !validUniqueValues(profile.Dns.AllowedResolvers, 1, 16, 512) {
		add("AF-POLICY-DNS-RESOLVERS", "dns.allowedResolvers", "Protected DNS requires a bounded, unique approved-resolver list.")
	}
	if profile.Networks == nil || !profile.Networks.RequireMeshOnUntrusted || !profile.Networks.BlockOpenWifiWithoutMesh {
		add("AF-POLICY-UNTRUSTED", "networks", "Untrusted networks must require the mesh and block open Wi-Fi without it.")
	}
	if profile.Telemetry == nil || profile.Telemetry.PayloadCapture || profile.Telemetry.RetentionDays == 0 || profile.Telemetry.RetentionDays > 30 {
		add("AF-POLICY-TELEMETRY", "telemetry", "Telemetry must disable payload capture and retain metadata for 1 to 30 days.")
	}
	if profile.Scrambler != nil && profile.Scrambler.Enabled {
		add("AF-POLICY-SCRAMBLER-DEFERRED", "scrambler.enabled", "Scrambler execution is not enabled in the locked release.")
	}
	if len(profile.Actions) == 0 {
		add("AF-POLICY-ACTIONS", "actions", "At least one protected action policy is required.")
	}
	for index, action := range profile.Actions {
		if action == nil || !action.RequireProtectedState ||
			!validUniqueValues(action.GetApplicationIds(), 1, 32, 128) ||
			!validUniqueValues(action.GetDataClasses(), 1, 32, 128) {
			add("AF-POLICY-ACTION-SCOPE", fmt.Sprintf("actions[%d]", index), "Each action policy needs applications, data classes, and protected-state enforcement.")
		}
	}
	sort.Slice(violations, func(left, right int) bool {
		if violations[left].Field == violations[right].Field {
			return violations[left].ReasonCode < violations[right].ReasonCode
		}
		return violations[left].Field < violations[right].Field
	})
	return violations
}

func validUniqueValues(values []string, minimum, maximum, maximumLength int) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > maximumLength || strings.TrimSpace(value) != value {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (compiler *Compiler) Compile(profile *antiflockv1.ProtectionProfile, nodeID string, planRevision uint64, capabilities *antiflockv1.CapabilityManifest) (*antiflockv1.Plan, []*antiflockv1.PolicyViolation, error) {
	violations := Validate(profile)
	if len(violations) != 0 {
		return nil, violations, nil
	}
	if compiler == nil || nodeID == "" || planRevision == 0 || capabilities == nil || capabilities.NodeId != nodeID {
		return nil, nil, errors.New("compiler, node, revision, and node-bound capabilities are required")
	}
	requirements := []*antiflockv1.CapabilityRequirement{
		requirement("firewall.egress.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		requirement("mesh.path.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
		requirement("network.route.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
		requirement("dns.protected.enforce", antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK),
	}
	for _, required := range requirements {
		if !supports(capabilities, required) {
			violations = append(violations, &antiflockv1.PolicyViolation{
				ReasonCode: "AF-CAPABILITY-MISSING", Field: "capabilities." + required.Key,
				SafeMessage: "The target node cannot safely enforce and roll back this plan.",
			})
		}
	}
	if len(violations) != 0 {
		return nil, violations, nil
	}
	now := compiler.clock().UTC()
	policyID := profile.Metadata.Id
	nonce := deriveNonce(compiler.key.Seed(), policyID, nodeID, profile.Metadata.Revision, planRevision)
	plan := &antiflockv1.Plan{
		Id:           deterministicPlanID(policyID, nodeID, profile.Metadata.Revision, planRevision),
		DeploymentId: compiler.deploymentID, NodeId: nodeID, PolicyId: policyID,
		PolicyRevision: profile.Metadata.Revision, Revision: planRevision, Nonce: nonce,
		CreatedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(5 * time.Minute)),
		Status:            antiflockv1.PlanStatus_PLAN_STATUS_SIGNED,
		RecoveryAllowlist: append([]string(nil), profile.Egress.RecoveryDestinations...),
		Sensitivity:       antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
	}
	plan.Preconditions = []*antiflockv1.PlanCheck{
		check("preflight-current-state", antiflockv1.CheckPhase_CHECK_PHASE_PRECONDITION, "state.capture", "Capture rollback state before mutation.", true, requirements),
	}
	plan.Actions = []*antiflockv1.PlanOperation{
		operation("guard-egress", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, "protected-egress", "Hold protected egress before changing the route.", requirements[0], map[string]any{
			"allowedDestinations":  stringListValue(profile.Egress.AllowedDestinations),
			"recoveryDestinations": stringListValue(profile.Egress.RecoveryDestinations),
		}),
		operation("connect-mesh", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_MESH, NormalizeDestination(profile.Mesh.Provider), "Connect the approved private mesh.", requirements[1], nil),
		operation("set-route", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_ROUTE, "approved-egress", "Select an approved protected route.", requirements[2], map[string]any{
			"allowedExitNodeIds": stringListValue(profile.Egress.AllowedExitNodeIds),
		}),
		operation("set-dns", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_DNS, "protected-dns", "Use DNS through the protected path.", requirements[3], map[string]any{
			"allowedResolvers": stringListValue(profile.Dns.AllowedResolvers),
		}),
	}
	plan.Verifications = []*antiflockv1.PlanCheck{
		check("verify-mesh", antiflockv1.CheckPhase_CHECK_PHASE_VERIFICATION, "mesh.connected", "Verify mesh connectivity.", true, requirements[1:2]),
		check("verify-route", antiflockv1.CheckPhase_CHECK_PHASE_VERIFICATION, "route.egress", "Verify the approved exit from the endpoint.", true, requirements[2:3]),
		check("verify-dns", antiflockv1.CheckPhase_CHECK_PHASE_VERIFICATION, "dns.path", "Verify DNS uses the protected path.", true, requirements[3:4]),
	}
	plan.Rollback = []*antiflockv1.PlanOperation{
		operation("rollback-dns", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_DNS, "captured:dns", "Restore captured DNS state.", requirements[3], nil),
		operation("rollback-route", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_ROUTE, "captured:route", "Restore captured route state.", requirements[2], nil),
		operation("rollback-firewall", antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL, "captured:firewall", "Restore captured firewall state.", requirements[0], nil),
	}
	plan.HumanReadableDryRun = "Hold protected egress; connect the private mesh; select and verify the approved exit; verify protected DNS; roll back captured state on any failure."
	if err := signPlan(plan, compiler.keyID, compiler.key, now); err != nil {
		return nil, nil, err
	}
	return plan, nil, nil
}

func requirement(key string, operations ...antiflockv1.CapabilityOperation) *antiflockv1.CapabilityRequirement {
	return &antiflockv1.CapabilityRequirement{Key: key, RequiredOperations: operations, MinimumSupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL}
}

func supports(manifest *antiflockv1.CapabilityManifest, requirement *antiflockv1.CapabilityRequirement) bool {
	for _, capability := range manifest.Capabilities {
		if capability == nil || capability.Key != requirement.Key || capability.SupportLevel != antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL {
			continue
		}
		for _, operation := range requirement.RequiredOperations {
			if !slices.Contains(capability.Operations, operation) {
				return false
			}
		}
		return true
	}
	return false
}

func operation(id string, kind antiflockv1.PlanOperationType, target, description string, requirement *antiflockv1.CapabilityRequirement, values map[string]any) *antiflockv1.PlanOperation {
	parametersMap := map[string]any{"simulation": false, "failMode": "CLOSED"}
	for key, value := range values {
		parametersMap[key] = value
	}
	parameters, _ := structpb.NewStruct(parametersMap)
	return &antiflockv1.PlanOperation{Id: id, Type: kind, Target: target, Description: description, Parameters: parameters, Timeout: durationpb.New(15 * time.Second), RequiredCapabilities: []*antiflockv1.CapabilityRequirement{requirement}}
}

func stringListValue(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func check(id string, phase antiflockv1.CheckPhase, kind, description string, required bool, requirements []*antiflockv1.CapabilityRequirement) *antiflockv1.PlanCheck {
	parameters, _ := structpb.NewStruct(map[string]any{"source": "endpoint"})
	return &antiflockv1.PlanCheck{Id: id, Phase: phase, CheckType: kind, Description: description, Parameters: parameters, Required: required, Timeout: durationpb.New(10 * time.Second), RequiredCapabilities: requirements}
}

func deriveNonce(key []byte, policyID, nodeID string, policyRevision, planRevision uint64) []byte {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "AntiFlock-Plan-Nonce-v1\x00%s\x00%s\x00%d\x00%d", policyID, nodeID, policyRevision, planRevision)
	return mac.Sum(nil)
}

func deterministicPlanID(policyID, nodeID string, policyRevision, planRevision uint64) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("AntiFlock-Plan-ID-v1\x00%s\x00%s\x00%d\x00%d", policyID, nodeID, policyRevision, planRevision)))
	return fmt.Sprintf("plan_%x", digest[:16])
}

func signPlan(plan *antiflockv1.Plan, keyID string, key ed25519.PrivateKey, signedAt time.Time) error {
	view := proto.Clone(plan).(*antiflockv1.Plan)
	view.Signature = nil
	view.Status = antiflockv1.PlanStatus_PLAN_STATUS_UNSPECIFIED
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	if err != nil {
		return fmt.Errorf("encode signable plan: %w", err)
	}
	digest := sha256.Sum256(encoded)
	signature := &antiflockv1.Signature{
		KeyId: keyID, Algorithm: antiflockv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
		SignedAt: timestamppb.New(signedAt), Encoding: antiflockv1.SignatureEncoding_SIGNATURE_ENCODING_PROTOBUF_DETERMINISTIC_V1,
		SignedContentDigest: &antiflockv1.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]}, Domain: planDomain,
	}
	input, err := signatureInput(signature)
	if err != nil {
		return err
	}
	signature.Value = ed25519.Sign(key, input)
	plan.Signature = signature
	return nil
}

func VerifyPlan(plan *antiflockv1.Plan, publicKey ed25519.PublicKey, now time.Time) error {
	if plan == nil || plan.Signature == nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("plan and Ed25519 verification key are required")
	}
	if plan.ExpiresAt == nil || plan.ExpiresAt.CheckValid() != nil || !plan.ExpiresAt.AsTime().After(now) || plan.CreatedAt == nil || plan.CreatedAt.CheckValid() != nil || plan.CreatedAt.AsTime().After(now.Add(5*time.Minute)) {
		return errors.New("plan is expired or has invalid timestamps")
	}
	view := proto.Clone(plan).(*antiflockv1.Plan)
	signature := view.Signature
	view.Signature = nil
	view.Status = antiflockv1.PlanStatus_PLAN_STATUS_UNSPECIFIED
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if !hmac.Equal(digest[:], signature.SignedContentDigest.GetDigest()) {
		return errors.New("plan signed-content digest mismatch")
	}
	input, err := signatureInput(signature)
	if err != nil || !ed25519.Verify(publicKey, input, signature.Value) {
		return errors.New("plan signature verification failed")
	}
	return nil
}

func signatureInput(signature *antiflockv1.Signature) ([]byte, error) {
	if signature == nil || signature.Algorithm != antiflockv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519 || signature.Encoding != antiflockv1.SignatureEncoding_SIGNATURE_ENCODING_PROTOBUF_DETERMINISTIC_V1 || signature.Domain != planDomain || signature.SignedAt == nil || signature.SignedAt.CheckValid() != nil || signature.SignedContentDigest == nil || signature.SignedContentDigest.Algorithm != "sha256" || len(signature.SignedContentDigest.Digest) != sha256.Size {
		return nil, errors.New("unsupported plan signature profile")
	}
	algorithm := make([]byte, 4)
	binary.BigEndian.PutUint32(algorithm, uint32(signature.Algorithm))
	seconds := make([]byte, 8)
	binary.BigEndian.PutUint64(seconds, uint64(signature.SignedAt.AsTime().Unix()))
	nanoseconds := make([]byte, 4)
	binary.BigEndian.PutUint32(nanoseconds, uint32(signature.SignedAt.AsTime().Nanosecond()))
	fields := [][]byte{[]byte(signaturePrefix), []byte(signature.Domain), algorithm, []byte("sha256"), signature.SignedContentDigest.Digest, seconds, nanoseconds}
	var result []byte
	for _, field := range fields {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(field)))
		result = append(result, length...)
		result = append(result, field...)
	}
	return result, nil
}

func NormalizeDestination(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
