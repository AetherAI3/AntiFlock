package capability

import (
	"slices"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// Verdict is the independent readiness decision for one requirement.
//
// Axes:
//   - Compatible: the manifest lists the key with a sufficient support level
//     and every required operation. This is what the enforcer's supportsAll
//     used to compute, and nothing more.
//   - DriverReady: Compatible, the entry is current, and the driver reported
//     HEALTHY. DEGRADED, UNAVAILABLE, and UNKNOWN all fail closed.
//   - RecoveryReady: DriverReady and the driver attested a recovery path.
type Verdict struct {
	Key           string
	Compatible    bool
	DriverReady   bool
	RecoveryReady bool
	Health        driver.HealthStatus
	ReasonCodes   []string
}

// Readiness aggregates verdicts. Every All* field is false unless at least
// one requirement was evaluated and every verdict passed that axis. Expired
// reports that the manifest as a whole is outside its validity window.
type Readiness struct {
	Verdicts         []Verdict
	AllCompatible    bool
	AllDriverReady   bool
	AllRecoveryReady bool
	Expired          bool
	// ReasonCodes holds manifest-level codes (schema, expiry, empty
	// requirements). Per-requirement codes live on each Verdict.
	ReasonCodes []string
}

// Evaluate decides, independently per requirement, whether the manifest
// makes the requirement compatible, driver-ready, and recovery-ready at now.
// It never mutates its inputs and never panics on nil entries.
//
// Evaluate does not verify the signature or the node binding: those are
// authentication decisions made by LoadManifestFile (or by the caller via
// Manifest.Verify) before a manifest is handed to Evaluate. A manifest that
// fails Validate is treated as absent: every verdict fails with
// ReasonSchema.
func Evaluate(manifest *Manifest, requirements []*antiflockv1.CapabilityRequirement, now time.Time) Readiness {
	readiness := Readiness{Verdicts: make([]Verdict, 0, len(requirements))}
	if len(requirements) == 0 {
		readiness.ReasonCodes = append(readiness.ReasonCodes, ReasonRequirementInvalid)
		return readiness
	}
	manifestCode := ""
	if err := manifest.Validate(); err != nil {
		manifestCode = ReasonSchema
	} else if !now.Before(manifest.ExpiresAt) {
		manifestCode = ReasonExpired
		readiness.Expired = true
	} else if manifest.IssuedAt.After(now.Add(maxClockSkew)) {
		manifestCode = ReasonNotYetValid
	}
	if manifestCode != "" {
		readiness.ReasonCodes = append(readiness.ReasonCodes, manifestCode)
	}
	for _, requirement := range requirements {
		verdict := Verdict{Key: requirement.GetKey(), Health: driver.HealthUnknown}
		if manifestCode != "" {
			verdict.ReasonCodes = []string{manifestCode}
			readiness.Verdicts = append(readiness.Verdicts, verdict)
			continue
		}
		readiness.Verdicts = append(readiness.Verdicts, evaluateOne(manifest, requirement, now))
	}
	readiness.AllCompatible = manifestCode == "" && all(readiness.Verdicts, func(v Verdict) bool { return v.Compatible })
	readiness.AllDriverReady = manifestCode == "" && all(readiness.Verdicts, func(v Verdict) bool { return v.DriverReady })
	readiness.AllRecoveryReady = manifestCode == "" && all(readiness.Verdicts, func(v Verdict) bool { return v.RecoveryReady })
	return readiness
}

// maxClockSkew bounds how far in the future a manifest's issued-at may lie.
const maxClockSkew = 5 * time.Minute

func all(verdicts []Verdict, predicate func(Verdict) bool) bool {
	if len(verdicts) == 0 {
		return false
	}
	for _, verdict := range verdicts {
		if !predicate(verdict) {
			return false
		}
	}
	return true
}

func evaluateOne(manifest *Manifest, requirement *antiflockv1.CapabilityRequirement, now time.Time) Verdict {
	verdict := Verdict{Key: requirement.GetKey(), Health: driver.HealthUnknown}
	if !validRequirement(requirement) {
		verdict.ReasonCodes = []string{ReasonRequirementInvalid}
		return verdict
	}
	index := slices.IndexFunc(manifest.Capabilities, func(entry Entry) bool { return entry.Key == requirement.Key })
	if index < 0 {
		verdict.ReasonCodes = []string{ReasonMissing}
		return verdict
	}
	probe := manifest.Capabilities[index].Probe()
	verdict.Health = probe.Health

	compatible := true
	if !supportSatisfies(probe.SupportLevel, requirement.MinimumSupportLevel) {
		compatible = false
		verdict.ReasonCodes = append(verdict.ReasonCodes, ReasonSupportLevel)
	}
	for _, operation := range requirement.RequiredOperations {
		if !slices.Contains(probe.Operations, operation) {
			compatible = false
			verdict.ReasonCodes = append(verdict.ReasonCodes, ReasonOperationMissing)
			break
		}
	}
	verdict.Compatible = compatible

	current := true
	if probe.Expired(now) {
		current = false
		verdict.ReasonCodes = append(verdict.ReasonCodes, ReasonExpired)
	}
	healthy := false
	switch probe.Health {
	case driver.HealthHealthy:
		healthy = true
	case driver.HealthDegraded:
		verdict.ReasonCodes = append(verdict.ReasonCodes, ReasonHealthDegraded)
	case driver.HealthUnavailable:
		verdict.ReasonCodes = append(verdict.ReasonCodes, ReasonHealthUnavailable)
	default:
		verdict.ReasonCodes = append(verdict.ReasonCodes, ReasonHealthUnknown)
	}
	verdict.DriverReady = compatible && current && healthy
	if !probe.RecoveryReady {
		verdict.ReasonCodes = append(verdict.ReasonCodes, ReasonRecoveryNotReady)
	}
	verdict.RecoveryReady = verdict.DriverReady && probe.RecoveryReady
	if len(verdict.ReasonCodes) == 0 {
		verdict.ReasonCodes = []string{ReasonOK}
	}
	return verdict
}

func validRequirement(requirement *antiflockv1.CapabilityRequirement) bool {
	if requirement == nil || requirement.Key == "" || len(requirement.RequiredOperations) == 0 {
		return false
	}
	if requirement.MinimumSupportLevel == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSPECIFIED ||
		antiflockv1.CapabilitySupportLevel_name[int32(requirement.MinimumSupportLevel)] == "" {
		return false
	}
	for _, operation := range requirement.RequiredOperations {
		if operation == antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_UNSPECIFIED ||
			antiflockv1.CapabilityOperation_name[int32(operation)] == "" {
			return false
		}
	}
	return true
}

// supportSatisfies mirrors the enforcer's support-level lattice so the two
// never disagree: PARTIAL accepts PARTIAL or FULL, FULL accepts only FULL,
// EXPERIMENTAL accepts only EXPERIMENTAL, UNSUPPORTED accepts any specified
// level, and an unspecified minimum never matches.
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
