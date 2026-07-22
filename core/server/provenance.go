package server

import (
	"strings"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
)

type evidenceProvenance string

const (
	provenanceUnknown    evidenceProvenance = "UNKNOWN"
	provenanceLive       evidenceProvenance = "LIVE"
	provenanceSimulation evidenceProvenance = "SIMULATION"
)

// nodeEvidenceProvenance derives a safety restriction from the immutable
// enrollment profile. A claimed simulation restriction is honored even when
// capabilities have not been independently verified because doing so only
// reduces what the node may authorize.
func nodeEvidenceProvenance(node model.Node) evidenceProvenance {
	if strings.EqualFold(node.PlatformVersion, "simulation") {
		return provenanceSimulation
	}
	var manifest antiflockv1.CapabilityManifest
	if len(node.Capabilities) == 0 || protojson.Unmarshal(node.Capabilities, &manifest) != nil {
		return provenanceUnknown
	}
	for _, capability := range manifest.GetCapabilities() {
		if capability == nil {
			continue
		}
		if strings.EqualFold(capability.GetImplementation(), "antiflock-sim") {
			return provenanceSimulation
		}
		for _, constraint := range capability.GetConstraints() {
			if strings.EqualFold(constraint, "simulation-only") || strings.EqualFold(constraint, "no-host-mutation") {
				return provenanceSimulation
			}
		}
	}
	return provenanceLive
}

func enrollmentEvidenceProvenance(platformVersion string, manifest *antiflockv1.CapabilityManifest) evidenceProvenance {
	if strings.EqualFold(platformVersion, "simulation") {
		return provenanceSimulation
	}
	if manifest == nil {
		return provenanceUnknown
	}
	for _, capability := range manifest.GetCapabilities() {
		if capability == nil {
			continue
		}
		if strings.EqualFold(capability.GetImplementation(), "antiflock-sim") {
			return provenanceSimulation
		}
		for _, constraint := range capability.GetConstraints() {
			if strings.EqualFold(constraint, "simulation-only") || strings.EqualFold(constraint, "no-host-mutation") {
				return provenanceSimulation
			}
		}
	}
	return provenanceLive
}

func eventEvidenceProvenance(event model.EventEnvelope, node model.Node) evidenceProvenance {
	nodeProvenance := nodeEvidenceProvenance(node)
	if nodeProvenance != provenanceLive {
		return nodeProvenance
	}
	for _, evidence := range event.Evidence {
		if value, exists := evidence.Attributes["simulation"]; exists {
			switch {
			case strings.EqualFold(value, "true"):
				return provenanceSimulation
			case !strings.EqualFold(value, "false"):
				return provenanceUnknown
			}
		}
		if strings.HasPrefix(strings.ToLower(evidence.Attributes["methodId"]), "antiflock.simulation.") {
			return provenanceSimulation
		}
	}
	return provenanceLive
}

func mergeEvidenceProvenance(left, right evidenceProvenance) evidenceProvenance {
	if left == provenanceSimulation || right == provenanceSimulation {
		return provenanceSimulation
	}
	if left == provenanceUnknown || right == provenanceUnknown {
		return provenanceUnknown
	}
	return provenanceLive
}
