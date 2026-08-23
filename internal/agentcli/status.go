package agentcli

import (
	"errors"
	"os"
	"time"

	agentruntime "github.com/DBarr3/AntiFlock/agent/runtime"
)

// DriverReadiness is one enforcement domain's readiness as the CLI can
// currently prove it. Until the driver and recovery packages are wired into
// this binary every domain is UNAVAILABLE with an exact reason.
type DriverReadiness struct {
	Domain     string `json:"domain"`
	State      string `json:"state"`
	ReasonCode string `json:"reasonCode"`
	Detail     string `json:"detail"`
}

// StatusResult is the read-only status payload. It never contains seeds,
// certificates, tokens, or queued telemetry.
type StatusResult struct {
	NodeID             string            `json:"nodeId"`
	ConfigPath         string            `json:"configPath"`
	ConfigDigest       string            `json:"configDigest"`
	KeyID              string            `json:"keyId,omitempty"`
	Enrollment         string            `json:"enrollment"`
	LastQueueWriteAt   string            `json:"lastQueueWriteAt,omitempty"`
	LastObservationAt  string            `json:"lastObservationAt,omitempty"`
	QueueDepth         int               `json:"queueDepth"`
	QueueLastSequence  uint64            `json:"queueLastSequence"`
	QueueMaximumEvents int               `json:"queueMaximumEvents"`
	Drivers            []DriverReadiness `json:"drivers"`
}

// UnwiredDrivers is the honest placeholder table: no domain is wired into
// this binary yet, and status must never collapse that into one green.
func UnwiredDrivers() []DriverReadiness {
	detail := "No enforcement driver is registered in this binary; readiness cannot be computed."
	domains := []string{"firewall", "mesh", "route", "dns"}
	drivers := make([]DriverReadiness, 0, len(domains)+1)
	for _, domain := range domains {
		drivers = append(drivers, DriverReadiness{Domain: domain, State: "UNAVAILABLE", ReasonCode: "AF-STATUS-DRIVER-NOT-WIRED", Detail: detail})
	}
	return append(drivers, DriverReadiness{Domain: "recovery", State: "UNAVAILABLE", ReasonCode: "AF-STATUS-RECOVERY-NOT-WIRED", Detail: "No independently verified host recovery path is registered in this binary."})
}

// IdentityFunc reports the enrollment identity state of a state directory.
// cmd/antiflock-agent supplies its existing localIdentityStatus.
type IdentityFunc func(stateDir string) string

// Status collects the read-only summary. Exit 0 when key and queue are
// usable, 7 (degraded) when either is missing, 3 when the config is unusable.
func Status(configPath string, identity IdentityFunc) (StatusResult, []Reason, int) {
	config, digest, err := LoadConfig(configPath)
	if err != nil {
		return StatusResult{}, []Reason{{Code: "AF-STATUS-CONFIG-INVALID", Message: err.Error()}}, ExitPrecondition
	}
	result := StatusResult{NodeID: config.NodeID, ConfigPath: configPath, ConfigDigest: digest, Drivers: UnwiredDrivers(), Enrollment: "unknown"}
	reasons := []Reason{}
	if identity != nil {
		result.Enrollment = identity(config.StateDir)
	}
	if keyID, err := KeyID(config.KeyPath()); err == nil {
		result.KeyID = keyID
	} else {
		reasons = append(reasons, Reason{Code: "AF-STATUS-KEY-UNAVAILABLE", Message: err.Error()})
	}
	queue, err := agentruntime.InspectQueue(config.QueueDir, config.NodeID)
	if err != nil {
		reasons = append(reasons, Reason{Code: "AF-STATUS-QUEUE-UNAVAILABLE", Message: safeError(err)})
	} else {
		result.QueueDepth, result.QueueLastSequence, result.QueueMaximumEvents = queue.RetainedEvents, queue.LastSequence, queue.MaximumEvents
	}
	if info, err := os.Lstat(config.QueueFile()); err == nil && info.Mode().IsRegular() {
		result.LastQueueWriteAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	// The observe loop does not record a completion marker yet; the queue
	// file's last write is the closest durable evidence and is labelled as such.
	reasons = append(reasons, Reason{Code: "AF-STATUS-OBSERVATION-NOT-RECORDED", Message: "last observation time is not recorded by the observe loop; lastQueueWriteAt is the nearest durable evidence"})
	reasons = append(reasons, Reason{Code: "AF-STATUS-DRIVER-NOT-WIRED", Message: "enforcement drivers are not wired into this binary; all domains are UNAVAILABLE"})
	if result.KeyID == "" || result.QueueMaximumEvents == 0 {
		return result, reasons, ExitDegraded
	}
	return result, reasons, ExitOK
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, os.ErrNotExist) {
		return "queue directory does not exist"
	}
	return Safe(err.Error())
}
