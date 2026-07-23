//go:build !linux

package collectors

import (
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// collectFlows keeps the common collector buildable outside Linux while making
// the unsupported capability explicit. It never substitutes another socket,
// packet, process, or provider inspection mechanism.
func (_ *LinuxCollector) collectFlows(_ time.Time) ([]*antiflockv1.FlowObservation, []string) {
	return nil, []string{"AF-COLLECTOR-FLOW-UNSUPPORTED"}
}
