//go:build !linux

package collectors

import (
	"testing"
	"time"
)

func TestNonLinuxFlowCollectionIsExplicitlyUnsupported(t *testing.T) {
	collector := &LinuxCollector{config: LinuxConfig{IncludeFlowMetadata: true}}
	flows, reasons := collector.collectFlows(time.Now().UTC())
	if len(flows) != 0 || len(reasons) != 1 || reasons[0] != "AF-COLLECTOR-FLOW-UNSUPPORTED" {
		t.Fatalf("non-Linux flow collection = flows=%#v reasons=%#v", flows, reasons)
	}
}
