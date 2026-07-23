package collectors

import (
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

func TestParseProcSocketTableCollectsMetadataOnlyConnectedSocket(t *testing.T) {
	content := []byte("  sl  local_address rem_address   st\n   0: 0100007F:1F90 08080808:0035 01\n   1: 00000000:0016 00000000:0000 0A\n")
	flows, err := parseProcSocketTable(content, antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP, "tcp", time.Now().UTC(), 8)
	if err != nil { t.Fatal(err) }
	if len(flows) != 1 { t.Fatalf("flows = %#v", flows) }
	flow := flows[0]
	if flow.Local.Address != "127.0.0.1" || flow.Local.Port != 8080 || flow.Remote.Address != "8.8.8.8" || flow.Remote.Port != 53 {
		t.Fatalf("unexpected endpoints: %#v", flow)
	}
	if flow.GetStartedAt() != nil || flow.GetEndedAt() != nil || flow.GetBytesSent() != 0 || flow.GetBytesReceived() != 0 {
		t.Fatal("socket table collector invented timing or traffic data")
	}
	if flow.GetProcess().GetAttributionQuality() != antiflockv1.ProcessAttributionQuality_PROCESS_ATTRIBUTION_QUALITY_UNAVAILABLE {
		t.Fatal("socket table collector claimed process attribution")
	}
}

func TestParseProcSocketTableRejectsMalformedRows(t *testing.T) {
	if _, err := parseProcSocketTable([]byte("sl local_address\n0: malformed\n"), antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP, "tcp", time.Now(), 1); err == nil {
		t.Fatal("malformed socket table was accepted")
	}
}
