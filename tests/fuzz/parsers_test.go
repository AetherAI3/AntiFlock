// Package fuzz holds stdlib fuzz targets (testing.F) for every parser and
// verifier that consumes bytes from outside the trust boundary. Seed corpora
// are inline so `go test ./tests/...` replays them in well under a minute
// without -fuzz; `node scripts/verify.mjs --section adversarial` runs each
// target under -fuzz for a bounded -fuzztime.
//
// Every target asserts the same two properties: the code never panics, and
// whenever it accepts an input the accepted value satisfies the package's own
// documented invariants (sorted, unique, bounded, signature-bound).
package fuzz_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/adapters/mesh/headscale"
	"github.com/DBarr3/AntiFlock/agent/collectors"
	"github.com/DBarr3/AntiFlock/internal/model"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
)

type bodyDoer []byte

func (body bodyDoer) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
}

func FuzzHeadscaleListNodes(f *testing.F) {
	seeds := []string{
		`{"nodes":[]}`,
		`{"nodes":[{"id":"1","nodeKey":"k","online":true,"ipAddresses":["100.64.0.1"]}]}`,
		`{"nodes":[{"id":1,"nodeKey":"k"},{"id":"2","nodeKey":"z"}]}`,
		`{"nodes":[{"id":"1","nodeKey":"a"},{"id":1,"nodeKey":"b"}]}`,
		`{"nodes":[{"id":" 1","nodeKey":"k"}]}`,
		`{"nodes":[{"id":-1}]}`,
		`{"nodes":[]} {}`,
		`[[[[[[[[[[`,
		``,
		`{"nodes":[{"id":"1","nodeKey":"k","ipAddresses":["::1","not-ip","100.64.0.1","100.64.0.1"]}]}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		client, err := headscale.NewClient(headscale.Config{
			BaseURL: "https://headscale.example", APIKey: "fuzz-key", HTTPClient: bodyDoer(body),
			ProviderAssociations: map[string]string{"1": "node-a", "k": "node-a"}, IncludeAddresses: true, MaximumResponseBytes: 64 << 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := client.ListNodes(context.Background(), time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
		if err != nil {
			if len(body) >= 16 && strings.Contains(err.Error(), string(body)) {
				t.Fatalf("error echoes response body: %v", err)
			}
			return
		}
		seen := map[string]bool{}
		for index, peer := range snapshot.Peers {
			if peer.GetProviderPeerId() == "" || seen[peer.GetProviderPeerId()] {
				t.Fatalf("accepted snapshot has empty or duplicate peer id at %d", index)
			}
			seen[peer.GetProviderPeerId()] = true
			if index > 0 && snapshot.Peers[index-1].GetProviderPeerId() >= peer.GetProviderPeerId() {
				t.Fatal("accepted snapshot is not sorted")
			}
			if peer.GetConnectionType() != antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_UNKNOWN && peer.GetConnectionType() != antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DISCONNECTED {
				t.Fatalf("control-plane data upgraded to %v", peer.GetConnectionType())
			}
			if peer.GetAuthorized() != (peer.GetNodeId() != "") {
				t.Fatal("authorized without association")
			}
			if !sort.StringsAreSorted(peer.GetMeshAddresses()) {
				t.Fatal("addresses not sorted")
			}
		}
	})
}

type memoryFiles map[string][]byte

func (files memoryFiles) ReadFile(path string) ([]byte, error) {
	if content, ok := files[path]; ok {
		return content, nil
	}
	return nil, io.ErrUnexpectedEOF
}

func collectorFor(t *testing.T, files memoryFiles, flows bool) *collectors.LinuxCollector {
	t.Helper()
	collector, err := collectors.NewLinuxCollector(collectors.LinuxConfig{
		NodeID: "node", BootID: "boot", RouteTablePath: "route", ResolvConfPath: "resolv",
		TCPTablePath: "tcp", TCP6TablePath: "tcp6", UDPTablePath: "udp", UDP6TablePath: "udp6",
		IncludeFlowMetadata: flows, IncludeSearchDomains: true, IncludeNonDefaultRoutes: true,
		Clock: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) },
		Files: files, Interfaces: emptyInterfaces{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func FuzzRouteTable(f *testing.F) {
	header := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	seeds := []string{
		header,
		header + "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
		header + "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
		header + "eth0\t00000000\t0100A8C0\n",
		header + "eth0\tZZZZZZZZ\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
		header + "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t0000FF0F\t0\t0\t0\n",
		"no header\n",
		"",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		collection, err := collectorFor(t, memoryFiles{"route": content, "resolv": []byte("nameserver 9.9.9.9\n")}, false).Collect(context.Background())
		if err != nil {
			t.Fatalf("collect must not fail on route input: %v", err)
		}
		invalid := false
		for _, reason := range collection.HealthReasonCodes {
			if strings.HasPrefix(reason, "AF-COLLECTOR-ROUTE-") {
				invalid = true
			}
		}
		routes := collection.Snapshot.GetRoutes()
		if invalid && len(routes) != 0 {
			t.Fatalf("routes emitted alongside a route reason code: %v", collection.HealthReasonCodes)
		}
		for index, route := range routes {
			if route.GetRouteId() == "" || !strings.HasPrefix(route.GetInterfaceId(), "if_") || !strings.Contains(route.GetDestination(), "/") {
				t.Fatalf("accepted route is not canonical: %v", route)
			}
			if index > 0 && routes[index-1].GetRouteId() >= route.GetRouteId() {
				t.Fatal("routes not sorted")
			}
		}
	})
}

func FuzzResolvConf(f *testing.F) {
	seeds := []string{
		"nameserver 9.9.9.9\n",
		"nameserver 9.9.9.9\nsearch example.internal corp\ndomain x\n",
		"nameserver evil.example\n",
		"nameserver 9.9.9.9 1.1.1.1\n",
		"search ../../etc\n",
		"nameserver 9.9.9.9 # nameserver 1.1.1.1\n",
		"# only comments\n",
		"",
		"nameserver ::1\nnameserver 127.0.0.1\nnameserver 127.0.0.1\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		collection, err := collectorFor(t, memoryFiles{"route": []byte("Iface\tDestination\n"), "resolv": content}, false).Collect(context.Background())
		if err != nil {
			t.Fatalf("collect must not fail on resolv input: %v", err)
		}
		dns := collection.Snapshot.GetDns()
		if dns == nil {
			return
		}
		if !sort.StringsAreSorted(dns.GetResolverAddresses()) || !sort.StringsAreSorted(dns.GetSearchDomains()) {
			t.Fatal("dns lists not sorted")
		}
		for _, resolver := range dns.GetResolverAddresses() {
			if strings.ContainsAny(resolver, " \t\r\n#") {
				t.Fatalf("resolver is not a literal address: %q", resolver)
			}
		}
		for _, domain := range dns.GetSearchDomains() {
			if len(domain) > 253 || strings.ContainsAny(domain, "\x00/\\") || domain != strings.ToLower(domain) {
				t.Fatalf("search domain is not canonical: %q", domain)
			}
		}
		if dns.GetPathVerified() {
			t.Fatal("resolv.conf parsing claimed a verified path")
		}
	})
}

func FuzzSocketTable(f *testing.F) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	seeds := []string{
		header,
		header + "   0: 0100007F:1F90 0200A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n",
		header + "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n",
		header + "   0: 00000000000000000000000001000000:1F90 00000000000000000000000001000000:01BB 01\n",
		header + "   0: 0100007F:1F90\n",
		header + "   0: ZZZZZZZZ:1F90 0200A8C0:01BB 01\n",
		header + "   0: 0100007F:1F90 0200A8C0:FFFFF 01\n",
		"",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		collection, err := collectorFor(t, memoryFiles{"route": []byte("Iface\tDestination\n"), "resolv": []byte("nameserver 9.9.9.9\n"), "tcp": content, "tcp6": content, "udp": content, "udp6": content}, true).Collect(context.Background())
		if err != nil {
			t.Fatalf("collect must not fail on socket input: %v", err)
		}
		for _, flow := range collection.Snapshot.GetFlows() {
			if flow.GetRemote().GetPort() == 0 || flow.GetRemote().GetAddress() == "" {
				t.Fatalf("accepted flow without a remote endpoint: %v", flow)
			}
			if flow.GetProcess().GetProcessId() != "" || flow.GetProcess().GetExecutableName() != "" {
				t.Fatalf("flow carries process attribution: %v", flow)
			}
			if flow.GetSensitivity() != antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE {
				t.Fatalf("flow sensitivity downgraded: %v", flow.GetSensitivity())
			}
		}
		if len(collection.Snapshot.GetFlows()) > 2048 {
			t.Fatal("flow cap exceeded")
		}
	})
}

func FuzzRejectUnknownFields(f *testing.F) {
	manifest, _ := proto.Marshal(&antiflockv1.CapabilityManifest{NodeId: "node", Capabilities: []*antiflockv1.Capability{{Key: "k", SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL}}})
	event, _ := proto.Marshal(&antiflockv1.EventEnvelope{Id: "e", NodeId: "node", Sequence: 1})
	for _, seed := range [][]byte{manifest, event, {0x08, 0x01}, {0xff, 0xff}, {}, {0xfa, 0xff, 0xff, 0xff, 0x0f, 0x01}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		for _, message := range []proto.Message{&antiflockv1.CapabilityManifest{}, &antiflockv1.Plan{}, &antiflockv1.EventEnvelope{}, &antiflockv1.PlanExecutionResult{}} {
			if err := proto.Unmarshal(wire, message); err != nil {
				continue
			}
			err := model.RejectUnknownFields(message)
			if len(message.ProtoReflect().GetUnknown()) != 0 && err == nil {
				t.Fatalf("unknown bytes survived RejectUnknownFields for %T", message)
			}
		}
	})
}
