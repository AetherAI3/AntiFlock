package hostile_test

import (
	"context"
	"errors"
	"net"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/collectors"
)

// fakeFiles serves kernel pseudo-files from memory; the collector never
// touches /proc or /etc in these tests.
type fakeFiles map[string][]byte

func (files fakeFiles) ReadFile(path string) ([]byte, error) {
	content, ok := files[path]
	if !ok {
		return nil, errors.New("fixture: no such file")
	}
	return content, nil
}

type noInterfaces struct{}

func (noInterfaces) Interfaces() ([]net.Interface, error)    { return nil, nil }
func (noInterfaces) Addrs(net.Interface) ([]net.Addr, error) { return nil, nil }

const (
	routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	goodRoute   = routeHeader + "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	goodResolv  = "nameserver 9.9.9.9\nsearch example.internal\n"
	tcpHeader   = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	goodTCP     = tcpHeader + "   0: 0100007F:1F90 0200A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"
)

func collect(t *testing.T, files fakeFiles, flows bool) *collectors.Collection {
	t.Helper()
	collector, err := collectors.NewLinuxCollector(collectors.LinuxConfig{
		NodeID: "node", BootID: "boot", RouteTablePath: "route", ResolvConfPath: "resolv",
		TCPTablePath: "tcp", TCP6TablePath: "tcp6", UDPTablePath: "udp", UDP6TablePath: "udp6",
		IncludeFlowMetadata: flows, IncludeSearchDomains: true,
		Clock: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) },
		Files: files, Interfaces: noInterfaces{},
	})
	if err != nil {
		t.Fatal(err)
	}
	collection, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return collection
}

// Invariant: a malformed route table never yields invented routes. The
// collector reports AF-COLLECTOR-ROUTE-INVALID (or -OVERSIZED) with an empty
// route list instead of a partial or fabricated fact.
func TestRouteTableHostileInputsProduceReasonCodesNotRoutes(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		content []byte
		reason  string
	}{
		"header-missing":       {[]byte("eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"row-truncated":        {[]byte(routeHeader + "eth0\t00000000\t0100A8C0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"destination-not-hex":  {[]byte(routeHeader + "eth0\tZZZZZZZZ\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"destination-too-long": {[]byte(routeHeader + "eth0\t0000000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"flags-not-hex":        {[]byte(routeHeader + "eth0\t00000000\t0100A8C0\tXX\t0\t0\t100\t00000000\t0\t0\t0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"metric-negative":      {[]byte(routeHeader + "eth0\t00000000\t0100A8C0\t0003\t0\t0\t-1\t00000000\t0\t0\t0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"metric-overflow":      {[]byte(routeHeader + "eth0\t00000000\t0100A8C0\t0003\t0\t0\t99999999999\t00000000\t0\t0\t0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"mask-non-contiguous":  {[]byte(routeHeader + "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t0000FF0F\t0\t0\t0\n"), "AF-COLLECTOR-ROUTE-INVALID"},
		"oversized":            {[]byte(routeHeader + strings.Repeat("eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", 40000)), "AF-COLLECTOR-ROUTE-OVERSIZED"},
		"nul-bytes":            {[]byte(routeHeader + "eth0\x00\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"), ""},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			collection := collect(t, fakeFiles{"route": testCase.content, "resolv": []byte(goodResolv)}, false)
			if testCase.reason == "" {
				// The interface name is hashed into an opaque id, so a NUL byte
				// cannot reach structured output. Assert that, rather than rejection.
				routes := collection.Snapshot.GetRoutes()
				if len(routes) != 1 || !strings.HasPrefix(routes[0].GetInterfaceId(), "if_") || strings.ContainsAny(routes[0].GetInterfaceId(), "\x00\t") {
					t.Fatalf("%s: routes = %v reasons = %v", name, routes, collection.HealthReasonCodes)
				}
				return
			}
			if !slices.Contains(collection.HealthReasonCodes, testCase.reason) {
				t.Fatalf("%s: reasons = %v, want %s", name, collection.HealthReasonCodes, testCase.reason)
			}
			if len(collection.Snapshot.GetRoutes()) != 0 {
				t.Fatalf("%s: routes emitted from invalid table: %v", name, collection.Snapshot.GetRoutes())
			}
		})
	}
}

// Invariant: resolv.conf injection cannot produce a resolver that is not a
// literal IP, cannot smuggle path separators in search domains, and never
// emits search domains unless explicitly enabled.
func TestResolvConfHostileInputsProduceReasonCodesNotResolvers(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		content []byte
		reason  string
	}{
		"nameserver-hostname":      {[]byte("nameserver evil.example\n"), "AF-COLLECTOR-DNS-INVALID"},
		"nameserver-extra-field":   {[]byte("nameserver 9.9.9.9 1.1.1.1\n"), "AF-COLLECTOR-DNS-INVALID"},
		"nameserver-empty":         {[]byte("nameserver\n"), "AF-COLLECTOR-DNS-INVALID"},
		"nameserver-with-port":     {[]byte("nameserver 9.9.9.9:53\n"), "AF-COLLECTOR-DNS-INVALID"},
		"search-path-traversal":    {[]byte("nameserver 9.9.9.9\nsearch ../../etc\n"), "AF-COLLECTOR-DNS-INVALID"},
		"search-backslash":         {[]byte("nameserver 9.9.9.9\nsearch a\\b\n"), "AF-COLLECTOR-DNS-INVALID"},
		"search-nul":               {[]byte("nameserver 9.9.9.9\nsearch a\x00b\n"), "AF-COLLECTOR-DNS-INVALID"},
		"search-overlong":          {[]byte("nameserver 9.9.9.9\nsearch " + strings.Repeat("a", 254) + "\n"), "AF-COLLECTOR-DNS-INVALID"},
		"oversized":                {[]byte(strings.Repeat("nameserver 9.9.9.9\n", 70000)), "AF-COLLECTOR-DNS-OVERSIZED"},
		"comment-hides-nameserver": {[]byte("nameserver 9.9.9.9 # nameserver 1.1.1.1\n"), ""},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			collection := collect(t, fakeFiles{"route": []byte(goodRoute), "resolv": testCase.content}, false)
			if testCase.reason == "" {
				if got := collection.Snapshot.GetDns().GetResolverAddresses(); !slices.Equal(got, []string{"9.9.9.9"}) {
					t.Fatalf("%s: resolvers = %v", name, got)
				}
				return
			}
			if !slices.Contains(collection.HealthReasonCodes, testCase.reason) {
				t.Fatalf("%s: reasons = %v, want %s", name, collection.HealthReasonCodes, testCase.reason)
			}
			if collection.Snapshot.GetDns() != nil {
				t.Fatalf("%s: dns emitted from invalid file: %v", name, collection.Snapshot.GetDns())
			}
		})
	}
	t.Run("search-domains-off-by-default", func(t *testing.T) {
		t.Parallel()
		collector, err := collectors.NewLinuxCollector(collectors.LinuxConfig{
			NodeID: "node", BootID: "boot", RouteTablePath: "route", ResolvConfPath: "resolv",
			Files: fakeFiles{"route": []byte(goodRoute), "resolv": []byte(goodResolv)}, Interfaces: noInterfaces{},
		})
		if err != nil {
			t.Fatal(err)
		}
		collection, err := collector.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(collection.Snapshot.GetDns().GetSearchDomains()) != 0 {
			t.Fatalf("search domains emitted without consent: %v", collection.Snapshot.GetDns().GetSearchDomains())
		}
	})
}

// Invariant: a malformed /proc/net/tcp table produces AF-COLLECTOR-FLOW-INVALID
// and no flows; a valid table never emits payloads or process identities.
func TestSocketTableHostileInputsProduceReasonCodesNotFlows(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("ENV-UNAVAILABLE: flow collection is compiled for linux only (agent/collectors/flows_other.go)")
	}
	cases := map[string]struct {
		content []byte
		reason  string
	}{
		"header-missing":      {[]byte("   0: 0100007F:1F90 0200A8C0:01BB 01\n"), "AF-COLLECTOR-FLOW-INVALID"},
		"row-truncated":       {[]byte(tcpHeader + "   0: 0100007F:1F90\n"), "AF-COLLECTOR-FLOW-INVALID"},
		"endpoint-not-hex":    {[]byte(tcpHeader + "   0: ZZZZZZZZ:1F90 0200A8C0:01BB 01\n"), "AF-COLLECTOR-FLOW-INVALID"},
		"endpoint-no-port":    {[]byte(tcpHeader + "   0: 0100007F 0200A8C0:01BB 01\n"), "AF-COLLECTOR-FLOW-INVALID"},
		"endpoint-odd-family": {[]byte(tcpHeader + "   0: 010000:1F90 0200A8C0:01BB 01\n"), "AF-COLLECTOR-FLOW-INVALID"},
		"port-overflow":       {[]byte(tcpHeader + "   0: 0100007F:1F90 0200A8C0:FFFFF 01\n"), "AF-COLLECTOR-FLOW-INVALID"},
		"oversized":           {[]byte(tcpHeader + strings.Repeat("   0: 0100007F:1F90 0200A8C0:01BB 01\n", 40000)), "AF-COLLECTOR-FLOW-OVERSIZED"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			collection := collect(t, fakeFiles{"route": []byte(goodRoute), "resolv": []byte(goodResolv), "tcp": testCase.content}, true)
			if !slices.Contains(collection.HealthReasonCodes, testCase.reason) {
				t.Fatalf("%s: reasons = %v, want %s", name, collection.HealthReasonCodes, testCase.reason)
			}
			if len(collection.Snapshot.GetFlows()) != 0 {
				t.Fatalf("%s: flows emitted from invalid table: %v", name, collection.Snapshot.GetFlows())
			}
		})
	}
	t.Run("valid-table-has-no-process-attribution", func(t *testing.T) {
		t.Parallel()
		collection := collect(t, fakeFiles{"route": []byte(goodRoute), "resolv": []byte(goodResolv), "tcp": []byte(goodTCP)}, true)
		if len(collection.Snapshot.GetFlows()) != 1 {
			t.Fatalf("flows = %v reasons = %v", collection.Snapshot.GetFlows(), collection.HealthReasonCodes)
		}
		flow := collection.Snapshot.GetFlows()[0]
		if flow.GetProcess().GetProcessId() != "" || flow.GetProcess().GetExecutableName() != "" || flow.GetProcess().GetExecutablePathHash() != "" {
			t.Fatalf("process attribution leaked: %v", flow.GetProcess())
		}
	})
}

// Invariant: missing sources are reported as UNAVAILABLE, never synthesized.
func TestMissingSourcesAreReportedNotSynthesized(t *testing.T) {
	t.Parallel()
	collection := collect(t, fakeFiles{}, true)
	for _, reason := range []string{"AF-COLLECTOR-ROUTE-UNAVAILABLE", "AF-COLLECTOR-DNS-UNAVAILABLE", "AF-COLLECTOR-FLOW-UNAVAILABLE"} {
		if runtime.GOOS != "linux" && reason == "AF-COLLECTOR-FLOW-UNAVAILABLE" {
			continue
		}
		if !slices.Contains(collection.HealthReasonCodes, reason) {
			t.Fatalf("reasons = %v, want %s", collection.HealthReasonCodes, reason)
		}
	}
	if collection.Snapshot.GetDns() != nil || len(collection.Snapshot.GetRoutes()) != 0 || len(collection.Snapshot.GetFlows()) != 0 {
		t.Fatalf("facts synthesized for missing sources: %v", collection.Snapshot)
	}
}
