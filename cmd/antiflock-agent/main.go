package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/adapters/mesh/headscale"
	"github.com/DBarr3/AntiFlock/adapters/mesh/tailscale"
	"github.com/DBarr3/AntiFlock/agent/collectors"
	"github.com/DBarr3/AntiFlock/agent/ingest"
	"github.com/DBarr3/AntiFlock/agent/runtime"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type outputDocument struct {
	SchemaVersion     string          `json:"schemaVersion"`
	Mode              string          `json:"mode"`
	ObservedAt        string          `json:"observedAt"`
	Snapshot          json.RawMessage `json:"snapshot"`
	HealthReasonCodes []string        `json:"healthReasonCodes,omitempty"`
	Mesh              *meshOutput     `json:"mesh,omitempty"`
}

type meshOutput struct {
	DryRun       *tailscale.CommandPlan `json:"dryRun,omitempty"`
	BackendState string                 `json:"backendState,omitempty"`
	Connected    bool                   `json:"connected"`
	Peers        []json.RawMessage      `json:"peers,omitempty"`
	Paths        []json.RawMessage      `json:"paths,omitempty"`
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if ctx == nil || stdout == nil || stderr == nil {
		return errors.New("agent context and output streams are required")
	}
	flags := flag.NewFlagSet("antiflock-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	nodeID := flags.String("node-id", "", "enrolled AntiFlock node id")
	bootID := flags.String("boot-id", "", "boot id (defaults to the Linux kernel boot id)")
	routeTable := flags.String("route-table", "/proc/net/route", "read-only Linux route table")
	resolvConf := flags.String("resolv-conf", "/etc/resolv.conf", "read-only resolver configuration")
	includeAddresses := flags.Bool("include-addresses", false, "include private interface and mesh addresses")
	includeSearchDomains := flags.Bool("include-search-domains", false, "include resolver search domains")
	includeNonDefaultRoutes := flags.Bool("include-non-default-routes", false, "include routes beyond the active default routes")
	includeFlowMetadata := flags.Bool("include-flow-metadata", false, "include current socket endpoint metadata; never captures packets or process data")
	meshProvider := flags.String("mesh-provider", "none", "read-only mesh probe: none, tailscale, or headscale")
	headscaleURL := flags.String("headscale-url", "", "Headscale HTTPS URL when mesh-provider=headscale")
	headscaleAPIKeyFile := flags.String("headscale-api-key-file", "", "private Headscale read-only API-key file")
	headscaleAssociationsFile := flags.String("headscale-associations-file", "", "JSON map of Headscale provider ids to AntiFlock node ids")
	meshDryRun := flags.Bool("mesh-dry-run", false, "show the mesh status command without executing it")
	compact := flags.Bool("compact", false, "write compact JSON")
	submit := flags.Bool("submit", false, "persist and submit signed telemetry to Core (default is inspect-only JSON)")
	coreURL := flags.String("core-url", "", "Core HTTPS URL for --submit")
	deploymentID := flags.String("deployment-id", "", "AntiFlock deployment id that enrolled this node")
	agentTokenFile := flags.String("agent-token-file", "", "optional private bearer-token file (loopback/demo only)")
	nodeKeyFile := flags.String("node-key-file", "", "private Ed25519 seed created during enrollment")
	queueDirectory := flags.String("queue-dir", "", "private durable queue directory")
	interval := flags.Duration("interval", 30*time.Second, "continuous collection interval for --submit")
	once := flags.Bool("once", false, "perform one durable collection/submission cycle and exit")
	clientCertificate := flags.String("client-cert", "", "approved node client certificate PEM for mTLS")
	clientKey := flags.String("client-key", "", "private key PEM for --client-cert")
	caCertificate := flags.String("ca-cert", "", "Core node CA PEM used to verify an mTLS Core")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("antiflock-agent accepts flags only")
	}
	if runtime.GOOS != "linux" {
		return errors.New("antiflock-agent local collection currently supports Linux only")
	}
	if strings.TrimSpace(*nodeID) == "" {
		return errors.New("node-id is required")
	}
	if *bootID == "" {
		content, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return errors.New("read Linux boot id")
		}
		*bootID = strings.TrimSpace(string(content))
	}
	if strings.TrimSpace(*bootID) != *bootID || len(*bootID) == 0 || len(*bootID) > 128 {
		return errors.New("boot-id must be a canonical value of at most 128 bytes")
	}
	observedAt := time.Now().UTC()
	collector, err := collectors.NewLinuxCollector(collectors.LinuxConfig{
		NodeID: *nodeID, BootID: *bootID, RouteTablePath: *routeTable, ResolvConfPath: *resolvConf,
		IncludeInterfaceAddresses: *includeAddresses, IncludeSearchDomains: *includeSearchDomains,
		IncludeNonDefaultRoutes: *includeNonDefaultRoutes, IncludeFlowMetadata: *includeFlowMetadata,
		Clock: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return err
	}
	if *submit {
		if strings.TrimSpace(*coreURL) == "" || strings.TrimSpace(*deploymentID) == "" || strings.TrimSpace(*nodeKeyFile) == "" || strings.TrimSpace(*queueDirectory) == "" {
			return errors.New("--submit requires core-url, deployment-id, node-key-file, and queue-dir")
		}
		token, err := readPrivateSecret(*agentTokenFile)
		if err != nil { return err }
		if token == "" && strings.TrimSpace(*clientCertificate) == "" {
			return errors.New("--submit requires agent-token-file or an approved client-cert")
		}
		httpClient, err := newAgentHTTPClient(*clientCertificate, *clientKey, *caCertificate)
		if err != nil { return err }
		submitter, err := ingest.NewClient(ingest.Config{Endpoint: *coreURL, Token: token, HTTP: httpClient})
		if err != nil { return err }
		queue, err := runtime.OpenQueue(*queueDirectory)
		if err != nil { return err }
		signer, err := runtime.LoadFileSigner(*nodeID, *nodeKeyFile, func() time.Time { return time.Now().UTC() })
		if err != nil { return err }
		source := runtime.Collector(collector)
		switch strings.ToLower(strings.TrimSpace(*meshProvider)) {
		case "none":
		case "tailscale":
			if *meshDryRun { return errors.New("--mesh-dry-run cannot be used with --submit") }
			probe, err := tailscale.NewProbe(tailscale.ExecRunner{}, tailscale.Config{NodeID: *nodeID, IncludeAddresses: *includeAddresses})
			if err != nil { return err }
			source = runtime.CollectorFunc(func(runContext context.Context) (*collectors.Collection, error) {
				collection, err := collector.Collect(runContext)
				if err != nil { return nil, err }
				mesh, err := probe.Collect(runContext, collection.Snapshot.ObservedAt.AsTime().UTC())
				if err != nil { return nil, err }
				collection.Snapshot.MeshPeers = mesh.Peers
				collection.Snapshot.MeshPaths = mesh.Paths
				return collection, nil
			})
		case "headscale":
			if *meshDryRun { return errors.New("--mesh-dry-run is only available for tailscale") }
			apiKey, err := readPrivateSecret(*headscaleAPIKeyFile)
			if err != nil || apiKey == "" || strings.TrimSpace(*headscaleURL) == "" { return errors.New("headscale submission requires headscale-url and headscale-api-key-file") }
			associations, err := readAssociations(*headscaleAssociationsFile)
			if err != nil { return err }
			client, err := headscale.NewClient(headscale.Config{BaseURL: *headscaleURL, APIKey: apiKey, ProviderAssociations: associations, IncludeAddresses: *includeAddresses})
			if err != nil { return err }
			source = runtime.CollectorFunc(func(runContext context.Context) (*collectors.Collection, error) {
				collection, err := collector.Collect(runContext)
				if err != nil { return nil, err }
				mesh, err := client.ListNodes(runContext, collection.Snapshot.ObservedAt.AsTime().UTC())
				if err != nil { return nil, err }
				collection.Snapshot.MeshPeers = mesh.Peers
				return collection, nil
			})
		default:
			return errors.New("mesh-provider must be none, tailscale, or headscale")
		}
		loop, err := runtime.NewLoop(runtime.LoopConfig{
			DeploymentID: *deploymentID, NodeID: *nodeID, BootID: *bootID, Interval: *interval,
			Collector: source, Queue: queue, Signer: signer, Submitter: submitter,
		})
		if err != nil { return err }
		if *once { return loop.RunOnce(ctx) }
		return loop.Run(ctx)
	}
	collection, err := collector.Collect(ctx)
	if err != nil {
		return err
	}
	marshal := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}
	snapshot, err := marshal.Marshal(collection.Snapshot)
	if err != nil {
		return errors.New("encode local observation snapshot")
	}
	document := outputDocument{
		SchemaVersion: "antiflock.agent-observation/v1", Mode: "read-only-local-observation",
		ObservedAt: observedAt.Format(time.RFC3339Nano), Snapshot: snapshot,
		HealthReasonCodes: append([]string(nil), collection.HealthReasonCodes...),
	}
	switch strings.ToLower(strings.TrimSpace(*meshProvider)) {
	case "none":
	case "tailscale":
		probe, err := tailscale.NewProbe(tailscale.ExecRunner{}, tailscale.Config{NodeID: *nodeID, IncludeAddresses: *includeAddresses})
		if err != nil {
			return err
		}
		document.Mesh = &meshOutput{}
		if *meshDryRun {
			plan := probe.DryRun()
			document.Mesh.DryRun = &plan
			break
		}
		meshSnapshot, err := probe.Collect(ctx, observedAt)
		if err != nil {
			return err
		}
		document.Mesh.BackendState = meshSnapshot.BackendState
		document.Mesh.Connected = meshSnapshot.Connected
		for _, peer := range meshSnapshot.Peers {
			encoded, err := marshalMessage(marshal, peer)
			if err != nil {
				return err
			}
			document.Mesh.Peers = append(document.Mesh.Peers, encoded)
		}
		for _, path := range meshSnapshot.Paths {
			encoded, err := marshalMessage(marshal, path)
			if err != nil {
				return err
			}
			document.Mesh.Paths = append(document.Mesh.Paths, encoded)
		}
	default:
		return errors.New("mesh-provider must be none or tailscale")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if !*compact {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(document); err != nil {
		return errors.New("write local observation output")
	}
	return nil
}


func readPrivateSecret(path string) (string, error) {
	if strings.TrimSpace(path) == "" { return "", nil }
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return "", errors.New("agent token file must be a private regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil || len(content) > 16<<10 { return "", errors.New("read bounded agent token file") }
	return strings.TrimSpace(string(content)), nil
}


func readAssociations(path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" { return nil, nil }
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
		return nil, errors.New("Headscale associations file must be a bounded regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil { return nil, errors.New("read Headscale associations file") }
	values := make(map[string]string)
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil { return nil, errors.New("decode Headscale associations JSON") }
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF { return nil, errors.New("Headscale associations JSON contains trailing data") }
	return values, nil
}

func newAgentHTTPClient(certificatePath, keyPath, caPath string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if (certificatePath == "") != (keyPath == "") { return nil, errors.New("client-cert and client-key must be provided together") }
	if certificatePath != "" {
		certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
		if err != nil { return nil, errors.New("load node client certificate") }
		transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	}
	if caPath != "" {
		content, err := os.ReadFile(caPath)
		if err != nil || len(content) == 0 || len(content) > 1<<20 { return nil, errors.New("read bounded Core CA certificate") }
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(content) { return nil, errors.New("Core CA certificate does not contain PEM certificates") }
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func marshalMessage(options protojson.MarshalOptions, message proto.Message) (json.RawMessage, error) {
	encoded, err := options.Marshal(message)
	if err != nil {
		return nil, errors.New("encode mesh observation")
	}
	return encoded, nil
}
