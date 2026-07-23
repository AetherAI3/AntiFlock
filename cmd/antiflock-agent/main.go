package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/adapters/mesh/tailscale"
	"github.com/DBarr3/AntiFlock/agent/collectors"
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
	meshProvider := flags.String("mesh-provider", "none", "read-only mesh probe: none or tailscale")
	meshDryRun := flags.Bool("mesh-dry-run", false, "show the mesh status command without executing it")
	compact := flags.Bool("compact", false, "write compact JSON")
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
		Clock: func() time.Time { return observedAt },
	})
	if err != nil {
		return err
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

func marshalMessage(options protojson.MarshalOptions, message proto.Message) (json.RawMessage, error) {
	encoded, err := options.Marshal(message)
	if err != nil {
		return nil, errors.New("encode mesh observation")
	}
	return encoded, nil
}
