package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

func init() {
	register(command{name: "init", summary: "create the agent config, state, queue, and node key", run: runInitCommand})
	register(command{name: "version", summary: "print the binary's embedded build information", run: runVersionCommand})
}

func runInitCommand(_ context.Context, args []string, out commandIO) int {
	var output outputFlags
	flags := newFlagSet("init", out, &output)
	defaults := agentcli.DefaultConfig()
	configPath := flags.String("config", agentcli.DefaultConfigPath, "config file to create")
	nodeID := flags.String("node-id", "", "stable AntiFlock node id (required)")
	deploymentID := flags.String("deployment-id", "", "AntiFlock deployment id (required)")
	coreURL := flags.String("core-url", "", "Core HTTPS URL (required)")
	displayName := flags.String("display-name", "", "human-readable endpoint name")
	stateDir := flags.String("state-dir", defaults.StateDir, "private state directory (node key, enrollment state)")
	queueDir := flags.String("queue-dir", defaults.QueueDir, "private durable queue directory")
	caCert := flags.String("ca-cert", "", "optional Core CA PEM path")
	interval := flags.Duration("interval", defaults.Interval, "observe submission interval")
	force := flags.Bool("force", false, "replace an existing config file (the node key is never replaced)")
	if code, ok := parseFlags(flags, args, out); !ok {
		return code
	}
	if strings.TrimSpace(*nodeID) == "" || strings.TrimSpace(*deploymentID) == "" || strings.TrimSpace(*coreURL) == "" {
		return emit(out, output, agentcli.Usage("init", "init requires --node-id, --deployment-id, and --core-url"), nil)
	}
	config := agentcli.Config{SchemaVersion: agentcli.ConfigSchema, NodeID: *nodeID, DisplayName: *displayName, DeploymentID: *deploymentID, CoreURL: *coreURL, StateDir: *stateDir, QueueDir: *queueDir, CACert: *caCert, Interval: *interval}
	result, reason, err := agentcli.Initialize(agentcli.InitOptions{ConfigPath: *configPath, Config: config, Force: *force})
	if err != nil {
		code := agentcli.ExitPrecondition
		switch reason.Code {
		case "AF-INIT-CONFIG-INVALID", "AF-INIT-CONFIG-PATH-INVALID":
			code = agentcli.ExitUsage
		case "AF-INIT-CONFIG-EXISTS":
			code = agentcli.ExitRefused
		}
		return emit(out, output, agentcli.Fail("init", code, reason.Code, reason.Message), nil)
	}
	envelope := agentcli.NewEnvelope("init", agentcli.ExitOK, result, reason)
	return emit(out, output, envelope, func(w io.Writer) {
		fmt.Fprintf(w, "  config:  %s (%s)\n", agentcli.Safe(result.ConfigPath), result.ConfigDigest)
		fmt.Fprintf(w, "  state:   %s\n", agentcli.Safe(result.StateDir))
		fmt.Fprintf(w, "  queue:   %s\n", agentcli.Safe(result.QueueDir))
		fmt.Fprintf(w, "  key:     %s (%s, created=%t)\n", agentcli.Safe(result.KeyPath), result.KeyID, result.KeyCreated)
		fmt.Fprintln(w, "  next:    antiflock-agent doctor --config "+agentcli.Safe(result.ConfigPath))
	})
}

func runVersionCommand(_ context.Context, args []string, out commandIO) int {
	var output outputFlags
	flags := newFlagSet("version", out, &output)
	if code, ok := parseFlags(flags, args, out); !ok {
		return code
	}
	info := agentcli.ReadVersion()
	envelope := agentcli.NewEnvelope("version", agentcli.ExitOK, info)
	if output.json {
		return emit(out, output, envelope, nil)
	}
	modified := ""
	if info.Modified {
		modified = ", modified"
	}
	fmt.Fprintf(out.stdout, "antiflock-agent %s (%s%s) %s %s/%s\n", info.Version, info.Revision, modified, info.GoVersion, info.OS, info.Arch)
	if info.BuildTime != "" {
		if _, err := time.Parse(time.RFC3339, info.BuildTime); err == nil {
			fmt.Fprintf(out.stdout, "  built: %s\n", info.BuildTime)
		}
	}
	return agentcli.ExitOK
}
