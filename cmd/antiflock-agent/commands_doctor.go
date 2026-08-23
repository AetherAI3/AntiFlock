package main

import (
	"context"
	"fmt"
	"io"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

// doctorEnvironment is replaced by tests with a fully injected host.
var doctorEnvironment = agentcli.DefaultEnvironment

func init() {
	register(command{name: "doctor", summary: "check host, config, key, directories, and recovery prerequisites", run: runDoctorCommand})
	register(command{name: "status", summary: "read-only summary of enrollment, queue, key, and driver readiness", run: runStatusCommand, accepts: func(args []string) bool { return !hasFlag(args, "node-id") }})
}

func runDoctorCommand(ctx context.Context, args []string, out commandIO) int {
	var output outputFlags
	flags := newFlagSet("doctor", out, &output)
	configPath := flags.String("config", agentcli.DefaultConfigPath, "config file to check")
	offline := flags.Bool("offline", false, "skip the Core reachability check")
	if code, ok := parseFlags(flags, args, out); !ok {
		return code
	}
	result, code := agentcli.Doctor(ctx, agentcli.DoctorOptions{ConfigPath: *configPath, Offline: *offline, Env: doctorEnvironment()})
	reasons := make([]agentcli.Reason, 0, len(result.Checks))
	for _, check := range result.Checks {
		if check.Status == agentcli.StatusFail || check.Status == agentcli.StatusWarn {
			reasons = append(reasons, agentcli.Reason{Code: check.ReasonCode, Message: check.Message})
		}
	}
	envelope := agentcli.NewEnvelope("doctor", code, result, reasons...)
	return emit(out, output, envelope, func(w io.Writer) {
		fmt.Fprintln(w, "Checks")
		for _, check := range result.Checks {
			recovery := ""
			if check.Recovery {
				recovery = " [recovery]"
			}
			fmt.Fprintf(w, "  %-7s %-15s %s%s: %s\n", check.Status, check.ID, check.ReasonCode, recovery, agentcli.Safe(check.Message))
		}
		fmt.Fprintf(w, "Summary: pass=%d warn=%d fail=%d unknown=%d\n", result.Summary[agentcli.StatusPass], result.Summary[agentcli.StatusWarn], result.Summary[agentcli.StatusFail], result.Summary[agentcli.StatusUnknown])
		fmt.Fprintln(w, "Missing recovery requirements (enforcement is not available in this binary):")
		for _, missing := range result.MissingRecoveryRequirements {
			fmt.Fprintf(w, "  - %s\n", agentcli.Safe(missing))
		}
	})
}

func runStatusCommand(_ context.Context, args []string, out commandIO) int {
	var output outputFlags
	flags := newFlagSet("status", out, &output)
	configPath := flags.String("config", agentcli.DefaultConfigPath, "config file")
	if code, ok := parseFlags(flags, args, out); !ok {
		return code
	}
	result, reasons, code := agentcli.Status(*configPath, localIdentityStatus)
	envelope := agentcli.NewEnvelope("status", code, result, reasons...)
	return emit(out, output, envelope, func(w io.Writer) {
		if code == agentcli.ExitPrecondition {
			return
		}
		fmt.Fprintf(w, "  node:        %s\n", agentcli.Safe(result.NodeID))
		fmt.Fprintf(w, "  enrollment:  %s\n", result.Enrollment)
		fmt.Fprintf(w, "  key id:      %s\n", orUnavailable(result.KeyID))
		fmt.Fprintf(w, "  config:      %s\n", result.ConfigDigest)
		fmt.Fprintf(w, "  queue depth: %d (last sequence %d, max %d)\n", result.QueueDepth, result.QueueLastSequence, result.QueueMaximumEvents)
		fmt.Fprintf(w, "  last queue write: %s\n", orUnavailable(result.LastQueueWriteAt))
		fmt.Fprintf(w, "  last observation: %s\n", orUnavailable(result.LastObservationAt))
		fmt.Fprintln(w, "  drivers:")
		for _, driver := range result.Drivers {
			fmt.Fprintf(w, "    %-9s %s (%s)\n", driver.Domain, driver.State, driver.ReasonCode)
		}
	})
}

func orUnavailable(value string) string {
	if value == "" {
		return "unavailable"
	}
	return value
}
