package main

import (
	"context"
	"fmt"
	"io"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

func init() {
	register(command{name: "plan", summary: "plan simulate | plan readiness (not available yet); plan verify is handled by plan.go", run: runPlanStubCommand, accepts: planStubAccepts})
}

// planStubAccepts claims only the subcommands this PR stubs. "plan verify"
// and any other form fall through to main.go's dispatcher (PR #60).
func planStubAccepts(args []string) bool {
	return len(args) > 0 && (args[0] == "simulate" || args[0] == "readiness")
}

// Each stub names the exact dependency that is missing so the command
// surface is complete and honest: the exit code is 5 (not ready) and never
// a silent success.
var planStubDependencies = map[string]string{
	"simulate":  "plan simulate needs cmd/antiflock-agent/plan.go (PR #60) and a simulation driver set from the agent/driver packages; none is wired into this binary",
	"readiness": "plan readiness needs the computed readiness API from agent/enforcement (capability lane) and the driver probe contract (agent/driver); none is wired into this binary",
}

func runPlanStubCommand(_ context.Context, args []string, out commandIO) int {
	subcommand := args[0]
	var output outputFlags
	flags := newFlagSet("plan "+subcommand, out, &output)
	if code, ok := parseFlags(flags, args[1:], out); !ok {
		return code
	}
	result := map[string]any{"subcommand": subcommand, "available": false, "mode": "verify-only-no-host-mutation", "drivers": agentcli.UnwiredDrivers()}
	envelope := agentcli.NewEnvelope("plan "+subcommand, agentcli.ExitNotReady, result, agentcli.Reason{Code: "AF-CLI-NOT-AVAILABLE-YET", Message: planStubDependencies[subcommand]})
	return emit(out, output, envelope, func(w io.Writer) {
		fmt.Fprintln(w, "  plan verify (signature and capability check without host mutation) is available; see docs/operator-runbook.md")
	})
}
