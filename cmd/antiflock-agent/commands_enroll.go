package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

func init() {
	register(command{name: "enroll", summary: "submit or retrieve this node's enrollment using the config file", run: runEnrollCommand, accepts: usesConfigFlag})
	register(command{name: "observe", summary: "run the read-only observer using the config file", run: runObserveCommand, accepts: usesConfigFlag})
}

// usesConfigFlag routes only config-driven invocations through the
// registry; the existing flag-only forms stay with main.go unchanged.
func usesConfigFlag(args []string) bool {
	return hasFlag(args, "config")
}

// legacyRunner delegates to the existing dispatcher so enrollment and
// observation behavior is byte-for-byte the code path main.go already owns.
var legacyRunner = run

func runEnrollCommand(ctx context.Context, args []string, out commandIO) int {
	var output outputFlags
	flags := newFlagSet("enroll", out, &output)
	configPath := flags.String("config", agentcli.DefaultConfigPath, "config file")
	tokenFile := flags.String("enrollment-token-file", "", "private enrollment token file created by an operator (required)")
	displayName := flags.String("display-name", "", "override the config displayName")
	certificateFile := flags.String("certificate-file", "", "override the approved certificate destination")
	if code, ok := parseFlags(flags, args, out); !ok {
		return code
	}
	config, _, err := agentcli.LoadConfig(*configPath)
	if err != nil {
		return emit(out, output, agentcli.Fail("enroll", agentcli.ExitPrecondition, "AF-ENROLL-CONFIG-INVALID", err.Error()), nil)
	}
	if strings.TrimSpace(*tokenFile) == "" {
		return emit(out, output, agentcli.Usage("enroll", "enroll requires --enrollment-token-file"), nil)
	}
	name := config.DisplayName
	if *displayName != "" {
		name = *displayName
	}
	if name == "" {
		name = config.NodeID
	}
	legacy := []string{"enroll", "--core-url", config.CoreURL, "--enrollment-token-file", *tokenFile, "--state-dir", config.StateDir, "--node-id", config.NodeID, "--display-name", name, "--compact"}
	if config.CACert != "" {
		legacy = append(legacy, "--ca-cert", config.CACert)
	}
	if *certificateFile != "" {
		legacy = append(legacy, "--certificate-file", *certificateFile)
	}
	var captured bytes.Buffer
	if err := legacyRunner(ctx, legacy, &captured, out.stderr); err != nil {
		return emit(out, output, agentcli.Fail("enroll", agentcli.ExitFailure, "AF-ENROLL-FAILED", agentcli.Safe(err.Error())), nil)
	}
	var document struct {
		Status     string `json:"status"`
		NextAction string `json:"nextAction"`
	}
	if err := json.Unmarshal(captured.Bytes(), &document); err != nil {
		return emit(out, output, agentcli.Fail("enroll", agentcli.ExitFailure, "AF-ENROLL-OUTPUT-INVALID", "enrollment output could not be decoded"), nil)
	}
	code, reasonCode := agentcli.ExitOK, "AF-ENROLL-APPROVED"
	switch document.Status {
	case "approved-ready-to-submit":
	case "pending-operator-approval":
		code, reasonCode = agentcli.ExitNotReady, "AF-ENROLL-PENDING"
	case "denied", "expired":
		code, reasonCode = agentcli.ExitRefused, "AF-ENROLL-"+strings.ToUpper(document.Status)
	default:
		code, reasonCode = agentcli.ExitFailure, "AF-ENROLL-STATUS-UNKNOWN"
	}
	envelope := agentcli.NewEnvelope("enroll", code, json.RawMessage(bytes.TrimSpace(captured.Bytes())), agentcli.Reason{Code: reasonCode, Message: document.NextAction})
	return emit(out, output, envelope, func(w io.Writer) {
		fmt.Fprintf(w, "  status: %s\n", agentcli.Safe(document.Status))
	})
}

// runObserveCommand expands the config into the flags the existing observe
// path expects and passes every other argument through untouched. Output is
// the existing antiflock.agent-observation/v1 document, not the CLI envelope.
func runObserveCommand(ctx context.Context, args []string, out commandIO) int {
	configPath, rest, ok := extractConfigFlag(args)
	if !ok {
		fmt.Fprintln(out.stderr, "observe --config requires a path")
		return agentcli.ExitUsage
	}
	config, _, err := agentcli.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(out.stderr, "observe: "+err.Error())
		return agentcli.ExitPrecondition
	}
	legacy := []string{"observe", "--node-id", config.NodeID}
	submit := false
	for _, arg := range rest {
		if arg == "--submit" || arg == "-submit" || arg == "--submit=true" || arg == "-submit=true" {
			submit = true
		}
	}
	if submit {
		legacy = append(legacy, "--core-url", config.CoreURL, "--deployment-id", config.DeploymentID, "--node-key-file", config.KeyPath(), "--queue-dir", config.QueueDir, "--interval", config.Interval.String())
		if !hasFlag(rest, "client-cert") && !hasFlag(rest, "agent-token-file") {
			legacy = append(legacy, "--client-cert", config.CertificatePath())
		}
		if config.CACert != "" && !hasFlag(rest, "ca-cert") {
			legacy = append(legacy, "--ca-cert", config.CACert)
		}
	}
	legacy = append(legacy, rest...)
	if err := legacyRunner(ctx, legacy, out.stdout, out.stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return agentcli.ExitUsage
		}
		fmt.Fprintln(out.stderr, agentcli.Safe(err.Error()))
		return agentcli.ExitFailure
	}
	return agentcli.ExitOK
}

func extractConfigFlag(args []string) (string, []string, bool) {
	rest := make([]string, 0, len(args))
	path := ""
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--config" || arg == "-config":
			if index+1 >= len(args) {
				return "", nil, false
			}
			path = args[index+1]
			index++
		case strings.HasPrefix(arg, "--config="):
			path = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-config="):
			path = strings.TrimPrefix(arg, "-config=")
		default:
			rest = append(rest, arg)
		}
	}
	return path, rest, path != ""
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == "--"+name || arg == "-"+name || strings.HasPrefix(arg, "--"+name+"=") || strings.HasPrefix(arg, "-"+name+"=") {
			return true
		}
	}
	return false
}
