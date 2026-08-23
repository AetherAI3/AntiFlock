package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

func init() {
	register(command{name: "update", summary: "check a release manifest against this binary, apply a verified file, or roll back", run: runUpdateCommand})
	register(command{name: "uninstall", summary: "remove the agent's own directories, config, and key (dry run by default)", run: runUninstallCommand})
}

func runUpdateCommand(_ context.Context, args []string, out commandIO) int {
	var output outputFlags
	flags := newFlagSet("update", out, &output)
	manifest := flags.String("manifest", "", "release manifest JSON (antiflock.release-manifest/v1)")
	check := flags.Bool("check", false, "compare the running binary with the manifest; never writes")
	fromFile := flags.String("from-file", "", "install this already-downloaded, checksum-verified binary")
	rollback := flags.Bool("rollback", false, "restore the .previous binary")
	target := flags.String("target", "", "binary to manage (default: the running executable)")
	if code, ok := parseFlags(flags, args, out); !ok {
		return code
	}
	modes := 0
	for _, enabled := range []bool{*check, *fromFile != "", *rollback} {
		if enabled {
			modes++
		}
	}
	if modes != 1 {
		return emit(out, output, agentcli.Usage("update", "update requires exactly one of --check, --from-file, or --rollback; it never downloads"), nil)
	}
	binary := strings.TrimSpace(*target)
	if binary == "" {
		path, err := agentcli.ExecutablePath()
		if err != nil {
			return emit(out, output, agentcli.Fail("update", agentcli.ExitRefused, "AF-UPDATE-TARGET-NOT-REGULAR", err.Error()), nil)
		}
		binary = path
	}
	var (
		result agentcli.UpdateResult
		reason agentcli.Reason
		code   int
	)
	switch {
	case *rollback:
		result, reason, code = agentcli.UpdateRollback(binary)
	case *check:
		if strings.TrimSpace(*manifest) == "" {
			return emit(out, output, agentcli.Usage("update", "--check requires --manifest"), nil)
		}
		result, reason, code = agentcli.UpdateCheck(binary, *manifest)
	default:
		if strings.TrimSpace(*manifest) == "" {
			return emit(out, output, agentcli.Usage("update", "--from-file requires --manifest"), nil)
		}
		result, reason, code = agentcli.UpdateApply(binary, *manifest, *fromFile)
	}
	envelope := agentcli.NewEnvelope("update", code, result, reason)
	return emit(out, output, envelope, func(w io.Writer) {
		fmt.Fprintf(w, "  mode:     %s\n", result.Mode)
		fmt.Fprintf(w, "  target:   %s\n", agentcli.Safe(result.Target))
		fmt.Fprintf(w, "  running:  %s\n", orUnavailable(result.RunningSHA256))
		if result.ManifestVersion != "" {
			fmt.Fprintf(w, "  manifest: %s %s\n", agentcli.Safe(result.ManifestVersion), result.ManifestSHA256)
		}
		if result.CandidateSHA256 != "" {
			fmt.Fprintf(w, "  candidate: %s\n", result.CandidateSHA256)
		}
		if result.BackupPath != "" {
			fmt.Fprintf(w, "  backup:   %s\n", agentcli.Safe(result.BackupPath))
		}
		fmt.Fprintln(w, "  signature: not verified by this command; verify SHA256SUMS with cosign per docs/release-policy.md before --from-file")
	})
}

func runUninstallCommand(_ context.Context, args []string, out commandIO) int {
	var output outputFlags
	flags := newFlagSet("uninstall", out, &output)
	configPath := flags.String("config", agentcli.DefaultConfigPath, "config file whose directories will be removed")
	yes := flags.Bool("yes", false, "actually remove (default is a dry run)")
	systemd := flags.Bool("systemd", false, "also disable and remove the systemd unit (root only)")
	if code, ok := parseFlags(flags, args, out); !ok {
		return code
	}
	result, reasons, code := agentcli.Uninstall(agentcli.UninstallOptions{ConfigPath: *configPath, Yes: *yes, Systemd: *systemd, EUID: os.Geteuid(), RunSystemctl: runSystemctl})
	envelope := agentcli.NewEnvelope("uninstall", code, result, reasons...)
	return emit(out, output, envelope, func(w io.Writer) {
		if result.DryRun {
			fmt.Fprintln(w, "  would remove:")
		} else {
			fmt.Fprintln(w, "  removed:")
			for _, path := range result.Removed {
				fmt.Fprintf(w, "    %s\n", agentcli.Safe(path))
			}
			fmt.Fprintln(w, "  planned:")
		}
		for _, path := range result.WouldRemove {
			fmt.Fprintf(w, "    %s\n", agentcli.Safe(path))
		}
		if len(result.Refused) != 0 {
			fmt.Fprintln(w, "  refused (outside the configured directories):")
			for _, path := range result.Refused {
				fmt.Fprintf(w, "    %s\n", agentcli.Safe(path))
			}
		}
		fmt.Fprintln(w, "  systemd commands (run as root, or pass --systemd as root):")
		for _, line := range result.SystemdCommands {
			fmt.Fprintf(w, "    %s\n", line)
		}
		fmt.Fprintf(w, "  firewall: %s\n", result.FirewallNote)
	})
}

// runSystemctl is the only place uninstall shells out. The verb list is
// fixed by agentcli.Uninstall; nothing here is derived from user input.
func runSystemctl(arguments ...string) error {
	command := exec.Command("/usr/bin/systemctl", arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.Stdout, command.Stderr = nil, nil
	return command.Run()
}
