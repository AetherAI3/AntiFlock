package agentcli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallDryRunListsAndRemovesNothing(t *testing.T) {
	t.Parallel()
	config, configPath := initializedConfig(t)
	result, reasons, code := Uninstall(UninstallOptions{ConfigPath: configPath, EUID: 1000})
	if code != ExitOK || !result.DryRun || !hasReason(reasons, "AF-UNINSTALL-DRY-RUN") || len(result.Removed) != 0 {
		t.Fatalf("dry run = %d %#v %#v", code, reasons, result)
	}
	if !containsPath(result.WouldRemove, config.KeyPath()) || !containsPath(result.WouldRemove, config.StateDir) || !containsPath(result.WouldRemove, configPath) {
		t.Fatalf("would remove = %#v", result.WouldRemove)
	}
	if len(result.Roots) != 1 || result.Roots[0] != config.StateDir {
		t.Fatalf("roots = %#v (queue nested under state must collapse)", result.Roots)
	}
	if _, err := os.Lstat(config.KeyPath()); err != nil {
		t.Fatal("dry run removed the key")
	}
	if result.FirewallNote == "" || len(result.SystemdCommands) < 2 {
		t.Fatalf("result = %#v", result)
	}
}

func TestUninstallYesRemovesOnlyContainedPathsAndNeverFollowsSymlinks(t *testing.T) {
	t.Parallel()
	config, configPath := initializedConfig(t)
	outside := filepath.Join(filepath.Dir(config.StateDir), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(config.StateDir, "escape")); err != nil {
		t.Skip("symlinks unavailable")
	}
	result, reasons, code := Uninstall(UninstallOptions{ConfigPath: configPath, Yes: true, EUID: 1000})
	if code != ExitOK || hasReason(reasons, "AF-UNINSTALL-REFUSED") {
		t.Fatalf("uninstall = %d %#v %#v", code, reasons, result)
	}
	if _, err := os.Lstat(victim); err != nil {
		t.Fatal("uninstall followed a symlink out of the state directory")
	}
	for _, path := range []string{config.StateDir, config.QueueDir, config.KeyPath(), configPath} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("%s still exists", path)
		}
	}
	if !hasReason(reasons, "AF-UNINSTALL-SYSTEMD-PRINTED") || !hasReason(reasons, "AF-UNINSTALL-FIREWALL-UNTOUCHED") || result.SystemdRan {
		t.Fatalf("reasons = %#v", reasons)
	}
}

func TestUninstallRefusesSymlinkedRootAndProtectedRoots(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	configPath := filepath.Join(filepath.Dir(config.StateDir), "agent.yaml")
	real := filepath.Join(filepath.Dir(config.StateDir), "real-state")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "node.seed"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, config.StateDir); err != nil {
		t.Skip("symlinks unavailable")
	}
	content, _ := config.Encode()
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	result, reasons, code := Uninstall(UninstallOptions{ConfigPath: configPath, Yes: true, EUID: 0})
	if code != ExitRefused || !hasReason(reasons, "AF-UNINSTALL-REFUSED-NOT-CONTAINED") || len(result.Removed) != 0 {
		t.Fatalf("symlinked root = %d %#v %#v", code, reasons, result)
	}
	if _, err := os.Lstat(filepath.Join(real, "node.seed")); err != nil {
		t.Fatal("uninstall removed through a symlinked state directory")
	}
	if _, err := os.Lstat(configPath); err != nil {
		t.Fatal("config removed on a refused uninstall")
	}

	protected := validConfig(t)
	protected.StateDir, protected.QueueDir = "/var/lib", "/var/lib/queue"
	protectedPath := filepath.Join(t.TempDir(), "agent.yaml")
	content, _ = protected.Encode()
	if err := os.WriteFile(protectedPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, reasons, code := Uninstall(UninstallOptions{ConfigPath: protectedPath, Yes: true, EUID: 0}); code != ExitRefused || !hasReason(reasons, "AF-UNINSTALL-REFUSED-PROTECTED-ROOT") {
		t.Fatalf("protected root = %d %#v", code, reasons)
	}
}

func TestUninstallDotDotConfigIsRejectedBeforeAnyRemoval(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	config.StateDir = config.StateDir + "/../escape"
	content := "schemaVersion: " + ConfigSchema + "\nnodeId: n\ndeploymentId: d\ncoreUrl: https://core.example.test\nstateDir: " + config.StateDir + "\nqueueDir: " + config.QueueDir + "\ninterval: 30s\n"
	configPath := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, reasons, code := Uninstall(UninstallOptions{ConfigPath: configPath, Yes: true, EUID: 0}); code != ExitPrecondition || !hasReason(reasons, "AF-UNINSTALL-CONFIG-INVALID") {
		t.Fatalf("dotdot config = %d %#v", code, reasons)
	}
}

func TestUninstallSystemdRunsOnlyAsRootWithInjectedSystemctl(t *testing.T) {
	t.Parallel()
	_, configPath := initializedConfig(t)
	var calls [][]string
	run := func(arguments ...string) error { calls = append(calls, arguments); return nil }
	_, reasons, code := Uninstall(UninstallOptions{ConfigPath: configPath, Yes: true, Systemd: true, EUID: 1000, RunSystemctl: run})
	if code != ExitOK || !hasReason(reasons, "AF-UNINSTALL-SYSTEMD-REQUIRES-ROOT") || len(calls) != 0 {
		t.Fatalf("unprivileged systemd = %d %#v calls=%v", code, reasons, calls)
	}
}
