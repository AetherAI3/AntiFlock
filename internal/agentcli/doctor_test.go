package agentcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeRunner struct {
	output string
	err    error
	calls  [][]string
}

func (runner *fakeRunner) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string{executable}, arguments...))
	return []byte(runner.output), runner.err
}

// fakeHost builds a fully injected environment over a temp tree with a
// "trusted" nft and ip (ownership is injected, so no root is needed).
func fakeHost(t *testing.T) (Environment, string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "sbin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nft", "ip"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "resolv.conf"), []byte("nameserver 192.0.2.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := Environment{
		GOOS: "linux", Now: func() time.Time { return time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC) }, EUID: 0,
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
		Dial:     func(context.Context, string) error { return nil },
		Runner:   &fakeRunner{output: "table inet antiflock-guard\n"},
		DiskFree: func(string) (uint64, error) { return 1 << 30, nil },
		// Every path below the temp root is treated as root-owned except the
		// temp root's own ancestors, which are real and may not be.
		OwnedByRoot:    func(os.FileInfo) (bool, error) { return true, nil },
		TrustRoot:      root,
		SystemdPath:    filepath.Join(root, "systemd"),
		ResolvConfPath: filepath.Join(root, "resolv.conf"),
		NftCandidates:  []string{filepath.Join(bin, "nft")},
		IPCandidates:   []string{filepath.Join(bin, "ip")},
	}
	return env, root
}

func initializedConfig(t *testing.T) (Config, string) {
	t.Helper()
	config := validConfig(t)
	configPath := filepath.Join(filepath.Dir(config.StateDir), "agent.yaml")
	if _, _, err := Initialize(InitOptions{ConfigPath: configPath, Config: config}); err != nil {
		t.Fatal(err)
	}
	return config, configPath
}

func statusOf(result DoctorResult, id string) Check {
	for _, check := range result.Checks {
		if check.ID == id {
			return check
		}
	}
	return Check{}
}

func TestDoctorPassesOnHealthyInjectedHost(t *testing.T) {
	t.Parallel()
	env, _ := fakeHost(t)
	_, configPath := initializedConfig(t)
	result, code := Doctor(context.Background(), DoctorOptions{ConfigPath: configPath, Env: env})
	for _, check := range result.Checks {
		if check.Status != StatusPass {
			t.Errorf("%s = %#v", check.ID, check)
		}
	}
	if code != ExitOK {
		t.Fatalf("exit = %d; %#v", code, result)
	}
	if len(result.MissingRecoveryRequirements) == 0 {
		t.Fatal("recovery driver must always be reported missing in this binary")
	}
	runner := env.Runner.(*fakeRunner)
	if len(runner.calls) != 1 || runner.calls[0][1] != "list" || runner.calls[0][2] != "tables" {
		t.Fatalf("runner calls = %#v", runner.calls)
	}
	if table := statusOf(result, "nft-table"); table.ReasonCode != "AF-DOCTOR-NFT-TABLE-PRESENT" {
		t.Fatalf("nft-table = %#v", table)
	}
}

func TestDoctorWarnsWithoutRecoveryToolingAndNeverRunsNftUnprivileged(t *testing.T) {
	t.Parallel()
	env, _ := fakeHost(t)
	env.EUID = 1000
	env.NftCandidates, env.IPCandidates = nil, nil
	_, configPath := initializedConfig(t)
	result, code := Doctor(context.Background(), DoctorOptions{ConfigPath: configPath, Env: env, Offline: true})
	if code != ExitDegraded {
		t.Fatalf("exit = %d; %#v", code, result)
	}
	if nft := statusOf(result, "nft"); nft.Status != StatusWarn || nft.ReasonCode != "AF-DOCTOR-NFT-MISSING" || !nft.Recovery {
		t.Fatalf("nft = %#v", nft)
	}
	if table := statusOf(result, "nft-table"); table.Status != StatusUnknown || table.ReasonCode != "AF-DOCTOR-NFT-TABLE-REQUIRES-ROOT" {
		t.Fatalf("nft-table = %#v", table)
	}
	if core := statusOf(result, "core"); core.Status != StatusUnknown || core.ReasonCode != "AF-DOCTOR-CORE-SKIPPED-OFFLINE" {
		t.Fatalf("core = %#v", core)
	}
	if len(env.Runner.(*fakeRunner).calls) != 0 {
		t.Fatal("doctor executed a command while unprivileged")
	}
	found := false
	for _, missing := range result.MissingRecoveryRequirements {
		if missing == "nft (AF-DOCTOR-NFT-MISSING)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing recovery requirements = %#v", result.MissingRecoveryRequirements)
	}
}

func TestDoctorFailsOnMissingConfigKeyAndUnsafePermissions(t *testing.T) {
	t.Parallel()
	env, root := fakeHost(t)
	result, code := Doctor(context.Background(), DoctorOptions{ConfigPath: filepath.Join(root, "missing.yaml"), Env: env})
	if code != ExitPrecondition || statusOf(result, "config").Status != StatusFail || statusOf(result, "key").Status != StatusUnknown {
		t.Fatalf("missing config = %d %#v", code, result)
	}
	config, configPath := initializedConfig(t)
	if err := os.Remove(config.KeyPath()); err != nil {
		t.Fatal(err)
	}
	result, code = Doctor(context.Background(), DoctorOptions{ConfigPath: configPath, Env: env})
	if code != ExitPrecondition || statusOf(result, "key").ReasonCode != "AF-DOCTOR-KEY-MISSING" {
		t.Fatalf("missing key = %d %#v", code, statusOf(result, "key"))
	}
	if err := os.Chmod(config.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	result, code = Doctor(context.Background(), DoctorOptions{ConfigPath: configPath, Env: env})
	if code != ExitPrecondition || statusOf(result, "state-dir").ReasonCode != "AF-DOCTOR-STATE-DIR-PERMISSIONS" {
		t.Fatalf("state-dir perms = %d %#v", code, statusOf(result, "state-dir"))
	}
}

func TestDoctorIndependentStatuses(t *testing.T) {
	t.Parallel()
	env, _ := fakeHost(t)
	env.Now = func() time.Time { return time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC) }
	env.DiskFree = func(string) (uint64, error) { return 10 << 20, nil }
	env.Dial = func(context.Context, string) error { return errors.New("refused") }
	env.GOOS = "plan9"
	_, configPath := initializedConfig(t)
	result, code := Doctor(context.Background(), DoctorOptions{ConfigPath: configPath, Env: env})
	if code != ExitPrecondition {
		t.Fatalf("exit = %d", code)
	}
	expect := map[string]string{"clock": "AF-DOCTOR-CLOCK-IMPLAUSIBLE", "disk": "AF-DOCTOR-DISK-FULL", "core": "AF-DOCTOR-CORE-UNREACHABLE", "os": "AF-DOCTOR-OS-UNSUPPORTED", "config": "AF-DOCTOR-CONFIG-VALID"}
	for id, reason := range expect {
		if got := statusOf(result, id).ReasonCode; got != reason {
			t.Errorf("%s = %s, want %s", id, got, reason)
		}
	}
	if result.Summary[StatusFail] != 1 || result.Summary[StatusWarn] < 3 {
		t.Fatalf("summary = %#v", result.Summary)
	}
}

func TestExecRunnerRefusesAnythingButListTables(t *testing.T) {
	t.Parallel()
	if _, err := (ExecRunner{}).Run(context.Background(), "/usr/sbin/nft", "-f", "-"); err == nil {
		t.Fatal("runner accepted a mutation invocation")
	}
	if _, err := (ExecRunner{}).Run(context.Background(), "/usr/sbin/ip", "route"); err == nil {
		t.Fatal("runner accepted a non-nft executable")
	}
}
