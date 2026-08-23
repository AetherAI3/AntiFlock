package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

func runCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, handled := dispatch(context.Background(), args, &stdout, &stderr)
	if !handled {
		t.Fatalf("dispatch did not claim %v", args)
	}
	return code, stdout.String(), stderr.String()
}

// initLayout runs init into a temp tree and returns the config path.
func initLayout(t *testing.T) (string, agentcli.Config) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "etc", "agent.yaml")
	stateDir := filepath.Join(root, "state")
	code, stdout, stderr := runCommand(t, "init", "--json", "--config", configPath, "--node-id", "lab-node-1", "--deployment-id", "deploy-1", "--core-url", "https://core.example.test:8787", "--display-name", "Lab node", "--state-dir", stateDir, "--queue-dir", filepath.Join(stateDir, "queue"))
	if code != agentcli.ExitOK {
		t.Fatalf("init exit %d: %s %s", code, stdout, stderr)
	}
	envelope := decodeEnvelope(t, []byte(stdout))
	if envelope.Command != "init" || len(envelope.Reasons) != 1 || envelope.Reasons[0].Code != "AF-INIT-OK" {
		t.Fatalf("init envelope = %#v", envelope)
	}
	config, _, err := agentcli.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return configPath, config
}

func TestInitCommandExitCodesAndSecrecy(t *testing.T) {
	t.Parallel()
	configPath, config := initLayout(t)
	seed, err := os.ReadFile(config.KeyPath())
	if err != nil || len(seed) != 32 {
		t.Fatalf("seed = %d bytes, %v", len(seed), err)
	}
	code, stdout, _ := runCommand(t, "init", "--config", configPath, "--node-id", "lab-node-1", "--deployment-id", "deploy-1", "--core-url", "https://core.example.test:8787")
	if code != agentcli.ExitRefused || !strings.Contains(stdout, "AF-INIT-CONFIG-EXISTS") {
		t.Fatalf("re-init exit %d: %s", code, stdout)
	}
	code, stdout, _ = runCommand(t, "init", "--force", "--config", configPath, "--node-id", "lab-node-1", "--deployment-id", "deploy-1", "--core-url", "https://core.example.test:8787", "--state-dir", config.StateDir, "--queue-dir", config.QueueDir)
	if code != agentcli.ExitOK || !strings.Contains(stdout, "created=false") {
		t.Fatalf("forced init exit %d: %s", code, stdout)
	}
	if strings.Contains(stdout, hex.EncodeToString(seed)) || bytes.Contains([]byte(stdout), seed) {
		t.Fatal("init printed key material")
	}
	if code, _, _ := runCommand(t, "init", "--json", "--config", configPath, "--node-id", "x"); code != agentcli.ExitUsage {
		t.Fatalf("missing required flags exit = %d", code)
	}
	if code, _, _ := runCommand(t, "init", "--json", "--config", configPath, "--node-id", "x", "--deployment-id", "d", "--core-url", "http://core.example.test"); code != agentcli.ExitUsage {
		t.Fatalf("invalid config exit = %d", code)
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()
	code, stdout, _ := runCommand(t, "version")
	if code != 0 || !strings.HasPrefix(stdout, "antiflock-agent ") || !strings.Contains(stdout, "go1.") {
		t.Fatalf("version = %d %q", code, stdout)
	}
	code, stdout, _ = runCommand(t, "version", "--json", "--compact")
	envelope := decodeEnvelope(t, []byte(stdout))
	if code != 0 || envelope.Command != "version" || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("version json = %d %q", code, stdout)
	}
	result := envelope.Result.(map[string]any)
	for _, key := range []string{"binary", "version", "revision", "modified", "goVersion", "os", "arch"} {
		if _, ok := result[key]; !ok {
			t.Errorf("version result lacks %s: %v", key, result)
		}
	}
}

const planSimulateGolden = `{
  "document": "antiflock.agent-cli/v1",
  "command": "plan simulate",
  "ok": false,
  "exit_code": 5,
  "reasons": [
    {
      "code": "AF-CLI-NOT-AVAILABLE-YET",
      "message": "plan simulate needs cmd/antiflock-agent/plan.go (PR #60) and a simulation driver set from the agent/driver packages; none is wired into this binary"
    }
  ],
  "result": {
    "available": false,
    "drivers": [
      {
        "domain": "firewall",
        "state": "UNAVAILABLE",
        "reasonCode": "AF-STATUS-DRIVER-NOT-WIRED",
        "detail": "No enforcement driver is registered in this binary; readiness cannot be computed."
      },
      {
        "domain": "mesh",
        "state": "UNAVAILABLE",
        "reasonCode": "AF-STATUS-DRIVER-NOT-WIRED",
        "detail": "No enforcement driver is registered in this binary; readiness cannot be computed."
      },
      {
        "domain": "route",
        "state": "UNAVAILABLE",
        "reasonCode": "AF-STATUS-DRIVER-NOT-WIRED",
        "detail": "No enforcement driver is registered in this binary; readiness cannot be computed."
      },
      {
        "domain": "dns",
        "state": "UNAVAILABLE",
        "reasonCode": "AF-STATUS-DRIVER-NOT-WIRED",
        "detail": "No enforcement driver is registered in this binary; readiness cannot be computed."
      },
      {
        "domain": "recovery",
        "state": "UNAVAILABLE",
        "reasonCode": "AF-STATUS-RECOVERY-NOT-WIRED",
        "detail": "No independently verified host recovery path is registered in this binary."
      }
    ],
    "mode": "verify-only-no-host-mutation",
    "subcommand": "simulate"
  }
}
`

func TestPlanStubsAreHonestAndGoldenStable(t *testing.T) {
	t.Parallel()
	code, stdout, _ := runCommand(t, "plan", "simulate", "--json")
	if code != agentcli.ExitNotReady {
		t.Fatalf("plan simulate exit = %d", code)
	}
	if stdout != planSimulateGolden {
		t.Fatalf("plan simulate JSON drifted from golden:\n%s", stdout)
	}
	code, stdout, _ = runCommand(t, "plan", "readiness")
	if code != agentcli.ExitNotReady || !strings.Contains(stdout, "AF-CLI-NOT-AVAILABLE-YET") || !strings.Contains(stdout, "agent/driver") {
		t.Fatalf("plan readiness = %d %q", code, stdout)
	}
	if code, _, _ := runCommand(t, "plan", "readiness", "--bogus"); code != agentcli.ExitUsage {
		t.Fatalf("plan readiness bad flag exit = %d", code)
	}
}

func TestStatusCommandReadsLayoutWithoutSecrets(t *testing.T) {
	t.Parallel()
	configPath, config := initLayout(t)
	code, stdout, _ := runCommand(t, "status", "--json", "--config", configPath)
	envelope := decodeEnvelope(t, []byte(stdout))
	if code != agentcli.ExitOK || envelope.Command != "status" {
		t.Fatalf("status = %d %s", code, stdout)
	}
	result := envelope.Result.(map[string]any)
	if result["enrollment"] != "pending-operator-approval" || result["nodeId"] != config.NodeID || !strings.HasPrefix(result["keyId"].(string), "ed25519:") {
		t.Fatalf("status result = %v", result)
	}
	seed, _ := os.ReadFile(config.KeyPath())
	if strings.Contains(stdout, hex.EncodeToString(seed)) {
		t.Fatal("status printed the seed")
	}
	drivers := result["drivers"].([]any)
	if len(drivers) != 5 {
		t.Fatalf("drivers = %v", drivers)
	}
	code, stdout, _ = runCommand(t, "status", "--config", configPath)
	if code != 0 || !strings.Contains(stdout, "firewall  UNAVAILABLE (AF-STATUS-DRIVER-NOT-WIRED)") {
		t.Fatalf("human status = %d %q", code, stdout)
	}
	if code, _, _ := runCommand(t, "status", "--json", "--config", filepath.Join(t.TempDir(), "none.yaml")); code != agentcli.ExitPrecondition {
		t.Fatalf("missing config exit = %d", code)
	}
}

func TestDoctorCommandUsesInjectedHostAndIsGoldenStable(t *testing.T) {
	// Not parallel: it swaps the package-level doctor environment.
	root := t.TempDir()
	saved := doctorEnvironment
	t.Cleanup(func() { doctorEnvironment = saved })
	doctorEnvironment = func() agentcli.Environment {
		return agentcli.Environment{
			GOOS: "linux", Now: func() time.Time { return time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC) }, EUID: 1000,
			LookPath:  func(string) (string, error) { return "", errors.New("absent") },
			Dial:      func(context.Context, string) error { return errors.New("unreachable") },
			DiskFree:  func(string) (uint64, error) { return 1 << 30, nil },
			TrustRoot: root, SystemdPath: filepath.Join(root, "no-systemd"), ResolvConfPath: filepath.Join(root, "no-resolv"),
		}
	}
	configPath, _ := initLayout(t)
	code, stdout, _ := runCommand(t, "doctor", "--json", "--offline", "--config", configPath)
	if code != agentcli.ExitDegraded {
		t.Fatalf("doctor exit = %d\n%s", code, stdout)
	}
	if stdout != doctorGolden {
		t.Fatalf("doctor JSON drifted from golden:\n%s", stdout)
	}
	code, stdout, _ = runCommand(t, "doctor", "--offline", "--config", configPath)
	if code != agentcli.ExitDegraded || !strings.Contains(stdout, "Missing recovery requirements") || !strings.Contains(stdout, "WARN    nft") {
		t.Fatalf("human doctor = %d %q", code, stdout)
	}
	if code, _, _ := runCommand(t, "doctor", "--json", "--config", filepath.Join(root, "none.yaml")); code != agentcli.ExitPrecondition {
		t.Fatalf("doctor without config exit = %d", code)
	}
}

const doctorGolden = `{
  "document": "antiflock.agent-cli/v1",
  "command": "doctor",
  "ok": false,
  "exit_code": 7,
  "reasons": [
    {
      "code": "AF-DOCTOR-NFT-MISSING",
      "message": "nft is not installed"
    },
    {
      "code": "AF-DOCTOR-IP-MISSING",
      "message": "ip is not installed"
    },
    {
      "code": "AF-DOCTOR-RESOLV-CONF-UNREADABLE",
      "message": "resolver configuration is missing or unreadable; DNS observations will be empty"
    },
    {
      "code": "AF-DOCTOR-SYSTEMD-ABSENT",
      "message": "systemd not detected; the packaged unit will not manage the agent"
    }
  ],
  "result": {
    "checks": [
      {
        "id": "os",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-OS-LINUX",
        "message": "linux host",
        "recovery": false
      },
      {
        "id": "privilege",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-PRIVILEGE-UNPRIVILEGED",
        "message": "running unprivileged; observe mode needs no privilege, root-only checks are UNKNOWN",
        "recovery": false
      },
      {
        "id": "config",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-CONFIG-VALID",
        "message": "config present and valid",
        "recovery": false
      },
      {
        "id": "key",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-KEY-PRIVATE",
        "message": "node key present with private permissions",
        "recovery": false
      },
      {
        "id": "state-dir",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-STATE-DIR-PRIVATE",
        "message": "private directory present",
        "recovery": false
      },
      {
        "id": "queue-dir",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-QUEUE-DIR-PRIVATE",
        "message": "private directory present",
        "recovery": false
      },
      {
        "id": "queue-writable",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-QUEUE-WRITABLE",
        "message": "queue directory is writable",
        "recovery": false
      },
      {
        "id": "disk",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-DISK-OK",
        "message": "state directory has sufficient free space",
        "recovery": false
      },
      {
        "id": "core",
        "status": "UNKNOWN",
        "reasonCode": "AF-DOCTOR-CORE-SKIPPED-OFFLINE",
        "message": "core reachability skipped (--offline)",
        "recovery": false
      },
      {
        "id": "clock",
        "status": "PASS",
        "reasonCode": "AF-DOCTOR-CLOCK-PLAUSIBLE",
        "message": "system clock is plausible",
        "recovery": false
      },
      {
        "id": "nft",
        "status": "WARN",
        "reasonCode": "AF-DOCTOR-NFT-MISSING",
        "message": "nft is not installed",
        "recovery": true
      },
      {
        "id": "ip",
        "status": "WARN",
        "reasonCode": "AF-DOCTOR-IP-MISSING",
        "message": "ip is not installed",
        "recovery": true
      },
      {
        "id": "resolv-conf",
        "status": "WARN",
        "reasonCode": "AF-DOCTOR-RESOLV-CONF-UNREADABLE",
        "message": "resolver configuration is missing or unreadable; DNS observations will be empty",
        "recovery": false
      },
      {
        "id": "systemd",
        "status": "WARN",
        "reasonCode": "AF-DOCTOR-SYSTEMD-ABSENT",
        "message": "systemd not detected; the packaged unit will not manage the agent",
        "recovery": false
      },
      {
        "id": "nft-table",
        "status": "UNKNOWN",
        "reasonCode": "AF-DOCTOR-NFT-TABLE-REQUIRES-ROOT",
        "message": "reading nftables tables requires root; skipped",
        "recovery": true
      }
    ],
    "summary": {
      "FAIL": 0,
      "PASS": 9,
      "UNKNOWN": 2,
      "WARN": 4
    },
    "missingRecoveryRequirements": [
      "nft (AF-DOCTOR-NFT-MISSING)",
      "ip (AF-DOCTOR-IP-MISSING)",
      "nft-table (AF-DOCTOR-NFT-TABLE-REQUIRES-ROOT)",
      "recovery-driver (AF-DOCTOR-RECOVERY-NOT-WIRED)"
    ],
    "offline": true
  }
}
`

func TestUpdateCommandCheckApplyRollback(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "antiflock-agent")
	if err := os.WriteFile(target, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, "candidate")
	if err := os.WriteFile(candidate, []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("v2"))
	manifest := filepath.Join(root, "release.json")
	content, _ := json.Marshal(agentcli.ReleaseManifest{Document: agentcli.ReleaseManifestSchema, Version: "0.2.0", Artifacts: []agentcli.ReleaseArtifact{{Name: "antiflock-agent", SHA256: hex.EncodeToString(sum[:])}}})
	if err := os.WriteFile(manifest, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCommand(t, "update", "--json", "--target", target); code != agentcli.ExitUsage {
		t.Fatalf("no mode exit = %d", code)
	}
	if code, _, _ := runCommand(t, "update", "--json", "--target", target, "--check", "--rollback"); code != agentcli.ExitUsage {
		t.Fatalf("two modes exit = %d", code)
	}
	code, stdout, _ := runCommand(t, "update", "--json", "--target", target, "--check", "--manifest", manifest)
	envelope := decodeEnvelope(t, []byte(stdout))
	if code != agentcli.ExitDegraded || envelope.Reasons[0].Code != "AF-UPDATE-AVAILABLE" {
		t.Fatalf("check = %d %s", code, stdout)
	}
	tampered := filepath.Join(root, "tampered")
	_ = os.WriteFile(tampered, []byte("evil"), 0o755)
	code, stdout, _ = runCommand(t, "update", "--json", "--target", target, "--from-file", tampered, "--manifest", manifest)
	if code != agentcli.ExitVerification || !strings.Contains(stdout, "AF-UPDATE-CHECKSUM-MISMATCH") {
		t.Fatalf("tampered apply = %d %s", code, stdout)
	}
	if current, _ := os.ReadFile(target); string(current) != "v1" {
		t.Fatal("tampered candidate was installed")
	}
	code, stdout, _ = runCommand(t, "update", "--target", target, "--from-file", candidate, "--manifest", manifest)
	if code != agentcli.ExitOK || !strings.Contains(stdout, "AF-UPDATE-APPLIED") || !strings.Contains(stdout, "signature: not verified") {
		t.Fatalf("apply = %d %s", code, stdout)
	}
	if current, _ := os.ReadFile(target); string(current) != "v2" {
		t.Fatal("candidate was not installed")
	}
	code, stdout, _ = runCommand(t, "update", "--json", "--target", target, "--check", "--manifest", manifest)
	if code != agentcli.ExitOK || !strings.Contains(stdout, "AF-UPDATE-CURRENT") {
		t.Fatalf("check after apply = %d %s", code, stdout)
	}
	code, stdout, _ = runCommand(t, "update", "--json", "--target", target, "--rollback")
	if code != agentcli.ExitOK || !strings.Contains(stdout, "AF-UPDATE-ROLLED-BACK") {
		t.Fatalf("rollback = %d %s", code, stdout)
	}
	if current, _ := os.ReadFile(target); string(current) != "v1" {
		t.Fatal("rollback did not restore v1")
	}
}

func TestUninstallCommandDryRunThenRemoveWithContainment(t *testing.T) {
	t.Parallel()
	configPath, config := initLayout(t)
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
	code, stdout, _ := runCommand(t, "uninstall", "--json", "--config", configPath)
	envelope := decodeEnvelope(t, []byte(stdout))
	if code != agentcli.ExitOK || envelope.Reasons[0].Code != "AF-UNINSTALL-DRY-RUN" {
		t.Fatalf("dry run = %d %s", code, stdout)
	}
	if _, err := os.Lstat(config.KeyPath()); err != nil {
		t.Fatal("dry run removed the key")
	}
	code, stdout, _ = runCommand(t, "uninstall", "--config", configPath, "--yes")
	if code != agentcli.ExitOK || !strings.Contains(stdout, "AF-UNINSTALL-FIREWALL-UNTOUCHED") || !strings.Contains(stdout, "systemctl disable --now antiflock-agent.service") {
		t.Fatalf("uninstall = %d %s", code, stdout)
	}
	if _, err := os.Lstat(victim); err != nil {
		t.Fatal("uninstall escaped through a symlink")
	}
	for _, path := range []string{config.StateDir, configPath} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("%s survived uninstall --yes", path)
		}
	}
}

func TestEnrollCommandMapsStatusesToExitCodes(t *testing.T) {
	// Not parallel: it swaps the package-level legacy runner.
	configPath, config := initLayout(t)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := legacyRunner
	t.Cleanup(func() { legacyRunner = saved })
	var seen []string
	status := "pending-operator-approval"
	legacyRunner = func(_ context.Context, args []string, stdout, _ io.Writer) error {
		seen = args
		_, err := io.WriteString(stdout, `{"schemaVersion":"antiflock.agent-enrollment-result/v1","status":"`+status+`","enrollmentId":"enr-1","proposedNodeId":"lab-node-1","stateDirectory":"x","nextAction":"wait"}`+"\n")
		return err
	}
	code, stdout, _ := runCommand(t, "enroll", "--json", "--config", configPath, "--enrollment-token-file", token)
	envelope := decodeEnvelope(t, []byte(stdout))
	if code != agentcli.ExitNotReady || envelope.Reasons[0].Code != "AF-ENROLL-PENDING" {
		t.Fatalf("pending = %d %s", code, stdout)
	}
	joined := strings.Join(seen, " ")
	for _, want := range []string{"enroll", "--core-url " + config.CoreURL, "--state-dir " + config.StateDir, "--node-id lab-node-1", "--display-name Lab node", "--enrollment-token-file " + token} {
		if !strings.Contains(joined, want) {
			t.Errorf("legacy args %q lack %q", joined, want)
		}
	}
	status = "approved-ready-to-submit"
	if code, _, _ := runCommand(t, "enroll", "--config", configPath, "--enrollment-token-file", token); code != agentcli.ExitOK {
		t.Fatalf("approved exit = %d", code)
	}
	status = "denied"
	if code, _, _ := runCommand(t, "enroll", "--config", configPath, "--enrollment-token-file", token); code != agentcli.ExitRefused {
		t.Fatalf("denied exit = %d", code)
	}
	legacyRunner = func(context.Context, []string, io.Writer, io.Writer) error {
		return errors.New("submit enrollment request: token=abc")
	}
	code, stdout, _ = runCommand(t, "enroll", "--json", "--config", configPath, "--enrollment-token-file", token)
	if code != agentcli.ExitFailure || strings.Contains(stdout, "abc") {
		t.Fatalf("failure = %d %s", code, stdout)
	}
	if code, _, _ := runCommand(t, "enroll", "--json", "--config", configPath); code != agentcli.ExitUsage {
		t.Fatalf("missing token exit = %d", code)
	}
}

func TestObserveCommandExpandsConfigIntoLegacyFlags(t *testing.T) {
	// Not parallel: it swaps the package-level legacy runner.
	configPath, config := initLayout(t)
	saved := legacyRunner
	t.Cleanup(func() { legacyRunner = saved })
	var seen []string
	legacyRunner = func(_ context.Context, args []string, stdout, _ io.Writer) error {
		seen = args
		_, err := io.WriteString(stdout, "{}\n")
		return err
	}
	code, _, _ := runCommand(t, "observe", "--config="+configPath, "--include-addresses")
	if code != 0 || strings.Join(seen, " ") != "observe --node-id lab-node-1 --include-addresses" {
		t.Fatalf("inspect args = %d %v", code, seen)
	}
	code, _, _ = runCommand(t, "observe", "--config", configPath, "--submit", "--once")
	joined := strings.Join(seen, " ")
	for _, want := range []string{"--submit", "--once", "--core-url " + config.CoreURL, "--deployment-id deploy-1", "--node-key-file " + config.KeyPath(), "--queue-dir " + config.QueueDir, "--client-cert " + config.CertificatePath(), "--interval 30s"} {
		if code != 0 || !strings.Contains(joined, want) {
			t.Errorf("submit args %q lack %q (exit %d)", joined, want, code)
		}
	}
	code, _, _ = runCommand(t, "observe", "--config", configPath, "--submit", "--agent-token-file", "/run/token")
	if code != 0 || strings.Contains(strings.Join(seen, " "), "--client-cert") {
		t.Fatalf("client-cert added although a token file was given: %v", seen)
	}
	if code, _, _ := runCommand(t, "observe", "--config"); code != agentcli.ExitUsage {
		t.Fatalf("dangling --config exit = %d", code)
	}
	if code, _, _ := runCommand(t, "observe", "--config", filepath.Join(t.TempDir(), "none.yaml")); code != agentcli.ExitPrecondition {
		t.Fatalf("missing config exit = %d", code)
	}
}

func TestUninstallCommandRefusesSymlinkedStateDirectory(t *testing.T) {
	t.Parallel()
	configPath, config := initLayout(t)
	real := filepath.Join(filepath.Dir(config.StateDir), "real-state")
	if err := os.Rename(config.StateDir, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, config.StateDir); err != nil {
		t.Skip("symlinks unavailable")
	}
	code, stdout, _ := runCommand(t, "uninstall", "--json", "--config", configPath, "--yes")
	envelope := decodeEnvelope(t, []byte(stdout))
	if code != agentcli.ExitRefused || envelope.Reasons[len(envelope.Reasons)-1].Code != "AF-UNINSTALL-REFUSED" {
		t.Fatalf("symlinked state dir = %d %s", code, stdout)
	}
	if _, err := os.Lstat(filepath.Join(real, "node.seed")); err != nil {
		t.Fatal("uninstall removed through a symlinked state directory")
	}
}
