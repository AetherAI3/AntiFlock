package agentcli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentruntime "github.com/DBarr3/AntiFlock/agent/runtime"
)

func TestContainedRejectsDotDotAndSymlinkEscapes(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "state")
	outside := filepath.Join(filepath.Dir(root), "outside")
	for _, directory := range []string{filepath.Join(root, "inner"), outside} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "inner", "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Contained(root, filepath.Join(root, "inner", "file")); err != nil {
		t.Fatalf("contained child rejected: %v", err)
	}
	if err := Contained(root, root); err != nil {
		t.Fatalf("root rejected: %v", err)
	}
	for _, candidate := range []string{
		filepath.Join(root, "..", "outside"),
		root + "/../outside",
		outside,
		filepath.Dir(root),
		"relative/path",
		filepath.Join(root, "missing"),
	} {
		if err := Contained(root, candidate); !errors.Is(err, ErrNotContained) {
			t.Errorf("Contained(%q) = %v, want ErrNotContained", candidate, err)
		}
	}
	for _, root := range []string{"/", "/etc", "/var/lib", "/usr", "relative"} {
		if err := Contained(root, filepath.Join(root, "x")); !errors.Is(err, ErrNotContained) {
			t.Errorf("protected root %q accepted", root)
		}
	}
	linkRoot := filepath.Join(filepath.Dir(root), "linkroot")
	if err := os.Symlink(root, linkRoot); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := Contained(linkRoot, filepath.Join(linkRoot, "inner")); !errors.Is(err, ErrNotContained) {
		t.Fatal("symlinked root accepted")
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	// The link itself may be removed (as a link) but nothing through it.
	if err := Contained(root, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("final symlink component rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "victim"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Contained(root, filepath.Join(root, "escape", "victim")); !errors.Is(err, ErrNotContained) {
		t.Fatal("path through a symlinked directory accepted")
	}
}

func TestInitializeCreatesPrivateLayoutAndNeverRegeneratesKey(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	configPath := filepath.Join(filepath.Dir(config.StateDir), "etc", "agent.yaml")
	result, reason, err := Initialize(InitOptions{ConfigPath: configPath, Config: config})
	if err != nil || reason.Code != "AF-INIT-OK" || !result.KeyCreated || !result.ConfigWrote || result.KeyID == "" {
		t.Fatalf("init = %#v %#v %v", result, reason, err)
	}
	for _, directory := range []string{config.StateDir, config.QueueDir} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s = %v %v", directory, info, err)
		}
	}
	for _, file := range []string{config.KeyPath(), config.EnrollmentStatePath()} {
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("file %s = %v %v", file, info, err)
		}
	}
	if info, err := os.Lstat(configPath); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("config = %v %v", info, err)
	}
	// The generated seed must be accepted by the runtime signer.
	if _, err := agentruntime.LoadFileSigner(config.NodeID, config.KeyPath(), nil); err != nil {
		t.Fatalf("runtime signer rejected the init key: %v", err)
	}
	seed, _ := os.ReadFile(config.KeyPath())

	_, reason, err = Initialize(InitOptions{ConfigPath: configPath, Config: config})
	if err == nil || reason.Code != "AF-INIT-CONFIG-EXISTS" {
		t.Fatalf("second init without force = %#v %v", reason, err)
	}
	again, reason, err := Initialize(InitOptions{ConfigPath: configPath, Config: config, Force: true})
	if err != nil || again.KeyCreated || again.KeyID != result.KeyID {
		t.Fatalf("forced init = %#v %#v %v", again, reason, err)
	}
	afterSeed, _ := os.ReadFile(config.KeyPath())
	if string(seed) != string(afterSeed) {
		t.Fatal("force regenerated the node key")
	}
	if _, err := os.Lstat(configPath + ".tmp"); err == nil {
		t.Fatal("staging file left behind")
	}
}

func TestInitializeRefusesInvalidConfigAndSymlinkedStateDir(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	configPath := filepath.Join(filepath.Dir(config.StateDir), "agent.yaml")
	bad := config
	bad.NodeID = ""
	if _, reason, err := Initialize(InitOptions{ConfigPath: configPath, Config: bad}); err == nil || reason.Code != "AF-INIT-CONFIG-INVALID" {
		t.Fatalf("invalid config accepted: %#v", reason)
	}
	if _, reason, err := Initialize(InitOptions{ConfigPath: "relative.yaml", Config: config}); err == nil || reason.Code != "AF-INIT-CONFIG-PATH-INVALID" {
		t.Fatalf("relative config path accepted: %#v", reason)
	}
	target := filepath.Join(filepath.Dir(config.StateDir), "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, config.StateDir); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, reason, err := Initialize(InitOptions{ConfigPath: configPath, Config: config}); err == nil || reason.Code != "AF-INIT-DIRECTORY" {
		t.Fatalf("symlinked state dir accepted: %#v", reason)
	}
}

func TestStatusReportsDegradedWithoutQueueAndUnwiredDrivers(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	configPath := filepath.Join(filepath.Dir(config.StateDir), "agent.yaml")
	if _, _, err := Initialize(InitOptions{ConfigPath: configPath, Config: config}); err != nil {
		t.Fatal(err)
	}
	identity := func(string) string { return "pending-operator-approval" }
	if err := os.Remove(config.QueueDir); err != nil {
		t.Fatal(err)
	}
	result, reasons, code := Status(configPath, identity)
	if code != ExitDegraded || result.KeyID == "" || result.Enrollment != "pending-operator-approval" {
		t.Fatalf("status without queue = %d %#v", code, result)
	}
	if !hasReason(reasons, "AF-STATUS-QUEUE-UNAVAILABLE") || !hasReason(reasons, "AF-STATUS-DRIVER-NOT-WIRED") {
		t.Fatalf("reasons = %#v", reasons)
	}
	queue, err := agentruntime.OpenQueue(config.QueueDir, config.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	_ = queue.Close()
	result, _, code = Status(configPath, identity)
	if code != ExitOK || result.QueueMaximumEvents == 0 {
		t.Fatalf("status with queue = %d %#v", code, result)
	}
	if len(result.Drivers) != 5 {
		t.Fatalf("drivers = %#v", result.Drivers)
	}
	for _, driver := range result.Drivers {
		if driver.State != "UNAVAILABLE" || driver.ReasonCode == "" {
			t.Fatalf("driver collapsed into ready: %#v", driver)
		}
	}
	if _, _, code := Status(filepath.Join(t.TempDir(), "missing.yaml"), identity); code != ExitPrecondition {
		t.Fatalf("missing config exit = %d", code)
	}
}

func hasReason(reasons []Reason, code string) bool {
	for _, reason := range reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}
