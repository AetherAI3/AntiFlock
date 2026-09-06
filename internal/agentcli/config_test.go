package agentcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	config := DefaultConfig()
	root := t.TempDir()
	config.NodeID, config.DeploymentID, config.DisplayName = "lab-node-1", "deploy-1", "Lab node"
	config.CoreURL = "https://core.example.test:8787"
	config.StateDir, config.QueueDir = filepath.Join(root, "state"), filepath.Join(root, "state", "queue")
	return config
}

func TestConfigRoundTripAndDigest(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	content, err := config.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "seed") || strings.Contains(string(content), "token") {
		t.Fatalf("config encodes secret-looking fields: %s", content)
	}
	parsed, err := ParseConfig(content)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, content)
	}
	if parsed != config {
		t.Fatalf("round trip mismatch: %#v != %#v", parsed, config)
	}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, digest, err := LoadConfig(path)
	if err != nil || loaded != config || digest != Digest(content) || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("load = %#v %q %v", loaded, digest, err)
	}
}

func TestConfigValidationIsFailClosed(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Config){
		"wrong schema":        func(c *Config) { c.SchemaVersion = "antiflock.agent-config/v0" },
		"empty node":          func(c *Config) { c.NodeID = "" },
		"node with newline":   func(c *Config) { c.NodeID = "lab\n1" },
		"node with space":     func(c *Config) { c.NodeID = "lab 1" },
		"http off loopback":   func(c *Config) { c.CoreURL = "http://core.example.test" },
		"url with user":       func(c *Config) { c.CoreURL = "https://user:pw@core.example.test" },
		"relative state dir":  func(c *Config) { c.StateDir = "state" },
		"dotdot state dir":    func(c *Config) { c.StateDir = "/var/lib/antiflock/../x" },
		"root state dir":      func(c *Config) { c.StateDir = "/" },
		"relative queue dir":  func(c *Config) { c.QueueDir = "./queue" },
		"interval too small":  func(c *Config) { c.Interval = time.Second },
		"interval too large":  func(c *Config) { c.Interval = 2 * time.Hour },
		"relative ca cert":    func(c *Config) { c.CACert = "ca.pem" },
		"empty deployment id": func(c *Config) { c.DeploymentID = "" },
	}
	for name, mutate := range cases {
		config := validConfig(t)
		mutate(&config)
		if err := config.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	loopback := validConfig(t)
	loopback.CoreURL = "http://127.0.0.1:8787"
	if err := loopback.Validate(); err != nil {
		t.Fatalf("loopback http rejected: %v", err)
	}
}

func TestParseConfigRejectsUnknownFieldsAndExtraDocuments(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	content, err := config.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfig(append(content, []byte("enrollmentToken: secret\n")...)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParseConfig(append(content, []byte("---\nschemaVersion: x\n")...)); err == nil {
		t.Fatal("second document accepted")
	}
	if _, err := ParseConfig(nil); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestLoadConfigRejectsSymlinkAndMissing(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if _, _, err := LoadConfig(filepath.Join(root, "missing.yaml")); err == nil {
		t.Fatal("missing config accepted")
	}
	config := validConfig(t)
	content, _ := config.Encode()
	real := filepath.Join(root, "real.yaml")
	if err := os.WriteFile(real, content, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, _, err := LoadConfig(link); err == nil {
		t.Fatal("symlinked config accepted")
	}
}
