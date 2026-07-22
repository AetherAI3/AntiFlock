package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/config"
)

func TestDefaultIsSafeAndValid(t *testing.T) {
	t.Setenv("ANTIFLOCK_ALLOW_PUBLIC_BIND", "")
	value := config.Default()
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	if value.Telemetry.CollectPayloads {
		t.Fatal("payload collection must default off")
	}
	if value.Scrambler.ExecutionEnabled {
		t.Fatal("Scrambler execution must default off")
	}
}

func TestLoadAppliesEnvironmentDataDirectory(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("ANTIFLOCK_DATA_DIR", directory)
	t.Setenv("ANTIFLOCK_LISTEN", "127.0.0.1:9876")
	value, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if value.Storage.Path != filepath.Join(directory, "antiflock.db") {
		t.Fatalf("storage path = %q", value.Storage.Path)
	}
	if value.Server.Listen != "127.0.0.1:9876" {
		t.Fatalf("listen = %q", value.Server.Listen)
	}
}

func TestLoadParsesYAMLAndRejectsUnsafeModes(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	content := []byte("server:\n  listen: 127.0.0.1:8787\ntelemetry:\n  collectPayloads: true\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("payload collection was accepted")
	}
	value := config.Default()
	value.Scrambler.ExecutionEnabled = true
	if err := value.Validate(); err == nil {
		t.Fatal("Scrambler execution was accepted")
	}
	value = config.Default()
	value.Protection.FailMode = "maybe"
	if err := value.Validate(); err == nil {
		t.Fatal("invalid fail mode was accepted")
	}
	value = config.Default()
	value.Protection.FailMode = "open"
	if err := value.Validate(); err == nil {
		t.Fatal("fail-open protection was accepted")
	}
	value = config.Default()
	value.Storage.EventRetention = 0
	if err := value.Validate(); err == nil {
		t.Fatal("disabled event retention was accepted")
	}
	value = config.Default()
	value.Storage.AuditRetention = 24 * time.Hour
	if err := value.Validate(); err == nil {
		t.Fatal("unsafe audit compaction was accepted")
	}
}

func TestPublicBindRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("ANTIFLOCK_ALLOW_PUBLIC_BIND", "")
	t.Setenv("ANTIFLOCK_DEMO_MODE", "")
	t.Setenv("ANTIFLOCK_DEMO_ALLOW_INSECURE_PRIVATE_HTTP", "")
	value := config.Default()
	value.Server.Listen = "192.168.50.20:8787"
	if err := value.Validate(); err == nil {
		t.Fatal("non-loopback bind was accepted without explicit opt-in")
	}
	t.Setenv("ANTIFLOCK_ALLOW_PUBLIC_BIND", "true")
	if err := value.Validate(); err == nil {
		t.Fatal("non-loopback bind was accepted without an approved CIDR and TLS")
	}
	value.Server.ApprovedBindCIDRs = []string{"192.168.50.0/24"}
	value.Server.TLSCertFile = "server.crt"
	value.Server.TLSKeyFile = "server.key"
	value.Server.PublicBaseURL = "https://192.168.50.20:8787"
	if err := value.Validate(); err != nil {
		t.Fatalf("explicit approved TLS bind was rejected: %v", err)
	}
}

func TestDemoPrivateHTTPRequiresBothFlagsAndExplicitApprovedIP(t *testing.T) {
	t.Setenv("ANTIFLOCK_ALLOW_PUBLIC_BIND", "true")
	value := config.Default()
	value.Server.Listen = "172.30.0.10:8787"
	value.Server.PublicBaseURL = "http://172.30.0.10:8787"
	value.Server.ApprovedBindCIDRs = []string{"172.30.0.0/24"}

	t.Setenv("ANTIFLOCK_DEMO_MODE", "true")
	t.Setenv("ANTIFLOCK_DEMO_ALLOW_INSECURE_PRIVATE_HTTP", "")
	if err := value.Validate(); err == nil || value.DemoInsecurePrivateHTTP() {
		t.Fatal("demo mode alone enabled insecure private HTTP")
	}
	t.Setenv("ANTIFLOCK_DEMO_MODE", "")
	t.Setenv("ANTIFLOCK_DEMO_ALLOW_INSECURE_PRIVATE_HTTP", "true")
	if err := value.Validate(); err == nil || value.DemoInsecurePrivateHTTP() {
		t.Fatal("insecure HTTP flag alone enabled the demo exception")
	}
	t.Setenv("ANTIFLOCK_DEMO_MODE", "true")
	if err := value.Validate(); err != nil || !value.DemoInsecurePrivateHTTP() {
		t.Fatalf("double-opt-in approved demo bind was rejected: %v", err)
	}
	value.Server.PublicBaseURL = "http://172.30.0.10:8788"
	if err := value.Validate(); err == nil || value.DemoInsecurePrivateHTTP() {
		t.Fatal("demo exception accepted a public URL on a different port")
	}
	value.Server.PublicBaseURL = "http://172.30.0.10:8787"

	value.Server.Listen = "0.0.0.0:8787"
	value.Server.PublicBaseURL = "http://0.0.0.0:8787"
	value.Server.ApprovedBindCIDRs = []string{"0.0.0.0/0"}
	if err := value.Validate(); err == nil || value.DemoInsecurePrivateHTTP() {
		t.Fatal("demo exception accepted a wildcard bind")
	}
}

func TestEquivalentIPv6WildcardBindsRequireOptIn(t *testing.T) {
	t.Setenv("ANTIFLOCK_ALLOW_PUBLIC_BIND", "")
	for _, listen := range []string{
		"0.0.0.0:8787",
		"[::]:8787",
		"[0:0:0:0:0:0:0:0]:8787",
		"[::ffff:0.0.0.0]:8787",
	} {
		value := config.Default()
		value.Server.Listen = listen
		if err := value.Validate(); err == nil {
			t.Errorf("wildcard bind %q was accepted without opt-in", listen)
		}
	}
	t.Setenv("ANTIFLOCK_ALLOW_PUBLIC_BIND", "true")
	value := config.Default()
	value.Server.Listen = "0.0.0.0:8787"
	value.Server.ApprovedBindCIDRs = []string{"0.0.0.0/0"}
	value.Server.TLSCertFile, value.Server.TLSKeyFile = "server.crt", "server.key"
	if err := value.Validate(); err == nil {
		t.Fatal("wildcard bind was accepted even with opt-in")
	}
}

func TestNonLoopbackHostnameAndUnapprovedIPv6AreRejected(t *testing.T) {
	t.Setenv("ANTIFLOCK_ALLOW_PUBLIC_BIND", "true")
	for _, listen := range []string{"gateway.local:8787", "[fd00::10]:8787"} {
		value := config.Default()
		value.Server.Listen = listen
		value.Server.ApprovedBindCIDRs = []string{"192.168.50.0/24"}
		value.Server.TLSCertFile, value.Server.TLSKeyFile = "server.crt", "server.key"
		if err := value.Validate(); err == nil {
			t.Fatalf("unapproved bind %q was accepted", listen)
		}
	}
}

func TestSecurityWindowsAndTLSPairsAreBounded(t *testing.T) {
	for name, mutate := range map[string]func(*config.Config){
		"zero telemetry freshness":   func(value *config.Config) { value.Protection.TelemetryStaleAfter = 0 },
		"excess telemetry freshness": func(value *config.Config) { value.Protection.TelemetryStaleAfter = 31 * time.Minute },
		"zero bypass ttl":            func(value *config.Config) { value.Protection.OneTimeBypassTTL = 0 },
		"excess bypass ttl":          func(value *config.Config) { value.Protection.OneTimeBypassTTL = 16 * time.Minute },
		"certificate without key":    func(value *config.Config) { value.Server.TLSCertFile = "server.crt" },
		"public base path":           func(value *config.Config) { value.Server.PublicBaseURL = "http://127.0.0.1:8787/api" },
		"invalid unused CIDR":        func(value *config.Config) { value.Server.ApprovedBindCIDRs = []string{"not-a-cidr"} },
		"missing action types":       func(value *config.Config) { value.Protection.ProtectedActions[0].ActionTypes = nil },
		"missing sensitivities":      func(value *config.Config) { value.Protection.ProtectedActions[0].Sensitivities = nil },
	} {
		t.Run(name, func(t *testing.T) {
			value := config.Default()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}
