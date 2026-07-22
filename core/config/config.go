package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Storage    StorageConfig    `yaml:"storage"`
	Identity   IdentityConfig   `yaml:"identity"`
	Protection ProtectionConfig `yaml:"protection"`
	Telemetry  TelemetryConfig  `yaml:"telemetry"`
	Scrambler  ScramblerConfig  `yaml:"scrambler"`
}

type ServerConfig struct {
	Listen            string   `yaml:"listen"`
	PublicBaseURL     string   `yaml:"publicBaseURL"`
	TrustedProxies    []string `yaml:"trustedProxies"`
	ApprovedBindCIDRs []string `yaml:"approvedBindCIDRs"`
	TLSCertFile       string   `yaml:"tlsCertFile"`
	TLSKeyFile        string   `yaml:"tlsKeyFile"`
}

type StorageConfig struct {
	Path           string        `yaml:"path"`
	EventRetention time.Duration `yaml:"eventRetention"`
	AuditRetention time.Duration `yaml:"auditRetention"`
}

type IdentityConfig struct {
	StateDirectory     string        `yaml:"stateDirectory"`
	EnrollmentTokenTTL time.Duration `yaml:"enrollmentTokenTTL"`
}

type ProtectionConfig struct {
	TelemetryStaleAfter    time.Duration                 `yaml:"telemetryStaleAfter"`
	RequireMeshOnUntrusted bool                          `yaml:"requireMeshOnUntrustedNetworks"`
	FailMode               string                        `yaml:"failMode"`
	AllowOneTimeBypass     bool                          `yaml:"allowOneTimeBypass"`
	OneTimeBypassTTL       time.Duration                 `yaml:"oneTimeBypassTTL"`
	ProtectedActions       []ProtectedActionPolicyConfig `yaml:"protectedActions"`
}

// ProtectedActionPolicyConfig is the fail-closed action scope installed at
// Core startup. Every dimension is explicit; "*" is the only wildcard and
// must be the sole value for that dimension.
type ProtectedActionPolicyConfig struct {
	NodeIDs             []string `yaml:"nodeIds"`
	ApplicationIDs      []string `yaml:"applicationIds"`
	DataClasses         []string `yaml:"dataClasses"`
	AllowedDestinations []string `yaml:"allowedDestinations"`
}

type TelemetryConfig struct {
	CollectFlowMetadata bool `yaml:"collectFlowMetadata"`
	CollectPayloads     bool `yaml:"collectPayloads"`
}

type ScramblerConfig struct {
	ExecutionEnabled  bool `yaml:"executionEnabled"`
	SimulationEnabled bool `yaml:"simulationEnabled"`
}

func Default() Config {
	return Config{
		Server:   ServerConfig{Listen: "127.0.0.1:8787", PublicBaseURL: "http://127.0.0.1:8787"},
		Storage:  StorageConfig{Path: "./data/antiflock.db", EventRetention: 14 * 24 * time.Hour},
		Identity: IdentityConfig{StateDirectory: "./data/identity", EnrollmentTokenTTL: 10 * time.Minute},
		Protection: ProtectionConfig{
			TelemetryStaleAfter:    2 * time.Minute,
			RequireMeshOnUntrusted: true,
			FailMode:               "closed",
			AllowOneTimeBypass:     true,
			OneTimeBypassTTL:       5 * time.Minute,
			ProtectedActions: []ProtectedActionPolicyConfig{{
				NodeIDs: []string{"*"}, ApplicationIDs: []string{"aether-code"},
				DataClasses: []string{"repository-source"}, AllowedDestinations: []string{"github.com"},
			}},
		},
		Telemetry: TelemetryConfig{CollectFlowMetadata: true, CollectPayloads: false},
		Scrambler: ScramblerConfig{ExecutionEnabled: false, SimulationEnabled: true},
	}
}

func Load(path string) (Config, error) {
	result := Default()
	if path != "" {
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(content, &result); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}
	applyEnvironment(&result)
	if err := result.Validate(); err != nil {
		return Config{}, err
	}
	return result, nil
}

func applyEnvironment(config *Config) {
	if value := os.Getenv("ANTIFLOCK_LISTEN"); value != "" {
		config.Server.Listen = value
	}
	if value := os.Getenv("ANTIFLOCK_DATA_DIR"); value != "" {
		config.Storage.Path = filepath.Join(value, "antiflock.db")
		config.Identity.StateDirectory = filepath.Join(value, "identity")
	}
}

func (config Config) Validate() error {
	if config.Server.Listen == "" {
		return errors.New("server.listen is required")
	}
	host, _, err := net.SplitHostPort(config.Server.Listen)
	if err != nil {
		return fmt.Errorf("invalid server.listen: %w", err)
	}
	ip := net.ParseIP(host)
	if host == "" || (ip != nil && ip.IsUnspecified()) {
		return errors.New("wildcard server binds are not supported; bind an explicit loopback or approved mesh address")
	}
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	demoInsecureHTTP := config.DemoInsecurePrivateHTTP()
	if strings.EqualFold(os.Getenv("ANTIFLOCK_DEMO_ALLOW_INSECURE_PRIVATE_HTTP"), "true") && !demoInsecureHTTP {
		return errors.New("insecure private HTTP requires both demo flags, an explicit approved private IP, matching HTTP public URL, and no TLS files")
	}
	for _, value := range config.Server.ApprovedBindCIDRs {
		if _, _, parseErr := net.ParseCIDR(value); parseErr != nil {
			return fmt.Errorf("invalid approved bind CIDR %q: %w", value, parseErr)
		}
	}
	if !loopback {
		if ip == nil {
			return errors.New("non-loopback server.bind must be an explicit approved IP address")
		}
		if !isInternalIP(ip) {
			return errors.New("non-loopback bind must use a private or mesh address")
		}
		if strings.ToLower(os.Getenv("ANTIFLOCK_ALLOW_PUBLIC_BIND")) != "true" {
			return errors.New("non-loopback bind requires environment variable ANTIFLOCK_ALLOW_PUBLIC_BIND=true")
		}
		approved := false
		for _, value := range config.Server.ApprovedBindCIDRs {
			_, network, _ := net.ParseCIDR(value)
			if network.Contains(ip) {
				approved = true
			}
		}
		if !approved {
			return errors.New("non-loopback bind is outside server.approvedBindCIDRs")
		}
		if !demoInsecureHTTP && (config.Server.TLSCertFile == "" || config.Server.TLSKeyFile == "") {
			return errors.New("non-loopback bind requires configured TLS certificate and key files")
		}
	}
	if (config.Server.TLSCertFile == "") != (config.Server.TLSKeyFile == "") {
		return errors.New("server TLS certificate and key must be configured together")
	}
	publicURL, err := url.Parse(config.Server.PublicBaseURL)
	if err != nil || publicURL.Host == "" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return errors.New("server.publicBaseURL must be an absolute URL without credentials, query, or fragment")
	}
	if loopback && publicURL.Scheme != "http" && publicURL.Scheme != "https" {
		return errors.New("loopback public base URL must use http or https")
	}
	if !loopback && publicURL.Scheme != "https" && !demoInsecureHTTP {
		return errors.New("non-loopback public base URL must use https")
	}
	if publicURL.Path != "" && publicURL.Path != "/" {
		return errors.New("server.publicBaseURL must not contain a path prefix")
	}
	if len(config.Server.TrustedProxies) != 0 {
		return errors.New("trusted proxies are unsupported until forwarded-header verification is implemented")
	}
	if config.Storage.Path == "" || config.Identity.StateDirectory == "" {
		return errors.New("storage path and identity state directory are required")
	}
	if config.Storage.EventRetention <= 0 {
		return errors.New("event retention must be positive")
	}
	if config.Storage.AuditRetention != 0 {
		return errors.New("audit retention is unsupported until externally witnessed compaction is implemented")
	}
	if config.Identity.EnrollmentTokenTTL <= 0 || config.Identity.EnrollmentTokenTTL > 15*time.Minute {
		return errors.New("enrollment token TTL must be positive and no more than 15 minutes")
	}
	if config.Protection.FailMode != "closed" {
		return errors.New("the locked protection boundary requires fail mode closed")
	}
	if config.Protection.TelemetryStaleAfter <= 0 || config.Protection.TelemetryStaleAfter > 30*time.Minute {
		return errors.New("telemetry stale window must be positive and no more than 30 minutes")
	}
	if config.Protection.OneTimeBypassTTL <= 0 || config.Protection.OneTimeBypassTTL > 15*time.Minute {
		return errors.New("one-time bypass TTL must be positive and no more than 15 minutes")
	}
	if len(config.Protection.ProtectedActions) == 0 || len(config.Protection.ProtectedActions) > 64 {
		return errors.New("between one and 64 explicit protected action policies are required")
	}
	for index, action := range config.Protection.ProtectedActions {
		for field, values := range map[string][]string{
			"nodeIds": action.NodeIDs, "applicationIds": action.ApplicationIDs,
			"dataClasses": action.DataClasses, "allowedDestinations": action.AllowedDestinations,
		} {
			if err := validateProtectedActionValues(values); err != nil {
				return fmt.Errorf("protection.protectedActions[%d].%s: %w", index, field, err)
			}
		}
	}
	if config.Telemetry.CollectPayloads {
		return errors.New("packet payload collection is outside the locked release boundary")
	}
	if config.Scrambler.ExecutionEnabled {
		return errors.New("scrambler execution is deferred; simulation is the only supported mode")
	}
	return nil
}

func validateProtectedActionValues(values []string) error {
	if len(values) == 0 || len(values) > 32 {
		return errors.New("must contain between one and 32 explicit values")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > 512 || strings.TrimSpace(value) != value {
			return errors.New("contains an empty, untrimmed, or oversized value")
		}
		if value == "*" && len(values) != 1 {
			return errors.New("wildcard must be the sole value")
		}
		if _, exists := seen[value]; exists {
			return errors.New("contains duplicate values")
		}
		seen[value] = struct{}{}
	}
	return nil
}

// DemoInsecurePrivateHTTP reports the deliberately narrow developer-lab
// exception to production TLS and node mTLS. The exception exists only when
// both explicit environment flags are true and the server is bound to one
// approved private IP with a matching HTTP public URL and no TLS files.
func (config Config) DemoInsecurePrivateHTTP() bool {
	if !strings.EqualFold(os.Getenv("ANTIFLOCK_DEMO_MODE"), "true") ||
		!strings.EqualFold(os.Getenv("ANTIFLOCK_DEMO_ALLOW_INSECURE_PRIVATE_HTTP"), "true") ||
		config.Server.TLSCertFile != "" || config.Server.TLSKeyFile != "" {
		return false
	}
	host, listenPort, err := net.SplitHostPort(config.Server.Listen)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || !isInternalIP(ip) {
		return false
	}
	approved := false
	for _, value := range config.Server.ApprovedBindCIDRs {
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr == nil && network.Contains(ip) {
			approved = true
			break
		}
	}
	if !approved {
		return false
	}
	publicURL, err := url.Parse(config.Server.PublicBaseURL)
	if err != nil || publicURL.Scheme != "http" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return false
	}
	publicIP := net.ParseIP(publicURL.Hostname())
	publicPort := publicURL.Port()
	if publicPort == "" {
		publicPort = "80"
	}
	return publicIP != nil && publicIP.Equal(ip) && publicPort == listenPort
}

func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	cgnat := &net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)}
	return cgnat.Contains(ip)
}
