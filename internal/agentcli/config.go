package agentcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigSchema is the on-disk schema identifier of the agent config file.
const ConfigSchema = "antiflock.agent-config/v1"

const (
	maximumConfigBytes   = 64 << 10
	minimumInterval      = 5 * time.Second
	maximumInterval      = time.Hour
	PrivateFileMode      = 0o600
	PrivateDirectoryMode = 0o700
)

// Default locations on a Linux host. They are defaults only; every path is
// overridable through the config file and the corresponding flags.
const (
	DefaultConfigPath = "/etc/antiflock/agent.yaml"
	DefaultStateDir   = "/var/lib/antiflock"
	DefaultQueueDir   = "/var/lib/antiflock/queue"
)

// Config is the agent's operator-owned configuration. It carries no secret
// material: the node key lives in StateDir (agent/enrollment contract), the
// enrollment token is always passed as a private file at enroll time.
type Config struct {
	SchemaVersion string        `yaml:"schemaVersion"`
	NodeID        string        `yaml:"nodeId"`
	DisplayName   string        `yaml:"displayName"`
	DeploymentID  string        `yaml:"deploymentId"`
	CoreURL       string        `yaml:"coreUrl"`
	StateDir      string        `yaml:"stateDir"`
	QueueDir      string        `yaml:"queueDir"`
	CACert        string        `yaml:"caCert"`
	Interval      time.Duration `yaml:"interval"`
}

// DefaultConfig returns a config with the Linux default layout filled in and
// identity fields empty.
func DefaultConfig() Config {
	return Config{SchemaVersion: ConfigSchema, StateDir: DefaultStateDir, QueueDir: DefaultQueueDir, Interval: 30 * time.Second}
}

// Validate is fail-closed: any unknown, empty, or unsafe value is an error.
func (config Config) Validate() error {
	if config.SchemaVersion != ConfigSchema {
		return errors.New("config schemaVersion must be " + ConfigSchema)
	}
	if !canonicalIdentifier(config.NodeID, 128) {
		return errors.New("config nodeId must be a canonical identifier of at most 128 bytes")
	}
	if config.DisplayName != "" && !printableText(config.DisplayName, 128) {
		return errors.New("config displayName must be canonical and at most 128 bytes")
	}
	if !canonicalIdentifier(config.DeploymentID, 128) {
		return errors.New("config deploymentId must be a canonical identifier of at most 128 bytes")
	}
	if err := validateCoreURL(config.CoreURL); err != nil {
		return err
	}
	if err := validateAbsoluteDirectory("stateDir", config.StateDir); err != nil {
		return err
	}
	if err := validateAbsoluteDirectory("queueDir", config.QueueDir); err != nil {
		return err
	}
	if config.CACert != "" && (!filepath.IsAbs(config.CACert) || filepath.Clean(config.CACert) != config.CACert) {
		return errors.New("config caCert must be an absolute canonical path")
	}
	if config.Interval < minimumInterval || config.Interval > maximumInterval {
		return errors.New("config interval must be between 5s and 1h")
	}
	return nil
}

// KeyPath, CertificatePath, EnrollmentStatePath and QueueFile follow the
// agent/enrollment and agent/runtime on-disk contracts; they are not
// configurable separately so that every command agrees on one layout.
func (config Config) KeyPath() string         { return filepath.Join(config.StateDir, "node.seed") }
func (config Config) CertificatePath() string { return filepath.Join(config.StateDir, "node.pem") }
func (config Config) EnrollmentStatePath() string {
	return filepath.Join(config.StateDir, "enrollment.json")
}
func (config Config) QueueFile() string { return filepath.Join(config.QueueDir, "queue.json") }

// Encode renders the config as YAML in the same style as configs/*.yaml.
func (config Config) Encode() ([]byte, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString("# antiflock-agent configuration. No secrets belong in this file.\n")
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(config); err != nil {
		return nil, errors.New("encode agent config")
	}
	if err := encoder.Close(); err != nil {
		return nil, errors.New("encode agent config")
	}
	return buffer.Bytes(), nil
}

// LoadConfig reads and validates a config file. Unknown fields, symlinks,
// and oversized files are rejected.
func LoadConfig(path string) (Config, string, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, "", errors.New("config path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, "", errors.New("config file is missing")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > maximumConfigBytes {
		return Config{}, "", errors.New("config file must be a bounded regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, "", errors.New("read config file")
	}
	config, err := ParseConfig(content)
	if err != nil {
		return Config{}, "", err
	}
	return config, Digest(content), nil
}

// ParseConfig decodes YAML with unknown fields rejected, then validates.
func ParseConfig(content []byte) (Config, error) {
	if len(content) == 0 || len(content) > maximumConfigBytes {
		return Config{}, errors.New("config content must be non-empty and bounded")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("config file is not valid agent YAML")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, errors.New("config file contains more than one document")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Digest is the sha256 hex digest reported as the config identity.
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validateCoreURL(raw string) error {
	value, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || value.Scheme == "" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" {
		return errors.New("config coreUrl must be an absolute HTTP(S) URL without credentials")
	}
	switch value.Scheme {
	case "https":
		return nil
	case "http":
		host := value.Hostname()
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return errors.New("config coreUrl requires HTTPS outside loopback")
	default:
		return errors.New("config coreUrl scheme must be https (or http on loopback)")
	}
}

func validateAbsoluteDirectory(field, value string) error {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return errors.New("config " + field + " must be an absolute canonical path")
	}
	if filepath.Dir(value) == value {
		return errors.New("config " + field + " must not be a filesystem root")
	}
	return nil
}

// printableText allows spaces (display names) but no control characters,
// leading/trailing whitespace, or non-ASCII.
func printableText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}
