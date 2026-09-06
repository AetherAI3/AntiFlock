package agentcli

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Check statuses are independent: one FAIL never hides another WARN.
const (
	StatusPass    = "PASS"
	StatusWarn    = "WARN"
	StatusFail    = "FAIL"
	StatusUnknown = "UNKNOWN"
)

// Runner executes one trusted host command and returns its output. Doctor
// only ever uses it for read-only listing; output never reaches the
// envelope, only a derived boolean does.
type Runner interface {
	Run(ctx context.Context, executable string, arguments ...string) ([]byte, error)
}

// ExecRunner is the production Runner. It refuses anything but the single
// read-only invocation doctor needs.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	if filepath.Base(executable) != "nft" || len(arguments) != 2 || arguments[0] != "list" || arguments[1] != "tables" {
		return nil, errors.New("doctor runner only permits nft list tables")
	}
	runContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(runContext, executable, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return command.Output()
}

// Environment is every host dependency doctor touches, injected so tests run
// without nft, ip, systemd, or network access.
type Environment struct {
	GOOS        string
	Now         func() time.Time
	EUID        int
	LookPath    func(file string) (string, error)
	Dial        func(ctx context.Context, coreURL string) error
	Runner      Runner
	DiskFree    func(path string) (uint64, error)
	OwnedByRoot func(info os.FileInfo) (bool, error)
	// TrustRoot bounds the parent-directory walk of the executable trust
	// check; production uses "/", tests use their temp root.
	TrustRoot      string
	SystemdPath    string
	ResolvConfPath string
	NftCandidates  []string
	IPCandidates   []string
}

// DefaultEnvironment is the production environment.
func DefaultEnvironment() Environment {
	return Environment{
		GOOS: osGOOS(), Now: func() time.Time { return time.Now().UTC() }, EUID: os.Geteuid(),
		LookPath: exec.LookPath, Dial: dialCore, Runner: ExecRunner{}, DiskFree: diskFree, OwnedByRoot: ownedByRoot,
		TrustRoot: "/", SystemdPath: "/run/systemd/system", ResolvConfPath: "/etc/resolv.conf",
		NftCandidates: []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"},
		IPCandidates:  []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"},
	}
}

// Check is one doctor finding.
type Check struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	ReasonCode string `json:"reasonCode"`
	Message    string `json:"message"`
	// Recovery marks checks that are prerequisites for host recovery
	// (future enforcement), not for observe mode.
	Recovery bool `json:"recovery"`
}

// DoctorResult is the doctor payload.
type DoctorResult struct {
	Checks                      []Check        `json:"checks"`
	Summary                     map[string]int `json:"summary"`
	MissingRecoveryRequirements []string       `json:"missingRecoveryRequirements"`
	Offline                     bool           `json:"offline"`
}

// DoctorOptions drives Doctor.
type DoctorOptions struct {
	ConfigPath string
	Offline    bool
	Env        Environment
}

const (
	diskFailBytes = 64 << 20
	diskWarnBytes = 256 << 20
)

// Doctor runs every check and derives the exit code: 3 if any FAIL, 7 if
// only WARN, otherwise 0. UNKNOWN never changes the exit code on its own.
func Doctor(ctx context.Context, options DoctorOptions) (DoctorResult, int) {
	env := options.Env
	result := DoctorResult{Summary: map[string]int{StatusPass: 0, StatusWarn: 0, StatusFail: 0, StatusUnknown: 0}, MissingRecoveryRequirements: []string{}, Offline: options.Offline}
	add := func(check Check) { result.Checks = append(result.Checks, check) }

	if env.GOOS == "linux" {
		add(Check{ID: "os", Status: StatusPass, ReasonCode: "AF-DOCTOR-OS-LINUX", Message: "linux host"})
	} else {
		add(Check{ID: "os", Status: StatusWarn, ReasonCode: "AF-DOCTOR-OS-UNSUPPORTED", Message: "antiflock-agent local collection supports Linux only; host is " + Safe(env.GOOS)})
	}
	if env.EUID == 0 {
		add(Check{ID: "privilege", Status: StatusPass, ReasonCode: "AF-DOCTOR-PRIVILEGE-ROOT", Message: "running as root; observe mode does not require it"})
	} else {
		add(Check{ID: "privilege", Status: StatusPass, ReasonCode: "AF-DOCTOR-PRIVILEGE-UNPRIVILEGED", Message: "running unprivileged; observe mode needs no privilege, root-only checks are UNKNOWN"})
	}

	config, _, err := LoadConfig(options.ConfigPath)
	configOK := err == nil
	if configOK {
		add(Check{ID: "config", Status: StatusPass, ReasonCode: "AF-DOCTOR-CONFIG-VALID", Message: "config present and valid"})
	} else {
		add(Check{ID: "config", Status: StatusFail, ReasonCode: "AF-DOCTOR-CONFIG-INVALID", Message: err.Error()})
	}
	if configOK {
		if _, err := KeyID(config.KeyPath()); err == nil {
			add(Check{ID: "key", Status: StatusPass, ReasonCode: "AF-DOCTOR-KEY-PRIVATE", Message: "node key present with private permissions"})
		} else if _, statErr := os.Lstat(config.KeyPath()); errors.Is(statErr, os.ErrNotExist) {
			add(Check{ID: "key", Status: StatusFail, ReasonCode: "AF-DOCTOR-KEY-MISSING", Message: "node key is missing; run antiflock-agent init"})
		} else {
			add(Check{ID: "key", Status: StatusFail, ReasonCode: "AF-DOCTOR-KEY-UNSAFE", Message: err.Error()})
		}
		add(directoryCheck("state-dir", "AF-DOCTOR-STATE-DIR", config.StateDir))
		add(directoryCheck("queue-dir", "AF-DOCTOR-QUEUE-DIR", config.QueueDir))
		add(writableCheck(config.QueueDir))
		add(diskCheck(env, config.StateDir))
		add(coreCheck(ctx, env, options.Offline, config.CoreURL))
	} else {
		for _, id := range []string{"key", "state-dir", "queue-dir", "queue-writable", "disk", "core"} {
			add(Check{ID: id, Status: StatusUnknown, ReasonCode: "AF-DOCTOR-SKIPPED-NO-CONFIG", Message: "skipped because the config is unusable"})
		}
	}

	now := time.Time{}
	if env.Now != nil {
		now = env.Now()
	}
	if now.Year() < 2024 {
		add(Check{ID: "clock", Status: StatusWarn, ReasonCode: "AF-DOCTOR-CLOCK-IMPLAUSIBLE", Message: "system clock is before 2024; signatures and certificate checks will be wrong"})
	} else {
		add(Check{ID: "clock", Status: StatusPass, ReasonCode: "AF-DOCTOR-CLOCK-PLAUSIBLE", Message: "system clock is plausible"})
	}

	nftPath, nftCheck := trustedBinaryCheck(env, "nft", "AF-DOCTOR-NFT", env.NftCandidates, true)
	add(nftCheck)
	_, ipCheck := trustedBinaryCheck(env, "ip", "AF-DOCTOR-IP", env.IPCandidates, true)
	add(ipCheck)
	if content, err := os.ReadFile(env.ResolvConfPath); err == nil && len(content) > 0 {
		add(Check{ID: "resolv-conf", Status: StatusPass, ReasonCode: "AF-DOCTOR-RESOLV-CONF-READABLE", Message: "resolver configuration is readable"})
	} else {
		add(Check{ID: "resolv-conf", Status: StatusWarn, ReasonCode: "AF-DOCTOR-RESOLV-CONF-UNREADABLE", Message: "resolver configuration is missing or unreadable; DNS observations will be empty"})
	}
	if RealDirectory(env.SystemdPath) {
		add(Check{ID: "systemd", Status: StatusPass, ReasonCode: "AF-DOCTOR-SYSTEMD-PRESENT", Message: "systemd is the running init"})
	} else {
		add(Check{ID: "systemd", Status: StatusWarn, ReasonCode: "AF-DOCTOR-SYSTEMD-ABSENT", Message: "systemd not detected; the packaged unit will not manage the agent"})
	}
	add(nftTableCheck(ctx, env, nftPath))

	for _, check := range result.Checks {
		result.Summary[check.Status]++
		if check.Recovery && check.Status != StatusPass {
			result.MissingRecoveryRequirements = append(result.MissingRecoveryRequirements, check.ID+" ("+check.ReasonCode+")")
		}
	}
	result.MissingRecoveryRequirements = append(result.MissingRecoveryRequirements, "recovery-driver (AF-DOCTOR-RECOVERY-NOT-WIRED)")
	switch {
	case result.Summary[StatusFail] > 0:
		return result, ExitPrecondition
	case result.Summary[StatusWarn] > 0:
		return result, ExitDegraded
	default:
		return result, ExitOK
	}
}

func directoryCheck(id, prefix, directory string) Check {
	info, err := os.Lstat(directory)
	switch {
	case err != nil:
		return Check{ID: id, Status: StatusFail, ReasonCode: prefix + "-MISSING", Message: "directory is missing; run antiflock-agent init"}
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		return Check{ID: id, Status: StatusFail, ReasonCode: prefix + "-NOT-DIRECTORY", Message: "path is not a real directory"}
	case info.Mode().Perm() != PrivateDirectoryMode:
		return Check{ID: id, Status: StatusFail, ReasonCode: prefix + "-PERMISSIONS", Message: "directory must be mode 0700"}
	default:
		return Check{ID: id, Status: StatusPass, ReasonCode: prefix + "-PRIVATE", Message: "private directory present"}
	}
}

func writableCheck(directory string) Check {
	if !RealDirectory(directory) {
		return Check{ID: "queue-writable", Status: StatusFail, ReasonCode: "AF-DOCTOR-QUEUE-NOT-WRITABLE", Message: "queue directory is missing"}
	}
	probe, err := os.CreateTemp(directory, ".doctor-*")
	if err != nil {
		return Check{ID: "queue-writable", Status: StatusFail, ReasonCode: "AF-DOCTOR-QUEUE-NOT-WRITABLE", Message: "queue directory is not writable by this user"}
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return Check{ID: "queue-writable", Status: StatusPass, ReasonCode: "AF-DOCTOR-QUEUE-WRITABLE", Message: "queue directory is writable"}
}

func diskCheck(env Environment, directory string) Check {
	if env.DiskFree == nil {
		return Check{ID: "disk", Status: StatusUnknown, ReasonCode: "AF-DOCTOR-DISK-UNSUPPORTED", Message: "free-space query is unavailable on this platform"}
	}
	free, err := env.DiskFree(directory)
	switch {
	case err != nil:
		return Check{ID: "disk", Status: StatusUnknown, ReasonCode: "AF-DOCTOR-DISK-UNSUPPORTED", Message: "free-space query failed"}
	case free < diskFailBytes:
		return Check{ID: "disk", Status: StatusFail, ReasonCode: "AF-DOCTOR-DISK-FULL", Message: "less than 64 MiB free for the state directory"}
	case free < diskWarnBytes:
		return Check{ID: "disk", Status: StatusWarn, ReasonCode: "AF-DOCTOR-DISK-LOW", Message: "less than 256 MiB free for the state directory"}
	default:
		return Check{ID: "disk", Status: StatusPass, ReasonCode: "AF-DOCTOR-DISK-OK", Message: "state directory has sufficient free space"}
	}
}

func coreCheck(ctx context.Context, env Environment, offline bool, coreURL string) Check {
	if offline {
		return Check{ID: "core", Status: StatusUnknown, ReasonCode: "AF-DOCTOR-CORE-SKIPPED-OFFLINE", Message: "core reachability skipped (--offline)"}
	}
	if env.Dial == nil {
		return Check{ID: "core", Status: StatusUnknown, ReasonCode: "AF-DOCTOR-CORE-SKIPPED-OFFLINE", Message: "no dialer available"}
	}
	if err := env.Dial(ctx, coreURL); err != nil {
		return Check{ID: "core", Status: StatusWarn, ReasonCode: "AF-DOCTOR-CORE-UNREACHABLE", Message: "core URL did not accept a TCP connection"}
	}
	return Check{ID: "core", Status: StatusPass, ReasonCode: "AF-DOCTOR-CORE-REACHABLE", Message: "core URL accepted a TCP connection"}
}

// trustedBinaryCheck reimplements the trust shape of the enforcement
// adapter's executable validation: canonical absolute path, no symlink,
// root-owned, not group/world writable, and the same for every parent.
func trustedBinaryCheck(env Environment, name, prefix string, candidates []string, recovery bool) (string, Check) {
	for _, candidate := range candidates {
		if _, err := os.Lstat(candidate); err != nil {
			continue
		}
		if err := trustedExecutable(env, candidate); err != nil {
			return "", Check{ID: name, Status: StatusWarn, ReasonCode: prefix + "-UNTRUSTED", Message: name + " found but not trusted: " + err.Error(), Recovery: recovery}
		}
		return candidate, Check{ID: name, Status: StatusPass, ReasonCode: prefix + "-TRUSTED", Message: name + " present at a trusted system path", Recovery: recovery}
	}
	if env.LookPath != nil {
		if _, err := env.LookPath(name); err == nil {
			return "", Check{ID: name, Status: StatusWarn, ReasonCode: prefix + "-UNTRUSTED", Message: name + " is only reachable via PATH, not at a trusted system path", Recovery: recovery}
		}
	}
	return "", Check{ID: name, Status: StatusWarn, ReasonCode: prefix + "-MISSING", Message: name + " is not installed", Recovery: recovery}
}

func trustedExecutable(env Environment, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path is not absolute and canonical")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("path traverses a symlink")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("executable mode is unsafe")
	}
	if env.OwnedByRoot != nil {
		if owned, err := env.OwnedByRoot(info); err != nil || !owned {
			return errors.New("executable is not owned by root")
		}
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return errors.New("parent directory is writable by group or other")
		}
		if env.OwnedByRoot != nil {
			if owned, err := env.OwnedByRoot(info); err != nil || !owned {
				return errors.New("parent directory is not owned by root")
			}
		}
		if parent := filepath.Dir(directory); parent == directory || directory == env.TrustRoot {
			return nil
		}
	}
}

func nftTableCheck(ctx context.Context, env Environment, nftPath string) Check {
	check := Check{ID: "nft-table", Recovery: true}
	switch {
	case env.EUID != 0:
		check.Status, check.ReasonCode, check.Message = StatusUnknown, "AF-DOCTOR-NFT-TABLE-REQUIRES-ROOT", "reading nftables tables requires root; skipped"
	case nftPath == "":
		check.Status, check.ReasonCode, check.Message = StatusUnknown, "AF-DOCTOR-NFT-TABLE-NO-TRUSTED-NFT", "no trusted nft binary to list tables with"
	case env.Runner == nil:
		check.Status, check.ReasonCode, check.Message = StatusUnknown, "AF-DOCTOR-NFT-TABLE-NO-RUNNER", "no command runner available"
	default:
		output, err := env.Runner.Run(ctx, nftPath, "list", "tables")
		if err != nil {
			check.Status, check.ReasonCode, check.Message = StatusWarn, "AF-DOCTOR-NFT-TABLE-LIST-FAILED", "nft list tables failed"
		} else if strings.Contains(string(output), "antiflock") {
			check.Status, check.ReasonCode, check.Message = StatusPass, "AF-DOCTOR-NFT-TABLE-PRESENT", "an AntiFlock nftables table exists (read-only observation)"
		} else {
			check.Status, check.ReasonCode, check.Message = StatusPass, "AF-DOCTOR-NFT-TABLE-ABSENT", "no AntiFlock nftables table exists; nothing to recover"
		}
	}
	return check
}

func dialCore(ctx context.Context, coreURL string) error {
	value, err := url.Parse(coreURL)
	if err != nil || value.Host == "" {
		return errors.New("core URL is invalid")
	}
	host, port := value.Hostname(), value.Port()
	if port == "" {
		port = "443"
		if value.Scheme == "http" {
			port = "80"
		}
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	return connection.Close()
}
