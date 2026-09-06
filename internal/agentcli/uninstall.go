package agentcli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SystemdUnitPaths are the only unit locations uninstall will ever name.
var SystemdUnitPaths = []string{"/etc/systemd/system/antiflock-agent.service", "/usr/lib/systemd/system/antiflock-agent.service"}

// UninstallOptions drives Uninstall.
type UninstallOptions struct {
	ConfigPath string
	// Yes performs the removal; the default is a dry run.
	Yes bool
	// Systemd allows running the unit removal commands (requires root).
	Systemd bool
	EUID    int
	// RunSystemctl executes one systemctl verb; nil prints the commands only.
	RunSystemctl func(arguments ...string) error
}

// UninstallResult is the uninstall payload.
type UninstallResult struct {
	DryRun          bool     `json:"dryRun"`
	Roots           []string `json:"roots"`
	WouldRemove     []string `json:"wouldRemove"`
	Removed         []string `json:"removed"`
	Refused         []string `json:"refused"`
	SystemdCommands []string `json:"systemdCommands"`
	SystemdRan      bool     `json:"systemdRan"`
	FirewallNote    string   `json:"firewallNote"`
}

const firewallNote = "Firewall state is never touched by uninstall. Removing an AntiFlock nftables table requires an explicit, verified recovery plan."

// Uninstall enumerates and (with Yes) removes the agent's own directories,
// config, and keys. Every path is containment-checked against the config
// roots; any path that escapes is refused and the command exits 6.
func Uninstall(options UninstallOptions) (UninstallResult, []Reason, int) {
	result := UninstallResult{DryRun: !options.Yes, Roots: []string{}, WouldRemove: []string{}, Removed: []string{}, Refused: []string{}, SystemdCommands: []string{}, FirewallNote: firewallNote}
	config, _, err := LoadConfig(options.ConfigPath)
	if err != nil {
		return result, []Reason{{Code: "AF-UNINSTALL-CONFIG-INVALID", Message: err.Error()}}, ExitPrecondition
	}
	reasons := []Reason{}
	roots := []string{config.StateDir, config.QueueDir}
	if strings.HasPrefix(config.QueueDir, config.StateDir+string(filepath.Separator)) {
		roots = []string{config.StateDir}
	}
	for _, root := range roots {
		switch {
		case IsProtectedRoot(root):
			result.Refused = append(result.Refused, root)
			reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REFUSED-PROTECTED-ROOT", Message: "configured directory is a protected system root: " + Safe(root)})
		case !RealDirectory(root):
			if _, err := os.Lstat(root); err == nil {
				result.Refused = append(result.Refused, root)
				reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REFUSED-NOT-CONTAINED", Message: "configured directory is not a real directory: " + Safe(root)})
			}
		default:
			result.Roots = append(result.Roots, root)
		}
	}
	for _, root := range result.Roots {
		entries, refused := enumerate(root)
		result.WouldRemove = append(result.WouldRemove, entries...)
		for _, path := range refused {
			result.Refused = append(result.Refused, path)
			reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REFUSED-NOT-CONTAINED", Message: "entry escapes its root and was refused: " + Safe(path)})
		}
	}
	configPath := filepath.Clean(options.ConfigPath)
	if info, err := os.Lstat(configPath); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && filepath.IsAbs(configPath) {
		result.WouldRemove = append(result.WouldRemove, configPath)
	}
	result.SystemdCommands = []string{"systemctl disable --now antiflock-agent.service"}
	for _, unit := range SystemdUnitPaths {
		if _, err := os.Lstat(unit); err == nil {
			result.SystemdCommands = append(result.SystemdCommands, "rm -- "+unit)
		}
	}
	result.SystemdCommands = append(result.SystemdCommands, "systemctl daemon-reload")
	if len(result.Refused) != 0 {
		reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REFUSED", Message: "nothing was removed because at least one path is outside the configured directories"})
		return result, reasons, ExitRefused
	}
	if !options.Yes {
		reasons = append(reasons, Reason{Code: "AF-UNINSTALL-DRY-RUN", Message: "dry run; pass --yes to remove the listed paths"})
		return result, reasons, ExitOK
	}
	// Removal order: deepest entries first, each re-checked for containment
	// against its root right before removal.
	for _, root := range result.Roots {
		entries, refused := enumerate(root)
		if len(refused) != 0 {
			reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REFUSED", Message: "layout changed during removal; stopped"})
			return result, reasons, ExitRefused
		}
		for _, path := range entries {
			if err := Contained(root, path); err != nil {
				result.Refused = append(result.Refused, path)
				reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REFUSED-NOT-CONTAINED", Message: "entry escapes its root and was refused: " + Safe(path)})
				return result, reasons, ExitRefused
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REMOVE-FAILED", Message: "could not remove " + Safe(path)})
				return result, reasons, ExitDegraded
			}
			result.Removed = append(result.Removed, path)
		}
	}
	if containsPath(result.WouldRemove, configPath) {
		if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			reasons = append(reasons, Reason{Code: "AF-UNINSTALL-REMOVE-FAILED", Message: "could not remove the config file"})
			return result, reasons, ExitDegraded
		}
		result.Removed = append(result.Removed, configPath)
	}
	if options.Systemd {
		if options.EUID != 0 || options.RunSystemctl == nil {
			reasons = append(reasons, Reason{Code: "AF-UNINSTALL-SYSTEMD-REQUIRES-ROOT", Message: "unit removal was not run; run the printed commands as root"})
		} else {
			if err := options.RunSystemctl("disable", "--now", "antiflock-agent.service"); err != nil {
				reasons = append(reasons, Reason{Code: "AF-UNINSTALL-SYSTEMD-FAILED", Message: "systemctl disable failed; run the printed commands manually"})
				return result, reasons, ExitDegraded
			}
			for _, unit := range SystemdUnitPaths {
				if err := os.Remove(unit); err != nil && !errors.Is(err, os.ErrNotExist) {
					reasons = append(reasons, Reason{Code: "AF-UNINSTALL-SYSTEMD-FAILED", Message: "could not remove the unit file; run the printed commands manually"})
					return result, reasons, ExitDegraded
				}
			}
			_ = options.RunSystemctl("daemon-reload")
			result.SystemdRan = true
		}
	} else {
		reasons = append(reasons, Reason{Code: "AF-UNINSTALL-SYSTEMD-PRINTED", Message: "systemd unit removal commands were printed, not run (pass --systemd as root)"})
	}
	reasons = append(reasons, Reason{Code: "AF-UNINSTALL-FIREWALL-UNTOUCHED", Message: firewallNote})
	return result, reasons, ExitOK
}

// enumerate lists every entry under root, deepest first, with root last.
// Symbolic links are listed as links and never followed. Entries whose
// containment check fails are returned separately.
func enumerate(root string) (entries, refused []string) {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			refused = append(refused, path)
			return nil
		}
		if containErr := Contained(root, path); containErr != nil {
			refused = append(refused, path)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		entries = append(entries, path)
		return nil
	})
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i]) != len(entries[j]) {
			return len(entries[i]) > len(entries[j])
		}
		return entries[i] > entries[j]
	})
	return entries, refused
}

func containsPath(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
