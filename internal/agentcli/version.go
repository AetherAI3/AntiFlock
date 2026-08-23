package agentcli

import (
	"runtime"
	"runtime/debug"
)

// VersionInfo is derived from the binary's embedded build information. The
// release pipeline builds with -buildvcs=true, so Revision and Modified are
// authoritative for release artifacts; a source build reports "(devel)".
type VersionInfo struct {
	Binary    string `json:"binary"`
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Modified  bool   `json:"modified"`
	BuildTime string `json:"buildTime,omitempty"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// ReadVersion reads build info; it never fails, unknown fields are "unknown".
func ReadVersion() VersionInfo {
	return versionFrom(debug.ReadBuildInfo())
}

func versionFrom(info *debug.BuildInfo, ok bool) VersionInfo {
	result := VersionInfo{Binary: "antiflock-agent", Version: "unknown", Revision: "unknown", GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if !ok || info == nil {
		return result
	}
	if info.Main.Version != "" {
		result.Version = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			result.Revision = setting.Value
		case "vcs.modified":
			result.Modified = setting.Value == "true"
		case "vcs.time":
			result.BuildTime = setting.Value
		}
	}
	return result
}
