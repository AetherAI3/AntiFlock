package hostile_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/sim"
)

// fakeCore answers only the two read endpoints the simulator consults before
// it touches local state. It never enrolls anything.
func fakeCore(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/overview", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"deploymentName":"deployment-fixture"}`))
	})
	mux.HandleFunc("GET /v1/nodes", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"nodes":[]}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func liveConfig(core *httptest.Server, stateDirectory string) sim.LiveConfig {
	return sim.LiveConfig{
		CoreURL:       core.URL,
		OperatorToken: strings.Repeat("o", 40), AgentToken: strings.Repeat("a", 40), SDKToken: strings.Repeat("s", 40),
		NodeID: "sim-agent-node", ApplicationID: "aether-code", StateDirectory: stateDirectory, DemoMode: true,
		Clock: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) },
	}
}

func bootstrapError(t *testing.T, config sim.LiveConfig) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return sim.RunLiveStream(ctx, config, time.Hour, func(sim.LiveStreamEvent) error {
		cancel()
		return context.Canceled
	})
}

// Invariant: the simulator's persistent identity state is loaded only from a
// real, private, bounded, schema-exact file. Symlinks, oversized files, loose
// modes, trailing data, and foreign node identities abort bootstrap.
func TestSimulatorLiveStateRejectsHostileFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: simulator state checks use POSIX modes and symlinks")
	}
	core := fakeCore(t)
	validState := `{"schemaVersion":"antiflock.sim-state/v1","nodeId":"sim-agent-node","bootId":"boot","publicKeyDigest":"` + strings.Repeat("a", 64) + `","enrollmentIssuedAt":"2026-07-22T12:00:00Z","lastSequence":1}`
	cases := map[string]func(t *testing.T, directory string){
		"state-symlinked": func(t *testing.T, directory string) {
			target := filepath.Join(filepath.Dir(directory), "target.json")
			if err := os.WriteFile(target, []byte(validState), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(directory, "state.json")); err != nil {
				t.Fatal(err)
			}
		},
		"state-oversized": func(t *testing.T, directory string) {
			padded := strings.Replace(validState, `"bootId":"boot"`, `"bootId":"`+strings.Repeat("b", 40*1024)+`"`, 1)
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(padded), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"state-world-readable": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(validState), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"state-trailing-data": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(validState+"{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"state-unknown-field": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(strings.Replace(validState, `"lastSequence"`, `"admin":true,"lastSequence"`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"state-foreign-node": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(strings.Replace(validState, "sim-agent-node", "other-node", 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"state-empty": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "state.json"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"state-without-key": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(validState), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"key-without-state": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "node.seed"), make([]byte, 32), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"key-wrong-length": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(validState), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "node.seed"), make([]byte, 31), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"key-symlinked": func(t *testing.T, directory string) {
			target := filepath.Join(filepath.Dir(directory), "seed")
			if err := os.WriteFile(target, make([]byte, 32), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(directory, "node.seed")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			arrange(t, directory)
			err := bootstrapError(t, liveConfig(core, directory))
			if err == nil || !strings.Contains(err.Error(), "bootstrap simulator") {
				t.Fatalf("%s: bootstrap err = %v, want a bootstrap failure", name, err)
			}
			if strings.Contains(err.Error(), strings.Repeat("a", 64)) || strings.Contains(err.Error(), "admin") {
				t.Fatalf("%s: error echoes state file content: %v", name, err)
			}
		})
	}
}

// Invariant: the simulator state directory itself must not be a symlink and
// must be private, checked before any network call is made.
func TestSimulatorLiveStateRejectsSymlinkedDirectoryBeforeNetwork(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: symlink creation requires privilege on Windows")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("ENV-UNAVAILABLE: symlinks unavailable on this filesystem")
	}
	unreachable := httptest.NewUnstartedServer(http.NotFoundHandler())
	unreachable.Start()
	unreachable.Close()
	config := liveConfig(unreachable, link)
	err := bootstrapError(t, config)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink rejection before any Core request", err)
	}
}

// Invariant: plain HTTP Core URLs require explicit demo mode and credentials
// must be distinct and bounded; hostile configuration never reaches disk.
func TestSimulatorLiveConfigRejectsUnsafeTransportAndCredentials(t *testing.T) {
	t.Parallel()
	core := fakeCore(t)
	directory := filepath.Join(t.TempDir(), "state")
	good := liveConfig(core, directory)
	cases := map[string]func(config *sim.LiveConfig){
		"plain-http-without-demo": func(config *sim.LiveConfig) { config.DemoMode = false },
		"shared-credentials":      func(config *sim.LiveConfig) { config.AgentToken = config.OperatorToken },
		"short-credential":        func(config *sim.LiveConfig) { config.SDKToken = "short" },
		"url-with-userinfo":       func(config *sim.LiveConfig) { config.CoreURL = strings.Replace(config.CoreURL, "http://", "http://u:p@", 1) },
		"url-with-query":          func(config *sim.LiveConfig) { config.CoreURL += "/?x=1" },
		"node-id-with-newline":    func(config *sim.LiveConfig) { config.NodeID = "sim\nnode" },
		"node-id-oversize":        func(config *sim.LiveConfig) { config.NodeID = strings.Repeat("n", 4096) },
		"empty-state-directory":   func(config *sim.LiveConfig) { config.StateDirectory = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config := good
			mutate(&config)
			err := bootstrapError(t, config)
			if err == nil || strings.Contains(err.Error(), "bootstrap simulator") {
				t.Fatalf("%s: err = %v, want a configuration rejection before bootstrap", name, err)
			}
			if _, statErr := os.Stat(directory); statErr == nil {
				t.Fatalf("%s: state directory was created for a rejected configuration", name)
			}
		})
	}
}

// Control: a clean state directory gets past every local-state check and
// fails only at enrollment, which the fake Core does not offer. This proves
// the hostile cases above fail because of the state, not the fixture.
func TestSimulatorLiveStateControlReachesEnrollment(t *testing.T) {
	t.Parallel()
	core := fakeCore(t)
	directory := filepath.Join(t.TempDir(), "state")
	err := bootstrapError(t, liveConfig(core, directory))
	if err == nil {
		t.Fatal("bootstrap succeeded against a Core with no enrollment endpoint")
	}
	for _, local := range []string{"state", "symlink", "private", "key"} {
		if strings.Contains(err.Error(), local) {
			t.Fatalf("control run failed on local state: %v", err)
		}
	}
	t.Logf("control failure (expected, at the network boundary): %v", err)
}
