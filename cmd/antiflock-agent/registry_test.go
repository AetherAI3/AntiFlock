package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

func TestRegistryExposesTheFullProductSurface(t *testing.T) {
	t.Parallel()
	expected := []string{"doctor", "enroll", "init", "observe", "plan", "status", "uninstall", "update", "version"}
	if got := commandNames(); strings.Join(got, ",") != strings.Join(expected, ",") {
		t.Fatalf("registered commands = %v, want %v", got, expected)
	}
	for _, name := range expected {
		if commands[name].summary == "" {
			t.Errorf("%s has no summary", name)
		}
	}
}

func TestRegisterRejectsDuplicatesAndIncompleteCommands(t *testing.T) {
	t.Parallel()
	expectPanic := func(name string, c command) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: register did not panic", name)
			}
		}()
		register(c)
	}
	expectPanic("duplicate", command{name: "version", run: func(context.Context, []string, commandIO) int { return 0 }})
	expectPanic("no run", command{name: "ghost"})
	expectPanic("no name", command{run: func(context.Context, []string, commandIO) int { return 0 }})
}

func TestDispatchFallsThroughForUnclaimedArguments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"flag first", []string{"--node-id", "x"}},
		{"unknown", []string{"frobnicate"}},
		{"plan verify stays with plan.go", []string{"plan", "verify", "--plan", "x"}},
		{"bare plan", []string{"plan"}},
		{"legacy status form", []string{"status", "--node-id", "n", "--queue-dir", "/q"}},
		{"legacy enroll form", []string{"enroll", "--core-url", "https://core.example.test"}},
		{"legacy observe form", []string{"observe", "--node-id", "n"}},
	}
	for _, c := range cases {
		if code, handled := dispatch(context.Background(), c.args, &bytes.Buffer{}, &bytes.Buffer{}); handled {
			t.Errorf("%s: dispatch claimed %v (exit %d)", c.name, c.args, code)
		}
	}
	var nilContext context.Context
	if _, handled := dispatch(nilContext, []string{"version"}, &bytes.Buffer{}, &bytes.Buffer{}); handled {
		t.Fatal("nil context was dispatched")
	}
}

func TestDispatchRedactsCommandOutput(t *testing.T) {
	// Not parallel: it swaps the package-level registry.
	leaky := command{name: "leaky-test", run: func(_ context.Context, _ []string, out commandIO) int {
		out.stdout.Write([]byte("Authorization: Bearer leaked-token\n"))
		out.stderr.Write([]byte("password=hunter2"))
		return 0
	}}
	saved := commands
	t.Cleanup(func() { commands = saved })
	commands = map[string]command{leaky.name: leaky}
	var stdout, stderr bytes.Buffer
	if code, handled := dispatch(context.Background(), []string{"leaky-test"}, &stdout, &stderr); !handled || code != 0 {
		t.Fatalf("dispatch = %d %t", code, handled)
	}
	if strings.Contains(stdout.String(), "leaked-token") || strings.Contains(stderr.String(), "hunter2") {
		t.Fatalf("secrets leaked: %q %q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "[REDACTED]") {
		t.Fatalf("partial stderr line was not flushed: %q", stderr.String())
	}
}

func TestEveryCommandHonoursUsageExitCode(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"init", "doctor", "status", "update", "uninstall", "version"} {
		var stderr bytes.Buffer
		code, handled := dispatch(context.Background(), []string{name, "--definitely-not-a-flag"}, &bytes.Buffer{}, &stderr)
		if !handled || code != agentcli.ExitUsage {
			t.Errorf("%s: unknown flag exit = %d handled=%t", name, code, handled)
		}
		code, handled = dispatch(context.Background(), []string{name, "positional"}, &bytes.Buffer{}, &stderr)
		if !handled || code != agentcli.ExitUsage {
			t.Errorf("%s: positional exit = %d handled=%t", name, code, handled)
		}
	}
}

func decodeEnvelope(t *testing.T, content []byte) agentcli.Envelope {
	t.Helper()
	var envelope agentcli.Envelope
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("envelope decode: %v\n%s", err, content)
	}
	if envelope.Document != agentcli.Document || envelope.OK != (envelope.ExitCode == 0) {
		t.Fatalf("envelope invariants violated: %#v", envelope)
	}
	return envelope
}
