// Package netns is a reusable rootless network-namespace harness for tests
// that need a real kernel networking stack (nft, ip route, resolvers) without
// root and without ever touching the developer host.
//
// Contract:
//
//   - RequireRootlessNetns(t) skips with an ENV-UNAVAILABLE reason when the
//     harness cannot run here (not Linux, no unshare binary, user namespaces
//     disabled). A skip is never a pass; docs/adversarial-qualification.md
//     records which CI job is required to run these tests for real.
//
//   - RunInNetns(t, body) runs body inside a fresh user+network namespace
//     created by `unshare -rn`. Go cannot safely unshare a user namespace
//     from a multi-threaded process, so the harness re-executes the current
//     test binary under unshare with -test.run pinned to the calling test and
//     an environment marker; the child invocation runs body directly. The
//     parent fails when the child exits non-zero and relays its output.
//
//   - Inside the namespace the process is uid 0 of the namespace, owns an
//     empty nftables ruleset and a loopback-only link table, and cannot see or
//     modify the host's tables, routes, or interfaces. Mutating nft/ip inside
//     body is therefore safe by construction.
//
//   - Command(t, name, args...) runs a tool inside body with a bounded timeout
//     and returns its stdout; it fails the test on a non-zero exit.
//
// Intended consumers: S6 (nftables driver), S7A/B/C (mesh, route, dns drivers)
// and the self-test in this package.
package netns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ChildMarker is the environment variable that tells a re-executed test
// binary it is already inside the namespace. Its value is the test name.
const ChildMarker = "ANTIFLOCK_NETNS_CHILD"

const probeTimeout = 10 * time.Second

// Availability reports whether the harness can run and, if not, why.
type Availability struct {
	Available bool
	Reason    string
}

// Probe checks, without side effects beyond spawning `unshare -rn -- true`,
// whether a rootless network namespace can be created on this host.
func Probe(ctx context.Context) Availability {
	if runtime.GOOS != "linux" {
		return Availability{Reason: "ENV-UNAVAILABLE: rootless network namespaces require Linux (GOOS=" + runtime.GOOS + ")"}
	}
	unsharePath, err := exec.LookPath("unshare")
	if err != nil {
		return Availability{Reason: "ENV-UNAVAILABLE: unshare(1) is not on PATH"}
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, unsharePath, "-rn", "--", "true")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return Availability{Reason: "ENV-UNAVAILABLE: `unshare -rn` failed (user namespaces disabled or restricted): " + sanitize(detail)}
	}
	return Availability{Available: true}
}

// RequireRootlessNetns skips the calling test when the harness is unusable.
func RequireRootlessNetns(t testing.TB) {
	t.Helper()
	availability := Probe(context.Background())
	if !availability.Available {
		t.Skip(availability.Reason)
	}
}

// InChild reports whether this process is the namespaced re-execution of
// the named test.
func InChild(testName string) bool {
	return os.Getenv(ChildMarker) == testName
}

// RunInNetns executes body inside a fresh rootless network namespace. See the
// package documentation for the re-exec mechanism.
func RunInNetns(t *testing.T, body func(t *testing.T)) {
	t.Helper()
	if InChild(t.Name()) {
		body(t)
		return
	}
	RequireRootlessNetns(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("netns: locate test binary: %v", err)
	}
	pattern := runPattern(t.Name())
	ctx, cancel := context.WithTimeout(context.Background(), childTimeout(t))
	defer cancel()
	command := exec.CommandContext(ctx, "unshare", "-rn", "--", executable,
		"-test.run", pattern, "-test.count=1", "-test.v", "-test.timeout", childTimeout(t).String())
	command.Env = append(os.Environ(), ChildMarker+"="+t.Name())
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err = command.Run()
	text := sanitize(output.String())
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("netns child for %s failed (exit %d):\n%s", t.Name(), exitErr.ExitCode(), text)
		}
		t.Fatalf("netns child for %s could not run: %v\n%s", t.Name(), err, text)
	}
	if !strings.Contains(text, "--- PASS: "+t.Name()) && !strings.Contains(text, "--- PASS: "+lastSegment(t.Name())) {
		t.Fatalf("netns child for %s produced no PASS line:\n%s", t.Name(), text)
	}
	t.Logf("netns child output:\n%s", text)
}

// Command runs a tool inside the namespace with a bounded timeout and returns
// its trimmed stdout. It must only be called from inside a RunInNetns body.
func Command(t testing.TB, name string, args ...string) string {
	t.Helper()
	if os.Getenv(ChildMarker) == "" {
		t.Fatalf("netns.Command(%s) called outside a RunInNetns body; refusing to run it on the host", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, sanitize(stderr.String()))
	}
	return strings.TrimSpace(stdout.String())
}

// TryCommand is Command without failing; it returns stdout, stderr, and the
// error so callers can assert on an expected refusal.
func TryCommand(t testing.TB, name string, args ...string) (string, string, error) {
	t.Helper()
	if os.Getenv(ChildMarker) == "" {
		t.Fatalf("netns.TryCommand(%s) called outside a RunInNetns body; refusing to run it on the host", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err
}

func runPattern(name string) string {
	parts := strings.Split(name, "/")
	for index, part := range parts {
		parts[index] = "^" + regexpQuote(part) + "$"
	}
	return strings.Join(parts, "/")
}

func regexpQuote(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			builder.WriteByte('\\')
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func lastSegment(name string) string {
	if index := strings.LastIndex(name, "/"); index >= 0 {
		return name[index+1:]
	}
	return name
}

func childTimeout(t *testing.T) time.Duration {
	if deadline, ok := t.Deadline(); ok {
		if remaining := time.Until(deadline) - 5*time.Second; remaining > time.Second {
			return remaining
		}
	}
	return 2 * time.Minute
}

// sanitize strips control characters other than newline and tab so relayed
// child output cannot carry terminal escapes into structured logs.
func sanitize(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r == '\n' || r == '\t':
			builder.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&builder, "\\x%02x", r)
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
