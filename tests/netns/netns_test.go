package netns_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/tests/netns"
)

// Self-test: inside a rootless namespace the process is namespace-root,
// sees only a loopback link, owns an empty nftables ruleset it can mutate,
// and none of that is visible from the host side of the harness.
func TestRootlessNetnsIsolatesRulesetAndLinks(t *testing.T) {
	netns.RunInNetns(t, func(t *testing.T) {
		if id := netns.Command(t, "id", "-u"); id != "0" {
			t.Fatalf("uid inside namespace = %q, want 0", id)
		}
		links := netns.Command(t, "ip", "-o", "link", "show")
		lines := strings.Split(strings.TrimSpace(links), "\n")
		if len(lines) != 1 || !strings.Contains(lines[0], "lo:") {
			t.Fatalf("namespace should expose only loopback, got:\n%s", links)
		}
		if _, err := exec.LookPath("nft"); err != nil {
			t.Skip("ENV-UNAVAILABLE: nft(8) is not on PATH inside the namespace")
		}
		if ruleset := netns.Command(t, "nft", "list", "ruleset"); strings.TrimSpace(ruleset) != "" {
			t.Fatalf("fresh namespace has a non-empty ruleset:\n%s", ruleset)
		}
		netns.Command(t, "nft", "add", "table", "inet", "antiflock_netns_selftest")
		tables := netns.Command(t, "nft", "list", "tables")
		if !strings.Contains(tables, "antiflock_netns_selftest") {
			t.Fatalf("table created inside namespace is not listed:\n%s", tables)
		}
		netns.Command(t, "nft", "delete", "table", "inet", "antiflock_netns_selftest")
		if ruleset := netns.Command(t, "nft", "list", "ruleset"); strings.TrimSpace(ruleset) != "" {
			t.Fatalf("ruleset not empty after delete:\n%s", ruleset)
		}
	})
	if netns.InChild(t.Name()) {
		return
	}
	// Host side: the table name must not exist here. Without root the host
	// nft refuses to list at all; either outcome proves non-visibility.
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "nft", "list", "tables").CombinedOutput()
	if err == nil && strings.Contains(string(output), "antiflock_netns_selftest") {
		t.Fatalf("namespace table leaked to the host: %s", output)
	}
}

// Subtests must be addressable by the re-exec pattern as well.
func TestRootlessNetnsSupportsSubtests(t *testing.T) {
	t.Run("loopback-only", func(t *testing.T) {
		netns.RunInNetns(t, func(t *testing.T) {
			routes := netns.Command(t, "ip", "-o", "route", "show")
			if strings.TrimSpace(routes) != "" {
				t.Fatalf("fresh namespace has routes:\n%s", routes)
			}
		})
	})
}

// Command refuses to run tools when invoked outside a namespace body, so a
// mistaken call can never reach the host.
func TestCommandRefusesToRunOnHost(t *testing.T) {
	if netns.InChild(t.Name()) {
		return
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected netns.Command to fail outside a namespace")
		}
	}()
	netns.Command(panicTB{t}, "true")
}

// panicTB turns Fatalf into a panic so the refusal can be observed without
// aborting the real test.
type panicTB struct{ *testing.T }

func (panicTB) Fatalf(format string, args ...any) { panic("fatal: " + format) }
func (panicTB) Helper()                           {}
