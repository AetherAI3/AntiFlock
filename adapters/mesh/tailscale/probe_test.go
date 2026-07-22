package tailscale

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

type recordingRunner struct {
	executable string
	arguments  []string
	output     []byte
	err        error
}

func (runner *recordingRunner) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.executable = executable
	runner.arguments = append([]string(nil), arguments...)
	return append([]byte(nil), runner.output...), runner.err
}

func TestProbeIsReadOnlyMinimizedAndPolicyBound(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{output: []byte(`{
  "BackendState": "Running",
  "Peer": {
    "nodekey:exit": {"ID":"provider-exit","TailscaleIPs":["100.64.0.2"],"Online":true,"Active":true,"CurAddr":"203.0.113.5:41641"},
    "nodekey:relay": {"ID":"provider-relay","Online":true,"Active":true,"Relay":"nyc"},
    "nodekey:offline": {"ID":"provider-offline","Online":false}
  },
  "ExitNodeStatus": {"ID":"provider-exit","Online":true},
  "FutureField": "ignored safely"
}`)}
	probe, err := NewProbe(runner, Config{
		NodeID: "phone", ProviderAssociations: map[string]string{"provider-exit": "exit-node"},
		ApprovedExitProviderIDs: []string{"provider-exit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := probe.DryRun()
	if plan.Executable != "tailscale" || !slices.Equal(plan.Arguments, []string{"status", "--json"}) {
		t.Fatalf("dry run = %#v", plan)
	}
	observedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	snapshot, err := probe.Collect(context.Background(), observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if runner.executable != "tailscale" || !slices.Equal(runner.arguments, []string{"status", "--json"}) {
		t.Fatalf("executed %q %v", runner.executable, runner.arguments)
	}
	if !snapshot.Connected || len(snapshot.Peers) != 3 || len(snapshot.Paths) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	peers := make(map[string]*antiflockv1.MeshPeerObservation)
	for _, peer := range snapshot.Peers {
		peers[peer.ProviderPeerId] = peer
		if len(peer.MeshAddresses) != 0 {
			t.Fatal("mesh addresses were exposed without opt-in")
		}
		if peer.LastHandshakeAt != nil {
			t.Fatal("status metadata was mislabeled as a handshake")
		}
	}
	if got := peers["provider-exit"]; got.NodeId != "exit-node" || !got.Authorized || got.ConnectionType != antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DIRECT {
		t.Fatalf("exit peer = %#v", got)
	}
	if got := peers["provider-relay"]; got.Authorized || got.ConnectionType != antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_RELAYED || got.RelayRegion != "nyc" {
		t.Fatalf("relay peer = %#v", got)
	}
	if got := peers["provider-offline"]; got.ConnectionType != antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DISCONNECTED {
		t.Fatalf("offline peer = %#v", got)
	}
	path := snapshot.Paths[0]
	if !path.ApprovedExitActive || !path.TunnelHealthy || path.ExitNodeId != "exit-node" || len(path.Evidence) != 0 {
		t.Fatalf("exit path = %#v", path)
	}
}

func TestProbeFailsClosedOnCommandOrJSONFailure(t *testing.T) {
	t.Parallel()
	for name, runner := range map[string]*recordingRunner{
		"command": {err: errors.New("provider details must not leak")},
		"json":    {output: []byte(`{"BackendState":"Running"} trailing`)},
	} {
		t.Run(name, func(t *testing.T) {
			probe, err := NewProbe(runner, Config{NodeID: "phone"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := probe.Collect(context.Background(), time.Now().UTC()); err == nil {
				t.Fatal("unsafe provider result was accepted")
			}
		})
	}
}

func TestExecRunnerRejectsMutationBeforeExecution(t *testing.T) {
	t.Parallel()
	runner := ExecRunner{}
	if _, err := runner.Run(context.Background(), "tailscale", "up"); err == nil {
		t.Fatal("mutating tailscale command was accepted")
	}
	if _, err := runner.Run(context.Background(), "sh", "status", "--json"); err == nil {
		t.Fatal("non-tailscale executable was accepted")
	}
}

func TestProbeRejectsAmbiguousProviderIdentities(t *testing.T) {
	t.Parallel()
	for name, output := range map[string]string{
		"noncanonical": `{"BackendState":"Running","Peer":{"nodekey:one":{"ID":" provider-one","Online":true}}}`,
		"duplicate":    `{"BackendState":"Running","Peer":{"nodekey:one":{"ID":"provider-one","Online":true},"nodekey:two":{"ID":"provider-one","Online":true}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			probe, err := NewProbe(&recordingRunner{output: []byte(output)}, Config{NodeID: "phone-node"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := probe.Collect(context.Background(), time.Now().UTC()); err == nil {
				t.Fatal("ambiguous provider identity was accepted")
			}
		})
	}
	if _, err := NewProbe(&recordingRunner{}, Config{
		NodeID: "phone-node", ProviderAssociations: map[string]string{" provider": "node"},
	}); err == nil {
		t.Fatal("noncanonical provider association was accepted")
	}
}
