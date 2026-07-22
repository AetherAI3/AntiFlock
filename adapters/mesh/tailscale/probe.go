// Package tailscale provides a read-only Tailscale status adapter. It never
// invokes up, down, set, serve, funnel, or any other mutating command.
package tailscale

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const defaultMaximumOutput = 1 << 20

// Runner is the narrow command surface used by Probe. Probe always requests
// exactly: tailscale status --json.
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// ExecRunner executes the read-only status command without a shell.
type ExecRunner struct {
	MaximumOutputBytes int
}

func (runner ExecRunner) Run(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	if !isTailscaleExecutable(executable) || len(arguments) != 2 || arguments[0] != "status" || arguments[1] != "--json" {
		return nil, errors.New("tailscale adapter rejected a non-read-only command")
	}
	limit := runner.MaximumOutputBytes
	if limit <= 0 {
		limit = defaultMaximumOutput
	}
	output := &limitedBuffer{limit: limit}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("tailscale status probe failed")
	}
	if output.overflow {
		return nil, errors.New("tailscale status output exceeded the safety limit")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		buffer.overflow = true
		value = value[:remaining]
	}
	_, _ = buffer.Buffer.Write(value)
	return original, nil
}

// Config binds provider identities to canonical AntiFlock node identities.
// Mesh IPs remain withheld unless IncludeAddresses is explicitly enabled.
type Config struct {
	Executable              string
	NodeID                  string
	ProviderAssociations    map[string]string
	ApprovedExitProviderIDs []string
	IncludeAddresses        bool
	MaximumOutputBytes      int
}

// CommandPlan is a secret-free dry run of the only command Probe can invoke.
type CommandPlan struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
}

// Snapshot contains local provider observations only. It carries no claim
// that an observed peer or exit has been independently VERIFIED.
type Snapshot struct {
	BackendState string
	Connected    bool
	ObservedAt   time.Time
	Peers        []*antiflockv1.MeshPeerObservation
	Paths        []*antiflockv1.MeshPathObservation
}

type Probe struct {
	runner Runner
	config Config
}

func NewProbe(runner Runner, config Config) (*Probe, error) {
	if runner == nil || strings.TrimSpace(config.NodeID) == "" || strings.TrimSpace(config.NodeID) != config.NodeID || len(config.NodeID) > 128 {
		return nil, errors.New("tailscale probe requires a runner and canonical node id")
	}
	if config.Executable == "" {
		config.Executable = "tailscale"
	}
	if !isTailscaleExecutable(config.Executable) {
		return nil, errors.New("tailscale executable must resolve to tailscale")
	}
	if config.MaximumOutputBytes <= 0 {
		config.MaximumOutputBytes = defaultMaximumOutput
	}
	if config.MaximumOutputBytes > 16<<20 {
		return nil, errors.New("tailscale output limit is too large")
	}
	associations, err := validatedAssociations(config.ProviderAssociations)
	if err != nil {
		return nil, err
	}
	approved, err := validatedApprovedIDs(config.ApprovedExitProviderIDs)
	if err != nil {
		return nil, err
	}
	config.ProviderAssociations = associations
	config.ApprovedExitProviderIDs = approved
	return &Probe{runner: runner, config: config}, nil
}

func (probe *Probe) DryRun() CommandPlan {
	if probe == nil {
		return CommandPlan{}
	}
	return CommandPlan{Executable: probe.config.Executable, Arguments: []string{"status", "--json"}}
}

// Collect executes the read-only status probe and translates only the minimum
// connection metadata needed by the local policy evaluator.
func (probe *Probe) Collect(ctx context.Context, observedAt time.Time) (*Snapshot, error) {
	if probe == nil {
		return nil, errors.New("tailscale probe is required")
	}
	if observedAt.IsZero() || timestamppb.New(observedAt.UTC()).CheckValid() != nil {
		return nil, errors.New("tailscale observation time is invalid")
	}
	output, err := probe.runner.Run(ctx, probe.config.Executable, "status", "--json")
	if err != nil {
		return nil, err
	}
	if len(output) == 0 || len(output) > probe.config.MaximumOutputBytes {
		return nil, errors.New("tailscale status output is empty or oversized")
	}
	var status statusDocument
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(&status); err != nil {
		return nil, errors.New("tailscale status output is not valid JSON")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	result := &Snapshot{BackendState: status.BackendState, Connected: status.BackendState == "Running", ObservedAt: observedAt.UTC()}
	peerByID := make(map[string]peerStatus, len(status.Peer))
	keys := make([]string, 0, len(status.Peer))
	for key := range status.Peer {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" || strings.TrimSpace(key) != key {
			return nil, errors.New("tailscale status contains a noncanonical provider key")
		}
		peer := status.Peer[key]
		providerID := peer.ID
		if providerID != "" && strings.TrimSpace(providerID) != providerID {
			return nil, errors.New("tailscale status contains a noncanonical provider id")
		}
		if providerID == "" {
			providerID = key
		}
		if _, duplicate := peerByID[providerID]; duplicate {
			return nil, errors.New("tailscale status contains duplicate provider ids")
		}
		peerByID[providerID] = peer
		canonicalNodeID, err := associatedNode(probe.config.ProviderAssociations, providerID, key)
		if err != nil {
			return nil, err
		}
		item := &antiflockv1.MeshPeerObservation{
			Provider: "tailscale", ProviderPeerId: providerID, NodeId: canonicalNodeID,
			ConnectionType: connectionType(peer), RelayRegion: relayRegion(peer), Authorized: canonicalNodeID != "",
		}
		if probe.config.IncludeAddresses {
			item.MeshAddresses = normalizedIPs(peer.TailscaleIPs)
		}
		result.Peers = append(result.Peers, item)
	}
	sort.Slice(result.Peers, func(left, right int) bool {
		return result.Peers[left].ProviderPeerId < result.Peers[right].ProviderPeerId
	})

	if status.ExitNodeStatus != nil && status.ExitNodeStatus.ID != "" {
		exitID := status.ExitNodeStatus.ID
		if strings.TrimSpace(exitID) != exitID {
			return nil, errors.New("tailscale exit node id is not canonical")
		}
		peer, peerKnown := peerByID[exitID]
		canonicalExitID, err := associatedNode(probe.config.ProviderAssociations, exitID)
		if err != nil {
			return nil, err
		}
		approved := result.Connected && status.ExitNodeStatus.Online && approvedExit(probe.config.ApprovedExitProviderIDs, exitID, canonicalExitID)
		pathConnection := antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_UNKNOWN
		if peerKnown {
			pathConnection = connectionType(peer)
		}
		path := &antiflockv1.MeshPathObservation{
			Provider: "tailscale", SourceNodeId: probe.config.NodeID, DestinationNodeId: canonicalExitID,
			ConnectionType: pathConnection, RelayRegion: relayRegion(peer), ExitNodeId: canonicalExitID,
			ApprovedExitActive: approved, TunnelHealthy: result.Connected && status.ExitNodeStatus.Online,
			ObservedAt: timestamppb.New(observedAt.UTC()),
		}
		path.PathId = stablePathID(probe.config.NodeID, exitID, path.ConnectionType)
		result.Paths = append(result.Paths, path)
	}
	return result, nil
}

type statusDocument struct {
	BackendState   string                `json:"BackendState"`
	Peer           map[string]peerStatus `json:"Peer"`
	ExitNodeStatus *exitNodeStatus       `json:"ExitNodeStatus"`
}

type peerStatus struct {
	ID           string   `json:"ID"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	Active       bool     `json:"Active"`
	CurAddr      string   `json:"CurAddr"`
	Relay        string   `json:"Relay"`
}

type exitNodeStatus struct {
	ID     string `json:"ID"`
	Online bool   `json:"Online"`
}

func connectionType(peer peerStatus) antiflockv1.MeshConnectionType {
	if !peer.Online {
		return antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DISCONNECTED
	}
	if peer.Active && peer.CurAddr != "" {
		return antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DIRECT
	}
	if peer.Active && peer.Relay != "" {
		return antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_RELAYED
	}
	return antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_UNKNOWN
}

func relayRegion(peer peerStatus) string {
	if connectionType(peer) == antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_RELAYED {
		return peer.Relay
	}
	return ""
}

func associatedNode(values map[string]string, providerIDs ...string) (string, error) {
	result := ""
	for _, providerID := range providerIDs {
		if nodeID := values[providerID]; nodeID != "" {
			if result != "" && result != nodeID {
				return "", errors.New("tailscale provider identities map to conflicting canonical nodes")
			}
			result = nodeID
		}
	}
	return result, nil
}

func approvedExit(values []string, providerID, canonicalID string) bool {
	for _, value := range values {
		if value == providerID || (canonicalID != "" && value == canonicalID) {
			return true
		}
	}
	return false
}

func normalizedIPs(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		canonical := ip.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result
}

func stablePathID(sourceNodeID, exitProviderID string, connection antiflockv1.MeshConnectionType) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("AntiFlock-Tailscale-Path-v1\x00%s\x00%s\x00%d", sourceNodeID, exitProviderID, connection)))
	return "mesh_path_" + hex.EncodeToString(digest[:16])
}

func validatedAssociations(source map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(source))
	for key, value := range source {
		if key == "" || value == "" || len(key) > 512 || len(value) > 128 || strings.TrimSpace(key) != key || strings.TrimSpace(value) != value {
			return nil, errors.New("tailscale provider associations must use canonical bounded identities")
		}
		result[key] = value
	}
	return result, nil
}

func validatedApprovedIDs(source []string) ([]string, error) {
	result := make([]string, 0, len(source))
	seen := make(map[string]struct{}, len(source))
	for _, value := range source {
		if value == "" || len(value) > 512 || strings.TrimSpace(value) != value {
			return nil, errors.New("tailscale approved exit ids must be canonical bounded identities")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errors.New("tailscale approved exit ids must be unique")
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func isTailscaleExecutable(value string) bool {
	base := strings.ToLower(filepath.Base(value))
	return base == "tailscale" || base == "tailscale.exe"
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	}
	return errors.New("tailscale status output contains trailing data")
}
