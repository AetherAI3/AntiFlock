// Package enrollment bootstraps a private endpoint identity into Core's
// operator-approved enrollment workflow.
package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	coreenrollment "github.com/DBarr3/AntiFlock/core/enrollment"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	stateSchema = "antiflock.agent-enrollment/v1"
	privateFileMode = 0o600
	privateDirectoryMode = 0o700
	maxStateBytes = 16 << 10
)

type Config struct {
	Endpoint string
	Token string
	StateDirectory string
	NodeID string
	DisplayName string
	HTTP *http.Client
	Clock func() time.Time
}

type Result struct { EnrollmentID string; ProposedNodeID string; StateDirectory string; Status antiflockv1.EnrollmentStatus; CertificateChainDER []byte }
type state struct { SchemaVersion string `json:"schemaVersion"`; NodeID string `json:"nodeId"`; RequestID string `json:"requestId"` }

// Submit preserves one Ed25519 seed and request identifier per state directory,
// so a network retry is idempotent from the endpoint's point of view.
func Submit(ctx context.Context, config Config) (Result, error) {
	if err := ctx.Err(); err != nil { return Result{}, err }
	endpoint, err := enrollmentEndpoint(config.Endpoint); if err != nil { return Result{}, err }
	if len(strings.TrimSpace(config.Token)) < 32 { return Result{}, errors.New("enrollment token is required") }
	if !canonical(config.NodeID, 128) || strings.TrimSpace(config.DisplayName) == "" || len(config.DisplayName) > 128 { return Result{}, errors.New("enrollment node id and display name are required") }
	clock := config.Clock; if clock == nil { clock = func() time.Time { return time.Now().UTC() } }
	privateKey, persisted, err := ensureIdentity(config.StateDirectory, config.NodeID); if err != nil { return Result{}, err }
	now := clock().UTC(); if now.IsZero() { return Result{}, errors.New("enrollment clock is invalid") }
	request := &antiflockv1.EnrollNodeRequest{
		TokenValue: strings.TrimSpace(config.Token), RequestId: persisted.RequestID, DisplayName: strings.TrimSpace(config.DisplayName),
		NodeType: antiflockv1.NodeType_NODE_TYPE_AGENT, Platform: runtime.GOOS, PlatformVersion: runtime.GOARCH, KeyAlgorithm: "ed25519",
		PublicKey: privateKey.Public().(ed25519.PublicKey), RequestedNodeId: config.NodeID, Capabilities: capabilityManifest(now),
	}
	proof, err := coreenrollment.ProofMessage(request); if err != nil { return Result{}, err }; request.ProofOfPossession = ed25519.Sign(privateKey, proof)
	body, err := (protojson.MarshalOptions{UseProtoNames: false}).Marshal(request); if err != nil { return Result{}, errors.New("encode enrollment request") }
	client := config.HTTP; if client == nil { client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }} }
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/enrollment/nodes", bytes.NewReader(body)); if err != nil { return Result{}, errors.New("build enrollment request") }
	httpRequest.Header.Set("Content-Type", "application/json"); httpRequest.Header.Set("Accept", "application/json"); httpRequest.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(httpRequest); if err != nil { return Result{}, fmt.Errorf("submit enrollment request: %w", err) }
	defer response.Body.Close()
	content, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil || response.StatusCode != http.StatusAccepted { return Result{}, errors.New("Core did not accept enrollment request") }
	var output antiflockv1.EnrollNodeResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, &output); err != nil || output.GetEnrollment() == nil || output.GetEnrollment().GetId() == "" { return Result{}, errors.New("decode Core enrollment response") }
	certificateDER := append([]byte(nil), output.GetNodeCertificateChainDer()...)
	if output.GetEnrollment().GetStatus() == antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		if len(certificateDER) == 0 || !certificateMatches(privateKey, certificateDER) { return Result{}, errors.New("Core approval did not return the enrolled node certificate") }
	} else if len(certificateDER) != 0 { return Result{}, errors.New("Core returned a certificate before enrollment approval") }
	return Result{EnrollmentID: output.GetEnrollment().GetId(), ProposedNodeID: output.GetEnrollment().GetProposedNodeId(), StateDirectory: config.StateDirectory, Status: output.GetEnrollment().GetStatus(), CertificateChainDER: certificateDER}, nil
}


// SaveApprovedCertificate persists the Core-issued certificate only when it
// matches the enrolled seed. Existing certificate material is never replaced.
func SaveApprovedCertificate(seedPath, certificatePath string, certificateDER []byte) error {
	privateKey, err := loadSeed(seedPath); if err != nil { return err }
	if !certificateMatches(privateKey, certificateDER) { return errors.New("approved certificate does not match enrolled seed") }
	if strings.TrimSpace(certificatePath) == "" { return errors.New("approved certificate path is required") }
	parent := filepath.Dir(certificatePath)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return errors.New("approved certificate directory must exist and not be a symlink") }
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if existing, err := os.Lstat(certificatePath); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 || existing.Mode().Perm() != privateFileMode || existing.Size() == 0 || existing.Size() > 1<<20 { return errors.New("approved certificate file is not private and regular") }
		previous, err := os.ReadFile(certificatePath); if err != nil || !bytes.Equal(previous, content) { return errors.New("approved certificate already exists with different contents") }
		return nil
	} else if !errors.Is(err, os.ErrNotExist) { return errors.New("inspect approved certificate file") }
	return writePrivateNew(certificatePath, content)
}

func certificateMatches(privateKey ed25519.PrivateKey, certificateDER []byte) bool {
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil { return false }
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	return ok && publicKey.Equal(privateKey.Public())
}

func capabilityManifest(now time.Time) *antiflockv1.CapabilityManifest {
	capability := &antiflockv1.Capability{Key: "network.metadata.observe", Domain: antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_NETWORK, Operations: []antiflockv1.CapabilityOperation{antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE}, SupportLevel: antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_FULL, Implementation: "antiflock-agent", ImplementationVersion: "v1", Constraints: []string{"read-only", "no-packet-payload"}, ObservedAt: timestamppb.New(now)}
	return &antiflockv1.CapabilityManifest{Revision: 1, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(365 * 24 * time.Hour)), Capabilities: []*antiflockv1.Capability{capability}}
}

func ensureIdentity(directory, nodeID string) (ed25519.PrivateKey, state, error) {
	if strings.TrimSpace(directory) == "" { return nil, state{}, errors.New("enrollment state directory is required") }
	if err := ensurePrivateDirectory(directory); err != nil { return nil, state{}, err }
	seedPath := filepath.Join(directory, "node.seed"); statePath := filepath.Join(directory, "enrollment.json")
	if _, err := os.Lstat(seedPath); err == nil {
		privateKey, err := loadSeed(seedPath); if err != nil { return nil, state{}, err }
		persisted, err := loadState(statePath, nodeID); if err != nil { return nil, state{}, err }
		return privateKey, persisted, nil
	} else if !errors.Is(err, os.ErrNotExist) { return nil, state{}, errors.New("inspect enrollment seed") }
	if _, err := os.Lstat(statePath); err == nil { return nil, state{}, errors.New("enrollment state exists without a seed") } else if !errors.Is(err, os.ErrNotExist) { return nil, state{}, errors.New("inspect enrollment state") }
	_, privateKey, err := ed25519.GenerateKey(rand.Reader); if err != nil { return nil, state{}, errors.New("generate enrollment seed") }
	requestID, err := randomID("enroll"); if err != nil { return nil, state{}, err }
	persisted := state{SchemaVersion: stateSchema, NodeID: nodeID, RequestID: requestID}
	content, err := json.Marshal(persisted); if err != nil { return nil, state{}, errors.New("encode enrollment state") }
	if err := writePrivateNew(seedPath, privateKey.Seed()); err != nil { return nil, state{}, err }
	if err := writePrivateNew(statePath, content); err != nil { return nil, state{}, err }
	return privateKey, persisted, nil
}

func ensurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, privateDirectoryMode); err != nil { return errors.New("create enrollment state directory") }
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return errors.New("enrollment state directory must be a real directory") }
	if err := os.Chmod(directory, privateDirectoryMode); err != nil { return errors.New("protect enrollment state directory") }
	return nil
}

func loadSeed(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != privateFileMode || info.Size() != ed25519.SeedSize { return nil, errors.New("enrollment seed must be a private regular seed file") }
	content, err := os.ReadFile(path); if err != nil || len(content) != ed25519.SeedSize { return nil, errors.New("read enrollment seed") }
	return ed25519.NewKeyFromSeed(content), nil
}

func writePrivateNew(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if err != nil { return errors.New("create private enrollment state") }
	if _, err := file.Write(content); err != nil { file.Close(); return errors.New("write private enrollment state") }
	if err := file.Sync(); err != nil { file.Close(); return errors.New("sync private enrollment state") }
	if err := file.Close(); err != nil { return errors.New("close private enrollment state") }
	return nil
}

func loadState(path, nodeID string) (state, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != privateFileMode || info.Size() == 0 || info.Size() > maxStateBytes { return state{}, errors.New("enrollment state must be a private regular file") }
	content, err := os.ReadFile(path); if err != nil { return state{}, errors.New("read enrollment state") }
	var value state
	if json.Unmarshal(content, &value) != nil || value.SchemaVersion != stateSchema || value.NodeID != nodeID || !canonical(value.RequestID, 128) { return state{}, errors.New("enrollment state is invalid") }
	return value, nil
}
func randomID(prefix string) (string, error) { raw := make([]byte, 12); if _, err := rand.Read(raw); err != nil { return "", err }; return prefix + "-" + hex.EncodeToString(raw), nil }
func canonical(value string, maximum int) bool { return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00") }
func enrollmentEndpoint(raw string) (string, error) { value, err := url.Parse(strings.TrimSpace(raw)); if err != nil || value.Scheme == "" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" || (value.Scheme != "https" && value.Scheme != "http") { return "", errors.New("enrollment Core URL must be absolute HTTP(S)") }; if value.Scheme == "http" && !loopback(value.Hostname()) { return "", errors.New("enrollment requires HTTPS outside loopback") }; return strings.TrimRight(value.String(), "/"), nil }
func loopback(host string) bool { if strings.EqualFold(host, "localhost") { return true }; ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
