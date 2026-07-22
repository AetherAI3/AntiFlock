package sim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maximumLiveResponseBytes = 8 << 20
	defaultHeartbeatInterval = 30 * time.Second
)

// LiveConfig contains the non-interactive simulator connection contract.
// Tokens must come from the environment or mounted files; the CLI deliberately
// has no credential flags so secrets cannot leak through process listings.
type LiveConfig struct {
	CoreURL        string           `json:"coreUrl,omitempty"`
	OperatorToken  string           `json:"-"`
	AgentToken     string           `json:"-"`
	SDKToken       string           `json:"-"`
	NodeID         string           `json:"nodeId,omitempty"`
	ApplicationID  string           `json:"applicationId,omitempty"`
	StateDirectory string           `json:"stateDirectory,omitempty"`
	BootID         string           `json:"bootId,omitempty"`
	DemoMode       bool             `json:"demoMode,omitempty"`
	Clock          func() time.Time `json:"-"`
}

type liveClient struct {
	baseURL        *url.URL
	http           *http.Client
	operatorToken  string
	agentToken     string
	sdkToken       string
	nodeID         string
	applicationID  string
	stateDirectory string
	bootID         string
	clock          func() time.Time
}

type liveSession struct {
	client       *liveClient
	deploymentID string
	privateKey   ed25519.PrivateKey
}

// LiveStreamEvent is a non-secret JSON-line status emitted by stream mode.
type LiveStreamEvent struct {
	SchemaVersion string `json:"schemaVersion"`
	Status        string `json:"status"`
	NodeID        string `json:"nodeId"`
	DeploymentID  string `json:"deploymentId,omitempty"`
	EventID       string `json:"eventId,omitempty"`
	ObservedAt    string `json:"observedAt"`
	SafeError     string `json:"safeError,omitempty"`
}

// LiveCoffeeShopResult is returned only after the live Core flow completes.
// Verified means the caller requested verification and every durable readback
// plus idempotent audit replay succeeded.
type LiveCoffeeShopResult struct {
	SchemaVersion        string   `json:"schemaVersion"`
	Simulation           bool     `json:"simulation"`
	NodeID               string   `json:"nodeId"`
	DeploymentID         string   `json:"deploymentId"`
	ActionID             string   `json:"actionId"`
	InitialDecision      string   `json:"initialDecision"`
	FinalDecision        string   `json:"finalDecision"`
	ContextEventIDs      []string `json:"contextEventIds"`
	VerificationEventIDs []string `json:"verificationEventIds"`
	AuditEventIDs        []string `json:"auditEventIds"`
	Verified             bool     `json:"verified"`
}

func newLiveClient(config LiveConfig) (*liveClient, error) {
	parsed, err := url.Parse(config.CoreURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("simulator Core URL must be an absolute HTTP(S) origin")
	}
	if parsed.Scheme == "http" && !config.DemoMode {
		return nil, errors.New("plain HTTP requires explicit ANTIFLOCK_DEMO_MODE")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if !validLiveCredential(config.OperatorToken) || !validLiveCredential(config.AgentToken) || !validLiveCredential(config.SDKToken) {
		return nil, errors.New("simulator requires separate operator, agent, and SDK credentials of at least 32 bytes")
	}
	if config.OperatorToken == config.AgentToken || config.OperatorToken == config.SDKToken || config.AgentToken == config.SDKToken {
		return nil, errors.New("simulator operator, agent, and SDK credentials must be distinct")
	}
	if !validRequestedNodeID(config.NodeID) {
		return nil, errors.New("simulator node id must be a canonical requested node identity")
	}
	if !boundedLiveID(config.ApplicationID) {
		return nil, errors.New("simulator application id is invalid")
	}
	if strings.TrimSpace(config.StateDirectory) == "" {
		return nil, errors.New("simulator state directory is required")
	}
	if config.BootID != "" && !boundedLiveID(config.BootID) {
		return nil, errors.New("simulator boot id is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	transport := http.DefaultTransport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := base.Clone()
		clone.DisableCompression = true
		transport = clone
	}
	return &liveClient{
		baseURL: parsed,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		operatorToken: config.OperatorToken, agentToken: config.AgentToken, sdkToken: config.SDKToken,
		nodeID: config.NodeID, applicationID: config.ApplicationID,
		stateDirectory: filepath.Clean(config.StateDirectory), bootID: config.BootID, clock: clock,
	}, nil
}

func validRequestedNodeID(value string) bool {
	if len(value) < 8 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	separator := false
	for index, character := range []byte(value) {
		if character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			separator = false
			continue
		}
		if index > 0 && (character == '-' || character == '_') && !separator && index != len(value)-1 {
			separator = true
			continue
		}
		return false
	}
	return true
}

func boundedLiveID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func validLiveCredential(value string) bool {
	return len(value) >= 32 && len(value) <= 16<<10 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

type liveHTTPError struct {
	status int
	path   string
}

func (err *liveHTTPError) Error() string {
	return fmt.Sprintf("Core request %s returned HTTP %d", err.path, err.status)
}

func (client *liveClient) endpoint(path string) string {
	base := *client.baseURL
	relative, err := url.Parse(path)
	if err != nil {
		return ""
	}
	base.Path = strings.TrimRight(base.Path, "/") + relative.Path
	base.RawQuery = relative.RawQuery
	return base.String()
}

func (client *liveClient) do(ctx context.Context, method, path, token string, body []byte, expected []int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, client.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("build Core request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("core request failed")
	}
	defer response.Body.Close()
	accepted := false
	for _, status := range expected {
		accepted = accepted || response.StatusCode == status
	}
	if !accepted {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return nil, &liveHTTPError{status: response.StatusCode, path: path}
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumLiveResponseBytes+1))
	if err != nil {
		return nil, errors.New("read Core response")
	}
	if len(content) > maximumLiveResponseBytes {
		return nil, errors.New("core response exceeds simulator limit")
	}
	return content, nil
}

func (client *liveClient) doProto(ctx context.Context, method, path, token string, input, output proto.Message, expected ...int) error {
	body, err := (protojson.MarshalOptions{UseProtoNames: false}).Marshal(input)
	if err != nil {
		return errors.New("encode Core protobuf request")
	}
	content, err := client.do(ctx, method, path, token, body, expected)
	if err != nil {
		return err
	}
	if output == nil {
		return nil
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, output); err != nil {
		return errors.New("decode Core protobuf response")
	}
	return nil
}

func (client *liveClient) doJSON(ctx context.Context, method, path, token string, input, output any, expected ...int) error {
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return errors.New("encode Core JSON request")
		}
	}
	content, err := client.do(ctx, method, path, token, body, expected)
	if err != nil {
		return err
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(output); err != nil {
		return errors.New("decode Core JSON response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("core JSON response contains trailing data")
	}
	return nil
}

func (client *liveClient) bootstrap(ctx context.Context) (*liveSession, error) {
	lock, err := acquireLiveStateLock(ctx, client.stateDirectory)
	if err != nil {
		return nil, err
	}
	defer lock.close()
	return client.bootstrapLocked(ctx)
}

func (client *liveClient) bootstrapLocked(ctx context.Context) (*liveSession, error) {
	deploymentID, err := client.deployment(ctx)
	if err != nil {
		return nil, err
	}
	state, err := loadLiveState(client.stateDirectory, client.nodeID)
	if err != nil {
		return nil, err
	}
	privateKey, keyExists, err := loadLivePrivateKey(client.stateDirectory)
	if err != nil {
		return nil, err
	}
	nodeState, nodeExists, err := client.nodeState(ctx)
	if err != nil {
		return nil, err
	}
	if nodeExists {
		if nodeState == "blocked" {
			return nil, errors.New("simulator node exists but is not active")
		}
		if state == nil || !keyExists {
			return nil, errors.New("core node exists without matching local simulator identity")
		}
		if err := validateLiveIdentity(state, privateKey); err != nil {
			return nil, err
		}
		if client.bootID != "" && state.BootID != client.bootID {
			return nil, errors.New("configured simulator boot id conflicts with persistent state")
		}
		return &liveSession{client: client, deploymentID: deploymentID, privateKey: privateKey}, nil
	}
	if state == nil && keyExists {
		return nil, errors.New("simulator key exists without identity state")
	}
	if state != nil && !keyExists {
		return nil, errors.New("simulator identity state exists without its node key")
	}
	if state == nil {
		state, privateKey, err = createLiveIdentity(client.stateDirectory, client.nodeID, client.clock())
		if err != nil {
			return nil, err
		}
		if client.bootID != "" {
			state.BootID = client.bootID
			if err := saveLiveState(client.stateDirectory, state); err != nil {
				return nil, err
			}
		}
	} else if err := validateLiveIdentity(state, privateKey); err != nil {
		return nil, err
	}
	if state.EnrollmentID != "" {
		if err := client.approve(ctx, state.EnrollmentID); err == nil {
			return &liveSession{client: client, deploymentID: deploymentID, privateKey: privateKey}, nil
		} else {
			var responseErr *liveHTTPError
			if !errors.As(err, &responseErr) || responseErr.status != http.StatusNotFound {
				return nil, fmt.Errorf("resume simulator enrollment: %w", err)
			}
			state.EnrollmentID = ""
			if err := saveLiveState(client.stateDirectory, state); err != nil {
				return nil, err
			}
		}
	}
	token, err := client.createEnrollmentToken(ctx)
	if err != nil {
		return nil, err
	}
	enrollmentID, proposedNodeID, err := client.enroll(ctx, state, privateKey, token)
	if err != nil {
		return nil, err
	}
	if proposedNodeID != client.nodeID {
		return nil, errors.New("core proposed a node identity outside the requested simulator identity")
	}
	state.EnrollmentID = enrollmentID
	if err := saveLiveState(client.stateDirectory, state); err != nil {
		return nil, err
	}
	if err := client.approve(ctx, enrollmentID); err != nil {
		return nil, err
	}
	return &liveSession{client: client, deploymentID: deploymentID, privateKey: privateKey}, nil
}

func (client *liveClient) deployment(ctx context.Context) (string, error) {
	var response struct {
		DeploymentName string `json:"deploymentName"`
	}
	if err := client.doJSON(ctx, http.MethodGet, "/v1/overview", client.operatorToken, nil, &response, http.StatusOK); err != nil {
		return "", err
	}
	if !boundedLiveID(response.DeploymentName) {
		return "", errors.New("core returned an invalid deployment identity")
	}
	return response.DeploymentName, nil
}

func (client *liveClient) nodeState(ctx context.Context) (string, bool, error) {
	var response struct {
		Nodes []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"nodes"`
	}
	if err := client.doJSON(ctx, http.MethodGet, "/v1/nodes", client.operatorToken, nil, &response, http.StatusOK); err != nil {
		return "", false, err
	}
	for _, node := range response.Nodes {
		if node.ID == client.nodeID {
			return node.State, true, nil
		}
	}
	return "", false, nil
}

func stableOperationID(prefix, value string) string {
	digest := sha256.Sum256([]byte("AntiFlock-Simulator-Operation-v1\x00" + value))
	return prefix + "-" + hex.EncodeToString(digest[:12])
}

func (client *liveClient) createEnrollmentToken(ctx context.Context) (string, error) {
	input := &antiflockv1.CreateEnrollmentTokenRequest{
		AllowedNodeType: antiflockv1.NodeType_NODE_TYPE_AGENT,
		AllowedTags:     []string{"demo"},
		OperationId:     stableOperationID("sim-token", client.nodeID),
	}
	var output antiflockv1.CreateEnrollmentTokenResponse
	if err := client.doProto(ctx, http.MethodPost, "/v1/enrollment/tokens", client.operatorToken, input, &output, http.StatusCreated); err != nil {
		return "", fmt.Errorf("create simulator enrollment token: %w", err)
	}
	if output.GetToken() == nil || output.GetTokenValue() == "" {
		return "", errors.New("core omitted the enrollment token")
	}
	return output.GetTokenValue(), nil
}

func (client *liveClient) enroll(ctx context.Context, state *liveState, privateKey ed25519.PrivateKey, token string) (string, string, error) {
	issuedAt, err := time.Parse(time.RFC3339Nano, state.EnrollmentIssuedAt)
	if err != nil {
		return "", "", errors.New("simulator enrollment time is invalid")
	}
	capability := func(key string, domain antiflockv1.CapabilityDomain, operation antiflockv1.CapabilityOperation) *antiflockv1.Capability {
		return &antiflockv1.Capability{
			Key: key, Domain: domain, Operations: []antiflockv1.CapabilityOperation{operation},
			SupportLevel:   antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_EXPERIMENTAL,
			Implementation: "antiflock-sim", ImplementationVersion: "v1",
			Constraints: []string{"simulation-only", "no-host-mutation"}, ObservedAt: timestamppb.New(issuedAt),
		}
	}
	input := &antiflockv1.EnrollNodeRequest{
		TokenValue: token, RequestId: stableOperationID("sim-enroll", client.nodeID),
		DisplayName: "AntiFlock deterministic simulator", NodeType: antiflockv1.NodeType_NODE_TYPE_AGENT,
		Platform: "linux", PlatformVersion: "simulation", KeyAlgorithm: "ed25519",
		PublicKey: privateKey.Public().(ed25519.PublicKey), RequestedNodeId: client.nodeID,
		Capabilities: &antiflockv1.CapabilityManifest{
			Revision: 1, IssuedAt: timestamppb.New(issuedAt), ExpiresAt: timestamppb.New(issuedAt.Add(365 * 24 * time.Hour)),
			Capabilities: []*antiflockv1.Capability{
				capability("network.metadata.observe", antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_NETWORK, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE),
				capability("mesh.path.verify", antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_MESH, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
				capability("dns.path.verify", antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_DNS, antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY),
			},
		},
	}
	proof, err := enrollment.ProofMessage(input)
	if err != nil {
		return "", "", errors.New("build simulator enrollment proof")
	}
	input.ProofOfPossession = ed25519.Sign(privateKey, proof)
	var output antiflockv1.EnrollNodeResponse
	if err := client.doProto(ctx, http.MethodPost, "/v1/enrollment/nodes", "", input, &output, http.StatusAccepted); err != nil {
		return "", "", fmt.Errorf("enroll simulator node: %w", err)
	}
	if output.GetEnrollment() == nil || !boundedLiveID(output.GetEnrollment().GetId()) || !boundedLiveID(output.GetEnrollment().GetProposedNodeId()) {
		return "", "", errors.New("core returned an invalid enrollment identity")
	}
	return output.GetEnrollment().GetId(), output.GetEnrollment().GetProposedNodeId(), nil
}

func (client *liveClient) approve(ctx context.Context, enrollmentID string) error {
	input := &antiflockv1.ApproveEnrollmentRequest{
		EnrollmentId: enrollmentID,
		OperationId:  stableOperationID("sim-approve", client.nodeID),
		ReasonCode:   "OPERATOR_APPROVED", ApprovedTags: []string{"demo"},
	}
	var output antiflockv1.ApproveEnrollmentResponse
	path := "/v1/enrollment/" + url.PathEscape(enrollmentID) + "/approve"
	if err := client.doProto(ctx, http.MethodPost, path, client.operatorToken, input, &output, http.StatusOK); err != nil {
		return fmt.Errorf("approve simulator enrollment: %w", err)
	}
	if output.GetNode() == nil || output.GetNode().GetMetadata().GetId() != client.nodeID ||
		output.GetNode().GetStatus() != antiflockv1.NodeStatus_NODE_STATUS_ACTIVE {
		return errors.New("core approval did not activate the requested simulator node")
	}
	return nil
}

type lockedSequenceSource struct {
	directory string
	state     *liveState
}

func (source *lockedSequenceSource) NextSequence(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if source.state.LastSequence == ^uint64(0) {
		return 0, errors.New("simulator event sequence exhausted")
	}
	source.state.LastSequence++
	if err := saveLiveState(source.directory, source.state); err != nil {
		return 0, err
	}
	return source.state.LastSequence, nil
}

type eventProjection struct {
	ID             string              `json:"id"`
	NodeID         string              `json:"nodeId"`
	BootID         string              `json:"bootId"`
	Sequence       uint64              `json:"sequence"`
	Classification model.EvidenceClass `json:"classification"`
}

func (client *liveClient) syncSequence(ctx context.Context, state *liveState) error {
	cursor := ""
	latestBoot := ""
	highestCurrent := uint64(0)
	for page := 0; page < 10000; page++ {
		path := "/v1/events?limit=500"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		var response struct {
			Events     []eventProjection `json:"events"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := client.doJSON(ctx, http.MethodGet, path, client.operatorToken, nil, &response, http.StatusOK); err != nil {
			return err
		}
		for _, event := range response.Events {
			if event.NodeID != client.nodeID {
				continue
			}
			latestBoot = event.BootID
			if event.BootID == state.BootID && event.Sequence > highestCurrent {
				highestCurrent = event.Sequence
			}
		}
		if len(response.Events) < 500 || response.NextCursor == "" {
			break
		}
		if response.NextCursor == cursor {
			return errors.New("core event cursor did not advance")
		}
		cursor = response.NextCursor
		if page == 9999 {
			return errors.New("core event history exceeds simulator synchronization limit")
		}
	}
	rotate := latestBoot != "" && latestBoot != state.BootID || state.LastSequence > highestCurrent
	if state.LastSequence < highestCurrent && latestBoot == state.BootID {
		state.LastSequence = highestCurrent
		return saveLiveState(client.stateDirectory, state)
	}
	if !rotate {
		return nil
	}
	if client.bootID != "" {
		return errors.New("configured simulator boot id cannot recover a sequence divergence")
	}
	bootID, err := randomIdentifier("sim-boot")
	if err != nil {
		return err
	}
	state.BootID, state.LastSequence = bootID, 0
	return saveLiveState(client.stateDirectory, state)
}

func (session *liveSession) sendObservations(ctx context.Context, observations []collectors.Observation) ([]*antiflockv1.EventEnvelope, error) {
	if len(observations) == 0 || len(observations) > 256 {
		return nil, errors.New("simulator event batch requires between one and 256 observations")
	}
	lock, err := acquireLiveStateLock(ctx, session.client.stateDirectory)
	if err != nil {
		return nil, err
	}
	defer lock.close()
	state, err := loadLiveState(session.client.stateDirectory, session.client.nodeID)
	if err != nil || state == nil {
		return nil, errors.New("load simulator event state")
	}
	if err := validateLiveIdentity(state, session.privateKey); err != nil {
		return nil, err
	}
	if err := session.client.syncSequence(ctx, state); err != nil {
		return nil, fmt.Errorf("synchronize simulator event sequence: %w", err)
	}
	return session.sendObservationsLocked(ctx, state, observations)
}

func (session *liveSession) sendObservationsLocked(ctx context.Context, state *liveState, observations []collectors.Observation) ([]*antiflockv1.EventEnvelope, error) {
	sequence := &lockedSequenceSource{directory: session.client.stateDirectory, state: state}
	builder, err := collectors.NewTelemetryBuilder(
		session.deploymentID, session.client.nodeID, state.BootID, sequence,
		collectors.EventSignerFunc(func(event *model.EventEnvelope) error {
			return events.SignAt(event, session.client.nodeID, session.privateKey, session.client.clock())
		}), session.client.clock,
	)
	if err != nil {
		return nil, err
	}
	wire := make([]*antiflockv1.EventEnvelope, 0, len(observations))
	for _, observation := range observations {
		event, _, err := builder.Build(ctx, observation)
		if err != nil {
			return nil, err
		}
		wire = append(wire, event)
	}
	batchID := stableOperationID("sim-batch", state.BootID+fmt.Sprintf(":%d", state.LastSequence))
	input := &antiflockv1.SubmitEventBatchRequest{Batch: &antiflockv1.EventBatch{
		BatchId: batchID, NodeId: session.client.nodeID, Events: wire,
	}}
	var output antiflockv1.SubmitEventBatchResponse
	if err := session.client.doProto(ctx, http.MethodPost, "/v1/events/batch", session.client.agentToken, input, &output, http.StatusOK); err != nil {
		return nil, fmt.Errorf("submit simulator event batch: %w", err)
	}
	ack := output.GetAck()
	if ack == nil || ack.GetBatchId() != batchID || len(ack.GetRejected()) != 0 || ack.GetHighestContiguousSequence() != state.LastSequence {
		return nil, errors.New("core did not durably acknowledge the complete simulator event batch")
	}
	return wire, nil
}

func (session *liveSession) sendHeartbeat(ctx context.Context) (string, error) {
	lock, err := acquireLiveStateLock(ctx, session.client.stateDirectory)
	if err != nil {
		return "", err
	}
	defer lock.close()
	state, err := loadLiveState(session.client.stateDirectory, session.client.nodeID)
	if err != nil || state == nil {
		return "", errors.New("load simulator heartbeat state")
	}
	if err := validateLiveIdentity(state, session.privateKey); err != nil {
		return "", err
	}
	if err := session.client.syncSequence(ctx, state); err != nil {
		return "", fmt.Errorf("synchronize simulator heartbeat sequence: %w", err)
	}
	now := session.client.clock().UTC()
	payload := &antiflockv1.NodeHeartbeat{
		NodeId: session.client.nodeID, BootId: state.BootID, ObservedAt: timestamppb.New(now),
		LastEventSequence: state.LastSequence, HealthReasonCodes: []string{"SIMULATION_ONLY", "HOST_MUTATION_DISABLED"},
	}
	wire, err := session.sendObservationsLocked(ctx, state, []collectors.Observation{{
		Kind: "node.heartbeat", ObservedAt: now, Classification: model.EvidenceDetected,
		Confidence: 1, Sensitivity: model.SensitivityInternal, Payload: payload,
	}})
	if err != nil {
		return "", err
	}
	return wire[0].GetId(), nil
}

// RunLiveStream bootstraps the simulator and continuously refreshes an explicit
// simulation-only protected baseline plus signed DETECTED heartbeats. This keeps
// the developer dashboard useful without claiming anything about the host.
// Transient refresh failures are reported as safe status records and retried;
// enrollment or identity failures remain fatal.
func RunLiveStream(ctx context.Context, config LiveConfig, interval time.Duration, emit func(LiveStreamEvent) error) error {
	if emit == nil {
		return errors.New("simulator stream emitter is required")
	}
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	client, err := newLiveClient(config)
	if err != nil {
		return err
	}
	session, err := client.bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap simulator: %w", err)
	}
	emitStatus := func(status, eventID, safeError string) error {
		return emit(LiveStreamEvent{
			SchemaVersion: "antiflock.sim-stream/v1", Status: status, NodeID: client.nodeID,
			DeploymentID: session.deploymentID, EventID: eventID,
			ObservedAt: client.clock().UTC().Format(time.RFC3339Nano), SafeError: safeError,
		})
	}
	if err := emitStatus("ready", "", ""); err != nil {
		return err
	}
	send := func() error {
		now := client.clock().UTC()
		runID := fmt.Sprintf("stream-%d", now.UnixNano())
		if _, sendErr := session.sendCoffeeShopContext(ctx, runID, now); sendErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return emitStatus("degraded", "", sendErr.Error())
		}
		verificationEventIDs, sendErr := session.sendVerifiedRecovery(ctx, runID, now)
		if sendErr == nil {
			sendErr = session.reportPosture(ctx, "PROTECTED", now, verificationEventIDs)
		}
		if sendErr == nil {
			var eventID string
			eventID, sendErr = session.sendHeartbeat(ctx)
			if sendErr == nil {
				return emitStatus("heartbeat", eventID, "")
			}
		}
		if sendErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return emitStatus("degraded", "", sendErr.Error())
		}
		return nil
	}
	if err := send(); err != nil && ctx.Err() == nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := send(); err != nil && ctx.Err() == nil {
				return err
			}
		}
	}
}

func evidenceForSimulation(id string, observedAt time.Time, statement []byte) model.EvidenceReference {
	digest := sha256.Sum256(statement)
	verifiedAt := observedAt.UTC()
	expiresAt := observedAt.UTC().Add(90 * time.Second)
	return model.EvidenceReference{
		ID: id, Role: "SUPPORTING", Classification: model.EvidenceVerified,
		SourceType: "DETERMINISTIC_RULE", Source: "AntiFlock deterministic simulator verifier",
		ObservedAt: observedAt.UTC(), LastVerifiedAt: &verifiedAt, ExpiresAt: &expiresAt,
		Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, LocationPrecision: "WITHHELD",
		Explanation: "Deterministic simulation verification only; this is not a measurement of the host network.",
		Integrity:   model.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]},
		Attributes:  map[string]string{"methodId": "antiflock.simulation.deterministic.v1", "simulation": "true"},
	}
}

func detectedEvidenceForSimulation(id string, observedAt time.Time, statement []byte) model.EvidenceReference {
	digest := sha256.Sum256(statement)
	return model.EvidenceReference{
		ID: id, Role: "SUPPORTING", Classification: model.EvidenceDetected,
		SourceType: "DETERMINISTIC_RULE", Source: "AntiFlock coffee-shop scenario",
		ObservedAt: observedAt.UTC(), Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate,
		LocationPrecision: "WITHHELD",
		Explanation:       "Deterministic simulation context only; no host network identifier was collected.",
		Integrity:         model.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]},
		Attributes:        map[string]string{"methodId": "antiflock.simulation.context.v1", "simulation": "true"},
	}
}

func (session *liveSession) sendCoffeeShopContext(ctx context.Context, runID string, observedAt time.Time) ([]string, error) {
	wifiStatement := []byte(runID + ":simulated untrusted open Wi-Fi with identifiers withheld")
	routeStatement := []byte(runID + ":simulated default route with interface and gateway withheld")
	wifi := &antiflockv1.WifiObservation{
		Security:   antiflockv1.WifiSecurity_WIFI_SECURITY_OPEN,
		Trust:      antiflockv1.NetworkTrust_NETWORK_TRUST_UNTRUSTED,
		ObservedAt: timestamppb.New(observedAt),
	}
	route := &antiflockv1.RouteObservation{
		RouteId: "simulated-default-route", Destination: "0.0.0.0/0", DefaultRoute: true,
		ObservedAt: timestamppb.New(observedAt),
	}
	wire, err := session.sendObservations(ctx, []collectors.Observation{
		{
			Kind: "network.wifi_changed", ObservedAt: observedAt, Classification: model.EvidenceDetected,
			Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, Payload: wifi,
			Evidence: []model.EvidenceReference{detectedEvidenceForSimulation(runID+":wifi-context", observedAt, wifiStatement)},
		},
		{
			Kind: "network.route_changed", ObservedAt: observedAt, Classification: model.EvidenceDetected,
			Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, Payload: route,
			Evidence: []model.EvidenceReference{detectedEvidenceForSimulation(runID+":route-context", observedAt, routeStatement)},
		},
	})
	if err != nil {
		return nil, err
	}
	return []string{wire[0].GetId(), wire[1].GetId()}, nil
}

func (session *liveSession) sendVerifiedRecovery(ctx context.Context, runID string, observedAt time.Time) ([]string, error) {
	meshStatement := []byte(runID + ":simulated healthy approved mesh exit")
	dnsStatement := []byte(runID + ":simulated verified DNS path")
	routeStatement := []byte(runID + ":simulated verified policy default route through mesh")
	egressStatement := []byte(runID + ":simulated external probe verified through the same mesh path")
	mesh := &antiflockv1.MeshPathObservation{
		PathId: "simulated-path", Provider: "simulation", SourceNodeId: session.client.nodeID,
		DestinationNodeId: "simulated-exit", ConnectionType: antiflockv1.MeshConnectionType_MESH_CONNECTION_TYPE_DIRECT,
		ExitNodeId: "simulated-exit", ApprovedExitActive: true, TunnelHealthy: true, ObservedAt: timestamppb.New(observedAt),
	}
	dns := &antiflockv1.DnsObservation{
		ResolverAddresses: []string{"192.0.2.53"}, Source: "simulation", PathVerified: true, ObservedAt: timestamppb.New(observedAt),
	}
	route := &antiflockv1.RouteObservation{
		RouteId: "simulated-protected-default", Destination: "0.0.0.0/0", InterfaceId: "simulated-mesh0",
		DefaultRoute: true, PolicyRoute: true, ObservedAt: timestamppb.New(observedAt),
	}
	egress := &antiflockv1.FlowObservation{
		FlowId: runID + "-external-egress-probe", Remote: &antiflockv1.FlowEndpoint{Hostname: "github.com", Port: 443},
		Protocol:  antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP,
		Direction: antiflockv1.FlowDirection_FLOW_DIRECTION_OUTBOUND, StartedAt: timestamppb.New(observedAt),
		EgressInterfaceId: "simulated-mesh0", MeshPathId: "simulated-path",
		Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_INTERNAL,
	}
	wire, err := session.sendObservations(ctx, []collectors.Observation{
		{
			Kind: "mesh.path_changed", ObservedAt: observedAt, Classification: model.EvidenceVerified,
			Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, Payload: mesh,
			Evidence: []model.EvidenceReference{evidenceForSimulation(runID+":mesh-evidence", observedAt, meshStatement)},
		},
		{
			Kind: "network.dns_changed", ObservedAt: observedAt, Classification: model.EvidenceVerified,
			Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, Payload: dns,
			Evidence: []model.EvidenceReference{evidenceForSimulation(runID+":dns-evidence", observedAt, dnsStatement)},
		},
		{
			Kind: "network.route_changed", ObservedAt: observedAt, Classification: model.EvidenceVerified,
			Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, Payload: route,
			Evidence: []model.EvidenceReference{evidenceForSimulation(runID+":route-evidence", observedAt, routeStatement)},
		},
		{
			Kind: "flow.started", ObservedAt: observedAt, Classification: model.EvidenceVerified,
			Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, Payload: egress,
			Evidence: []model.EvidenceReference{evidenceForSimulation(runID+":egress-evidence", observedAt, egressStatement)},
		},
	})
	if err != nil {
		return nil, err
	}
	return []string{wire[0].GetId(), wire[1].GetId(), wire[2].GetId(), wire[3].GetId()}, nil
}

type liveDecision struct {
	Decision    string   `json:"decision"`
	ActionID    string   `json:"actionId"`
	ReasonCodes []string `json:"reasonCodes"`
	Protection  struct {
		ObservedAt     string `json:"observedAt"`
		PolicyRevision uint64 `json:"policyRevision"`
	} `json:"protection"`
	Audit struct {
		PolicyRevision uint64 `json:"policyRevision"`
	} `json:"audit"`
}

type liveAuditEvent struct {
	EventID        string         `json:"eventId"`
	Lifecycle      string         `json:"lifecycle"`
	OccurredAt     string         `json:"occurredAt"`
	ActionID       string         `json:"actionId"`
	RequestID      string         `json:"requestId"`
	Decision       string         `json:"decision"`
	TraceID        string         `json:"traceId"`
	PolicyRevision uint64         `json:"policyRevision"`
	ReasonCodes    []string       `json:"reasonCodes"`
	Details        map[string]any `json:"details,omitempty"`
}

func (session *liveSession) reportPosture(ctx context.Context, state string, observedAt time.Time, eventIDs []string) error {
	truth := state == "PROTECTED"
	reasons := []string{"AF-SIMULATION-EXPOSED"}
	if truth {
		reasons = []string{"AF-SIMULATION-VERIFIED"}
	}
	report := map[string]any{
		"nodeId": session.client.nodeID, "state": state,
		"observedAt":   observedAt.UTC().Format(time.RFC3339Nano),
		"validUntil":   observedAt.UTC().Add(90 * time.Second).Format(time.RFC3339Nano),
		"networkTrust": "UNTRUSTED", "meshConnected": truth, "approvedExitActive": truth,
		"dnsProtected": truth, "routeProtected": truth, "reasonCodes": reasons,
		"policyRevision": uint64(7), "verificationEventIds": eventIDs,
	}
	var output struct {
		Accepted bool `json:"accepted"`
	}
	if err := session.client.doJSON(ctx, http.MethodPost, "/v1/posture/report", session.client.agentToken, report, &output, http.StatusAccepted); err != nil {
		return fmt.Errorf("report simulator posture: %w", err)
	}
	if !output.Accepted {
		return errors.New("core did not accept simulator posture")
	}
	return nil
}

func (session *liveSession) evaluate(ctx context.Context, action map[string]any) (liveDecision, error) {
	var output liveDecision
	if err := session.client.doJSON(ctx, http.MethodPost, "/v1/actions/evaluate", session.client.sdkToken, map[string]any{"action": action}, &output, http.StatusCreated, http.StatusOK); err != nil {
		return liveDecision{}, fmt.Errorf("evaluate simulator action: %w", err)
	}
	return output, nil
}

func safeReasonCodes(values []string, fallback string) []string {
	if len(values) == 0 {
		return []string{fallback}
	}
	return append([]string(nil), values...)
}

func (session *liveSession) appendAudit(ctx context.Context, event liveAuditEvent) error {
	path := "/v1/actions/" + url.PathEscape(event.ActionID) + "/audit"
	if err := session.client.doJSON(ctx, http.MethodPost, path, session.client.sdkToken, event, nil, http.StatusNoContent); err != nil {
		return fmt.Errorf("append simulator action audit: %w", err)
	}
	return nil
}

func makeAudit(runID, lifecycle string, index int, now time.Time, actionID, operationID string, decision liveDecision) liveAuditEvent {
	return liveAuditEvent{
		EventID: fmt.Sprintf("%s-audit-%02d", runID, index), Lifecycle: lifecycle,
		OccurredAt: now.UTC().Format(time.RFC3339Nano), ActionID: actionID, RequestID: actionID,
		Decision: decision.Decision, TraceID: operationID, PolicyRevision: decision.Audit.PolicyRevision,
		ReasonCodes: safeReasonCodes(decision.ReasonCodes, "AF-SIMULATION-LIFECYCLE"),
		Details:     map[string]any{"simulation": true},
	}
}

// RunLiveCoffeeShop performs a real Core-backed demo. VERIFIED records describe
// only deterministic simulated facts and are labeled as such; no host network
// or tunnel state is claimed. When verify is true, success requires durable
// event/action/posture readback and exact audit-event replay.
func RunLiveCoffeeShop(ctx context.Context, config LiveConfig, verify bool) (*LiveCoffeeShopResult, error) {
	client, err := newLiveClient(config)
	if err != nil {
		return nil, err
	}
	session, err := client.bootstrap(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap simulator: %w", err)
	}
	runID, err := randomIdentifier("simrun")
	if err != nil {
		return nil, err
	}
	actionID := runID + "-action"
	operationID := runID + "-operation"
	start := client.clock().UTC()
	contextEventIDs, err := session.sendCoffeeShopContext(ctx, runID, start)
	if err != nil {
		return nil, err
	}
	if err := session.reportPosture(ctx, "EXPOSED", start, nil); err != nil {
		return nil, err
	}
	action := map[string]any{
		"id": actionID, "applicationId": client.applicationID, "nodeId": client.nodeID,
		"actionType": "git.push", "destinations": []string{"github.com"},
		"dataClass": "repository-source", "sensitivity": "SENSITIVITY_OPERATOR_PRIVATE",
		"deadline": start.Add(90 * time.Second).Format(time.RFC3339Nano), "operationId": operationID,
	}
	held, err := session.evaluate(ctx, action)
	if err != nil {
		return nil, err
	}
	if held.Decision != "HOLD" || held.ActionID != actionID {
		return nil, errors.New("core did not hold the exposed simulator action")
	}
	audits := []liveAuditEvent{
		makeAudit(runID, "SDK_DECISION_RECEIVED", 1, client.clock(), actionID, operationID, held),
		makeAudit(runID, "SDK_HOLD_WAIT_STARTED", 2, client.clock(), actionID, operationID, held),
	}
	for _, event := range audits {
		if err := session.appendAudit(ctx, event); err != nil {
			return nil, err
		}
	}
	recoveredAt := client.clock().UTC()
	verificationEventIDs, err := session.sendVerifiedRecovery(ctx, runID, recoveredAt)
	if err != nil {
		return nil, err
	}
	protectedAt := client.clock().UTC()
	heldObservedAt, parseErr := time.Parse(time.RFC3339Nano, held.Protection.ObservedAt)
	if parseErr != nil {
		return nil, errors.New("core returned an invalid held posture observation time")
	}
	if !protectedAt.After(heldObservedAt) {
		protectedAt = heldObservedAt.Add(time.Nanosecond)
	}
	if err := session.reportPosture(ctx, "PROTECTED", protectedAt, verificationEventIDs); err != nil {
		return nil, err
	}
	var waitResponse struct {
		Restored bool `json:"restored"`
	}
	waitBody := map[string]any{
		"actionId": actionID, "afterObservedAt": held.Protection.ObservedAt,
		"deadline": client.clock().UTC().Add(15 * time.Second).Format(time.RFC3339Nano),
	}
	waitPath := "/v1/actions/" + url.PathEscape(actionID) + "/wait"
	if err := client.doJSON(ctx, http.MethodPost, waitPath, client.sdkToken, waitBody, &waitResponse, http.StatusOK); err != nil {
		return nil, fmt.Errorf("wait for simulator protection recovery: %w", err)
	}
	if !waitResponse.Restored {
		return nil, errors.New("core did not observe simulator protection recovery")
	}
	allowed, err := session.evaluate(ctx, action)
	if err != nil {
		return nil, err
	}
	if allowed.Decision != "ALLOW" || allowed.ActionID != actionID {
		return nil, errors.New("core did not release the held simulator action")
	}
	finalAudits := []liveAuditEvent{
		makeAudit(runID, "SDK_PROTECTION_RESTORED", 3, client.clock(), actionID, operationID, allowed),
		makeAudit(runID, "SDK_ACTION_EXECUTION_STARTED", 4, client.clock(), actionID, operationID, allowed),
		makeAudit(runID, "SDK_ACTION_EXECUTION_SUCCEEDED", 5, client.clock(), actionID, operationID, allowed),
	}
	for _, event := range finalAudits {
		if err := session.appendAudit(ctx, event); err != nil {
			return nil, err
		}
	}
	audits = append(audits, finalAudits...)
	result := &LiveCoffeeShopResult{
		SchemaVersion: "antiflock.live-simulation/v1", Simulation: true,
		NodeID: client.nodeID, DeploymentID: session.deploymentID, ActionID: actionID,
		InitialDecision: held.Decision, FinalDecision: allowed.Decision,
		ContextEventIDs: contextEventIDs, VerificationEventIDs: verificationEventIDs,
		AuditEventIDs: make([]string, 0, len(audits)),
	}
	for _, event := range audits {
		result.AuditEventIDs = append(result.AuditEventIDs, event.EventID)
	}
	if verify {
		if err := session.verifyCoffeeShop(ctx, result, audits); err != nil {
			return nil, fmt.Errorf("verify live coffee-shop simulation: %w", err)
		}
		result.Verified = true
	}
	return result, nil
}

func (session *liveSession) verifyCoffeeShop(ctx context.Context, result *LiveCoffeeShopResult, audits []liveAuditEvent) error {
	var actionResponse struct {
		Actions []struct {
			ActionID string `json:"actionId"`
			NodeID   string `json:"nodeId"`
			Decision string `json:"decision"`
		} `json:"actions"`
	}
	if err := session.client.doJSON(ctx, http.MethodGet, "/v1/actions?limit=200", session.client.operatorToken, nil, &actionResponse, http.StatusOK); err != nil {
		return err
	}
	actionVerified := false
	for _, action := range actionResponse.Actions {
		if action.ActionID == result.ActionID && action.NodeID == session.client.nodeID && action.Decision == "ALLOW" {
			actionVerified = true
		}
	}
	if !actionVerified {
		return errors.New("durable ALLOW action was not found")
	}
	wanted := make(map[string]model.EvidenceClass, len(result.ContextEventIDs)+len(result.VerificationEventIDs))
	foundEvents := make(map[string]bool, len(wanted))
	for _, id := range result.ContextEventIDs {
		wanted[id] = model.EvidenceDetected
	}
	for _, id := range result.VerificationEventIDs {
		wanted[id] = model.EvidenceVerified
	}
	cursor := ""
	for page := 0; page < 10000; page++ {
		path := "/v1/events?limit=500"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		var response struct {
			Events     []eventProjection `json:"events"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := session.client.doJSON(ctx, http.MethodGet, path, session.client.operatorToken, nil, &response, http.StatusOK); err != nil {
			return err
		}
		for _, event := range response.Events {
			if expected, exists := wanted[event.ID]; exists && event.NodeID == session.client.nodeID && event.Classification == expected {
				foundEvents[event.ID] = true
			}
		}
		if len(response.Events) < 500 || response.NextCursor == "" {
			break
		}
		cursor = response.NextCursor
	}
	for id, expected := range wanted {
		if !foundEvents[id] {
			return fmt.Errorf("durable %s event %s was not found", expected, id)
		}
	}
	var posture struct {
		State          string `json:"state"`
		NodeID         string `json:"nodeId"`
		EvidenceClass  string `json:"evidenceClass"`
		PolicyRevision uint64 `json:"policyRevision"`
	}
	if err := session.client.doJSON(ctx, http.MethodGet, "/v1/posture", session.client.operatorToken, nil, &posture, http.StatusOK); err != nil {
		return err
	}
	if posture.State != "PROTECTED" || posture.NodeID != session.client.nodeID || posture.EvidenceClass != "VERIFIED" || posture.PolicyRevision != 7 {
		return errors.New("durable protected simulator posture was not found")
	}
	for _, event := range audits {
		if err := session.appendAudit(ctx, event); err != nil {
			return errors.New("durable action audit replay failed")
		}
	}
	return nil
}
