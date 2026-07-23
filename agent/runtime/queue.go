// Package runtime provides the fail-closed delivery loop used by a real AntiFlock endpoint agent.
package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
)

const (
	queueSchema = "antiflock.agent-queue/v1"
	queueFileName = "queue.json"
	maximumQueueEvents = 10000
	maximumQueueBytes = 32 << 20
)

type queuedEvent struct {
	Priority collectors.QueuePriority `json:"priority"`
	Wire string `json:"wire"`
}

type queueState struct {
	SchemaVersion string `json:"schemaVersion"`
	NodeID string `json:"nodeId"`
	LastSequence uint64 `json:"lastSequence"`
	Events []queuedEvent `json:"events"`
}

// Queue is a bounded, private on-disk write-ahead queue. It stores signed
// protobuf envelopes verbatim; retries never re-sign or regenerate them.
type Queue struct {
	directory string
	nodeID string
	mu sync.Mutex
	state queueState
}

func OpenQueue(directory, nodeID string) (*Queue, error) {
	if strings.TrimSpace(directory) == "" || strings.TrimSpace(nodeID) == "" { return nil, errors.New("agent queue directory and node id are required") }
	if err := os.MkdirAll(directory, 0o700); err != nil { return nil, errors.New("create agent queue directory") }
	absolute, err := filepath.Abs(directory); if err != nil { return nil, errors.New("resolve agent queue directory") }
	resolved, err := filepath.EvalSymlinks(absolute); if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) { return nil, errors.New("agent queue directory must not traverse symlinks") }
	if err := os.Chmod(absolute, 0o700); err != nil { return nil, errors.New("protect agent queue directory") }
	queue := &Queue{directory: absolute, nodeID: nodeID, state: queueState{SchemaVersion: queueSchema, NodeID: nodeID}}
	if err := queue.load(); err != nil { return nil, err }
	return queue, nil
}

func (queue *Queue) NextSequence(ctx context.Context) (uint64, error) {
	if queue == nil { return 0, errors.New("agent queue is required") }
	if err := ctx.Err(); err != nil { return 0, err }
	queue.mu.Lock(); defer queue.mu.Unlock()
	if queue.state.LastSequence == ^uint64(0) { return 0, errors.New("agent event sequence exhausted") }
	queue.state.LastSequence++
	if err := queue.save(); err != nil { return 0, err }
	return queue.state.LastSequence, nil
}

func (queue *Queue) Enqueue(ctx context.Context, event *antiflockv1.EventEnvelope, priority collectors.QueuePriority) error {
	if queue == nil || event == nil || event.GetId() == "" || event.GetSequence() == 0 { return errors.New("queue requires a signed identified event") }
	if err := ctx.Err(); err != nil { return err }
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(event); if err != nil { return errors.New("encode queued event") }
	queue.mu.Lock(); defer queue.mu.Unlock()
	if len(queue.state.Events) >= maximumQueueEvents { return errors.New("agent queue is full; telemetry is retained and collection must pause") }
	queue.state.Events = append(queue.state.Events, queuedEvent{Priority: priority, Wire: base64.RawStdEncoding.EncodeToString(wire)})
	if err := queue.save(); err != nil { queue.state.Events = queue.state.Events[:len(queue.state.Events)-1]; return err }
	return nil
}

// Batch returns events in their source sequence order. It does not mutate the
// queue; callers must call Acknowledge only after the Core acknowledgement.
func (queue *Queue) Batch(ctx context.Context, maximum int) ([]*antiflockv1.EventEnvelope, error) {
	if queue == nil || maximum < 1 || maximum > 256 { return nil, errors.New("batch size must be between one and 256") }
	if err := ctx.Err(); err != nil { return nil, err }
	queue.mu.Lock(); defer queue.mu.Unlock()
	capacity := len(queue.state.Events); if capacity > maximum { capacity = maximum }
	values := make([]*antiflockv1.EventEnvelope, 0, capacity)
	bootID := ""
	for _, stored := range queue.state.Events {
		if len(values) == maximum { break }
		wire, err := base64.RawStdEncoding.DecodeString(stored.Wire); if err != nil { return nil, errors.New("queued event encoding is invalid") }
		var event antiflockv1.EventEnvelope
		if err := proto.Unmarshal(wire, &event); err != nil || event.GetId() == "" || event.GetSequence() == 0 || event.GetNodeId() != queue.nodeID || event.GetBootId() == "" { return nil, errors.New("queued event is invalid") }
		if bootID == "" { bootID = event.GetBootId() }
		if event.GetBootId() != bootID { continue }
		values = append(values, &event)
	}
	sort.Slice(values, func(left, right int) bool { return values[left].GetSequence() < values[right].GetSequence() })
	return values, nil
}

// Acknowledge removes exactly the events sent in a rejection-free Core batch.
// The Core's contiguous cursor is intentionally not used as a deletion signal:
// source sequence gaps are legal, while the acknowledgement proves durability.
func (queue *Queue) Acknowledge(ctx context.Context, events []*antiflockv1.EventEnvelope) error {
	if queue == nil || len(events) == 0 { return errors.New("queue acknowledgement requires events") }
	if err := ctx.Err(); err != nil { return err }
	ids := make(map[string]struct{}, len(events)); for _, event := range events { if event == nil || event.GetId() == "" { return errors.New("queue acknowledgement contains an invalid event") }; ids[event.GetId()] = struct{}{} }
	queue.mu.Lock(); defer queue.mu.Unlock()
	original := append([]queuedEvent(nil), queue.state.Events...)
	kept := make([]queuedEvent, 0, len(original))
	for _, stored := range original {
		wire, err := base64.RawStdEncoding.DecodeString(stored.Wire); if err != nil { return errors.New("queued event encoding is invalid") }
		var event antiflockv1.EventEnvelope; if err := proto.Unmarshal(wire, &event); err != nil { return errors.New("queued event is invalid") }
		if _, sent := ids[event.GetId()]; !sent { kept = append(kept, stored) }
	}
	if len(kept) == len(original) { return errors.New("acknowledgement did not match queued events") }
	queue.state.Events = kept
	if err := queue.save(); err != nil {
		queue.state.Events = original
		return err
	}
	return nil
}

func (queue *Queue) load() error {
	path := filepath.Join(queue.directory, queueFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) { return nil }
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() > maximumQueueBytes { return errors.New("agent queue file is not a bounded private regular file") }
	content, err := os.ReadFile(path); if err != nil { return errors.New("read agent queue") }
	decoder := json.NewDecoder(strings.NewReader(string(content))); decoder.DisallowUnknownFields()
	if err := decoder.Decode(&queue.state); err != nil { return errors.New("decode agent queue") }
	var extra any; if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) { return errors.New("agent queue contains trailing data") }
	if queue.state.SchemaVersion != queueSchema || queue.state.NodeID != queue.nodeID || len(queue.state.Events) > maximumQueueEvents { return errors.New("agent queue schema is invalid") }
	return nil
}

func (queue *Queue) save() error {
	content, err := json.Marshal(queue.state); if err != nil || len(content) > maximumQueueBytes { return errors.New("encode bounded agent queue") }
	temporary, err := os.CreateTemp(queue.directory, ".queue-*.tmp"); if err != nil { return errors.New("stage agent queue") }
	temporaryPath := temporary.Name(); defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil { temporary.Close(); return errors.New("protect staged agent queue") }
	if _, err := temporary.Write(content); err != nil { temporary.Close(); return errors.New("write staged agent queue") }
	if err := temporary.Sync(); err != nil { temporary.Close(); return errors.New("sync staged agent queue") }
	if err := temporary.Close(); err != nil { return errors.New("close staged agent queue") }
	if err := os.Rename(temporaryPath, filepath.Join(queue.directory, queueFileName)); err != nil { return fmt.Errorf("install agent queue: %w", err) }
	return nil
}
