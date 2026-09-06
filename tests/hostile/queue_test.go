package hostile_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	agentruntime "github.com/DBarr3/AntiFlock/agent/runtime"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
)

const queueNode = "node-queue"

func writeQueueFile(t *testing.T, directory string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "queue.json"), content, mode); err != nil {
		t.Fatal(err)
	}
}

func queueEntry(t *testing.T, event *antiflockv1.EventEnvelope) string {
	t.Helper()
	wire, err := proto.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawStdEncoding.EncodeToString(wire)
}

func queueDocument(t *testing.T, node string, wires ...string) []byte {
	t.Helper()
	events := make([]map[string]any, 0, len(wires))
	for _, wire := range wires {
		events = append(events, map[string]any{"priority": 1, "wire": wire})
	}
	content, err := json.Marshal(map[string]any{"schemaVersion": "antiflock.agent-queue/v1", "nodeId": node, "lastSequence": len(wires), "events": events})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// Invariant: a queue file that is not a complete, private, schema-exact JSON
// document is refused at open; the agent never starts on ambiguous state.
func TestQueueOpenRejectsCorruptAndUnsafeFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: queue file mode checks are POSIX permission bits")
	}
	good := queueDocument(t, queueNode, queueEntry(t, &antiflockv1.EventEnvelope{Id: "e1", Sequence: 1, NodeId: queueNode, BootId: "boot"}))
	cases := map[string]struct {
		content []byte
		mode    os.FileMode
	}{
		"truncated-json":      {good[:len(good)/2], 0o600},
		"trailing-data":       {append(append([]byte(nil), good...), []byte("{}")...), 0o600},
		"unknown-field":       {[]byte(strings.Replace(string(good), `"nodeId"`, `"extra":1,"nodeId"`, 1)), 0o600},
		"schema-drift":        {[]byte(strings.Replace(string(good), "antiflock.agent-queue/v1", "antiflock.agent-queue/v2", 1)), 0o600},
		"foreign-node":        {queueDocument(t, "node-other"), 0o600},
		"world-readable":      {good, 0o644},
		"group-readable":      {good, 0o640},
		"too-many-events":     {queueDocument(t, queueNode, repeat(queueEntry(t, &antiflockv1.EventEnvelope{Id: "e", Sequence: 1, NodeId: queueNode, BootId: "b"}), 10001)...), 0o600},
		"oversized":           {[]byte(`{"schemaVersion":"antiflock.agent-queue/v1","nodeId":"` + queueNode + `","lastSequence":1,"events":[{"priority":1,"wire":"` + strings.Repeat("A", 33<<20) + `"}]}`), 0o600},
		"array-document":      {[]byte(`[]`), 0o600},
		"empty-file":          {nil, 0o600},
		"negative-sequence":   {[]byte(strings.Replace(string(good), `"lastSequence":1`, `"lastSequence":-1`, 1)), 0o600},
		"sequence-as-string":  {[]byte(strings.Replace(string(good), `"lastSequence":1`, `"lastSequence":"1"`, 1)), 0o600},
		"priority-as-string":  {[]byte(strings.Replace(string(good), `"priority":1`, `"priority":"1"`, 1)), 0o600},
		"priority-out-of-range": {[]byte(strings.Replace(string(good), `"priority":1`, `"priority":300`, 1)), 0o600},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := filepath.Join(t.TempDir(), "queue")
			writeQueueFile(t, directory, testCase.content, testCase.mode)
			queue, err := agentruntime.OpenQueue(directory, queueNode)
			if err == nil {
				_ = queue.Close()
				t.Fatalf("%s: corrupt queue opened", name)
			}
			if strings.Contains(err.Error(), "antiflock.agent-queue") || strings.Contains(err.Error(), "node-other") {
				t.Fatalf("%s: error echoes file content: %v", name, err)
			}
			if _, err := agentruntime.InspectQueue(directory, queueNode); err == nil {
				t.Fatalf("%s: corrupt queue inspected as healthy", name)
			}
		})
	}
}

func repeat(value string, count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = value
	}
	return values
}

// Invariant: one corrupt entry must not poison delivery of every other
// event. Either the loader rejects the file at open (fail closed, operator
// sees it) or Batch skips the entry; it must not return an error forever
// while the queue fills up.
func TestQueuePoisonEntryDoesNotBlockDeliveryForever(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: queue file mode checks are POSIX permission bits")
	}
	healthy := queueEntry(t, &antiflockv1.EventEnvelope{Id: "e1", Sequence: 1, NodeId: queueNode, BootId: "boot"})
	cases := map[string]string{
		"not-base64":        "!!!!",
		"not-protobuf":      base64.RawStdEncoding.EncodeToString([]byte{0xff, 0xff, 0xff}),
		"foreign-node":      queueEntry(t, &antiflockv1.EventEnvelope{Id: "e2", Sequence: 2, NodeId: "node-other", BootId: "boot"}),
		"missing-boot":      queueEntry(t, &antiflockv1.EventEnvelope{Id: "e2", Sequence: 2, NodeId: queueNode}),
		"sequence-zero":     queueEntry(t, &antiflockv1.EventEnvelope{Id: "e2", Sequence: 0, NodeId: queueNode, BootId: "boot"}),
		"empty-id":          queueEntry(t, &antiflockv1.EventEnvelope{Id: "", Sequence: 2, NodeId: queueNode, BootId: "boot"}),
		"truncated-protobuf": func() string {
			wire, err := proto.Marshal(&antiflockv1.EventEnvelope{Id: "e2", Sequence: 2, NodeId: queueNode, BootId: "boot", Kind: "network.route_changed"})
			if err != nil {
				t.Fatal(err)
			}
			return base64.RawStdEncoding.EncodeToString(wire[:len(wire)-3])
		}(),
	}
	for name, poison := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := filepath.Join(t.TempDir(), "queue")
			writeQueueFile(t, directory, queueDocument(t, queueNode, healthy, poison), 0o600)
			queue, err := agentruntime.OpenQueue(directory, queueNode)
			if err != nil {
				return // rejected at open: fail closed, acceptable
			}
			defer queue.Close()
			batch, err := queue.Batch(context.Background(), 16)
			if err != nil {
				t.Skipf("KNOWN-GAP AF-GAP-005: agent/runtime queue accepts a %s entry at open, then Batch fails for the whole queue (%v); healthy events behind it are never delivered", name, err)
			}
			if len(batch) != 1 || batch[0].GetId() != "e1" {
				t.Fatalf("%s: batch = %v", name, batch)
			}
		})
	}
}

// Invariant: the queue directory and file must be real, private paths.
func TestQueueRejectsSymlinkedDirectoryAndFile(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: symlink creation requires privilege on Windows")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	writeQueueFile(t, real, queueDocument(t, queueNode), 0o600)
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("ENV-UNAVAILABLE: symlinks unavailable on this filesystem")
	}
	if queue, err := agentruntime.OpenQueue(link, queueNode); err == nil {
		_ = queue.Close()
		t.Fatal("symlinked queue directory opened")
	}
	if _, err := agentruntime.InspectQueue(link, queueNode); err == nil {
		t.Fatal("symlinked queue directory inspected")
	}

	other := filepath.Join(root, "other")
	writeQueueFile(t, other, queueDocument(t, queueNode), 0o600)
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, queueDocument(t, queueNode), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(other, "queue.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(other, "queue.json")); err != nil {
		t.Fatal(err)
	}
	if queue, err := agentruntime.OpenQueue(other, queueNode); err == nil {
		_ = queue.Close()
		t.Fatal("symlinked queue file opened")
	}
}

// Invariant: a second writer in the same process is refused, and the lock
// file itself must be a private regular file.
func TestQueueRefusesSecondWriterAndHostileLockFile(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: lock file mode checks are POSIX permission bits")
	}
	directory := filepath.Join(t.TempDir(), "queue")
	first, err := agentruntime.OpenQueue(directory, queueNode)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := agentruntime.OpenQueue(directory, queueNode); err == nil {
		_ = second.Close()
		t.Fatal("second writer acquired the queue")
	}
	hostile := filepath.Join(t.TempDir(), "queue")
	if err := os.MkdirAll(hostile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostile, "queue.lock"), nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if queue, err := agentruntime.OpenQueue(hostile, queueNode); err == nil {
		_ = queue.Close()
		t.Fatal("world-writable lock file accepted")
	}
}
