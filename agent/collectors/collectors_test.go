package collectors

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type memoryFiles map[string][]byte

func (files memoryFiles) ReadFile(path string) ([]byte, error) {
	value, ok := files[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

type fixedInterfaces struct {
	values []net.Interface
	addrs  map[string][]net.Addr
}

func (source fixedInterfaces) Interfaces() ([]net.Interface, error) {
	return append([]net.Interface(nil), source.values...), nil
}

func (source fixedInterfaces) Addrs(value net.Interface) ([]net.Addr, error) {
	return append([]net.Addr(nil), source.addrs[value.Name]...), nil
}

func TestLinuxCollectorMinimizesMetadataAndIsDeterministic(t *testing.T) {
	t.Parallel()
	observedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	collector, err := NewLinuxCollector(LinuxConfig{
		NodeID: "node", BootID: "boot", RouteTablePath: "routes", ResolvConfPath: "dns",
		Clock: func() time.Time { return observedAt },
		Files: memoryFiles{
			"routes": []byte("Iface\tDestination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0\t00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\neth0\t0001A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"),
			"dns":    []byte("nameserver 9.9.9.9\nsearch private.corp.example\n"),
		},
		Interfaces: fixedInterfaces{
			values: []net.Interface{{Index: 2, MTU: 1500, Name: "eth0", Flags: net.FlagUp}},
			addrs:  map[string][]net.Addr{"eth0": {&net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(first.Snapshot, second.Snapshot) {
		t.Fatal("identical local sources did not produce an identical snapshot")
	}
	if len(first.HealthReasonCodes) != 0 || len(first.Snapshot.Interfaces) != 1 || len(first.Snapshot.Routes) != 1 || first.Snapshot.Dns == nil {
		t.Fatalf("unexpected collection: %#v", first)
	}
	if got := first.Snapshot.Routes[0]; !got.DefaultRoute || got.Gateway != "192.168.1.1" || got.InterfaceId != first.Snapshot.Interfaces[0].InterfaceId {
		t.Fatalf("default route = %#v", got)
	}
	if len(first.Snapshot.Interfaces[0].Addresses) != 0 {
		t.Fatal("private interface addresses were collected without opt-in")
	}
	if len(first.Snapshot.Dns.SearchDomains) != 0 || first.Snapshot.Dns.PathVerified {
		t.Fatal("search domains leaked or DNS path was represented as verified")
	}
	if first.Snapshot.Wifi != nil || len(first.Snapshot.Flows) != 0 || len(first.Snapshot.ListeningServices) != 0 {
		t.Fatal("collector crossed the payload, Wi-Fi, flow, or process minimization boundary")
	}
	for _, observation := range first.Observations() {
		if observation.Classification != model.EvidenceDetected || observation.Sensitivity != model.SensitivityOperatorPrivate {
			t.Fatalf("observation classification changed: %#v", observation)
		}
	}
}

func TestLinuxCollectorReportsUnavailableFactsWithoutFabricatingThem(t *testing.T) {
	t.Parallel()
	collector, err := NewLinuxCollector(LinuxConfig{
		NodeID: "node", BootID: "boot", RouteTablePath: "missing-route", ResolvConfPath: "missing-dns",
		Clock: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) },
		Files: memoryFiles{}, Interfaces: fixedInterfaces{},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.HealthReasonCodes, []string{"AF-COLLECTOR-DNS-UNAVAILABLE", "AF-COLLECTOR-ROUTE-UNAVAILABLE"}) {
		t.Fatalf("health reasons = %v", result.HealthReasonCodes)
	}
	if result.Snapshot.Dns != nil || len(result.Snapshot.Routes) != 0 {
		t.Fatal("unavailable DNS or route facts were fabricated")
	}
}

type sequenceSource struct {
	mu   sync.Mutex
	next uint64
}

func (source *sequenceSource) NextSequence(context.Context) (uint64, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return source.next, nil
}

type memoryQueue struct {
	mu       sync.Mutex
	events   []*antiflockv1.EventEnvelope
	priority []QueuePriority
}

func (queue *memoryQueue) Enqueue(_ context.Context, event *antiflockv1.EventEnvelope, priority QueuePriority) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.events = append(queue.events, proto.Clone(event).(*antiflockv1.EventEnvelope))
	queue.priority = append(queue.priority, priority)
	return nil
}

func TestTelemetryBuilderSignsBeforeQueueingAndRejectsUnsupportedVerifiedClaims(t *testing.T) {
	t.Parallel()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	observedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	builder, err := NewTelemetryBuilder(
		"deployment", "node", "boot", &sequenceSource{},
		EventSignerFunc(func(event *model.EventEnvelope) error {
			return events.SignAt(event, "node", privateKey, observedAt)
		}),
		func() time.Time { return observedAt },
	)
	if err != nil {
		t.Fatal(err)
	}
	observation := Observation{
		Kind: "network.dns_changed", ObservedAt: observedAt,
		Classification: model.EvidenceDetected, Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate,
		Payload: &antiflockv1.DnsObservation{
			ResolverAddresses: []string{"9.9.9.9"}, Source: "resolv.conf", PathVerified: false,
			ObservedAt: timestamppbAt(observedAt),
		},
	}
	queue := &memoryQueue{}
	wire, err := builder.BuildAndEnqueue(context.Background(), queue, observation)
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.events) != 1 || queue.priority[0] != QueuePriorityObservation || wire.SourceSignature == nil {
		t.Fatalf("queued event = %#v, priorities = %v", wire, queue.priority)
	}
	event, err := model.EventFromProto(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := events.VerifySource(event, publicKey); err != nil {
		t.Fatalf("verify queued event: %v", err)
	}
	if event.Classification != model.EvidenceDetected || event.ReceivedAt != (time.Time{}) {
		t.Fatal("queue changed evidence class or assigned Core receipt time")
	}

	observation.Classification = model.EvidenceVerified
	if _, _, err := builder.Build(context.Background(), observation); err == nil {
		t.Fatal("VERIFIED telemetry without verification provenance was accepted")
	}
}

func TestTelemetryBuilderRejectsSignerMutationOutsideSignatureFields(t *testing.T) {
	t.Parallel()
	seed := make([]byte, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	builder, err := NewTelemetryBuilder(
		"deployment", "node", "boot", &sequenceSource{},
		EventSignerFunc(func(event *model.EventEnvelope) error {
			event.Classification = model.EvidenceReported
			return events.SignAt(event, "node", privateKey, now)
		}), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = builder.Build(context.Background(), Observation{
		Kind: "network.dns_changed", ObservedAt: now, Classification: model.EvidenceDetected,
		Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate,
		Payload: &antiflockv1.DnsObservation{Source: "test", ObservedAt: timestamppb.New(now)},
	})
	if err == nil || !strings.Contains(err.Error(), "immutable source content") {
		t.Fatalf("mutating signer result = %v", err)
	}
}

func timestamppbAt(value time.Time) *timestamppb.Timestamp {
	return timestamppb.New(value)
}
