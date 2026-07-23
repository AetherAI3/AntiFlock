// Package collectors contains privacy-minimized endpoint observation and
// telemetry assembly seams. It deliberately has no packet-capture surface.
package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultRouteTable = "/proc/net/route"
	defaultResolvConf = "/etc/resolv.conf"
	maximumSourceSize = 1 << 20
)

// FileReader is the read-only filesystem surface used by the Linux collector.
type FileReader interface {
	ReadFile(string) ([]byte, error)
}

// InterfaceSource is the read-only network-interface surface used by the
// Linux collector. It does not expose packets, sockets, or process payloads.
type InterfaceSource interface {
	Interfaces() ([]net.Interface, error)
	Addrs(net.Interface) ([]net.Addr, error)
}

type osFiles struct{}

func (osFiles) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

type osInterfaces struct{}

func (osInterfaces) Interfaces() ([]net.Interface, error) { return net.Interfaces() }
func (osInterfaces) Addrs(value net.Interface) ([]net.Addr, error) {
	return value.Addrs()
}

// LinuxConfig controls the deliberately narrow local collection boundary.
// Addresses, search domains, Wi-Fi identifiers, flows, and processes are not
// collected unless an explicit field below allows the minimum required data.
type LinuxConfig struct {
	NodeID                    string
	BootID                    string
	RouteTablePath            string
	ResolvConfPath            string
	IncludeInterfaceAddresses bool
	IncludeSearchDomains      bool
	IncludeNonDefaultRoutes   bool
	IncludeFlowMetadata       bool
	TCPTablePath              string
	TCP6TablePath             string
	UDPTablePath              string
	UDP6TablePath             string
	Clock                     func() time.Time
	Files                     FileReader
	Interfaces                InterfaceSource
}

// LinuxCollector reads kernel-exposed metadata without invoking a shell or
// requiring elevated privileges.
type LinuxCollector struct {
	config LinuxConfig
}

// Collection is a local snapshot plus explicit partial-collection reasons.
// Missing facts remain missing; callers must not infer a protected state from
// an absent warning or synthesize observations for unavailable sources.
type Collection struct {
	Snapshot          *antiflockv1.ObservationSnapshot `json:"snapshot"`
	HealthReasonCodes []string                         `json:"healthReasonCodes,omitempty"`
}

// NewLinuxCollector constructs a read-only collector. Private address and
// search-domain collection is off by default.
func NewLinuxCollector(config LinuxConfig) (*LinuxCollector, error) {
	if strings.TrimSpace(config.NodeID) == "" || strings.TrimSpace(config.BootID) == "" {
		return nil, errors.New("collector node and boot identifiers are required")
	}
	if config.RouteTablePath == "" {
		config.RouteTablePath = defaultRouteTable
	}
	if config.ResolvConfPath == "" {
		config.ResolvConfPath = defaultResolvConf
	}
	if config.TCPTablePath == "" { config.TCPTablePath = defaultTCPTable }
	if config.TCP6TablePath == "" { config.TCP6TablePath = defaultTCP6Table }
	if config.UDPTablePath == "" { config.UDPTablePath = defaultUDPTable }
	if config.UDP6TablePath == "" { config.UDP6TablePath = defaultUDP6Table }
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.Files == nil {
		config.Files = osFiles{}
	}
	if config.Interfaces == nil {
		config.Interfaces = osInterfaces{}
	}
	return &LinuxCollector{config: config}, nil
}

// Collect reads one point-in-time metadata snapshot. Route and DNS failures
// produce reason codes and empty facts rather than invented fallback values.
func (collector *LinuxCollector) Collect(ctx context.Context) (*Collection, error) {
	if collector == nil {
		return nil, errors.New("linux collector is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observedAt := collector.config.Clock().UTC()
	if observedAt.IsZero() || timestamppb.New(observedAt).CheckValid() != nil {
		return nil, errors.New("collector clock returned an invalid time")
	}

	interfaces, err := collector.collectInterfaces(ctx, observedAt)
	if err != nil {
		return nil, fmt.Errorf("collect network interfaces: %w", err)
	}
	result := &Collection{Snapshot: &antiflockv1.ObservationSnapshot{
		NodeId: collector.config.NodeID, BootId: collector.config.BootID,
		ObservedAt: timestamppb.New(observedAt), Interfaces: interfaces,
	}}

	routeBytes, err := collector.config.Files.ReadFile(collector.config.RouteTablePath)
	if err != nil {
		result.HealthReasonCodes = append(result.HealthReasonCodes, "AF-COLLECTOR-ROUTE-UNAVAILABLE")
	} else if len(routeBytes) > maximumSourceSize {
		result.HealthReasonCodes = append(result.HealthReasonCodes, "AF-COLLECTOR-ROUTE-OVERSIZED")
	} else if result.Snapshot.Routes, err = parseRoutes(routeBytes, observedAt, collector.config.IncludeNonDefaultRoutes); err != nil {
		result.Snapshot.Routes = nil
		result.HealthReasonCodes = append(result.HealthReasonCodes, "AF-COLLECTOR-ROUTE-INVALID")
	}

	dnsBytes, err := collector.config.Files.ReadFile(collector.config.ResolvConfPath)
	if err != nil {
		result.HealthReasonCodes = append(result.HealthReasonCodes, "AF-COLLECTOR-DNS-UNAVAILABLE")
	} else if len(dnsBytes) > maximumSourceSize {
		result.HealthReasonCodes = append(result.HealthReasonCodes, "AF-COLLECTOR-DNS-OVERSIZED")
	} else if result.Snapshot.Dns, err = parseDNS(dnsBytes, observedAt, collector.config.IncludeSearchDomains); err != nil {
		result.Snapshot.Dns = nil
		result.HealthReasonCodes = append(result.HealthReasonCodes, "AF-COLLECTOR-DNS-INVALID")
	}

	if collector.config.IncludeFlowMetadata {
		result.Snapshot.Flows, result.HealthReasonCodes = collector.collectFlows(observedAt), result.HealthReasonCodes
		flows, reasons := collector.collectFlows(observedAt)
		result.Snapshot.Flows = flows
		result.HealthReasonCodes = append(result.HealthReasonCodes, reasons...)
	}

	sort.Strings(result.HealthReasonCodes)
	result.HealthReasonCodes = compactStrings(result.HealthReasonCodes)
	if err := assignSnapshotID(result.Snapshot); err != nil {
		return nil, err
	}
	return result, nil
}

func (collector *LinuxCollector) collectInterfaces(ctx context.Context, observedAt time.Time) ([]*antiflockv1.NetworkInterfaceObservation, error) {
	values, err := collector.config.Interfaces.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]*antiflockv1.NetworkInterfaceObservation, 0, len(values))
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := &antiflockv1.NetworkInterfaceObservation{
			InterfaceId: opaqueInterfaceID(value.Index, value.Name), Name: value.Name,
			Type: "unknown", Up: value.Flags&net.FlagUp != 0, Mtu: uint32(max(value.MTU, 0)),
			ObservedAt: timestamppb.New(observedAt),
		}
		if value.Flags&net.FlagLoopback != 0 {
			item.Type = "loopback"
		}
		if collector.config.IncludeInterfaceAddresses {
			addresses, addressErr := collector.config.Interfaces.Addrs(value)
			if addressErr != nil {
				return nil, fmt.Errorf("read interface %q addresses: %w", value.Name, addressErr)
			}
			item.Addresses = normalizeAddresses(addresses)
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].InterfaceId < result[right].InterfaceId })
	return result, nil
}

func normalizeAddresses(values []net.Addr) []*antiflockv1.NetworkAddress {
	result := make([]*antiflockv1.NetworkAddress, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		ip, network, err := net.ParseCIDR(value.String())
		if err != nil || ip == nil || network == nil {
			continue
		}
		ones, _ := network.Mask.Size()
		family := "ipv6"
		if ip.To4() != nil {
			ip = ip.To4()
			family = "ipv4"
		}
		key := ip.String() + "/" + strconv.Itoa(ones)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, &antiflockv1.NetworkAddress{Address: ip.String(), PrefixLength: uint32(ones), AddressFamily: family})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Address == result[right].Address {
			return result[left].PrefixLength < result[right].PrefixLength
		}
		return result[left].Address < result[right].Address
	})
	return result
}

func parseRoutes(content []byte, observedAt time.Time, includeNonDefault bool) ([]*antiflockv1.RouteObservation, error) {
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "Destination") {
		return nil, errors.New("route table header is missing")
	}
	result := make([]*antiflockv1.RouteObservation, 0)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 8 {
			return nil, errors.New("route table row is incomplete")
		}
		destination, err := decodeLittleEndianIPv4(fields[1])
		if err != nil {
			return nil, err
		}
		gateway, err := decodeLittleEndianIPv4(fields[2])
		if err != nil {
			return nil, err
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			return nil, errors.New("route table flags are invalid")
		}
		metric, err := strconv.ParseUint(fields[6], 10, 32)
		if err != nil {
			return nil, errors.New("route table metric is invalid")
		}
		maskIP, err := decodeLittleEndianIPv4(fields[7])
		if err != nil {
			return nil, err
		}
		prefix, bits := net.IPMask(maskIP.To4()).Size()
		if bits != 32 || prefix < 0 {
			return nil, errors.New("route table mask is not contiguous")
		}
		isDefault := destination.Equal(net.IPv4zero) && prefix == 0
		if flags&0x1 == 0 || (!includeNonDefault && !isDefault) {
			continue
		}
		interfaceID := opaqueInterfaceID(0, fields[0])
		item := &antiflockv1.RouteObservation{
			Destination: destination.String() + "/" + strconv.Itoa(prefix), Gateway: gateway.String(),
			InterfaceId: interfaceID, Metric: uint32(metric), DefaultRoute: isDefault,
			ObservedAt: timestamppb.New(observedAt),
		}
		item.RouteId = stableID("route", fields[0], item.Destination, item.Gateway, strconv.FormatUint(metric, 10))
		result = append(result, item)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].RouteId < result[right].RouteId })
	return result, nil
}

func parseDNS(content []byte, observedAt time.Time, includeSearch bool) (*antiflockv1.DnsObservation, error) {
	result := &antiflockv1.DnsObservation{Source: "resolv.conf", PathVerified: false, ObservedAt: timestamppb.New(observedAt)}
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) != 2 {
				return nil, errors.New("nameserver entry is malformed")
			}
			ip := net.ParseIP(fields[1])
			if ip == nil {
				return nil, errors.New("nameserver address is invalid")
			}
			result.ResolverAddresses = append(result.ResolverAddresses, ip.String())
		case "search", "domain":
			if !includeSearch {
				continue
			}
			for _, domain := range fields[1:] {
				if len(domain) == 0 || len(domain) > 253 || strings.ContainsAny(domain, "\x00/\\") {
					return nil, errors.New("search domain is invalid")
				}
				result.SearchDomains = append(result.SearchDomains, strings.ToLower(domain))
			}
		}
	}
	sort.Strings(result.ResolverAddresses)
	result.ResolverAddresses = compactStrings(result.ResolverAddresses)
	sort.Strings(result.SearchDomains)
	result.SearchDomains = compactStrings(result.SearchDomains)
	return result, nil
}

func decodeLittleEndianIPv4(value string) (net.IP, error) {
	bytes, err := hex.DecodeString(value)
	if err != nil || len(bytes) != net.IPv4len {
		return nil, errors.New("route table IPv4 value is invalid")
	}
	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0]).To4(), nil
}

func opaqueInterfaceID(_ int, name string) string {
	// Linux route metadata identifies an interface by name while net.Interfaces
	// also exposes an ephemeral index. Using only the local name keeps references
	// consistent without publishing a hardware address.
	return stableID("if", name)
}

func stableID(prefix string, values ...string) string {
	hasher := sha256.New()
	hasher.Write([]byte("AntiFlock-Local-ID-v1\x00" + prefix))
	for _, value := range values {
		hasher.Write([]byte{0})
		hasher.Write([]byte(value))
	}
	return prefix + "_" + hex.EncodeToString(hasher.Sum(nil)[:12])
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func assignSnapshotID(snapshot *antiflockv1.ObservationSnapshot) error {
	view := proto.Clone(snapshot).(*antiflockv1.ObservationSnapshot)
	view.SnapshotId = ""
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	if err != nil {
		return fmt.Errorf("encode observation snapshot: %w", err)
	}
	digest := sha256.Sum256(encoded)
	snapshot.SnapshotId = "snapshot_" + hex.EncodeToString(digest[:16])
	return nil
}

// Observation is the queue-ready event input emitted by a collector. Payload
// is deterministic protobuf metadata, never packet or application content.
type Observation struct {
	Kind           string
	ObservedAt     time.Time
	Classification model.EvidenceClass
	Confidence     float32
	Sensitivity    model.Sensitivity
	Payload        proto.Message
	Evidence       []model.EvidenceReference
}

// Observations projects a collection into the canonical event-kind payloads.
func (collection *Collection) Observations() []Observation {
	if collection == nil || collection.Snapshot == nil || collection.Snapshot.ObservedAt == nil {
		return nil
	}
	observedAt := collection.Snapshot.ObservedAt.AsTime().UTC()
	result := make([]Observation, 0, len(collection.Snapshot.Interfaces)+len(collection.Snapshot.Routes)+len(collection.Snapshot.Flows)+1)
	appendObservation := func(kind string, payload proto.Message) {
		result = append(result, Observation{
			Kind: kind, ObservedAt: observedAt, Classification: model.EvidenceDetected,
			Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate, Payload: payload,
		})
	}
	for _, item := range collection.Snapshot.Interfaces {
		appendObservation("network.interface_changed", proto.Clone(item))
	}
	for _, item := range collection.Snapshot.Routes {
		appendObservation("network.route_changed", proto.Clone(item))
	}
	if collection.Snapshot.Dns != nil {
		appendObservation("network.dns_changed", proto.Clone(collection.Snapshot.Dns))
	}
	for _, item := range collection.Snapshot.Flows {
		appendObservation("flow.updated", proto.Clone(item))
	}
	return result
}

// EventSigner signs the canonical source event. Production implementations
// must use the enrolled node key and the deterministic event signing profile.
type EventSigner interface {
	Sign(*model.EventEnvelope) error
}

// EventSignerFunc adapts a signing function to EventSigner.
type EventSignerFunc func(*model.EventEnvelope) error

func (function EventSignerFunc) Sign(event *model.EventEnvelope) error { return function(event) }

// SequenceSource must durably allocate a monotonic per-node sequence. Gaps are
// permitted and visible; reuse is not.
type SequenceSource interface {
	NextSequence(context.Context) (uint64, error)
}

// QueuePriority lets a bounded offline queue retain security-state events
// before ordinary observation metadata under pressure.
type QueuePriority uint8

const (
	QueuePriorityObservation QueuePriority = iota + 1
	QueuePrioritySecurityState
)

// EventQueue is the durable offline boundary. Enqueue must persist the signed
// envelope before returning success.
type EventQueue interface {
	Enqueue(context.Context, *antiflockv1.EventEnvelope, QueuePriority) error
}

// TelemetryBuilder deterministically builds signed source envelopes before
// they enter an offline queue.
type TelemetryBuilder struct {
	deploymentID string
	nodeID       string
	bootID       string
	clock        func() time.Time
	sequences    SequenceSource
	signer       EventSigner
}

func NewTelemetryBuilder(deploymentID, nodeID, bootID string, sequences SequenceSource, signer EventSigner, clock func() time.Time) (*TelemetryBuilder, error) {
	if strings.TrimSpace(deploymentID) == "" || strings.TrimSpace(nodeID) == "" || strings.TrimSpace(bootID) == "" || sequences == nil || signer == nil {
		return nil, errors.New("telemetry builder requires deployment, node, boot, sequence, and signer")
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &TelemetryBuilder{deploymentID: deploymentID, nodeID: nodeID, bootID: bootID, sequences: sequences, signer: signer, clock: clock}, nil
}

// Build creates and validates one signed event. It never upgrades the supplied
// evidence class; VERIFIED still requires real supporting provenance.
func (builder *TelemetryBuilder) Build(ctx context.Context, observation Observation) (*antiflockv1.EventEnvelope, QueuePriority, error) {
	if builder == nil {
		return nil, 0, errors.New("telemetry builder is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if !observation.Classification.Valid() || !observation.Sensitivity.Valid() || observation.ObservedAt.IsZero() ||
		math.IsNaN(float64(observation.Confidence)) || math.IsInf(float64(observation.Confidence), 0) || observation.Confidence < 0 || observation.Confidence > 1 ||
		observation.Payload == nil || !observation.Payload.ProtoReflect().IsValid() {
		return nil, 0, errors.New("observation metadata is incomplete or invalid")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(observation.Payload)
	if err != nil {
		return nil, 0, fmt.Errorf("encode observation payload: %w", err)
	}
	sequence, err := builder.sequences.NextSequence(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("allocate event sequence: %w", err)
	}
	if sequence == 0 {
		return nil, 0, errors.New("sequence source returned zero")
	}
	typeURL := "type.googleapis.com/" + string(observation.Payload.ProtoReflect().Descriptor().FullName())
	event := model.EventEnvelope{
		SchemaVersion: "antiflock.event/v1", DeploymentID: builder.deploymentID, NodeID: builder.nodeID,
		Kind: observation.Kind, ObservedAt: observation.ObservedAt.UTC(), Sequence: sequence, BootID: builder.bootID,
		Classification: observation.Classification, Confidence: observation.Confidence, Sensitivity: observation.Sensitivity,
		PayloadTypeURL: typeURL, Payload: payload, Evidence: append([]model.EvidenceReference(nil), observation.Evidence...),
	}
	event.ID = eventID(event)
	if err := model.ValidateEvidenceAt(event, builder.clock().UTC()); err != nil {
		return nil, 0, fmt.Errorf("validate event evidence: %w", err)
	}
	immutableDigest, err := immutableEventDigest(event)
	if err != nil {
		return nil, 0, err
	}
	if err := builder.signer.Sign(&event); err != nil {
		return nil, 0, fmt.Errorf("sign event: %w", err)
	}
	signedImmutableDigest, err := immutableEventDigest(event)
	if err != nil || immutableDigest != signedImmutableDigest {
		return nil, 0, errors.New("event signer changed immutable source content")
	}
	if event.SourceSignature.KeyID != builder.nodeID {
		return nil, 0, errors.New("event signer used a key outside the node identity")
	}
	if err := model.ValidateEvidenceAt(event, builder.clock().UTC()); err != nil {
		return nil, 0, fmt.Errorf("validate signed event evidence: %w", err)
	}
	if err := event.Validate(); err != nil {
		return nil, 0, fmt.Errorf("validate signed event: %w", err)
	}
	wire, err := model.EventToProto(event)
	if err != nil {
		return nil, 0, fmt.Errorf("encode signed event: %w", err)
	}
	return wire, priorityForKind(observation.Kind), nil
}

func immutableEventDigest(event model.EventEnvelope) ([sha256.Size]byte, error) {
	event.PayloadDigest = model.IntegrityDigest{}
	event.SourceSignature = model.Signature{}
	encoded, err := json.Marshal(event)
	if err != nil {
		return [sha256.Size]byte{}, errors.New("encode immutable event content")
	}
	return sha256.Sum256(encoded), nil
}

// BuildAndEnqueue persists a signed envelope through the caller's offline
// queue. It returns only after the queue confirms persistence.
func (builder *TelemetryBuilder) BuildAndEnqueue(ctx context.Context, queue EventQueue, observation Observation) (*antiflockv1.EventEnvelope, error) {
	if queue == nil {
		return nil, errors.New("offline event queue is required")
	}
	event, priority, err := builder.Build(ctx, observation)
	if err != nil {
		return nil, err
	}
	if err := queue.Enqueue(ctx, event, priority); err != nil {
		return nil, fmt.Errorf("enqueue signed event: %w", err)
	}
	return event, nil
}

func priorityForKind(kind string) QueuePriority {
	for _, prefix := range []string{"policy.", "posture.", "finding.", "action.", "scrambler."} {
		if strings.HasPrefix(kind, prefix) {
			return QueuePrioritySecurityState
		}
	}
	switch kind {
	case "node.enrolled", "node.suspended", "node.revoked":
		return QueuePrioritySecurityState
	default:
		return QueuePriorityObservation
	}
}

func eventID(event model.EventEnvelope) string {
	hasher := sha256.New()
	fmt.Fprintf(hasher, "AntiFlock-Event-ID-v1\x00%s\x00%s\x00%s\x00%d\x00%s\x00", event.DeploymentID, event.NodeID, event.BootID, event.Sequence, event.Kind)
	hasher.Write(event.Payload)
	return "event_" + hex.EncodeToString(hasher.Sum(nil)[:16])
}
