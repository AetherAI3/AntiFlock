package collectors

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultTCPTable = "/proc/net/tcp"
	defaultTCP6Table = "/proc/net/tcp6"
	defaultUDPTable = "/proc/net/udp"
	defaultUDP6Table = "/proc/net/udp6"
	maximumFlowRecords = 2048
)

// flowTable describes a kernel socket table. It deliberately has no packet,
// byte-counter, inode, uid, or process-attribution fields.
type flowTable struct {
	path string
	protocol antiflockv1.TransportProtocol
	label string
}

func (collector *LinuxCollector) collectFlows(observedAt time.Time) ([]*antiflockv1.FlowObservation, []string) {
	tables := []flowTable{
		{path: collector.config.TCPTablePath, protocol: antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP, label: "tcp"},
		{path: collector.config.TCP6TablePath, protocol: antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP, label: "tcp"},
		{path: collector.config.UDPTablePath, protocol: antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP, label: "udp"},
		{path: collector.config.UDP6TablePath, protocol: antiflockv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP, label: "udp"},
	}
	flows := make([]*antiflockv1.FlowObservation, 0)
	reasons := make([]string, 0)
	for _, table := range tables {
		content, err := collector.config.Files.ReadFile(table.path)
		if err != nil { reasons = append(reasons, "AF-COLLECTOR-FLOW-UNAVAILABLE"); continue }
		if len(content) > maximumSourceSize { reasons = append(reasons, "AF-COLLECTOR-FLOW-OVERSIZED"); continue }
		values, err := parseProcSocketTable(content, table.protocol, table.label, observedAt, maximumFlowRecords-len(flows))
		if err != nil { reasons = append(reasons, "AF-COLLECTOR-FLOW-INVALID"); continue }
		flows = append(flows, values...)
		if len(flows) >= maximumFlowRecords { reasons = append(reasons, "AF-COLLECTOR-FLOW-LIMITED"); break }
	}
	sort.Strings(reasons)
	return flows, compactStrings(reasons)
}

func parseProcSocketTable(content []byte, protocol antiflockv1.TransportProtocol, label string, observedAt time.Time, limit int) ([]*antiflockv1.FlowObservation, error) {
	if limit < 0 { return nil, errors.New("flow record limit is invalid") }
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "local_address") { return nil, errors.New("socket table header is missing") }
	result := make([]*antiflockv1.FlowObservation, 0)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 { continue }
		if len(fields) < 4 { return nil, errors.New("socket table row is incomplete") }
		// 0A is LISTEN; a zero remote endpoint is an unconnected UDP socket.
		if fields[3] == "0A" { continue }
		local, err := parseProcEndpoint(fields[1]); if err != nil { return nil, err }
		remote, err := parseProcEndpoint(fields[2]); if err != nil { return nil, err }
		if remote.Address == "" || remote.Port == 0 || net.ParseIP(remote.Address).IsUnspecified() { continue }
		flow := &antiflockv1.FlowObservation{
			FlowId: stableID("flow", label, local.Address, strconv.FormatUint(uint64(local.Port), 10), remote.Address, strconv.FormatUint(uint64(remote.Port), 10)),
			Local: local, Remote: remote, Protocol: protocol, Direction: antiflockv1.FlowDirection_FLOW_DIRECTION_UNKNOWN,
			Process: &antiflockv1.ProcessReference{AttributionQuality: antiflockv1.ProcessAttributionQuality_PROCESS_ATTRIBUTION_QUALITY_UNAVAILABLE},
			Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_OPERATOR_PRIVATE,
		}
		result = append(result, flow)
		if len(result) >= limit { break }
	}
	sort.Slice(result, func(left, right int) bool { return result[left].FlowId < result[right].FlowId })
	return result, nil
}

func parseProcEndpoint(value string) (*antiflockv1.FlowEndpoint, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 { return nil, errors.New("socket endpoint is malformed") }
	raw, err := hex.DecodeString(parts[0]); if err != nil { return nil, errors.New("socket address is invalid") }
	var ip net.IP
	switch len(raw) {
	case net.IPv4len:
		ip = net.IPv4(raw[3], raw[2], raw[1], raw[0])
	case net.IPv6len:
		for index := 0; index < len(raw); index += 4 { raw[index], raw[index+3] = raw[index+3], raw[index]; raw[index+1], raw[index+2] = raw[index+2], raw[index+1] }
		ip = net.IP(raw)
	default:
		return nil, errors.New("socket address family is invalid")
	}
	port, err := strconv.ParseUint(parts[1], 16, 16); if err != nil { return nil, errors.New("socket port is invalid") }
	return &antiflockv1.FlowEndpoint{Address: ip.String(), Port: uint32(port)}, nil
}

// flowObservationTime documents that a kernel socket table is a current
// snapshot. It is intentionally not written into FlowObservation.started_at
// because the kernel table cannot prove the connection start time.
func flowObservationTime(value time.Time) *timestamppb.Timestamp { return timestamppb.New(value.UTC()) }

var _ = fmt.Sprintf
