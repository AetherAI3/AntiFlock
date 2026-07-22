package enforcement

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

var ErrNftablesApplyDisabled = errors.New("nftables apply is disabled")

// NftablesRunner is the explicit privileged-process boundary. Implementations
// receive a prevalidated nft batch on stdin and must never invoke a shell.
type NftablesRunner interface {
	Run(context.Context, string, []string, []byte) error
}

// NftablesExecRunner invokes exactly nft -f -. It discards command output so
// provider or host details cannot be copied into safe API messages.
type NftablesExecRunner struct{}

func (NftablesExecRunner) Run(ctx context.Context, executable string, arguments []string, input []byte) error {
	if !isNftExecutable(executable) || !slicesEqual(arguments, []string{"-f", "-"}) || len(input) == 0 || len(input) > 64*1024 {
		return errors.New("nftables runner rejected an unsupported command")
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = bytes.NewReader(input)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errors.New("nftables transaction failed")
	}
	return nil
}

type NftablesConfig struct {
	Executable  string
	TableName   string
	EnableApply bool
}

// NftablesCommand is a reviewable, shell-free dry run. Arguments and input are
// passed separately to the executor.
type NftablesCommand struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
	Input      string   `json:"input"`
}

// NftablesAdapter renders an isolated fail-closed output table. It never
// flushes or replaces an existing table. Rollback deletes only a table that
// this adapter instance successfully created.
type NftablesAdapter struct {
	runner      NftablesRunner
	executable  string
	tableName   string
	enableApply bool
	mu          sync.Mutex
	ownsTable   bool
}

func NewNftablesAdapter(runner NftablesRunner, config NftablesConfig) (*NftablesAdapter, error) {
	if runner == nil {
		return nil, errors.New("nftables runner is required")
	}
	if config.Executable == "" {
		config.Executable = "nft"
	}
	if config.TableName == "" {
		config.TableName = "antiflock_guard"
	}
	if !isNftExecutable(config.Executable) || !validNftIdentifier(config.TableName) {
		return nil, errors.New("nftables executable or table name is invalid")
	}
	return &NftablesAdapter{
		runner: runner, executable: config.Executable, tableName: config.TableName, enableApply: config.EnableApply,
	}, nil
}

// DryRunApply renders the only supported firewall action. Recovery entries
// must be literal IP addresses or CIDRs; hostnames require a separately
// verified resolver-to-address preparation step and therefore fail closed.
func (adapter *NftablesAdapter) DryRunApply(operation *antiflockv1.PlanOperation) (NftablesCommand, error) {
	if adapter == nil || operation == nil || operation.Id != "guard-egress" ||
		operation.Type != antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL || operation.Target != "protected-egress" {
		return NftablesCommand{}, errors.New("nftables adapter supports only the signed guard-egress action")
	}
	if !exactFields(operation.Parameters, "simulation", "failMode", "allowedDestinations", "recoveryDestinations") {
		return NftablesCommand{}, errors.New("nftables action parameters are incomplete or unsupported")
	}
	simulation, simulationOK := boolField(operation.Parameters, "simulation")
	failMode, failModeOK := stringField(operation.Parameters, "failMode")
	_, allowedOK := stringListField(operation.Parameters, "allowedDestinations", 0, 32, 512)
	recovery, recoveryOK := stringListField(operation.Parameters, "recoveryDestinations", 1, 32, 512)
	if !simulationOK || simulation || !failModeOK || failMode != "CLOSED" || !allowedOK || !recoveryOK {
		return NftablesCommand{}, errors.New("nftables action does not request the supported fail-closed mode")
	}
	ipv4, ipv6, err := literalNetworks(recovery)
	if err != nil {
		return NftablesCommand{}, err
	}
	input := renderGuardTable(adapter.tableName, ipv4, ipv6)
	return NftablesCommand{Executable: adapter.executable, Arguments: []string{"-f", "-"}, Input: input}, nil
}

func (adapter *NftablesAdapter) DryRunRollback(operation *antiflockv1.PlanOperation) (NftablesCommand, error) {
	if adapter == nil || operation == nil || operation.Id != "rollback-firewall" ||
		operation.Type != antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL || operation.Target != "captured:firewall" ||
		!exactFields(operation.Parameters, "simulation", "failMode") {
		return NftablesCommand{}, errors.New("nftables adapter supports only its signed firewall rollback")
	}
	simulation, simulationOK := boolField(operation.Parameters, "simulation")
	failMode, failModeOK := stringField(operation.Parameters, "failMode")
	if !simulationOK || simulation || !failModeOK || failMode != "CLOSED" {
		return NftablesCommand{}, errors.New("nftables rollback parameters are invalid")
	}
	input := fmt.Sprintf("delete table inet %s\n", adapter.tableName)
	return NftablesCommand{Executable: adapter.executable, Arguments: []string{"-f", "-"}, Input: input}, nil
}

// Apply crosses the nft process boundary only when EnableApply was explicitly
// set at construction. Dry-run rendering is always available.
func (adapter *NftablesAdapter) Apply(ctx context.Context, operation *antiflockv1.PlanOperation) (OperationObservation, error) {
	if adapter == nil {
		return OperationObservation{}, errors.New("nftables adapter is required")
	}
	command, err := adapter.DryRunApply(operation)
	if err != nil {
		return OperationObservation{}, err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if !adapter.enableApply {
		return OperationObservation{}, ErrNftablesApplyDisabled
	}
	if adapter.ownsTable {
		return OperationObservation{}, errors.New("nftables guard table is already owned by this adapter")
	}
	if err := adapter.runner.Run(ctx, command.Executable, command.Arguments, []byte(command.Input)); err != nil {
		return OperationObservation{}, err
	}
	adapter.ownsTable = true
	return OperationObservation{
		Succeeded: true, ReasonCode: "AF-NFTABLES-GUARD-APPLIED", SafeMessage: "The isolated nftables guard table was applied.",
	}, nil
}

// Rollback refuses to delete a table unless this process observed its own
// successful creation. Crash recovery requires a durable ownership record and
// is intentionally left to the agent state integration.
func (adapter *NftablesAdapter) Rollback(ctx context.Context, operation *antiflockv1.PlanOperation) (OperationObservation, error) {
	if adapter == nil {
		return OperationObservation{}, errors.New("nftables adapter is required")
	}
	command, err := adapter.DryRunRollback(operation)
	if err != nil {
		return OperationObservation{}, err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if !adapter.enableApply {
		return OperationObservation{}, ErrNftablesApplyDisabled
	}
	if !adapter.ownsTable {
		return OperationObservation{}, errors.New("nftables adapter will not delete an unowned table")
	}
	if err := adapter.runner.Run(ctx, command.Executable, command.Arguments, []byte(command.Input)); err != nil {
		return OperationObservation{}, err
	}
	adapter.ownsTable = false
	return OperationObservation{
		Succeeded: true, ReasonCode: "AF-NFTABLES-GUARD-ROLLED-BACK", SafeMessage: "The isolated nftables guard table was removed.",
	}, nil
}

func literalNetworks(values []string) ([]string, []string, error) {
	var ipv4, ipv6 []string
	for _, value := range values {
		canonical, family, err := literalNetwork(value)
		if err != nil {
			return nil, nil, errors.New("nftables recovery entries must be literal IP addresses or CIDRs")
		}
		if family == 4 {
			ipv4 = append(ipv4, canonical)
		} else {
			ipv6 = append(ipv6, canonical)
		}
	}
	sort.Strings(ipv4)
	sort.Strings(ipv6)
	return ipv4, ipv6, nil
}

func literalNetwork(value string) (string, int, error) {
	if ip := net.ParseIP(value); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), 4, nil
		}
		return ip.String(), 6, nil
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip == nil || network == nil || network.String() != value {
		return "", 0, errors.New("invalid literal network")
	}
	if ip.To4() != nil {
		return network.String(), 4, nil
	}
	return network.String(), 6, nil
}

func renderGuardTable(table string, ipv4, ipv6 []string) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "add table inet %s\n", table)
	fmt.Fprintf(&builder, "add chain inet %s output { type filter hook output priority -150; policy drop; }\n", table)
	fmt.Fprintf(&builder, "add rule inet %s output oifname \"lo\" accept\n", table)
	if len(ipv4) != 0 {
		fmt.Fprintf(&builder, "add set inet %s recovery_v4 { type ipv4_addr; flags interval; }\n", table)
		fmt.Fprintf(&builder, "add element inet %s recovery_v4 { %s }\n", table, strings.Join(ipv4, ", "))
		fmt.Fprintf(&builder, "add rule inet %s output ip daddr @recovery_v4 accept\n", table)
	}
	if len(ipv6) != 0 {
		fmt.Fprintf(&builder, "add set inet %s recovery_v6 { type ipv6_addr; flags interval; }\n", table)
		fmt.Fprintf(&builder, "add element inet %s recovery_v6 { %s }\n", table, strings.Join(ipv6, ", "))
		fmt.Fprintf(&builder, "add rule inet %s output ip6 daddr @recovery_v6 accept\n", table)
	}
	return builder.String()
}

func validNftIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func isNftExecutable(value string) bool {
	base := strings.ToLower(filepath.Base(value))
	return base == "nft" || base == "nft.exe"
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
