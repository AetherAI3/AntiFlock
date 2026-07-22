package enforcement

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

type recordingNftRunner struct {
	mu       sync.Mutex
	commands []NftablesCommand
}

func (runner *recordingNftRunner) Run(_ context.Context, executable string, arguments []string, input []byte) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.commands = append(runner.commands, NftablesCommand{
		Executable: executable, Arguments: append([]string(nil), arguments...), Input: string(append([]byte(nil), input...)),
	})
	return nil
}

func (runner *recordingNftRunner) Commands() []NftablesCommand {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]NftablesCommand(nil), runner.commands...)
}

func TestNftablesDryRunRendersIsolatedFailClosedRecoveryTable(t *testing.T) {
	t.Parallel()
	adapter, err := NewNftablesAdapter(&recordingNftRunner{}, NftablesConfig{})
	if err != nil {
		t.Fatal(err)
	}
	command, err := adapter.DryRunApply(nftApplyOperation(t, []string{"198.51.100.8", "2001:db8::/64"}))
	if err != nil {
		t.Fatal(err)
	}
	if command.Executable != "nft" || !slices.Equal(command.Arguments, []string{"-f", "-"}) {
		t.Fatalf("command = %#v", command)
	}
	for _, required := range []string{
		"add table inet antiflock_guard", "policy drop", "recovery_v4", "198.51.100.8", "recovery_v6", "2001:db8::/64",
	} {
		if !strings.Contains(command.Input, required) {
			t.Fatalf("rendered batch is missing %q:\n%s", required, command.Input)
		}
	}
	if strings.Contains(command.Input, "203.0.113.10") {
		t.Fatal("ordinary allowed destination bypassed the pre-verification recovery hold")
	}
	if strings.Contains(command.Input, "established") {
		t.Fatal("pre-existing non-recovery flows bypassed the fail-closed hold")
	}
}

func TestNftablesApplyRequiresExplicitOptInAndRollbackOwnership(t *testing.T) {
	t.Parallel()
	operation := nftApplyOperation(t, []string{"198.51.100.8"})
	rollback := nftRollbackOperation(t)
	disabledRunner := &recordingNftRunner{}
	disabled, err := NewNftablesAdapter(disabledRunner, NftablesConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.Apply(context.Background(), operation); !errors.Is(err, ErrNftablesApplyDisabled) || len(disabledRunner.Commands()) != 0 {
		t.Fatalf("disabled apply = %v, commands = %#v", err, disabledRunner.Commands())
	}

	runner := &recordingNftRunner{}
	enabled, err := NewNftablesAdapter(runner, NftablesConfig{EnableApply: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enabled.Rollback(context.Background(), rollback); err == nil {
		t.Fatal("adapter deleted a table it did not own")
	}
	if result, err := enabled.Apply(context.Background(), operation); err != nil || !result.Succeeded {
		t.Fatalf("apply = %#v, %v", result, err)
	}
	if result, err := enabled.Rollback(context.Background(), rollback); err != nil || !result.Succeeded {
		t.Fatalf("rollback = %#v, %v", result, err)
	}
	commands := runner.Commands()
	if len(commands) != 2 || !strings.HasPrefix(commands[1].Input, "delete table inet antiflock_guard") {
		t.Fatalf("commands = %#v", commands)
	}
}

func TestNftablesRejectsHostnamesInjectionAndArbitraryCommands(t *testing.T) {
	t.Parallel()
	adapter, err := NewNftablesAdapter(&recordingNftRunner{}, NftablesConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"core.internal", "198.51.100.8; accept", "198.51.100.8\naccept"} {
		if _, err := adapter.DryRunApply(nftApplyOperation(t, []string{unsafe})); err == nil {
			t.Fatalf("unsafe recovery destination %q was accepted", unsafe)
		}
	}
	runner := NftablesExecRunner{}
	if err := runner.Run(context.Background(), "sh", []string{"-f", "-"}, []byte("add table inet test\n")); err == nil {
		t.Fatal("non-nft executable was accepted")
	}
	if err := runner.Run(context.Background(), "nft", []string{"list", "ruleset"}, []byte("ignored")); err == nil {
		t.Fatal("arbitrary nft arguments were accepted")
	}
}

func nftApplyOperation(t *testing.T, recovery []string) *antiflockv1.PlanOperation {
	t.Helper()
	parameters, err := structpb.NewStruct(map[string]any{
		"simulation": false, "failMode": "CLOSED",
		"allowedDestinations": []any{"203.0.113.10"}, "recoveryDestinations": stringValues(recovery),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &antiflockv1.PlanOperation{
		Id: "guard-egress", Type: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL,
		Target: "protected-egress", Parameters: parameters,
	}
}

func nftRollbackOperation(t *testing.T) *antiflockv1.PlanOperation {
	t.Helper()
	parameters, err := structpb.NewStruct(map[string]any{"simulation": false, "failMode": "CLOSED"})
	if err != nil {
		t.Fatal(err)
	}
	return &antiflockv1.PlanOperation{
		Id: "rollback-firewall", Type: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL,
		Target: "captured:firewall", Parameters: parameters,
	}
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
