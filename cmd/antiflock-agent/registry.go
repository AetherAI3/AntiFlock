package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

// commandIO is the output pair handed to every registered command. Both
// writers are wrapped in a redacting writer by dispatch, so commands may
// print freely and still never leak a token or key.
type commandIO struct {
	stdout io.Writer
	stderr io.Writer
}

// command is one self-registering product command. run returns the process
// exit code per docs/exit-codes.md. accepts, when set, lets a command
// decline an argument vector so the legacy dispatcher in main.go handles it
// (plan verify stays owned by plan.go).
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, out commandIO) int
	accepts func(args []string) bool
}

// commands is the registry. Commands register from init() in commands_*.go.
// main.go wires it with one line:
//
//	if code, ok := dispatch(context.Background(), os.Args[1:], os.Stdout, os.Stderr); ok { os.Exit(code) }
var commands = map[string]command{}

func register(c command) {
	if strings.TrimSpace(c.name) == "" || c.run == nil {
		panic("agent command registration requires a name and a run function")
	}
	if _, exists := commands[c.name]; exists {
		panic("agent command registered twice: " + c.name)
	}
	commands[c.name] = c
}

// dispatch routes args[0] to a registered command. It reports false when no
// registered command claims the arguments, so the caller can fall through to
// its own dispatcher.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) (int, bool) {
	if ctx == nil || len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return 0, false
	}
	c, ok := commands[args[0]]
	if !ok || (c.accepts != nil && !c.accepts(args[1:])) {
		return 0, false
	}
	out := agentcli.NewRedactingWriter(stdout)
	errOut := agentcli.NewRedactingWriter(stderr)
	code := c.run(ctx, args[1:], commandIO{stdout: out, stderr: errOut})
	_ = out.Flush()
	_ = errOut.Flush()
	return code, true
}

// commandNames lists registered commands in stable order for help text.
func commandNames() []string {
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// outputFlags are shared by every registered command.
type outputFlags struct {
	json    bool
	compact bool
}

func newFlagSet(name string, out commandIO, output *outputFlags) *flag.FlagSet {
	flags := flag.NewFlagSet("antiflock-agent "+name, flag.ContinueOnError)
	flags.SetOutput(out.stderr)
	flags.BoolVar(&output.json, "json", false, "write the antiflock.agent-cli/v1 JSON envelope instead of human text")
	flags.BoolVar(&output.compact, "compact", false, "compact JSON (with --json)")
	return flags
}

// parseFlags parses and maps flag errors to exit code 2; help is also 2 but
// prints usage without an error line.
func parseFlags(flags *flag.FlagSet, args []string, out commandIO) (int, bool) {
	if err := flags.Parse(args); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(out.stderr, "usage error; see --help")
		}
		return agentcli.ExitUsage, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(out.stderr, "%s accepts flags only\n", flags.Name())
		return agentcli.ExitUsage, false
	}
	return 0, true
}

// emit writes the envelope as JSON or as human text and returns its exit code.
func emit(out commandIO, output outputFlags, envelope agentcli.Envelope, human func(w io.Writer)) int {
	if output.json {
		if err := agentcli.WriteJSON(out.stdout, envelope, output.compact); err != nil {
			fmt.Fprintln(out.stderr, err)
			return agentcli.ExitFailure
		}
		return envelope.ExitCode
	}
	agentcli.WriteHumanHeader(out.stdout, envelope)
	if human != nil {
		human(out.stdout)
	}
	return envelope.ExitCode
}
