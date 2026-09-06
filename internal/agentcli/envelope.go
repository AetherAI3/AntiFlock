package agentcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Exit codes are the public contract documented in docs/exit-codes.md.
const (
	ExitOK           = 0
	ExitFailure      = 1
	ExitUsage        = 2
	ExitPrecondition = 3
	ExitVerification = 4
	ExitNotReady     = 5
	ExitRefused      = 6
	ExitDegraded     = 7
)

// Document is the stable schema identifier carried by every JSON envelope.
const Document = "antiflock.agent-cli/v1"

// Reason is one machine-readable explanation of an outcome.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Envelope is the single output shape shared by every command.
type Envelope struct {
	Document string   `json:"document"`
	Command  string   `json:"command"`
	OK       bool     `json:"ok"`
	ExitCode int      `json:"exit_code"`
	Reasons  []Reason `json:"reasons"`
	Result   any      `json:"result"`
}

// NewEnvelope builds an envelope whose ok flag is derived from the exit code.
// A non-zero exit code is never reported as ok.
func NewEnvelope(command string, exitCode int, result any, reasons ...Reason) Envelope {
	if reasons == nil {
		reasons = []Reason{}
	}
	return Envelope{Document: Document, Command: command, OK: exitCode == ExitOK, ExitCode: exitCode, Reasons: reasons, Result: result}
}

// Fail is the shorthand for an envelope without a result payload.
func Fail(command string, exitCode int, code, message string) Envelope {
	if exitCode == ExitOK {
		exitCode = ExitFailure
	}
	return NewEnvelope(command, exitCode, map[string]any{}, Reason{Code: code, Message: message})
}

// Usage is the shorthand for exit code 2.
func Usage(command, message string) Envelope {
	return Fail(command, ExitUsage, "AF-CLI-USAGE", message)
}

// WriteJSON encodes the envelope as one indented JSON document. HTML escaping
// is disabled so paths and URLs round-trip; every string inside the envelope
// is still JSON-escaped, so untrusted text cannot break the document.
func WriteJSON(writer io.Writer, envelope Envelope, compact bool) error {
	if writer == nil {
		return errors.New("envelope writer is required")
	}
	if envelope.Reasons == nil {
		envelope.Reasons = []Reason{}
	}
	if envelope.Result == nil {
		envelope.Result = map[string]any{}
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if !compact {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(envelope); err != nil {
		return errors.New("write agent cli envelope")
	}
	return nil
}

// WriteHumanHeader prints the common human prefix: command, outcome, reasons.
// Callers append command-specific lines after it.
func WriteHumanHeader(writer io.Writer, envelope Envelope) {
	state := "ok"
	if !envelope.OK {
		state = "failed"
	}
	fmt.Fprintf(writer, "antiflock-agent %s: %s (exit %d)\n", envelope.Command, state, envelope.ExitCode)
	for _, reason := range envelope.Reasons {
		fmt.Fprintf(writer, "  %s: %s\n", reason.Code, Safe(reason.Message))
	}
}

// Safe renders a possibly untrusted string for a human terminal line. It is
// identity for plain printable ASCII and otherwise a Go-quoted ASCII literal,
// so control characters and terminal escapes never reach the terminal raw.
func Safe(value string) string {
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return strconv.QuoteToASCII(value)
		}
	}
	return value
}
