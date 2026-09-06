// Package agentcli holds the pure, testable command logic behind the
// antiflock-agent product CLI (init, enroll, doctor, status, update,
// uninstall, version).
//
// Contract (see docs/exit-codes.md and docs/agent-lifecycle.md):
//
//   - Every command returns an Envelope. The JSON form is the stable document
//     "antiflock.agent-cli/v1": {document, command, ok, exit_code, reasons,
//     result}. Human output is derived from the same envelope.
//   - Exit codes are the closed set in this package: 0 ok, 1 generic failure,
//     2 usage, 3 precondition/doctor failure, 4 verification failure, 5 not
//     ready, 6 refused, 7 partial/degraded.
//   - Reasons are stable machine codes ("AF-<COMMAND>-<WHAT>") with a safe
//     message. Messages never embed raw command output, secrets, or
//     unescaped untrusted text; identifiers from the host are quoted with
//     strconv.QuoteToASCII before they reach a human line.
//   - Nothing in this package mutates host network state. The only
//     mutations are inside the operator-configured agent directories
//     (init, update, uninstall) and each of those has a containment check.
//   - Host probes (doctor) go through an injected Environment so tests never
//     execute nft, ip, or systemd tooling.
package agentcli
