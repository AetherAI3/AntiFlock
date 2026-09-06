# antiflock-agent exit codes and output contract

This is the contract for every product command of `antiflock-agent`
(`init`, `doctor`, `status`, `enroll --config`, `observe --config`,
`plan simulate`, `plan readiness`, `update`, `uninstall`, `version`).
The codes are a closed set; scripts may switch on them. Changing a code's
meaning is a breaking change under `docs/release-policy.md`.

## Exit codes

| Code | Meaning | Typical producers |
| --- | --- | --- |
| `0` | Success. Every check the command made passed or was not applicable. | `init`, `status` with key and queue usable, `update --check` when current, `uninstall` dry run |
| `1` | Generic failure: an I/O or network error the command could not classify. | `enroll` when Core is unreachable, `update` when a rename fails |
| `2` | Usage: unknown flag, missing required flag, positional argument, invalid config value given on the command line. | every command |
| `3` | Precondition failure: the host or layout is not usable (config missing or invalid, key missing, directory permissions wrong, `doctor` reports at least one `FAIL`). | `doctor`, `status`, `enroll`, `uninstall` |
| `4` | Verification failure: a signed or hashed input did not verify (release manifest invalid, candidate checksum does not match, plan invalid). | `update`, future `plan verify` |
| `5` | Not ready: the capability, driver, or recovery path the command needs is not present in this binary, or the operator has not yet approved something. | `plan simulate`, `plan readiness`, `enroll` while pending approval |
| `6` | Refused: a policy or safety boundary stopped the command before it changed anything. | `uninstall` when a path escapes the configured directories, `update` when the target is not a regular file, `init` when the config exists without `--force`, `enroll` denied or expired |
| `7` | Partial or degraded: the command completed but reported at least one `WARN` or a missing component. | `doctor` with warnings only, `status` with a missing key or queue, `update --check` when an update is available |

Rules:

- A non-zero code is never reported as `"ok": true`.
- `doctor` exits `3` if any check is `FAIL`, `7` if the worst status is
  `WARN`, `0` otherwise. `UNKNOWN` never changes the exit code on its own.
- `update --check` uses `7` for "update available" so a cron job can
  distinguish "current" (`0`) from "needs attention" without parsing JSON.
- The legacy flag-only forms (`observe --node-id ...`, `enroll --core-url ...`,
  `status --node-id ...`, `plan verify ...`) keep their existing `0`/`1`
  behaviour. They are dispatched by `main.go`, not by the registry.

## JSON envelope

Every product command accepts `--json` (and `--compact`). The document is:

```json
{
  "document": "antiflock.agent-cli/v1",
  "command": "doctor",
  "ok": false,
  "exit_code": 7,
  "reasons": [
    { "code": "AF-DOCTOR-NFT-MISSING", "message": "nft is not installed" }
  ],
  "result": { }
}
```

- `document` is constant. A consumer must reject any other value.
- `command` is the command name (`"plan simulate"` for subcommands).
- `ok` is `exit_code == 0`.
- `reasons` is always an array (possibly empty) of `{code, message}`.
  Codes are stable identifiers of the form `AF-<COMMAND>-<WHAT>`; messages
  are safe prose and may change between releases.
- `result` is always an object. Its shape is per command and documented in
  `docs/agent-lifecycle.md`. It never contains key material, tokens,
  certificate bodies, queued telemetry, or raw command output.

Human output (the default) prints the same envelope header
(`antiflock-agent <command>: ok|failed (exit N)` followed by the reasons)
and then command-specific lines. Untrusted strings are quoted with
Go-style ASCII escaping before they reach the terminal.

## Reason code namespaces

| Prefix | Command |
| --- | --- |
| `AF-CLI-*` | registry and usage (`AF-CLI-USAGE`, `AF-CLI-NOT-AVAILABLE-YET`) |
| `AF-INIT-*` | `init` |
| `AF-DOCTOR-*` | `doctor` checks |
| `AF-STATUS-*` | `status` (including `AF-STATUS-DRIVER-NOT-WIRED`) |
| `AF-ENROLL-*` | `enroll --config` |
| `AF-UPDATE-*` | `update` |
| `AF-UNINSTALL-*` | `uninstall` |

## Output redaction

Both stdout and stderr of every registry command pass through a redacting
writer (`internal/agentcli/log.go`). It masks `Authorization` headers, bearer
tokens, `token=`/`secret=`/`password=`/`api_key=`/`seed=` pairs, well-known
token prefixes, and PEM private-key blocks, line by line, buffering partial
lines so a secret split across writes is still masked. Hex digests are not
masked because checksums are part of the update contract.
