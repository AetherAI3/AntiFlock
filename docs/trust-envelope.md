# Trust envelope and taint model

Package: `internal/trust` (standard library only).

## First rule

Every string that enters the agent or Core from outside the running process is
data. It may be displayed, stored, digested, compared, and reasoned about. It
may never instruct, authorize, grant, or configure anything. This holds for
plan descriptions, dry-run text, capability metadata, node labels, provider
responses, git metadata, tool output, model output, imported findings, witness
responses, operator input, and log lines alike.

A signature proves provenance and integrity only. It says who produced the
bytes and that they were not altered. It says nothing about whether the bytes
are safe to print, safe to parse, fresh, or permitted to do anything.

## Five independent dimensions

An `Envelope` carries one external string and tracks five things separately.
They never collapse into one another.

| Dimension | Type | Values | What it answers |
| --- | --- | --- | --- |
| Origin | `Origin` | `PLAN`, `DRY_RUN`, `CAPABILITY_METADATA`, `NODE_LABEL`, `PROVIDER`, `GIT_METADATA`, `TOOL_OUTPUT`, `MODEL_OUTPUT`, `IMPORTED_FINDING`, `WITNESS_RESPONSE`, `LOG`, `OPERATOR_INPUT`, `UNKNOWN` | Where did the bytes come from? |
| Authenticity | `Authenticity` | `UNAUTHENTICATED`, `SIGNATURE_VALID`, `SIGNATURE_INVALID`, `LOCALLY_OBSERVED` | What does cryptography or local observation prove about the bytes? |
| Evidence class | `EvidenceClass` | `EVIDENCE_CLASS_UNSPECIFIED`, `..._DETECTED`, `..._VERIFIED`, `..._REPORTED`, `..._INFERRED`, `..._SUSPECTED`, `..._UNKNOWN` (identical numbers and names to `antiflock.v1.EvidenceClass`) | How is the claim the bytes make known? See `docs/evidence-model.md`. |
| Control class | `ControlClass` | `DATA_ONLY` (the only value) | Can the content confer authority? Never. |
| Taint | `Taint` bit set | `UNTRUSTED`, `CONTAINS_CONTROL_CHARS`, `CONTAINS_BIDI`, `CONTAINS_INSTRUCTION_LIKE`, `OVERSIZED`, `TRUNCATED`, `DUPLICATE_FIELDS`, `STALE`, `REPLAYED`, `SIGNED_BUT_UNAUTHORIZED` | What hostile shapes were found in the bytes or in their delivery? |

Plus `Digest` (`sha256:` + hex of the raw bytes), `SchemaVersion`,
`ParserVersion`, and `Payload` (raw bytes kept for parsers and digest checks,
plus the sanitized `Rendered` form that is the only thing ever printed).

### Why ControlClass has one value

Authority in AntiFlock comes from pinned keys, node-bound manifests, and
operator action, never from text. `ControlClass` exists so the question "can
this content grant anything?" is asked and answered in the type system.
`ControlClass` is an empty struct; every value equals `DataOnly`, and
`GrantsCapability()` returns `false` by construction rather than by a runtime
check that could be mutated. A future capability type must live in a
different package; this one cannot carry it.

### Taint is monotonic

Nothing in the package clears a taint bit. `WithAuthenticity` changes only
`Authenticity`; `WithTaint` only adds bits; `WithEvidenceClass` only replaces
the evidence class. `TaintUntrusted` is set on every envelope so a reader can
see that the classification happened. A mutation test confirms that letting
`SIGNATURE_VALID` clear `CONTAINS_INSTRUCTION_LIKE` fails both the unit test
and the corpus.

## Instruction-like text stays quoted data

`LooksInstructionLike` flags text shaped like an instruction to an operator or
a model: "ignore previous", "you are now", role markers (`system:`,
`assistant:`, `<|im_start|>`), shell markers (`sudo`, `nft `, `rm -rf`, code
fences), and authority words (`approve`, `grant`, `execute`, `override`).

The detector is deliberately liberal about what it flags and deliberately
powerless about what it does: the only effect of a hit is the advisory
`TaintContainsInstructionLike` bit. A plan description that says "approve" or
a commit message mentioning "sudo" will be flagged and will still render
exactly as written. Flagged or not, the text is `DataOnly`; it cannot grant
capability, change policy, or authorize execution. False negatives are
tolerated for the same reason. Callers that know the content is prose about
instructions (documentation) may set `WrapOptions.SkipInstructionScan`.

## Rendering rules

`Render(raw, policy)` produces `Rendered.Text`, which is safe for terminals
and for JSON:

- no byte below `0x20` except `\n`; no `0x7f`; under `ASCIIOnly`, no byte at
  or above `0x80`;
- CRLF becomes LF silently; a lone CR is a finding;
- NUL, other C0 controls, DEL, C1 controls, bidi overrides/embeddings/isolates
  and marks (U+202A..U+202E, U+2066..U+2069, U+200E, U+200F, U+061C),
  zero-width and other format runes (`Cf`, including BOM and soft hyphen),
  U+2028/U+2029, and invalid UTF-8 bytes are escaped as `\xNN`, `\uNNNN`, or
  `\UNNNNNNNN` (escape mode) or dropped (strip mode);
- ESC sequences, CSI, OSC (including OSC 8 hyperlinks and OSC 52 clipboard
  writes), DCS, SOS, PM, and APC are recognised as units in both 7-bit
  (`ESC x`) and 8-bit (U+009B, U+009D, U+0090, U+0098, U+009E, U+009F) form,
  terminated by BEL, `ESC \`, or U+009C, and escaped byte by byte or stripped
  whole; an unterminated string body is bounded at 1024 bytes;
- unassigned, surrogate, and private-use runes are escaped without a finding;
  non-ASCII spaces and all printable runes pass through under the UTF-8
  policy;
- output is capped at `MaxBytes` (default 4096, minimum 64) including the
  marker `…[truncated N bytes]`, where N counts input bytes not rendered and
  the ellipsis is itself escaped under `ASCIIOnly`; `TaintTruncated` marks a
  cut rendering and `TaintOversized` marks input longer than the cap;
- taints and findings are computed over the whole input, including the part
  beyond the cut.

`Render` is idempotent: rendering its own output changes nothing and reports
no taint. `Rendered.Findings` lists what was found (`CSI`, `OSC`, `BIDI`,
`FORMAT`, `NUL`, ...), which is how the corpus pins the parser.

Backslashes are not escaped, so the rendering is a display form, not an
invertible encoding. Use `Digest` and `Payload.Raw()` for identity and
parsing, never the rendered text.

Helpers:

- `QuoteForTerminal(s)`: always-ASCII, single-line, `strconv.QuoteToASCII`
  form without surrounding quotes. Matches the existing plan-verification
  output style.
- `SafeLabel(s, max)`: maps an identifier onto `[A-Za-z0-9._:-]`, replacing
  each disallowed rune with `_`, cutting to `max` bytes (default 128), and
  returning `_` for an empty result. `IsSafeLabel` is the predicate. This is
  the same allowlist as `safePlanToken` in plan verification.
- `Scan(s)`: the taint bits without rendering and without a cap.

## Bounded JSON

`BoundedJSON(raw, limits)` walks JSON with `encoding/json`'s streaming
tokenizer before any caller unmarshals it, enforcing byte size, nesting depth
(default 32), token count (default 100k), string length (default 64 KiB),
number literal length (default 64), duplicate keys per object, and trailing
content. It returns the taint set (`OVERSIZED`, `DUPLICATE_FIELDS`, plus the
control/bidi/instruction taints found inside string tokens) and a typed
`*JSONError` wrapping one of `ErrJSONOversized`, `ErrJSONDepth`,
`ErrJSONTokens`, `ErrJSONStringLength`, `ErrJSONNumberLength`,
`ErrJSONDuplicateKey`, `ErrJSONTrailing`, `ErrJSONMalformed`, `ErrJSONEmpty`.
Error text never echoes input bytes. The walk is iterative, so a 100k-deep
array costs a frame per level, not a stack frame.

## Freshness and replay

`Freshness.Check(digest, issuedAt, expiresAt, now, seen)` returns `STALE` when
the receipt is unissued, issued in the future beyond `Skew`, expired beyond
`Skew`, or older than `MaxAge`; and `REPLAYED` when `seen` already held the
digest. `CheckReceipt` applies one minute of skew. `SeenSet` is a bounded,
concurrency-safe set with least-recently-observed eviction; it is a detection
aid, not a durable replay registry, and every checked digest (stale ones
included) is recorded so a stale receipt cannot return as fresh after a clock
change.

## How callers should use it

```go
env := trust.Wrap(trust.OriginPlan, trust.Unauthenticated, plan.Description, trust.WrapOptions{})
// after signature verification:
env = env.WithAuthenticity(trust.SignatureValid)          // taint unchanged
if !bound.Matches(node) {
    env = env.WithTaint(trust.TaintSignedButUnauthorized)
}
fmt.Fprintf(w, "  description: %s\n", env.Text())          // or QuoteForTerminal(env.Text())
json.NewEncoder(w).Encode(env)                             // emits Summary: never raw bytes
```

| Source | Origin | Typical authenticity | Notes |
| --- | --- | --- | --- |
| Plan fields (description, ids) | `PLAN` | `SIGNATURE_VALID` after verification | Ids additionally go through `SafeLabel`/`IsSafeLabel`; the signature does not make a description printable. |
| `humanReadableDryRun` / dry-run text | `DRY_RUN` | inherits the plan's | Render before it reaches JSON or a terminal; today bidi/format runes pass raw through JSON output. |
| Capability manifest metadata | `CAPABILITY_METADATA` | `SIGNATURE_VALID` or `LOCALLY_OBSERVED` | `BoundedJSON` before unmarshal; duplicate keys are a rejection, not last-wins. |
| Node labels / hostnames | `NODE_LABEL` | `LOCALLY_OBSERVED` | `SafeLabel` for identifiers, `Render` for display strings. |
| Provider API responses | `PROVIDER` | `UNAUTHENTICATED` | `BoundedJSON` with tight limits; provider text is never an instruction. |
| Git metadata (commit messages, refs, author) | `GIT_METADATA` | `UNAUTHENTICATED` | OSC 8 links and bidi in commit text are the common hostile shapes. |
| Tool / command output | `TOOL_OUTPUT` | `LOCALLY_OBSERVED` | Structured output must carry `Text`, never raw bytes (hard rule 7). |
| Model output | `MODEL_OUTPUT` | `UNAUTHENTICATED` | Always `DataOnly`; the instruction detector is expected to fire often here. |
| Imported findings / intelligence packs | `IMPORTED_FINDING` | `SIGNATURE_VALID` for signed packs | Evidence class from the pack; taint from the bytes; neither implies the other. |
| Witness responses / receipts | `WITNESS_RESPONSE` | `SIGNATURE_VALID` | Add `Freshness.Check` results via `ExtraTaint` or `WithTaint`. |
| Logs | `LOG` | `LOCALLY_OBSERVED` | CRLF injection and cursor movement are the common hostile shapes. |
| Operator input | `OPERATOR_INPUT` | `LOCALLY_OBSERVED` | Still data; authority comes from the action the operator takes, not the text. |

Rules for importers:

1. Wrap at the boundary, as close to the read as possible, before the value
   is stored, logged, compared, or displayed.
2. Print `Text()` or `QuoteForTerminal(Text())`; encode the `Envelope` or its
   `Summary`; never print `Payload.Raw()`.
3. Parse `Payload.Raw()` only after `BoundedJSON` (or an equivalent bound for
   other formats) accepted it.
4. Treat `Taint` as an input to policy you own. The package never blocks.
5. Never derive a decision from `CONTAINS_INSTRUCTION_LIKE` being absent.

## Hostile corpus

`internal/trust/testdata/hostile/` holds the corpus as files with a
`manifest.json` index. Each entry names the fixture, origin, authenticity,
and the exact taints, finding kinds, rendered text, JSON errors, or receipt
verdicts the package must report. `corpus_test.go` loads every fixture
through `Wrap`/`Render`/`BoundedJSON`/`CheckReceipt`, asserts the manifest
expectations exactly, and additionally asserts on every rendering: the byte
invariant above, idempotence, digest correctness, `DataOnly`, that
`SIGNATURE_VALID` leaves taint untouched, and that JSON output does not
contain the raw hostile input. A test also fails if a fixture file is not
referenced by the manifest or vice versa.

Fixture groups: terminal escapes (CSI colour and cursor, OSC 8, OSC 52, DCS,
7-bit SOS/PM/APC/nF, 8-bit C1 introducers, bare ESC); bidirectional Unicode
(RLO in a plan description, LRO and isolates, a safe-looking filename,
legitimate RTL text that must not be flagged); nesting (depth 64, depth 1000,
deep mixed arrays, duplicate keys flat and nested, trailing content,
unterminated, oversized number, 70 KB string); signed malicious text (a JSON
document whose `description` is an instruction and whose `signature` field is
present; authenticity is irrelevant to taint); receipts (stale, replayed with
the same digest twice, future-dated); identifiers (zero-width joiners and BOM,
homoglyphs); raw (NUL-embedded, CRLF log injection, U+2028/U+2029 with tab
and DEL, BOM-first, invalid UTF-8, plain and zero-width-split instructions,
a benign control, a 1 MiB string).

`FuzzRender` and `FuzzBoundedJSON` seed from the corpus;
`TestRenderPropertiesDeterministic` drives 4000 fixed-seed hostile inputs
through seven policies. Hostile bytes live only in `testdata/`; Go sources
use escapes so static analysis does not reject them.
