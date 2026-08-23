// Package trust is the metadata and taint firewall for AntiFlock.
//
// Every string that enters the agent or Core from outside the process is
// data. Plan descriptions, dry-run text, capability metadata, node labels,
// provider and git metadata, tool and model output, imported findings,
// witness responses, and log lines are all carried in an Envelope that
// tracks five independent dimensions:
//
//   - Origin: where the bytes came from.
//   - Authenticity: what a signature or local observation proves about them.
//   - EvidenceClass: how a claim made by the bytes is known (proto vocabulary).
//   - ControlClass: always DataOnly. An envelope can never grant capability.
//   - Taint: what hostile shapes were found in the bytes.
//
// The dimensions never collapse into each other. A valid signature sets
// Authenticity and nothing else: it proves provenance and integrity of the
// bytes, not that the bytes are safe to display, safe to parse, fresh, or
// permitted to instruct anything. Instruction-shaped text stays quoted data.
//
// Contract for importers:
//
//	env := trust.Wrap(trust.OriginPlan, trust.Unauthenticated, description, trust.WrapOptions{})
//	fmt.Fprintln(w, env.Text())          // terminal/JSON safe rendering
//	if env.Taint.Has(trust.TaintContainsInstructionLike) { ... }   // observe, do not obey
//	env = env.WithAuthenticity(trust.SignatureValid)                // taint unchanged
//
// Rendering (Render, QuoteForTerminal, SafeLabel) is idempotent and never
// emits a byte below 0x20 other than newline, never 0x7f, and under an ASCII
// policy never a byte at or above 0x80. BoundedJSON walks JSON with explicit
// limits before any caller unmarshals it. Freshness and SeenSet detect stale
// and replayed receipts. Nothing in this package executes, authorizes, or
// blocks; it only labels. Callers decide policy from the labels.
//
// The package depends on the standard library only. See docs/trust-envelope.md.
package trust
