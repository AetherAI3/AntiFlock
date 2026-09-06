// Package hostile holds failing-first security fixtures for AntiFlock's
// parsers, loaders, signature verifiers, and request decoders.
//
// Every test states one invariant and the reason code or error the production
// code must produce. A test that documents behavior main does not have yet is
// skipped with t.Skip("KNOWN-GAP AF-GAP-nnn: ...") and the gap is listed, with
// its owner lane, in docs/adversarial-qualification.md. Acceptance gate 11
// fails the build when a skip lacks a gap id or a file has no live test, so a
// gap can never be hidden by skipping.
//
// Nothing in this package touches the developer host: every input is an
// in-memory literal or a file under t.TempDir(), every network call is served
// by httptest, and no privileged tool is executed.
package hostile
