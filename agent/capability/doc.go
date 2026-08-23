// Package capability replaces caller-asserted readiness with authenticated
// capability discovery for the AntiFlock agent.
//
// Trust chain (every arrow is a validation step, none may be skipped):
//
//	driver.Prober.Probe  ->  driver.ProbeResult.Validate  ->  ProbeResult.Digest
//	  ->  Manifest (node-bound, revisioned, bounded expiry)  ->  Manifest.Sign (node key)
//	  ->  LoadManifestFile (hardened open, bounded read, strict JSON, node binding,
//	      signature, expiry)  ->  Evaluate (per-requirement verdicts, fail closed)
//
// Contract:
//
//   - Discover runs explicitly registered probers under bounded timeouts and
//     produces a Manifest whose entries are validated ProbeResults bound to their
//     digest. Nothing in the manifest is accepted from a caller.
//   - Manifest.Digest is deterministic (length-prefixed, entries sorted by key);
//     Manifest.Sign and Manifest.Verify use an Ed25519 signature over the
//     domain-separated message "AntiFlock-CapabilityManifest-v1" || digest.
//   - LoadManifestFile is the only supported way to read a Manifest from disk.
//     It never follows symlinks, never reads more than MaxManifestBytes, rejects
//     unknown fields, duplicate keys, deep nesting, trailing content, and hostile
//     strings, and fails closed on concurrent modification, node mismatch,
//     invalid signature, and expiry.
//   - Evaluate returns one independent verdict per CapabilityRequirement with
//     stable AF-CAP- reason codes. Compatibility, driver readiness, and recovery
//     readiness are separate axes; a manifest-level failure fails every axis.
//
// A valid, node-signed, compatible manifest proves only that the node's own
// drivers observed the listed capabilities at the stated time. It does not
// establish that a plan is authorized, that the host is ready to mutate, or
// that the capability is still available when a plan executes.
package capability
