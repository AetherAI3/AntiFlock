# Security policy

AntiFlock is pre-release security software. Do not rely on it as the sole
control for life safety, emergency communication, legal compliance, anonymity,
or protection against a determined observer.

## Reporting a vulnerability

Please use the repository host's private vulnerability-reporting or Security
Advisory feature. Do not open a public issue for a suspected vulnerability. If
private reporting has not yet been enabled, contact a listed maintainer through
a private channel and disclose only enough to establish a secure reporting
path; do not include exploit details in a public forum.

Include, when safe:

- affected version, commit, platform, and component;
- impact and preconditions;
- minimal reproduction or proof of concept;
- whether enrollment, identity, plan signing/replay, privileged enforcement,
  location, community safety, or Scrambler rollback is involved; and
- a safe way to contact you.

Do not test against systems, accounts, people, monitoring equipment, or
networks you do not own or have explicit authorization to assess. Do not access
or retain other people's data, disrupt service, degrade emergency access,
publish precise sensitive locations, or use AntiFlock to interfere with
equipment.

## Response

Maintainers will acknowledge a complete private report as soon as practical,
classify its security and privacy impact, preserve evidence, and coordinate a
fix and disclosure timeline. Timing cannot be guaranteed before a staffed
security contact and release process are published. Reports affecting private
keys, authentication, authorization, enrollment, signed plans, bypass,
rollback, payload or precise-location exposure, or community abuse controls
are treated as release-blocking until assessed.

Supported versions will be listed here at the first release. Until then, only
the latest commit on the primary development branch receives fixes.

## Security invariants

- Never submit private keys, recovery credentials, enrollment token values,
  operator identifiers, exact location, or packet payloads in an issue or log.
- Never weaken evidence labels or warning honesty as a mitigation shortcut.
- Never force-push or silently rewrite a security audit trail.
- Security fixes that change a public contract require a compatibility and
  migration note.
