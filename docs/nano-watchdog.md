# Nano watchdog reference boundary

AntiFlock pins its Nano v0.1 compatibility contract to DBarr3/Nano PR #1 at
commit `40f697ba9020a4d4fee985406779c0d90ea2d6f4`. The Go implementation in
`core/nano` is an independent conformance implementation; no unlicensed Nano
source is vendored into this Apache-2.0 repository.

The locked flow is:

```text
typed finding -> numeric, one-hot context -> deterministic Nano evaluation
              -> admitted intent binding -> SecureActionRequest proposal
              -> existing Secure Action gate -> consent/audit lifecycle
```

Nano has no host capability. It cannot access the filesystem, processes,
network, clock, randomness, Scrambler enforcer, provider credential, or SDK
operation callback. In the watchdog admission profile, `OBSERVE` is trace-only
and `EXECUTE` can only select a separately admitted binding. The binding fixes
the application, action type, data class, sensitivity, and destination; script
text cannot widen them.

For example, Nano v0.1 has numeric conditions rather than string comparisons:

```nano
strategy ProbeWatch {
  agent Watchdog
  every 1s {
    if REASON_404_PROBING == 1
    and CONFIDENCE > 0.8 {
      execute()
    }
  }
}
```

`core/nano.FrameForFinding` performs the typed reason-code projection and
keeps confidence in `[0, 1]`. The caller persists the returned schedule cursor,
so processing one-event frames cannot cause an hourly program to fire once per
event. Source, token, condition, signal, timestamp, instruction, and output
budgets fail closed.

Every emitted proposal uses application `antiflock-nano`. The configured live
Core policies mark its currently admitted operations `consentRequired`, so a
protected posture still returns `REQUIRE_CONSENT`; only the operator's existing
one-time authorization route can produce one exact, expiring grant.

## Admitted watchdog runner

Core now admits a source program at `POST /v1/watchdogs`. Admission compiles the
source against the pinned Nano limits and watchdog profile, verifies the fixed
binding, persists trimmed immutable source plus canonical digest in SQLite, and
commits a signed audit entry in the same transaction. `POST
/v1/watchdogs/{id}/run` accepts only one typed finding and returns expiring
`SecureActionProposal` values; it does not call a provider, action callback,
or host enforcer. The durable cursor is written before any proposal is returned.

A rule author can express a narrow threshold such as:

```nano
strategy PublicSurfaceWatch {
  agent Watchdog
  every 5m {
    if REASON_UNEXPECTED_EXPOSURE == 1
    and CONFIDENCE >= 0.9 {
      execute()
    }
  }
}
```

The program does not name a host, URL, secret, destination, command, or action parameters. At admission time, the operator selects one fixed binding—such as an offline owned-surface fixture query—and the binding fixes the application ID, action type, data class, sensitivity, and destination. The operator must still authorize each proposal through the existing consent workflow.

Core can now run an admitted program over its own bounded set of current OPEN
findings at `POST /v1/watchdogs/{id}/run-open-findings`. The request accepts no
caller-supplied finding or signal; Core derives a sorted, capped typed context from
its finding projection and skips stale findings. The equivalent operator command is
`antiflockctl watchdog run-open-findings --program-id …`. This is an
operator-invoked, proposal-only pass—not a background scheduler or an action path.

Still **OPEN**: unattended finding-to-program scheduling, program disable/version
lifecycle, proposal audit projection in Third-Eye, replay fixtures, and a dedicated
operator authoring flow. Nano remains host-governed: it cannot fetch data, read
secrets, call a provider, or execute a response.

## Public-surface and physical references

The first public-surface adapters are offline deterministic fixtures for
Shodan-style exposed-service metadata, a broker-registry association, and a
paste-reference match. They accept only verified, unexpired, operator-owned
asset digests. Results remain `REPORTED` with `SIMULATION` provenance and never
store a raw banner, paste body, broker record, arbitrary person query, or
caller-selected URL. Suggested responses are reversible plans requiring the
Secure Action gate; fixture execution is disabled.

The Android vehicle appearance reference accepts only coarse, already
classified enums. Correlation uses a per-session HMAC secret, expires within
15 minutes, and remains in memory. No camera frame, image, embedding, face,
plate, VIN/OCR text, make/model, exact location, or reusable correlation token
is accepted or serialized.

## Deliberately unavailable

This release does not perform live third-party scraping, publish synthetic
identities, spoof location or device fingerprints, expose honeypots, rotate
routes or ports, or mutate a host. Those operations require separate provider,
legal, privacy, platform, and production-security gates. Nano output is a
proposal and explanation; it is never evidence or authority.
