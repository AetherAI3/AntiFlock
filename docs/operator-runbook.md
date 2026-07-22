# Local operator runbook

This runbook operates the completed reference vertical slice on one trusted
workstation. It is a private, simulation-backed demonstration. It is not a
production VPN, an Android kill switch, or evidence that surveillance is
occurring.

## Safety boundary

- Run the stack only on a workstation you control.
- The Core API remains on an internal Docker network. Only the authenticated
  dashboard is published to the host, on `127.0.0.1:4173`.
- The simulator observes and mutates only its deterministic scenario state. It
  does not change the host firewall, routes, DNS, VPN, or mesh configuration.
- Do not expose the dashboard port to another interface, proxy it publicly, or
  reuse the generated development credentials in another environment.

## Requirements

- Docker Desktop or Docker Engine with Compose v2.
- Node.js 24 or newer.
- At least 2 GB of free disk space for images, build cache, and local state.

Go, Buf, Staticcheck, govulncheck, JDK, and Gradle do not need to be installed
on the host for the normal repository verification path; the harness uses
pinned containers and the checked-in Gradle wrapper where appropriate.

## Start the private stack

From the repository root:

```powershell
npm run dev
```

The launcher creates or repairs `.antiflock/dev.env`, starts Core, waits for
its health check, then starts the continuous simulator and dashboard. Existing
credentials are preserved when the file is valid.

Open <http://127.0.0.1:4173>. The browser prompts for HTTP Basic credentials:

- Username: `operator`
- Password: the value of `ANTIFLOCK_DASHBOARD_TOKEN` in
  `.antiflock/dev.env`

Treat the environment file as a secret. Do not paste it into a command, issue,
chat, log, screenshot, or browser URL. The dashboard credential is independent
from the scoped Core credentials, and the Core operator credential is never
sent to browser JavaScript.

Confirm the stack is healthy without printing credentials:

```powershell
docker compose --env-file .antiflock/dev.env ps
```

Expected services are `core`, `simulator`, and `web`; Core should report
healthy. A newly started dashboard may briefly show `CHECKING CORE`, then
`LIVE CORE` when its projections and event stream are available.

## Run the protected-action scenario

```powershell
npm run lab
```

If the continuous simulator is running, the launcher pauses it, executes one
isolated coffee-shop scenario, and resumes it. A successful result is JSON with:

- `schemaVersion` equal to `antiflock.live-simulation/v1`;
- `simulation` equal to `true`;
- the action moving from `HOLD` to `ALLOW` only after recovery evidence;
- two context events, four control-specific verification events, and five
  lifecycle audit events; and
- `verified` equal to `true`.

The dashboard should show an identifier-withheld untrusted Wi-Fi environment,
an observed route, and simulation-labeled mesh, DNS, policy-route, and external
egress verification. `DETECTED` context is never promoted to `VERIFIED`
evidence by the scenario.

## Verify the repository

```powershell
npm run verify
```

This is the locked verification gate. It checks protocol generation, Go
formatting/tests/race analysis/vet/build/static analysis/vulnerability reachability,
JavaScript lockfiles/audits/tests/builds/type checks/lint, the Android wrapper,
and the ten strict acceptance gates. A nonzero exit means the reference slice
is not releasable.

For a quick machine-readable acceptance report only:

```powershell
npm run acceptance:strict
```

The `secure-action-sdk` acceptance gate includes the live Compose-backed SDK
harness. It can also be run directly while diagnosing that boundary:

```powershell
npm run test:sdk:live
```

That harness temporarily creates a randomly selected loopback-only bridge to
Core, opts into executing simulation evidence for its controlled callback,
then removes the bridge and restores the prior stack state. Normal SDK callers
deny simulation evidence by default.

## Stop, reset, and recover

Stop services while preserving the SQLite database and simulator identity:

```powershell
npm run down
```

`make clean` is intentionally destructive: it stops the stack and removes the
named Docker volumes before deleting generated local build output. Use it only
when a complete local-state reset is intended. The private development
credential file is not removed.

If the dashboard cannot connect:

1. Run `docker compose --env-file .antiflock/dev.env ps` and confirm Core is
   healthy.
2. Run `npm run down`, then `npm run dev`.
3. Confirm another process is not using `127.0.0.1:4173`.
4. If `.antiflock/dev.env` is invalid, run `npm run dev:env`; the helper repairs
   missing values without printing secrets.
5. Use `docker compose --env-file .antiflock/dev.env logs --tail 100 core web`
   only on the trusted workstation. Review output before sharing it.

Do not work around an authentication, health, evidence, or policy failure by
disabling the check. Preserve the failure and investigate it.

## Production work that remains out of scope

Production use requires, at minimum, a real Android `VpnService` and packet
transport, real-device leak and recovery testing, platform keystore enrollment,
production TLS and node authentication, reviewed privileged enforcement,
imported surveillance datasets with license/provenance controls, production
Scrambler execution, and independent security/privacy review. The exact gates
are tracked in [release status](release-status.md) and
[open decisions](open-questions.md).
