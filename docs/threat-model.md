# Threat model

## Scope and protected assets

This model covers a single-operator or explicitly delegated deployment,
enrolled endpoints, local Core, provider adapters, the dashboard, regional
intelligence packs, community report ingestion, the Secure Action API, and
Scrambler plans. Protected assets include device private keys, deployment and
operator identity, policies and plan-signing keys, rollback and recovery
state, network and flow metadata, precise location, verified footprint assets,
community reporter privacy, and the integrity of evidence and audit history.

It does not claim to make a compromised kernel trustworthy, provide anonymity
against a global observer, detect every RF or cellular interceptor, prevent an
authorized destination from retaining data, or infer that nearby equipment is
targeting the operator.

## Adversaries

- An attacker on the local network who can observe, drop, replay, redirect, or
  manipulate traffic, DNS, DHCP, routes, or gateways.
- A compromised or malicious mesh peer, enrolled endpoint, adapter, plugin, or
  intelligence source.
- A remote attacker targeting Core, the dashboard, enrollment, local IPC, or
  agent-control channels.
- An abusive community reporter or moderator submitting false, identifying,
  stale, dangerous, or harassment-oriented content.
- A curious hosted-service operator, analytics provider, or database reader.
- A local user or application without authority to inspect another principal's
  assets or authorize a bypass.
- Accidental misconfiguration, clock skew, stale telemetry, partial platform
  capability, storage corruption, or a failed mutation.

## Primary threats and controls

| Threat | Required controls | Residual truth |
| --- | --- | --- |
| Plan forgery, downgrade, replay, or cross-node use | Authenticated channel, signed target-bound plan, nonce, monotonic revision, issue/expiry times, local validation | A compromised endpoint can still alter its own enforcement or reporting. |
| Enrollment theft | Short-lived single-use token, endpoint-generated key, explicit approval, token hash at rest, audit, immediate reachable revocation | A stolen token may race legitimate enrollment before use or expiry. |
| Core outage | Cached signed policy, local posture and enforcement, bounded queue, explicit offline expiry and recovery allowlist | New policy and global visibility are unavailable; posture may become `UNKNOWN` or service `UNAVAILABLE`. |
| Route, DNS, or gateway manipulation | Independent local facts, approved-exit and external-identity probes, deterministic findings, fail-closed policy | Indicators can support `SUSPECTED`; they do not by themselves prove an active interceptor. |
| Kill-switch lockout | Preflight, rollback capture, narrow recovery traffic, safe mode, local override, expiring plans | Local physical recovery may still be required. |
| Telemetry or audit tampering | Per-node sequencing, event IDs, signatures/digests, immutable append, correction events, replayable projections | A fully compromised node can lie before signing. |
| Dashboard/API takeover | Loopback/approved-mesh bind by default, authentication, least privilege, CSRF/origin protection where applicable, scoped authorization | Browser or OS compromise can inherit the operator's privileges. |
| Sensitive metadata collection | Metadata minimization, payload capture off, local location matching, per-class retention, export/delete controls | Flow metadata and topology remain sensitive even without payloads. |
| Community-report abuse | Infrastructure-only scope, PII stripping, precision reduction, moderation, provenance, dispute, decay, rate controls | Public infrastructure reports may still be wrong or misused. |
| Footprint dossier building | Ownership or explicit authorization proof, scoped connectors, no arbitrary-person query, revocation and deletion | Public records about verified assets may contain third-party references that require minimization. |
| Malicious intelligence pack | Signed manifest, content digest, source/license provenance, expiry, rollback, parser limits | A trusted signer can still publish erroneous data; evidence class remains visible. |
| Scrambler disruption or misuse | Simulation first, constrained candidate pool, same plan transaction, health checks, max latency, automatic rollback, audit | State changes can interrupt sessions and do not promise anonymity. |
| AI overreach | AI outside the blocking path; deterministic reason codes and preserved evidence; generated explanations labeled | Summaries can be wrong and must never replace source evidence. |

## Security boundaries

Core does not sit in the packet path. The normal agent does not run as root;
elevated operations are isolated behind authenticated, narrow local RPC.
Third-party plugins eventually run out of process and receive explicit
capabilities. Hosted services are not implicitly trusted with exact location,
private identifiers, payloads, or device keys.

## Abuse cases the product refuses

AntiFlock MUST NOT provide real-time tracking of people or officers, target
private individuals, publish personal routines, facilitate harassment, give
instructions to damage or interfere with equipment, generate routes designed
to evade lawful controls, investigate private identifiers without authority,
or turn uncertainty into a sensational allegation.

## Review triggers

Threat-model review is required before enabling payload capture, adding a new
privileged helper or enforcement backend, changing enrollment or signing,
uploading precise location, adding multi-tenancy, executing third-party code,
introducing model output into a decision path, or enabling a new Scrambler
state dimension.
