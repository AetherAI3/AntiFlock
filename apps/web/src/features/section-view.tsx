"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import type {
  DashboardSection,
  Finding,
  PathSegment,
  SecureAction,
  TimelineEvent,
} from "../api/contracts";
import {
  CheckState,
  confidence,
  EmptyState,
  ErrorState,
  EvidenceBadge,
  formatTimestamp,
  KeyValue,
  Metric,
  Panel,
  PanelHeader,
  SeverityBadge,
  StateBadge,
} from "../components/ui";
import { useDashboard, type DataMode } from "../state/dashboard-context";
import {
  hasCompleteOneTimeAuthorizationScope,
  oneTimeAuthorizationScopeFingerprint,
} from "../state/action-consent";

function OverviewView() {
  const {
    data,
    mode,
    scenario,
    replayCoffeeShop,
    restoreShield,
  } = useDashboard();
  const exposed = data.posture.state === "EXPOSED";
  const protectedState = data.posture.state === "PROTECTED";
  const currentPath = data.paths[0];

  return (
    <div className="view-stack overview-view">
      <div className="overview-grid">
        <Panel className={`posture-command posture-command-${data.posture.state.toLowerCase()}`} labelledBy="posture-title">
          <div className="posture-command-copy">
            <p className="eyebrow">Protection posture &middot; {data.posture.reasonCode}</p>
            <h2 id="posture-title">{data.posture.state}</h2>
            <p className="posture-summary">{data.posture.summary}</p>
            <div className="posture-meta">
              <EvidenceBadge value={data.posture.evidenceClass} />
              <span>{confidence(data.posture.confidence)} confidence</span>
              <span>Evaluated {formatTimestamp(data.posture.evaluatedAt)}</span>
            </div>
          </div>
          <div className="operator-orbit" aria-label={`Operator environment: ${data.overview.environment.name}. Current state: ${data.posture.state}.`}>
            <span className="orbit orbit-one" aria-hidden="true" />
            <span className="orbit orbit-two" aria-hidden="true" />
            <span className="orbit orbit-three" aria-hidden="true" />
            <span className="operator-core"><small>YOU</small><strong>01</strong></span>
            <span className="orbit-node orbit-node-phone"><b>PHONE</b><small>{data.nodes[0]?.protection ?? "UNKNOWN"}</small></span>
            <span className="orbit-node orbit-node-exit"><b>EXIT</b><small>{data.overview.exitVerified ? "VERIFIED" : "UNAVAILABLE"}</small></span>
            <span className="orbit-node orbit-node-field"><b>FIELD</b><small>{data.fieldReports.length} REPORTED</small></span>
          </div>
        </Panel>

        <Panel className="environment-panel" labelledBy="environment-title">
          <PanelHeader title="Current environment" eyebrow="Locally detected" id="environment-title" />
          <div className="environment-name">
            <span className={`environment-glyph environment-${data.overview.environment.trust}`} aria-hidden="true">NET</span>
            <div><strong>{data.overview.environment.name}</strong><span>{data.overview.environment.security}</span></div>
          </div>
          <dl className="key-value-list">
            <KeyValue label="Trust" value={<StateBadge value={data.overview.environment.trust.toUpperCase()} />} />
            <KeyValue label="Gateway" value={data.overview.environment.gateway} mono />
            <KeyValue label="Known network" value={data.overview.environment.known ? "Yes" : "No \u00b7 first seen today"} />
            <KeyValue label="Changed" value={formatTimestamp(data.overview.environment.changedAt)} />
          </dl>
        </Panel>
      </div>

      {exposed && (
        <section className="interruption-alert" role="alert" aria-labelledby="interruption-title">
          <div className="alert-code" aria-hidden="true">!</div>
          <div className="alert-copy">
            <p className="eyebrow">Detected &middot; AF-PATH-001</p>
            <h2 id="interruption-title">Protection interrupted</h2>
            <p>Your approved secure route is unavailable on an untrusted network. Protected traffic has been paused.</p>
            <p className="uncertainty-line"><strong>Active interception is not confirmed.</strong> A broken route and nearby reported infrastructure are separate facts.</p>
            <div className="alert-context" aria-label="Protection interruption details">
              <span><small>Private mesh</small><b>Disconnected</b></span>
              <span><small>DNS path</small><b>Unverified</b></span>
              <span><small>Held actions</small><b>{data.overview.heldActions}</b></span>
              <span><small>Reported nearby</small><b>{data.fieldReports.length}</b></span>
            </div>
          </div>
          <div className="alert-actions">
            <button className="button button-primary" type="button" onClick={restoreShield}>{mode === "demo" ? "Restore Shield (demo)" : "Recheck protection"}</button>
            <Link className="button button-warning" href="/actions">Review held actions</Link>
            <Link className="button button-quiet" href="/field">View environment</Link>
          </div>
        </section>
      )}

      {protectedState && scenario.stage === "recovered" && (
        <section className="recovery-banner" role="status">
          <div><span className="recovery-check" aria-hidden="true">&#10003;</span></div>
          <div>
            <p className="eyebrow">Verified recovery</p>
            <h2>Protection restored</h2>
            <p>Mesh, DNS, and external egress identity match the Shielded policy. The held Aether Code action was released.</p>
          </div>
          {mode === "demo" && <button className="button button-quiet" type="button" onClick={replayCoffeeShop}>Replay incident</button>}
        </section>
      )}

      <div className="scenario-strip" aria-label="Coffee-shop scenario progression">
        <div>
          <p className="eyebrow">Coffee-shop vertical slice</p>
          <strong>Step {scenario.step} / 7 &middot; {scenario.label}</strong>
        </div>
        <ol>
          {["Join", "Verify", "Detect", "Hold", "Restore", "Confirm", "Release"].map((label, index) => (
            <li className={index < scenario.step ? "complete" : index === scenario.step ? "current" : "pending"} key={label}>
              <span>{index + 1}</span><small>{label}</small>
            </li>
          ))}
        </ol>
      </div>

      <div className="metric-grid">
        <Metric
          label="Protected devices"
          value={`${data.overview.protectedDevices} / ${data.overview.totalDevices}`}
          detail={data.overview.protectedDevices === data.overview.totalDevices ? "All enrolled endpoints verified" : "One endpoint is outside policy"}
          state={data.overview.protectedDevices === data.overview.totalDevices ? "good" : "warn"}
        />
        <Metric label="Approved exit" value={data.overview.exitVerified ? "Verified" : "Unavailable"} detail={data.overview.currentExit} state={data.overview.exitVerified ? "good" : "bad"} />
        <Metric label="DNS path" value={data.overview.dnsState} detail={data.overview.dnsResolver} state={data.overview.dnsState === "verified" ? "good" : "warn"} />
        <Metric label="Open findings" value={data.overview.openFindings} detail={`${data.findings.filter((finding) => finding.severity === "critical" && finding.status === "open").length} critical`} state={data.overview.openFindings ? "warn" : "good"} />
      </div>

      <div className="two-column-grid">
        <Panel labelledBy="active-path-title">
          <PanelHeader title="Active protected path" eyebrow="Application route" id="active-path-title" action={<Link href="/path">Inspect path &rarr;</Link>} />
          {currentPath ? <CompactPath segments={currentPath.segments} /> : <EmptyState title="No path projected" text="Core has not reported an application route." />}
        </Panel>
        <Panel labelledBy="recent-events-title">
          <PanelHeader title="Recent decisions" eyebrow="Append-only timeline" id="recent-events-title" action={<Link href="/activity">Full activity &rarr;</Link>} />
          <EventList events={data.events.slice(0, 4)} compact />
        </Panel>
      </div>
    </div>
  );
}

function CompactPath({ segments }: { segments: PathSegment[] }) {
  return (
    <ol className="compact-path" aria-label="Route segments">
      {segments.map((segment, index) => (
        <li className={`path-${segment.state}`} key={segment.id}>
          <span className="path-index">{String(index + 1).padStart(2, "0")}</span>
          <div><strong>{segment.label}</strong><small>{segment.detail}</small></div>
          <StateBadge value={segment.state.toUpperCase()} />
        </li>
      ))}
    </ol>
  );
}

function TopologyView() {
  const { data } = useDashboard();
  const edgeByTarget = new Map(data.topology.map((edge) => [edge.target, edge]));
  return (
    <div className="view-stack">
      <div className="view-intro">
        <div><p className="eyebrow">Asset graph + observer graph</p><h2>Operator-centered topology</h2><p>Only operator-controlled or explicitly observed relationships appear as facts. Unknown path segments remain labeled unknown.</p></div>
        <div className="legend" aria-label="Topology state legend">
          <span><i className="legend-trusted" />Trusted</span><span><i className="legend-degraded" />Degraded</span><span><i className="legend-blocked" />Blocked</span><span><i className="legend-unknown" />Unknown</span>
        </div>
      </div>
      <Panel className="topology-panel" labelledBy="topology-title">
        <PanelHeader title="Private security domain" eyebrow="Current projection" id="topology-title" action={<span className="mono annotation">{data.topology.length} relationships</span>} />
        <div className="topology-stage">
          <div className="topology-rings" aria-hidden="true"><span /><span /><span /></div>
          <div className="topology-operator"><small>IDENTITY</small><strong>LOCAL<br />OPERATOR</strong><span>Verified owner</span></div>
          <div className="topology-grid">
            {data.nodes.map((node, index) => {
              const edge = edgeByTarget.get(node.id);
              return (
                <article className={`topology-node topology-slot-${(index % 6) + 1} topology-${edge?.state ?? "unknown"}`} key={node.id}>
                  <div className="node-code">{node.kind.slice(0, 2).toUpperCase()}</div>
                  <div><strong>{node.name}</strong><span>{node.platform}</span><small>{node.meshAddress}</small></div>
                  <StateBadge value={node.protection} />
                </article>
              );
            })}
            <article className="topology-node topology-slot-5 topology-unknown observer-node">
              <div className="node-code">DS</div>
              <div><strong>api.github.com</strong><span>Destination service</span><small>Visibility beyond exit: limited</small></div>
              <EvidenceBadge value="Inferred" />
            </article>
          </div>
        </div>
      </Panel>
      <div className="two-column-grid">
        <Panel labelledBy="relationships-title">
          <PanelHeader title="Observed relationships" eyebrow="Evidence-aware edges" id="relationships-title" />
          {data.topology.length ? (
            <div className="relationship-list">
              {data.topology.map((edge) => (
                <div className="relationship-row" key={edge.id}>
                  <code>{edge.source}</code><span className={`relationship-line line-${edge.state}`}><small>{edge.label}</small></span><code>{edge.target}</code><EvidenceBadge value={edge.evidenceClass} />
                </div>
              ))}
            </div>
          ) : <EmptyState title="No topology relationships" text="No entity edges were returned by Core." />}
        </Panel>
        <Panel labelledBy="network-facts-title">
          <PanelHeader title="Network facts" eyebrow="Current endpoint" id="network-facts-title" />
          <dl className="key-value-list roomy">
            <KeyValue label="Network" value={data.overview.environment.name} />
            <KeyValue label="Trust" value={<StateBadge value={data.overview.environment.trust.toUpperCase()} />} />
            <KeyValue label="Gateway" value={data.overview.environment.gateway} mono />
            <KeyValue label="Approved exit" value={data.overview.currentExit} />
            <KeyValue label="DNS resolver" value={data.overview.dnsResolver} mono />
            <KeyValue label="Packet payloads" value="Not collected" />
          </dl>
        </Panel>
      </div>
    </div>
  );
}

function PathView() {
  const { data } = useDashboard();
  const [selectedId, setSelectedId] = useState(data.paths[0]?.id ?? "");
  const selected = data.paths.find((path) => path.id === selectedId) ?? data.paths[0];
  return (
    <div className="view-stack">
      <div className="view-intro">
        <div><p className="eyebrow">Logical route evidence</p><h2>Path inspection</h2><p>The path is a projection of reported and verified segments. AntiFlock does not imply visibility beyond the evidence shown for each hop.</p></div>
        {data.paths.length > 1 && (
          <label className="field-control">Path<select value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>{data.paths.map((path) => <option value={path.id} key={path.id}>{path.application} &rarr; {path.destination}</option>)}</select></label>
        )}
      </div>
      {selected ? (
        <>
          <Panel className="path-hero" labelledBy="path-title">
            <PanelHeader title={`${selected.application} \u2192 ${selected.destination}`} eyebrow="Current path" id="path-title" action={<StateBadge value={selected.state.toUpperCase()} />} />
            <ol className="path-diagram" aria-label="Detailed application path">
              {selected.segments.map((segment, index) => (
                <li className={`path-segment path-${segment.state}`} key={segment.id}>
                  <div className="segment-node"><span>{String(index + 1).padStart(2, "0")}</span><strong>{segment.label}</strong><small>{segment.kind}</small></div>
                  <div className="segment-detail"><p>{segment.detail}</p><EvidenceBadge value={segment.evidenceClass} /></div>
                  {index < selected.segments.length - 1 && <span className="segment-connector" aria-hidden="true" />}
                </li>
              ))}
            </ol>
          </Panel>
          <div className="three-column-grid">
            <Metric label="Route policy" value={selected.policy} detail="Compiled for this endpoint" state="neutral" />
            <Metric label="Encryption" value={selected.encrypted === null ? "Unknown" : selected.encrypted ? "Verified" : "Not present"} detail="Unknown is preserved when the exit is unreachable" state={selected.encrypted ? "good" : "warn"} />
            <Metric label="Last change" value={formatTimestamp(selected.updatedAt)} detail="Projection observation time" state="neutral" />
          </div>
        </>
      ) : <EmptyState title="No application path available" text="Connect an observed application or wait for the path projection to report a route." />}
    </div>
  );
}

function EventList({ events, compact = false }: { events: TimelineEvent[]; compact?: boolean }) {
  if (!events.length) return <EmptyState title="No matching events" text="No events meet the current filter." />;
  return (
    <ol className={`event-list ${compact ? "event-list-compact" : ""}`}>
      {events.map((event) => (
        <li key={event.id}>
          <span className={`event-marker marker-${event.severity}`} aria-hidden="true" />
          <div className="event-time"><time dateTime={event.observedAt}>{formatTimestamp(event.observedAt)}</time><code>{event.kind}</code></div>
          <div className="event-copy"><strong>{event.title}</strong><p>{event.summary}</p>{event.reasonCode && <code>{event.reasonCode}</code>}</div>
          <div className="event-proof"><EvidenceBadge value={event.evidenceClass} /><small>{confidence(event.confidence)}</small></div>
        </li>
      ))}
    </ol>
  );
}

function ActivityView() {
  const { data } = useDashboard();
  const [query, setQuery] = useState("");
  const [classification, setClassification] = useState("all");
  const [severity, setSeverity] = useState("all");
  const filtered = useMemo(() => data.events.filter((event) => {
    const matchesText = `${event.kind} ${event.title} ${event.summary} ${event.reasonCode ?? ""}`.toLowerCase().includes(query.toLowerCase());
    return matchesText && (classification === "all" || event.evidenceClass === classification) && (severity === "all" || event.severity === severity);
  }), [classification, data.events, query, severity]);
  return (
    <div className="view-stack">
      <div className="view-intro">
        <div><p className="eyebrow">Append-only projection</p><h2>Activity timeline</h2><p>Observed time and received time remain separate in the event model. This view uses observed time and keeps event classification visible.</p></div>
        <span className="record-count">{filtered.length} / {data.events.length} events</span>
      </div>
      <div className="filter-bar" role="search" aria-label="Filter activity">
        <label className="search-control"><span>Search timeline</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Event, reason code, destination..." /></label>
        <label className="field-control">Evidence<select value={classification} onChange={(event) => setClassification(event.target.value)}><option value="all">All classes</option>{["Detected", "Verified", "Reported", "Inferred", "Suspected", "Unknown"].map((value) => <option key={value}>{value}</option>)}</select></label>
        <label className="field-control">Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All levels</option>{["critical", "high", "medium", "low", "info"].map((value) => <option key={value}>{value}</option>)}</select></label>
      </div>
      <Panel className="timeline-panel" labelledBy="timeline-title">
        <PanelHeader title="Decision and network history" eyebrow="Newest first" id="timeline-title" />
        <EventList events={filtered} />
      </Panel>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <details className={`finding-card finding-${finding.severity}`} open={finding.severity === "critical" && finding.status === "open"}>
      <summary>
        <div className="finding-summary-main"><span className="finding-rule">{finding.ruleId}</span><strong>{finding.title}</strong><p>{finding.condition}</p></div>
        <div className="finding-summary-meta"><SeverityBadge value={finding.severity} /><EvidenceBadge value={finding.classification} /><span>{confidence(finding.confidence)}</span><StateBadge value={finding.status.toUpperCase()} /></div>
      </summary>
      <div className="finding-body">
        <div className="finding-explanation">
          <div><h3>Consequence</h3><p>{finding.consequence}</p></div>
          <div><h3>Recommended response</h3><p>{finding.recommendation}</p></div>
          <div className="uncertainty-box"><h3>Uncertainty / false-positive context</h3><p>{finding.falsePositiveNote}</p></div>
        </div>
        <div className="evidence-table-wrap">
          <table className="data-table evidence-table">
            <caption>Evidence supporting {finding.ruleId}</caption>
            <thead><tr><th>Evidence</th><th>Value</th><th>Class</th><th>Source</th><th>Last verified</th><th>Confidence</th></tr></thead>
            <tbody>{finding.evidence.map((item) => <tr key={item.id}><td>{item.label}</td><td>{item.value}</td><td><EvidenceBadge value={item.evidenceClass} /></td><td>{item.source}</td><td>{formatTimestamp(item.lastVerifiedAt)}</td><td>{confidence(item.confidence)}</td></tr>)}</tbody>
          </table>
        </div>
      </div>
    </details>
  );
}

function FindingsView() {
  const { data } = useDashboard();
  const [status, setStatus] = useState<"open" | "resolved" | "all">("open");
  const visible = data.findings.filter((finding) => status === "all" || finding.status === status);
  return (
    <div className="view-stack">
      <div className="view-intro">
        <div><p className="eyebrow">Explainable security state</p><h2>Findings and evidence</h2><p>No generic warnings: each finding shows the condition, consequence, supporting evidence, confidence, uncertainty, and recommended response.</p></div>
        <div className="segmented-control" role="group" aria-label="Finding status filter">{(["open", "resolved", "all"] as const).map((value) => <button type="button" className={status === value ? "active" : ""} aria-pressed={status === value} onClick={() => setStatus(value)} key={value}>{value}</button>)}</div>
      </div>
      <div className="finding-list">
        {visible.length ? visible.map((finding) => <FindingCard finding={finding} key={finding.id} />) : <EmptyState title={`No ${status} findings`} text="The projection contains no findings with this status." />}
      </div>
    </div>
  );
}

function DevicesView() {
  const { data, createEnrollmentToken, clearEnrollmentSecret, enrollmentSecret, pendingCommand } = useDashboard();
  const [query, setQuery] = useState("");
  const visible = data.nodes.filter((node) => `${node.name} ${node.platform} ${node.tags.join(" ")}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <div className="view-stack">
      <div className="view-intro">
        <div><p className="eyebrow">Stable AntiFlock identity</p><h2>Enrolled devices and agents</h2><p>Mesh-provider identity is observed separately from the AntiFlock credential and reported capability manifest.</p></div>
        <button className="button button-primary" type="button" onClick={() => void createEnrollmentToken()} disabled={pendingCommand === "enrollment-token"}>{pendingCommand === "enrollment-token" ? "Creating..." : "Create enrollment token"}</button>
      </div>
      {enrollmentSecret && (
        <Panel className="enrollment-secret" labelledBy="enrollment-secret-title">
          <PanelHeader title="Copy this enrollment token now" eyebrow="Single use &middot; memory only" id="enrollment-secret-title" />
          <p>The dashboard does not persist this credential. It expires {formatTimestamp(enrollmentSecret.expiresAt)} and is permanently consumed by the first valid enrollment request.</p>
          <code>{enrollmentSecret.tokenValue}</code>
          <div className="button-row">
            <button className="button button-primary" type="button" onClick={() => void navigator.clipboard.writeText(enrollmentSecret.tokenValue)}>Copy token</button>
            <button className="button button-quiet" type="button" onClick={clearEnrollmentSecret}>Forget token</button>
          </div>
        </Panel>
      )}
      <div className="filter-bar single-filter" role="search">
        <label className="search-control"><span>Find a node</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name, platform, tag..." /></label>
      </div>
      {visible.length ? (
        <div className="device-grid">
          {visible.map((node) => (
            <article className="device-card" key={node.id}>
              <header>
                <span className={`device-kind device-${node.kind}`} aria-hidden="true">{node.kind.slice(0, 2).toUpperCase()}</span>
                <div><h2>{node.name}</h2><p>{node.platform}</p></div>
                <StateBadge value={node.protection} />
              </header>
              <dl className="key-value-list">
                <KeyValue label="Connection" value={node.state} />
                <KeyValue label="Mesh address" value={node.meshAddress} mono />
                <KeyValue label="Network" value={node.network} />
                <KeyValue label="Agent" value={node.agentVersion} mono />
                <KeyValue label="Last seen" value={formatTimestamp(node.lastSeen)} />
              </dl>
              <div className="capability-list"><span>Reported capabilities</span>{node.capabilities.length ? <ul>{node.capabilities.map((item) => <li key={item}>{item}</li>)}</ul> : <p>No capabilities reported</p>}</div>
              <footer>{node.tags.map((tag) => <span className="tag" key={tag}>{tag}</span>)}</footer>
            </article>
          ))}
        </div>
      ) : <EmptyState title="No matching nodes" text="Try a broader search or enroll a new endpoint." />}
    </div>
  );
}

function PoliciesView() {
  const { data, validatePolicy, pendingCommand } = useDashboard();
  const active = data.policies.find((policy) => policy.status === "active") ?? data.policies[0];
  return (
    <div className="view-stack">
      <div className="view-intro">
        <div><p className="eyebrow">Deterministic policy compiler</p><h2>Protection policies</h2><p>Operator intent compiles against each device capability set. Unsupported controls remain warnings rather than silently disappearing.</p></div>
        <button className="button button-primary" type="button" onClick={() => void validatePolicy()} disabled={!active || pendingCommand === "policy-validate"}>{pendingCommand === "policy-validate" ? "Validating..." : "Validate active policy"}</button>
      </div>
      {active ? (
        <div className="policy-layout">
          <Panel className="policy-summary" labelledBy="policy-active-title">
            <PanelHeader title={active.name} eyebrow="Active protection profile" id="policy-active-title" action={<StateBadge value={active.mode.toUpperCase()} />} />
            <div className="policy-meta-grid"><Metric label="Revision" value={active.revision} detail={`Updated ${formatTimestamp(active.updatedAt)}`} /><Metric label="Targets" value={active.targetCount} detail="Capability-matched endpoints" /><Metric label="Status" value={active.status} detail="Signed local revision" state="good" /></div>
            <table className="data-table policy-table"><caption>Active policy rules</caption><thead><tr><th>Control</th><th>Required behavior</th><th>Mode</th></tr></thead><tbody>{active.rules.map((rule) => <tr key={rule.id}><td>{rule.label}</td><td>{rule.value}</td><td><span className={`mode-label mode-${rule.enforcement}`}>{rule.enforcement}</span></td></tr>)}</tbody></table>
          </Panel>
          <Panel className="dry-run-panel" labelledBy="dry-run-title">
            <PanelHeader title="Human-readable dry run" eyebrow="No changes applied" id="dry-run-title" />
            <div className="terminal-block" role="region" aria-label="Policy dry-run preview">
              <p><span>PROFILE</span> shielded</p><p><span>TARGET</span> operator-phone</p>
              <hr />
              <p className="terminal-add">+ Require private mesh for Internet egress</p>
              <p className="terminal-add">+ Route through home-gateway</p>
              <p className="terminal-add">+ Restrict DNS to mesh resolver</p>
              <p className="terminal-add">+ Keep recovery endpoints reachable</p>
              <p className="terminal-warn">! Per-application attribution supplied by SDK only</p>
              <hr />
              <p><span>ROLLBACK</span> restore route, DNS, and firewall snapshot</p>
            </div>
            <div className="safety-note"><strong>Safety gate</strong><p>Applying a plan requires verified rollback state, a monotonic revision, an unexpired signature, and local precondition checks.</p></div>
          </Panel>
        </div>
      ) : <EmptyState title="No policy profiles" text="Core returned no protection profiles." />}
      <Panel labelledBy="profiles-title"><PanelHeader title="Available profiles" eyebrow={"Observe \u2192 Guard \u2192 Shield \u2192 Scramble"} id="profiles-title" />
        <div className="profile-row">{data.policies.map((policy) => <article key={policy.id}><StateBadge value={policy.mode.toUpperCase()} /><div><strong>{policy.name}</strong><span>Revision {policy.revision} &middot; {policy.targetCount} target{policy.targetCount === 1 ? "" : "s"}</span></div><small>{policy.status}</small></article>)}</div>
      </Panel>
    </div>
  );
}

export function OneTimeAuthorizationControl({
  action,
  mode,
  pending,
  onAuthorize,
}: {
  action: SecureAction;
  mode: DataMode;
  pending: boolean;
  onAuthorize: (actionId: string) => Promise<void>;
}) {
  const [confirmedFingerprint, setConfirmedFingerprint] = useState<string | null>(null);
  const scopeFingerprint = oneTimeAuthorizationScopeFingerprint(action);
  const confirmed = confirmedFingerprint === scopeFingerprint;
  const hasCompleteScope = hasCompleteOneTimeAuthorizationScope(action);
  const authorizationAvailable = hasCompleteScope
    && (mode === "demo" || Boolean(action.oneTimeAuthorization?.enabled));

  return (
    <footer className="action-consent">
      <div className="action-consent-copy">
        <p className="eyebrow">Confirm exact one-time scope</p>
        <p>This authorization does not disable global protection and applies only to every value shown below.</p>
        <dl className="consent-scope">
          <KeyValue label="Action ID" value={action.id} mono />
          <KeyValue label="Operation ID" value={action.operationId} mono />
          <KeyValue label="Application ID" value={action.applicationId} mono />
          <KeyValue label="Node ID" value={action.nodeId} mono />
          <KeyValue label="Action type" value={action.actionType} mono />
          <KeyValue label="Destinations" value={action.destinations.join(", ") || "Not reported"} mono />
          <KeyValue label="Data class" value={action.dataClass} mono />
          <KeyValue label="Sensitivity" value={action.sensitivity} mono />
          <KeyValue label="Authorization expires" value={action.oneTimeAuthorization?.maximumExpiresAt ? formatTimestamp(action.oneTimeAuthorization.maximumExpiresAt) : "Not reported"} />
        </dl>
        {authorizationAvailable ? (
          <label className="consent-confirmation">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmedFingerprint(event.target.checked ? scopeFingerprint : null)}
              disabled={pending}
            />
            <span>I confirm this exact application, action, destination, data, and sensitivity scope.</span>
          </label>
        ) : (
          <p className="consent-unavailable" role="status">Core did not provide a complete, enabled one-time authorization scope.</p>
        )}
      </div>
      <button
        className="button button-warning"
        type="button"
        onClick={() => {
          setConfirmedFingerprint(null);
          void onAuthorize(action.id);
        }}
        disabled={!authorizationAvailable || !confirmed || pending}
      >
        {pending ? "Authorizing..." : authorizationAvailable ? "Authorize this exact scope once" : "One-time authorization unavailable"}
      </button>
    </footer>
  );
}

function ActionsView() {
  const { data, mode, sendOnce, pendingCommand } = useDashboard();
  const [decision, setDecision] = useState("all");
  const visible = data.actions.filter((action) => decision === "all" || action.decision === decision);
  return (
    <div className="view-stack">
      <div className="view-intro">
        <div><p className="eyebrow">Secure Action Gate</p><h2>Application decisions</h2><p>Application-native holds are distinct from universal network blocking. One-time authorization is narrow, expiring, and audited.</p></div>
        <label className="field-control">Decision<select value={decision} onChange={(event) => setDecision(event.target.value)}><option value="all">All decisions</option>{["ALLOW", "HOLD", "BLOCK", "REQUIRE_CONSENT", "ALLOW_ONCE"].map((value) => <option key={value}>{value}</option>)}</select></label>
      </div>
      {visible.length ? <div className="action-list">{visible.map((action) => (
        <article className={`action-card action-${action.decision.toLowerCase()}`} key={action.id}>
          <header><span className="action-app">AC</span><div><p className="eyebrow">{action.applicationId}</p><h2>{action.actionType}</h2></div><StateBadge value={action.decision} /></header>
          <dl className="action-facts"><KeyValue label="Destination" value={action.destination} mono /><KeyValue label="Data class" value={action.dataClass} /><KeyValue label="Sensitivity" value={action.sensitivity} mono /><KeyValue label="Created" value={formatTimestamp(action.createdAt)} /><KeyValue label="Expiry" value={action.expiresAt ? formatTimestamp(action.expiresAt) : "No expiry reported"} /></dl>
          <div className="reason-codes"><span>Decision reasons</span>{action.reasonCodes.map((code) => <code key={code}>{code}</code>)}</div>
          {["HOLD", "BLOCK", "REQUIRE_CONSENT"].includes(action.decision) && action.oneTimeAuthorization?.enabled && (
            <OneTimeAuthorizationControl action={action} mode={mode} pending={pendingCommand === "send-once"} onAuthorize={sendOnce} />
          )}
        </article>
      ))}</div> : <EmptyState title="No matching actions" text="No secure actions meet this decision filter." />}
      <Panel labelledBy="sdk-boundary-title"><PanelHeader title="Enforcement boundary" eyebrow="Evidence honesty" id="sdk-boundary-title" /><div className="boundary-grid"><div><strong>Universal protection</strong><p>The VPN or firewall can block network egress. A third-party application may show its own pending or failed state.</p></div><div><strong>Integrated protection</strong><p>The Secure Action SDK can hold a specific action, explain the reason, authorize once, and retry after verification.</p></div></div></Panel>
    </div>
  );
}

function FieldView() {
  const { data } = useDashboard();
  const [selectedId, setSelectedId] = useState(data.fieldReports[0]?.id ?? "");
  const selected = data.fieldReports.find((report) => report.id === selectedId) ?? data.fieldReports[0];
  return (
    <div className="view-stack">
      <section className="field-disclaimer" aria-labelledby="field-disclaimer-title">
        <div className="report-glyph" aria-hidden="true">RPT</div><div><p className="eyebrow">Reported infrastructure &middot; separate evidence domain</p><h2 id="field-disclaimer-title">Nearby reports do not indicate active network interception</h2><p>These markers come from public or community sources. They are not evidence that a system is observing you specifically or that it caused the current route failure.</p></div>
      </section>
      <div className="field-layout">
        <Panel className="field-map-panel" labelledBy="field-map-title">
          <PanelHeader title="Current area" eyebrow="Local regional-pack match" id="field-map-title" action={<span className="privacy-chip">Exact location stays on device</span>} />
          <div className="field-map" role="img" aria-label={`${data.fieldReports.length} reported infrastructure markers around an approximate current area`}>
            <div className="map-grid" aria-hidden="true" /><div className="map-road road-one" aria-hidden="true" /><div className="map-road road-two" aria-hidden="true" /><div className="current-area"><span>APPROXIMATE<br />CURRENT AREA</span></div>
            {data.fieldReports.map((report, index) => <button className={`map-marker ${selected?.id === report.id ? "selected" : ""}`} style={{ left: `${report.coordinates.x}%`, top: `${report.coordinates.y}%` }} type="button" aria-label={`Select ${report.label}: ${report.distance}`} onClick={() => setSelectedId(report.id)} key={report.id}><span>{index + 1}</span></button>)}
            <div className="map-scale" aria-hidden="true"><span />500 m approximate</div>
          </div>
        </Panel>
        <Panel className="report-detail" labelledBy="report-detail-title">
          {selected ? <><PanelHeader title={selected.label} eyebrow={selected.category} id="report-detail-title" action={<EvidenceBadge value={selected.classification} />} />
            <div className="report-confidence"><span>Source confidence</span><strong>{confidence(selected.confidence)}</strong><div><i style={{ width: confidence(selected.confidence) }} /></div></div>
            <dl className="key-value-list roomy"><KeyValue label="Distance" value={selected.distance} /><KeyValue label="Direction" value={selected.direction} /><KeyValue label="Location precision" value={selected.locationPrecision} /><KeyValue label="Verification" value={selected.status} /><KeyValue label="Source" value={selected.source} /><KeyValue label="Last verified" value={formatTimestamp(selected.lastVerifiedAt)} /><KeyValue label="Expires" value={formatTimestamp(selected.expiresAt)} /></dl>
          </> : <EmptyState title="No report selected" text="Select a marker to inspect its source and freshness." />}
        </Panel>
      </div>
      <Panel labelledBy="reports-title"><PanelHeader title="Nearby report inventory" eyebrow="Freshness and precision preserved" id="reports-title" /><div className="report-list">{data.fieldReports.length ? data.fieldReports.map((report, index) => <button type="button" onClick={() => setSelectedId(report.id)} aria-pressed={selected?.id === report.id} key={report.id}><span className="report-number">{String(index + 1).padStart(2, "0")}</span><div><strong>{report.label}</strong><small>{report.distance} &middot; {report.locationPrecision}</small></div><EvidenceBadge value={report.classification} /><span>{report.status}</span><time dateTime={report.lastVerifiedAt}>{formatTimestamp(report.lastVerifiedAt)}</time></button>) : <EmptyState title="No nearby reports" text="The active regional pack returned no matching infrastructure reports." />}</div></Panel>
    </div>
  );
}

function FootprintView() {
  const { data } = useDashboard();
  const verified = data.footprintAssets.filter((asset) => asset.verification === "verified").length;
  return (
    <div className="view-stack">
      <section className="ownership-boundary">
        <div className="ownership-mark" aria-hidden="true">OWN</div><div><p className="eyebrow">Authorization boundary</p><h2>Only operator-verified assets are analyzed</h2><p>AntiFlock is an owned-asset exposure graph, not a people-search or dossier system. Pending assets remain outside active investigation until ownership is proven.</p></div>
      </section>
      <div className="metric-grid footprint-metrics"><Metric label="Verified assets" value={`${verified} / ${data.footprintAssets.length}`} detail="Ownership challenges completed" state="good" /><Metric label="Public assets" value={data.footprintAssets.filter((asset) => asset.exposure === "public").length} detail="Visible without private access" state="neutral" /><Metric label="Exposure findings" value={data.footprintAssets.reduce((total, asset) => total + asset.findings, 0)} detail="One breach-reference review" state="warn" /><Metric label="Relationships" value={data.footprintRelationships.length} detail="Each edge carries evidence class" state="neutral" /></div>
      <Panel className="footprint-graph-panel" labelledBy="footprint-title">
        <PanelHeader title="Digital footprint graph" eyebrow={"Verified identity \u2192 public exposure"} id="footprint-title" />
        {data.footprintAssets.length ? <div className="footprint-graph">
          <div className="footprint-identity"><small>VERIFIED IDENTITY</small><strong>Local operator</strong><span>Private root</span></div>
          <div className="footprint-assets">{data.footprintAssets.map((asset, index) => <article className={`footprint-asset asset-position-${(index % 6) + 1} exposure-${asset.exposure}`} key={asset.id}><span className="asset-code">{asset.type.slice(0, 2).toUpperCase()}</span><div><small>{asset.type}</small><strong>{asset.label}</strong><span>{asset.exposure} exposure</span></div><StateBadge value={asset.verification.toUpperCase()} /></article>)}</div>
        </div> : <EmptyState title="No verified assets" text="Add an asset and complete an ownership challenge before AntiFlock analyzes it." />}
      </Panel>
      <div className="two-column-grid">
        <Panel labelledBy="asset-inventory-title"><PanelHeader title="Asset inventory" eyebrow="Ownership and exposure" id="asset-inventory-title" /><div className="asset-list">{data.footprintAssets.map((asset) => <article key={asset.id}><div><span className="asset-type">{asset.type}</span><strong>{asset.label}</strong></div><StateBadge value={asset.verification.toUpperCase()} /><span className={`exposure-label exposure-${asset.exposure}`}>{asset.exposure}</span><time dateTime={asset.lastCheckedAt}>{formatTimestamp(asset.lastCheckedAt)}</time><b>{asset.findings} finding{asset.findings === 1 ? "" : "s"}</b></article>)}</div></Panel>
        <Panel labelledBy="footprint-rel-title"><PanelHeader title="Evidence-aware relationships" eyebrow="No unlabeled inferences" id="footprint-rel-title" /><div className="footprint-relations">{data.footprintRelationships.map((relationship) => { const source = data.footprintAssets.find((asset) => asset.id === relationship.source); const target = data.footprintAssets.find((asset) => asset.id === relationship.target); return <div key={relationship.id}><span>{source?.label ?? relationship.source}</span><div><i /><small>{relationship.label}</small></div><span>{target?.label ?? relationship.target}</span><EvidenceBadge value={relationship.classification} /></div>; })}</div></Panel>
      </div>
    </div>
  );
}

function ScramblerView() {
  const { data, simulateScrambler, activateScrambler, pendingCommand } = useDashboard();
  const failed = data.scrambler.checks.filter((check) => check.state === "fail").length;
  const unknown = data.scrambler.checks.filter((check) => check.state === "unknown" || check.state === "pending").length;
  const ready = failed === 0 && unknown === 0 && data.posture.state === "PROTECTED";
  return (
    <div className="view-stack">
      <section className="scrambler-hero">
        <div><p className="eyebrow">Moving-target defense &middot; controlled transitions</p><h2>{data.scrambler.state}</h2><p>Scrambler proposes state changes, runs preflight, applies only approved candidates, verifies the resulting path, and rolls back when a required check fails.</p><div className="scrambler-tags"><span>Profile {data.scrambler.profile}</span><span>State {data.scrambler.stateId}</span><span>Risk {data.scrambler.risk}</span></div></div>
        <div className="scrambler-dial" aria-label={`Scrambler state ${data.scrambler.state}`}><span className="dial-ring ring-a" aria-hidden="true" /><span className="dial-ring ring-b" aria-hidden="true" /><div><small>STATE</small><strong>{data.scrambler.stateId.split(" ")[0]}</strong><span>{data.scrambler.state}</span></div></div>
      </section>
      <div className="scrambler-layout">
        <Panel labelledBy="transition-title"><PanelHeader title="Candidate transition" eyebrow="Simulation first" id="transition-title" action={<span className="risk-label">{data.scrambler.risk} risk</span>} />
          <div className="route-transition"><article><small>CURRENT EXIT</small><strong>{data.scrambler.currentExit}</strong><span>{data.posture.state === "PROTECTED" ? "verified" : "not verified"}</span></article><div><span aria-hidden="true">&rarr;</span><small>proposed</small></div><article><small>CANDIDATE EXIT</small><strong>{data.scrambler.proposedExit ?? "No candidate"}</strong><span>not applied</span></article></div>
          <div className="button-row"><button className="button button-primary" type="button" onClick={() => void simulateScrambler()} disabled={pendingCommand === "scrambler-simulate"}>{pendingCommand === "scrambler-simulate" ? "Simulating..." : "Run preflight simulation"}</button><button className="button button-warning" type="button" onClick={() => void activateScrambler()} disabled>Activation outside release boundary</button></div>
          {!ready && <p className="inline-warning">Activation held: {failed} required check{failed === 1 ? "" : "s"} failed and {unknown} remain unknown or pending.</p>}
        </Panel>
        <Panel labelledBy="verification-title"><PanelHeader title="Required verification" eyebrow="All checks must pass" id="verification-title" />
          <ul className="verification-list">{data.scrambler.checks.map((check) => <li key={check.id}><CheckState state={check.state} /><span>{check.label}</span></li>)}</ul>
          <div className="rollback-note"><strong>Rollback retained</strong><p>The previous state remains available until Core reachability, peers, DNS, approved destinations, leak checks, exit identity, and critical applications all pass.</p></div>
        </Panel>
      </div>
      <Panel labelledBy="state-machine-title"><PanelHeader title="Transition state machine" eyebrow="No privileged back door" id="state-machine-title" />
        <ol className="state-machine" aria-label="Scrambler transition states">{["IDLE", "PLANNING", "PREFLIGHT", "DRAINING", "APPLYING", "VERIFYING", "ACTIVE"].map((state, index) => <li className={data.scrambler.state === state ? "active" : ""} key={state}><span>{String(index + 1).padStart(2, "0")}</span><strong>{state}</strong>{index < 6 && <i aria-hidden="true" />}</li>)}<li className={data.scrambler.state === "ROLLING_BACK" ? "active rollback" : "rollback"}><span>RB</span><strong>ROLLING BACK</strong></li></ol>
      </Panel>
    </div>
  );
}

function SettingsView() {
  const { data, apiBase, demoFallback, updateConnectionSettings, streamStatus, mode, lastRefresh, failedEndpoints } = useDashboard();
  const [nextFallback, setNextFallback] = useState(demoFallback);
  return (
    <div className="view-stack settings-view">
      <div className="view-intro"><div><p className="eyebrow">Local dashboard settings</p><h2>Core connection</h2><p>Connection settings stay on this browser. They do not alter endpoint protection, agent policy, or mesh configuration.</p></div></div>
      <div className="settings-layout">
        <Panel labelledBy="connection-settings-title"><PanelHeader title="Projection source" eyebrow="REST + durable SSE" id="connection-settings-title" />
          <form className="settings-form" onSubmit={(event) => { event.preventDefault(); updateConnectionSettings("", nextFallback); }}>
              <label><span>AntiFlock Core connection</span><input value="Same-origin private proxy" readOnly aria-readonly="true" aria-describedby="api-help" /><small id="api-help">The browser accepts live state only through the dashboard&apos;s server-authenticated proxy. Core credentials never enter browser storage.</small></label>
            <label><span>SSE projection endpoint</span><input value="/v1/stream?topics=..." readOnly aria-readonly="true" /><small>Durable cursors resume through the event stream. The stream carries projections, not packet payloads.</small></label>
            <label className="toggle-control"><input type="checkbox" checked={nextFallback} onChange={(event) => setNextFallback(event.target.checked)} /><span><strong>Use deterministic demo fallback</strong><small>If Core is unavailable, label and show the coffee-shop fixture instead of a blank console.</small></span></label>
            <button className="button button-primary" type="submit">Save and reconnect</button>
          </form>
        </Panel>
        <Panel labelledBy="connection-status-title"><PanelHeader title="Connection status" eyebrow="Current browser session" id="connection-status-title" /><dl className="key-value-list roomy"><KeyValue label="Data mode" value={<StateBadge value={mode.toUpperCase()} />} /><KeyValue label="Event stream" value={streamStatus} /><KeyValue label="Base URL" value={apiBase || "Same origin"} mono /><KeyValue label="Last refresh" value={lastRefresh ? formatTimestamp(lastRefresh) : "No successful live refresh"} /><KeyValue label="Missing projections" value={failedEndpoints.length ? failedEndpoints.join(", ") : "None reported"} /></dl></Panel>
      </div>
      <Panel className="agent-setup-panel" labelledBy="agent-setup-title">
        <PanelHeader title="Bring an endpoint online" eyebrow="Third-Eye setup" id="agent-setup-title" action={<span className="mono annotation">{data.nodes.length} enrolled</span>} />
        <p className="setup-intro">Setup materials stay on the operator machine. This console receives only signed projections, never your node seed, client certificate, or provider key.</p>
        <div className="setup-card-grid">
          <article className={`setup-card ${data.nodes.length ? "setup-ready" : "setup-open"}`}>
            <span className="setup-step">01</span><div><p>Enrolled agent</p><strong>{data.nodes.length ? "Projected" : "Waiting for first node"}</strong><small>Run <code>antiflock-agent enroll</code>, approve it, then rerun the same command to save its matching certificate before the one-cycle smoke test.</small></div><StateBadge value={data.nodes.length ? "READY" : "OPEN"} />
          </article>
          <article className="setup-card setup-open">
            <span className="setup-step">02</span><div><p>Network Third-Eye</p><strong>Metadata-only flow monitor</strong><small>Opt in with <code>--include-flow-metadata</code>. It reads socket endpoints only—never packet or application payloads.</small></div><StateBadge value="OPT-IN" />
          </article>
          <article className="setup-card setup-open">
            <span className="setup-step">03</span><div><p>Mesh provider</p><strong>Tailscale or Headscale</strong><small>Tailscale uses read-only local status. Headscale uses a private read-only key file and explicit identity associations.</small></div><StateBadge value="BYOK" />
          </article>
          <article className="setup-card setup-open">
            <span className="setup-step">04</span><div><p>Nano watchdog</p><strong>Opt-in Core proposal scheduler</strong><small>Core can run an explicit allowlist of admitted Nano programs over bounded current findings at a configured interval. It returns expiring proposals only; program lifecycle and proposal audit remain OPEN.</small></div><StateBadge value="WIRED" />
          </article>
        </div>
        <p className="setup-note">Detailed operator commands and file-permission requirements are in the enrolled-agent guide. No setup card can change a provider or host configuration.</p>
      </Panel>
      <div className="two-column-grid">
        <Panel labelledBy="data-min-title"><PanelHeader title="Data minimization" eyebrow="Locked defaults" id="data-min-title" /><ul className="policy-check-list"><li><CheckState state="pass" /><span><strong>Packet payload collection disabled</strong><small>Flow metadata only in the standard installation.</small></span></li><li><CheckState state="pass" /><span><strong>Exact field location stays local</strong><small>Regional packs are matched on the endpoint.</small></span></li><li><CheckState state="pass" /><span><strong>Operator ownership required</strong><small>Footprint assets are not investigated before verification.</small></span></li></ul></Panel>
        <Panel labelledBy="evidence-semantics-title"><PanelHeader title="Evidence semantics" eyebrow="Words have fixed meanings" id="evidence-semantics-title" /><div className="evidence-key">{(["Detected", "Verified", "Reported", "Inferred", "Suspected", "Unknown"] as const).map((value) => <div key={value}><EvidenceBadge value={value} /><p>{{ Detected: "Observed directly by an authorized endpoint or gateway.", Verified: "Confirmed by trusted review or multiple reliable sources.", Reported: "Supplied by a public source or community report.", Inferred: "Calculated from observable conditions.", Suspected: "Possible active event; evidence is not conclusive.", Unknown: "AntiFlock lacks sufficient visibility." }[value]}</p></div>)}</div></Panel>
      </div>
    </div>
  );
}

export function SectionView({ section }: { section: DashboardSection }) {
  const { mode, error, refresh } = useDashboard();
  if (mode === "error" && section !== "settings") return <ErrorState error={error} onRetry={() => void refresh()} />;
  switch (section) {
    case "overview": return <OverviewView />;
    case "network": return <TopologyView />;
    case "path": return <PathView />;
    case "activity": return <ActivityView />;
    case "findings": return <FindingsView />;
    case "devices": return <DevicesView />;
    case "policies": return <PoliciesView />;
    case "actions": return <ActionsView />;
    case "field":
    case "intelligence": return <FieldView />;
    case "footprint": return <FootprintView />;
    case "scrambler": return <ScramblerView />;
    case "settings": return <SettingsView />;
    default: return <OverviewView />;
  }
}
