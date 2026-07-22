import Link from "next/link";
import type { ReactNode } from "react";
import type { EvidenceClass, ProtectionState, Severity } from "../api/contracts";

export function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.getTime() === 0) return "Not reported";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

export function confidence(value: number): string {
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

export function Panel({ children, className = "", labelledBy }: { children: ReactNode; className?: string; labelledBy?: string }) {
  return <section className={`panel ${className}`} aria-labelledby={labelledBy}>{children}</section>;
}

export function PanelHeader({ title, eyebrow, action, id }: { title: string; eyebrow?: string; action?: ReactNode; id?: string }) {
  return (
    <header className="panel-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h2 id={id}>{title}</h2>
      </div>
      {action && <div className="panel-header-action">{action}</div>}
    </header>
  );
}

export function EvidenceBadge({ value }: { value: EvidenceClass }) {
  return <span className={`evidence-badge evidence-${value.toLowerCase()}`}>{value}</span>;
}

export function StateBadge({ value }: { value: ProtectionState | string }) {
  return <span className={`state-badge state-${value.toLowerCase().replaceAll(" ", "-")}`}>{value}</span>;
}

export function SeverityBadge({ value }: { value: Severity }) {
  return <span className={`severity-badge severity-${value}`}>{value}</span>;
}

export function Metric({ label, value, detail, state = "neutral" }: { label: string; value: ReactNode; detail: string; state?: "neutral" | "good" | "warn" | "bad" }) {
  return (
    <div className={`metric metric-${state}`}>
      <span className="metric-label">{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

export function EmptyState({ title, text, action }: { title: string; text: string; action?: ReactNode }) {
  return (
    <div className="empty-state" role="status">
      <span className="empty-symbol" aria-hidden="true">&empty;</span>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}

export function KeyValue({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="key-value">
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </div>
  );
}

export function CheckState({ state }: { state: "pass" | "fail" | "warning" | "unknown" | "pending" }) {
  const label = { pass: "Pass", fail: "Fail", warning: "Warning", unknown: "Unknown", pending: "Pending" }[state];
  return <span className={`check-state check-${state}`}><span aria-hidden="true" />{label}</span>;
}

export function ErrorState({ error, onRetry }: { error: string | null; onRetry: () => void }) {
  return (
    <div className="error-state" role="alert">
      <p className="eyebrow">Visibility unknown</p>
      <h2>No current Core projections are available</h2>
      <p>AntiFlock cannot determine the protection state from the web dashboard alone. No live conclusion is being inferred from cached or sample data.</p>
      {error && <code>{error}</code>}
      <div className="button-row">
        <button className="button button-primary" type="button" onClick={onRetry}>Retry Core</button>
        <Link className="button button-quiet" href="/settings">Review connection settings</Link>
      </div>
    </div>
  );
}
