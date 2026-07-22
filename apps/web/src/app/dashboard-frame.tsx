"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import type { DashboardSection } from "../api/contracts";
import { useDashboard } from "../state/dashboard-context";

interface NavItem {
  section: DashboardSection;
  label: string;
  code: string;
  group: "Command" | "Inspect" | "Control" | "Intelligence";
}

const NAV_ITEMS: NavItem[] = [
  { section: "overview", label: "Overview", code: "OV", group: "Command" },
  { section: "network", label: "Network", code: "NW", group: "Inspect" },
  { section: "path", label: "Path", code: "PT", group: "Inspect" },
  { section: "activity", label: "Activity", code: "AC", group: "Inspect" },
  { section: "findings", label: "Findings", code: "FD", group: "Inspect" },
  { section: "devices", label: "Devices", code: "DV", group: "Control" },
  { section: "policies", label: "Policies", code: "PL", group: "Control" },
  { section: "actions", label: "Actions", code: "AT", group: "Control" },
  { section: "field", label: "Field Intel", code: "FI", group: "Intelligence" },
  { section: "footprint", label: "Footprint", code: "FP", group: "Intelligence" },
  { section: "scrambler", label: "Scrambler", code: "SC", group: "Intelligence" },
  { section: "settings", label: "Settings", code: "ST", group: "Intelligence" },
];

const DESCRIPTIONS: Record<DashboardSection, string> = {
  overview: "Current protection, environment, and decisions",
  network: "Operator-centered topology and observed relationships",
  path: "Application-to-destination route evidence",
  activity: "Normalized event and audit timeline",
  findings: "Explainable conditions with source evidence",
  devices: "Enrolled endpoints, agents, and capabilities",
  policies: "Intent, enforcement scope, and dry-run controls",
  actions: "Held, allowed, blocked, and bypassed requests",
  field: "Nearby reported infrastructure and data freshness",
  intelligence: "Nearby reported infrastructure and data freshness",
  footprint: "Verified operator-owned public exposure",
  scrambler: "Simulated state mutation with verification and rollback",
  settings: "Core connection and local display behavior",
};

function currentSection(pathname: string): DashboardSection {
  const candidate = pathname.split("/").filter(Boolean)[0] ?? "overview";
  if (candidate === "intelligence") return "field";
  return NAV_ITEMS.some((item) => item.section === candidate) ? (candidate as DashboardSection) : "overview";
}

function SourceBanner() {
  const { mode, error, failedEndpoints, streamStatus } = useDashboard();
  const copy = {
    checking: {
      label: "CHECKING CORE",
      text: "Establishing the source of truth. Values below remain marked until the Core response is known.",
    },
    live: {
      label: "LIVE CORE",
      text: `Dashboard projections are live. Event stream: ${streamStatus}.`,
    },
    partial: {
      label: "PARTIAL LIVE",
      text: `${failedEndpoints.length} projection${failedEndpoints.length === 1 ? "" : "s"} unavailable. Missing areas are marked unavailable; no sample value is presented as live telemetry.`,
    },
    demo: {
      label: "DEMO SCENARIO",
      text: "Core is unavailable. Showing deterministic coffee-shop fixtures. These values are not live observations and do not describe your network.",
    },
    error: {
      label: "NO DATA",
      text: "Core is unavailable and demo fallback is disabled. No current protection conclusion can be made.",
    },
  }[mode];

  return (
    <div className={`source-banner source-${mode}`} role={mode === "error" ? "alert" : "status"}>
      <span className="source-label">{copy.label}</span>
      <span>{copy.text}</span>
      {error && mode !== "live" && <span className="source-detail">Detail: {error}</span>}
    </div>
  );
}

export function DashboardFrame({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const section = currentSection(pathname);
  const {
    data,
    mode,
    streamStatus,
    isLoading,
    refresh,
    replayCoffeeShop,
    commandFeedback,
    clearFeedback,
  } = useDashboard();

  const groups: NavItem["group"][] = ["Command", "Inspect", "Control", "Intelligence"];
  const title = NAV_ITEMS.find((item) => item.section === section)?.label ?? "Overview";

  return (
    <div className="dashboard-shell" data-mode={mode} data-posture={data.posture.state.toLowerCase()}>
      <a className="skip-link" href="#main-content">Skip to dashboard content</a>
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true"><span>AF</span></span>
          <span>
            <strong>AntiFlock</strong>
            <small>Third-Eye Console</small>
          </span>
        </div>

        <nav className="primary-nav">
          {groups.map((group) => (
            <div className="nav-group" key={group}>
              <p className="nav-group-label">{group}</p>
              {NAV_ITEMS.filter((item) => item.group === group).map((item) => {
                const active = item.section === section || (item.section === "field" && pathname.startsWith("/intelligence"));
                const href = item.section === "overview" ? "/" : `/${item.section}`;
                const badge = item.section === "findings"
                  ? data.findings.filter((finding) => finding.status === "open").length
                  : item.section === "actions"
                    ? data.actions.filter((action) => action.decision === "HOLD").length
                    : null;
                return (
                  <Link href={href} className="nav-link" aria-current={active ? "page" : undefined} key={item.section}>
                    <span className="nav-code" aria-hidden="true">{item.code}</span>
                    <span>{item.label}</span>
                    {badge !== null && badge > 0 && <span className="nav-badge" aria-label={`${badge} open`}>{badge}</span>}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-status">
          <div className="sidebar-status-row">
            <span className={`status-dot dot-${mode}`} aria-hidden="true" />
            <span>{mode === "demo" ? "Local demonstration" : mode === "live" ? "Core connected" : mode === "partial" ? "Core partially connected" : "Checking Core"}</span>
          </div>
          <div className="sidebar-status-row subtle">
            <span className="mini-code" aria-hidden="true">EV</span>
            <span>Stream {streamStatus}</span>
          </div>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="page-heading">
            <div className="eyebrow">Aether home domain / {section}</div>
            <h1>{title}</h1>
            <p>{DESCRIPTIONS[section]}</p>
          </div>
          <div className="topbar-actions">
            {mode === "demo" && (
              <button className="button button-quiet" type="button" onClick={replayCoffeeShop}>
                Replay coffee-shop incident
              </button>
            )}
            <button className="button button-icon" type="button" onClick={() => void refresh()} disabled={isLoading} aria-label="Refresh dashboard projections">
              <span aria-hidden="true">↻</span>
              <span>{isLoading ? "Checking" : "Refresh"}</span>
            </button>
            <div className={`posture-chip posture-${data.posture.state.toLowerCase()}`}>
              <span className="status-dot" aria-hidden="true" />
              <span>{data.posture.state}</span>
            </div>
          </div>
        </header>

        <SourceBanner />
        {isLoading && <div className="loading-line" role="progressbar" aria-label="Loading dashboard projections" />}
        {commandFeedback && (
          <div className={`command-feedback feedback-${commandFeedback.kind}`} role={commandFeedback.kind === "error" ? "alert" : "status"}>
            <span>{commandFeedback.message}</span>
            <button type="button" onClick={clearFeedback} aria-label="Dismiss message">×</button>
          </div>
        )}

        <main id="main-content" className="dashboard-content" aria-busy={isLoading}>
          {children}
        </main>
      </div>
    </div>
  );
}
