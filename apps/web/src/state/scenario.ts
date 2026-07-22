import type { DashboardData, ProtectionState, TimelineEvent } from "../api/contracts";
import { createDemoData } from "../test-fixtures/demo";

export type ScenarioStage = "protected" | "joining" | "verifying" | "exposed" | "restoring" | "bypassed" | "recovered";

export interface ScenarioState {
  stage: ScenarioStage;
  step: number;
  label: string;
}

export const initialScenario: ScenarioState = {
  stage: "exposed",
  step: 4,
  label: "Protected traffic paused",
};

export function scenarioState(stage: ScenarioStage): ScenarioState {
  const states: Record<ScenarioStage, ScenarioState> = {
    protected: { stage, step: 0, label: "Ready to replay" },
    joining: { stage, step: 1, label: "Untrusted network joined" },
    verifying: { stage, step: 2, label: "Verifying required controls" },
    exposed: { stage, step: 4, label: "Protected traffic paused" },
    restoring: { stage, step: 5, label: "Restoring the approved route" },
    bypassed: { stage, step: 6, label: "One scoped action allowed" },
    recovered: { stage, step: 7, label: "Protection verified; held action released" },
  };
  return states[stage];
}

function nowEvent(id: string, kind: string, title: string, summary: string, reasonCode?: string): TimelineEvent {
  const timestamp = new Date().toISOString();
  return {
    id: `${id}-${timestamp}`,
    kind,
    title,
    summary,
    observedAt: timestamp,
    receivedAt: timestamp,
    evidenceClass: "Detected",
    confidence: 1,
    severity: kind.includes("failed") || kind.includes("held") ? "high" : "info",
    nodeId: "pixel-9",
    reasonCode,
  };
}

export function dataForScenario(stage: ScenarioStage, previous?: DashboardData): DashboardData {
  if (stage === "protected") {
    return createDemoData("PROTECTED");
  }
  if (stage === "joining") {
    const next = createDemoData("VERIFYING");
    next.posture.summary = "The phone joined an untrusted network. Cached policy verification has started locally.";
    next.posture.reasonCode = "AF-NET-UNTRUSTED";
    next.events = [
      nowEvent("scenario-join", "network.wifi_changed", "Joined an untrusted network", "Rook & Pine Coffee is not in the trusted network inventory."),
      ...(previous?.events ?? next.events),
    ];
    return next;
  }
  if (stage === "verifying" || stage === "restoring") {
    const next = createDemoData("VERIFYING");
    next.posture.summary = stage === "restoring"
      ? "AntiFlock is reconnecting the mesh, selecting the approved exit, and rechecking DNS and egress identity."
      : "AntiFlock is checking the mesh interface, approved exit, DNS path, external identity, and recovery endpoint.";
    next.events = [
      nowEvent(
        stage === "restoring" ? "scenario-restore" : "scenario-verify",
        stage === "restoring" ? "mesh.recovery_started" : "posture.verifying",
        stage === "restoring" ? "Shield restoration started" : "Protection verification started",
        next.posture.summary,
      ),
      ...(previous?.events ?? next.events),
    ];
    return next;
  }
  if (stage === "exposed") {
    const next = createDemoData("EXPOSED");
    next.events = previous
      ? [
          nowEvent("scenario-held", "action.held", "Sensitive action held", "Aether Code request is held locally until the approved route is restored.", "AF-PATH-001"),
          nowEvent("scenario-exposed", "finding.opened", "Protection interrupted", "The approved secure route is unavailable on an untrusted network.", "AF-PATH-001"),
          ...previous.events,
        ]
      : next.events;
    return next;
  }
  if (stage === "recovered") {
    const next = createDemoData("PROTECTED");
    next.actions[0] = { ...next.actions[0], decision: "ALLOW", reasonCodes: ["AF-OK-000"] };
    next.events = [
      nowEvent("scenario-release", "action.allowed", "Held action released", "Aether Code request proceeded after the path was verified."),
      nowEvent("scenario-protected", "posture.changed", "Protection restored", "Mesh, DNS, and external egress identity all match the Shielded policy.", "AF-OK-000"),
      ...(previous?.events ?? next.events),
    ];
    return next;
  }

  const next = createDemoData("EXPOSED");
  const expires = new Date(Date.now() + 5 * 60_000).toISOString();
  next.actions[0] = {
    ...next.actions[0],
    decision: "ALLOW_ONCE",
    reasonCodes: ["USER-SCOPED-BYPASS", "AF-PATH-001"],
    expiresAt: expires,
  };
  next.overview.heldActions = 0;
  next.events = [
    nowEvent(
      "scenario-bypass",
      "action.bypassed",
      "One action authorized",
      "A narrow exception allows only Aether Code → api.github.com for this action. Protection remains otherwise fail closed.",
      "USER-SCOPED-BYPASS",
    ),
    ...(previous?.events ?? next.events),
  ];
  return next;
}

export function protectionStateForStage(stage: ScenarioStage): ProtectionState {
  if (stage === "protected" || stage === "recovered") return "PROTECTED";
  if (stage === "joining" || stage === "verifying" || stage === "restoring") return "VERIFYING";
  return "EXPOSED";
}
