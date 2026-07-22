import type {
  DashboardData,
  DeviceNode,
  EvidenceClass,
  FieldReport,
  Finding,
  FootprintAsset,
  FootprintRelationship,
  LiveEventEnvelope,
  NetworkPath,
  Posture,
  ProtectionState,
  ScramblerState,
  TimelineEvent,
  TopologyEdge,
} from "./contracts";
import { createDemoData } from "../test-fixtures/demo";

export const REST_ENDPOINTS = {
  overview: "/v1/overview",
  nodes: "/v1/nodes",
  topology: "/v1/topology",
  paths: "/v1/paths",
  events: "/v1/events?limit=100",
  findings: "/v1/findings",
  posture: "/v1/posture",
  actions: "/v1/actions?limit=100",
  fieldReports: "/v1/field/reports",
  footprint: "/v1/footprint",
  scrambler: "/v1/scrambler/state",
} as const;

export const COMMAND_ENDPOINTS = {
  enrollmentToken: "/v1/enrollment/tokens",
  validatePolicy: "/v1/policies/validate",
  compilePolicy: "/v1/policies/compile",
  applyPlan: (id: string) => `/v1/plans/${encodeURIComponent(id)}/apply`,
  rollbackPlan: (id: string) => `/v1/plans/${encodeURIComponent(id)}/rollback`,
  evaluateAction: "/v1/actions/evaluate",
  authorizeAction: (id: string) => `/v1/actions/${encodeURIComponent(id)}/authorize`,
  fieldReports: "/v1/field/reports",
  footprintAssets: "/v1/footprint/assets",
  simulateScrambler: "/v1/scrambler/simulate",
  activateScrambler: "/v1/scrambler/activate",
} as const;

const STREAM_TOPICS = [
  "posture.changed",
  "finding.opened",
  "finding.resolved",
  "node.changed",
  "path.changed",
  "action.held",
  "scrambler.changed",
];

type UnknownRecord = Record<string, unknown>;

export interface DashboardLoadResult {
  data: DashboardData;
  mode: "live" | "partial";
  successfulEndpoints: string[];
  failedEndpoints: string[];
}

function record(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as UnknownRecord) : {};
}

function first(source: UnknownRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null) return source[key];
  }
  return undefined;
}

function stringValue(source: UnknownRecord, keys: string[], fallback: string): string {
  const value = first(source, ...keys);
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function numberValue(source: UnknownRecord, keys: string[], fallback: number): number {
  const value = first(source, ...keys);
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function booleanValue(source: UnknownRecord, keys: string[], fallback: boolean): boolean {
  const value = first(source, ...keys);
  return typeof value === "boolean" ? value : fallback;
}

function list(value: unknown, ...keys: string[]): unknown[] {
  if (Array.isArray(value)) return value;
  const source = record(value);
  for (const key of keys) {
    if (Array.isArray(source[key])) return source[key] as unknown[];
  }
  return [];
}

function evidenceClass(value: unknown, fallback: EvidenceClass = "Unknown"): EvidenceClass {
  if (typeof value !== "string") return fallback;
  const lastToken = value.split("_").at(-1) ?? value;
  const normalized = lastToken.slice(0, 1).toUpperCase() + lastToken.slice(1).toLowerCase();
  return ["Detected", "Verified", "Reported", "Inferred", "Suspected", "Unknown"].includes(normalized)
    ? (normalized as EvidenceClass)
    : fallback;
}

function protectionState(value: unknown, fallback: ProtectionState): ProtectionState {
  if (typeof value !== "string") return fallback;
  const normalized = value.toUpperCase().replace("PROTECTION_STATE_", "");
  if (normalized === "UNAVAILABLE") return "UNKNOWN";
  return ["PROTECTED", "DEGRADED", "SUSPICIOUS", "EXPOSED", "UNKNOWN", "VERIFYING"].includes(normalized)
    ? (normalized as ProtectionState)
    : fallback;
}

function enumToken(value: unknown, fallback: string): string {
  if (typeof value !== "string" || !value) return fallback;
  return value.split("_").at(-1)?.toLowerCase() ?? fallback;
}

export function createUnknownLiveData(): DashboardData {
  const data = createDemoData("UNKNOWN");
  data.overview = {
    operatorName: "Local operator",
    deploymentName: "AntiFlock deployment",
    environment: {
      name: "Not reported by Core",
      type: "unknown",
      trust: "unknown",
      security: "Unknown",
      known: false,
      gateway: "Not reported",
      changedAt: new Date(0).toISOString(),
    },
    protectedDevices: 0,
    totalDevices: 0,
    openFindings: 0,
    heldActions: 0,
    currentExit: "Not reported by Core",
    exitVerified: false,
    dnsState: "unknown",
    dnsResolver: "Not reported by Core",
    scramblerState: "Not reported by Core",
  };
  data.posture = {
    state: "UNKNOWN",
    reasonCode: "AF-VISIBILITY-UNKNOWN",
    summary: "Core has not supplied enough current telemetry to evaluate protection.",
    evaluatedAt: new Date(0).toISOString(),
    confidence: 0,
    evidenceClass: "Unknown",
    checks: [],
  };
  data.nodes = [];
  data.paths = [];
  data.topology = [];
  data.events = [];
  data.findings = [];
  data.actions = [];
  data.policies = [];
  data.fieldReports = [];
  data.footprintAssets = [];
  data.footprintRelationships = [];
  data.scrambler = {
    state: "IDLE",
    profile: "Not reported",
    stateId: "Unknown",
    currentExit: "Not reported by Core",
    lastTransitionAt: new Date(0).toISOString(),
    simulationOnly: true,
    risk: "high",
    checks: [],
  };
  return data;
}

function timestamp(source: UnknownRecord, fallback: string): string {
  return stringValue(source, ["observed_at", "observedAt", "updated_at", "updatedAt", "timestamp"], fallback);
}

export function normalizePosture(value: unknown, fallback: Posture): Posture {
  const source = record(record(value).posture ?? value);
  const reasons = list(first(source, "reasons"));
  const primaryReason = record(reasons[0]);
  const checksRaw = list(first(source, "checks", "controls", "reasons"));
  const state = protectionState(first(source, "state", "protection_state", "protectionState"), fallback.state);
  return {
    ...fallback,
    state,
    reasonCode: stringValue(source, ["reason_code", "reasonCode", "primary_reason"], stringValue(primaryReason, ["reason_code", "rule_id"], fallback.reasonCode)),
    summary: stringValue(source, ["summary", "explanation"], stringValue(primaryReason, ["summary", "current_fact", "claim"], fallback.summary)),
    evaluatedAt: stringValue(source, ["evaluated_at", "evaluatedAt", "updated_at"], fallback.evaluatedAt),
    confidence: numberValue(source, ["confidence"], fallback.confidence),
    evidenceClass: evidenceClass(first(source, "classification", "evidence_class", "evidenceClass"), fallback.evidenceClass),
    checks: checksRaw.length
      ? checksRaw.map((item, index) => {
          const check = record(item);
          const rawState = stringValue(check, ["state", "status"], "unknown").toLowerCase();
          return {
            id: stringValue(check, ["id", "rule_id", "reason_code"], `check-${index}`),
            label: stringValue(check, ["label", "name", "reason_code", "rule_id"], "Unnamed control"),
            state: (["pass", "fail", "warning", "unknown"].includes(rawState) ? rawState : state === "PROTECTED" ? "pass" : state === "UNKNOWN" ? "unknown" : "fail") as "pass" | "fail" | "warning" | "unknown",
            observed: stringValue(check, ["observed", "current_fact", "actual", "claim"], "No observation supplied"),
            expected: stringValue(check, ["expected", "expected_fact"], "No expected value supplied"),
            evidenceClass: evidenceClass(first(check, "classification", "evidence_class")),
            checkedAt: stringValue(check, ["checked_at", "observed_at"], fallback.evaluatedAt),
          };
        })
      : fallback.checks,
  };
}

function normalizeNodes(value: unknown, fallback: DeviceNode[]): DeviceNode[] {
  const values = list(value, "nodes", "items");
  if (!values.length) return [];
  return values.map((item, index) => {
    const node = record(item);
    const fallbackNode = fallback[index % Math.max(fallback.length, 1)];
    const kind = stringValue(node, ["kind", "node_type", "type"], fallbackNode?.kind ?? "device");
    const normalizedKind = ["phone", "laptop", "desktop", "gateway", "server", "agent", "router"].includes(kind) ? kind : "agent";
    return {
      id: stringValue(node, ["id", "node_id"], `node-${index}`),
      name: stringValue(node, ["name", "display_name", "hostname"], "Unnamed node"),
      kind: normalizedKind as DeviceNode["kind"],
      platform: stringValue(node, ["platform", "os", "operating_system"], "Unknown platform"),
      state: enumToken(first(node, "state", "connection_state", "status"), "stale") as DeviceNode["state"],
      protection: protectionState(first(node, "protection", "protection_state"), "UNKNOWN"),
      lastSeen: stringValue(node, ["last_seen", "lastSeen", "updated_at"], new Date(0).toISOString()),
      network: stringValue(node, ["network", "network_name"], "Unknown network"),
      meshAddress: stringValue(node, ["mesh_address", "meshAddress", "address"], "Not reported"),
      agentVersion: stringValue(node, ["agent_version", "agentVersion"], "Unknown"),
      capabilities: list(first(node, "capabilities")).filter((entry): entry is string => typeof entry === "string"),
      tags: list(first(node, "tags")).filter((entry): entry is string => typeof entry === "string"),
    };
  });
}

function normalizeEvents(value: unknown): TimelineEvent[] {
  const values = list(value, "events", "items");
  if (!values.length) return [];
  return values.map((item, index) => {
    const event = record(item);
    const payload = record(first(event, "payload", "data"));
    const kind = stringValue(event, ["kind", "type"], "event.unknown");
    const observedAt = timestamp(event, new Date(0).toISOString());
    return {
      id: stringValue(event, ["id", "event_id"], `event-${index}`),
      kind,
      title: stringValue(payload, ["title"], stringValue(event, ["title"], kind.replaceAll(".", " "))),
      summary: stringValue(payload, ["summary", "message"], stringValue(event, ["summary", "message"], "No event explanation supplied.")),
      observedAt,
      receivedAt: stringValue(event, ["received_at", "receivedAt"], observedAt),
      evidenceClass: evidenceClass(first(event, "classification", "evidence_class"), "Detected"),
      confidence: numberValue(event, ["confidence"], 1),
      severity: enumToken(first(event, "severity"), "info") as TimelineEvent["severity"],
      nodeId: stringValue(event, ["node_id", "nodeId"], "") || undefined,
      reasonCode: stringValue(payload, ["reason_code", "reasonCode"], "") || undefined,
    };
  });
}

function normalizeFindings(value: unknown, fallback: Finding[]): Finding[] {
  const values = list(value, "findings", "active_findings", "items");
  if (!values.length) return [];
  return values.map((item, index) => {
    const finding = record(item);
    const metadata = record(first(finding, "metadata"));
    const fallbackFinding = fallback[index % Math.max(fallback.length, 1)];
    const evidence = list(first(finding, "evidence", "evidence_items") ?? first(metadata, "evidence"));
    return {
      id: stringValue(finding, ["id", "finding_id"], `finding-${index}`),
      ruleId: stringValue(finding, ["rule_id", "ruleId", "reason_code"], "AF-UNKNOWN"),
      title: stringValue(finding, ["title", "name"], "Unlabeled finding"),
      condition: stringValue(finding, ["condition", "summary", "current_fact", "claim"], "Core did not supply a condition explanation."),
      consequence: stringValue(finding, ["consequence", "impact"], "Consequence not supplied."),
      recommendation: stringValue(finding, ["recommendation", "recommended_action"], "Review the underlying evidence before acting."),
      falsePositiveNote: stringValue(finding, ["false_positive_note", "uncertainty"], "The available evidence may be incomplete."),
      status: enumToken(first(finding, "status"), "open") as Finding["status"],
      severity: enumToken(first(finding, "severity"), "medium") as Finding["severity"],
      classification: evidenceClass(first(finding, "classification", "evidence_class") ?? first(metadata, "classification")),
      confidence: numberValue(finding, ["confidence"], numberValue(metadata, ["confidence"], 0)),
      firstSeen: stringValue(finding, ["first_seen", "firstSeen", "first_seen_at"], new Date(0).toISOString()),
      lastSeen: stringValue(finding, ["last_seen", "lastSeen", "last_seen_at", "updated_at"], new Date(0).toISOString()),
      evidence: evidence.length
        ? evidence.map((entry, evidenceIndex) => {
            const itemRecord = record(entry);
            return {
              id: stringValue(itemRecord, ["id", "evidence_id"], `evidence-${evidenceIndex}`),
              label: stringValue(itemRecord, ["label", "type"], "Evidence"),
              value: stringValue(itemRecord, ["value", "summary"], "No value supplied"),
              source: stringValue(itemRecord, ["source", "source_name"], "Unknown source"),
              observedAt: stringValue(itemRecord, ["observed_at", "observedAt"], new Date(0).toISOString()),
              lastVerifiedAt: stringValue(itemRecord, ["last_verified_at", "lastVerifiedAt"], new Date(0).toISOString()),
              evidenceClass: evidenceClass(first(itemRecord, "classification", "evidence_class")),
              confidence: numberValue(itemRecord, ["confidence"], 0),
              expiresAt: stringValue(itemRecord, ["expires_at", "expiresAt"], "") || undefined,
            };
          })
        : fallbackFinding?.evidence ?? [],
    };
  });
}

function normalizePaths(value: unknown, fallback: NetworkPath[]): NetworkPath[] {
  const values = list(value, "paths", "items");
  if (!values.length) return [];
  return values.map((item, index) => {
    const path = record(item);
    const fallbackPath = fallback[index % Math.max(fallback.length, 1)];
    const segments = list(first(path, "segments", "hops"));
    const checks = list(first(path, "checks"));
    const pathState = stringValue(path, ["state", "status"], "UNKNOWN").toUpperCase();
    const normalizedPathState: NetworkPath["state"] = pathState === "PROTECTED"
      ? "active"
      : pathState === "EXPOSED"
        ? "blocked"
        : ["DEGRADED", "SUSPICIOUS", "VERIFYING"].includes(pathState)
          ? "held"
          : "unknown";
    const checkForRole = (role: string): UnknownRecord => {
      const expected = ({ LOCAL_NETWORK: "local-network", ROUTE: "route", MESH_EXIT: "mesh", DNS: "dns" } as Record<string, string>)[role];
      return record(checks.find((candidate) => stringValue(record(candidate), ["id"], "") === expected));
    };
    const segmentState = (check: UnknownRecord): NetworkPath["segments"][number]["state"] => {
      switch (stringValue(check, ["state"], "UNKNOWN").toUpperCase()) {
        case "PASS": return "trusted";
        case "FAIL": return "blocked";
        case "STALE": return "degraded";
        default: return "unknown";
      }
    };
    const segmentDetail = (segment: UnknownRecord): string => {
      const details = record(first(segment, "details"));
      const values = [
        stringValue(details, ["provider"], ""),
        stringValue(details, ["exitNodeId", "exit_node_id", "gateway", "address"], ""),
        ...list(first(details, "resolverAddresses", "resolver_addresses")).filter((entry): entry is string => typeof entry === "string"),
      ].filter(Boolean);
      return values.join(" · ") || "No additional fact was reported";
    };
    return {
      id: stringValue(path, ["id", "path_id"], `path-${index}`),
      application: stringValue(path, ["application", "application_id"], "Unknown application"),
      sourceNodeId: stringValue(path, ["source_node_id", "sourceNodeId"], "unknown-node"),
      destination: stringValue(path, ["destination", "destination_name"], "Unknown destination"),
      state: normalizedPathState,
      encrypted: typeof first(path, "encrypted") === "boolean" ? (first(path, "encrypted") as boolean) : null,
      policy: stringValue(path, ["policy", "policy_name"], "No policy reported"),
      updatedAt: stringValue(path, ["updated_at", "updatedAt", "observed_at", "observedAt"], new Date(0).toISOString()),
      segments: segments.length
        ? segments.map((entry, segmentIndex) => {
            const segment = record(entry);
            const role = stringValue(segment, ["logicalRole", "logical_role"], "").toUpperCase();
            const rawKind = ({ LOCAL_NETWORK: "device", ROUTE: "policy", MESH_EXIT: "exit", DNS: "dns" } as Record<string, string>)[role]
              ?? enumToken(first(segment, "kind", "type", "hop_type"), "relay");
            const check = checkForRole(role);
            return {
              id: stringValue(segment, ["id", "segment_id"], `segment-${segmentIndex}`),
              label: stringValue(segment, ["label", "name", "entity_id"], role ? role.replaceAll("_", " ") : "Unknown hop"),
              kind: (["application", "device", "policy", "mesh", "relay", "exit", "dns", "destination"].includes(rawKind) ? rawKind : "relay") as NetworkPath["segments"][number]["kind"],
              state: Object.keys(check).length ? segmentState(check) : "unknown",
              detail: stringValue(segment, ["detail", "summary"], segmentDetail(segment)),
              evidenceClass: evidenceClass(first(segment, "classification", "evidence_class")),
            };
          })
        : fallbackPath?.segments ?? [],
    };
  });
}

function normalizeTopology(value: unknown): TopologyEdge[] {
  const values = list(value, "relationships", "edges", "links");
  return values.map((item, index) => {
    const edge = record(item);
    const active = stringValue(edge, ["state", "status"], "UNKNOWN").toUpperCase() === "ACTIVE";
    const classification = evidenceClass(first(edge, "classification", "evidence_class"));
    return {
      id: stringValue(edge, ["id", "relationship_id", "edge_id"], `edge-${index}`),
      source: stringValue(edge, ["source", "source_id", "source_entity_id", "sourceEntityId"], "unknown-source"),
      target: stringValue(edge, ["target", "target_id", "target_entity_id", "targetEntityId"], "unknown-target"),
      label: stringValue(edge, ["label", "relationship_type", "kind", "type"], "unlabeled relationship"),
      state: active && classification === "Verified" ? "trusted" : active ? "unknown" : "degraded",
      evidenceClass: classification,
    };
  });
}

function normalizeFieldReports(value: unknown): FieldReport[] {
  const values = list(value, "reports", "field_reports", "items");
  return values.map((item, index) => {
    const report = record(item);
    const geometry = record(first(report, "geometry", "coordinates"));
    const x = numberValue(geometry, ["x", "longitude", "lng"], 50);
    const y = numberValue(geometry, ["y", "latitude", "lat"], 50);
    return {
      id: stringValue(report, ["id", "report_id"], `field-${index}`),
      category: stringValue(report, ["category", "type"], "Reported infrastructure"),
      label: stringValue(report, ["label", "title", "display_name"], "Unnamed report"),
      distance: stringValue(report, ["distance", "distance_label"], "Distance not reported"),
      locationPrecision: stringValue(report, ["location_precision", "locationPrecision", "precision"], "Precision not reported"),
      direction: stringValue(report, ["direction"], "Direction not reported"),
      classification: evidenceClass(first(report, "classification", "evidence_class"), "Reported"),
      confidence: numberValue(report, ["confidence"], 0),
      status: enumToken(first(report, "status"), "unreviewed") as FieldReport["status"],
      source: stringValue(report, ["source", "source_name"], "Source not reported"),
      observedAt: stringValue(report, ["observed_at", "observedAt"], new Date(0).toISOString()),
      lastVerifiedAt: stringValue(report, ["last_verified_at", "lastVerifiedAt"], new Date(0).toISOString()),
      expiresAt: stringValue(report, ["expires_at", "expiresAt"], new Date(0).toISOString()),
      coordinates: {
        x: Math.max(5, Math.min(95, Math.abs(x) <= 1 ? 50 + x * 35 : x)),
        y: Math.max(5, Math.min(95, Math.abs(y) <= 1 ? 50 - y * 35 : y)),
      },
    };
  });
}

function normalizeFootprint(value: unknown): { assets: FootprintAsset[]; relationships: FootprintRelationship[] } {
  const source = record(value);
  const assets = list(first(source, "assets", "entities")).map((item, index) => {
    const asset = record(item);
    return {
      id: stringValue(asset, ["id", "asset_id", "entity_id"], `asset-${index}`),
      type: stringValue(asset, ["type", "asset_type", "entity_type"], "Asset"),
      label: stringValue(asset, ["label", "display_name", "name"], "Unnamed asset"),
      verification: enumToken(first(asset, "verification", "verification_status", "ownership_status"), "unverified") as FootprintAsset["verification"],
      exposure: enumToken(first(asset, "exposure", "exposure_state", "visibility"), "unknown") as FootprintAsset["exposure"],
      lastCheckedAt: stringValue(asset, ["last_checked_at", "lastCheckedAt", "updated_at"], new Date(0).toISOString()),
      findings: numberValue(asset, ["findings", "finding_count"], 0),
    };
  });
  const relationships = list(first(source, "relationships", "edges")).map((item, index) => {
    const relationship = record(item);
    return {
      id: stringValue(relationship, ["id", "relationship_id"], `footprint-edge-${index}`),
      source: stringValue(relationship, ["source", "source_id", "source_entity_id"], "unknown-source"),
      target: stringValue(relationship, ["target", "target_id", "target_entity_id"], "unknown-target"),
      label: stringValue(relationship, ["label", "relationship_type", "kind"], "unlabeled relationship"),
      classification: evidenceClass(first(relationship, "classification", "evidence_class")),
    };
  });
  return { assets, relationships };
}

function normalizeScrambler(value: unknown, fallback: ScramblerState): ScramblerState {
  const source = record(record(value).scrambler ?? value);
  const checks = list(first(source, "checks", "verifications"));
  const rawState = stringValue(source, ["state"], fallback.state).toUpperCase().replace("SCRAMBLER_STATE_", "");
  const allowedStates = ["IDLE", "PLANNING", "PREFLIGHT", "DRAINING", "APPLYING", "VERIFYING", "ACTIVE", "ROLLING_BACK"];
  return {
    ...fallback,
    state: (allowedStates.includes(rawState) ? rawState : "IDLE") as ScramblerState["state"],
    profile: stringValue(source, ["profile", "profile_name"], fallback.profile),
    stateId: stringValue(source, ["state_id", "stateId", "id"], fallback.stateId),
    currentExit: stringValue(source, ["current_exit", "currentExit", "exit_node"], fallback.currentExit),
    proposedExit: stringValue(source, ["proposed_exit", "proposedExit", "candidate_exit"], "") || undefined,
    lastTransitionAt: stringValue(source, ["last_transition_at", "lastTransitionAt", "updated_at"], fallback.lastTransitionAt),
    simulationOnly: booleanValue(source, ["simulation_only", "simulationOnly"], fallback.simulationOnly),
    risk: enumToken(first(source, "risk", "risk_level"), fallback.risk) as ScramblerState["risk"],
    checks: checks.map((item, index) => {
      const check = record(item);
      return {
        id: stringValue(check, ["id", "check_id"], `scrambler-check-${index}`),
        label: stringValue(check, ["label", "name"], "Unnamed verification"),
        state: enumToken(first(check, "state", "status"), "unknown") as ScramblerState["checks"][number]["state"],
      };
    }),
  };
}

function normalizeActions(value: unknown): DashboardData["actions"] {
  return list(value, "actions", "items").map((item, index) => {
    const action = record(item);
    const scope = record(first(action, "scope"));
    const authorization = record(first(action, "oneTimeAuthorization", "one_time_authorization"));
    const destinations = list(first(scope, "destinations"))
      .filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
    const maximumExpiresAt = stringValue(authorization, ["maximumExpiresAt", "maximum_expires_at"], "");
    return {
      id: stringValue(action, ["actionId", "action_id", "id"], `action-${index}`),
      operationId: stringValue(action, ["operationId", "operation_id"], ""),
      application: stringValue(action, ["applicationId", "application_id", "application"], "Unknown application"),
      nodeId: stringValue(action, ["nodeId", "node_id"], ""),
      actionType: stringValue(scope, ["actionType", "action_type"], "Unknown action"),
      destination: destinations.join(", ") || "No destination reported",
      destinations,
      dataClass: stringValue(scope, ["dataClass", "data_class"], "Unknown"),
      decision: stringValue(action, ["decision"], "HOLD") as DashboardData["actions"][number]["decision"],
      reasonCodes: list(first(action, "reasonCodes", "reason_codes")).filter((entry): entry is string => typeof entry === "string"),
      createdAt: stringValue(action, ["createdAt", "created_at"], new Date(0).toISOString()),
      expiresAt: stringValue(action, ["expiresAt", "expires_at"], "") || undefined,
      oneTimeAuthorization: Object.keys(authorization).length
        ? {
            enabled: booleanValue(authorization, ["enabled"], false),
            maximumExpiresAt,
            consentReasonCode: stringValue(authorization, ["consentReasonCode", "consent_reason_code"], ""),
          }
        : undefined,
    };
  });
}

async function fetchProjection(baseUrl: string, path: string, signal: AbortSignal): Promise<unknown> {
  const response = await fetch(resolveUrl(baseUrl, path), {
    headers: { Accept: "application/json" },
    credentials: "same-origin",
    signal,
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) throw new Error("response was not JSON");
  return response.json();
}

export function resolveUrl(baseUrl: string, path: string): string {
  const trimmed = baseUrl.trim().replace(/\/$/, "");
  return `${trimmed}${path}` || path;
}

export async function loadDashboard(baseUrl: string, signal: AbortSignal): Promise<DashboardLoadResult> {
  const entries = Object.entries(REST_ENDPOINTS);
  const results = await Promise.allSettled(entries.map(([, path]) => fetchProjection(baseUrl, path, signal)));
  const payloads = new Map<string, unknown>();
  const successfulEndpoints: string[] = [];
  const failedEndpoints: string[] = [];

  results.forEach((result, index) => {
    const [key, path] = entries[index];
    if (result.status === "fulfilled") {
      payloads.set(key, result.value);
      successfulEndpoints.push(path);
    } else {
      failedEndpoints.push(path);
    }
  });

  if (successfulEndpoints.length === 0) {
    throw new Error("AntiFlock Core did not return any dashboard projections.");
  }

  const overviewPayload = record(payloads.get("overview"));
  const overviewPosture = record(first(overviewPayload, "posture", "protection"));
  const postureState = protectionState(first(record(payloads.get("posture")), "state", "protection_state"), protectionState(first(overviewPosture, "state", "protection_state"), "UNKNOWN"));
  const data = createUnknownLiveData();
  data.posture.state = postureState;

  if (payloads.has("posture") || first(overviewPayload, "posture")) {
    data.posture = normalizePosture(payloads.get("posture") ?? overviewPosture, data.posture);
  }
  if (payloads.has("nodes") || first(overviewPayload, "nodes")) {
    data.nodes = normalizeNodes(payloads.get("nodes") ?? first(overviewPayload, "nodes"), data.nodes);
  }
  if (payloads.has("events") || first(overviewPayload, "recent_events")) {
    data.events = normalizeEvents(payloads.get("events") ?? first(overviewPayload, "recent_events"));
  }
  if (payloads.has("findings") || first(overviewPayload, "active_findings")) {
    data.findings = normalizeFindings(payloads.get("findings") ?? first(overviewPayload, "active_findings"), data.findings);
  }
  if (payloads.has("actions")) {
    data.actions = normalizeActions(payloads.get("actions"));
  }
  if (payloads.has("paths") || first(overviewPayload, "current_path")) {
    const rawPaths = payloads.get("paths") ?? { paths: [first(overviewPayload, "current_path")] };
    data.paths = normalizePaths(rawPaths, data.paths);
  }
  if (payloads.has("topology")) {
    data.topology = normalizeTopology(payloads.get("topology"));
  }
  if (payloads.has("fieldReports")) {
    data.fieldReports = normalizeFieldReports(payloads.get("fieldReports"));
  }
  if (payloads.has("footprint")) {
    const footprint = normalizeFootprint(payloads.get("footprint"));
    data.footprintAssets = footprint.assets;
    data.footprintRelationships = footprint.relationships;
  }
  if (payloads.has("scrambler") || first(overviewPayload, "scrambler")) {
    data.scrambler = normalizeScrambler(payloads.get("scrambler") ?? first(overviewPayload, "scrambler"), data.scrambler);
  }

  const overview = record(first(overviewPayload, "overview") ?? overviewPayload);
  const environment = record(first(overview, "environment", "current_environment"));
  const rawEnvironmentType = enumToken(first(environment, "type", "network_type"), "unknown");
  const rawTrust = enumToken(first(environment, "trust", "trust_state"), "unknown");
  data.overview = {
    ...data.overview,
    operatorName: stringValue(overview, ["operator_name", "operatorName"], data.overview.operatorName),
    deploymentName: stringValue(overview, ["deployment_name", "deploymentName"], data.overview.deploymentName),
    protectedDevices: numberValue(overview, ["protected_devices", "protectedDevices"], data.nodes.filter((node) => node.protection === "PROTECTED").length),
    totalDevices: numberValue(overview, ["total_devices", "totalDevices", "node_count"], data.nodes.length),
    openFindings: numberValue(overview, ["open_findings", "openFindings", "active_finding_count"], data.findings.filter((finding) => finding.status === "open").length),
    heldActions: numberValue(overview, ["held_actions", "heldActions"], data.actions.filter((action) => action.decision === "HOLD").length),
    currentExit: stringValue(overview, ["current_exit", "currentExit", "exit_node"], data.overview.currentExit),
    exitVerified: booleanValue(overview, ["exit_verified", "exitVerified"], data.overview.exitVerified),
    dnsResolver: stringValue(overview, ["dns_resolver", "dnsResolver"], data.overview.dnsResolver),
    scramblerState: stringValue(overview, ["scrambler_state", "scramblerState"], data.scrambler.state),
    environment: {
      name: stringValue(environment, ["name", "display_name", "ssid"], data.overview.environment.name),
      type: (["home", "office", "mobile", "public", "unknown"].includes(rawEnvironmentType) ? rawEnvironmentType : "unknown") as DashboardData["overview"]["environment"]["type"],
      trust: (["trusted", "untrusted", "unknown"].includes(rawTrust) ? rawTrust : "unknown") as DashboardData["overview"]["environment"]["trust"],
      security: stringValue(environment, ["security", "security_mode"], data.overview.environment.security),
      known: booleanValue(environment, ["known", "is_known"], false),
      gateway: stringValue(environment, ["gateway", "gateway_address"], data.overview.environment.gateway),
      changedAt: stringValue(environment, ["changed_at", "observed_at"], data.overview.environment.changedAt),
    },
  };

  return {
    data,
    mode: failedEndpoints.length ? "partial" : "live",
    successfulEndpoints,
    failedEndpoints,
  };
}

export async function postCommand<T = unknown>(baseUrl: string, path: string, body: unknown): Promise<T> {
  const response = await fetch(resolveUrl(baseUrl, path), {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errorBody = await response.json().catch(() => null) as { message?: unknown } | null;
    const safeMessage = typeof errorBody?.message === "string" ? `: ${errorBody.message}` : "";
    throw new Error(`${response.status} ${response.statusText}${safeMessage}`);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function openLiveStream(
  baseUrl: string,
  onEnvelope: (envelope: LiveEventEnvelope) => void,
  onStatus: (status: "connecting" | "connected" | "reconnecting" | "unsupported") => void,
): () => void {
  if (typeof EventSource === "undefined") {
    onStatus("unsupported");
    return () => undefined;
  }

  const cursor = typeof window !== "undefined" ? window.localStorage.getItem("antiflock.stream.cursor") : null;
  const query = new URLSearchParams({ topics: STREAM_TOPICS.join(",") });
  if (cursor) query.set("cursor", cursor);
  const source = new EventSource(resolveUrl(baseUrl, `/v1/stream?${query.toString()}`), { withCredentials: true });
  onStatus("connecting");

  const receive = (event: MessageEvent<string>) => {
    try {
      const parsed = JSON.parse(event.data) as UnknownRecord;
      const durableCursor = typeof parsed.cursor === "string" ? parsed.cursor : event.lastEventId;
      if (durableCursor && typeof window !== "undefined") {
        window.localStorage.setItem("antiflock.stream.cursor", durableCursor);
      }
      const eventRecord = record(parsed.event ?? parsed);
      onEnvelope({
        id: durableCursor || stringValue(eventRecord, ["id"], "") || undefined,
        kind: stringValue(eventRecord, ["kind", "type"], event.type || "message"),
        observedAt: stringValue(eventRecord, ["observed_at", "observedAt"], "") || undefined,
        data: parsed,
        payload: eventRecord.payload,
      });
    } catch {
      // Invalid stream frames are ignored; the next durable event can still be processed.
    }
  };

  source.onopen = () => onStatus("connected");
  source.onerror = () => onStatus("reconnecting");
  source.onmessage = receive;
  STREAM_TOPICS.forEach((topic) => source.addEventListener(topic, receive as EventListener));

  return () => source.close();
}
