export type EvidenceClass =
  | "Detected"
  | "Verified"
  | "Reported"
  | "Inferred"
  | "Suspected"
  | "Unknown";

export type ProtectionState =
  | "PROTECTED"
  | "DEGRADED"
  | "SUSPICIOUS"
  | "EXPOSED"
  | "UNKNOWN"
  | "VERIFYING";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type DashboardSection =
  | "overview"
  | "network"
  | "path"
  | "activity"
  | "findings"
  | "devices"
  | "policies"
  | "actions"
  | "field"
  | "intelligence"
  | "footprint"
  | "scrambler"
  | "settings";

export interface ProtectionCheck {
  id: string;
  label: string;
  state: "pass" | "fail" | "warning" | "unknown";
  observed: string;
  expected: string;
  evidenceClass: EvidenceClass;
  checkedAt: string;
}

export interface Posture {
  state: ProtectionState;
  reasonCode: string;
  summary: string;
  evaluatedAt: string;
  confidence: number;
  evidenceClass: EvidenceClass;
  checks: ProtectionCheck[];
}

export interface Environment {
  name: string;
  type: "home" | "office" | "mobile" | "public" | "unknown";
  trust: "trusted" | "untrusted" | "unknown";
  security: string;
  known: boolean;
  gateway: string;
  changedAt: string;
}

export interface Overview {
  operatorName: string;
  deploymentName: string;
  simulation: boolean | null;
  evidenceProvenance: "LIVE" | "SIMULATION" | "UNKNOWN";
  environment: Environment;
  protectedDevices: number;
  totalDevices: number;
  openFindings: number;
  heldActions: number;
  currentExit: string;
  exitVerified: boolean;
  dnsState: "verified" | "unverified" | "changed" | "unknown";
  dnsResolver: string;
  scramblerState: string;
}

export interface DeviceNode {
  id: string;
  name: string;
  kind: "phone" | "laptop" | "desktop" | "gateway" | "server" | "agent" | "router";
  platform: string;
  state: "online" | "offline" | "stale" | "blocked";
  protection: ProtectionState;
  lastSeen: string;
  network: string;
  meshAddress: string;
  agentVersion: string;
  capabilities: string[];
  tags: string[];
}

export interface PathSegment {
  id: string;
  label: string;
  kind: "application" | "device" | "policy" | "mesh" | "relay" | "exit" | "dns" | "destination";
  state: "trusted" | "degraded" | "blocked" | "unknown";
  detail: string;
  evidenceClass: EvidenceClass;
}

export interface NetworkPath {
  id: string;
  application: string;
  sourceNodeId: string;
  destination: string;
  state: "active" | "held" | "blocked" | "unknown";
  encrypted: boolean | null;
  policy: string;
  updatedAt: string;
  segments: PathSegment[];
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  state: "trusted" | "degraded" | "blocked" | "unknown";
  evidenceClass: EvidenceClass;
}

export interface TimelineEvent {
  id: string;
  kind: string;
  title: string;
  summary: string;
  observedAt: string;
  receivedAt: string;
  evidenceClass: EvidenceClass;
  confidence: number;
  severity: Severity;
  nodeId?: string;
  reasonCode?: string;
}

export interface EvidenceItem {
  id: string;
  label: string;
  value: string;
  source: string;
  observedAt: string;
  lastVerifiedAt: string;
  evidenceClass: EvidenceClass;
  confidence: number;
  expiresAt?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  condition: string;
  consequence: string;
  recommendation: string;
  falsePositiveNote: string;
  status: "open" | "resolved" | "dismissed";
  severity: Severity;
  classification: EvidenceClass;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  evidence: EvidenceItem[];
}

export interface SecureAction {
  id: string;
  operationId: string;
  applicationId: string;
  nodeId: string;
  actionType: string;
  destination: string;
  destinations: string[];
  dataClass: string;
  sensitivity: string;
  decision: "ALLOW" | "HOLD" | "BLOCK" | "REQUIRE_CONSENT" | "ALLOW_ONCE";
  reasonCodes: string[];
  createdAt: string;
  expiresAt?: string;
  oneTimeAuthorization?: {
    enabled: boolean;
    maximumExpiresAt: string;
    consentReasonCode: string;
  };
}

export interface PolicyRule {
  id: string;
  label: string;
  value: string;
  enforcement: "observe" | "advise" | "guard" | "shield";
}

export interface PolicyProfile {
  id: string;
  name: string;
  mode: "Observe" | "Guard" | "Shield" | "Scramble";
  status: "active" | "draft" | "invalid";
  revision: number;
  updatedAt: string;
  targetCount: number;
  rules: PolicyRule[];
}

export interface FieldReport {
  id: string;
  category: string;
  label: string;
  distance: string;
  locationPrecision: string;
  direction: string;
  classification: EvidenceClass;
  confidence: number;
  status: "unreviewed" | "corroborated" | "documented" | "verified" | "stale" | "disputed";
  source: string;
  observedAt: string;
  lastVerifiedAt: string;
  expiresAt: string;
  coordinates: { x: number; y: number };
}

export interface FootprintAsset {
  id: string;
  type: string;
  label: string;
  verification: "verified" | "pending" | "unverified";
  exposure: "public" | "limited" | "private" | "unknown";
  lastCheckedAt: string;
  findings: number;
}

export interface FootprintRelationship {
  id: string;
  source: string;
  target: string;
  label: string;
  classification: EvidenceClass;
}

export interface ScramblerCheck {
  id: string;
  label: string;
  state: "pass" | "fail" | "pending" | "unknown";
}

export interface ScramblerState {
  state: "IDLE" | "PLANNING" | "PREFLIGHT" | "DRAINING" | "APPLYING" | "VERIFYING" | "ACTIVE" | "ROLLING_BACK";
  profile: string;
  stateId: string;
  currentExit: string;
  proposedExit?: string;
  lastTransitionAt: string;
  simulationOnly: boolean;
  risk: "low" | "medium" | "high";
  checks: ScramblerCheck[];
}

export interface DashboardData {
  overview: Overview;
  posture: Posture;
  nodes: DeviceNode[];
  paths: NetworkPath[];
  topology: TopologyEdge[];
  events: TimelineEvent[];
  findings: Finding[];
  actions: SecureAction[];
  policies: PolicyProfile[];
  fieldReports: FieldReport[];
  footprintAssets: FootprintAsset[];
  footprintRelationships: FootprintRelationship[];
  scrambler: ScramblerState;
}

export interface LiveEventEnvelope {
  id?: string;
  kind: string;
  observedAt?: string;
  data?: unknown;
  payload?: unknown;
}
