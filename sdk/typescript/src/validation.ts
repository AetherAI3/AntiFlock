import { InvalidAgentResponseError, InvalidSecureActionRequestError } from "./errors.js";
import {
  DECISION_TYPES,
  PROTECTION_STATES,
  type ActionAuditMetadata,
  type EvidenceClass,
  type JsonValue,
  type NetworkTrust,
  type OneTimeAuthorization,
  type OneTimeScope,
  type ProtectionSnapshot,
  type SecureActionDecision,
  type SecureActionRequest,
  type Sensitivity,
} from "./types.js";

const SENSITIVITIES = new Set<Sensitivity>([
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "RESTRICTED",
]);
const NETWORK_TRUSTS = new Set<NetworkTrust>(["TRUSTED", "UNTRUSTED", "UNKNOWN"]);
const EVIDENCE_CLASSES = new Set<EvidenceClass>([
  "DETECTED",
  "VERIFIED",
  "REPORTED",
  "INFERRED",
  "SUSPECTED",
  "UNKNOWN",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new InvalidAgentResponseError(`${path} must be an object`);
  }
  return value;
}

function stringValue(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new InvalidAgentResponseError(`${path} must be a non-empty string`);
  }
  return value;
}

function numberValue(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new InvalidAgentResponseError(`${path} must be a non-negative safe integer`);
  }
  return value;
}

function booleanOrNull(value: unknown, path: string): boolean | null {
  if (typeof value !== "boolean" && value !== null) {
    throw new InvalidAgentResponseError(`${path} must be a boolean or null`);
  }
  return value;
}

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) {
    throw new InvalidAgentResponseError(`${path} must be an array`);
  }
  return value.map((entry, index) => stringValue(entry, `${path}[${index}]`));
}

function isoDate(value: unknown, path: string): string {
  const text = stringValue(value, path);
  if (!Number.isFinite(Date.parse(text))) {
    throw new InvalidAgentResponseError(`${path} must be an ISO-8601 timestamp`);
  }
  return text;
}

function enumValue<T extends string>(value: unknown, values: ReadonlySet<T>, path: string): T {
  const text = stringValue(value, path);
  if (!values.has(text as T)) {
    throw new InvalidAgentResponseError(`${path} has an unsupported value: ${text}`);
  }
  return text as T;
}

export function canonicalDestinations(destinations: readonly string[]): string[] {
  return [...new Set(destinations.map((destination) => destination.trim()))].sort((left, right) =>
    left.localeCompare(right),
  );
}

function assertJsonValue(value: unknown, path: string): asserts value is JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJsonValue(item, `${path}[${index}]`));
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      assertJsonValue(item, `${path}.${key}`);
    }
    return;
  }
  throw new InvalidSecureActionRequestError(`${path} must contain only JSON-safe values`);
}

export function normalizeRequest(request: SecureActionRequest): SecureActionRequest {
  const required = [
    ["id", request.id],
    ["applicationId", request.applicationId],
    ["nodeId", request.nodeId],
    ["actionType", request.actionType],
    ["dataClass", request.dataClass],
    ["operationId", request.operationId],
  ] as const;
  for (const [name, value] of required) {
    if (typeof value !== "string" || value.trim() === "") {
      throw new InvalidSecureActionRequestError(`${name} must be a non-empty string`);
    }
  }
  if (!SENSITIVITIES.has(request.sensitivity)) {
    throw new InvalidSecureActionRequestError(`Unsupported sensitivity: ${request.sensitivity}`);
  }
  const destinations = canonicalDestinations(request.destinations);
  if (destinations.length === 0 || destinations.some((destination) => destination === "")) {
    throw new InvalidSecureActionRequestError("destinations must contain at least one non-empty value");
  }
  if (request.deadline !== undefined && !Number.isFinite(Date.parse(request.deadline))) {
    throw new InvalidSecureActionRequestError("deadline must be an ISO-8601 timestamp");
  }
  if (request.metadata !== undefined) {
    assertJsonValue(request.metadata, "metadata");
  }

  return {
    id: request.id.trim(),
    applicationId: request.applicationId.trim(),
    nodeId: request.nodeId.trim(),
    actionType: request.actionType.trim(),
    destinations,
    dataClass: request.dataClass.trim(),
    sensitivity: request.sensitivity,
    operationId: request.operationId.trim(),
    ...(request.deadline === undefined ? {} : { deadline: request.deadline }),
    ...(request.metadata === undefined ? {} : { metadata: request.metadata }),
  };
}

export function scopeForRequest(request: SecureActionRequest): OneTimeScope {
  return {
    id: request.id,
    applicationId: request.applicationId,
    nodeId: request.nodeId,
    operationId: request.operationId,
    actionType: request.actionType,
    destinations: canonicalDestinations(request.destinations),
  };
}

export function sameScope(left: OneTimeScope, right: OneTimeScope): boolean {
  return (
    left.id === right.id &&
    left.applicationId === right.applicationId &&
    left.nodeId === right.nodeId &&
    left.operationId === right.operationId &&
    left.actionType === right.actionType &&
    JSON.stringify(canonicalDestinations(left.destinations)) ===
      JSON.stringify(canonicalDestinations(right.destinations))
  );
}

export function parseProtectionSnapshot(raw: unknown): ProtectionSnapshot {
  const value = record(raw, "protection");
  const state = enumValue(value.state, new Set(PROTECTION_STATES), "protection.state");
  const networkTrust = enumValue(value.networkTrust, NETWORK_TRUSTS, "protection.networkTrust");
  return {
    state,
    observedAt: isoDate(value.observedAt, "protection.observedAt"),
    networkTrust,
    meshConnected: booleanOrNull(value.meshConnected, "protection.meshConnected"),
    approvedExitActive: booleanOrNull(
      value.approvedExitActive,
      "protection.approvedExitActive",
    ),
    dnsProtected: booleanOrNull(value.dnsProtected, "protection.dnsProtected"),
    reasonCodes: stringArray(value.reasonCodes, "protection.reasonCodes"),
  };
}

function parseAudit(raw: unknown): ActionAuditMetadata {
  const value = record(raw, "audit");
  return {
    traceId: stringValue(value.traceId, "audit.traceId"),
    decisionId: stringValue(value.decisionId, "audit.decisionId"),
    policyRevision: numberValue(value.policyRevision, "audit.policyRevision"),
    evaluatedAt: isoDate(value.evaluatedAt, "audit.evaluatedAt"),
    agentId: stringValue(value.agentId, "audit.agentId"),
    evidenceClass: enumValue(value.evidenceClass, EVIDENCE_CLASSES, "audit.evidenceClass"),
  };
}

export function parseScope(raw: unknown, path = "scope"): OneTimeScope {
  const value = record(raw, path);
  return {
    id: stringValue(value.id, `${path}.id`),
    applicationId: stringValue(value.applicationId, `${path}.applicationId`),
    nodeId: stringValue(value.nodeId, `${path}.nodeId`),
    operationId: stringValue(value.operationId, `${path}.operationId`),
    actionType: stringValue(value.actionType, `${path}.actionType`),
    destinations: canonicalDestinations(stringArray(value.destinations, `${path}.destinations`)),
  };
}

export function parseAuthorization(raw: unknown): OneTimeAuthorization {
  const value = record(raw, "authorization");
  if (value.remainingUses !== 1) {
    throw new InvalidAgentResponseError("authorization.remainingUses must be exactly 1");
  }
  const issuedAt = isoDate(value.issuedAt, "authorization.issuedAt");
  const expiresAt = isoDate(value.expiresAt, "authorization.expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new InvalidAgentResponseError(
      "authorization.expiresAt must be after authorization.issuedAt",
    );
  }
  return {
    grantId: stringValue(value.grantId, "authorization.grantId"),
    token: stringValue(value.token, "authorization.token"),
    scope: parseScope(value.scope, "authorization.scope"),
    issuedAt,
    expiresAt,
    remainingUses: 1,
  };
}

export function parseDecision(raw: unknown): SecureActionDecision {
  const value = record(raw, "decision response");
  const decision = enumValue(value.decision, new Set(DECISION_TYPES), "decision");
  const base = {
    actionId: stringValue(value.actionId, "actionId"),
    protection: parseProtectionSnapshot(value.protection),
    reasonCodes: stringArray(value.reasonCodes, "reasonCodes"),
    audit: parseAudit(value.audit),
  };

  switch (decision) {
    case "ALLOW":
      return { decision, ...base };
    case "BLOCK":
      return { decision, ...base };
    case "HOLD": {
      const hold = record(value.hold, "hold");
      if (hold.releaseWhen !== "PROTECTION_RESTORED") {
        throw new InvalidAgentResponseError(
          "hold.releaseWhen must be PROTECTION_RESTORED",
        );
      }
      return {
        decision,
        ...base,
        hold: {
          releaseWhen: "PROTECTION_RESTORED",
          expiresAt: isoDate(hold.expiresAt, "hold.expiresAt"),
        },
      };
    }
    case "REQUIRE_CONSENT": {
      const consent = record(value.consent, "consent");
      return {
        decision,
        ...base,
        consent: {
          prompt: stringValue(consent.prompt, "consent.prompt"),
          expiresAt: isoDate(consent.expiresAt, "consent.expiresAt"),
          scope: parseScope(consent.scope, "consent.scope"),
        },
      };
    }
    case "ALLOW_ONCE":
      return { decision, ...base, authorization: parseAuthorization(value.authorization) };
  }
}
