import { InvalidAgentResponseError } from "./errors.js";
import type {
  ActionAuditMetadata,
  AllowOnceDecision,
  AuthorizeOnceRequest,
  DecisionType,
  EvidenceClass,
  OneTimeAuthorization,
  ProtectionSnapshot,
  ProtectionState,
  SecureActionDecision,
  SecureActionRequest,
  Sensitivity,
} from "./types.js";
import { parseDecision, scopeForRequest } from "./validation.js";

type WireRecord = Record<string, unknown>;

const SENSITIVITY_TO_PROTO: Record<Sensitivity, string> = {
  PUBLIC: "SENSITIVITY_PUBLIC",
  INTERNAL: "SENSITIVITY_INTERNAL",
  CONFIDENTIAL: "SENSITIVITY_OPERATOR_PRIVATE",
  RESTRICTED: "SENSITIVITY_RESTRICTED",
};

const DECISION_FROM_PROTO = new Map<string | number, DecisionType>([
  [1, "ALLOW"],
  [2, "HOLD"],
  [3, "BLOCK"],
  [4, "REQUIRE_CONSENT"],
  [5, "ALLOW_ONCE"],
  ["ALLOW", "ALLOW"],
  ["HOLD", "HOLD"],
  ["BLOCK", "BLOCK"],
  ["REQUIRE_CONSENT", "REQUIRE_CONSENT"],
  ["ALLOW_ONCE", "ALLOW_ONCE"],
  ["SECURE_ACTION_DECISION_TYPE_ALLOW", "ALLOW"],
  ["SECURE_ACTION_DECISION_TYPE_HOLD", "HOLD"],
  ["SECURE_ACTION_DECISION_TYPE_BLOCK", "BLOCK"],
  ["SECURE_ACTION_DECISION_TYPE_REQUIRE_CONSENT", "REQUIRE_CONSENT"],
  ["SECURE_ACTION_DECISION_TYPE_ALLOW_ONCE", "ALLOW_ONCE"],
]);

const PROTECTION_FROM_PROTO = new Map<string | number, ProtectionState>([
  [1, "PROTECTED"],
  [2, "DEGRADED"],
  [3, "SUSPICIOUS"],
  [4, "EXPOSED"],
  [5, "UNKNOWN"],
  [6, "UNAVAILABLE"],
  ["PROTECTED", "PROTECTED"],
  ["DEGRADED", "DEGRADED"],
  ["SUSPICIOUS", "SUSPICIOUS"],
  ["EXPOSED", "EXPOSED"],
  ["UNKNOWN", "UNKNOWN"],
  ["UNAVAILABLE", "UNAVAILABLE"],
  ["PROTECTION_STATE_PROTECTED", "PROTECTED"],
  ["PROTECTION_STATE_DEGRADED", "DEGRADED"],
  ["PROTECTION_STATE_SUSPICIOUS", "SUSPICIOUS"],
  ["PROTECTION_STATE_EXPOSED", "EXPOSED"],
  ["PROTECTION_STATE_UNKNOWN", "UNKNOWN"],
  ["PROTECTION_STATE_UNAVAILABLE", "UNAVAILABLE"],
]);

function asRecord(value: unknown, path: string): WireRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InvalidAgentResponseError(`${path} must be an object`);
  }
  return value as WireRecord;
}

function first(value: WireRecord, ...names: string[]): unknown {
  for (const name of names) {
    if (value[name] !== undefined) return value[name];
  }
  return undefined;
}

function requiredString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new InvalidAgentResponseError(`${path} must be a non-empty string`);
  }
  return value;
}

function timestamp(value: unknown, path: string): string {
  const text = requiredString(value, path);
  if (!Number.isFinite(Date.parse(text))) {
    throw new InvalidAgentResponseError(`${path} must be an RFC3339 timestamp`);
  }
  return text;
}

function stringList(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) {
    throw new InvalidAgentResponseError(`${path} must be an array`);
  }
  return value.map((item, index) => requiredString(item, `${path}[${index}]`));
}

function safeRevision(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string" && /^\d+$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed)) return parsed;
  }
  return 0;
}

export function toCanonicalEvaluateRequest(request: SecureActionRequest): WireRecord {
  return {
    action: {
      id: request.id,
      applicationId: request.applicationId,
      nodeId: request.nodeId,
      actionType: request.actionType,
      destinations: [...request.destinations],
      dataClass: request.dataClass,
      sensitivity: SENSITIVITY_TO_PROTO[request.sensitivity],
      ...(request.deadline === undefined ? {} : { deadline: request.deadline }),
      operationId: request.operationId,
    },
  };
}

export function toCanonicalAuthorizeRequest(request: AuthorizeOnceRequest): WireRecord {
  // The consent decision's expiry is the upper bound; a projection may shorten
  // this further according to policy. The public client validates the returned
  // decision's actual expiry before it executes.
  return {
    actionId: request.actionId,
    operationId: request.request.operationId,
    authorizedDestinations: [...request.scope.destinations],
    expiresAt: request.expiresAt,
    consentReasonCode: "USER_EXPLICIT",
  };
}

export function parseCanonicalProtectionSnapshot(raw: unknown): ProtectionSnapshot {
  const value = asRecord(raw, "protection");
  // SDK-native transports may already return the richer internal snapshot.
  if (value.networkTrust !== undefined && value.observedAt !== undefined) {
    const state = PROTECTION_FROM_PROTO.get(value.state as string | number);
    if (state === undefined) throw new InvalidAgentResponseError("protection.state is invalid");
    const networkTrust = requiredString(value.networkTrust, "protection.networkTrust");
    if (!["TRUSTED", "UNTRUSTED", "UNKNOWN"].includes(networkTrust)) {
      throw new InvalidAgentResponseError("protection.networkTrust is invalid");
    }
    return {
      state,
      observedAt: timestamp(value.observedAt, "protection.observedAt"),
      validUntil: timestamp(value.validUntil, "protection.validUntil"),
      policyRevision: safeRevision(value.policyRevision),
      networkTrust: networkTrust as ProtectionSnapshot["networkTrust"],
      meshConnected: typeof value.meshConnected === "boolean" ? value.meshConnected : null,
      approvedExitActive:
        typeof value.approvedExitActive === "boolean" ? value.approvedExitActive : null,
      dnsProtected: typeof value.dnsProtected === "boolean" ? value.dnsProtected : null,
      reasonCodes: stringList(value.reasonCodes ?? [], "protection.reasonCodes"),
    };
  }

  const state = PROTECTION_FROM_PROTO.get(first(value, "state") as string | number);
  if (state === undefined) {
    throw new InvalidAgentResponseError("canonical protection.state is invalid or unspecified");
  }
  const reasons = first(value, "reasons");
  const reasonCodes = Array.isArray(reasons)
    ? reasons.map((reason, index) => {
        const item = asRecord(reason, `protection.reasons[${index}]`);
        return requiredString(
          first(item, "reasonCode", "reason_code"),
          `protection.reasons[${index}].reasonCode`,
        );
      })
    : [];
  return {
    state,
    observedAt: timestamp(
      first(value, "evaluatedAt", "evaluated_at"),
      "protection.evaluatedAt",
    ),
    validUntil: timestamp(
      first(value, "validUntil", "valid_until"),
      "protection.validUntil",
    ),
    policyRevision: safeRevision(first(value, "policyRevision", "policy_revision")),
    networkTrust: "UNKNOWN",
    meshConnected: null,
    approvedExitActive: null,
    dnsProtected: null,
    reasonCodes,
  };
}

export function parseCanonicalDecisionResponse(
  raw: unknown,
  request: SecureActionRequest,
): SecureActionDecision {
  const envelope = asRecord(raw, "action decision response");
  const nested = envelope.decision;
  const value =
    typeof nested === "object" && nested !== null && !Array.isArray(nested)
      ? (nested as WireRecord)
      : envelope;

  // Rich SDK-native adapters can use the internal contract directly.
  if (
    value.audit !== undefined &&
    value.actionId !== undefined &&
    typeof value.decision === "string" &&
    ["ALLOW", "HOLD", "BLOCK", "REQUIRE_CONSENT", "ALLOW_ONCE"].includes(value.decision) &&
    typeof value.protection === "object" &&
    value.protection !== null &&
    (value.protection as WireRecord).networkTrust !== undefined
  ) {
    return parseDecision(value);
  }

  const decisionValue = first(value, "decision");
  const decision = DECISION_FROM_PROTO.get(decisionValue as string | number);
  if (decision === undefined) {
    throw new InvalidAgentResponseError("canonical decision is invalid or unspecified");
  }
  const actionId = requiredString(first(value, "actionId", "action_id"), "decision.actionId");
  const protectionRaw = first(value, "protection");
  const protection = parseCanonicalProtectionSnapshot(protectionRaw);
  const reasonCodesRaw = first(value, "reasonCodes", "reason_codes");
  const reasonCodes =
    reasonCodesRaw === undefined
      ? protection.reasonCodes
      : stringList(reasonCodesRaw, "decision.reasonCodes");
  const protectionRecord = asRecord(protectionRaw, "protection");
  const policyRevision = protection.policyRevision;
  const audit: ActionAuditMetadata = {
    // The canonical protection snapshot id identifies evidence, not the
    // application's idempotency boundary. Bind lifecycle audits to the exact
    // operation that was evaluated.
    traceId: request.operationId,
    decisionId: `${request.operationId}:${decision}:${actionId}`,
    policyRevision,
    evaluatedAt: protection.observedAt,
    agentId:
      typeof first(protectionRecord, "nodeId", "node_id") === "string"
        ? (first(protectionRecord, "nodeId", "node_id") as string)
        : request.nodeId,
    evidenceClass: "UNKNOWN" as EvidenceClass,
  };
  const base = { actionId, protection, reasonCodes, audit };

  if (decision === "ALLOW") return { decision, ...base };
  if (decision === "BLOCK") return { decision, ...base };

  const expiresAt = timestamp(
    first(value, "expiresAt", "expires_at"),
    "decision.expiresAt",
  );
  if (decision === "HOLD") {
    return {
      decision,
      ...base,
      hold: { releaseWhen: "PROTECTION_RESTORED", expiresAt },
    };
  }
  if (decision === "REQUIRE_CONSENT") {
    const userMessage = first(value, "userMessage", "user_message");
    return {
      decision,
      ...base,
      consent: {
        prompt:
          typeof userMessage === "string" && userMessage.trim() !== ""
            ? userMessage
            : "Authorize this exact action once outside the protected route?",
        expiresAt,
        scope: scopeForRequest(request),
      },
    };
  }

  const token = requiredString(first(value, "authorization"), "decision.authorization");
  const authorization: OneTimeAuthorization = {
    grantId: `${actionId}:${request.operationId}`,
    token,
    scope: scopeForRequest(request),
    issuedAt: protection.observedAt,
    expiresAt,
    remainingUses: 1,
  };
  const result: AllowOnceDecision = { decision, ...base, authorization };
  return result;
}
