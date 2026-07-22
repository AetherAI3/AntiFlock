export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { readonly [key: string]: JsonValue };

export const DECISION_TYPES = [
  "ALLOW",
  "HOLD",
  "BLOCK",
  "REQUIRE_CONSENT",
  "ALLOW_ONCE",
] as const;

export type DecisionType = (typeof DECISION_TYPES)[number];

export const PROTECTION_STATES = [
  "PROTECTED",
  "DEGRADED",
  "SUSPICIOUS",
  "EXPOSED",
  "UNKNOWN",
  "UNAVAILABLE",
] as const;

export type ProtectionState = (typeof PROTECTION_STATES)[number];
export type EvidenceClass =
  | "DETECTED"
  | "VERIFIED"
  | "REPORTED"
  | "INFERRED"
  | "SUSPECTED"
  | "UNKNOWN";
export type NetworkTrust = "TRUSTED" | "UNTRUSTED" | "UNKNOWN";
export type Sensitivity = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED";

export interface ProtectionSnapshot {
  readonly state: ProtectionState;
  readonly observedAt: string;
  readonly networkTrust: NetworkTrust;
  readonly meshConnected: boolean | null;
  readonly approvedExitActive: boolean | null;
  readonly dnsProtected: boolean | null;
  readonly reasonCodes: readonly string[];
}

/**
 * Describes an operation without including its payload. Applications should not
 * place message bodies, credentials, repository contents, or other secrets in
 * metadata.
 */
export interface SecureActionRequest {
  readonly id: string;
  readonly applicationId: string;
  readonly nodeId: string;
  readonly actionType: string;
  readonly destinations: readonly string[];
  readonly dataClass: string;
  readonly sensitivity: Sensitivity;
  readonly deadline?: string;
  /** Stable idempotency/correlation identifier for retries of this operation. */
  readonly operationId: string;
  readonly metadata?: Readonly<Record<string, JsonValue>>;
}

export interface ActionAuditMetadata {
  readonly traceId: string;
  readonly decisionId: string;
  readonly policyRevision: number;
  readonly evaluatedAt: string;
  readonly agentId: string;
  readonly evidenceClass: EvidenceClass;
}

export interface OneTimeScope {
  readonly id: string;
  readonly applicationId: string;
  readonly nodeId: string;
  readonly operationId: string;
  readonly actionType: string;
  readonly destinations: readonly string[];
}

export interface OneTimeAuthorization {
  readonly grantId: string;
  readonly token: string;
  readonly scope: OneTimeScope;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly remainingUses: 1;
}

interface DecisionBase {
  readonly actionId: string;
  readonly protection: ProtectionSnapshot;
  readonly reasonCodes: readonly string[];
  readonly audit: ActionAuditMetadata;
}

export interface AllowDecision extends DecisionBase {
  readonly decision: "ALLOW";
}

export interface HoldDecision extends DecisionBase {
  readonly decision: "HOLD";
  readonly hold: {
    readonly releaseWhen: "PROTECTION_RESTORED";
    readonly expiresAt: string;
  };
}

export interface BlockDecision extends DecisionBase {
  readonly decision: "BLOCK";
}

export interface RequireConsentDecision extends DecisionBase {
  readonly decision: "REQUIRE_CONSENT";
  readonly consent: {
    readonly prompt: string;
    readonly expiresAt: string;
    readonly scope: OneTimeScope;
  };
}

export interface AllowOnceDecision extends DecisionBase {
  readonly decision: "ALLOW_ONCE";
  readonly authorization: OneTimeAuthorization;
}

export type SecureActionDecision =
  | AllowDecision
  | HoldDecision
  | BlockDecision
  | RequireConsentDecision
  | AllowOnceDecision;

export interface EvaluationContext {
  readonly attempt: number;
  readonly priorActionId?: string;
}

export interface WaitForProtectionRequest {
  readonly actionId: string;
  readonly afterObservedAt: string;
  readonly deadline: string;
  readonly signal?: AbortSignal;
}

export interface WaitForProtectionResult {
  readonly restored: boolean;
  readonly snapshot: ProtectionSnapshot;
}

export interface AuthorizeOnceRequest {
  readonly actionId: string;
  readonly request: SecureActionRequest;
  readonly scope: OneTimeScope;
  readonly expiresAt: string;
  readonly consent: {
    readonly confirmed: true;
    readonly confirmedAt: string;
    readonly method: "USER_EXPLICIT";
  };
}

export type AuditLifecycle =
  | "SDK_DECISION_RECEIVED"
  | "SDK_HOLD_WAIT_STARTED"
  | "SDK_PROTECTION_RESTORED"
  | "SDK_CONSENT_DECLINED"
  | "SDK_ACTION_EXECUTION_STARTED"
  | "SDK_ACTION_EXECUTION_SUCCEEDED"
  | "SDK_ACTION_EXECUTION_FAILED";

export interface ActionAuditEvent {
  readonly eventId: string;
  readonly lifecycle: AuditLifecycle;
  readonly occurredAt: string;
  readonly actionId: string;
  readonly requestId: string;
  readonly decision: DecisionType;
  readonly traceId: string;
  readonly policyRevision: number;
  readonly reasonCodes: readonly string[];
  readonly details?: Readonly<Record<string, JsonValue>>;
}

export interface AgentTransport {
  evaluate(
    request: SecureActionRequest,
    context: EvaluationContext,
    signal?: AbortSignal,
  ): Promise<SecureActionDecision>;

  waitForProtection(request: WaitForProtectionRequest): Promise<WaitForProtectionResult>;

  authorizeOnce(request: AuthorizeOnceRequest, signal?: AbortSignal): Promise<AllowOnceDecision>;

  appendAudit(event: ActionAuditEvent, signal?: AbortSignal): Promise<void>;
}

export type ConsentResponse =
  | { readonly confirmed: true }
  | { readonly confirmed: false; readonly reason?: string };

export interface ConsentContext {
  readonly request: SecureActionRequest;
  readonly decision: RequireConsentDecision;
}

export type ConsentProvider = (context: ConsentContext) => Promise<ConsentResponse>;

export interface ActionExecutionContext {
  readonly request: SecureActionRequest;
  readonly decision: AllowDecision | AllowOnceDecision;
  readonly attempt: number;
}

export type SecureActionOperation<T> = (context: ActionExecutionContext) => Promise<T> | T;

export interface ExecuteOptions {
  readonly signal?: AbortSignal;
  readonly retryOnProtectionRestored?: boolean;
  readonly maxProtectionRestorations?: number;
  readonly consentProvider?: ConsentProvider;
  readonly onDecision?: (decision: SecureActionDecision, attempt: number) => void | Promise<void>;
}

export type SecureActionOutcome<T> =
  | {
      readonly status: "executed";
      readonly value: T;
      readonly actionId: string;
      readonly decision: "ALLOW" | "ALLOW_ONCE";
      readonly attempts: number;
      readonly audit: ActionAuditMetadata;
    }
  | {
      readonly status: "blocked";
      readonly actionId: string;
      readonly reasonCodes: readonly string[];
      readonly audit: ActionAuditMetadata;
    }
  | {
      readonly status: "held";
      readonly actionId: string;
      readonly reasonCodes: readonly string[];
      readonly expiresAt: string;
      readonly audit: ActionAuditMetadata;
    }
  | {
      readonly status: "consent_required";
      readonly actionId: string;
      readonly prompt: string;
      readonly audit: ActionAuditMetadata;
    }
  | {
      readonly status: "expired";
      readonly actionId: string;
      readonly reasonCodes: readonly string[];
      readonly audit: ActionAuditMetadata;
    };

export interface SecureActionClientOptions {
  readonly defaultDeadlineMs?: number;
  readonly defaultMaxProtectionRestorations?: number;
  readonly auditMode?: "required" | "best-effort";
  readonly now?: () => Date;
  readonly idFactory?: () => string;
}
