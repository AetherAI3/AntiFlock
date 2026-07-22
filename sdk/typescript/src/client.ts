import { randomUUID } from "node:crypto";
import {
  AuditAppendError,
  InvalidAgentResponseError,
  InvalidSecureActionRequestError,
  OneTimeAuthorizationError,
  SecureActionAbortedError,
  SimulationExecutionDeniedError,
} from "./errors.js";
import type {
  ActionAuditEvent,
  AgentTransport,
  AllowDecision,
  AllowOnceDecision,
  AuditLifecycle,
  AuthorizeOnceRequest,
  EvaluationContext,
  ExecuteOptions,
  JsonValue,
  OneTimeAuthorization,
  SecureActionClientOptions,
  SecureActionDecision,
  SecureActionOperation,
  SecureActionOutcome,
  SecureActionRequest,
} from "./types.js";
import { normalizeRequest, parseDecision, sameScope, scopeForRequest } from "./validation.js";

function immutableClone<T>(value: T): T {
  const clone = (current: unknown): unknown => {
    if (Array.isArray(current)) return current.map(clone);
    if (current !== null && typeof current === "object") {
      return Object.fromEntries(
        Object.entries(current as Record<string, unknown>).map(([key, item]) => [key, clone(item)]),
      );
    }
    return current;
  };
  const freeze = (current: unknown): unknown => {
    if (current !== null && typeof current === "object" && !Object.isFrozen(current)) {
      for (const item of Object.values(current as Record<string, unknown>)) freeze(item);
      Object.freeze(current);
    }
    return current;
  };
  return freeze(clone(value)) as T;
}

interface ResolvedClientOptions {
  readonly defaultDeadlineMs: number;
  readonly defaultMaxProtectionRestorations: number;
  readonly auditMode: "required" | "best-effort";
  readonly now: () => Date;
  readonly idFactory: () => string;
}

export class SecureActionClient {
  readonly #transport: AgentTransport;
  readonly #options: ResolvedClientOptions;
  readonly #consumedGrants = new Map<string, number>();

  constructor(transport: AgentTransport, options: SecureActionClientOptions = {}) {
    if ((options.defaultDeadlineMs ?? 60_000) <= 0) {
      throw new InvalidSecureActionRequestError("defaultDeadlineMs must be positive");
    }
    if ((options.defaultMaxProtectionRestorations ?? 3) < 0) {
      throw new InvalidSecureActionRequestError(
        "defaultMaxProtectionRestorations must be non-negative",
      );
    }
    this.#transport = transport;
    this.#options = {
      defaultDeadlineMs: options.defaultDeadlineMs ?? 60_000,
      defaultMaxProtectionRestorations: options.defaultMaxProtectionRestorations ?? 3,
      auditMode: options.auditMode ?? "required",
      now: options.now ?? (() => new Date()),
      idFactory: options.idFactory ?? randomUUID,
    };
  }

  async evaluate(
    request: SecureActionRequest,
    signal?: AbortSignal,
  ): Promise<SecureActionDecision> {
    const normalized = immutableClone(this.#withDeadline(normalizeRequest(request)));
    this.#throwIfUnavailable(normalized.deadline!, signal);
    const decision = parseDecision(await this.#transport.evaluate(normalized, { attempt: 0 }, signal));
    this.#validateDecisionBinding(decision, normalized);
    this.#throwIfAllowUnavailable(decision, signal);
    return decision;
  }

  async execute<T>(
    request: SecureActionRequest,
    operation: SecureActionOperation<T>,
    options: ExecuteOptions = {},
  ): Promise<SecureActionOutcome<T>> {
    const normalized = immutableClone(this.#withDeadline(normalizeRequest(request)));
    const deadline = normalized.deadline!;
    const maxRestorations =
      options.maxProtectionRestorations ?? this.#options.defaultMaxProtectionRestorations;
    if (!Number.isInteger(maxRestorations) || maxRestorations < 0) {
      throw new InvalidSecureActionRequestError(
        "maxProtectionRestorations must be a non-negative integer",
      );
    }

    let attempt = 0;
    let priorActionId: string | undefined;

    while (true) {
      this.#throwIfUnavailable(deadline, options.signal);
      const context: EvaluationContext = {
        attempt,
        ...(priorActionId === undefined ? {} : { priorActionId }),
      };
      // Treat every transport as untrusted at runtime. Parsing creates a fresh
      // decision object so a transport-held reference cannot mutate the branch
      // after validation.
      const decision = parseDecision(await this.#transport.evaluate(normalized, context, options.signal));
      this.#validateDecisionBinding(decision, normalized);
      this.#throwIfAllowUnavailable(decision, options.signal);
      priorActionId = decision.actionId;
      await this.#audit(normalized, decision, "SDK_DECISION_RECEIVED", {}, options.signal, false);
      // Audit storage is asynchronous. Do not disclose an ALLOW to observers
      // after the evidence that justified it has expired in that interval.
      this.#throwIfAllowUnavailable(decision, options.signal);
      // Observers receive a separate parsed copy. Their callback must never be
      // able to rewrite BLOCK/HOLD into an executable decision.
      await options.onDecision?.(immutableClone(parseDecision(decision)), attempt);
      this.#throwIfAllowUnavailable(decision, options.signal);

      switch (decision.decision) {
        case "BLOCK":
          return {
            status: "blocked",
            actionId: decision.actionId,
            reasonCodes: decision.reasonCodes,
            audit: decision.audit,
          };

        case "HOLD": {
          if (
            options.retryOnProtectionRestored === false ||
            attempt >= maxRestorations
          ) {
            return {
              status: "held",
              actionId: decision.actionId,
              reasonCodes: decision.reasonCodes,
              expiresAt: decision.hold.expiresAt,
              audit: decision.audit,
            };
          }
          const waitDeadline = this.#earliest(deadline, decision.hold.expiresAt);
          await this.#audit(
            normalized,
            decision,
            "SDK_HOLD_WAIT_STARTED",
            { waitDeadline },
            options.signal,
            false,
          );
          const wait = await this.#transport.waitForProtection({
            actionId: decision.actionId,
            afterObservedAt: decision.protection.observedAt,
            deadline: waitDeadline,
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          });
          if (!wait.restored || wait.snapshot.state !== "PROTECTED") {
            return {
              status: "expired",
              actionId: decision.actionId,
              reasonCodes: [
                ...decision.reasonCodes,
                wait.restored
                  ? "SDK_RESTORED_STATE_NOT_PROTECTED"
                  : "SDK_PROTECTION_RESTORE_TIMEOUT",
              ],
              audit: decision.audit,
            };
          }
          await this.#audit(
            normalized,
            decision,
            "SDK_PROTECTION_RESTORED",
            { observedAt: wait.snapshot.observedAt },
            options.signal,
            false,
          );
          attempt += 1;
          continue;
        }

        case "REQUIRE_CONSENT": {
          if (options.consentProvider === undefined) {
            return {
              status: "consent_required",
              actionId: decision.actionId,
              prompt: decision.consent.prompt,
              audit: decision.audit,
            };
          }
          if (!sameScope(decision.consent.scope, scopeForRequest(normalized))) {
            throw new OneTimeAuthorizationError(
              "Agent requested consent for a scope that does not match the action",
            );
          }
          const response = await options.consentProvider(immutableClone({ request: normalized, decision }));
          if (!response.confirmed) {
            await this.#audit(
              normalized,
              decision,
              "SDK_CONSENT_DECLINED",
              response.reason === undefined ? {} : { reason: response.reason },
              options.signal,
              false,
            );
            return {
              status: "consent_required",
              actionId: decision.actionId,
              prompt: decision.consent.prompt,
              audit: decision.audit,
            };
          }
          this.#throwIfUnavailable(decision.consent.expiresAt, options.signal);
          const authorizeRequest: AuthorizeOnceRequest = {
            actionId: decision.actionId,
            request: normalized,
            scope: decision.consent.scope,
            expiresAt: this.#earliest(decision.consent.expiresAt, normalized.deadline!),
            consent: {
              confirmed: true,
              confirmedAt: this.#options.now().toISOString(),
              method: "USER_EXPLICIT",
            },
          };
          const authorizedDecision = parseDecision(await this.#transport.authorizeOnce(
            authorizeRequest,
            options.signal,
          ));
          this.#validateDecisionBinding(authorizedDecision, normalized);
          if (authorizedDecision.decision !== "ALLOW_ONCE") {
            throw new OneTimeAuthorizationError("Agent did not return an ALLOW_ONCE authorization");
          }
          await this.#audit(
            normalized,
            authorizedDecision,
            "SDK_DECISION_RECEIVED",
            {},
            options.signal,
            false,
          );
          await options.onDecision?.(immutableClone(parseDecision(authorizedDecision)), attempt + 1);
          return await this.#executeAllowed(
            normalized,
            authorizedDecision,
            attempt + 1,
            operation,
            options.signal,
            options.allowSimulationExecution === true,
          );
        }

        case "ALLOW_ONCE":
          return await this.#executeAllowed(
            normalized,
            decision,
            attempt,
            operation,
            options.signal,
            options.allowSimulationExecution === true,
          );

        case "ALLOW":
          return await this.#executeAllowed(
            normalized,
            decision,
            attempt,
            operation,
            options.signal,
            options.allowSimulationExecution === true,
          );
      }
    }
  }

  async #executeAllowed<T>(
    request: SecureActionRequest,
    decision: AllowDecision | AllowOnceDecision,
    attempt: number,
    operation: SecureActionOperation<T>,
    signal?: AbortSignal,
    allowSimulationExecution = false,
  ): Promise<SecureActionOutcome<T>> {
    this.#throwIfUnavailable(request.deadline!, signal);
    this.#throwIfAllowUnavailable(decision, signal);
    if (decision.protection.evidenceProvenance === "SIMULATION" && !allowSimulationExecution) {
      throw new SimulationExecutionDeniedError(
        "Simulation-labeled protection cannot execute an application callback without explicit opt-in",
      );
    }
    if (decision.protection.evidenceProvenance === "UNKNOWN") {
      throw new InvalidAgentResponseError(
        "Protection evidence provenance must be LIVE before an application callback can execute",
      );
    }
    if (decision.decision === "ALLOW_ONCE") {
      this.#validateAuthorization(decision.authorization, request);
      this.#consumeGrant(decision.authorization);
    }
    try {
      await this.#audit(
        request,
        decision,
        "SDK_ACTION_EXECUTION_STARTED",
        {},
        signal,
        false,
        true,
      );
    } catch (error) {
      // A failed/ambiguous transport call must never run the operation. Release
      // only the client-local reservation so a retry can ask the authoritative
      // server whether the one-time grant was consumed.
      if (decision.decision === "ALLOW_ONCE") {
        this.#consumedGrants.delete(decision.authorization.grantId);
      }
      throw error;
    }
    // The audit/consume transport is asynchronous and may ignore cancellation.
    // Recheck every execution bound immediately before crossing into caller code.
    this.#throwIfUnavailable(request.deadline!, signal);
    this.#throwIfAllowUnavailable(decision, signal);
    if (decision.decision === "ALLOW_ONCE") {
      this.#validateAuthorization(decision.authorization, request);
    }
    let value: T;
    try {
      value = await operation(immutableClone({ request, decision, attempt }));
    } catch (error) {
      await this.#audit(
        request,
        decision,
        "SDK_ACTION_EXECUTION_FAILED",
        { errorType: error instanceof Error ? error.name : "unknown" },
        signal,
        true,
      );
      throw error;
    }
    // Keep completion-audit failures out of the operation-failure branch: the
    // action succeeded and callers must not be told (or tempted to retry) as if
    // the underlying operation itself had failed.
    await this.#audit(
      request,
      decision,
      "SDK_ACTION_EXECUTION_SUCCEEDED",
      {},
      signal,
      true,
    );
    return {
      status: "executed",
      value,
      actionId: decision.actionId,
      decision: decision.decision,
      attempts: attempt,
      audit: decision.audit,
    };
  }

  #withDeadline(request: SecureActionRequest): SecureActionRequest {
    if (request.deadline !== undefined) {
      return request;
    }
    return {
      ...request,
      deadline: new Date(this.#options.now().getTime() + this.#options.defaultDeadlineMs).toISOString(),
    };
  }

  #validateAuthorization(
    authorization: OneTimeAuthorization,
    request: SecureActionRequest,
  ): void {
    if (authorization.grantId.trim() === "" || authorization.token.trim() === "") {
      throw new OneTimeAuthorizationError("One-time authorization is malformed");
    }
    if (
      !Number.isFinite(Date.parse(authorization.issuedAt)) ||
      !Number.isFinite(Date.parse(authorization.expiresAt))
    ) {
      throw new OneTimeAuthorizationError("One-time authorization timestamps are malformed");
    }
    if (Date.parse(authorization.expiresAt) <= Date.parse(authorization.issuedAt)) {
      throw new OneTimeAuthorizationError(
        "One-time authorization expiry must be after its issue time",
      );
    }
    if (authorization.remainingUses !== 1) {
      throw new OneTimeAuthorizationError("One-time authorization has no usable grant");
    }
    if (!sameScope(authorization.scope, scopeForRequest(request))) {
      throw new OneTimeAuthorizationError(
        "One-time authorization scope does not match the secure action request",
      );
    }
    if (Date.parse(authorization.expiresAt) <= this.#options.now().getTime()) {
      throw new OneTimeAuthorizationError("One-time authorization has expired");
    }
  }

  #validateDecisionBinding(
    decision: SecureActionDecision,
    request: SecureActionRequest,
  ): void {
    if (decision.actionId !== request.id) {
      throw new InvalidAgentResponseError(
        "Agent decision actionId does not match the secure action request",
      );
    }
    if (decision.audit.traceId !== request.operationId) {
      throw new InvalidAgentResponseError(
        "Agent decision traceId does not match the secure action operationId",
      );
    }
    if (decision.audit.agentId !== request.nodeId) {
      throw new InvalidAgentResponseError(
        "Agent decision agentId does not match the secure action nodeId",
      );
    }
    if (decision.audit.policyRevision !== decision.protection.policyRevision) {
      throw new InvalidAgentResponseError(
        "Agent decision policy revision does not match the protection snapshot",
      );
    }
    if (decision.decision === "ALLOW" && decision.protection.state !== "PROTECTED") {
      throw new InvalidAgentResponseError(
        "Agent returned ALLOW without a protected posture",
      );
    }
    if (
      decision.decision === "ALLOW" &&
      (decision.protection.policyRevision === 0 ||
        Date.parse(decision.protection.validUntil) <= Date.parse(decision.protection.observedAt))
    ) {
      throw new InvalidAgentResponseError(
        "Agent returned ALLOW without a fresh, versioned protection snapshot",
      );
    }
  }

  #consumeGrant(authorization: OneTimeAuthorization): void {
    const now = this.#options.now().getTime();
    for (const [grantId, expiresAt] of this.#consumedGrants) {
      if (expiresAt <= now) this.#consumedGrants.delete(grantId);
    }
    if (this.#consumedGrants.has(authorization.grantId)) {
      throw new OneTimeAuthorizationError("One-time authorization was already consumed");
    }
    // This synchronous claim occurs before the first operation await, making
    // concurrent reuse within one client instance fail closed.
    this.#consumedGrants.set(authorization.grantId, Date.parse(authorization.expiresAt));
  }

  async #audit(
    request: SecureActionRequest,
    decision: SecureActionDecision,
    lifecycle: AuditLifecycle,
    details: Readonly<Record<string, JsonValue>>,
    signal: AbortSignal | undefined,
    actionMayHaveExecuted: boolean,
    forceRequired = false,
  ): Promise<void> {
    const event: ActionAuditEvent = {
      eventId: this.#options.idFactory(),
      lifecycle,
      occurredAt: this.#options.now().toISOString(),
      actionId: decision.actionId,
      requestId: request.id,
      decision: decision.decision,
      traceId: decision.audit.traceId,
      policyRevision: decision.audit.policyRevision,
      reasonCodes: decision.reasonCodes,
      ...(Object.keys(details).length === 0 ? {} : { details }),
    };
    try {
      await this.#transport.appendAudit(event, signal);
    } catch (error) {
      if (forceRequired || this.#options.auditMode === "required") {
        throw new AuditAppendError(lifecycle, actionMayHaveExecuted, error);
      }
    }
  }

  #throwIfUnavailable(deadline: string, signal?: AbortSignal): void {
    if (signal?.aborted) {
      throw new SecureActionAbortedError("Secure action was aborted");
    }
    if (Date.parse(deadline) <= this.#options.now().getTime()) {
      throw new SecureActionAbortedError("Secure action deadline has expired");
    }
  }

  #throwIfAllowUnavailable(
    decision: SecureActionDecision,
    signal?: AbortSignal,
  ): void {
    if (decision.decision !== "ALLOW") {
      return;
    }
    if (signal?.aborted) {
      throw new SecureActionAbortedError("Secure action was aborted");
    }
    if (Date.parse(decision.protection.validUntil) <= this.#options.now().getTime()) {
      throw new SecureActionAbortedError(
        "Secure action protection evidence has expired",
      );
    }
  }

  #earliest(left: string, right: string): string {
    return Date.parse(left) <= Date.parse(right) ? left : right;
  }
}
