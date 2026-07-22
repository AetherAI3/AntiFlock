import { AgentTransportError } from "./errors.js";
import {
  parseCanonicalDecisionResponse,
  parseCanonicalProtectionSnapshot,
  toCanonicalAuthorizeRequest,
  toCanonicalEvaluateRequest,
} from "./canonical-wire.js";
import type {
  ActionAuditEvent,
  AgentTransport,
  AllowOnceDecision,
  AuthorizeOnceRequest,
  EvaluationContext,
  SecureActionDecision,
  SecureActionRequest,
  WaitForProtectionRequest,
  WaitForProtectionResult,
} from "./types.js";

export interface FetchLoopbackTransportOptions {
  readonly baseUrl?: string;
  readonly bearerToken?: string;
  /** Separate operator credential used only for explicit one-time consent. */
  readonly authorizationBearerToken?: string;
  readonly clientId?: string;
  readonly requestTimeoutMs?: number;
  readonly allowNonLoopback?: boolean;
  /** Explicit escape hatch for OS-authenticated proxies that add auth elsewhere. */
  readonly allowUnauthenticated?: boolean;
  readonly fetch?: typeof globalThis.fetch;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);

export class FetchLoopbackTransport implements AgentTransport {
  readonly #baseUrl: URL;
  readonly #bearerToken: string | undefined;
  readonly #authorizationBearerToken: string | undefined;
  readonly #clientId: string;
  readonly #requestTimeoutMs: number;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: FetchLoopbackTransportOptions = {}) {
    this.#baseUrl = new URL(options.baseUrl ?? "http://127.0.0.1:8787/");
    const isLoopback = LOOPBACK_HOSTS.has(this.#baseUrl.hostname);
    if (!options.allowNonLoopback && !isLoopback) {
      throw new AgentTransportError(
        `Refusing non-loopback AntiFlock agent endpoint: ${this.#baseUrl.hostname}`,
      );
    }
    if (this.#baseUrl.protocol !== "http:" && this.#baseUrl.protocol !== "https:") {
      throw new AgentTransportError("AntiFlock agent endpoint must use HTTP or HTTPS");
    }
    if (!isLoopback && this.#baseUrl.protocol !== "https:") {
      throw new AgentTransportError("Non-loopback AntiFlock endpoints require HTTPS");
    }
    if (!options.allowUnauthenticated && !validToken(options.bearerToken)) {
      throw new AgentTransportError(
        "An AntiFlock agent bearer token of at least 32 bytes is required unless unauthenticated transport is explicitly enabled",
      );
    }
    if (options.authorizationBearerToken !== undefined && !validToken(options.authorizationBearerToken)) {
      throw new AgentTransportError("The AntiFlock authorization bearer token must contain at least 32 bytes");
    }
    this.#bearerToken = options.bearerToken;
    this.#authorizationBearerToken = options.authorizationBearerToken;
    this.#clientId = options.clientId ?? "antiflock-typescript-sdk";
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== "function") {
      throw new AgentTransportError("A Fetch-compatible implementation is required");
    }
  }

  async evaluate(
    request: SecureActionRequest,
    _context: EvaluationContext,
    signal?: AbortSignal,
  ): Promise<SecureActionDecision> {
    const raw = await this.#post(
      "v1/actions/evaluate",
      toCanonicalEvaluateRequest(request),
      signal,
    );
    return parseCanonicalDecisionResponse(raw, request);
  }

  async waitForProtection(request: WaitForProtectionRequest): Promise<WaitForProtectionResult> {
    const { signal: requestSignal, ...body } = request;
    const raw = await this.#post(
      `v1/actions/${encodeURIComponent(request.actionId)}/wait`,
      body,
      requestSignal,
      Math.max(
        this.#requestTimeoutMs,
        Number.isFinite(Date.parse(request.deadline))
          ? Date.parse(request.deadline) - Date.now() + 1_000
          : this.#requestTimeoutMs,
      ),
    );
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new AgentTransportError("AntiFlock wait response must be an object");
    }
    const response = raw as Record<string, unknown>;
    if (typeof response.restored !== "boolean") {
      throw new AgentTransportError("AntiFlock wait response is missing restored");
    }
    return {
      restored: response.restored,
      snapshot: parseCanonicalProtectionSnapshot(response.snapshot),
    };
  }

  async authorizeOnce(
    request: AuthorizeOnceRequest,
    signal?: AbortSignal,
  ): Promise<AllowOnceDecision> {
    if (this.#authorizationBearerToken === undefined) {
      throw new AgentTransportError(
        "One-time authorization requires a separate operator credential or an external operator approval flow",
      );
    }
    const raw = await this.#post(
      `v1/actions/${encodeURIComponent(request.actionId)}/authorize`,
      toCanonicalAuthorizeRequest(request),
      signal,
      this.#requestTimeoutMs,
      this.#authorizationBearerToken,
    );
    const decision = parseCanonicalDecisionResponse(raw, request.request);
    if (decision.decision !== "ALLOW_ONCE") {
      throw new AgentTransportError(
        `Authorize endpoint returned ${decision.decision}; expected ALLOW_ONCE`,
      );
    }
    return decision;
  }

  async appendAudit(event: ActionAuditEvent, signal?: AbortSignal): Promise<void> {
    await this.#post(
      `v1/actions/${encodeURIComponent(event.actionId)}/audit`,
      event,
      signal,
    );
  }

  async #post(
    path: string,
    body: unknown,
    signal?: AbortSignal,
    timeoutMs = this.#requestTimeoutMs,
    bearerToken = this.#bearerToken,
  ): Promise<unknown> {
    const timeoutController = new AbortController();
    const timeout = setTimeout(() => timeoutController.abort(), Math.max(1, timeoutMs));
    const combinedSignal = signal
      ? AbortSignal.any([signal, timeoutController.signal])
      : timeoutController.signal;
    try {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        accept: "application/json",
        "x-antiflock-client": this.#clientId,
      };
      if (bearerToken !== undefined) {
        headers.authorization = `Bearer ${bearerToken}`;
      }
      const response = await this.#fetch(new URL(path, this.#baseUrl), {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: combinedSignal,
      });
      if (!response.ok) {
        const details = (await response.text().catch(() => "")).slice(0, 512);
        throw new AgentTransportError(
          `AntiFlock agent returned HTTP ${response.status}${details ? `: ${details}` : ""}`,
          { status: response.status },
        );
      }
      if (response.status === 204) {
        return {};
      }
      return await response.json();
    } catch (error) {
      if (error instanceof AgentTransportError) {
        throw error;
      }
      throw new AgentTransportError(`AntiFlock agent request failed for ${path}`, { cause: error });
    } finally {
      clearTimeout(timeout);
    }
  }
}

function validToken(value: string | undefined): boolean {
  return value !== undefined && value.length >= 32 && value.trim() === value && !/[\r\n]/.test(value);
}
