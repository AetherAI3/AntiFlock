export class SecureActionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class InvalidSecureActionRequestError extends SecureActionError {}

export class InvalidAgentResponseError extends SecureActionError {}

export class AgentTransportError extends SecureActionError {
  readonly status: number | undefined;

  constructor(message: string, options?: { readonly status?: number; readonly cause?: unknown }) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.status = options?.status;
  }
}

export class SecureActionAbortedError extends SecureActionError {}

export class AuditAppendError extends SecureActionError {
  readonly lifecycle: string;
  readonly actionMayHaveExecuted: boolean;

  constructor(
    lifecycle: string,
    actionMayHaveExecuted: boolean,
    cause: unknown,
  ) {
    super(`AntiFlock audit append failed during ${lifecycle}`, { cause });
    this.lifecycle = lifecycle;
    this.actionMayHaveExecuted = actionMayHaveExecuted;
  }
}

export class OneTimeAuthorizationError extends SecureActionError {}
