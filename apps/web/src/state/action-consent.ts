import type { SecureAction } from "../api/contracts";

function isSpecific(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0
    && !normalized.startsWith("unknown")
    && !normalized.startsWith("not reported")
    && !normalized.startsWith("no destination");
}

export function hasCompleteOneTimeAuthorizationScope(action: SecureAction): boolean {
  return [
    action.id,
    action.operationId,
    action.applicationId,
    action.nodeId,
    action.actionType,
    action.dataClass,
    action.sensitivity,
  ].every(isSpecific)
    && action.destinations.length > 0
    && action.destinations.every(isSpecific);
}

export function oneTimeAuthorizationScopeFingerprint(action: SecureAction): string {
  return JSON.stringify({
    actionId: action.id,
    operationId: action.operationId,
    applicationId: action.applicationId,
    nodeId: action.nodeId,
    actionType: action.actionType,
    destinations: action.destinations,
    dataClass: action.dataClass,
    sensitivity: action.sensitivity,
    maximumExpiresAt: action.oneTimeAuthorization?.maximumExpiresAt ?? "",
  });
}
