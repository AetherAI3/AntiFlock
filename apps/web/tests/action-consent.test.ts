import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { SecureAction } from "../src/api/contracts";
import { OneTimeAuthorizationControl } from "../src/features/section-view";
import {
  hasCompleteOneTimeAuthorizationScope,
  oneTimeAuthorizationScopeFingerprint,
} from "../src/state/action-consent";

const action: SecureAction = {
  id: "action-1",
  operationId: "operation-1",
  applicationId: "aether-code",
  nodeId: "node-1",
  actionType: "git.push",
  destination: "github.com",
  destinations: ["github.com"],
  dataClass: "repository-source",
  sensitivity: "SENSITIVITY_OPERATOR_PRIVATE",
  decision: "HOLD",
  reasonCodes: ["AF-PATH-001"],
  createdAt: "2026-07-22T10:00:00Z",
  oneTimeAuthorization: {
    enabled: true,
    maximumExpiresAt: "2026-07-22T10:05:00Z",
    consentReasonCode: "USER_EXPLICIT",
  },
};

test("requires every canonical action scope dimension before one-time authorization", () => {
  assert.equal(hasCompleteOneTimeAuthorizationScope(action), true);
  assert.equal(hasCompleteOneTimeAuthorizationScope({ ...action, sensitivity: "Unknown" }), false);
  assert.equal(hasCompleteOneTimeAuthorizationScope({ ...action, applicationId: "" }), false);
  assert.equal(hasCompleteOneTimeAuthorizationScope({ ...action, destinations: [] }), false);
});

test("binds confirmation state to the exact scope and authorization expiry", () => {
  const fingerprint = oneTimeAuthorizationScopeFingerprint(action);
  assert.notEqual(fingerprint, oneTimeAuthorizationScopeFingerprint({ ...action, destinations: ["gitlab.com"] }));
  assert.notEqual(fingerprint, oneTimeAuthorizationScopeFingerprint({ ...action, sensitivity: "SENSITIVITY_RESTRICTED" }));
  assert.notEqual(fingerprint, oneTimeAuthorizationScopeFingerprint({
    ...action,
    oneTimeAuthorization: { ...action.oneTimeAuthorization!, maximumExpiresAt: "2026-07-22T10:06:00Z" },
  }));
});

test("renders the exact scope and requires explicit confirmation before authorization", () => {
  const html = renderToStaticMarkup(createElement(OneTimeAuthorizationControl, {
    action,
    mode: "live",
    pending: false,
    onAuthorize: async () => undefined,
  }));

  for (const expected of [
    "Action ID",
    "action-1",
    "Operation ID",
    "operation-1",
    "Application ID",
    "aether-code",
    "Node ID",
    "node-1",
    "Action type",
    "git.push",
    "Destinations",
    "github.com",
    "Data class",
    "repository-source",
    "Sensitivity",
    "SENSITIVITY_OPERATOR_PRIVATE",
  ]) {
    assert.match(html, new RegExp(expected));
  }
  assert.match(html, /type="checkbox"/);
  assert.match(html, /I confirm this exact application, action, destination, data, and sensitivity scope/);
  assert.match(html, /<button[^>]*disabled=""[^>]*>Authorize this exact scope once<\/button>/);
});

test("does not offer authorization when Core omits a scope dimension", () => {
  const html = renderToStaticMarkup(createElement(OneTimeAuthorizationControl, {
    action: { ...action, sensitivity: "Unknown" },
    mode: "live",
    pending: false,
    onAuthorize: async () => undefined,
  }));

  assert.match(html, /Core did not provide a complete, enabled one-time authorization scope/);
  assert.doesNotMatch(html, /type="checkbox"/);
  assert.match(html, /One-time authorization unavailable/);
});
