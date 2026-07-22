import assert from "node:assert/strict";
import test from "node:test";
import { createUnknownLiveData, loadDashboard, normalizePosture, resolveUrl, REST_ENDPOINTS, COMMAND_ENDPOINTS } from "../src/api/client";
import { createDemoData } from "../src/test-fixtures/demo";

test("documents every dashboard REST projection and command surface", () => {
  assert.deepEqual(Object.values(REST_ENDPOINTS), [
    "/v1/overview",
    "/v1/nodes",
    "/v1/topology",
    "/v1/paths",
    "/v1/events?limit=100",
    "/v1/findings",
    "/v1/posture",
    "/v1/actions?limit=100",
    "/v1/field/reports",
    "/v1/footprint",
    "/v1/scrambler/state",
  ]);
  assert.equal(COMMAND_ENDPOINTS.applyPlan("plan/a"), "/v1/plans/plan%2Fa/apply");
  assert.equal(COMMAND_ENDPOINTS.authorizeAction("action 1"), "/v1/actions/action%201/authorize");
});

test("normalizes canonical snake_case posture projections", () => {
  const fallback = createDemoData("UNKNOWN").posture;
  const normalized = normalizePosture({
    state: "PROTECTED",
    evaluated_at: "2026-07-21T14:00:00Z",
    confidence: 0.97,
    recommended_response: "No action required",
  }, fallback);
  assert.equal(normalized.state, "PROTECTED");
  assert.equal(normalized.evaluatedAt, "2026-07-21T14:00:00Z");
  assert.equal(normalized.confidence, 0.97);
});

test("resolves same-origin and configured Core URLs without duplicate slashes", () => {
  assert.equal(resolveUrl("", "/v1/overview"), "/v1/overview");
  assert.equal(resolveUrl("https://core.internal/", "/v1/overview"), "https://core.internal/v1/overview");
});

test("partial live state never presents demo fixtures as telemetry", () => {
  const live = createUnknownLiveData();
  assert.equal(live.posture.state, "UNKNOWN");
  assert.equal(live.posture.evidenceClass, "Unknown");
  assert.equal(live.nodes.length, 0);
  assert.equal(live.fieldReports.length, 0);
  assert.equal(live.footprintAssets.length, 0);
  assert.equal(live.actions.length, 0);
  assert.equal(live.overview.currentExit, "Not reported by Core");
  assert.equal(live.overview.simulation, null);
});

test("partial Core responses preserve canonical projections and mark other areas unavailable", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/v1/overview")) {
      return Response.json({
        posture: {
          state: "PROTECTED",
          evaluated_at: "2026-07-21T14:00:00Z",
          confidence: 0.99,
          reasons: [],
        },
        nodes: [{ id: "node-1", display_name: "Gateway", node_type: "gateway", protection_state: "PROTECTED" }],
        active_findings: [],
        recent_events: [],
        current_exit: "gateway-1",
        exit_verified: true,
        simulation: true,
      });
    }
    return new Response("Unavailable", { status: 503 });
  }) as typeof fetch;
  try {
    const result = await loadDashboard("https://core.internal", new AbortController().signal);
    assert.equal(result.mode, "partial");
    assert.equal(result.data.posture.state, "PROTECTED");
    assert.equal(result.data.nodes[0]?.name, "Gateway");
    assert.equal(result.data.fieldReports.length, 0);
    assert.equal(result.data.overview.environment.name, "Not reported by Core");
    assert.equal(result.data.overview.simulation, true);
    assert.ok(result.failedEndpoints.includes("/v1/field/reports"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("hydrates bounded one-time authorization metadata from the live action projection", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/v1/actions?")) {
      return Response.json({ actions: [{
        actionId: "action-1",
        operationId: "operation-1",
        applicationId: "aether-code",
        nodeId: "node-1",
        decision: "HOLD",
        reasonCodes: ["AF-PATH-001"],
        scope: { actionType: "git.push", destinations: ["api.github.com"], dataClass: "repository-source", sensitivity: "SENSITIVITY_OPERATOR_PRIVATE" },
        createdAt: "2026-07-21T13:42:00Z",
        oneTimeAuthorization: { enabled: true, maximumExpiresAt: "2026-07-21T13:47:00Z", consentReasonCode: "USER_EXPLICIT" },
      }] });
    }
    if (url.endsWith("/v1/overview")) return Response.json({});
    return new Response("Unavailable", { status: 503 });
  }) as typeof fetch;
  try {
    const result = await loadDashboard("https://core.internal", new AbortController().signal);
    assert.equal(result.data.actions[0]?.id, "action-1");
    assert.equal(result.data.actions[0]?.applicationId, "aether-code");
    assert.deepEqual(result.data.actions[0]?.destinations, ["api.github.com"]);
    assert.equal(result.data.actions[0]?.sensitivity, "SENSITIVITY_OPERATOR_PRIVATE");
    assert.equal(result.data.actions[0]?.oneTimeAuthorization?.consentReasonCode, "USER_EXPLICIT");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("maps Core durable path facts without upgrading observed evidence", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/v1/overview")) return Response.json({});
    if (url.endsWith("/v1/paths")) {
      return Response.json({ paths: [{
        id: "current-path:node-1",
        sourceNodeId: "node-1",
        state: "PROTECTED",
        observedAt: "2026-07-22T12:00:00Z",
        hops: [{
          position: 1,
          logicalRole: "MESH_EXIT",
          kind: "mesh.path_changed",
          classification: "VERIFIED",
          details: { provider: "tailscale", exitNodeId: "home-gateway" },
        }],
        checks: [{ id: "mesh", state: "PASS" }],
      }] });
    }
    if (url.endsWith("/v1/topology")) {
      return Response.json({ relationships: [{
        id: "mesh:node-1:gateway-1:path-1",
        type: "MESH_PATH",
        sourceEntityId: "node-1",
        targetEntityId: "gateway-1",
        state: "ACTIVE",
        classification: "DETECTED",
      }] });
    }
    return new Response("Unavailable", { status: 503 });
  }) as typeof fetch;
  try {
    const result = await loadDashboard("", new AbortController().signal);
    assert.equal(result.data.paths[0]?.state, "active");
    assert.equal(result.data.paths[0]?.segments[0]?.kind, "exit");
    assert.equal(result.data.paths[0]?.segments[0]?.state, "trusted");
    assert.match(result.data.paths[0]?.segments[0]?.detail ?? "", /tailscale.*home-gateway/);
    assert.equal(result.data.topology[0]?.source, "node-1");
    assert.equal(result.data.topology[0]?.evidenceClass, "Detected");
    assert.equal(result.data.topology[0]?.state, "unknown");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
