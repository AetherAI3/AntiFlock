import assert from "node:assert/strict";
import test from "node:test";
import { dashboardAccessResponse, proxyCoreRequest, withSecurityHeaders } from "../worker/proxy";

const token = "operator-token-that-is-definitely-more-than-thirty-two-bytes";
const dashboardToken = "dashboard-token-that-is-also-more-than-thirty-two-bytes";
const authorization = `Basic ${btoa(`operator:${dashboardToken}`)}`;
const bindings = {
  ANTIFLOCK_API_ORIGIN: "http://core:8787",
  ANTIFLOCK_OPERATOR_TOKEN: token,
  ANTIFLOCK_DASHBOARD_TOKEN: dashboardToken,
};

test("private Core proxy is inert when no server-side bindings exist", async () => {
  const response = await proxyCoreRequest(new Request("https://dashboard.example/v1/overview"), undefined, async () => {
    throw new Error("fetch must not run");
  });
  assert.equal(response, null);
});

test("proxy injects the server credential and strips browser credentials", async () => {
  let observed: Request | undefined;
  const response = await proxyCoreRequest(
    new Request("https://dashboard.example/v1/overview?detail=1", {
      headers: { Authorization: authorization, Cookie: "session=attacker", "X-Forwarded-For": "203.0.113.2" },
    }),
    bindings,
    async (input, init) => {
      observed = new Request(input, init);
      return Response.json({ status: "ok" }, { headers: { "Set-Cookie": "leak=yes", "Cache-Control": "no-store" } });
    },
  );
  assert.equal(observed?.url, "http://core:8787/v1/overview?detail=1");
  assert.equal(observed?.headers.get("Authorization"), `Bearer ${token}`);
  assert.equal(observed?.headers.get("Cookie"), null);
  assert.equal(observed?.headers.get("X-Forwarded-For"), null);
  assert.equal(response?.headers.get("Set-Cookie"), null);
  assert.equal(response?.headers.get("X-Frame-Options"), "DENY");
});

test("proxy rejects cross-origin mutations before contacting Core", async () => {
  let contacted = false;
  const response = await proxyCoreRequest(
    new Request("https://dashboard.example/v1/policies/validate", {
      method: "POST",
      headers: { Authorization: authorization, Origin: "https://attacker.example", "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json" },
      body: "{}",
    }),
    { ...bindings, ANTIFLOCK_API_ORIGIN: "https://core.internal" },
    async () => { contacted = true; return Response.json({}); },
  );
  assert.equal(response?.status, 403);
  assert.equal(contacted, false);
});

test("proxy allows same-origin JSON mutations and preserves streaming bodies", async () => {
  const response = await proxyCoreRequest(
    new Request("https://dashboard.example/v1/policies/validate", {
      method: "POST",
      headers: { Authorization: authorization, Origin: "https://dashboard.example", "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" },
      body: JSON.stringify({ profile: {} }),
    }),
    { ...bindings, ANTIFLOCK_API_ORIGIN: "https://core.internal" },
    async (_input, init) => {
      assert.equal(new TextDecoder().decode(init?.body as ArrayBuffer), JSON.stringify({ profile: {} }));
      return new Response("data: verified\n\n", { headers: { "Content-Type": "text/event-stream" } });
    },
  );
  assert.equal(response?.status, 200);
  assert.equal(await response?.text(), "data: verified\n\n");
});

test("private dashboard and Core proxy require an independent operator credential", async () => {
  const request = new Request("https://dashboard.example/v1/policies/validate", {
    method: "POST",
    headers: { Origin: "https://dashboard.example", "Content-Type": "application/json" },
    body: "{}",
  });
  const access = await dashboardAccessResponse(request, bindings);
  assert.equal(access?.status, 401);
  assert.match(access?.headers.get("WWW-Authenticate") ?? "", /Basic/);

  let contacted = false;
  const proxied = await proxyCoreRequest(request, bindings, async () => {
    contacted = true;
    return Response.json({});
  });
  assert.equal(proxied?.status, 401);
  assert.equal(contacted, false);
});

test("security headers do not issue HSTS for the local HTTP dashboard", () => {
  const local = withSecurityHeaders(new Response("ok"), "http://127.0.0.1:4173/");
  const hosted = withSecurityHeaders(new Response("ok"), "https://dashboard.example/");
  assert.equal(local.headers.get("Strict-Transport-Security"), null);
  assert.match(hosted.headers.get("Strict-Transport-Security") ?? "", /max-age=/);
});
