import assert from "node:assert/strict";
import test from "node:test";
import { proxyCoreRequest, withSecurityHeaders } from "../worker/proxy";

const token = "operator-token-that-is-definitely-more-than-thirty-two-bytes";

test("private Core proxy is inert when no server-side bindings exist", async () => {
  const response = await proxyCoreRequest(new Request("https://dashboard.example/v1/overview"), {}, async () => {
    throw new Error("fetch must not run");
  });
  assert.equal(response, null);
});

test("proxy injects the server credential and strips browser credentials", async () => {
  let observed: Request | undefined;
  const response = await proxyCoreRequest(
    new Request("https://dashboard.example/v1/overview?detail=1", {
      headers: { Authorization: "Bearer attacker", Cookie: "session=attacker", "X-Forwarded-For": "203.0.113.2" },
    }),
    { ANTIFLOCK_API_ORIGIN: "http://core:8787", ANTIFLOCK_OPERATOR_TOKEN: token },
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
      headers: { Origin: "https://attacker.example", "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json" },
      body: "{}",
    }),
    { ANTIFLOCK_API_ORIGIN: "https://core.internal", ANTIFLOCK_OPERATOR_TOKEN: token },
    async () => { contacted = true; return Response.json({}); },
  );
  assert.equal(response?.status, 403);
  assert.equal(contacted, false);
});

test("proxy allows same-origin JSON mutations and preserves streaming bodies", async () => {
  const response = await proxyCoreRequest(
    new Request("https://dashboard.example/v1/policies/validate", {
      method: "POST",
      headers: { Origin: "https://dashboard.example", "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" },
      body: JSON.stringify({ profile: {} }),
    }),
    { ANTIFLOCK_API_ORIGIN: "https://core.internal", ANTIFLOCK_OPERATOR_TOKEN: token },
    async (_input, init) => {
      assert.equal(new TextDecoder().decode(init?.body as ArrayBuffer), JSON.stringify({ profile: {} }));
      return new Response("data: verified\n\n", { headers: { "Content-Type": "text/event-stream" } });
    },
  );
  assert.equal(response?.status, 200);
  assert.equal(await response?.text(), "data: verified\n\n");
});

test("security headers do not issue HSTS for the local HTTP dashboard", () => {
  const local = withSecurityHeaders(new Response("ok"), "http://127.0.0.1:4173/");
  const hosted = withSecurityHeaders(new Response("ok"), "https://dashboard.example/");
  assert.equal(local.headers.get("Strict-Transport-Security"), null);
  assert.match(hosted.headers.get("Strict-Transport-Security") ?? "", /max-age=/);
});
